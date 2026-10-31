//! `sigil log prove-consistency` / `sigil log check-consistency`: a portable receipt that the log
//! state pinned as anchor `OLD:ROOT` is a prefix of the later state `NEW:ROOT`, checkable offline
//! from the two roots alone (no INDEX, no segments, no keys). See "Consistency proofs" in
//! `docs/SEGMENT-LOG.md`.
//!
//! The proof is the chain hash of entry `OLD` plus its inclusion path in the tree over the first
//! `NEW` entries ([`crate::merkle::consistency_path`]). From those the verifier rebuilds **both**
//! roots ([`crate::merkle::roots_from_consistency`]); both must match. Sigil's tree (no RFC 6962
//! leaf/node prefixes, odd last node paired with itself) keeps entry `OLD` the last node of every
//! old layer, so this one path is a complete consistency proof for that tree shape.
//! Purely additive: nothing is written to the log.

use super::*;

const CONSISTENCY_MAGIC: &str = "sigil-log-consistency=1";

#[derive(Clone, Debug)]
pub struct Consistency {
    pub log_id: String,
    /// Informational (not covered by anything).
    pub name: String,
    pub old_size: u64,
    pub old_root: [u8; 32],
    pub new_size: u64,
    pub new_root: [u8; 32],
    /// Chain hash of entry `old_size` (the leaf the path starts from).
    pub leaf: [u8; 32],
    pub path: Vec<[u8; 32]>,
    /// The signed HEAD at `new_size`, when there is one.
    pub head: Option<ProofHead>,
    pub handovers: Vec<String>,
}

impl Consistency {
    pub fn render(&self) -> String {
        let mut s = format!("{CONSISTENCY_MAGIC}\nlog={}\n", self.log_id);
        if !self.name.is_empty() && !self.name.contains('\n') {
            s.push_str(&format!("name={}\n", self.name));
        }
        s.push_str(&format!(
            "old-size={}\nold-root={}\nnew-size={}\nnew-root={}\nleaf={}\npath={}\n",
            self.old_size,
            hex32(&self.old_root),
            self.new_size,
            hex32(&self.new_root),
            hex32(&self.leaf),
            self.path.iter().map(hex32).collect::<Vec<_>>().join(",")
        ));
        if let Some(h) = &self.head {
            s.push_str(&format!(
                "head-chain={}\nhead-t={}\nsigner={}\nsig={}\n",
                hex32(&h.chain),
                h.time,
                hex32(&h.signer),
                hex::encode(h.sig)
            ));
            for (i, l) in self.handovers.iter().enumerate() {
                s.push_str(&format!("handover-{}={l}\n", i + 1));
            }
        }
        s
    }

    pub fn parse(text: &str) -> Result<Consistency> {
        let mut lines = text.lines();
        if lines.next().map(str::trim) != Some(CONSISTENCY_MAGIC) {
            return Err(err(format!(
                "not a sigil consistency proof (first line must be {CONSISTENCY_MAGIC})"
            )));
        }
        let mut kv: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
        for l in lines {
            let l = l.trim_end_matches('\r');
            if l.trim().is_empty() || l.starts_with('#') {
                continue;
            }
            let Some((k, v)) = l.split_once('=') else {
                return Err(err(format!("consistency proof: bad line {l:?}")));
            };
            if kv.insert(k.trim(), v).is_some() {
                return Err(err(format!("consistency proof: duplicate {k}=")));
            }
        }
        let need = |k: &str| {
            kv.get(k)
                .copied()
                .ok_or_else(|| err(format!("consistency proof: missing {k}=")))
        };
        let h32 = |k: &str| -> Result<[u8; 32]> {
            parse_hex32(need(k)?.trim()).ok_or_else(|| err(format!("consistency proof: bad {k}=")))
        };
        let num = |k: &str| -> Result<u64> {
            need(k)?
                .trim()
                .parse()
                .map_err(|_| err(format!("consistency proof: bad {k}=")))
        };
        let path_s = need("path")?.trim();
        let path = if path_s.is_empty() {
            Vec::new()
        } else {
            path_s
                .split(',')
                .map(|p| {
                    parse_hex32(p.trim()).ok_or_else(|| err("consistency proof: bad path= hash"))
                })
                .collect::<Result<Vec<_>>>()?
        };
        let head = match (kv.get("signer"), kv.get("sig")) {
            (None, None) => None,
            (Some(_), Some(sig)) => Some(ProofHead {
                chain: h32("head-chain")?,
                time: num("head-t")?,
                signer: h32("signer")?,
                sig: hex::decode(sig.trim())
                    .ok()
                    .and_then(|b| <[u8; 64]>::try_from(b).ok())
                    .ok_or_else(|| err("consistency proof: bad sig="))?,
            }),
            _ => {
                return Err(err(
                    "consistency proof: signer= and sig= must come together",
                ))
            }
        };
        let mut handovers = Vec::new();
        while let Some(l) = kv.get(format!("handover-{}", handovers.len() + 1).as_str()) {
            handovers.push(l.to_string());
        }
        if kv.keys().filter(|k| k.starts_with("handover-")).count() != handovers.len() {
            return Err(err(
                "consistency proof: handover-N= lines must be numbered 1, 2, … without gaps",
            ));
        }
        Ok(Consistency {
            log_id: need("log")?.trim().to_string(),
            name: kv
                .get("name")
                .map(|s| s.trim().to_string())
                .unwrap_or_default(),
            old_size: num("old-size")?,
            old_root: h32("old-root")?,
            new_size: num("new-size")?,
            new_root: h32("new-root")?,
            leaf: h32("leaf")?,
            path,
            head,
            handovers,
        })
    }
}

/// Cut a consistency proof from the first `old` entries to the first `new` entries (default: the
/// HEAD the log vouches for). `old_root`, when given (the anchor you pinned), must be this log's
/// root at `old`, or the proof is refused: the log is not an extension of that anchor.
pub fn prove_consistency(
    path: &Path,
    old: u64,
    old_root: Option<[u8; 32]>,
    new: Option<u64>,
) -> Result<Consistency> {
    let log = Log::open(path)?;
    let idx = read_index(&log)?;
    if let Some((line, code, msg)) = &idx.error {
        return Err(err(format!(
            "INDEX line {line} is damaged ({code}: {msg}); run `sigil log verify` first"
        )));
    }
    let n = idx.entries.len() as u64;
    let trusted = trusted_len(&log, &idx) as u64;
    let head = match read_head(&log) {
        Some(Ok(h)) if h.seq == trusted && h.seq > 0 => Some(h),
        _ => None,
    };
    let new = match new {
        Some(m) if m > n => {
            return Err(err(format!("--to {m}: the INDEX has only {n} entries")));
        }
        Some(m) => m,
        None if trusted == 0 => {
            return Err(err(
                "the log has no HEAD it vouches for (empty, or HEAD/signature does not match); run `sigil log verify`, or pass --to N",
            ));
        }
        None => trusted,
    };
    if old == 0 {
        return Err(err(
            "the old anchor must cover at least 1 entry (an empty log is a prefix of everything)",
        ));
    }
    if old > new {
        return Err(err(format!(
            "old size {old} is larger than new size {new}: a log never shrinks, so there is no consistency to prove (rollback?)"
        )));
    }
    let entries = &idx.entries[..new as usize];
    let have_old = root_of(&entries[..old as usize]);
    if let Some(r) = old_root {
        if r != have_old {
            return Err(err(format!(
                "this log's root at {old} is {}, not the anchor's {}: the log is not an extension of that anchor (history rewritten, or another log)",
                hex32(&have_old),
                hex32(&r)
            )));
        }
    }
    let leaves: Vec<[u8; 32]> = entries.iter().map(|e| e.chain).collect();
    let signed = head.as_ref().filter(|h| h.seq == new).and_then(|h| {
        Some(ProofHead {
            chain: h.chain,
            time: h.time,
            signer: h.signer?,
            sig: h.sig?,
        })
    });
    let is_signed = signed.is_some();
    let o = old as usize;
    Ok(Consistency {
        log_id: log.id.clone(),
        name: log.name.clone(),
        old_size: old,
        old_root: have_old,
        new_size: new,
        new_root: root_of(entries),
        leaf: leaves[o - 1],
        path: crate::merkle::consistency_path(&leaves, o)
            .ok_or_else(|| crate::Error::Msg(format!("internal: entry {o} outside the log")))?,
        head: signed,
        handovers: if is_signed {
            entries
                .iter()
                .filter(|e| e.is_handover() && e.seq < new)
                .map(|e| format!("{} chain={}", e.body, hex32(&e.chain)))
                .collect()
        } else {
            Vec::new()
        },
    })
}

#[derive(Default)]
pub struct ConsistencyCheckOpts {
    /// Require the old side to be exactly this pinned `SEQ:ROOT`.
    pub old: Option<(u64, [u8; 32])>,
    /// Require the new side to be exactly this `SEQ:ROOT`.
    pub new: Option<(u64, [u8; 32])>,
    /// Require the new root signed by this key (or one it handed the log over to).
    pub signer: Option<[u8; 32]>,
}

#[derive(Debug)]
pub struct ConsistencyCheck {
    pub log_id: String,
    pub old_size: u64,
    pub old_root: [u8; 32],
    pub new_size: u64,
    pub new_root: [u8; 32],
    pub signed_by: Option<[u8; 32]>,
    pub signer_chain: Vec<[u8; 32]>,
}

impl ConsistencyCheck {
    pub fn render(&self) -> String {
        let mut s = format!(
            "consistency proof OK: {}:{} is a prefix of {}:{}\n  log {}\n",
            self.old_size,
            hex32(&self.old_root),
            self.new_size,
            hex32(&self.new_root),
            self.log_id
        );
        match self.signed_by {
            Some(k) => {
                s.push_str(&format!("  new root signed by {}\n", hex32(&k)));
                if self.signer_chain.len() > 1 {
                    s.push_str(&format!(
                        "  signer chain: {} key(s) via handovers\n",
                        self.signer_chain.len()
                    ));
                }
            }
            None => s.push_str(
                "  unsigned: only as strong as the roots you compare it with (--old / --new pins)\n",
            ),
        }
        s
    }
}

/// Check a consistency proof offline. Fails closed on size regression, a path that does not
/// rebuild both claimed roots (non-prefix, tampered or truncated), a bad HEAD signature, or pins
/// / signer requirements that do not match.
pub fn check_consistency(c: &Consistency, opts: &ConsistencyCheckOpts) -> Result<ConsistencyCheck> {
    let bad = |m: String| err(format!("consistency proof does not verify: {m}"));
    if c.old_size == 0 {
        return Err(bad("old-size is 0".into()));
    }
    if c.old_size > c.new_size {
        return Err(bad(format!(
            "old-size {} is larger than new-size {} (size regression: a rollback, not an extension)",
            c.old_size, c.new_size
        )));
    }
    let (old_root, new_root) = crate::merkle::roots_from_consistency(
        &c.leaf,
        c.old_size as usize,
        c.new_size as usize,
        &c.path,
    )
    .ok_or_else(|| {
        bad(format!(
            "path= has the wrong number of hashes for {} → {}",
            c.old_size, c.new_size
        ))
    })?;
    if new_root != c.new_root {
        return Err(bad(
            "the path does not lead to new-root= (leaf, path or root altered)".into(),
        ));
    }
    if old_root != c.old_root {
        return Err(bad(
            "the path does not rebuild old-root=: the old state is not a prefix of the new one (or the proof was altered)".into(),
        ));
    }
    let signed_by = match &c.head {
        None => None,
        Some(h) => {
            if c.old_size == c.new_size && h.chain != c.leaf {
                return Err(bad("head-chain= is not the chain of the last entry".into()));
            }
            let head = Head {
                seq: c.new_size,
                chain: h.chain,
                root: c.new_root,
                time: h.time,
                signer: Some(h.signer),
                sig: Some(h.sig),
            };
            if head.signature_ok(&c.log_id) != Some(true) {
                return Err(bad(
                    "the HEAD signature does not verify (wrong log, root or key)".into(),
                ));
            }
            Some(h.signer)
        }
    };
    let signer_chain = match signed_by {
        Some(pk) => handover_chain(&c.log_id, c.new_size, &c.handovers, pk).map_err(bad)?,
        None if !c.handovers.is_empty() => {
            return Err(bad("handover-N= lines in an unsigned proof".into()))
        }
        None => Vec::new(),
    };
    if let Some(want) = opts.signer {
        match signed_by {
            Some(_) if signer_chain.contains(&want) => {}
            Some(pk) => {
                return Err(bad(format!(
                    "signed by {}, not by the required key {} (nor handed over from it)",
                    hex32(&pk),
                    hex32(&want)
                )))
            }
            None => {
                return Err(bad(
                    "the proof is unsigned but --signer requires a signature".into(),
                ))
            }
        }
    }
    for (side, pin, size, root) in [
        ("old", opts.old, c.old_size, c.old_root),
        ("new", opts.new, c.new_size, c.new_root),
    ] {
        if let Some((s, r)) = pin {
            if s != size {
                return Err(bad(format!(
                    "the proof's {side} side is {size}:… but the pin is {s}:…"
                )));
            }
            if r != root {
                return Err(bad(format!(
                    "{side} root at {s} differs from the pinned anchor (history rewritten, or another log)"
                )));
            }
        }
    }
    Ok(ConsistencyCheck {
        log_id: c.log_id.clone(),
        old_size: c.old_size,
        old_root: c.old_root,
        new_size: c.new_size,
        new_root: c.new_root,
        signed_by,
        signer_chain,
    })
}
