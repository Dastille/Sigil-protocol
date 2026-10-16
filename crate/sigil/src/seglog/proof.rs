//! `sigil log prove` / `sigil log check-proof`: a portable receipt that one INDEX entry is part
//! of a log. See "Inclusion proofs" in `docs/SEGMENT-LOG.md`.
//!
//! A proof carries the entry's INDEX line, the previous entry's chain hash, and a Merkle path from
//! that entry's chain hash to the root over the first `size` entries (the same root `log ls` prints
//! as the `SEQ:ROOT` anchor). When `size` is the HEAD of a signed log, the HEAD's signature fields
//! come along, so the receipt verifies offline with nothing but the signer's public key.
//! When the signer was rotated before `size`, the handover entries come along too
//! (`handover-1=`, …), so `--signer` can name any key of the chain (e.g. the one pinned at init).
//! Purely additive: no new file in the log, no layout change; the INDEX is only read.

use super::*;

const PROOF_MAGIC: &str = "sigil-log-proof=1";

/// The signed HEAD a proof was cut against (only when `size` equals that HEAD's seq).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ProofHead {
    /// Chain hash of entry `size`.
    pub chain: [u8; 32],
    pub time: u64,
    pub signer: [u8; 32],
    pub sig: [u8; 64],
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Proof {
    pub log_id: String,
    /// Informational (not covered by anything).
    pub name: String,
    /// The full INDEX line (`… chain=<hex>`).
    pub line: String,
    /// Chain hash of the entry before it (the genesis hash for seq 1).
    pub prev: [u8; 32],
    /// Number of INDEX entries the root covers.
    pub size: u64,
    pub path: Vec<[u8; 32]>,
    pub root: [u8; 32],
    pub head: Option<ProofHead>,
    /// Signer handover entries before `size` (full INDEX lines, ascending), when signed: they
    /// connect the HEAD's signer to the earlier signers. Each carries the outgoing key's signature.
    pub handovers: Vec<String>,
}

/// `(seq, from, to, sig)` of a handover entry.
type HandoverFields = (u64, [u8; 32], [u8; 32], [u8; 64]);

/// The fields of a handover INDEX line (no chain check: it needs no neighbour).
fn parse_handover(line: &str) -> Option<HandoverFields> {
    let body = &line[..line.rfind(" chain=")?];
    let kv: std::collections::BTreeMap<&str, &str> = body
        .split_whitespace()
        .filter_map(|t| t.split_once('='))
        .collect();
    if kv.get("op") != Some(&"signer") {
        return None;
    }
    Some((
        kv.get("seq")?.parse().ok()?,
        parse_hex32(kv.get("from")?)?,
        parse_hex32(kv.get("to")?)?,
        parse_hex64(kv.get("sig")?)?,
    ))
}

impl Proof {
    pub fn render(&self) -> String {
        let mut s = format!("{PROOF_MAGIC}\nlog={}\n", self.log_id);
        if !self.name.is_empty() && !self.name.contains('\n') {
            s.push_str(&format!("name={}\n", self.name));
        }
        s.push_str(&format!(
            "entry={}\nprev={}\nsize={}\n",
            self.line,
            hex32(&self.prev),
            self.size
        ));
        s.push_str(&format!(
            "path={}\n",
            self.path.iter().map(hex32).collect::<Vec<_>>().join(",")
        ));
        s.push_str(&format!("root={}\n", hex32(&self.root)));
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

    pub fn parse(text: &str) -> Result<Proof> {
        let mut lines = text.lines();
        if lines.next().map(str::trim) != Some(PROOF_MAGIC) {
            return Err(err(format!(
                "not a sigil log proof (first line must be {PROOF_MAGIC})"
            )));
        }
        let mut kv: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
        for l in lines {
            let l = l.trim_end_matches('\r');
            if l.trim().is_empty() || l.starts_with('#') {
                continue;
            }
            let Some((k, v)) = l.split_once('=') else {
                return Err(err(format!("proof: bad line {l:?}")));
            };
            if kv.insert(k.trim(), v).is_some() {
                return Err(err(format!("proof: duplicate {k}=")));
            }
        }
        let need = |k: &str| {
            kv.get(k)
                .copied()
                .ok_or_else(|| err(format!("proof: missing {k}=")))
        };
        let h32 = |k: &str| -> Result<[u8; 32]> {
            parse_hex32(need(k)?.trim()).ok_or_else(|| err(format!("proof: bad {k}=")))
        };
        let path_s = need("path")?.trim();
        let path = if path_s.is_empty() {
            Vec::new()
        } else {
            path_s
                .split(',')
                .map(|p| parse_hex32(p.trim()).ok_or_else(|| err("proof: bad path= hash")))
                .collect::<Result<Vec<_>>>()?
        };
        let head = match (kv.get("signer"), kv.get("sig")) {
            (None, None) => None,
            (Some(_), Some(sig)) => Some(ProofHead {
                chain: h32("head-chain")?,
                time: need("head-t")?
                    .trim()
                    .parse()
                    .map_err(|_| err("proof: bad head-t="))?,
                signer: h32("signer")?,
                sig: hex::decode(sig.trim())
                    .ok()
                    .and_then(|b| <[u8; 64]>::try_from(b).ok())
                    .ok_or_else(|| err("proof: bad sig="))?,
            }),
            _ => return Err(err("proof: signer= and sig= must come together")),
        };
        let mut handovers = Vec::new();
        while let Some(l) = kv.get(format!("handover-{}", handovers.len() + 1).as_str()) {
            handovers.push(l.to_string());
        }
        if kv.keys().filter(|k| k.starts_with("handover-")).count() != handovers.len() {
            return Err(err(
                "proof: handover-N= lines must be numbered 1, 2, … without gaps",
            ));
        }
        Ok(Proof {
            log_id: need("log")?.trim().to_string(),
            name: kv
                .get("name")
                .map(|s| s.trim().to_string())
                .unwrap_or_default(),
            line: need("entry")?.to_string(),
            prev: h32("prev")?,
            size: need("size")?
                .trim()
                .parse()
                .map_err(|_| err("proof: bad size="))?,
            path,
            root: h32("root")?,
            head,
            handovers,
        })
    }
}

/// Cut a proof that entry `seq` is in the log. By default against the HEAD the log vouches for
/// (signed when the log is signed); `at = Some(m)` proves it against the root over the first `m`
/// entries instead (an older anchor you pinned), signed only if `m` is the HEAD's seq.
pub fn prove(path: &Path, seq: u64, at: Option<u64>) -> Result<Proof> {
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
    let size = match at {
        Some(m) => {
            if m > n {
                return Err(err(format!("--at {m}: the INDEX has only {n} entries")));
            }
            m
        }
        None => {
            if trusted == 0 {
                return Err(err(if log.signer.is_some() {
                    "HEAD is missing or its signature does not verify, so nothing in this log can be proved; run `sigil log verify`"
                } else {
                    "the log is empty or its HEAD does not match the INDEX; run `sigil log verify`"
                }));
            }
            trusted
        }
    };
    if seq == 0 || seq > size {
        return Err(err(format!(
            "seq {seq} is not among the {size} entries being proved (1..={size})"
        )));
    }
    let entries = &idx.entries[..size as usize];
    let leaves: Vec<[u8; 32]> = entries.iter().map(|e| e.chain).collect();
    let i = (seq - 1) as usize;
    let e = &entries[i];
    let signed = head.as_ref().filter(|h| h.seq == size).and_then(|h| {
        Some(ProofHead {
            chain: h.chain,
            time: h.time,
            signer: h.signer?,
            sig: h.sig?,
        })
    });
    let is_signed = signed.is_some();
    Ok(Proof {
        log_id: log.id.clone(),
        name: log.name.clone(),
        line: format!("{} chain={}", e.body, hex32(&e.chain)),
        prev: if i == 0 {
            log.genesis()
        } else {
            entries[i - 1].chain
        },
        size,
        // Infallible: `seq` was range-checked against `size`, so `i < leaves.len()`.
        path: crate::merkle::merkle_path(&leaves, i).expect("index in range"),
        root: root_of(entries),
        head: signed,
        // the handovers that bring the HEAD's signer back to the earlier ones (see `signer_chain`)
        handovers: if is_signed {
            entries
                .iter()
                .filter(|e| e.is_handover() && e.seq < size)
                .map(|e| format!("{} chain={}", e.body, hex32(&e.chain)))
                .collect()
        } else {
            Vec::new()
        },
    })
}

#[derive(Default)]
pub struct ProofCheckOpts {
    /// Require the proof to be signed by this Ed25519 key.
    pub signer: Option<[u8; 32]>,
    /// Require the proof to be against exactly this pinned `SEQ:ROOT`.
    pub anchor: Option<(u64, [u8; 32])>,
    /// Require the entry's plain bytes to be exactly these (SHA-256, length).
    pub file: Option<([u8; 32], u64)>,
}

#[derive(Debug)]
pub struct ProofCheck {
    pub log_id: String,
    pub name: String,
    pub entry: Entry,
    pub size: u64,
    pub root: [u8; 32],
    /// The key whose valid signature covers the root (None = unsigned proof).
    pub signed_by: Option<[u8; 32]>,
    /// Signers the proof's handovers connect, oldest first, ending with `signed_by` (just
    /// `[signed_by]` without handovers; empty when unsigned).
    pub signer_chain: Vec<[u8; 32]>,
    pub file_matched: bool,
}

impl ProofCheck {
    pub fn render(&self) -> String {
        let e = &self.entry;
        let what = match &e.op {
            Op::Seg => format!("segment, {} byte(s), sha {}", e.size, hex32(&e.sha)),
            Op::Compact { of } => format!(
                "compaction of {}, {} byte(s), sha {}",
                fmt_ranges(of),
                e.size,
                hex32(&e.sha)
            ),
            Op::Tomb { del, shred, .. } => format!(
                "{} of {}",
                if *shred { "crypto-shred" } else { "tombstone" },
                fmt_ranges(del)
            ),
            Op::Signer { from, to, .. } => format!(
                "signer handover {}… → {}…",
                &hex32(from)[..16],
                &hex32(to)[..16]
            ),
        };
        let mut s = format!(
            "proof ok: entry {} ({what}, appended {}) is in log {}{}\n  at anchor {}:{}\n",
            e.seq,
            iso_utc(e.time),
            self.log_id,
            if self.name.is_empty() {
                String::new()
            } else {
                format!(" ({})", self.name)
            },
            self.size,
            hex32(&self.root)
        );
        if self.file_matched {
            s.push_str("  file matches the entry's bytes (SHA-256 and size)\n");
        }
        match &self.signed_by {
            Some(pk) => {
                s.push_str(&format!("  signed by {}\n", hex32(pk)));
                if self.signer_chain.len() > 1 {
                    s.push_str(&format!(
                        "  signer handed over: {} (each handover signed by the outgoing key)\n",
                        self.signer_chain.iter().map(|k| format!("{}…", &hex32(k)[..16])).collect::<Vec<_>>().join(" → ")
                    ));
                }
            }
            None => s.push_str(
                "  unsigned: only as strong as the root you compare it with (check the anchor against one you pinned, or use a signed log)\n",
            ),
        }
        s
    }
}

/// Check a proof offline (no access to the log). Any mismatch is an error naming what failed.
pub fn check_proof(p: &Proof, opts: &ProofCheckOpts) -> Result<ProofCheck> {
    let bad = |m: String| err(format!("proof does not verify: {m}"));
    let seq = p
        .line
        .split_whitespace()
        .find_map(|t| t.strip_prefix("seq="))
        .and_then(|v| v.parse::<u64>().ok())
        .ok_or_else(|| bad("entry= has no seq".into()))?;
    if seq == 0 || seq > p.size {
        return Err(bad(format!(
            "entry seq {seq} is outside the {} entries the root covers",
            p.size
        )));
    }
    let probe = Log {
        dir: PathBuf::new(),
        name: String::new(),
        id: p.log_id.clone(),
        signer: None,
        format: LOG_FORMAT,
        segkeys: false,
    };
    if seq == 1 && p.prev != probe.genesis() {
        return Err(bad(
            "entry 1 must follow the log's genesis hash (prev= is not it)".into(),
        ));
    }
    let entry =
        parse_line(&p.line, seq, &p.prev).map_err(|(code, m)| bad(format!("{code}: {m}")))?;
    if let Op::Signer { from, to, sig } = &entry.op {
        if !handover_sig_ok(&p.log_id, seq, from, to, sig) {
            return Err(bad(
                "the entry is a signer handover whose signature does not verify (forged)".into(),
            ));
        }
    }
    let root =
        crate::merkle::root_from_path(&entry.chain, (seq - 1) as usize, p.size as usize, &p.path)
            .ok_or_else(|| {
            bad(format!(
                "path= has the wrong number of hashes for entry {seq} of {}",
                p.size
            ))
        })?;
    if root != p.root {
        return Err(bad(
            "the Merkle path does not lead to root= (entry, path or root altered)".into(),
        ));
    }
    let signed_by = match &p.head {
        None => None,
        Some(h) => {
            if seq == p.size && h.chain != entry.chain {
                return Err(bad(
                    "head-chain= is not the chain of the last covered entry".into(),
                ));
            }
            let head = Head {
                seq: p.size,
                chain: h.chain,
                root: p.root,
                time: h.time,
                signer: Some(h.signer),
                sig: Some(h.sig),
            };
            if head.signature_ok(&p.log_id) != Some(true) {
                return Err(bad(
                    "the HEAD signature does not verify (wrong log, root or key)".into(),
                ));
            }
            Some(h.signer)
        }
    };
    // Handovers: each valid under its outgoing key, in order, before `size`, ending at HEAD's signer.
    let mut signer_chain: Vec<[u8; 32]> = Vec::new();
    if let Some(pk) = signed_by {
        let mut last_seq = 0u64;
        for (i, l) in p.handovers.iter().enumerate() {
            let (hseq, from, to, sig) = parse_handover(l)
                .ok_or_else(|| bad(format!("handover-{} is not a signer handover line", i + 1)))?;
            if hseq <= last_seq || hseq >= p.size {
                return Err(bad(format!(
                    "handover-{} (seq {hseq}) is out of order or not before entry {}",
                    i + 1,
                    p.size
                )));
            }
            if signer_chain.last().is_some_and(|c| *c != from) {
                return Err(bad(format!(
                    "handover-{} is not from the key the previous one handed over to",
                    i + 1
                )));
            }
            if !handover_sig_ok(&p.log_id, hseq, &from, &to, &sig) {
                return Err(bad(format!("handover-{} signature does not verify (forged, or from another log / position)", i + 1)));
            }
            if signer_chain.is_empty() {
                signer_chain.push(from);
            }
            signer_chain.push(to);
            last_seq = hseq;
        }
        match signer_chain.last() {
            None => signer_chain.push(pk),
            Some(last) if *last != pk => {
                return Err(bad(
                    "the handovers do not end at the key that signed HEAD".into()
                ))
            }
            Some(_) => {}
        }
    } else if !p.handovers.is_empty() {
        return Err(bad("handover-N= lines in an unsigned proof".into()));
    }
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
    if let Some((aseq, aroot)) = opts.anchor {
        if aseq != p.size {
            return Err(bad(format!(
                "the proof is against {}:… but the anchor is {aseq}:… (cut one for it with `sigil log prove --at {aseq}`)",
                p.size
            )));
        }
        if aroot != p.root {
            return Err(bad(format!(
                "root at {aseq} differs from the pinned anchor (history rewritten, or another log)"
            )));
        }
    }
    let file_matched = match opts.file {
        None => false,
        Some((sha, len)) => {
            if matches!(entry.op, Op::Tomb { .. }) {
                return Err(bad(
                    "--file given, but this entry is a tombstone (it holds no bytes)".into(),
                ));
            }
            if matches!(entry.op, Op::Signer { .. }) {
                return Err(bad(
                    "--file given, but this entry is a signer handover (it holds no bytes)".into(),
                ));
            }
            if sha != entry.sha || len != entry.size {
                return Err(bad(format!(
                    "the file is not this entry's bytes (entry: {} byte(s), sha {})",
                    entry.size,
                    hex32(&entry.sha)
                )));
            }
            true
        }
    };
    Ok(ProofCheck {
        log_id: p.log_id.clone(),
        name: p.name.clone(),
        entry,
        size: p.size,
        root,
        signed_by,
        signer_chain,
        file_matched,
    })
}
