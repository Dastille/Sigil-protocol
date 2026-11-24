//! Card follow-ups: a **child receipt** (`log card-prove` / `log check-card-child`): one child of a
//! card with its Merkle path, so the rest of the card is not handed over; and **card consistency**
//! (`log check-card-consistency OLD NEW`): a later card keeps every child of an earlier one at the
//! same or a later state, each growth proved (see "Cards" in `docs/SEGMENT-LOG.md`).
//!
//! Receipt format `sigil-card-proof=1` (no new crypto: the card's leaf, Merkle path and signature):
//!
//! ```text
//! sigil-card-proof=1
//! name=2026-10
//! n=5
//! index=3
//! child=kind=log log=<id> size=31 root=<hex> chain=<hex> t=<unix> [signer=<hex> sig=<hex>]
//! path=<hex>,<hex>,…
//! root=<hex>
//! signer=<hex>          (when the card is signed)
//! sig=<hex>
//! ```

use super::card::{card_message, leaf, log_prefix_ok, match_child, sig_ok};
use super::*;

const PROOF_MAGIC: &str = "sigil-card-proof=1";

/// One child of a card and the path that ties it to the card root.
#[derive(Clone, Debug)]
pub struct CardChildProof {
    pub name: String,
    pub n: usize,
    /// 1-based child number.
    pub index: usize,
    pub child: CardChild,
    pub path: Vec<[u8; 32]>,
    pub root: [u8; 32],
    pub signer: Option<([u8; 32], [u8; 64])>,
}

/// Pick child `sel` of `card`: a 1-based number, a log id or a card name.
pub fn prove_card_child(card: &Card, sel: &str) -> Result<CardChildProof> {
    let i = match sel.parse::<usize>() {
        Ok(k) if (1..=card.children.len()).contains(&k) => k - 1,
        Ok(k) => {
            return Err(err(format!(
                "child {k}: the card has children 1..={}",
                card.children.len()
            )))
        }
        Err(_) => card
            .children
            .iter()
            .position(|c| match c {
                CardChild::Log { log_id, .. } => log_id == sel,
                CardChild::Card { name, .. } => name == sel,
            })
            .ok_or_else(|| {
                err(format!(
                    "no child {sel:?} in card {} (give a number, log id or card name)",
                    card.name
                ))
            })?,
    };
    let leaves: Vec<[u8; 32]> = card
        .children
        .iter()
        .enumerate()
        .map(|(k, c)| leaf(k + 1, &c.line()))
        .collect();
    let path = crate::merkle::merkle_path(&leaves, i)
        .ok_or_else(|| err("internal: no Merkle path for that child"))?;
    Ok(CardChildProof {
        name: card.name.clone(),
        n: card.children.len(),
        index: i + 1,
        child: card.children[i].clone(),
        path,
        root: card.root,
        signer: card.signer,
    })
}

impl CardChildProof {
    pub fn render(&self) -> String {
        let mut s = format!(
            "{PROOF_MAGIC}\nname={}\nn={}\nindex={}\nchild={}\npath={}\nroot={}\n",
            self.name,
            self.n,
            self.index,
            self.child.line(),
            self.path.iter().map(hex32).collect::<Vec<_>>().join(","),
            hex32(&self.root)
        );
        if let Some((pk, sig)) = &self.signer {
            s.push_str(&format!("signer={}\nsig={}\n", hex32(pk), hex::encode(sig)));
        }
        s
    }

    /// Parse a receipt (shape only; [`check_card_child`] verifies it).
    pub fn parse(text: &str) -> Result<CardChildProof> {
        let bad = |m: String| err(format!("card receipt does not verify: {m}"));
        let mut lines = text.lines();
        if lines.next().map(str::trim) != Some(PROOF_MAGIC) {
            return Err(err(format!(
                "not a sigil card receipt (first line must be {PROOF_MAGIC})"
            )));
        }
        let mut kv = std::collections::BTreeMap::new();
        for l in lines {
            let l = l.trim_end_matches('\r');
            if l.is_empty() {
                continue;
            }
            let (k, v) = l
                .split_once('=')
                .ok_or_else(|| bad(format!("bad line {l:?}")))?;
            if kv.insert(k, v).is_some() {
                return Err(bad(format!("duplicate {k}=")));
            }
        }
        let need = |k: &str| {
            kv.get(k)
                .copied()
                .ok_or_else(|| bad(format!("missing {k}=")))
        };
        let num =
            |k: &str| -> Result<usize> { need(k)?.parse().map_err(|_| bad(format!("bad {k}="))) };
        let path = match need("path")? {
            "" => Vec::new(),
            p => p
                .split(',')
                .map(parse_hex32)
                .collect::<Option<Vec<_>>>()
                .ok_or_else(|| bad("bad path=".into()))?,
        };
        let signer = match (kv.get("signer"), kv.get("sig")) {
            (None, None) => None,
            (Some(pk), Some(sig)) => Some((
                parse_hex32(pk).ok_or_else(|| bad("bad signer=".into()))?,
                hex::decode(sig)
                    .ok()
                    .and_then(|b| <[u8; 64]>::try_from(b).ok())
                    .ok_or_else(|| bad("bad sig=".into()))?,
            )),
            _ => return Err(bad("signer= and sig= must come together".into())),
        };
        Ok(CardChildProof {
            name: need("name")?.to_string(),
            n: num("n")?,
            index: num("index")?,
            child: CardChild::parse(need("child")?)
                .ok_or_else(|| bad("child= is not a canonical child line".into()))?,
            path,
            root: parse_hex32(need("root")?).ok_or_else(|| bad("bad root=".into()))?,
            signer,
        })
    }
}

#[derive(Default)]
pub struct CardChildCheckOpts<'a> {
    /// Require the card signed by this key.
    pub signer: Option<[u8; 32]>,
    /// Require the proved child to be this log id or card name.
    pub expect: Option<&'a str>,
    /// Also check this log / card file against the proved child.
    pub child: Option<&'a Path>,
}

#[derive(Debug)]
pub struct CardChildCheck {
    pub name: String,
    pub n: usize,
    pub index: usize,
    pub what: String,
    pub root: [u8; 32],
    pub signed_by: Option<[u8; 32]>,
    pub matched: Option<String>,
}

impl CardChildCheck {
    pub fn render(&self) -> String {
        let mut s = format!(
            "card receipt OK: child-{} of {} ({} children) root {}{}\n  child-{}: {}\n",
            self.index,
            self.name,
            self.n,
            hex32(&self.root),
            match self.signed_by {
                Some(k) => format!(", signed by {}", hex32(&k)),
                None => ", unsigned".to_string(),
            },
            self.index,
            self.what
        );
        if let Some(m) = &self.matched {
            s.push_str(&format!("  {m}\n"));
        }
        s
    }
}

/// Verify a child receipt offline: the child line hashes (with its position) up the path to the
/// card root, the card signature covers name, n and that root, the child's own signature verifies;
/// then the optional `--signer`, `--expect` and `--child` requirements. Fails closed.
pub fn check_card_child(
    p: &CardChildProof,
    opts: &CardChildCheckOpts<'_>,
) -> Result<CardChildCheck> {
    let bad = |m: String| err(format!("card receipt does not verify: {m}"));
    if p.n == 0 || p.index == 0 || p.index > p.n {
        return Err(bad(format!("index={} outside 1..={}", p.index, p.n)));
    }
    let got =
        crate::merkle::root_from_path(&leaf(p.index, &p.child.line()), p.index - 1, p.n, &p.path);
    if got != Some(p.root) {
        return Err(bad(
            "the child and path do not lead to root= (altered child, position or path)".into(),
        ));
    }
    if let Some((pk, sig)) = &p.signer {
        if !sig_ok(pk, sig, &card_message(&p.name, p.n, &p.root)) {
            return Err(bad("the card signature does not verify".into()));
        }
    }
    // the child's own embedded signature, as Card::parse checks it
    let one = Card {
        name: p.name.clone(),
        children: vec![p.child.clone()],
        root: [0; 32],
        signer: None,
    };
    child_sigs_ok(&one).map_err(|m| bad(format!("child-{}: {m}", p.index)))?;
    match (opts.signer, p.signer) {
        (None, _) => {}
        (Some(w), Some((pk, _))) if pk == w => {}
        (Some(w), Some((pk, _))) => {
            return Err(bad(format!(
                "signed by {}, not by the required key {}",
                hex32(&pk),
                hex32(&w)
            )))
        }
        (Some(_), None) => {
            return Err(bad(
                "the card is unsigned but --signer requires a signature".into(),
            ))
        }
    }
    if let Some(e) = opts.expect {
        let is = match &p.child {
            CardChild::Log { log_id, .. } => log_id == e,
            CardChild::Card { name, .. } => name == e,
        };
        if !is {
            return Err(bad(format!(
                "the proved child is {}, not {e:?}",
                p.child.describe()
            )));
        }
    }
    let matched = match opts.child {
        Some(c) => Some(match_child(std::slice::from_ref(&p.child), c, "the proved child")?.1),
        None => None,
    };
    Ok(CardChildCheck {
        name: p.name.clone(),
        n: p.n,
        index: p.index,
        what: p.child.describe(),
        root: p.root,
        signed_by: p.signer.map(|s| s.0),
        matched,
    })
}

/// The embedded signatures of `card`'s children (log HEAD / card), as `Card::parse` checks them.
fn child_sigs_ok(card: &Card) -> std::result::Result<(), String> {
    for c in &card.children {
        let ok = match c {
            CardChild::Log {
                log_id,
                size,
                root,
                chain,
                time,
                signer: Some((pk, sig)),
            } => {
                Head {
                    seq: *size,
                    chain: *chain,
                    root: *root,
                    time: *time,
                    signer: Some(*pk),
                    sig: Some(*sig),
                }
                .signature_ok(log_id)
                    == Some(true)
            }
            CardChild::Card {
                name,
                size,
                root,
                signer: Some((pk, sig)),
            } => sig_ok(pk, sig, &card_message(name, *size as usize, root)),
            _ => true,
        };
        if !ok {
            return Err("its signature does not verify".into());
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// card consistency
// ---------------------------------------------------------------------------

#[derive(Default)]
pub struct CardConsistencyOpts<'a> {
    /// Require both cards signed by this key.
    pub signer: Option<[u8; 32]>,
    /// Child logs: a grown log child is proved by the log's own INDEX (both roots are prefixes).
    pub logs: &'a [PathBuf],
    /// `sigil-log-consistency` proofs (from `log prove-consistency`) for grown log children.
    pub proofs: &'a [PathBuf],
    /// `(old, new)` versions of nested cards that changed, checked recursively.
    pub pairs: &'a [(PathBuf, PathBuf)],
}

#[derive(Debug, Default)]
pub struct CardConsistency {
    pub name: String,
    pub old_n: usize,
    pub new_n: usize,
    /// One line per old child: how it was carried into the new card.
    pub kept: Vec<String>,
    /// Children only the new card has.
    pub added: Vec<String>,
}

impl CardConsistency {
    pub fn render(&self) -> String {
        let mut s = format!(
            "card consistency OK: {} ({} → {} children)\n",
            self.name, self.old_n, self.new_n
        );
        for k in &self.kept {
            s.push_str(&format!("  = {k}\n"));
        }
        for a in &self.added {
            s.push_str(&format!("  + {a} (new)\n"));
        }
        s
    }
}

fn key(c: &CardChild) -> String {
    match c {
        CardChild::Log { log_id, .. } => format!("log {log_id}"),
        CardChild::Card { name, .. } => format!("card {name}"),
    }
}

fn read_card(p: &Path) -> Result<Card> {
    let t = fs::read_to_string(p).map_err(|e| err(format!("{}: {e}", p.display())))?;
    Card::parse(&t).map_err(|e| err(format!("{}: {e}", p.display())))
}

/// `new` is consistent with `old` when: both verify; same name; the new card is signed by the old
/// card's signer (or both by `--signer`); and **every** old child is in the new card, either
/// identical or at a later state proved to extend it: a log child by its INDEX (`--child LOG`) or a
/// consistency proof (`--proof`), a nested card by a recursive check of both versions (`--pair`).
/// Children only the new card lists are allowed (reported). Anything unproved fails.
pub fn check_card_consistency(
    old: &Card,
    new: &Card,
    opts: &CardConsistencyOpts<'_>,
) -> Result<CardConsistency> {
    consistency_at(old, new, opts, 0)
}

fn consistency_at(
    old: &Card,
    new: &Card,
    opts: &CardConsistencyOpts<'_>,
    depth: usize,
) -> Result<CardConsistency> {
    let bad = |m: String| err(format!("cards are not consistent: {m}"));
    if depth > 16 {
        return Err(bad("nested cards deeper than 16".into()));
    }
    if old.name != new.name {
        return Err(bad(format!(
            "different names ({} vs {})",
            old.name, new.name
        )));
    }
    let who = |c: &Card| c.signer.map(|s| s.0);
    if depth == 0 {
        if let Some(w) = opts.signer {
            for (side, c) in [("old", old), ("new", new)] {
                if who(c) != Some(w) {
                    return Err(bad(format!(
                        "the {side} card is not signed by the required key {}",
                        hex32(&w)
                    )));
                }
            }
        }
    }
    if let Some(o) = who(old) {
        if who(new) != Some(o) {
            return Err(bad(format!(
                "the old card is signed by {} but the new one is {}",
                hex32(&o),
                who(new).map_or("unsigned".to_string(), |k| format!(
                    "signed by {}",
                    hex32(&k)
                ))
            )));
        }
    }
    let mut rep = CardConsistency {
        name: new.name.clone(),
        old_n: old.children.len(),
        new_n: new.children.len(),
        ..Default::default()
    };
    for oc in &old.children {
        let nc = new
            .children
            .iter()
            .find(|c| key(c) == key(oc))
            .ok_or_else(|| bad(format!("{} was dropped from the new card", oc.describe())))?;
        if nc == oc {
            rep.kept.push(format!("{}: unchanged", oc.describe()));
            continue;
        }
        let how = match (oc, nc) {
            (
                CardChild::Log {
                    log_id,
                    size: os,
                    root: or,
                    ..
                },
                CardChild::Log {
                    size: ns, root: nr, ..
                },
            ) => {
                if ns < os || (ns == os && nr != or) {
                    return Err(bad(format!(
                        "log {log_id}: {os}:{} → {ns}:{} goes back or forks",
                        hex32(or),
                        hex32(nr)
                    )));
                }
                if ns == os {
                    // same size and root, other fields (time / HEAD signature) differ: still the same state
                    "same state, re-signed HEAD".to_string()
                } else {
                    log_grew(log_id, (*os, or), (*ns, nr), opts)
                        .map_err(|m| bad(format!("log {log_id} {os} → {ns}: {m}")))?
                }
            }
            (
                CardChild::Card {
                    name,
                    root: or,
                    size: os,
                    ..
                },
                CardChild::Card {
                    root: nr, size: ns, ..
                },
            ) => {
                let pair = opts.pairs.iter().find_map(|(a, b)| {
                    let (a, b) = (read_card(a).ok()?, read_card(b).ok()?);
                    (a.name == *name
                        && a.root == *or
                        && a.children.len() as u64 == *os
                        && b.root == *nr
                        && b.children.len() as u64 == *ns)
                        .then_some((a, b))
                });
                let (a, b) = pair.ok_or_else(|| {
                    bad(format!(
                        "nested card {name} changed; give both versions with --pair OLD NEW"
                    ))
                })?;
                let sub = consistency_at(&a, &b, opts, depth + 1)?;
                format!(
                    "nested card consistent ({} → {} children)",
                    sub.old_n, sub.new_n
                )
            }
            _ => return Err(bad(format!("{} changed kind", oc.describe()))),
        };
        rep.kept.push(format!("{}: {how}", nc.describe()));
    }
    for nc in &new.children {
        if !old.children.iter().any(|c| key(c) == key(nc)) {
            rep.added.push(nc.describe());
        }
    }
    Ok(rep)
}

/// Prove that log `id` at `old` extends to `new`: by a given log's INDEX, or a consistency proof.
fn log_grew(
    id: &str,
    old: (u64, &[u8; 32]),
    new: (u64, &[u8; 32]),
    opts: &CardConsistencyOpts<'_>,
) -> std::result::Result<String, String> {
    for p in opts.logs {
        let Ok(log) = Log::open(p) else { continue };
        if log.id != id {
            continue;
        }
        log_prefix_ok(&log, old.0, old.1)?;
        log_prefix_ok(&log, new.0, new.1)?;
        return Ok(format!("grew, both states are prefixes of {}", p.display()));
    }
    for p in opts.proofs {
        let Ok(t) = fs::read_to_string(p) else {
            continue;
        };
        let Ok(c) = Consistency::parse(&t) else {
            continue;
        };
        if c.log_id != id || c.old_size != old.0 || c.new_size != new.0 {
            continue;
        }
        check_consistency(
            &c,
            &ConsistencyCheckOpts {
                old: Some((old.0, *old.1)),
                new: Some((new.0, *new.1)),
                signer: None,
            },
        )
        .map_err(|e| format!("{}: {e}", p.display()))?;
        return Ok(format!("grew, proved by {}", p.display()));
    }
    Err("grew, but no proof: give the log with --child or a `log prove-consistency` file with --proof".into())
}
