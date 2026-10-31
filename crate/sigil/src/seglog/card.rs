//! `sigil log card` / `sigil log check-card`: a **card** is a small signed text file that commits,
//! under its own Merkle root, to a list of children: segment-log states (`SEQ:ROOT` of a log's
//! vouched HEAD, with that HEAD's signature when the log is signed) and/or other cards. Cards of
//! cards give roll-ups (daily logs → a monthly card → a yearly card). See "Cards" in
//! `docs/SEGMENT-LOG.md`.
//!
//! Format `sigil-log-card=1` (a new, separate file type; logs are not changed):
//!
//! ```text
//! sigil-log-card=1
//! name=2026-10
//! n=2
//! child-1=kind=log log=<id> size=31 root=<hex> chain=<hex> t=<unix> [signer=<hex> sig=<hex>]
//! child-2=kind=card name=2026-10-02 size=4 root=<hex> [signer=<hex> sig=<hex>]
//! root=<hex>
//! signer=<hex>          (optional)
//! sig=<hex>             (optional)
//! ```
//!
//! Leaf `i` = `SHA-256("sigil-card-child-v1\0" ‖ i ‖ "\0" ‖ line)`, root = `merkle::merkle_root`
//! of the leaves. The position is in every leaf, so the odd-last-node padding cannot fake an
//! extra child. The card signature (Ed25519, like a HEAD) covers name, n and root.

use super::*;

const CARD_MAGIC: &str = "sigil-log-card=1";

/// One child of a card.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum CardChild {
    Log {
        log_id: String,
        size: u64,
        root: [u8; 32],
        chain: [u8; 32],
        time: u64,
        signer: Option<([u8; 32], [u8; 64])>,
    },
    Card {
        name: String,
        size: u64,
        root: [u8; 32],
        signer: Option<([u8; 32], [u8; 64])>,
    },
}

impl CardChild {
    fn line(&self) -> String {
        let sig = |s: &Option<([u8; 32], [u8; 64])>| match s {
            Some((pk, sig)) => format!(" signer={} sig={}", hex32(pk), hex::encode(sig)),
            None => String::new(),
        };
        match self {
            CardChild::Log {
                log_id,
                size,
                root,
                chain,
                time,
                signer,
            } => format!(
                "kind=log log={log_id} size={size} root={} chain={} t={time}{}",
                hex32(root),
                hex32(chain),
                sig(signer)
            ),
            CardChild::Card {
                name,
                size,
                root,
                signer,
            } => format!(
                "kind=card name={name} size={size} root={}{}",
                hex32(root),
                sig(signer)
            ),
        }
    }

    fn parse(l: &str) -> Option<CardChild> {
        let kv: std::collections::BTreeMap<&str, &str> = l
            .split_whitespace()
            .filter_map(|t| t.split_once('='))
            .collect();
        let signer = match (kv.get("signer"), kv.get("sig")) {
            (None, None) => None,
            (Some(pk), Some(sig)) => Some((
                parse_hex32(pk)?,
                hex::decode(sig)
                    .ok()
                    .and_then(|b| <[u8; 64]>::try_from(b).ok())?,
            )),
            _ => return None,
        };
        let c = match *kv.get("kind")? {
            "log" => CardChild::Log {
                log_id: kv.get("log")?.to_string(),
                size: kv.get("size")?.parse().ok()?,
                root: parse_hex32(kv.get("root")?)?,
                chain: parse_hex32(kv.get("chain")?)?,
                time: kv.get("t")?.parse().ok()?,
                signer,
            },
            "card" => CardChild::Card {
                name: kv.get("name")?.to_string(),
                size: kv.get("size")?.parse().ok()?,
                root: parse_hex32(kv.get("root")?)?,
                signer,
            },
            _ => return None,
        };
        // canonical form only: the leaf hashes exactly this text
        (c.line() == l).then_some(c)
    }

    pub fn describe(&self) -> String {
        match self {
            CardChild::Log {
                log_id,
                size,
                root,
                signer,
                ..
            } => format!(
                "log {log_id} at {size}:{}{}",
                hex32(root),
                if signer.is_some() {
                    " (signed HEAD)"
                } else {
                    ""
                }
            ),
            CardChild::Card {
                name,
                size,
                root,
                signer,
            } => format!(
                "card {name} ({size} children) root {}{}",
                hex32(root),
                if signer.is_some() { " (signed)" } else { "" }
            ),
        }
    }
}

#[derive(Clone, Debug)]
pub struct Card {
    pub name: String,
    pub children: Vec<CardChild>,
    pub root: [u8; 32],
    pub signer: Option<([u8; 32], [u8; 64])>,
}

fn name_ok(n: &str) -> bool {
    !n.is_empty()
        && n.len() <= 128
        && n.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"._-:".contains(&b))
}

/// The first log id / card name that two children share.
fn duplicate(children: &[CardChild]) -> Option<String> {
    let key = |c: &CardChild| match c {
        CardChild::Log { log_id, .. } => format!("log {log_id}"),
        CardChild::Card { name, .. } => format!("card {name}"),
    };
    let mut seen = std::collections::BTreeSet::new();
    children.iter().map(key).find(|k| !seen.insert(k.clone()))
}

fn leaf(i: usize, line: &str) -> [u8; 32] {
    let mut b = format!("sigil-card-child-v1\0{i}\0").into_bytes();
    b.extend_from_slice(line.as_bytes());
    sha256(&b)
}

fn card_root(children: &[CardChild]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = children
        .iter()
        .enumerate()
        .map(|(i, c)| leaf(i + 1, &c.line()))
        .collect();
    crate::merkle::merkle_root(&leaves)
}

fn card_message(name: &str, n: usize, root: &[u8; 32]) -> Vec<u8> {
    format!("sigil-card-v1\nname={name}\nn={n}\nroot={}\n", hex32(root)).into_bytes()
}

fn sig_ok(pk: &[u8; 32], sig: &[u8; 64], msg: &[u8]) -> bool {
    VerifyingKey::from_bytes(pk)
        .map(|vk| vk.verify(msg, &Signature::from_bytes(sig)).is_ok())
        .unwrap_or(false)
}

impl Card {
    pub fn render(&self) -> String {
        let mut s = format!(
            "{CARD_MAGIC}\nname={}\nn={}\n",
            self.name,
            self.children.len()
        );
        for (i, c) in self.children.iter().enumerate() {
            s.push_str(&format!("child-{}={}\n", i + 1, c.line()));
        }
        s.push_str(&format!("root={}\n", hex32(&self.root)));
        if let Some((pk, sig)) = &self.signer {
            s.push_str(&format!("signer={}\nsig={}\n", hex32(pk), hex::encode(sig)));
        }
        s
    }

    /// Parse and check the card's own integrity: canonical child lines, `n`, the Merkle root and
    /// the card signature; every child's embedded signature (log HEAD or card). Children
    /// themselves are checked by [`check_card`].
    pub fn parse(text: &str) -> Result<Card> {
        let bad = |m: String| err(format!("card does not verify: {m}"));
        let mut lines = text.lines();
        if lines.next().map(str::trim) != Some(CARD_MAGIC) {
            return Err(err(format!(
                "not a sigil card (first line must be {CARD_MAGIC})"
            )));
        }
        let mut kv: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
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
        let name = need("name")?.to_string();
        if !name_ok(&name) {
            return Err(bad("name= must be 1-128 of A-Z a-z 0-9 . _ - :".into()));
        }
        let n: usize = need("n")?.parse().map_err(|_| bad("bad n=".into()))?;
        let mut children = Vec::with_capacity(n.min(1 << 16));
        for i in 1..=n {
            let l = need(&format!("child-{i}"))?;
            children.push(
                CardChild::parse(l)
                    .ok_or_else(|| bad(format!("child-{i} is not a canonical child line")))?,
            );
        }
        if kv.keys().filter(|k| k.starts_with("child-")).count() != n {
            return Err(bad(format!(
                "n={n} but a different number of child-N= lines"
            )));
        }
        if n == 0 {
            return Err(bad("a card needs at least one child".into()));
        }
        if let Some(d) = duplicate(&children) {
            return Err(bad(format!("{d} appears twice")));
        }
        let root = parse_hex32(need("root")?).ok_or_else(|| bad("bad root=".into()))?;
        if card_root(&children) != root {
            return Err(bad(
                "root= is not the Merkle root of the child lines (a child was added, removed, reordered or altered)".into(),
            ));
        }
        let signer = match (kv.get("signer"), kv.get("sig")) {
            (None, None) => None,
            (Some(pk), Some(sig)) => {
                let pk = parse_hex32(pk).ok_or_else(|| bad("bad signer=".into()))?;
                let sig = hex::decode(sig)
                    .ok()
                    .and_then(|b| <[u8; 64]>::try_from(b).ok())
                    .ok_or_else(|| bad("bad sig=".into()))?;
                if !sig_ok(&pk, &sig, &card_message(&name, n, &root)) {
                    return Err(bad("the card signature does not verify".into()));
                }
                Some((pk, sig))
            }
            _ => return Err(bad("signer= and sig= must come together".into())),
        };
        for (i, c) in children.iter().enumerate() {
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
                return Err(bad(format!(
                    "child-{}: its signature does not verify",
                    i + 1
                )));
            }
        }
        Ok(Card {
            name,
            children,
            root,
            signer,
        })
    }
}

/// The child entry for one input: a segment log (its vouched HEAD) or a card file.
fn child_of(path: &Path) -> Result<CardChild> {
    if path.is_file() {
        let text = fs::read_to_string(path).map_err(|e| err(format!("{}: {e}", path.display())))?;
        let c = Card::parse(&text).map_err(|e| err(format!("{}: {e}", path.display())))?;
        return Ok(CardChild::Card {
            name: c.name,
            size: c.children.len() as u64,
            root: c.root,
            signer: c.signer,
        });
    }
    let log = Log::open(path)?;
    let idx = read_index(&log)?;
    if let Some((line, code, msg)) = &idx.error {
        return Err(err(format!(
            "{}: INDEX line {line} is damaged ({code}: {msg}); run `sigil log verify` first",
            path.display()
        )));
    }
    let trusted = trusted_len(&log, &idx) as u64;
    let head = match read_head(&log) {
        Some(Ok(h)) if h.seq == trusted && h.seq > 0 => h,
        _ => {
            return Err(err(format!(
                "{}: no HEAD the log vouches for (empty, unsigned-and-headless, or HEAD/signature does not match); run `sigil log verify`",
                path.display()
            )))
        }
    };
    Ok(CardChild::Log {
        log_id: log.id.clone(),
        size: head.seq,
        root: head.root,
        chain: head.chain,
        time: head.time,
        signer: head.signer.zip(head.sig),
    })
}

/// Make a card named `name` over `inputs` (segment logs and/or card files, in this order),
/// signed with `sign` when given.
pub fn make_card(name: &str, inputs: &[PathBuf], sign: Option<&Identity>) -> Result<Card> {
    if !name_ok(name) {
        return Err(err("--name must be 1-128 of A-Z a-z 0-9 . _ - :"));
    }
    if inputs.is_empty() {
        return Err(err("a card needs at least one child (log or card)"));
    }
    let children = inputs
        .iter()
        .map(|p| child_of(p))
        .collect::<Result<Vec<_>>>()?;
    if let Some(d) = duplicate(&children) {
        return Err(err(format!(
            "{d} appears twice (one entry per log id / card name)"
        )));
    }
    let root = card_root(&children);
    let signer = sign.map(|id| {
        let sk = SigningKey::from_bytes(&id.ed25519_seed);
        (
            sk.verifying_key().to_bytes(),
            sk.sign(&card_message(name, children.len(), &root))
                .to_bytes(),
        )
    });
    Ok(Card {
        name: name.to_string(),
        children,
        root,
        signer,
    })
}

#[derive(Default)]
pub struct CardCheckOpts<'a> {
    /// Require the card signed by this key.
    pub signer: Option<[u8; 32]>,
    /// Logs / card files to check against their child entries.
    pub children: &'a [PathBuf],
    /// Every child entry must be matched by one of `children` (none missing).
    pub all: bool,
}

#[derive(Debug)]
pub struct CardCheck {
    pub name: String,
    pub root: [u8; 32],
    pub n: usize,
    pub signed_by: Option<[u8; 32]>,
    /// `(child number, what, how it was checked)`.
    pub checked: Vec<(usize, String, String)>,
}

impl CardCheck {
    pub fn render(&self) -> String {
        let mut s = format!(
            "card OK: {} ({} children) root {}{}\n",
            self.name,
            self.n,
            hex32(&self.root),
            match self.signed_by {
                Some(k) => format!(", signed by {}", hex32(&k)),
                None => ", unsigned".to_string(),
            }
        );
        for (i, what, how) in &self.checked {
            s.push_str(&format!("  child-{i}: {what}: {how}\n"));
        }
        s
    }
}

/// Check a card; with `opts.children`, also check those logs / cards against it. Fails closed on
/// a tampered card, a bad signature, a child that does not match (rewritten or rolled-back log,
/// different card), a given child the card does not list, and (with `all`) a missing child.
pub fn check_card(card: &Card, opts: &CardCheckOpts<'_>) -> Result<CardCheck> {
    let bad = |m: String| err(format!("card does not verify: {m}"));
    if let Some(want) = opts.signer {
        match card.signer {
            Some((pk, _)) if pk == want => {}
            Some((pk, _)) => {
                return Err(bad(format!(
                    "signed by {}, not by the required key {}",
                    hex32(&pk),
                    hex32(&want)
                )))
            }
            None => {
                return Err(bad(
                    "the card is unsigned but --signer requires a signature".into(),
                ))
            }
        }
    }
    let mut checked: Vec<(usize, String, String)> = Vec::new();
    for p in opts.children {
        let (i, how) = if p.is_file() {
            let text = fs::read_to_string(p).map_err(|e| err(format!("{}: {e}", p.display())))?;
            let sub = Card::parse(&text).map_err(|e| bad(format!("{}: {e}", p.display())))?;
            let i = card
                .children
                .iter()
                .position(|c| matches!(c, CardChild::Card { name, .. } if *name == sub.name))
                .ok_or_else(|| {
                    bad(format!(
                        "{}: card {} is not a child of this card",
                        p.display(),
                        sub.name
                    ))
                })?;
            if let CardChild::Card { size, root, .. } = &card.children[i] {
                if *root != sub.root || *size != sub.children.len() as u64 {
                    return Err(bad(format!(
                        "{}: card {} does not match child-{} (different root: altered or another card)",
                        p.display(),
                        sub.name,
                        i + 1
                    )));
                }
            }
            (i, "card file matches (root, children)".to_string())
        } else {
            let log =
                Log::open(p).map_err(|e| bad(format!("missing child {}: {e}", p.display())))?;
            let i = card
                .children
                .iter()
                .position(|c| matches!(c, CardChild::Log { log_id, .. } if *log_id == log.id))
                .ok_or_else(|| {
                    bad(format!(
                        "{}: log {} is not a child of this card",
                        p.display(),
                        log.id
                    ))
                })?;
            let CardChild::Log { size, root, .. } = &card.children[i] else {
                return Err(bad("internal: child kind".into()));
            };
            let idx = read_index(&log)?;
            let have = idx.entries.len() as u64;
            if have < *size {
                return Err(bad(format!(
                    "{}: the log has {have} valid entries but the card pins {size} (rolled back or damaged)",
                    p.display()
                )));
            }
            if root_of(&idx.entries[..*size as usize]) != *root {
                return Err(bad(format!(
                    "{}: root at {size} differs from the card (history rewritten, or another log)",
                    p.display()
                )));
            }
            (
                i,
                format!("log matches at {size} (now {have} entries; the card's state is a prefix)"),
            )
        };
        if checked.iter().any(|(j, _, _)| *j == i + 1) {
            return Err(bad(format!("child-{} is given twice", i + 1)));
        }
        checked.push((i + 1, card.children[i].describe(), how));
    }
    if opts.all {
        if let Some(i) = (1..=card.children.len()).find(|i| !checked.iter().any(|(j, _, _)| j == i))
        {
            return Err(bad(format!(
                "missing child-{}: {} (give it with --child)",
                i,
                card.children[i - 1].describe()
            )));
        }
    }
    checked.sort_by_key(|c| c.0);
    Ok(CardCheck {
        name: card.name.clone(),
        root: card.root,
        n: card.children.len(),
        signed_by: card.signer.map(|s| s.0),
        checked,
    })
}
