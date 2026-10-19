//! Segment log: an append-only, tamper-evident log of sealed batches inside a
//! `name.sigil/` container (`kind=log`).
//!
//! ```text
//! events.sigil/
//!   CONTAINER                     sigil-container=1  kind=log  name=events  log=1  log-id=…  [signer=…]
//!   INDEX                         one hash-chained line per segment (append-only text)
//!   HEAD                          latest seq + chain + Merkle root, optionally Ed25519-signed
//!   segments/0000/0000000001.sg1  immutable sealed segment stars (any .sg1: ECC, pass, encrypt-to)
//! ```
//!
//! Slice 2 adds two chain-covered entry types that carry no segment of their own
//! (`op=tomb`: delete markers; `op=compact`: merged replacement segments). A log that never uses
//! them stays `log=1` and byte-compatible with slice 1; the first one flips the manifest to `log=2`.
//!
//! Slice 3 adds opt-in **per-segment keys** (`init --segment-keys`, `log=3`): every segment is sealed
//! under its own random key, the keys live (wrapped to the log's recipients / passphrase) in a small
//! sharded key ring (`keys/NNNN.sg1`), and `sigil log shred` destroys a key so the ciphertext stays
//! unreadable while the INDEX, Merkle root and anchors verify exactly as before (`keyring.rs`).
//!
//! Signer rotation (`log=4`, opt-in by use): `sigil log rotate-signer` appends one chain-covered
//! `op=signer` entry in which the outgoing signer hands the log over to a new Ed25519 key, signed
//! with its own key (`rotate.rs`). Verification follows the chain of handovers from the key pinned at
//! `init`; a log that is never rotated stays at its format, byte for byte.
//!
//! Each `append` seals one batch as a normal `.sg1` star (so ECC, `sigil mend`, passphrase
//! and encrypt-to all work unchanged), then appends a chained INDEX line, then rewrites HEAD.
//! The `.sg1` byte layout is untouched; a log is only folder structure plus two small text
//! files. See `docs/SEGMENT-LOG.md`.

use std::fs;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};

use crate::container;
use crate::doctor::{health_bytes, Finding, Health, Severity};
use crate::keys::{Identity, PublicIdentity};
use crate::{hex32, sha256, Mode, Result};

pub const KIND: &str = "log";
/// Highest log format this sigil understands. `log=1` = segments only (slice 1);
/// `log=2` = the INDEX may also hold tombstone / compaction entries (slice 2);
/// `log=3` = per-segment keys (`segkeys=1`, a `keys/` key ring, shred entries) (slice 3);
/// `log=4` = the INDEX may also hold signer handover entries (`op=signer`, `log rotate-signer`).
pub const LOG_FORMAT: u32 = 4;
/// What `init` writes, and what a log stays at until it first needs a newer feature.
pub const LOG_BASE_FORMAT: u32 = 1;
pub const INDEX_FILE: &str = "INDEX";
pub const HEAD_FILE: &str = "HEAD";
pub const LOCK_FILE: &str = "LOG.lock";
pub const SEGMENTS_DIR: &str = "segments";
/// Key ring folder of a log made with `init --segment-keys` (`keys/0000.sg1`, one star per 1000 segments).
pub const KEYS_DIR: &str = "keys";
const INDEX_MAGIC: &str = "sigil-log-index=1";
const HEAD_MAGIC: &str = "sigil-log-head=1";
const SEGMENTS_PER_FOLDER: u64 = 1000;

fn err(s: impl Into<String>) -> crate::Error {
    crate::Error::Msg(s.into())
}

fn io(e: std::io::Error) -> crate::Error {
    err(e.to_string())
}

fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

// ---------------------------------------------------------------------------
// Opening
// ---------------------------------------------------------------------------

/// An opened log container.
#[derive(Clone, Debug)]
pub struct Log {
    pub dir: PathBuf,
    pub name: String,
    pub id: String,
    /// Ed25519 public key pinned at `init --identity`: the first signer. Handover entries in the
    /// INDEX (`op=signer`) pass the authority on; see `signer_for`.
    pub signer: Option<[u8; 32]>,
    /// Manifest `log=N` (1 until the first tombstone / compaction entry; 3 for a segment-keys log).
    pub format: u32,
    /// `segkeys=1`: every segment is sealed under its own key, kept in the key ring (slice 3).
    pub segkeys: bool,
}

/// True when `path` (or `path.sigil`) is a log container.
pub fn is_log(path: &Path) -> bool {
    resolve_dir(path).is_some()
}

fn resolve_dir(path: &Path) -> Option<PathBuf> {
    let path = path.components().as_path().to_path_buf();
    [path.clone(), container::with_suffix(&path)]
        .into_iter()
        .find(|cand| {
            container::is_container(cand)
                && container::read_manifest(cand)
                    .map(|m| m.kind == KIND)
                    .unwrap_or(false)
        })
}

impl Log {
    pub fn open(path: &Path) -> Result<Log> {
        let dir = resolve_dir(path).ok_or_else(|| {
            err(format!(
                "{} is not a segment log (`sigil log init` creates one)",
                path.display()
            ))
        })?;
        Self::open_dir(&dir)
    }

    fn open_dir(dir: &Path) -> Result<Log> {
        let m = container::read_manifest(dir)?;
        if m.kind != KIND {
            return Err(err(format!(
                "{} is a {} container, not a segment log",
                dir.display(),
                m.kind
            )));
        }
        let fmt = m
            .extra
            .get("log")
            .and_then(|v| v.trim().parse::<u32>().ok())
            .unwrap_or(0);
        if fmt == 0 {
            return Err(err("segment log manifest has no log=N"));
        }
        if fmt > LOG_FORMAT {
            return Err(err(format!(
                "segment log format {fmt} is newer than this sigil understands ({LOG_FORMAT}); upgrade sigil"
            )));
        }
        let id = m
            .extra
            .get("log-id")
            .cloned()
            .ok_or_else(|| err("segment log manifest has no log-id"))?;
        let signer = match m.extra.get("signer") {
            Some(h) => Some(parse_hex32(h).ok_or_else(|| err("bad signer= in manifest"))?),
            None => None,
        };
        let segkeys = match m.extra.get("segkeys").map(|v| v.trim()) {
            None => false,
            Some("1") => true,
            Some(other) => return Err(err(format!("bad segkeys={other} in manifest"))),
        };
        if segkeys && fmt < 3 {
            return Err(err("segment log manifest has segkeys=1 but log<3"));
        }
        Ok(Log {
            dir: dir.to_path_buf(),
            name: m.name,
            id,
            signer,
            format: fmt,
            segkeys,
        })
    }

    pub fn segment_path(&self, seq: u64) -> PathBuf {
        segment_path(&self.dir, seq)
    }

    fn genesis(&self) -> [u8; 32] {
        let mut b = b"sigil-log-genesis-v1\0".to_vec();
        b.extend_from_slice(self.id.as_bytes());
        sha256(&b)
    }
}

pub fn segment_path(dir: &Path, seq: u64) -> PathBuf {
    dir.join(SEGMENTS_DIR)
        .join(format!("{:04}", seq / SEGMENTS_PER_FOLDER))
        .join(format!("{seq:010}.sg1"))
}

/// Filename shown by `sigil mount` / `--export-dir` for a live segment: zero-padded seq,
/// matching the on-disk basename without `.sg1` (e.g. `0000000007`).
pub fn mount_name(seq: u64) -> String {
    format!("{seq:010}")
}

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s.trim()).ok()?.try_into().ok()
}

fn parse_hex64(s: &str) -> Option<[u8; 64]> {
    hex::decode(s.trim()).ok()?.try_into().ok()
}

// ---------------------------------------------------------------------------
// INDEX + HEAD
// ---------------------------------------------------------------------------

/// What an INDEX line is.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Op {
    /// A sealed batch (slice-1 line; no `op=` key).
    Seg,
    /// `op=tomb`: marks earlier segments (by their seq) as deleted. No segment file.
    /// `shred`: a crypto-shred (`shred=1`, segment-keys logs only): the key of every named
    /// segment's file is destroyed, so its data is unrecoverable, not just hidden.
    Tomb {
        del: Vec<(u64, u64)>,
        reason: Option<String>,
        shred: bool,
    },
    /// `op=compact`: a merged replacement segment holding the plain bytes of the earlier
    /// segments `of` (ascending seq, concatenated). Original entries stay in the INDEX.
    Compact { of: Vec<(u64, u64)> },
    /// `op=signer` (log=4): the signer in effect hands the log over to `to`. `sig` is `from`'s
    /// Ed25519 signature over the handover statement (`handover_message`). No segment file. The
    /// HEAD covering this entry is still signed by `from`; every later HEAD by `to`.
    Signer {
        from: [u8; 32],
        to: [u8; 32],
        sig: [u8; 64],
    },
}

/// One INDEX line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub seq: u64,
    /// Unix seconds at append.
    pub time: u64,
    /// Plain (unsealed) size in bytes (0 for a tombstone).
    pub size: u64,
    /// SHA-256 true-name of the plain bytes (equals the star's header digest; zeros for a tombstone).
    pub sha: [u8; 32],
    pub chain: [u8; 32],
    pub op: Op,
    /// The line up to (not including) ` chain=`; covered by the chain hash. Unknown keys live here.
    body: String,
}

impl Entry {
    /// Keys this sigil does not know (kept and hashed, so future additive fields stay protected).
    pub fn extra_keys(&self) -> Vec<&str> {
        self.body
            .split_whitespace()
            .filter_map(|t| t.split_once('=').map(|(k, _)| k))
            .filter(|k| {
                !matches!(
                    *k,
                    "seq"
                        | "t"
                        | "size"
                        | "sha"
                        | "op"
                        | "del"
                        | "reason"
                        | "of"
                        | "shred"
                        | "src"
                        | "from"
                        | "to"
                        | "sig"
                )
            })
            .collect()
    }

    /// True for a tombstone / compaction line (needs `log=2`).
    pub fn is_meta(&self) -> bool {
        !matches!(self.op, Op::Seg)
    }

    /// True for a crypto-shred line (needs `log=3`).
    pub fn is_shred(&self) -> bool {
        matches!(self.op, Op::Tomb { shred: true, .. })
    }

    /// True for a signer handover line (needs `log=4`).
    pub fn is_handover(&self) -> bool {
        matches!(self.op, Op::Signer { .. })
    }

    /// The entry owns a segment file (a segment or a compaction segment; not a record).
    pub fn has_file(&self) -> bool {
        matches!(self.op, Op::Seg | Op::Compact { .. })
    }
}

// --- seq range lists: "1-4,6,8-9" -------------------------------------------------

/// Ascending, non-overlapping inclusive ranges. `None` if malformed.
pub fn parse_ranges(s: &str) -> Option<Vec<(u64, u64)>> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for part in s.split(',') {
        let (a, b) = match part.split_once('-') {
            Some((a, b)) => (a.parse::<u64>().ok()?, b.parse::<u64>().ok()?),
            None => {
                let a = part.parse::<u64>().ok()?;
                (a, a)
            }
        };
        if a == 0 || b < a || out.last().map(|l| a <= l.1).unwrap_or(false) {
            return None;
        }
        out.push((a, b));
    }
    (!out.is_empty()).then_some(out)
}

pub fn fmt_ranges(r: &[(u64, u64)]) -> String {
    r.iter()
        .map(|&(a, b)| {
            if a == b {
                a.to_string()
            } else {
                format!("{a}-{b}")
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

/// Collapse an ascending list of seqs into ranges.
pub fn compress(seqs: &[u64]) -> Vec<(u64, u64)> {
    let mut out: Vec<(u64, u64)> = Vec::new();
    for &s in seqs {
        match out.last_mut() {
            Some(l) if l.1 + 1 == s => l.1 = s,
            _ => out.push((s, s)),
        }
    }
    out
}

fn expand(r: &[(u64, u64)]) -> Vec<u64> {
    r.iter().flat_map(|&(a, b)| a..=b).collect()
}

/// Reasons are free text; INDEX values must stay one token, so everything but a safe set is %XX.
fn enc_reason(s: &str) -> String {
    let mut o = String::new();
    for b in s.bytes() {
        if b.is_ascii_alphanumeric() || b"-_.~,:/@".contains(&b) {
            o.push(b as char);
        } else {
            o.push_str(&format!("%{b:02X}"));
        }
    }
    o
}

fn dec_reason(s: &str) -> Option<String> {
    let b = s.as_bytes();
    let mut out = Vec::new();
    let mut i = 0;
    while i < b.len() {
        if b[i] == b'%' {
            let h = std::str::from_utf8(b.get(i + 1..i + 3)?).ok()?;
            out.push(u8::from_str_radix(h, 16).ok()?);
            i += 3;
        } else {
            out.push(b[i]);
            i += 1;
        }
    }
    String::from_utf8(out).ok()
}

// --- what the entries add up to ----------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
enum K {
    Seg,
    Tomb,
    Compact,
    Signer,
}

/// What a segment file's slot means once the whole INDEX is folded.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Slot {
    /// Not a file-holding entry (a tombstone).
    NoFile,
    /// Holds at least one live (not deleted, not moved) member: the file is required.
    Needed,
    /// Every member is tombstoned: the file is only still there because nobody erased it yet.
    DeadDeleted,
    /// Its live members moved into a later compaction segment: the file is redundant.
    DeadSuperseded,
}

/// The INDEX folded into "which segments are deleted, and where does each live batch's data
/// physically sit". Built entry by entry, so a bad tombstone / compaction line is caught where
/// it appears.
#[derive(Clone, Debug, Default)]
pub struct State {
    kinds: Vec<K>,
    sizes: Vec<u64>,
    /// member seq → seq of the tombstone entry that deleted it
    deleted: std::collections::BTreeMap<u64, u64>,
    /// member seq → seq of the (latest) compaction entry holding it; absent = its own file
    moved: std::collections::BTreeMap<u64, u64>,
    /// compaction entry seq → its members (ascending)
    members: std::collections::BTreeMap<u64, Vec<u64>>,
    /// member seq → seq of the shred entry that destroyed the key of the file holding it
    shredded: std::collections::BTreeMap<u64, u64>,
    /// file-holding entries whose key a shred entry destroyed
    shred_holders: std::collections::BTreeSet<u64>,
    /// signer handover entries: (seq, from, to), ascending
    handovers: Vec<(u64, [u8; 32], [u8; 32])>,
}

impl State {
    pub fn build(entries: &[Entry]) -> State {
        let mut st = State::default();
        for e in entries {
            // entries already passed validation when parsed; an invalid one simply stops the fold
            if st.apply(e).is_err() {
                break;
            }
        }
        st
    }

    /// Fold one more entry (must be the next one); `Err` = the line is structurally invalid.
    pub fn apply(&mut self, e: &Entry) -> std::result::Result<(), (&'static str, String)> {
        if e.seq != self.kinds.len() as u64 + 1 {
            return Err((
                "index-seq",
                format!("expected seq {}, found {}", self.kinds.len() + 1, e.seq),
            ));
        }
        match &e.op {
            Op::Seg => {
                self.kinds.push(K::Seg);
                self.sizes.push(e.size);
            }
            Op::Tomb { del, shred, .. } => {
                for &(a, b) in del {
                    if b >= e.seq {
                        return Err((
                            "index-tombstone",
                            format!(
                                "seq {}: tombstone names seq {b}, which is not earlier",
                                e.seq
                            ),
                        ));
                    }
                    for s in a..=b {
                        if self.kinds[s as usize - 1] != K::Seg {
                            return Err((
                                "index-tombstone",
                                format!(
                                    "seq {}: tombstone names seq {s}, which is not a segment entry",
                                    e.seq
                                ),
                            ));
                        }
                        if *shred {
                            // an earlier plain tombstone may be hardened into a shred, a shred is final
                            if self.shredded.contains_key(&s) {
                                return Err((
                                    "index-shred",
                                    format!("seq {}: seq {s} was already shredded", e.seq),
                                ));
                            }
                        } else if self.deleted.contains_key(&s) {
                            return Err((
                                "index-tombstone",
                                format!("seq {}: seq {s} was already deleted", e.seq),
                            ));
                        }
                    }
                }
                let named = expand(del);
                if *shred {
                    // One key seals a whole file. A compaction segment's key cannot be destroyed for
                    // some of its batches only: every live batch in the file must be named.
                    let holders: std::collections::BTreeSet<u64> =
                        named.iter().map(|s| self.holder_of(*s)).collect();
                    for &h in &holders {
                        if let Some(m) = self
                            .live_members(h)
                            .into_iter()
                            .find(|m| !named.contains(m))
                        {
                            return Err((
                                "index-shred",
                                format!("seq {}: shred of the file of entry {h} leaves live batch {m} unnamed (they share one key)", e.seq),
                            ));
                        }
                    }
                    for &h in &holders {
                        self.shred_holders.insert(h);
                        let held: Vec<u64> = self
                            .members_of(h)
                            .into_iter()
                            .filter(|m| self.holder_of(*m) == h)
                            .collect();
                        for m in held {
                            self.shredded.entry(m).or_insert(e.seq);
                            self.deleted.entry(m).or_insert(e.seq);
                        }
                    }
                }
                for s in named {
                    self.deleted.entry(s).or_insert(e.seq);
                }
                self.kinds.push(K::Tomb);
                self.sizes.push(0);
            }
            Op::Compact { of } => {
                if of.iter().any(|r| r.1 >= e.seq) {
                    return Err((
                        "index-compact",
                        format!("seq {}: compaction names a seq that is not earlier", e.seq),
                    ));
                }
                let mut total = 0u64;
                for s in expand(of) {
                    if s >= e.seq || self.kinds[s as usize - 1] != K::Seg {
                        return Err(("index-compact", format!("seq {}: compaction names seq {s}, which is not an earlier segment entry", e.seq)));
                    }
                    if self.deleted.contains_key(&s) {
                        return Err((
                            "index-compact",
                            format!(
                                "seq {}: compaction includes seq {s}, which is deleted",
                                e.seq
                            ),
                        ));
                    }
                    total += self.sizes[s as usize - 1];
                }
                if total != e.size {
                    return Err((
                        "index-compact",
                        format!(
                            "seq {}: size {} is not the sum of its members ({total})",
                            e.seq, e.size
                        ),
                    ));
                }
                let m = expand(of);
                for &s in &m {
                    self.moved.insert(s, e.seq);
                }
                self.members.insert(e.seq, m);
                self.kinds.push(K::Compact);
                self.sizes.push(e.size);
            }
            Op::Signer { from, to, .. } => {
                // Who may hand over (the signer in effect) is checked against the log's pin and the
                // signature in `read_index`; structurally a handover only has to name a new key.
                if from == to {
                    return Err((
                        "index-signer",
                        format!("seq {}: signer handover to the same key", e.seq),
                    ));
                }
                self.handovers.push((e.seq, *from, *to));
                self.kinds.push(K::Signer);
                self.sizes.push(0);
            }
        }
        Ok(())
    }

    pub fn len(&self) -> usize {
        self.kinds.len()
    }

    pub fn is_empty(&self) -> bool {
        self.kinds.is_empty()
    }

    pub fn is_seg(&self, seq: u64) -> bool {
        seq >= 1 && self.kinds.get(seq as usize - 1) == Some(&K::Seg)
    }

    pub fn is_tomb(&self, seq: u64) -> bool {
        seq >= 1 && self.kinds.get(seq as usize - 1) == Some(&K::Tomb)
    }

    pub fn is_compact(&self, seq: u64) -> bool {
        seq >= 1 && self.kinds.get(seq as usize - 1) == Some(&K::Compact)
    }

    /// Entry `seq` is a signer handover record.
    pub fn is_signer(&self, seq: u64) -> bool {
        seq >= 1 && self.kinds.get(seq as usize - 1) == Some(&K::Signer)
    }

    /// Entry `seq` owns a segment file (segment or compaction entry; not a tombstone / handover record).
    pub fn has_file(&self, seq: u64) -> bool {
        seq >= 1 && matches!(self.kinds.get(seq as usize - 1), Some(K::Seg | K::Compact))
    }

    /// Signer handover entries `(seq, from, to)`, ascending.
    pub fn handovers(&self) -> &[(u64, [u8; 32], [u8; 32])] {
        &self.handovers
    }

    /// The tombstone entry that deleted segment `seq`.
    pub fn deleted_by(&self, seq: u64) -> Option<u64> {
        self.deleted.get(&seq).copied()
    }

    /// The shred entry that destroyed the key protecting segment `seq`'s bytes.
    pub fn shredded_by(&self, seq: u64) -> Option<u64> {
        self.shredded.get(&seq).copied()
    }

    pub fn is_shredded(&self, seq: u64) -> bool {
        self.shredded.contains_key(&seq)
    }

    /// True when the key of the file held by entry `h` was destroyed by a shred entry.
    pub fn key_shredded(&self, h: u64) -> bool {
        self.shred_holders.contains(&h)
    }

    pub fn shred_count(&self) -> usize {
        self.shredded.len()
    }

    /// Seq of the entry whose file physically holds segment `seq`'s bytes.
    pub fn holder_of(&self, seq: u64) -> u64 {
        self.moved.get(&seq).copied().unwrap_or(seq)
    }

    /// Original segments stored in entry `h`'s file (ascending): `[h]` for a plain segment.
    pub fn members_of(&self, h: u64) -> Vec<u64> {
        match self.kinds.get(h as usize - 1) {
            Some(K::Seg) => vec![h],
            Some(K::Compact) => self.members.get(&h).cloned().unwrap_or_default(),
            _ => Vec::new(),
        }
    }

    /// Members of `h` that are live and whose data is in `h`'s file.
    pub fn live_members(&self, h: u64) -> Vec<u64> {
        self.members_of(h)
            .into_iter()
            .filter(|m| self.holder_of(*m) == h && !self.deleted.contains_key(m))
            .collect()
    }

    /// Members whose data is in `h`'s file but which are deleted (still on disk).
    pub fn deleted_members(&self, h: u64) -> Vec<u64> {
        self.members_of(h)
            .into_iter()
            .filter(|m| self.holder_of(*m) == h && self.deleted.contains_key(m))
            .collect()
    }

    pub fn slot(&self, h: u64) -> Slot {
        match self.kinds.get((h as usize).wrapping_sub(1)) {
            None | Some(K::Tomb) | Some(K::Signer) => Slot::NoFile,
            Some(_) => {
                if !self.live_members(h).is_empty() {
                    Slot::Needed
                } else if self.members_of(h).iter().any(|m| self.holder_of(*m) != h) {
                    Slot::DeadSuperseded
                } else {
                    Slot::DeadDeleted
                }
            }
        }
    }

    pub fn size_of(&self, seq: u64) -> u64 {
        self.sizes.get(seq as usize - 1).copied().unwrap_or(0)
    }

    pub fn deleted_count(&self) -> usize {
        self.deleted.len()
    }

    pub fn tomb_count(&self) -> usize {
        self.kinds.iter().filter(|k| **k == K::Tomb).count()
    }

    pub fn compact_count(&self) -> usize {
        self.kinds.iter().filter(|k| **k == K::Compact).count()
    }

    /// Segments that are not deleted (live data batches).
    pub fn live_count(&self) -> usize {
        self.kinds
            .iter()
            .enumerate()
            .filter(|(i, k)| **k == K::Seg && !self.deleted.contains_key(&(*i as u64 + 1)))
            .count()
    }
}

fn chain_hash(prev: &[u8; 32], body: &str) -> [u8; 32] {
    let mut b = b"sigil-log-entry-v1\0".to_vec();
    b.extend_from_slice(prev);
    b.extend_from_slice(body.as_bytes());
    sha256(&b)
}

fn root_of(entries: &[Entry]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = entries.iter().map(|e| e.chain).collect();
    crate::merkle::merkle_root(&leaves)
}

/// Merkle root over the first `n` chain hashes (what `--anchor N:ROOT` pins).
pub fn root_at(entries: &[Entry], n: usize) -> Option<[u8; 32]> {
    (n <= entries.len()).then(|| root_of(&entries[..n]))
}

#[derive(Debug, Default)]
pub struct ParsedIndex {
    pub entries: Vec<Entry>,
    /// The entries folded (deleted / moved / holders).
    pub state: State,
    /// Byte length of the intact part (everything before a torn last line).
    pub good_len: u64,
    /// Last line had no newline (crash mid-append): ignored.
    pub torn: bool,
    /// First broken line: (1-based line number, code, message). Entries before it are still listed.
    pub error: Option<(usize, &'static str, String)>,
}

fn parse_line(
    line: &str,
    want_seq: u64,
    prev: &[u8; 32],
) -> std::result::Result<Entry, (&'static str, String)> {
    let pos = line
        .rfind(" chain=")
        .ok_or(("index-line", "no chain= field".to_string()))?;
    let body = &line[..pos];
    let chain =
        parse_hex32(&line[pos + 7..]).ok_or(("index-line", "bad chain= value".to_string()))?;
    let mut kv: std::collections::BTreeMap<&str, &str> = std::collections::BTreeMap::new();
    for t in body.split_whitespace() {
        if let Some((k, v)) = t.split_once('=') {
            kv.entry(k).or_insert(v);
        }
    }
    let seq = kv.get("seq").and_then(|v| v.parse::<u64>().ok());
    let time = kv.get("t").and_then(|v| v.parse::<u64>().ok());
    let (Some(seq), Some(time)) = (seq, time) else {
        return Err(("index-line", "missing seq/t".into()));
    };
    let bad = |what: &str| ("index-line", format!("missing or bad {what}"));
    let (size, sha, op) = match kv.get("op").copied() {
        None => {
            let size = kv.get("size").and_then(|v| v.parse::<u64>().ok());
            let sha = kv.get("sha").and_then(|v| parse_hex32(v));
            let (Some(size), Some(sha)) = (size, sha) else {
                return Err(bad("size/sha"));
            };
            (size, sha, Op::Seg)
        }
        Some("tomb") => {
            let del = kv
                .get("del")
                .and_then(|v| parse_ranges(v))
                .ok_or_else(|| bad("del= (seq ranges)"))?;
            let reason = match kv.get("reason") {
                Some(r) => Some(dec_reason(r).ok_or_else(|| bad("reason="))?),
                None => None,
            };
            let shred = match kv.get("shred").copied() {
                None => false,
                Some("1") => true,
                Some(_) => return Err(bad("shred= (must be 1)")),
            };
            (0, [0u8; 32], Op::Tomb { del, reason, shred })
        }
        Some("compact") => {
            let size = kv.get("size").and_then(|v| v.parse::<u64>().ok());
            let sha = kv.get("sha").and_then(|v| parse_hex32(v));
            let of = kv.get("of").and_then(|v| parse_ranges(v));
            let (Some(size), Some(sha), Some(of)) = (size, sha, of) else {
                return Err(bad("size/sha/of"));
            };
            (size, sha, Op::Compact { of })
        }
        Some("signer") => {
            let from = kv.get("from").and_then(|v| parse_hex32(v));
            let to = kv.get("to").and_then(|v| parse_hex32(v));
            let sig = kv.get("sig").and_then(|v| parse_hex64(v));
            let (Some(from), Some(to), Some(sig)) = (from, to, sig) else {
                return Err(bad("from/to/sig= (an unsigned handover is not a handover)"));
            };
            (0, [0u8; 32], Op::Signer { from, to, sig })
        }
        Some(other) => {
            return Err((
                "index-op",
                format!("entry type op={other} is not known to this sigil; upgrade sigil"),
            ));
        }
    };
    if seq != want_seq {
        return Err(("index-seq", format!("expected seq {want_seq}, found {seq}")));
    }
    if chain_hash(prev, body) != chain {
        return Err((
            "index-chain",
            format!("seq {seq}: chain hash does not match (entry or an earlier one was altered)"),
        ));
    }
    Ok(Entry {
        seq,
        time,
        size,
        sha,
        chain,
        op,
        body: body.to_string(),
    })
}

pub fn parse_index(text: &str, genesis: &[u8; 32]) -> ParsedIndex {
    let mut out = ParsedIndex::default();
    let mut prev = *genesis;
    let mut offset = 0u64;
    let mut lines = text.split_inclusive('\n').enumerate().peekable();
    match lines.next() {
        Some((_, l)) if l.trim_end() == INDEX_MAGIC && l.ends_with('\n') => {
            offset += l.len() as u64
        }
        Some((_, l)) if l.trim_end() == INDEX_MAGIC => {
            out.torn = true;
            out.good_len = 0;
            return out;
        }
        _ => {
            out.error = Some((
                1,
                "index-line",
                format!("not a sigil log INDEX (first line must be {INDEX_MAGIC})"),
            ));
            return out;
        }
    }
    out.good_len = offset;
    for (i, l) in lines {
        if !l.ends_with('\n') {
            out.torn = true;
            break;
        }
        let line = l.trim_end_matches(['\n', '\r']);
        if line.trim().is_empty() || line.starts_with('#') {
            offset += l.len() as u64;
            out.good_len = offset;
            continue;
        }
        let parsed = parse_line(line, out.entries.len() as u64 + 1, &prev)
            .and_then(|e| out.state.apply(&e).map(|_| e));
        match parsed {
            Ok(e) => {
                prev = e.chain;
                out.entries.push(e);
                offset += l.len() as u64;
                out.good_len = offset;
            }
            Err((code, msg)) => {
                out.error = Some((i + 1, code, msg));
                break;
            }
        }
    }
    out
}

/// The signed (or plain) checkpoint over the INDEX.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Head {
    pub seq: u64,
    pub chain: [u8; 32],
    pub root: [u8; 32],
    pub time: u64,
    pub signer: Option<[u8; 32]>,
    pub sig: Option<[u8; 64]>,
}

impl Head {
    fn message(&self, id: &str) -> Vec<u8> {
        format!(
            "sigil-log-head-v1\nid={id}\nseq={}\nchain={}\nroot={}\nt={}\n",
            self.seq,
            hex32(&self.chain),
            hex32(&self.root),
            self.time
        )
        .into_bytes()
    }

    fn render(&self) -> String {
        let mut s = format!(
            "{HEAD_MAGIC}\nseq={}\nchain={}\nroot={}\nt={}\n",
            self.seq,
            hex32(&self.chain),
            hex32(&self.root),
            self.time
        );
        if let (Some(pk), Some(sig)) = (&self.signer, &self.sig) {
            s.push_str(&format!("signer={}\nsig={}\n", hex32(pk), hex::encode(sig)));
        }
        s
    }

    pub fn parse(text: &str) -> Result<Head> {
        let mut lines = text.lines();
        if lines.next().map(str::trim) != Some(HEAD_MAGIC) {
            return Err(err("not a sigil log HEAD"));
        }
        let (mut seq, mut chain, mut root, mut time, mut signer, mut sig) =
            (None, None, None, None, None, None);
        for l in lines {
            let Some((k, v)) = l.trim().split_once('=') else {
                continue;
            };
            match k {
                "seq" => seq = v.parse::<u64>().ok(),
                "chain" => chain = parse_hex32(v),
                "root" => root = parse_hex32(v),
                "t" => time = v.parse::<u64>().ok(),
                "signer" => signer = parse_hex32(v),
                "sig" => {
                    sig = hex::decode(v.trim())
                        .ok()
                        .and_then(|b| <[u8; 64]>::try_from(b).ok())
                }
                _ => {}
            }
        }
        match (seq, chain, root, time) {
            (Some(seq), Some(chain), Some(root), Some(time)) => Ok(Head {
                seq,
                chain,
                root,
                time,
                signer,
                sig,
            }),
            _ => Err(err("HEAD is missing seq/chain/root/t")),
        }
    }

    fn signature_ok(&self, id: &str) -> Option<bool> {
        let (pk, sig) = (self.signer?, self.sig?);
        let vk = VerifyingKey::from_bytes(&pk).ok();
        Some(match vk {
            Some(vk) => vk
                .verify(&self.message(id), &Signature::from_bytes(&sig))
                .is_ok(),
            None => false,
        })
    }
}

fn make_head(log: &Log, entries: &[Entry], sign: Option<&Identity>) -> Head {
    let mut h = Head {
        seq: entries.len() as u64,
        chain: entries
            .last()
            .map(|e| e.chain)
            .unwrap_or_else(|| log.genesis()),
        root: root_of(entries),
        time: now(),
        signer: None,
        sig: None,
    };
    if let Some(id) = sign {
        let sk = SigningKey::from_bytes(&id.ed25519_seed);
        h.signer = Some(sk.verifying_key().to_bytes());
        h.sig = Some(sk.sign(&h.message(&log.id)).to_bytes());
    }
    h
}

fn write_atomic(path: &Path, data: &[u8]) -> Result<()> {
    let mut part = path.as_os_str().to_os_string();
    part.push(".part");
    let part = PathBuf::from(part);
    if let Some(p) = path.parent() {
        fs::create_dir_all(p).map_err(io)?;
    }
    {
        let mut f = fs::File::create(&part).map_err(io)?;
        f.write_all(data).map_err(io)?;
        f.sync_all().map_err(io)?;
    }
    fs::rename(&part, path).map_err(io)
}

/// What the outgoing signer signs in a handover entry: bound to the log, the entry's position and
/// both keys, so it cannot be replayed into another log or at another seq.
pub(crate) fn handover_message(id: &str, seq: u64, from: &[u8; 32], to: &[u8; 32]) -> Vec<u8> {
    format!(
        "sigil-log-signer-v1\nid={id}\nseq={seq}\nfrom={}\nto={}\n",
        hex32(from),
        hex32(to)
    )
    .into_bytes()
}

/// `sig` is `from`'s valid signature over the handover statement.
pub(crate) fn handover_sig_ok(
    id: &str,
    seq: u64,
    from: &[u8; 32],
    to: &[u8; 32],
    sig: &[u8; 64],
) -> bool {
    match VerifyingKey::from_bytes(from) {
        Ok(vk) => vk
            .verify(
                &handover_message(id, seq, from, to),
                &Signature::from_bytes(sig),
            )
            .is_ok(),
        Err(_) => false,
    }
}

/// The first handover that is not valid in this log: the log is unsigned, it is not from the signer
/// in effect at that point, or its signature does not verify. `(index into entries, message)`.
fn handover_problem(log: &Log, entries: &[Entry]) -> Option<(usize, String)> {
    let mut cur = log.signer;
    for (i, e) in entries.iter().enumerate() {
        let Op::Signer { from, to, sig } = &e.op else {
            continue;
        };
        let Some(c) = cur else {
            return Some((i, format!("seq {}: signer handover in a log that was created unsigned (no signer pinned at init)", e.seq)));
        };
        if *from != c {
            return Some((
                i,
                format!(
                    "seq {}: handover is from {}… but the signer at that point is {}…",
                    e.seq,
                    &hex32(from)[..16],
                    &hex32(&c)[..16]
                ),
            ));
        }
        if !handover_sig_ok(&log.id, e.seq, from, to, sig) {
            return Some((i, format!("seq {}: handover signature does not verify (forged, or copied from another log / position)", e.seq)));
        }
        cur = Some(*to);
    }
    None
}

/// The chain of signers in force for a HEAD that covers the first `n` entries: the key pinned at
/// `init`, then the new key of every handover with seq < `n` (a handover's own entry is still
/// vouched for by the outgoing key). Empty for an unsigned log. Assumes the entries passed
/// `read_index` (handovers validated).
pub(crate) fn signer_chain(log: &Log, entries: &[Entry], n: usize) -> Vec<[u8; 32]> {
    let Some(pin) = log.signer else {
        return Vec::new();
    };
    let mut chain = vec![pin];
    for e in entries.iter().take_while(|e| (e.seq as usize) < n) {
        if let Op::Signer { to, .. } = &e.op {
            chain.push(*to);
        }
    }
    chain
}

/// The key that must sign a HEAD covering the first `n` entries (`n = entries.len() + 1`: the
/// signer of the next write).
pub(crate) fn signer_for(log: &Log, entries: &[Entry], n: usize) -> Option<[u8; 32]> {
    signer_chain(log, entries, n).last().copied()
}

fn read_index(log: &Log) -> Result<ParsedIndex> {
    let text = fs::read(log.dir.join(INDEX_FILE)).map_err(|e| err(format!("read INDEX: {e}")))?;
    let mut idx = parse_index(&String::from_utf8_lossy(&text), &log.genesis());
    // A handover under a manifest older than log=4 cannot come from a sigil that follows the format
    // (the manifest is raised first); a handover that is not the signer's own is damage, not data.
    if log.format < 4 {
        if let Some(i) = idx.entries.iter().position(|e| e.is_handover()) {
            idx.entries.truncate(i);
            idx.state = State::build(&idx.entries);
            if idx.error.is_none() {
                idx.error = Some((
                    i + 2,
                    "log-format",
                    format!(
                        "INDEX has a signer handover at seq {} but the manifest says log={}",
                        i + 1,
                        log.format
                    ),
                ));
            }
        }
    }
    if let Some((i, msg)) = handover_problem(log, &idx.entries) {
        idx.entries.truncate(i);
        idx.state = State::build(&idx.entries);
        if idx.error.is_none() {
            idx.error = Some((i + 2, "index-signer", msg));
        }
    }
    // A tombstone / compaction line under a `log=1` manifest cannot come from a sigil that
    // follows the format (the manifest is upgraded first): treat it as damage, not as data.
    if !log.segkeys {
        if let Some(i) = idx.entries.iter().position(|e| e.is_shred()) {
            idx.entries.truncate(i);
            idx.state = State::build(&idx.entries);
            if idx.error.is_none() {
                idx.error = Some((
                    i + 2,
                    "log-format",
                    format!("INDEX has a shred entry at seq {} but this log has no per-segment keys (segkeys=1 is missing)", i + 1),
                ));
            }
        }
    }
    if log.format < 2 {
        if let Some(i) = idx.entries.iter().position(|e| e.is_meta()) {
            idx.entries.truncate(i);
            idx.state = State::build(&idx.entries);
            if idx.error.is_none() {
                idx.error = Some((
                    i + 2,
                    "log-format",
                    format!("INDEX has a tombstone/compaction entry at seq {} but the manifest says log=1", i + 1),
                ));
            }
        }
    }
    Ok(idx)
}

/// How many INDEX entries the HEAD vouches for, i.e. how many may drive *deleting files*.
/// A consistent HEAD covers `h.seq` entries; for a signed log it must also carry the pinned
/// signer's valid signature. No HEAD on an unsigned log: the INDEX alone (a checksum-only log
/// has no stronger witness). Anything else: 0 (nothing beyond the entries' own chain is trusted).
fn trusted_len(log: &Log, idx: &ParsedIndex) -> usize {
    let n = idx.entries.len();
    match read_head(log) {
        None => {
            if log.signer.is_none() {
                n
            } else {
                0
            }
        }
        Some(Err(_)) => 0,
        Some(Ok(h)) => {
            let hs = h.seq as usize;
            if hs > n {
                return 0;
            }
            let chain_ok = if hs == 0 {
                h.chain == log.genesis()
            } else {
                idx.entries[hs - 1].chain == h.chain
            };
            if !chain_ok || root_of(&idx.entries[..hs]) != h.root {
                return 0;
            }
            if let Some(want) = signer_for(log, &idx.entries, hs) {
                if h.signer != Some(want) || h.signature_ok(&log.id) != Some(true) {
                    return 0;
                }
            } else if h.signature_ok(&log.id) == Some(false) {
                return 0;
            }
            hs
        }
    }
}

fn read_head(log: &Log) -> Option<Result<Head>> {
    let p = log.dir.join(HEAD_FILE);
    if !p.is_file() {
        return None;
    }
    Some(
        fs::read_to_string(&p)
            .map_err(io)
            .and_then(|t| Head::parse(&t)),
    )
}

mod adopt;
mod compact;
mod keyring;
mod proof;
mod rotate;
mod shred;
pub use adopt::*;
pub use compact::*;
use keyring::RingCache;
pub use keyring::{shard_of as keyring_shard_of, shard_path as keyring_shard_path};
pub use proof::*;
pub use rotate::*;
pub use shred::*;

// ---------------------------------------------------------------------------
// init / append
// ---------------------------------------------------------------------------

/// The directory `sigil log init PATH` creates: `PATH` if it ends in `.sigil`, else `PATH.sigil`.
pub fn dir_for_init(path: &Path) -> PathBuf {
    if container::has_suffix(path) {
        path.components().as_path().to_path_buf()
    } else {
        container::with_suffix(path)
    }
}

/// Create an empty log. `sign` pins an Ed25519 signer: every later append must use the same key.
pub fn init(path: &Path, sign: Option<&Identity>) -> Result<Log> {
    init_with(path, sign, false)
}

/// Like `init`; `segment_keys` opts into per-segment keys (slice 3, makes the log `log=3`).
pub fn init_with(path: &Path, sign: Option<&Identity>, segment_keys: bool) -> Result<Log> {
    let dir = dir_for_init(path);
    if dir.exists()
        && fs::read_dir(&dir)
            .map(|mut r| r.next().is_some())
            .unwrap_or(true)
    {
        return Err(err(format!(
            "{} already exists and is not empty; refusing",
            dir.display()
        )));
    }
    let name = container::strip_suffix(
        dir.file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| err("bad log name"))?,
    )
    .to_string();
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw).map_err(|e| err(e.to_string()))?;
    let id = hex::encode(raw);
    fs::create_dir_all(dir.join(SEGMENTS_DIR)).map_err(io)?;
    let format = if segment_keys { 3 } else { LOG_BASE_FORMAT };
    if segment_keys {
        fs::create_dir_all(dir.join(KEYS_DIR)).map_err(io)?;
    }
    let mut m = container::Manifest::new(KIND, &name);
    m.extra.insert("log".into(), format.to_string());
    if segment_keys {
        m.extra.insert("segkeys".into(), "1".into());
    }
    m.extra.insert("log-id".into(), id.clone());
    let signer = sign.map(|i| {
        SigningKey::from_bytes(&i.ed25519_seed)
            .verifying_key()
            .to_bytes()
    });
    if let Some(pk) = &signer {
        m.extra.insert("signer".into(), hex32(pk));
    }
    let log = Log {
        dir: dir.clone(),
        name,
        id,
        signer,
        format,
        segkeys: segment_keys,
    };
    write_atomic(&dir.join(INDEX_FILE), format!("{INDEX_MAGIC}\n").as_bytes())?;
    write_atomic(
        &dir.join(HEAD_FILE),
        make_head(&log, &[], sign).render().as_bytes(),
    )?;
    // The manifest goes last: only a complete log is recognised as a container.
    container::write_manifest(&dir, &m)?;
    Ok(log)
}

struct LockGuard(PathBuf);
impl Drop for LockGuard {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
}

fn lock(log: &Log) -> Result<LockGuard> {
    let p = log.dir.join(LOCK_FILE);
    match fs::OpenOptions::new().write(true).create_new(true).open(&p) {
        Ok(mut f) => {
            let _ = writeln!(f, "pid={}", std::process::id());
            Ok(LockGuard(p))
        }
        Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => Err(err(format!(
            "another append is running, or one crashed: remove {} if no sigil is using this log",
            p.display()
        ))),
        Err(e) => Err(io(e)),
    }
}

pub struct AppendOpts<'a> {
    pub mode: Mode,
    pub pass: Option<&'a str>,
    pub recipients: &'a [PublicIdentity],
    /// Signing key (required when the log pinned a signer; refused for an unsigned log).
    pub identity: Option<&'a Identity>,
}

impl Default for AppendOpts<'_> {
    fn default() -> Self {
        AppendOpts {
            mode: Mode::Reflection,
            pass: None,
            recipients: &[],
            identity: None,
        }
    }
}

#[derive(Clone, Debug)]
pub struct AppendReport {
    pub seq: u64,
    pub size: u64,
    pub sha: [u8; 32],
    pub segment: PathBuf,
    pub sealed_bytes: u64,
    pub root: [u8; 32],
    pub signed: bool,
    /// Things worth telling the user (torn tail trimmed, lagging head re-covered).
    pub notes: Vec<String>,
}

/// A signed log needs its current signer's key, an unsigned log refuses one. Early check (before
/// the lock); writers repeat it with `signer_gate_at` on the INDEX they read under the lock.
fn signer_gate(log: &Log, identity: Option<&Identity>) -> Result<()> {
    if log.signer.is_some() && identity.is_some() {
        match read_index(log) {
            Ok(idx) if idx.error.is_none() => return signer_gate_at(log, &idx.entries, identity),
            // a damaged INDEX: the writer's `prepare_write` refuses it with the real reason
            _ => return Ok(()),
        }
    }
    signer_gate_at(log, &[], identity)
}

/// `signer_gate` against these INDEX entries: the key must be the signer of the next write.
fn signer_gate_at(log: &Log, entries: &[Entry], identity: Option<&Identity>) -> Result<()> {
    let current = signer_for(log, entries, entries.len() + 1);
    match (current, identity) {
        (Some(_), None) => Err(err(
            "this log is signed: give the signing key with --identity KEY.sgk",
        )),
        (None, Some(_)) => Err(err(
            "this log was created unsigned (no --identity at init); appends cannot sign it",
        )),
        (Some(pk), Some(id)) => {
            if SigningKey::from_bytes(&id.ed25519_seed)
                .verifying_key()
                .to_bytes()
                != pk
            {
                if Some(pk) == log.signer {
                    return Err(err("--identity is not the key this log is pinned to"));
                }
                return Err(err(format!(
                    "--identity is not this log's current signer {}… (the signing key was handed over; see `sigil log ls`)",
                    &hex32(&pk)[..16]
                )));
            }
            Ok(())
        }
        (None, None) => Ok(()),
    }
}

/// Under the lock: read INDEX + HEAD and refuse on any inconsistency (shared by every writer).
fn prepare_write(log: &Log) -> Result<(ParsedIndex, Vec<String>)> {
    let mut notes = Vec::new();
    let idx = read_index(log)?;
    if let Some((line, _, msg)) = &idx.error {
        return Err(err(format!(
            "INDEX is damaged at line {line} ({msg}); run `sigil log verify` — refusing to write"
        )));
    }
    let n = idx.entries.len();
    match read_head(log) {
        Some(Ok(h)) => {
            if h.seq as usize > n {
                return Err(err(format!(
                    "HEAD says {} entries but INDEX has {n}: the index was truncated; refusing to write (run `sigil log verify`)",
                    h.seq
                )));
            }
            if h.seq > 0 && idx.entries[h.seq as usize - 1].chain != h.chain {
                return Err(err(
                    "HEAD does not match INDEX; refusing to write (run `sigil log verify`)",
                ));
            }
            if (h.seq as usize) < n {
                notes.push(format!(
                    "HEAD was {} entr{} behind INDEX (an earlier operation was interrupted); the new HEAD covers them",
                    n - h.seq as usize,
                    if n - h.seq as usize == 1 { "y" } else { "ies" }
                ));
            }
        }
        Some(Err(e)) => return Err(err(format!("HEAD unreadable ({e}); refusing to write"))),
        None => notes.push("HEAD was missing; rewritten".into()),
    }
    if idx.torn {
        notes.push("trimmed a torn last INDEX line left by a crash".into());
    }
    Ok((idx, notes))
}

/// Raise the manifest to `log=2` (idempotent). Must happen **before** the first tombstone /
/// compaction line is written, so an older sigil refuses the log instead of misreading it.
fn upgrade_manifest(log: &mut Log) -> Result<()> {
    raise_format(log, 2)
}

/// Raise the manifest to `log=to` (no-op when it is already there or newer). Manifest first,
/// before the first line that needs it.
fn raise_format(log: &mut Log, to: u32) -> Result<()> {
    if log.format >= to {
        return Ok(());
    }
    let mut m = container::read_manifest(&log.dir)?;
    m.extra.insert("log".into(), to.to_string());
    container::write_manifest(&log.dir, &m)?;
    log.format = to;
    Ok(())
}

/// Append chained lines (bodies without ` chain=`) to INDEX in one write + fsync, then rewrite
/// HEAD. Returns the new full entry list and HEAD.
fn commit(
    log: &Log,
    idx: ParsedIndex,
    bodies: &[String],
    identity: Option<&Identity>,
) -> Result<(Vec<Entry>, Head)> {
    let entries = commit_index(log, idx, bodies)?;
    let head = commit_head(log, &entries, identity)?;
    Ok((entries, head))
}

/// INDEX half of `commit` (the commit point: a complete line is part of the log).
fn commit_index(log: &Log, idx: ParsedIndex, bodies: &[String]) -> Result<Vec<Entry>> {
    let mut entries = idx.entries;
    let mut text = String::new();
    for body in bodies {
        let prev = entries
            .last()
            .map(|e| e.chain)
            .unwrap_or_else(|| log.genesis());
        let chain = chain_hash(&prev, body);
        let line = format!("{body} chain={}", hex32(&chain));
        let e = parse_line(&line, entries.len() as u64 + 1, &prev)
            .map_err(|(c, m)| err(format!("internal: new INDEX line rejected ({c}: {m})")))?;
        text.push_str(&line);
        text.push('\n');
        entries.push(e);
    }
    {
        let ipath = log.dir.join(INDEX_FILE);
        let f = fs::OpenOptions::new()
            .write(true)
            .open(&ipath)
            .map_err(io)?;
        f.set_len(idx.good_len).map_err(io)?;
        let mut f = fs::OpenOptions::new()
            .append(true)
            .open(&ipath)
            .map_err(io)?;
        f.write_all(text.as_bytes()).map_err(io)?;
        f.sync_all().map_err(io)?;
    }
    Ok(entries)
}

/// HEAD half of `commit` (atomic replace; signed when the log is).
fn commit_head(log: &Log, entries: &[Entry], identity: Option<&Identity>) -> Result<Head> {
    let head = make_head(log, entries, identity);
    write_atomic(&log.dir.join(HEAD_FILE), head.render().as_bytes())?;
    Ok(head)
}

/// Seal `data` as the next immutable segment and extend the chain.
pub fn append(path: &Path, data: &[u8], opts: &AppendOpts<'_>) -> Result<AppendReport> {
    let log = Log::open(path)?;
    signer_gate(&log, opts.identity)?;
    let _guard = lock(&log)?;
    let (idx, notes) = prepare_write(&log)?;
    signer_gate_at(&log, &idx.entries, opts.identity)?;
    let n = idx.entries.len();
    let seq = n as u64 + 1;
    let sha = sha256(data);
    // Per-segment keys: the segment is sealed to its own fresh key; --pass / --to only wrap that
    // key into the key ring. Without them there would be nowhere to keep it, so refuse first.
    let own_key = if log.segkeys {
        if opts.pass.filter(|p| !p.is_empty()).is_none() && opts.recipients.is_empty() {
            return Err(err(
                "this log has per-segment keys: give --pass and/or --to so the segment key can be wrapped and kept in the key ring",
            ));
        }
        Some(keyring::new_key()?)
    } else {
        None
    };
    let sealed = match &own_key {
        Some((_, id)) => crate::seal_kn_to(
            data,
            opts.mode,
            None,
            &format!("segment-{seq}"),
            false,
            "",
            &[],
            None,
            crate::DEFAULT_PIECE,
            &[id.public()],
        )?,
        None => crate::seal_kn_to(
            data,
            opts.mode,
            opts.pass,
            &format!("segment-{seq}"),
            false,
            "",
            &[],
            None,
            crate::DEFAULT_PIECE,
            opts.recipients,
        )?,
    };
    // 1. segment (atomic; replaces an unindexed leftover from a crash at the same seq), then its key
    //    (a record without an INDEX line is an orphan `gc` reclaims; the next append replaces it)
    let seg = log.segment_path(seq);
    write_atomic(&seg, &sealed)?;
    if let Some((m, _)) = &own_key {
        keyring::put(&log, seq, m, opts.pass, opts.recipients)?;
    }
    // 2. INDEX line, 3. HEAD
    let t = now();
    let body = format!("seq={seq} t={t} size={} sha={}", data.len(), hex32(&sha));
    let (_entries, head) = commit(&log, idx, &[body], opts.identity)?;
    Ok(AppendReport {
        seq,
        size: data.len() as u64,
        sha,
        segment: seg,
        sealed_bytes: sealed.len() as u64,
        root: head.root,
        signed: head.sig.is_some(),
        notes,
    })
}

// ---------------------------------------------------------------------------
// ls / read
// ---------------------------------------------------------------------------

#[derive(Clone, Debug)]
pub struct Listing {
    pub log: Log,
    pub entries: Vec<Entry>,
    pub state: State,
    pub head: Option<Head>,
    /// Segment file present for entry `i` (always false for a tombstone).
    pub present: Vec<bool>,
}

/// Index-only listing (no segment bytes are read).
pub fn list(path: &Path) -> Result<Listing> {
    let log = Log::open(path)?;
    let idx = read_index(&log)?;
    if let Some((line, _, msg)) = &idx.error {
        return Err(err(format!(
            "INDEX is damaged at line {line}: {msg} (run `sigil log verify`)"
        )));
    }
    let present = idx
        .entries
        .iter()
        .map(|e| e.has_file() && log.segment_path(e.seq).is_file())
        .collect();
    let head = read_head(&log).and_then(|h| h.ok());
    Ok(Listing {
        log,
        entries: idx.entries,
        state: idx.state,
        head,
        present,
    })
}

/// ISO-8601 UTC from unix seconds (no external time crate).
pub fn iso_utc(t: u64) -> String {
    let days = (t / 86400) as i64;
    let rem = t % 86400;
    let z = days + 719468;
    let era = z.div_euclid(146097);
    let doe = z.rem_euclid(146097);
    let yoe = (doe - doe / 1460 + doe / 36524 - doe / 146096) / 365;
    let y = yoe + era * 400;
    let doy = doe - (365 * yoe + yoe / 4 - yoe / 100);
    let mp = (5 * doy + 2) / 153;
    let d = doy - (153 * mp + 2) / 5 + 1;
    let m = if mp < 10 { mp + 3 } else { mp - 9 };
    let y = if m <= 2 { y + 1 } else { y };
    format!(
        "{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z",
        rem / 3600,
        rem % 3600 / 60,
        rem % 60
    )
}

impl Listing {
    pub fn render(&self) -> String {
        let head = self.head.as_ref();
        let st = &self.state;
        let mut s = format!(
            "log {}  entries={}  {}",
            self.log.dir.display(),
            self.entries.len(),
            match head.and_then(|h| h.signer) {
                Some(pk) => format!("signed by {}", &hex32(&pk)[..16]),
                None if self.log.signer.is_some() => "signer pinned, HEAD UNSIGNED".to_string(),
                None => "unsigned".to_string(),
            }
        );
        if self.log.segkeys || st.tomb_count() + st.compact_count() > 0 {
            s.push_str(&format!(
                "  [log={}:{} {} deleted, {} tombstone(s), {} compaction(s){}]",
                self.log.format,
                if self.log.segkeys {
                    " per-segment keys,"
                } else {
                    ""
                },
                st.deleted_count(),
                st.tomb_count(),
                st.compact_count(),
                if self.log.segkeys {
                    format!(", {} shredded", st.shred_count())
                } else {
                    String::new()
                }
            ));
        }
        if !st.handovers().is_empty() {
            s.push_str(&format!(
                "  [log={}: signer handed over {} time(s)]",
                self.log.format,
                st.handovers().len()
            ));
        }
        s.push('\n');
        s.push_str("  seq  time (UTC)            size        sha256            segment\n");
        for (e, p) in self.entries.iter().zip(&self.present) {
            let (size, sha) = match e.op {
                Op::Tomb { .. } | Op::Signer { .. } => ("-".to_string(), "-".to_string()),
                _ => (e.size.to_string(), format!("{}…", &hex32(&e.sha)[..16])),
            };
            let file = if *p { "ok" } else { "MISSING" };
            let what = match &e.op {
                Op::Seg => match st.deleted_by(e.seq) {
                    _ if st.is_shredded(e.seq) => format!(
                        "SHREDDED (entry #{}) — key destroyed, unrecoverable{}",
                        st.shredded_by(e.seq).unwrap_or(0),
                        if *p { "; ciphertext still on disk, `sigil gc --apply` erases it" } else { "" }
                    ),
                    Some(t) => format!(
                        "DELETED (tombstone #{t}){}",
                        if st.holder_of(e.seq) == e.seq && *p { " — file still on disk, erase with `log compact --apply`" } else { "" }
                    ),
                    None if st.holder_of(e.seq) != e.seq => format!("in #{}", st.holder_of(e.seq)),
                    None => file.to_string(),
                },
                Op::Tomb { del, reason, shred } => format!(
                    "{}: deletes {}{}",
                    if *shred { "crypto-shred" } else { "tombstone" },
                    fmt_ranges(del),
                    reason.as_ref().map(|r| format!("  reason: {r:?}")).unwrap_or_default()
                ),
                Op::Compact { of } => match st.slot(e.seq) {
                    Slot::Needed => format!("{file}  (compaction of {})", fmt_ranges(of)),
                    _ if *p => format!("superseded (compaction of {}) — file still on disk", fmt_ranges(of)),
                    _ => format!("superseded (compaction of {})", fmt_ranges(of)),
                },
                Op::Signer { from, to, .. } => format!(
                    "signer handover: {}… → {}…  (signed by the outgoing key; later HEADs by the new one)",
                    &hex32(from)[..16],
                    &hex32(to)[..16]
                ),
            };
            s.push_str(&format!(
                "  {:<4} {}  {:<10}  {:<17}  {}\n",
                e.seq,
                iso_utc(e.time),
                size,
                sha,
                what
            ));
        }
        if let Some(h) = head {
            s.push_str(&format!("head: seq {}  root {}\n", h.seq, hex32(&h.root)));
            s.push_str(&format!(
                "anchor (pin elsewhere, check with `verify --anchor`): {}:{}\n",
                h.seq,
                hex32(&h.root)
            ));
        }
        let pend: u64 = self
            .present
            .iter()
            .enumerate()
            .filter(|(_, p)| **p)
            .map(|(i, _)| {
                st.deleted_members(i as u64 + 1)
                    .iter()
                    .filter(|m| !st.is_shredded(**m))
                    .map(|m| st.size_of(*m))
                    .sum::<u64>()
            })
            .sum();
        if pend > 0 {
            s.push_str(&format!("{pend} byte(s) of deleted data are still on disk: `sigil log compact --apply` erases them\n"));
        }
        s
    }
}

pub struct ReadOpts<'a> {
    pub pass: Option<&'a str>,
    pub identities: &'a [Identity],
}

/// Plain bytes of one segment file (a plain segment or a compaction segment), checked against
/// the INDEX (hash and size). Also reports whether keys were needed to open it.
fn read_holder(
    log: &Log,
    ring: &mut RingCache,
    e: &Entry,
    opts: &ReadOpts<'_>,
) -> Result<(Vec<u8>, bool)> {
    let p = log.segment_path(e.seq);
    let file = fs::read(&p).map_err(|er| err(format!("segment {} unreadable: {er}", e.seq)))?;
    let (plain, keyed) = if log.segkeys {
        // every segment of such a log has its own key, wrapped in the key ring
        let id = ring.identity(e.seq, opts.pass, opts.identities)?;
        let plain = crate::unseal_ex_keys(&file, None, &[], &[id])
            .map_err(|er| err(format!("segment {}: {er}", e.seq)))?;
        (plain, true)
    } else {
        // Try without keys first: it tells whether the segment is protected at all.
        match crate::unseal_ex_keys(&file, None, &[], &[]) {
            Ok(p) => (p, false),
            Err(_) => (
                crate::unseal_ex_keys(&file, opts.pass, &[], opts.identities)
                    .map_err(|er| err(format!("segment {}: {er}", e.seq)))?,
                true,
            ),
        }
    };
    if sha256(&plain) != e.sha || plain.len() as u64 != e.size {
        return Err(err(format!(
            "segment {} does not match the index (substituted or altered)",
            e.seq
        )));
    }
    Ok((plain, keyed))
}

/// Plain bytes of one segment, checked against the INDEX (hash and size).
pub fn read_segment(log: &Log, e: &Entry, opts: &ReadOpts<'_>) -> Result<Vec<u8>> {
    read_holder(log, &mut RingCache::new(log), e, opts).map(|(p, _)| p)
}

/// Cuts one original segment out of whichever file holds it, with a one-file cache.
struct Reader<'a> {
    log: &'a Log,
    entries: &'a [Entry],
    state: &'a State,
    opts: &'a ReadOpts<'a>,
    cache: Option<(u64, Vec<u8>)>,
    ring: RingCache,
    /// A source that needed keys was opened.
    keyed_seen: bool,
}

impl<'a> Reader<'a> {
    fn new(log: &'a Log, entries: &'a [Entry], state: &'a State, opts: &'a ReadOpts<'a>) -> Self {
        Reader {
            log,
            entries,
            state,
            opts,
            cache: None,
            ring: RingCache::new(log),
            keyed_seen: false,
        }
    }

    fn member(&mut self, seq: u64) -> Result<Vec<u8>> {
        let h = self.state.holder_of(seq);
        let e = &self.entries[seq as usize - 1];
        if h == seq {
            let (p, k) = read_holder(self.log, &mut self.ring, e, self.opts)?;
            self.keyed_seen |= k;
            return Ok(p);
        }
        if self.cache.as_ref().map(|c| c.0) != Some(h) {
            let (p, k) = read_holder(
                self.log,
                &mut self.ring,
                &self.entries[h as usize - 1],
                self.opts,
            )?;
            self.keyed_seen |= k;
            self.cache = Some((h, p));
        }
        // The block above fills `cache` whenever it did not already hold `h`.
        let Some((_, plain)) = self.cache.as_ref() else {
            return Err(err("internal: segment cache empty after fill"));
        };
        let mut off = 0usize;
        for m in self.state.members_of(h) {
            let sz = self.state.size_of(m) as usize;
            if m == seq {
                let part = plain.get(off..off + sz).ok_or_else(|| {
                    err(format!(
                        "compaction segment {h} is shorter than its members"
                    ))
                })?;
                if sha256(part) != e.sha {
                    return Err(err(format!(
                        "segment {seq} (inside compaction segment {h}) does not match the index"
                    )));
                }
                return Ok(part.to_vec());
            }
            off += sz;
        }
        Err(err(format!(
            "segment {seq} is not inside compaction segment {h}"
        )))
    }
}

/// How `read_range` treats tombstoned segments.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ReadMode {
    /// One named segment: a tombstone (or a non-data entry) is an error.
    Single,
    /// A range: deleted segments are skipped and reported.
    SkipDeleted,
    /// A range: any deleted segment is an error.
    Strict,
}

#[derive(Debug, Default)]
pub struct ReadOut {
    pub parts: Vec<(u64, Vec<u8>)>,
    /// Segments in the range that are deleted by a tombstone (skipped).
    pub skipped_deleted: Vec<u64>,
}

fn deleted_msg(entries: &[Entry], st: &State, seq: u64) -> String {
    if let Some(t) = st.shredded_by(seq) {
        let reason = match entries.get(t as usize - 1).map(|e| &e.op) {
            Some(Op::Tomb {
                reason: Some(r), ..
            }) => format!(" (reason: {r})"),
            _ => String::new(),
        };
        return format!("segment {seq} was crypto-shredded by entry #{t}{reason}; its key is destroyed and its data cannot be recovered");
    }
    let t = st.deleted_by(seq).unwrap_or(0);
    let reason = match entries.get(t as usize - 1).map(|e| &e.op) {
        Some(Op::Tomb {
            reason: Some(r), ..
        }) => format!(" (reason: {r})"),
        _ => String::new(),
    };
    format!("segment {seq} was deleted by tombstone #{t}{reason}; its data is no longer part of this log")
}

/// Read segments `from..=to` (1-based, inclusive) after checking INDEX and HEAD integrity.
/// Entries that are not data (tombstone / compaction records) are never returned; deleted
/// segments follow `mode`.
pub fn read_range(
    path: &Path,
    from: u64,
    to: u64,
    opts: &ReadOpts<'_>,
    mode: ReadMode,
) -> Result<ReadOut> {
    let log = Log::open(path)?;
    let loaded = load(&log, &CheckOpts::default());
    if let Some(f) = loaded
        .findings
        .iter()
        .find(|f| f.severity == Severity::Error)
    {
        return Err(err(format!(
            "refusing to read: {} {}: {}",
            f.code, f.subject, f.message
        )));
    }
    let entries = &loaded.index.entries;
    let st = &loaded.index.state;
    let n = entries.len() as u64;
    if from == 0 || to < from {
        return Err(err(
            "segment numbers start at 1 and --from must not exceed --to",
        ));
    }
    if to > n {
        return Err(err(format!(
            "segment {to} does not exist (the log has {n})"
        )));
    }
    let mut out = ReadOut::default();
    let mut rd = Reader::new(&log, entries, st, opts);
    for seq in from..=to {
        if !st.is_seg(seq) {
            if mode == ReadMode::Single {
                return Err(err(if st.is_tomb(seq) {
                    format!("entry {seq} is a tombstone record, not data (see `sigil log ls`)")
                } else if st.is_signer(seq) {
                    format!(
                        "entry {seq} is a signer handover record, not data (see `sigil log ls`)"
                    )
                } else {
                    format!("entry {seq} is a compaction record; read the original segments it covers (see `sigil log ls`)")
                }));
            }
            continue;
        }
        if st.deleted_by(seq).is_some() {
            if mode == ReadMode::SkipDeleted {
                out.skipped_deleted.push(seq);
                continue;
            }
            return Err(err(deleted_msg(entries, st, seq)));
        }
        out.parts.push((seq, rd.member(seq)?));
    }
    Ok(out)
}

// ---------------------------------------------------------------------------
// verify (shared with `sigil doctor`)
// ---------------------------------------------------------------------------

pub struct CheckOpts<'a> {
    pub pass: Option<&'a str>,
    pub identities: &'a [Identity],
    /// Skip the bit-level ECC check of every segment (existence + header digest only).
    pub quick: bool,
    /// Require HEAD signed by this Ed25519 key, or by a key it handed the log over to (in
    /// addition to the manifest pin and its handovers).
    pub signer: Option<[u8; 32]>,
    /// `(seq, root)` pins: the Merkle root of the first `seq` entries must equal `root`.
    pub anchors: &'a [(u64, [u8; 32])],
    pub temp_age_secs: u64,
}

impl Default for CheckOpts<'_> {
    fn default() -> Self {
        CheckOpts {
            pass: None,
            identities: &[],
            quick: true,
            signer: None,
            anchors: &[],
            temp_age_secs: crate::gc::DEFAULT_TEMP_AGE_SECS,
        }
    }
}

struct Loaded {
    index: ParsedIndex,
    head: Option<Head>,
    findings: Vec<Finding>,
    /// Entries the HEAD vouches for (see `trusted_len`): only these may drive deleting files.
    trusted: usize,
}

fn fnd(
    sev: Severity,
    code: &'static str,
    subject: impl Into<String>,
    msg: impl Into<String>,
    hint: Option<&str>,
) -> Finding {
    Finding {
        severity: sev,
        code,
        subject: subject.into(),
        message: msg.into(),
        hint: hint.map(String::from),
    }
}

/// INDEX chain + HEAD checks (no segment files are touched).
fn load(log: &Log, opts: &CheckOpts<'_>) -> Loaded {
    let mut findings = Vec::new();
    let index = match read_index(log) {
        Ok(i) => i,
        Err(e) => {
            findings.push(fnd(
                Severity::Error,
                "index-missing",
                INDEX_FILE,
                e.to_string(),
                Some("restore INDEX from a copy; segments are still on disk"),
            ));
            return Loaded {
                index: ParsedIndex::default(),
                head: None,
                findings,
                trusted: 0,
            };
        }
    };
    if let Some((line, code, msg)) = &index.error {
        findings.push(fnd(
            Severity::Error,
            code,
            format!("{INDEX_FILE}:{line}"),
            msg.clone(),
            Some("the chain is broken from here on; restore INDEX from a copy or a signed HEAD's earlier state"),
        ));
    }
    if index.torn {
        findings.push(fnd(
            Severity::Warn,
            "index-torn",
            INDEX_FILE,
            "last INDEX line is incomplete (crash during append); ignored",
            Some("the next append trims it"),
        ));
    }
    let n = index.entries.len() as u64;
    let broken = index.error.is_some();
    let head = match read_head(log) {
        None => {
            findings.push(fnd(
                if log.signer.is_some() {
                    Severity::Error
                } else {
                    Severity::Warn
                },
                "head-missing",
                HEAD_FILE,
                "no HEAD checkpoint",
                Some("the next append rewrites it (a signed log needs --identity)"),
            ));
            None
        }
        Some(Err(e)) => {
            findings.push(fnd(Severity::Error, "head", HEAD_FILE, e.to_string(), None));
            None
        }
        Some(Ok(h)) => Some(h),
    };
    if let Some(h) = &head {
        if h.seq > n {
            if !broken {
                findings.push(fnd(
                    Severity::Error,
                    "head-truncated",
                    HEAD_FILE,
                    format!(
                        "HEAD covers {} entries but INDEX has only {n}: entries were cut off",
                        h.seq
                    ),
                    Some("restore INDEX from a copy; do not append or gc until then"),
                ));
            }
        } else {
            let consistent = if h.seq == 0 {
                h.chain == log.genesis()
            } else {
                index.entries[h.seq as usize - 1].chain == h.chain
            };
            if !consistent {
                findings.push(fnd(
                    Severity::Error,
                    "head-mismatch",
                    HEAD_FILE,
                    format!(
                        "HEAD's chain at seq {} differs from INDEX (history rewritten)",
                        h.seq
                    ),
                    None,
                ));
            } else if root_of(&index.entries[..h.seq as usize]) != h.root {
                findings.push(fnd(
                    Severity::Error,
                    "head-root",
                    HEAD_FILE,
                    "HEAD's Merkle root does not match the INDEX entries",
                    None,
                ));
            } else if h.seq < n {
                findings.push(fnd(
                    Severity::Warn,
                    "head-lag",
                    HEAD_FILE,
                    format!("HEAD covers {} of {n} entries (an append was interrupted, or INDEX has unsigned extra lines)", h.seq),
                    Some("the next append re-covers them"),
                ));
            }
        }
        let chain = signer_chain(
            log,
            &index.entries,
            (h.seq as usize).min(index.entries.len()),
        );
        let expect = chain.last().copied();
        match (h.signature_ok(&log.id), h.signer, expect) {
            (Some(false), _, _) => findings.push(fnd(Severity::Error, "head-signature", HEAD_FILE, "HEAD signature does not verify (altered, or from another log)", None)),
            (_, Some(pk), Some(want)) if pk != want && h.seq <= n => findings.push(fnd(
                Severity::Error,
                "head-signer",
                HEAD_FILE,
                if chain.len() > 1 {
                    format!("HEAD is signed by a different key than the log's signer at seq {} ({}…, after {} handover(s))", h.seq, &hex32(&want)[..16], chain.len() - 1)
                } else {
                    "HEAD is signed by a different key than the one pinned at init".to_string()
                },
                None,
            )),
            (None, _, Some(_)) => findings.push(fnd(Severity::Error, "head-unsigned", HEAD_FILE, "this log pins a signer but HEAD is not signed (signature stripped?)", None)),
            _ => {}
        }
        if let Some(want) = opts.signer {
            // the expected key signed HEAD itself, or HEAD's signer holds the log through handovers from it
            let via_chain = h.signer.is_some() && h.signer == expect && chain.contains(&want);
            if h.signer != Some(want) && !via_chain {
                findings.push(fnd(
                    Severity::Error,
                    "head-signer",
                    HEAD_FILE,
                    format!("HEAD is not signed by the expected key {}, nor by a key it handed the log over to", &hex32(&want)[..16]),
                    None,
                ));
            }
        }
    }
    for (seq, root) in opts.anchors {
        match root_at(&index.entries, *seq as usize) {
            Some(r) if r == *root => {}
            Some(_) => findings.push(fnd(Severity::Error, "anchor", format!("seq {seq}"), "Merkle root at this seq differs from the pinned anchor (history rewritten)", None)),
            None => findings.push(fnd(Severity::Error, "anchor", format!("seq {seq}"), format!("INDEX has only {n} entries; the anchor needs {seq} (log truncated or rolled back)"), None)),
        }
    }
    let trusted = trusted_len(log, &index);
    Loaded {
        index,
        head,
        findings,
        trusted,
    }
}

#[derive(Debug, Default)]
pub struct CheckReport {
    pub findings: Vec<Finding>,
    pub entries: usize,
    pub verified: usize,
    pub container_version: Option<u32>,
    pub signed: bool,
    /// Segment entries (deleted ones included), not counting tombstone / compaction records.
    pub segments: usize,
    /// Segments deleted by a tombstone.
    pub deleted: usize,
    pub tombstones: usize,
    pub compactions: usize,
    /// `log=N` of the manifest.
    pub format: u32,
    /// The log was made with `init --segment-keys`.
    pub segkeys: bool,
    /// Segments whose key a shred entry destroyed.
    pub shredded: usize,
    /// Signer handover entries (`log rotate-signer`).
    pub handovers: usize,
}

/// Full integrity check: manifest, INDEX chain, HEAD (+signature), every segment, strays.
/// Needs no keys; with `pass` / `identities` it also unseals each segment and compares the
/// plain hash and size with the INDEX.
pub fn check(path: &Path, opts: &CheckOpts<'_>) -> Result<CheckReport> {
    let mut rep = CheckReport::default();
    let dir = match resolve_dir(path) {
        Some(d) => d,
        None => {
            return Err(err(format!("{} is not a segment log", path.display())));
        }
    };
    match container::read_manifest(&dir) {
        Ok(m) => rep.container_version = Some(m.version),
        Err(e) => {
            rep.findings.push(fnd(Severity::Error, "manifest", container::CONTAINER_FILE, e.to_string(), Some("upgrade sigil if the container is newer; otherwise restore CONTAINER from a copy")));
            return Ok(rep);
        }
    }
    let log = match Log::open_dir(&dir) {
        Ok(l) => l,
        Err(e) => {
            rep.findings.push(fnd(
                Severity::Error,
                "manifest",
                container::CONTAINER_FILE,
                e.to_string(),
                Some("upgrade sigil if the log format is newer"),
            ));
            return Ok(rep);
        }
    };
    let loaded = load(&log, opts);
    rep.findings.extend(loaded.findings);
    rep.signed = loaded
        .head
        .as_ref()
        .map(|h| h.sig.is_some())
        .unwrap_or(false);
    let trusted = loaded.trusted;
    let st = loaded.index.state;
    let entries = loaded.index.entries;
    rep.entries = entries.len();
    rep.format = log.format;
    rep.segments = (1..=entries.len() as u64).filter(|s| st.is_seg(*s)).count();
    rep.deleted = st.deleted_count();
    rep.tombstones = st.tomb_count();
    rep.compactions = st.compact_count();
    rep.segkeys = log.segkeys;
    rep.shredded = st.shred_count();
    rep.handovers = st.handovers().len();
    if let (Some(pin), Some(&(_, _, last))) = (log.signer, st.handovers().last()) {
        rep.findings.push(fnd(
            Severity::Info,
            "signer-handovers",
            "INDEX",
            format!(
                "signer handed over {} time(s): {}… → {}… (each handover signed by the outgoing key; earlier HEADs, anchors and proofs stay valid)",
                st.handovers().len(),
                &hex32(&pin)[..16],
                &hex32(&last)[..16]
            ),
            None,
        ));
    }
    if st.shred_count() > 0 {
        rep.findings.push(fnd(
            Severity::Info,
            "shreds",
            "INDEX",
            format!("{} segment(s) crypto-shredded: their keys are destroyed, the entries (and every anchor) still verify", st.shred_count()),
            None,
        ));
    }
    if st.tomb_count() > 0 {
        rep.findings.push(fnd(
            Severity::Info,
            "tombstones",
            "INDEX",
            format!(
                "{} segment(s) deleted by {} tombstone(s) (log={})",
                st.deleted_count(),
                st.tomb_count(),
                log.format
            ),
            None,
        ));
    }
    if st.compact_count() > 0 {
        rep.findings.push(fnd(
            Severity::Info,
            "compactions",
            "INDEX",
            format!("{} compaction segment(s); original entries stay in the INDEX, their anchors still verify", st.compact_count()),
            None,
        ));
    }
    // Only entries the HEAD vouches for may declare a file dead; everything beyond is assumed live.
    let st_t = State::build(&entries[..trusted]);
    let keyed = opts.pass.is_some() || !opts.identities.is_empty();
    let mut ring = RingCache::new(&log);
    for e in &entries {
        if !st.has_file(e.seq) {
            continue;
        }
        let p = log.segment_path(e.seq);
        let subject = p.strip_prefix(&dir).unwrap_or(&p).display().to_string();
        let slot = if e.seq as usize > trusted {
            Slot::Needed
        } else {
            st_t.slot(e.seq)
        };
        if slot != Slot::Needed {
            if let Ok(md) = fs::metadata(&p) {
                if slot == Slot::DeadDeleted && st_t.key_shredded(e.seq) {
                    rep.findings.push(fnd(
                        Severity::Info,
                        "shredded-segment",
                        subject,
                        format!("segment {} is crypto-shredded; its unreadable ciphertext ({} bytes) is still on disk", e.seq, md.len()),
                        Some("sigil gc --apply erases the file"),
                    ));
                    continue;
                }
                let (code, msg, hint) = if slot == Slot::DeadDeleted {
                    (
                        "deleted-segment",
                        format!("segment {} was deleted by a tombstone but its file ({} bytes) is still on disk", e.seq, md.len()),
                        "sigil log compact --apply (or sigil gc --apply) erases it",
                    )
                } else {
                    (
                        "superseded-segment",
                        format!("segment {} was merged into a compaction segment; this file ({} bytes) is redundant", e.seq, md.len()),
                        "sigil gc --apply",
                    )
                };
                rep.findings
                    .push(fnd(Severity::Warn, code, subject, msg, Some(hint)));
            }
            continue;
        }
        let dirty = st_t.deleted_members(e.seq);
        if !dirty.is_empty() && (e.seq as usize) <= trusted {
            rep.findings.push(fnd(
                Severity::Warn,
                "deleted-data",
                subject.clone(),
                format!(
                    "compaction segment {} still contains deleted segment(s) {} ({} bytes of plain data)",
                    e.seq,
                    fmt_ranges(&compress(&dirty)),
                    dirty.iter().map(|m| st.size_of(*m)).sum::<u64>()
                ),
                Some("sigil log compact --apply rewrites it without them"),
            ));
        }
        let bytes = match fs::read(&p) {
            Ok(b) => b,
            Err(_) => {
                rep.findings.push(fnd(
                    Severity::Error,
                    "segment-missing",
                    subject,
                    format!("index entry {} has no segment file", e.seq),
                    Some("restore the segment from a copy (any copy of the sealed .sg1 works)"),
                ));
                continue;
            }
        };
        rep.verified += 1;
        let digest = crate::locate_header(&bytes).ok().map(|(h, _, _)| h.digest);
        match digest {
            Some(d) if d != e.sha => {
                rep.findings.push(fnd(Severity::Error, "segment-digest", subject.clone(), format!("segment {} is a different star than the index recorded (substituted or altered)", e.seq), None));
                continue;
            }
            None => {
                rep.findings.push(fnd(
                    Severity::Error,
                    "bit-rot-unrecoverable",
                    subject.clone(),
                    "not readable as a mark",
                    Some("restore this segment from another copy"),
                ));
                continue;
            }
            _ => {}
        }
        if !opts.quick {
            match health_bytes(&bytes) {
                Health::Ok => {}
                Health::Mendable(m) => rep.findings.push(fnd(
                    Severity::Warn,
                    "bit-rot",
                    subject.clone(),
                    format!("{m} — repairable"),
                    Some("sigil log mend PATH"),
                )),
                Health::Damaged(m) => {
                    rep.findings.push(fnd(
                        Severity::Error,
                        "bit-rot-unrecoverable",
                        subject.clone(),
                        m,
                        Some("restore this segment from another copy"),
                    ));
                    continue;
                }
            }
        }
        if keyed {
            let opened = if log.segkeys {
                ring.identity(e.seq, opts.pass, opts.identities)
                    .and_then(|id| crate::unseal_ex_keys(&bytes, None, &[], &[id]))
            } else {
                crate::unseal_ex_keys(&bytes, opts.pass, &[], opts.identities)
            };
            match opened {
                Ok(plain) if sha256(&plain) == e.sha && plain.len() as u64 == e.size => {
                    // a compaction segment must also cut back into exactly the original batches
                    if st.is_compact(e.seq) {
                        let mut off = 0usize;
                        for m in st.members_of(e.seq) {
                            let sz = st.size_of(m) as usize;
                            let ok = plain
                                .get(off..off + sz)
                                .map(|part| sha256(part) == entries[m as usize - 1].sha)
                                .unwrap_or(false);
                            if !ok {
                                rep.findings.push(fnd(Severity::Error, "segment-content", subject.clone(), format!("compaction segment {} does not hold original segment {m} as the index recorded it", e.seq), None));
                            }
                            off += sz;
                        }
                    }
                }
                Ok(_) => rep.findings.push(fnd(
                    Severity::Error,
                    "segment-content",
                    subject,
                    format!(
                        "segment {} unseals to bytes that differ from the index",
                        e.seq
                    ),
                    None,
                )),
                Err(er) => rep.findings.push(fnd(
                    Severity::Error,
                    "segment-unseal",
                    subject,
                    format!(
                        "segment {} cannot be opened with the given keys: {er}",
                        e.seq
                    ),
                    None,
                )),
            }
        }
    }
    if log.segkeys {
        check_keys(&log, &entries, &st, &st_t, trusted, opts, &mut rep);
    }
    // Strays.
    let extras = scan_extras(&log, &entries, trusted, opts.temp_age_secs);
    for x in &extras {
        match x.kind {
            ExtraKind::Orphan => rep.findings.push(fnd(
                Severity::Warn,
                "orphan-segment",
                x.rel(&dir),
                format!(
                    "segment no INDEX entry uses ({} bytes): a crashed append",
                    x.bytes
                ),
                Some("sigil gc --apply"),
            )),
            ExtraKind::Recent => rep.findings.push(fnd(
                Severity::Info,
                "recent-segment",
                x.rel(&dir),
                "unindexed but recent: an append may be in progress",
                None,
            )),
            ExtraKind::Temp => rep.findings.push(fnd(
                Severity::Warn,
                "temp-file",
                x.rel(&dir),
                "abandoned temp file",
                Some("sigil gc --apply"),
            )),
            ExtraKind::Unknown => rep.findings.push(fnd(
                Severity::Info,
                "unknown-file",
                x.rel(&dir),
                "not part of a segment log; left alone",
                None,
            )),
            ExtraKind::Stale(_) | ExtraKind::EmptyDir => {}
        }
    }
    Ok(rep)
}

/// Key ring checks of a segment-keys log (needs no key): every needed segment has its record, no
/// record outlives its segment, a shred is complete, the shards are healthy.
fn check_keys(
    log: &Log,
    entries: &[Entry],
    st: &State,
    st_t: &State,
    trusted: usize,
    opts: &CheckOpts<'_>,
    rep: &mut CheckReport,
) {
    let scan = keyring::scan(log);
    let mut present = std::collections::BTreeSet::new();
    let mut unreadable = std::collections::BTreeSet::new();
    for (shard, r) in &scan {
        let rel = format!("{KEYS_DIR}/{shard:04}.sg1");
        match r {
            Ok(set) => {
                present.extend(set.iter().copied());
                if !opts.quick {
                    if let Ok(bytes) = fs::read(keyring::shard_path(&log.dir, *shard)) {
                        match health_bytes(&bytes) {
                            Health::Ok => {}
                            Health::Mendable(m) => rep.findings.push(fnd(
                                Severity::Warn,
                                "bit-rot",
                                rel,
                                format!("{m} — repairable"),
                                Some("sigil log mend PATH"),
                            )),
                            Health::Damaged(m) => rep.findings.push(fnd(
                                Severity::Error,
                                "bit-rot-unrecoverable",
                                rel,
                                m,
                                Some("restore the key ring shard from a copy"),
                            )),
                        }
                    }
                }
            }
            Err(m) => {
                unreadable.insert(*shard);
                rep.findings.push(fnd(Severity::Error, "keyring-damaged", rel, m.clone(), Some("sigil log mend PATH, or restore the shard from a copy; its segments cannot be opened meanwhile")));
            }
        }
    }
    for e in entries {
        if !st.has_file(e.seq) {
            continue;
        }
        let needed = e.seq as usize > trusted || st_t.slot(e.seq) == Slot::Needed;
        let has = present.contains(&e.seq);
        if needed && !has && !unreadable.contains(&keyring::shard_of(e.seq)) {
            rep.findings.push(fnd(
                Severity::Error,
                "key-missing",
                format!("{KEYS_DIR}/{:04}.sg1", keyring::shard_of(e.seq)),
                format!(
                    "segment {} has no key in the key ring: it cannot be opened",
                    e.seq
                ),
                Some("restore the key ring from a copy; a destroyed key cannot be recreated"),
            ));
        } else if !needed && has {
            if st_t.key_shredded(e.seq) {
                rep.findings.push(fnd(
                    Severity::Warn,
                    "shred-key-present",
                    format!("{KEYS_DIR}/{:04}.sg1", keyring::shard_of(e.seq)),
                    format!("segment {} is recorded as shredded but its key is still in the ring (an interrupted shred)", e.seq),
                    Some("sigil gc --apply destroys it"),
                ));
            } else {
                rep.findings.push(fnd(
                    Severity::Warn,
                    "dead-key",
                    format!("{KEYS_DIR}/{:04}.sg1", keyring::shard_of(e.seq)),
                    format!("the key of segment {} is still in the ring though the segment is deleted or merged away", e.seq),
                    Some("sigil gc --apply (or log compact --apply) destroys it"),
                ));
            }
        }
    }
    for seq in present
        .iter()
        .filter(|s| **s as usize > entries.len() || !st.has_file(**s))
    {
        rep.findings.push(fnd(
            Severity::Warn,
            "orphan-key",
            format!("{KEYS_DIR}/{:04}.sg1", keyring::shard_of(*seq)),
            format!("key record {seq} belongs to no INDEX entry: a crashed append or compaction"),
            Some("sigil gc --apply"),
        ));
    }
}

// ---------------------------------------------------------------------------
// strays (gc / doctor)
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub(crate) enum ExtraKind {
    /// `segments/…/<seq>.sg1` beyond the INDEX and old enough to be a crash leftover.
    Orphan,
    /// Same, but young (maybe an append in flight): never reclaimed.
    Recent,
    Temp,
    EmptyDir,
    Unknown,
    /// Has an INDEX entry, but the entry is deleted (tombstone) or merged away (compaction):
    /// the file is dead weight. Only decided from entries the HEAD vouches for.
    Stale(Slot),
}

pub(crate) struct Extra {
    pub path: PathBuf,
    pub kind: ExtraKind,
    pub bytes: u64,
}

impl Extra {
    fn rel(&self, root: &Path) -> String {
        self.path
            .strip_prefix(root)
            .unwrap_or(&self.path)
            .display()
            .to_string()
    }
}

fn old_enough(p: &Path, secs: u64) -> bool {
    if secs == 0 {
        return true;
    }
    fs::metadata(p)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .map(|d| d >= Duration::from_secs(secs))
        .unwrap_or(false)
}

fn sorted(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir)
        .map(|r| r.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

fn seg_seq(p: &Path) -> Option<u64> {
    let n = p.file_name()?.to_str()?;
    let stem = n.strip_suffix(".sg1")?;
    (stem.len() == 10 && stem.bytes().all(|b| b.is_ascii_digit())).then(|| stem.parse().ok())?
}

/// Everything in the log folder that is not a live segment. A live segment (one with a needed
/// INDEX entry) is never listed, so nothing built on this can delete one. Files of entries beyond
/// `trusted` (not yet covered by a valid HEAD) are always treated as live.
pub(crate) fn scan_extras(log: &Log, all: &[Entry], trusted: usize, temp_age: u64) -> Vec<Extra> {
    let entries = all.len() as u64;
    let st_t = State::build(&all[..trusted.min(all.len())]);
    let st_all = State::build(all);
    let mut out = Vec::new();
    let sz = |p: &Path| fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    for p in sorted(&log.dir) {
        let n = p
            .file_name()
            .and_then(|n| n.to_str())
            .unwrap_or("")
            .to_string();
        if matches!(
            n.as_str(),
            container::CONTAINER_FILE | INDEX_FILE | HEAD_FILE
        ) {
            continue;
        }
        if p.is_dir() && (n == SEGMENTS_DIR || (n == KEYS_DIR && log.segkeys)) {
            continue;
        }
        if p.is_file() && (n.ends_with(".part") || n == LOCK_FILE) {
            if old_enough(&p, temp_age) {
                out.push(Extra {
                    bytes: sz(&p),
                    path: p,
                    kind: ExtraKind::Temp,
                });
            }
            continue;
        }
        out.push(Extra {
            bytes: 0,
            path: p,
            kind: ExtraKind::Unknown,
        });
    }
    if log.segkeys {
        for p in sorted(&log.dir.join(KEYS_DIR)) {
            let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if n.ends_with(".part") && p.is_file() {
                if old_enough(&p, temp_age) {
                    out.push(Extra {
                        bytes: sz(&p),
                        path: p,
                        kind: ExtraKind::Temp,
                    });
                }
            } else if keyring::shard_of_file(&p).is_none() || !p.is_file() {
                out.push(Extra {
                    bytes: 0,
                    path: p,
                    kind: ExtraKind::Unknown,
                });
            }
        }
    }
    for shard in sorted(&log.dir.join(SEGMENTS_DIR)) {
        if !shard.is_dir() {
            out.push(Extra {
                bytes: 0,
                path: shard,
                kind: ExtraKind::Unknown,
            });
            continue;
        }
        let files = sorted(&shard);
        let mut live = 0usize;
        for p in &files {
            let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if n.ends_with(".part") && p.is_file() {
                if old_enough(p, temp_age) {
                    out.push(Extra {
                        bytes: sz(p),
                        path: p.clone(),
                        kind: ExtraKind::Temp,
                    });
                } else {
                    live += 1;
                }
                continue;
            }
            match seg_seq(p) {
                Some(s) if s >= 1 && s <= entries && st_all.has_file(s) => {
                    if (s as usize) <= trusted && !matches!(st_t.slot(s), Slot::Needed) {
                        out.push(Extra {
                            bytes: sz(p),
                            path: p.clone(),
                            kind: ExtraKind::Stale(st_t.slot(s)),
                        });
                    } else {
                        live += 1;
                    }
                }
                Some(_) => {
                    live += 1;
                    let kind = if old_enough(p, temp_age) {
                        ExtraKind::Orphan
                    } else {
                        ExtraKind::Recent
                    };
                    out.push(Extra {
                        bytes: sz(p),
                        path: p.clone(),
                        kind,
                    });
                }
                None => {
                    live += 1;
                    out.push(Extra {
                        bytes: 0,
                        path: p.clone(),
                        kind: ExtraKind::Unknown,
                    });
                }
            }
        }
        if live == 0 {
            out.push(Extra {
                bytes: 0,
                path: shard,
                kind: ExtraKind::EmptyDir,
            });
        }
    }
    out
}

/// What `gc` is allowed to base its decisions on.
pub(crate) struct GcGate {
    pub entries: Vec<Entry>,
    /// Entries the HEAD vouches for.
    pub trusted: usize,
    /// File-holding entries that are still needed.
    pub kept: usize,
}

/// Safety gate for `gc`: the INDEX must be fully readable and HEAD must not claim more entries
/// than the INDEX holds (otherwise "beyond the index" could be live data).
pub(crate) fn gc_gate(log: &Log) -> Result<GcGate> {
    let idx = read_index(log)?;
    if let Some((line, _, msg)) = &idx.error {
        return Err(err(format!(
            "INDEX is damaged at line {line} ({msg}); gc will not guess which segments are live. Run `sigil log verify`"
        )));
    }
    if let Some(Ok(h)) = read_head(log) {
        if h.seq as usize > idx.entries.len() {
            return Err(err(format!(
                "HEAD covers {} entries but INDEX has {}: gc refuses (the missing entries' segments may be live)",
                h.seq,
                idx.entries.len()
            )));
        }
    }
    let trusted = trusted_len(log, &idx);
    let st = State::build(&idx.entries[..trusted]);
    let kept = (1..=idx.entries.len() as u64)
        .filter(|s| {
            (*s as usize) > trusted && idx.state.has_file(*s) || st.slot(*s) == Slot::Needed
        })
        .count();
    Ok(GcGate {
        entries: idx.entries,
        trusted,
        kept,
    })
}

/// Key records nothing needs any more: beyond the INDEX (crashed append / compaction), or of a
/// segment the HEAD-vouched entries declare deleted, merged away or shredded. Records of entries
/// the HEAD does not cover yet are always kept.
pub(crate) fn dead_keys(log: &Log, gate: &GcGate) -> Result<Vec<u64>> {
    let mut dead = Vec::new();
    let st_t = State::build(&gate.entries[..gate.trusted]);
    for (shard, r) in keyring::scan(log) {
        let set = r.map_err(|m| {
            err(format!(
                "key ring shard {shard:04} is unreadable ({m}); keys were not examined"
            ))
        })?;
        for s in set {
            let beyond = s as usize > gate.entries.len();
            if beyond || (s as usize <= gate.trusted && st_t.slot(s) != Slot::Needed) {
                dead.push(s);
            }
        }
    }
    Ok(dead)
}

/// Destroy the dead key records (see `dead_keys`) under the log lock, with a fresh look at the
/// INDEX, so an append in flight can never lose its brand-new key to a concurrent `gc`.
pub(crate) fn reclaim_dead_keys(log: &Log) -> Result<Vec<u64>> {
    if !log.segkeys {
        return Ok(Vec::new());
    }
    let _guard = lock(log)?;
    let gate = gc_gate(log)?;
    let dead = dead_keys(log, &gate)?;
    keyring::destroy(log, &dead)
}

// ---------------------------------------------------------------------------
// mend
// ---------------------------------------------------------------------------

#[derive(Debug, Default)]
pub struct MendReport {
    pub checked: usize,
    /// Segments rewritten in place (same plain bytes, same true-name).
    pub mended: Vec<u64>,
    pub missing: Vec<u64>,
    pub unrecoverable: Vec<(u64, String)>,
    /// Key ring shards healed in place (segment-keys logs).
    pub keys_mended: Vec<u64>,
    /// Key ring shards ECC cannot heal.
    pub keys_unrecoverable: Vec<(u64, String)>,
}

/// Heal every repairable segment in place (atomic replace). Never changes the INDEX / HEAD:
/// mending keeps the plain bytes and their true-name.
pub fn mend(path: &Path) -> Result<MendReport> {
    let log = Log::open(path)?;
    let idx = read_index(&log)?;
    if let Some((line, _, msg)) = &idx.error {
        return Err(err(format!(
            "INDEX is damaged at line {line} ({msg}); run `sigil log verify`"
        )));
    }
    let mut rep = MendReport::default();
    for e in &idx.entries {
        // tombstones have no file; deleted / merged-away segments are not worth healing
        if !idx.state.has_file(e.seq) || idx.state.slot(e.seq) != Slot::Needed {
            continue;
        }
        let p = log.segment_path(e.seq);
        let Ok(bytes) = fs::read(&p) else {
            rep.missing.push(e.seq);
            continue;
        };
        rep.checked += 1;
        match health_bytes(&bytes) {
            Health::Ok => {}
            Health::Damaged(m) => rep.unrecoverable.push((e.seq, m)),
            Health::Mendable(_) => match crate::mend_bytes(&bytes) {
                Ok(healed) => {
                    let good = crate::locate_header(&healed)
                        .map(|(h, _, _)| h.digest == e.sha)
                        .unwrap_or(false);
                    if !good {
                        rep.unrecoverable.push((
                            e.seq,
                            "mended star does not carry the indexed true-name".into(),
                        ));
                    } else if healed != bytes {
                        write_atomic(&p, &healed)?;
                        rep.mended.push(e.seq);
                    }
                }
                Err(er) => rep.unrecoverable.push((e.seq, er.to_string())),
            },
        }
    }
    if log.segkeys {
        let (m, b) = keyring::mend_shards(&log)?;
        rep.keys_mended = m;
        rep.keys_unrecoverable = b;
    }
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn iso_utc_known_dates() {
        assert_eq!(iso_utc(0), "1970-01-01T00:00:00Z");
        assert_eq!(iso_utc(951_782_400), "2000-02-29T00:00:00Z");
        assert_eq!(iso_utc(1_760_000_000), "2025-10-09T08:53:20Z");
    }

    fn line(prev: &[u8; 32], seq: u64, extra: &str) -> (String, [u8; 32]) {
        let body = format!("seq={seq} t=5 size=3 sha={}{extra}", hex32(&sha256(b"abc")));
        let c = chain_hash(prev, &body);
        (format!("{body} chain={}\n", hex32(&c)), c)
    }

    #[test]
    fn chain_parse_and_unknown_keys_are_covered() {
        let g = sha256(b"g");
        let (l1, c1) = line(&g, 1, "");
        let (l2, _) = line(&c1, 2, " flag=future");
        let text = format!("{INDEX_MAGIC}\n{l1}{l2}");
        let p = parse_index(&text, &g);
        assert!(p.error.is_none() && !p.torn);
        assert_eq!(p.entries.len(), 2);
        assert_eq!(p.entries[1].extra_keys(), vec!["flag"]);
        assert_eq!(p.good_len as usize, text.len());
        // the unknown key is protected by the chain
        let bad = text.replace("flag=future", "flag=other");
        assert_eq!(parse_index(&bad, &g).error.unwrap().1, "index-chain");
        // wrong genesis (another log's INDEX pasted in)
        assert!(parse_index(&text, &sha256(b"other")).error.is_some());
        // reordered / gapped seq
        let (l3, _) = line(&c1, 3, "");
        let gap = format!("{INDEX_MAGIC}\n{l1}{l3}");
        assert_eq!(parse_index(&gap, &g).error.unwrap().1, "index-seq");
        // torn tail
        let torn = format!("{INDEX_MAGIC}\n{l1}seq=2 t=5");
        let p = parse_index(&torn, &g);
        assert!(
            p.torn
                && p.entries.len() == 1
                && p.good_len as usize == INDEX_MAGIC.len() + 1 + l1.len()
        );
    }

    #[test]
    fn ranges_and_reasons_round_trip() {
        assert_eq!(
            parse_ranges("1-4,6,8-9"),
            Some(vec![(1, 4), (6, 6), (8, 9)])
        );
        assert_eq!(fmt_ranges(&[(1, 4), (6, 6), (8, 9)]), "1-4,6,8-9");
        assert_eq!(compress(&[1, 2, 3, 5, 7, 8]), vec![(1, 3), (5, 5), (7, 8)]);
        for bad in [
            "", "0", "3-2", "2,2", "4,1", "1-3,3", "a", "1-", "-1", "1,,2",
        ] {
            assert_eq!(parse_ranges(bad), None, "{bad:?}");
        }
        for r in [
            "",
            "plain",
            "with space and = sign",
            "100% sure\nnewline",
            "ünï/cødé: ok, fine",
        ] {
            let e = enc_reason(r);
            assert!(!e.contains(char::is_whitespace) && !e.contains('='), "{e}");
            assert_eq!(dec_reason(&e).as_deref(), Some(r));
        }
        assert_eq!(dec_reason("%zz"), None);
    }

    /// Build a valid chained INDEX text from bodies.
    fn chained(g: &[u8; 32], bodies: &[&str]) -> String {
        let mut prev = *g;
        let mut t = format!("{INDEX_MAGIC}\n");
        for b in bodies {
            let c = chain_hash(&prev, b);
            t.push_str(&format!("{b} chain={}\n", hex32(&c)));
            prev = c;
        }
        t
    }

    #[test]
    fn tombstone_and_compaction_lines_fold_into_state() {
        let g = sha256(b"g");
        let sh = hex32(&sha256(b"abc"));
        let s = |n: u64| format!("seq={n} t=5 size=3 sha={sh}");
        let (s1, s2, s3) = (s(1), s(2), s(3));
        let t4 = "seq=4 t=6 op=tomb del=2 reason=gdpr%20request";
        let c5 = format!("seq=5 t=7 size=6 sha={sh} op=compact of=1,3");
        let text = chained(&g, &[&s1, &s2, &s3, t4, &c5]);
        let p = parse_index(&text, &g);
        assert!(p.error.is_none(), "{:?}", p.error);
        assert_eq!(p.entries.len(), 5);
        let st = &p.state;
        assert!(st.is_seg(1) && st.is_tomb(4) && st.is_compact(5));
        assert_eq!(st.deleted_by(2), Some(4));
        assert_eq!(st.holder_of(1), 5);
        assert_eq!(st.holder_of(2), 2);
        assert_eq!(st.members_of(5), vec![1, 3]);
        assert_eq!(st.slot(1), Slot::DeadSuperseded);
        assert_eq!(st.slot(2), Slot::DeadDeleted);
        assert_eq!(st.slot(4), Slot::NoFile);
        assert_eq!(st.slot(5), Slot::Needed);
        assert_eq!(
            (
                st.deleted_count(),
                st.tomb_count(),
                st.compact_count(),
                st.live_count()
            ),
            (1, 1, 1, 2)
        );
        assert!(
            matches!(&p.entries[3].op, Op::Tomb { reason: Some(r), .. } if r == "gdpr request")
        );
        assert!(p.entries[3].extra_keys().is_empty());
        // a later tombstone of a compacted member makes the holder dirty, not dead
        let t6 = "seq=6 t=8 op=tomb del=3";
        let p = parse_index(&chained(&g, &[&s1, &s2, &s3, t4, &c5, t6]), &g);
        assert!(p.error.is_none());
        assert_eq!(p.state.slot(5), Slot::Needed);
        assert_eq!(p.state.deleted_members(5), vec![3]);
        assert_eq!(p.state.live_members(5), vec![1]);
    }

    #[test]
    fn invalid_tombstones_and_compactions_are_rejected_where_they_appear() {
        let g = sha256(b"g");
        let sh = hex32(&sha256(b"abc"));
        let s = |n: u64| format!("seq={n} t=5 size=3 sha={sh}");
        let (s1, s2) = (s(1), s(2));
        let cases: Vec<(String, &str)> = vec![
            ("seq=3 t=1 op=tomb del=3".into(), "index-tombstone"),
            ("seq=3 t=1 op=tomb del=1-9".into(), "index-tombstone"),
            ("seq=3 t=1 op=tomb".into(), "index-line"),
            ("seq=3 t=1 op=tomb del=2-1".into(), "index-line"),
            ("seq=3 t=1 op=unknown".into(), "index-op"),
            (
                format!("seq=3 t=1 size=7 sha={sh} op=compact of=1-2"),
                "index-compact",
            ), // size != 6
            (
                format!("seq=3 t=1 size=6 sha={sh} op=compact of=1-5"),
                "index-compact",
            ),
            (
                format!("seq=3 t=1 size=6 sha={sh} op=compact of=3"),
                "index-compact",
            ),
            (
                format!("seq=3 t=1 size=6 sha={sh} op=compact"),
                "index-line",
            ),
            (
                format!("seq=4 t=1 size=6 sha={sh} op=compact of=1-2"),
                "index-seq",
            ),
        ];
        for (body, code) in cases {
            let p = parse_index(&chained(&g, &[&s1, &s2, &body]), &g);
            let e = p.error.unwrap_or_else(|| panic!("{body} accepted"));
            assert_eq!(e.1, code, "{body}: {e:?}");
            assert_eq!(
                p.entries.len(),
                2,
                "entries before the bad line stay listed"
            );
        }
        // tombstone of an already deleted seq, compaction including a deleted seq, tombstone of a tombstone
        let t3 = "seq=3 t=1 op=tomb del=1";
        for (body, code) in [
            ("seq=4 t=1 op=tomb del=1", "index-tombstone"),
            ("seq=4 t=1 op=tomb del=3", "index-tombstone"),
            (
                &*format!("seq=4 t=1 size=6 sha={sh} op=compact of=1-2"),
                "index-compact",
            ),
        ] {
            let p = parse_index(&chained(&g, &[&s1, &s2, t3, body]), &g);
            assert_eq!(p.error.unwrap().1, code, "{body}");
        }
    }

    #[test]
    fn shred_lines_fold_into_state_and_invalid_ones_are_rejected() {
        let g = sha256(b"g");
        let sh = hex32(&sha256(b"abc"));
        let s = |n: u64| format!("seq={n} t=5 size=3 sha={sh}");
        let (s1, s2, s3) = (s(1), s(2), s(3));
        // a shred is a tombstone with shred=1: deleted AND key destroyed
        let t4 = "seq=4 t=6 op=tomb del=2 shred=1 reason=gdpr";
        let p = parse_index(&chained(&g, &[&s1, &s2, &s3, t4]), &g);
        assert!(p.error.is_none(), "{:?}", p.error);
        let st = &p.state;
        assert!(p.entries[3].is_shred() && p.entries[3].extra_keys().is_empty());
        assert_eq!(
            (st.deleted_by(2), st.shredded_by(2), st.is_shredded(1)),
            (Some(4), Some(4), false)
        );
        assert!(st.key_shredded(2) && !st.key_shredded(1));
        assert_eq!(
            (st.slot(2), st.slot(1), st.shred_count(), st.deleted_count()),
            (Slot::DeadDeleted, Slot::Needed, 1, 1)
        );
        // a plain tombstone may be hardened into a shred; a shred is final
        let t4p = "seq=4 t=6 op=tomb del=2";
        let p = parse_index(
            &chained(&g, &[&s1, &s2, &s3, t4p, "seq=5 t=7 op=tomb del=2 shred=1"]),
            &g,
        );
        assert!(p.error.is_none(), "{:?}", p.error);
        assert_eq!(
            (p.state.deleted_by(2), p.state.shredded_by(2)),
            (Some(4), Some(5))
        );
        for (bodies, code) in [
            (vec![t4, "seq=5 t=7 op=tomb del=2 shred=1"], "index-shred"),
            (vec![t4, "seq=5 t=7 op=tomb del=2"], "index-tombstone"),
            (vec!["seq=4 t=6 op=tomb del=2 shred=0"], "index-line"),
            (vec!["seq=4 t=6 op=tomb del=4 shred=1"], "index-tombstone"),
        ] {
            let mut all = vec![s1.as_str(), s2.as_str(), s3.as_str()];
            all.extend(bodies.iter().copied());
            let e = parse_index(&chained(&g, &all), &g)
                .error
                .unwrap_or_else(|| panic!("{bodies:?} accepted"));
            assert_eq!(e.1, code, "{bodies:?}: {e:?}");
        }
        // one key per file: a compaction segment's batches can only be shredded together
        let c4 = format!("seq=4 t=6 size=6 sha={sh} op=compact of=1-2");
        let part = parse_index(
            &chained(&g, &[&s1, &s2, &s3, &c4, "seq=5 t=7 op=tomb del=1 shred=1"]),
            &g,
        );
        assert_eq!(part.error.unwrap().1, "index-shred");
        let all = parse_index(
            &chained(
                &g,
                &[&s1, &s2, &s3, &c4, "seq=5 t=7 op=tomb del=1-2 shred=1"],
            ),
            &g,
        );
        assert!(all.error.is_none(), "{:?}", all.error);
        assert!(
            all.state.key_shredded(4)
                && all.state.is_shredded(1)
                && all.state.is_shredded(2)
                && !all.state.is_shredded(3)
        );
        assert_eq!(all.state.slot(4), Slot::DeadDeleted);
        // an already-deleted sibling does not have to be named again, but it is shredded with the file
        let t5 = "seq=5 t=7 op=tomb del=1";
        let sib = parse_index(
            &chained(
                &g,
                &[&s1, &s2, &s3, &c4, t5, "seq=6 t=8 op=tomb del=2 shred=1"],
            ),
            &g,
        );
        assert!(sib.error.is_none(), "{:?}", sib.error);
        assert!(sib.state.is_shredded(1) && sib.state.is_shredded(2));
    }

    #[test]
    fn head_roundtrip_and_signature() {
        let id = Identity::generate().unwrap();
        let log = Log {
            dir: PathBuf::new(),
            name: "x".into(),
            id: "ab".repeat(16),
            signer: None,
            format: 1,
            segkeys: false,
        };
        let h = make_head(&log, &[], Some(&id));
        let back = Head::parse(&h.render()).unwrap();
        assert_eq!(back, h);
        assert_eq!(back.signature_ok(&log.id), Some(true));
        assert_eq!(
            back.signature_ok("another-log-id"),
            Some(false),
            "signature is bound to the log id"
        );
        assert_eq!(make_head(&log, &[], None).signature_ok(&log.id), None);
    }

    fn tmpdir(tag: &str) -> PathBuf {
        let d =
            std::env::temp_dir().join(format!("sigil-rotate-unit-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn pk(i: &Identity) -> [u8; 32] {
        SigningKey::from_bytes(&i.ed25519_seed)
            .verifying_key()
            .to_bytes()
    }

    /// Append a hand-made line with a valid chain hash (what someone with file access can do).
    fn push_line(log: &Log, body: &str) {
        let p = log.dir.join(INDEX_FILE);
        let text = fs::read_to_string(&p).unwrap();
        let prev = parse_index(&text, &log.genesis())
            .entries
            .last()
            .map(|e| e.chain)
            .unwrap_or_else(|| log.genesis());
        fs::write(
            &p,
            format!("{text}{body} chain={}\n", hex32(&chain_hash(&prev, body))),
        )
        .unwrap();
    }

    fn handover_body(log: &Log, seq: u64, by: &Identity, from: &[u8; 32], to: &[u8; 32]) -> String {
        let sig = SigningKey::from_bytes(&by.ed25519_seed)
            .sign(&handover_message(&log.id, seq, from, to))
            .to_bytes();
        format!(
            "seq={seq} t=9 op=signer from={} to={} sig={}",
            hex32(from),
            hex32(to),
            hex::encode(sig)
        )
    }

    fn codes(path: &Path, signer: Option<[u8; 32]>) -> Vec<&'static str> {
        let rep = check(
            path,
            &CheckOpts {
                signer,
                ..Default::default()
            },
        )
        .unwrap();
        rep.findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .map(|f| f.code)
            .collect()
    }

    fn signed_append(path: &Path, data: &[u8], id: &Identity) -> Result<AppendReport> {
        append(
            path,
            data,
            &AppendOpts {
                identity: Some(id),
                mode: Mode::Glyph,
                ..Default::default()
            },
        )
    }

    #[test]
    fn signer_rotation_follows_the_chain_of_handovers() {
        let (a, b, c) = (
            Identity::generate().unwrap(),
            Identity::generate().unwrap(),
            Identity::generate().unwrap(),
        );
        let d = tmpdir("chain");
        let path = d.join("ev");
        init(&path, Some(&a)).unwrap();
        signed_append(&path, b"one", &a).unwrap();
        signed_append(&path, b"two", &a).unwrap();
        assert_eq!(
            Log::open(&path).unwrap().format,
            1,
            "a log that is never rotated keeps its format"
        );
        let r = rotate_signer(&path, &a, pk(&b)).unwrap();
        assert_eq!((r.entry, r.from, r.to, r.handovers), (3, pk(&a), pk(&b), 1));
        let log = Log::open(&path).unwrap();
        assert_eq!(
            (log.format, log.signer),
            (4, Some(pk(&a))),
            "manifest raised to log=4; signer= stays the init pin"
        );
        let entries = read_index(&log).unwrap().entries;
        // the handover's own HEAD is the outgoing key's; every later one the new key's
        assert_eq!(signer_for(&log, &entries, 3), Some(pk(&a)));
        assert_eq!(signer_for(&log, &entries, 4), Some(pk(&b)));
        assert_eq!(signer_chain(&log, &entries, 4), vec![pk(&a), pk(&b)]);
        assert_eq!(read_head(&log).unwrap().unwrap().signer, Some(pk(&a)));
        assert!(codes(&path, None).is_empty());
        // the old key may no longer write; the new one must
        let e = signed_append(&path, b"three", &a).unwrap_err().to_string();
        assert!(e.contains("current signer"), "{e}");
        assert!(
            rotate_signer(&path, &a, pk(&c)).is_err(),
            "the outgoing key cannot hand over twice"
        );
        signed_append(&path, b"three", &b).unwrap();
        assert_eq!(read_head(&log).unwrap().unwrap().signer, Some(pk(&b)));
        assert!(codes(&path, None).is_empty());
        assert!(
            codes(&path, Some(pk(&a))).is_empty(),
            "--signer may name the init key"
        );
        assert!(codes(&path, Some(pk(&b))).is_empty());
        assert_eq!(codes(&path, Some(pk(&c))), vec!["head-signer"]);
        let rep = check(&path, &CheckOpts::default()).unwrap();
        assert!(rep.findings.iter().any(|f| f.code == "signer-handovers") && rep.handovers == 1);
        // a chain of two; refusals
        assert!(rotate_signer(&path, &b, pk(&b))
            .unwrap_err()
            .to_string()
            .contains("already"));
        for junk in [[0xffu8; 32], [0u8; 32], {
            let mut k = [0u8; 32];
            k[0] = 1;
            k
        }] {
            assert!(
                rotate_signer(&path, &b, junk)
                    .unwrap_err()
                    .to_string()
                    .contains("not a valid"),
                "{junk:?}"
            );
        }
        rotate_signer(&path, &b, pk(&c)).unwrap();
        signed_append(&path, b"four", &c).unwrap();
        let entries = read_index(&log).unwrap().entries;
        assert_eq!(
            signer_chain(&log, &entries, entries.len() + 1),
            vec![pk(&a), pk(&b), pk(&c)]
        );
        assert!(codes(&path, Some(pk(&a))).is_empty() && codes(&path, Some(pk(&b))).is_empty());
        // records hold no file: gc / doctor / mend do not miss one
        assert!(check(
            &path,
            &CheckOpts {
                quick: false,
                ..Default::default()
            }
        )
        .unwrap()
        .findings
        .iter()
        .all(|f| f.severity != Severity::Error));
        assert!(mend(&path).unwrap().missing.is_empty());
        let ls = list(&path).unwrap();
        assert_eq!(ls.present.iter().filter(|p| **p).count(), 4);
        assert!(ls.render().contains("signer handover:"));
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn forged_misplaced_or_unsigned_handovers_are_refused() {
        let (a, b, eve) = (
            Identity::generate().unwrap(),
            Identity::generate().unwrap(),
            Identity::generate().unwrap(),
        );
        let d = tmpdir("forged");
        let fresh = |name: &str, sign: Option<&Identity>| -> (PathBuf, Log) {
            let p = d.join(name);
            init(&p, sign).unwrap();
            match sign {
                Some(id) => signed_append(&p, b"x", id).unwrap(),
                None => append(
                    &p,
                    b"x",
                    &AppendOpts {
                        mode: Mode::Glyph,
                        ..Default::default()
                    },
                )
                .unwrap(),
            };
            let mut log = Log::open(&p).unwrap();
            raise_format(&mut log, 4).unwrap();
            (p, log)
        };
        // Eve signs a handover "from a to eve"
        let (p, log) = fresh("eve", Some(&a));
        push_line(&log, &handover_body(&log, 2, &eve, &pk(&a), &pk(&eve)));
        assert!(codes(&p, None).contains(&"index-signer"));
        assert!(
            signed_append(&p, b"y", &eve).is_err() && signed_append(&p, b"y", &a).is_err(),
            "writers refuse a damaged INDEX"
        );
        // Eve hands over from herself (not the signer in effect)
        let (p, log) = fresh("notcur", Some(&a));
        push_line(&log, &handover_body(&log, 2, &eve, &pk(&eve), &pk(&b)));
        assert!(codes(&p, None).contains(&"index-signer"));
        // a genuine statement, replayed at another seq
        let (p, log) = fresh("replay", Some(&a));
        let at5 = handover_body(&log, 5, &a, &pk(&a), &pk(&b));
        push_line(&log, &at5.replacen("seq=5", "seq=2", 1));
        assert!(codes(&p, None).contains(&"index-signer"));
        // a handover in an unsigned log
        let (p, log) = fresh("unsigned", None);
        push_line(&log, &handover_body(&log, 2, &a, &pk(&a), &pk(&b)));
        assert!(codes(&p, None).contains(&"index-signer"));
        assert!(rotate_signer(&p, &a, pk(&b)).is_err());
        // no signature at all is not a handover
        let (p, log) = fresh("nosig", Some(&a));
        push_line(
            &log,
            &format!(
                "seq=2 t=9 op=signer from={} to={}",
                hex32(&pk(&a)),
                hex32(&pk(&b))
            ),
        );
        assert!(codes(&p, None).contains(&"index-line"));
        // a valid handover under a manifest older than log=4
        let p = d.join("oldfmt");
        init(&p, Some(&a)).unwrap();
        signed_append(&p, b"x", &a).unwrap();
        let log = Log::open(&p).unwrap();
        push_line(&log, &handover_body(&log, 2, &a, &pk(&a), &pk(&b)));
        assert!(codes(&p, None).contains(&"log-format"));
        // the same line under log=4 is fine (head-lag only: HEAD does not cover it yet)
        let mut log = Log::open(&p).unwrap();
        raise_format(&mut log, 4).unwrap();
        assert!(codes(&p, None).is_empty());
        signed_append(&p, b"y", &b).unwrap();
        assert!(codes(&p, Some(pk(&a))).is_empty());
        let _ = fs::remove_dir_all(&d);
    }
}
