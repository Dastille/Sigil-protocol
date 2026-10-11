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
pub const LOG_FORMAT: u32 = 1;
pub const INDEX_FILE: &str = "INDEX";
pub const HEAD_FILE: &str = "HEAD";
pub const LOCK_FILE: &str = "LOG.lock";
pub const SEGMENTS_DIR: &str = "segments";
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
    SystemTime::now().duration_since(UNIX_EPOCH).map(|d| d.as_secs()).unwrap_or(0)
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
    /// Ed25519 public key pinned at `init --identity` (every HEAD must be signed by it).
    pub signer: Option<[u8; 32]>,
}

/// True when `path` (or `path.sigil`) is a log container.
pub fn is_log(path: &Path) -> bool {
    resolve_dir(path).is_some()
}

fn resolve_dir(path: &Path) -> Option<PathBuf> {
    let path = path.components().as_path().to_path_buf();
    for cand in [path.clone(), container::with_suffix(&path)] {
        if container::is_container(&cand)
            && container::read_manifest(&cand).map(|m| m.kind == KIND).unwrap_or(false)
        {
            return Some(cand);
        }
    }
    None
}

impl Log {
    pub fn open(path: &Path) -> Result<Log> {
        let dir = resolve_dir(path).ok_or_else(|| {
            err(format!("{} is not a segment log (`sigil log init` creates one)", path.display()))
        })?;
        Self::open_dir(&dir)
    }

    fn open_dir(dir: &Path) -> Result<Log> {
        let m = container::read_manifest(dir)?;
        if m.kind != KIND {
            return Err(err(format!("{} is a {} container, not a segment log", dir.display(), m.kind)));
        }
        let fmt = m.extra.get("log").and_then(|v| v.trim().parse::<u32>().ok()).unwrap_or(0);
        if fmt == 0 {
            return Err(err("segment log manifest has no log=N"));
        }
        if fmt > LOG_FORMAT {
            return Err(err(format!(
                "segment log format {fmt} is newer than this sigil understands ({LOG_FORMAT}); upgrade sigil"
            )));
        }
        let id = m.extra.get("log-id").cloned().ok_or_else(|| err("segment log manifest has no log-id"))?;
        let signer = match m.extra.get("signer") {
            Some(h) => Some(parse_hex32(h).ok_or_else(|| err("bad signer= in manifest"))?),
            None => None,
        };
        Ok(Log { dir: dir.to_path_buf(), name: m.name, id, signer })
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

fn parse_hex32(s: &str) -> Option<[u8; 32]> {
    hex::decode(s.trim()).ok()?.try_into().ok()
}

// ---------------------------------------------------------------------------
// INDEX + HEAD
// ---------------------------------------------------------------------------

/// One INDEX line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Entry {
    pub seq: u64,
    /// Unix seconds at append.
    pub time: u64,
    /// Plain (unsealed) size in bytes.
    pub size: u64,
    /// SHA-256 true-name of the plain bytes (equals the star's header digest).
    pub sha: [u8; 32],
    pub chain: [u8; 32],
    /// The line up to (not including) ` chain=`; covered by the chain hash. Unknown keys live here.
    body: String,
}

impl Entry {
    /// Keys this sigil does not know (kept and hashed, so future additive fields stay protected).
    pub fn extra_keys(&self) -> Vec<&str> {
        self.body
            .split_whitespace()
            .filter_map(|t| t.split_once('=').map(|(k, _)| k))
            .filter(|k| !matches!(*k, "seq" | "t" | "size" | "sha"))
            .collect()
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
    /// Byte length of the intact part (everything before a torn last line).
    pub good_len: u64,
    /// Last line had no newline (crash mid-append): ignored.
    pub torn: bool,
    /// First broken line: (1-based line number, code, message). Entries before it are still listed.
    pub error: Option<(usize, &'static str, String)>,
}

fn parse_line(line: &str, want_seq: u64, prev: &[u8; 32]) -> std::result::Result<Entry, (&'static str, String)> {
    let pos = line.rfind(" chain=").ok_or(("index-line", "no chain= field".to_string()))?;
    let body = &line[..pos];
    let chain = parse_hex32(&line[pos + 7..]).ok_or(("index-line", "bad chain= value".to_string()))?;
    let (mut seq, mut time, mut size, mut sha) = (None, None, None, None);
    for t in body.split_whitespace() {
        let Some((k, v)) = t.split_once('=') else { continue };
        match k {
            "seq" => seq = v.parse::<u64>().ok(),
            "t" => time = v.parse::<u64>().ok(),
            "size" => size = v.parse::<u64>().ok(),
            "sha" => sha = parse_hex32(v),
            _ => {}
        }
    }
    let (Some(seq), Some(time), Some(size), Some(sha)) = (seq, time, size, sha) else {
        return Err(("index-line", "missing seq/t/size/sha".into()));
    };
    if seq != want_seq {
        return Err(("index-seq", format!("expected seq {want_seq}, found {seq}")));
    }
    if chain_hash(prev, body) != chain {
        return Err(("index-chain", format!("seq {seq}: chain hash does not match (entry or an earlier one was altered)")));
    }
    Ok(Entry { seq, time, size, sha, chain, body: body.to_string() })
}

pub fn parse_index(text: &str, genesis: &[u8; 32]) -> ParsedIndex {
    let mut out = ParsedIndex::default();
    let mut prev = *genesis;
    let mut offset = 0u64;
    let mut lines = text.split_inclusive('\n').enumerate().peekable();
    match lines.next() {
        Some((_, l)) if l.trim_end() == INDEX_MAGIC && l.ends_with('\n') => offset += l.len() as u64,
        Some((_, l)) if l.trim_end() == INDEX_MAGIC => {
            out.torn = true;
            out.good_len = 0;
            return out;
        }
        _ => {
            out.error = Some((1, "index-line", format!("not a sigil log INDEX (first line must be {INDEX_MAGIC})")));
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
        match parse_line(line, out.entries.len() as u64 + 1, &prev) {
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
        let (mut seq, mut chain, mut root, mut time, mut signer, mut sig) = (None, None, None, None, None, None);
        for l in lines {
            let Some((k, v)) = l.trim().split_once('=') else { continue };
            match k {
                "seq" => seq = v.parse::<u64>().ok(),
                "chain" => chain = parse_hex32(v),
                "root" => root = parse_hex32(v),
                "t" => time = v.parse::<u64>().ok(),
                "signer" => signer = parse_hex32(v),
                "sig" => sig = hex::decode(v.trim()).ok().and_then(|b| <[u8; 64]>::try_from(b).ok()),
                _ => {}
            }
        }
        match (seq, chain, root, time) {
            (Some(seq), Some(chain), Some(root), Some(time)) => Ok(Head { seq, chain, root, time, signer, sig }),
            _ => Err(err("HEAD is missing seq/chain/root/t")),
        }
    }

    fn signature_ok(&self, id: &str) -> Option<bool> {
        let (pk, sig) = (self.signer?, self.sig?);
        let vk = VerifyingKey::from_bytes(&pk).ok();
        Some(match vk {
            Some(vk) => vk.verify(&self.message(id), &Signature::from_bytes(&sig)).is_ok(),
            None => false,
        })
    }
}

fn make_head(log: &Log, entries: &[Entry], sign: Option<&Identity>) -> Head {
    let mut h = Head {
        seq: entries.len() as u64,
        chain: entries.last().map(|e| e.chain).unwrap_or_else(|| log.genesis()),
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

fn read_index(log: &Log) -> Result<ParsedIndex> {
    let text = fs::read(log.dir.join(INDEX_FILE)).map_err(|e| err(format!("read INDEX: {e}")))?;
    Ok(parse_index(&String::from_utf8_lossy(&text), &log.genesis()))
}

fn read_head(log: &Log) -> Option<Result<Head>> {
    let p = log.dir.join(HEAD_FILE);
    if !p.is_file() {
        return None;
    }
    Some(fs::read_to_string(&p).map_err(io).and_then(|t| Head::parse(&t)))
}

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
    let dir = dir_for_init(path);
    if dir.exists() && fs::read_dir(&dir).map(|mut r| r.next().is_some()).unwrap_or(true) {
        return Err(err(format!("{} already exists and is not empty; refusing", dir.display())));
    }
    let name = container::strip_suffix(
        dir.file_name().and_then(|n| n.to_str()).ok_or_else(|| err("bad log name"))?,
    )
    .to_string();
    let mut raw = [0u8; 16];
    getrandom::getrandom(&mut raw).map_err(|e| err(e.to_string()))?;
    let id = hex::encode(raw);
    fs::create_dir_all(dir.join(SEGMENTS_DIR)).map_err(io)?;
    let mut m = container::Manifest::new(KIND, &name);
    m.extra.insert("log".into(), LOG_FORMAT.to_string());
    m.extra.insert("log-id".into(), id.clone());
    let signer = sign.map(|i| SigningKey::from_bytes(&i.ed25519_seed).verifying_key().to_bytes());
    if let Some(pk) = &signer {
        m.extra.insert("signer".into(), hex32(pk));
    }
    let log = Log { dir: dir.clone(), name, id, signer };
    write_atomic(&dir.join(INDEX_FILE), format!("{INDEX_MAGIC}\n").as_bytes())?;
    write_atomic(&dir.join(HEAD_FILE), make_head(&log, &[], sign).render().as_bytes())?;
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
        AppendOpts { mode: Mode::Reflection, pass: None, recipients: &[], identity: None }
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

/// Seal `data` as the next immutable segment and extend the chain.
pub fn append(path: &Path, data: &[u8], opts: &AppendOpts<'_>) -> Result<AppendReport> {
    let log = Log::open(path)?;
    match (&log.signer, opts.identity) {
        (Some(_), None) => {
            return Err(err("this log is signed: give the signing key with --identity KEY.sgk"));
        }
        (None, Some(_)) => {
            return Err(err("this log was created unsigned (no --identity at init); appends cannot sign it"));
        }
        (Some(pk), Some(id)) => {
            if SigningKey::from_bytes(&id.ed25519_seed).verifying_key().to_bytes() != *pk {
                return Err(err("--identity is not the key this log is pinned to"));
            }
        }
        (None, None) => {}
    }
    let _guard = lock(&log)?;
    let mut notes = Vec::new();
    let idx = read_index(&log)?;
    if let Some((line, _, msg)) = &idx.error {
        return Err(err(format!("INDEX is damaged at line {line} ({msg}); run `sigil log verify` — refusing to append")));
    }
    let n = idx.entries.len();
    match read_head(&log) {
        Some(Ok(h)) => {
            if h.seq as usize > n {
                return Err(err(format!(
                    "HEAD says {} entries but INDEX has {n}: the index was truncated; refusing to append (run `sigil log verify`)",
                    h.seq
                )));
            }
            if h.seq > 0 && idx.entries[h.seq as usize - 1].chain != h.chain {
                return Err(err("HEAD does not match INDEX; refusing to append (run `sigil log verify`)"));
            }
            if (h.seq as usize) < n {
                notes.push(format!(
                    "HEAD was {} entr{} behind INDEX (an earlier append was interrupted); the new HEAD covers them",
                    n - h.seq as usize,
                    if n - h.seq as usize == 1 { "y" } else { "ies" }
                ));
            }
        }
        Some(Err(e)) => return Err(err(format!("HEAD unreadable ({e}); refusing to append"))),
        None => notes.push("HEAD was missing; rewritten".into()),
    }
    if idx.torn {
        notes.push("trimmed a torn last INDEX line left by a crash".into());
    }
    let seq = n as u64 + 1;
    let prev = idx.entries.last().map(|e| e.chain).unwrap_or_else(|| log.genesis());
    let sha = sha256(data);
    let sealed = crate::seal_kn_to(
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
    )?;
    // 1. segment (atomic; replaces an unindexed leftover from a crash at the same seq)
    let seg = log.segment_path(seq);
    write_atomic(&seg, &sealed)?;
    // 2. INDEX line
    let t = now();
    let body = format!("seq={seq} t={t} size={} sha={}", data.len(), hex32(&sha));
    let chain = chain_hash(&prev, &body);
    let line = format!("{body} chain={}\n", hex32(&chain));
    {
        let ipath = log.dir.join(INDEX_FILE);
        let f = fs::OpenOptions::new().write(true).open(&ipath).map_err(io)?;
        f.set_len(idx.good_len).map_err(io)?;
        let mut f = fs::OpenOptions::new().append(true).open(&ipath).map_err(io)?;
        f.write_all(line.as_bytes()).map_err(io)?;
        f.sync_all().map_err(io)?;
    }
    // 3. HEAD
    let mut entries = idx.entries;
    entries.push(Entry { seq, time: t, size: data.len() as u64, sha, chain, body });
    let head = make_head(&log, &entries, opts.identity);
    write_atomic(&log.dir.join(HEAD_FILE), head.render().as_bytes())?;
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
    pub head: Option<Head>,
    /// Segment file present for entry `i`.
    pub present: Vec<bool>,
}

/// Index-only listing (no segment bytes are read).
pub fn list(path: &Path) -> Result<Listing> {
    let log = Log::open(path)?;
    let idx = read_index(&log)?;
    if let Some((line, _, msg)) = &idx.error {
        return Err(err(format!("INDEX is damaged at line {line}: {msg} (run `sigil log verify`)")));
    }
    let present = idx.entries.iter().map(|e| log.segment_path(e.seq).is_file()).collect();
    let head = read_head(&log).and_then(|h| h.ok());
    Ok(Listing { log, entries: idx.entries, head, present })
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
    format!("{y:04}-{m:02}-{d:02}T{:02}:{:02}:{:02}Z", rem / 3600, rem % 3600 / 60, rem % 60)
}

impl Listing {
    pub fn render(&self) -> String {
        let head = self.head.as_ref();
        let mut s = format!(
            "log {}  entries={}  {}\n",
            self.log.dir.display(),
            self.entries.len(),
            match head.and_then(|h| h.signer) {
                Some(pk) => format!("signed by {}", &hex32(&pk)[..16]),
                None if self.log.signer.is_some() => "signer pinned, HEAD UNSIGNED".to_string(),
                None => "unsigned".to_string(),
            }
        );
        s.push_str("  seq  time (UTC)            size        sha256            segment\n");
        for (e, p) in self.entries.iter().zip(&self.present) {
            s.push_str(&format!(
                "  {:<4} {}  {:<10}  {}…  {}\n",
                e.seq,
                iso_utc(e.time),
                e.size,
                &hex32(&e.sha)[..16],
                if *p { "ok" } else { "MISSING" }
            ));
        }
        if let Some(h) = head {
            s.push_str(&format!("head: seq {}  root {}\n", h.seq, hex32(&h.root)));
            s.push_str(&format!("anchor (pin elsewhere, check with `verify --anchor`): {}:{}\n", h.seq, hex32(&h.root)));
        }
        s
    }
}

pub struct ReadOpts<'a> {
    pub pass: Option<&'a str>,
    pub identities: &'a [Identity],
}

/// Plain bytes of one segment, checked against the INDEX (hash and size).
pub fn read_segment(log: &Log, e: &Entry, opts: &ReadOpts<'_>) -> Result<Vec<u8>> {
    let p = log.segment_path(e.seq);
    let file = fs::read(&p).map_err(|er| err(format!("segment {} unreadable: {er}", e.seq)))?;
    let plain = crate::unseal_ex_keys(&file, opts.pass, &[], opts.identities)
        .map_err(|er| err(format!("segment {}: {er}", e.seq)))?;
    if sha256(&plain) != e.sha || plain.len() as u64 != e.size {
        return Err(err(format!("segment {} does not match the index (substituted or altered)", e.seq)));
    }
    Ok(plain)
}

/// Read segments `from..=to` (1-based, inclusive) after checking INDEX and HEAD integrity.
pub fn read_range(path: &Path, from: u64, to: u64, opts: &ReadOpts<'_>) -> Result<Vec<(u64, Vec<u8>)>> {
    let log = Log::open(path)?;
    let loaded = load(&log, &CheckOpts::default());
    if let Some(f) = loaded.findings.iter().find(|f| f.severity == Severity::Error) {
        return Err(err(format!("refusing to read: {} {}: {}", f.code, f.subject, f.message)));
    }
    let n = loaded.index.entries.len() as u64;
    if from == 0 || to < from {
        return Err(err("segment numbers start at 1 and --from must not exceed --to"));
    }
    if to > n {
        return Err(err(format!("segment {to} does not exist (the log has {n})")));
    }
    let mut out = Vec::new();
    for e in &loaded.index.entries[(from - 1) as usize..to as usize] {
        out.push((e.seq, read_segment(&log, e, opts)?));
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
    /// Require HEAD signed by this Ed25519 key (in addition to the manifest pin).
    pub signer: Option<[u8; 32]>,
    /// `(seq, root)` pins: the Merkle root of the first `seq` entries must equal `root`.
    pub anchors: &'a [(u64, [u8; 32])],
    pub temp_age_secs: u64,
}

impl Default for CheckOpts<'_> {
    fn default() -> Self {
        CheckOpts { pass: None, identities: &[], quick: true, signer: None, anchors: &[], temp_age_secs: crate::gc::DEFAULT_TEMP_AGE_SECS }
    }
}

struct Loaded {
    index: ParsedIndex,
    head: Option<Head>,
    findings: Vec<Finding>,
}

fn fnd(sev: Severity, code: &'static str, subject: impl Into<String>, msg: impl Into<String>, hint: Option<&str>) -> Finding {
    Finding { severity: sev, code, subject: subject.into(), message: msg.into(), hint: hint.map(String::from) }
}

/// INDEX chain + HEAD checks (no segment files are touched).
fn load(log: &Log, opts: &CheckOpts<'_>) -> Loaded {
    let mut findings = Vec::new();
    let index = match read_index(log) {
        Ok(i) => i,
        Err(e) => {
            findings.push(fnd(Severity::Error, "index-missing", INDEX_FILE, e.to_string(), Some("restore INDEX from a copy; segments are still on disk")));
            return Loaded { index: ParsedIndex::default(), head: None, findings };
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
        findings.push(fnd(Severity::Warn, "index-torn", INDEX_FILE, "last INDEX line is incomplete (crash during append); ignored", Some("the next append trims it")));
    }
    let n = index.entries.len() as u64;
    let broken = index.error.is_some();
    let head = match read_head(log) {
        None => {
            findings.push(fnd(
                if log.signer.is_some() { Severity::Error } else { Severity::Warn },
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
                    format!("HEAD covers {} entries but INDEX has only {n}: entries were cut off", h.seq),
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
                findings.push(fnd(Severity::Error, "head-mismatch", HEAD_FILE, format!("HEAD's chain at seq {} differs from INDEX (history rewritten)", h.seq), None));
            } else if root_of(&index.entries[..h.seq as usize]) != h.root {
                findings.push(fnd(Severity::Error, "head-root", HEAD_FILE, "HEAD's Merkle root does not match the INDEX entries", None));
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
        match (h.signature_ok(&log.id), h.signer, log.signer) {
            (Some(false), _, _) => findings.push(fnd(Severity::Error, "head-signature", HEAD_FILE, "HEAD signature does not verify (altered, or from another log)", None)),
            (_, Some(pk), Some(pin)) if pk != pin => findings.push(fnd(Severity::Error, "head-signer", HEAD_FILE, "HEAD is signed by a different key than the one pinned at init", None)),
            (None, _, Some(_)) => findings.push(fnd(Severity::Error, "head-unsigned", HEAD_FILE, "this log pins a signer but HEAD is not signed (signature stripped?)", None)),
            _ => {}
        }
        if let Some(want) = opts.signer {
            if h.signer != Some(want) {
                findings.push(fnd(Severity::Error, "head-signer", HEAD_FILE, format!("HEAD is not signed by the expected key {}", &hex32(&want)[..16]), None));
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
    Loaded { index, head, findings }
}

#[derive(Debug, Default)]
pub struct CheckReport {
    pub findings: Vec<Finding>,
    pub entries: usize,
    pub verified: usize,
    pub container_version: Option<u32>,
    pub signed: bool,
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
            rep.findings.push(fnd(Severity::Error, "manifest", container::CONTAINER_FILE, e.to_string(), Some("upgrade sigil if the log format is newer")));
            return Ok(rep);
        }
    };
    let loaded = load(&log, opts);
    rep.findings.extend(loaded.findings);
    rep.signed = loaded.head.as_ref().map(|h| h.sig.is_some()).unwrap_or(false);
    let entries = loaded.index.entries;
    rep.entries = entries.len();
    let keyed = opts.pass.is_some() || !opts.identities.is_empty();
    for e in &entries {
        let p = log.segment_path(e.seq);
        let subject = p.strip_prefix(&dir).unwrap_or(&p).display().to_string();
        let bytes = match fs::read(&p) {
            Ok(b) => b,
            Err(_) => {
                rep.findings.push(fnd(Severity::Error, "segment-missing", subject, format!("index entry {} has no segment file", e.seq), Some("restore the segment from a copy (any copy of the sealed .sg1 works)")));
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
                rep.findings.push(fnd(Severity::Error, "bit-rot-unrecoverable", subject.clone(), "not readable as a mark", Some("restore this segment from another copy")));
                continue;
            }
            _ => {}
        }
        if !opts.quick {
            match health_bytes(&bytes) {
                Health::Ok => {}
                Health::Mendable(m) => rep.findings.push(fnd(Severity::Warn, "bit-rot", subject.clone(), format!("{m} — repairable"), Some("sigil log mend PATH"))),
                Health::Damaged(m) => {
                    rep.findings.push(fnd(Severity::Error, "bit-rot-unrecoverable", subject.clone(), m, Some("restore this segment from another copy")));
                    continue;
                }
            }
        }
        if keyed {
            match crate::unseal_ex_keys(&bytes, opts.pass, &[], opts.identities) {
                Ok(plain) if sha256(&plain) == e.sha && plain.len() as u64 == e.size => {}
                Ok(_) => rep.findings.push(fnd(Severity::Error, "segment-content", subject, format!("segment {} unseals to bytes that differ from the index", e.seq), None)),
                Err(er) => rep.findings.push(fnd(Severity::Error, "segment-unseal", subject, format!("segment {} cannot be opened with the given keys: {er}", e.seq), None)),
            }
        }
    }
    // Strays.
    let st = scan_extras(&log, entries.len() as u64, opts.temp_age_secs);
    for x in &st {
        match x.kind {
            ExtraKind::Orphan => rep.findings.push(fnd(Severity::Warn, "orphan-segment", x.rel(&dir), format!("segment no INDEX entry uses ({} bytes): a crashed append", x.bytes), Some("sigil gc --apply"))),
            ExtraKind::Recent => rep.findings.push(fnd(Severity::Info, "recent-segment", x.rel(&dir), "unindexed but recent: an append may be in progress", None)),
            ExtraKind::Temp => rep.findings.push(fnd(Severity::Warn, "temp-file", x.rel(&dir), "abandoned temp file", Some("sigil gc --apply"))),
            ExtraKind::Unknown => rep.findings.push(fnd(Severity::Info, "unknown-file", x.rel(&dir), "not part of a segment log; left alone", None)),
            ExtraKind::EmptyDir => {}
        }
    }
    Ok(rep)
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
}

pub(crate) struct Extra {
    pub path: PathBuf,
    pub kind: ExtraKind,
    pub bytes: u64,
}

impl Extra {
    fn rel(&self, root: &Path) -> String {
        self.path.strip_prefix(root).unwrap_or(&self.path).display().to_string()
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
    let mut v: Vec<PathBuf> = fs::read_dir(dir).map(|r| r.flatten().map(|e| e.path()).collect()).unwrap_or_default();
    v.sort();
    v
}

fn seg_seq(p: &Path) -> Option<u64> {
    let n = p.file_name()?.to_str()?;
    let stem = n.strip_suffix(".sg1")?;
    (stem.len() == 10 && stem.bytes().all(|b| b.is_ascii_digit())).then(|| stem.parse().ok())?
}

/// Everything in the log folder that is not a live segment. Live segments (seq ≤ `entries`)
/// are never listed, so nothing built on this can delete one.
pub(crate) fn scan_extras(log: &Log, entries: u64, temp_age: u64) -> Vec<Extra> {
    let mut out = Vec::new();
    let sz = |p: &Path| fs::metadata(p).map(|m| m.len()).unwrap_or(0);
    for p in sorted(&log.dir) {
        let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string();
        if matches!(n.as_str(), container::CONTAINER_FILE | INDEX_FILE | HEAD_FILE) {
            continue;
        }
        if p.is_dir() && n == SEGMENTS_DIR {
            continue;
        }
        if p.is_file() && (n.ends_with(".part") || n == LOCK_FILE) {
            if old_enough(&p, temp_age) {
                out.push(Extra { bytes: sz(&p), path: p, kind: ExtraKind::Temp });
            }
            continue;
        }
        out.push(Extra { bytes: 0, path: p, kind: ExtraKind::Unknown });
    }
    for shard in sorted(&log.dir.join(SEGMENTS_DIR)) {
        if !shard.is_dir() {
            out.push(Extra { bytes: 0, path: shard, kind: ExtraKind::Unknown });
            continue;
        }
        let files = sorted(&shard);
        let mut live = 0usize;
        for p in &files {
            let n = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if n.ends_with(".part") && p.is_file() {
                if old_enough(p, temp_age) {
                    out.push(Extra { bytes: sz(p), path: p.clone(), kind: ExtraKind::Temp });
                } else {
                    live += 1;
                }
                continue;
            }
            match seg_seq(p) {
                Some(s) if s >= 1 && s <= entries => live += 1,
                Some(_) => {
                    live += 1;
                    let kind = if old_enough(p, temp_age) { ExtraKind::Orphan } else { ExtraKind::Recent };
                    out.push(Extra { bytes: sz(p), path: p.clone(), kind });
                }
                None => {
                    live += 1;
                    out.push(Extra { bytes: 0, path: p.clone(), kind: ExtraKind::Unknown });
                }
            }
        }
        if live == 0 {
            out.push(Extra { bytes: 0, path: shard, kind: ExtraKind::EmptyDir });
        }
    }
    out
}

/// Safety gate for `gc`: the INDEX must be fully readable and HEAD must not claim more entries
/// than the INDEX holds (otherwise "beyond the index" could be live data). Returns the entry count.
pub(crate) fn gc_gate(log: &Log) -> Result<u64> {
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
    Ok(idx.entries.len() as u64)
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
}

/// Heal every repairable segment in place (atomic replace). Never changes the INDEX / HEAD:
/// mending keeps the plain bytes and their true-name.
pub fn mend(path: &Path) -> Result<MendReport> {
    let log = Log::open(path)?;
    let idx = read_index(&log)?;
    if let Some((line, _, msg)) = &idx.error {
        return Err(err(format!("INDEX is damaged at line {line} ({msg}); run `sigil log verify`")));
    }
    let mut rep = MendReport::default();
    for e in &idx.entries {
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
                    let good = crate::locate_header(&healed).map(|(h, _, _)| h.digest == e.sha).unwrap_or(false);
                    if !good {
                        rep.unrecoverable.push((e.seq, "mended star does not carry the indexed true-name".into()));
                    } else if healed != bytes {
                        write_atomic(&p, &healed)?;
                        rep.mended.push(e.seq);
                    }
                }
                Err(er) => rep.unrecoverable.push((e.seq, er.to_string())),
            },
        }
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
        assert!(p.torn && p.entries.len() == 1 && p.good_len as usize == INDEX_MAGIC.len() + 1 + l1.len());
    }

    #[test]
    fn head_roundtrip_and_signature() {
        let id = Identity::generate().unwrap();
        let log = Log { dir: PathBuf::new(), name: "x".into(), id: "ab".repeat(16), signer: None };
        let h = make_head(&log, &[], Some(&id));
        let back = Head::parse(&h.render()).unwrap();
        assert_eq!(back, h);
        assert_eq!(back.signature_ok(&log.id), Some(true));
        assert_eq!(back.signature_ok("another-log-id"), Some(false), "signature is bound to the log id");
        assert_eq!(make_head(&log, &[], None).signature_ok(&log.id), None);
    }
}
