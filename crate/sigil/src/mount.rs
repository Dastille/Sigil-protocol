//! Mount of a `.sg1` / SGDR pack, vault tip, or segment log so apps see normal paths.
//!
//! Durable seals stay intact: cleartext lives only in RAM (FUSE) or an export
//! directory. Use `--export-dir --writable` for a dirty cleartext tree, then
//! `sigil vault commit --from-export` to re-seal as a new vault version.
//! FUSE remains read-only. Segment logs (`kind=log`) mount read-only as one file
//! per live segment (tombstones omitted; compaction members keep their original
//! seq names); always available via `--export-dir`.

use crate::folder::{is_dir_pack, list_dir_pack, locate_entry_star, DirEntry};
use crate::keys::Identity;
use crate::packhead::{PackLayout, Src};
use crate::vault::{self, VAULT_SUFFIX};
use crate::work::{is_work_pack, payload_name, PackReader, WORK_MAGIC};
use crate::{locate_header, unseal_ex_keys, Result};
use std::collections::{HashMap, VecDeque};
use std::fs;
use std::io::{self, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1);

/// Most bytes of whole-held members (classic seals, log segments) kept decoded between
/// reads. Past it the oldest are dropped and decoded again when read; the member being
/// read is always kept, so a member larger than this still opens.
const WHOLE_CACHE_BYTES: u64 = 256 * 1024 * 1024;

/// Decoded chunk stars kept between reads (each is one star, at most the pack's
/// `--chunk`, 4 MiB by default). Shared by large-file members and a large Warded
/// Tome's body: three is the fewest that keep a member star and the two body stars
/// it may straddle, so sequential reads decode each star once.
const STAR_CACHE: usize = 3;

/// Star-cache key of a large Warded Tome's body (inode numbers start at 1).
const BODY_KEY: u64 = 0;

/// Where a large-file member's SGWK pack lives.
#[derive(Clone, Debug)]
enum PackHome {
    /// `[base, base + len)` of a file on disk (a whole `.sg1`, a constellation star, or a
    /// member in place inside a plain Tome).
    File { path: PathBuf, base: u64, len: u64 },
    /// `[base, base + len)` of a Warded Tome's inner pack, already decrypted in memory
    /// (a small body: at most the Tome's `--chunk`).
    Inner { base: u64, len: u64 },
    /// `[base, base + len)` of a large Warded Tome's inner pack, decrypted a body star
    /// at a time on demand (never whole).
    Body { base: u64, len: u64 },
}

/// A readable view of a [`PackHome`] (offsets are relative to the pack's first byte).
enum HomeSrc<'a> {
    File {
        f: crate::packhead::FileSrc,
        base: u64,
        len: u64,
    },
    Mem(&'a [u8]),
    Body {
        fs: &'a VaultFs,
        base: u64,
        len: u64,
    },
}

impl Src for HomeSrc<'_> {
    fn size(&self) -> u64 {
        match self {
            HomeSrc::File { len, .. } | HomeSrc::Body { len, .. } => *len,
            HomeSrc::Mem(m) => m.len() as u64,
        }
    }
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<()> {
        let size = self.size();
        if off.checked_add(buf.len() as u64).is_none_or(|e| e > size) {
            return Err(crate::Error::Msg("read past the end of the pack".into()));
        }
        match self {
            HomeSrc::File { f, base, .. } => f.read_at(*base + off, buf),
            HomeSrc::Mem(m) => {
                let start = off as usize;
                buf.copy_from_slice(&m[start..start + buf.len()]);
                Ok(())
            }
            HomeSrc::Body { fs, base, .. } => {
                let body = fs
                    .sealed_body
                    .as_ref()
                    .ok_or_else(|| crate::Error::Msg("internal: no Warded Tome body".into()))?;
                fs.pieces_fill(BODY_KEY, body, *base + off, buf)
            }
        }
    }
}

/// `Read + Seek` over a [`Src`], for walking a Tome's framing held in one.
struct SrcCursor<S: Src> {
    src: S,
    pos: u64,
}

impl<S: Src> Read for SrcCursor<S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        let left = self.src.size().saturating_sub(self.pos);
        let n = (out.len() as u64).min(left) as usize;
        if n == 0 {
            return Ok(0);
        }
        self.src
            .read_at(self.pos, &mut out[..n])
            .map_err(|e| io::Error::other(e.to_string()))?;
        self.pos += n as u64;
        Ok(n)
    }
}

impl<S: Src> Seek for SrcCursor<S> {
    fn seek(&mut self, to: SeekFrom) -> io::Result<u64> {
        let size = self.src.size() as i128;
        let next = match to {
            SeekFrom::Start(o) => o as i128,
            SeekFrom::End(d) => size + d as i128,
            SeekFrom::Current(d) => self.pos as i128 + d as i128,
        };
        if !(0..=size).contains(&next) {
            return Err(io::Error::other("seek outside the Tome body"));
        }
        self.pos = next as u64;
        Ok(self.pos)
    }
}

/// Reads a pack's plaintext star by star through a [`PackReader`] (with all its
/// checks), noting each star's plaintext `(offset, length)` as it goes.
struct SpanReader<'a, S: Src> {
    r: PackReader<'a, S>,
    spans: Vec<(u64, u64)>,
    at: u64,
    buf: Vec<u8>,
    pos: usize,
}

impl<S: Src> Read for SpanReader<'_, S> {
    fn read(&mut self, out: &mut [u8]) -> io::Result<usize> {
        // Skips empty stars; bounded by the star count (one star per pass).
        while self.pos == self.buf.len() {
            match self.r.next_star() {
                Ok(Some(p)) => {
                    self.spans.push((self.at, p.len() as u64));
                    self.at += p.len() as u64;
                    self.buf = p;
                    self.pos = 0;
                }
                Ok(None) => return Ok(0),
                Err(e) => return Err(io::Error::other(e.to_string())),
            }
        }
        let n = out.len().min(self.buf.len() - self.pos);
        out[..n].copy_from_slice(&self.buf[self.pos..self.pos + n]);
        self.pos += n;
        Ok(n)
    }
}

/// A large-file member, read one chunk star at a time.
///
/// Opening it reads every star once with the same checks as `sigil unseal` (each star's
/// own check, its facet position, and the pack's total), holding one star at a time, and
/// records where each star's plaintext starts. Later reads open only the stars they
/// cover and check each one again, so a pack changed on disk after it was opened is
/// refused rather than read.
struct PackPieces {
    home: PackHome,
    layout: PackLayout,
    /// Plaintext `(offset, length)` of each star, in order.
    spans: Vec<(u64, u64)>,
    pass: Option<String>,
}

/// Where a member's bytes come from, before any large pack is checked.
enum Located {
    /// Decoded whole (a classic seal or log segment).
    Whole(Arc<Vec<u8>>),
    /// A large-file pack at `home`, opened with `pass`.
    Pack(PackHome, Option<String>),
}

/// How a member's bytes are held.
#[derive(Clone)]
enum Body {
    /// Decoded whole (one AES-GCM message, or a log segment).
    Whole(Arc<Vec<u8>>),
    /// A large-file member read in pieces.
    Pack(Arc<PackPieces>),
}

/// A decoded chunk star kept between reads: `((inode, star index), plaintext)`.
type CachedStar = ((u64, usize), Arc<Vec<u8>>);

/// Decoded members and stars kept between reads, with the bounds above.
#[derive(Default)]
struct Cache {
    bodies: HashMap<u64, Body>,
    /// Inodes of whole-held bodies, oldest first, and their total size.
    whole_order: VecDeque<u64>,
    whole_bytes: u64,
    /// Recently opened chunk stars: `((inode, star index), plaintext)`, oldest first.
    stars: VecDeque<CachedStar>,
}

impl Cache {
    fn keep_whole(&mut self, ino: u64, data: &Arc<Vec<u8>>) {
        self.bodies.insert(ino, Body::Whole(data.clone()));
        self.whole_order.push_back(ino);
        self.whole_bytes += data.len() as u64;
        // Bounded by the number of held bodies; never drops the one just added.
        while self.whole_bytes > WHOLE_CACHE_BYTES && self.whole_order.len() > 1 {
            let Some(old) = self.whole_order.pop_front() else {
                break;
            };
            if let Some(Body::Whole(d)) = self.bodies.remove(&old) {
                self.whole_bytes = self.whole_bytes.saturating_sub(d.len() as u64);
            }
        }
    }

    fn star(&self, key: (u64, usize)) -> Option<Arc<Vec<u8>>> {
        self.stars
            .iter()
            .find(|(k, _)| *k == key)
            .map(|(_, v)| v.clone())
    }

    fn keep_star(&mut self, key: (u64, usize), plain: Arc<Vec<u8>>) {
        self.stars.retain(|(k, _)| *k != key);
        self.stars.push_back((key, plain));
        while self.stars.len() > STAR_CACHE {
            self.stars.pop_front();
        }
    }
}

#[derive(Clone, Debug)]
enum FileSrc {
    /// Whole seal is one payload (single-file mark / work pack / vault tip mark).
    Whole,
    /// One entry inside an SGDR folder pack (`rel` is the pack-relative path).
    Entry { rel: String },
    /// A constellation member: the star file for one list name (`None` = star missing).
    Member { star: Option<PathBuf> },
    /// One live segment of a `kind=log` container (plain bytes; may sit inside a compaction holder).
    LogSeg { seq: u64 },
}

#[derive(Clone, Debug)]
enum NodeKind {
    Dir,
    File { size: u64, src: FileSrc },
}

#[derive(Clone, Debug)]
struct Node {
    name: String,
    parent: u64,
    kind: NodeKind,
    children: Vec<u64>,
}

/// In-memory VFS over a durable `.sg1` (never written).
pub struct VaultFs {
    seal: PathBuf,
    /// Set when this VFS is a segment-log view (`kind=log`); `seal` is then the log directory.
    log_dir: Option<PathBuf>,
    pass: Option<String>,
    wards: Vec<(String, String)>,
    identities: Vec<Identity>,
    nodes: HashMap<u64, Node>,
    /// path → ino ("" = root)
    by_path: HashMap<String, u64>,
    next_ino: u64,
    cache: Mutex<Cache>,
    /// Inner v1 pack of a sealed (v2) folder pack with a small (classic) body,
    /// decrypted in memory only; at most the Tome's `--chunk`.
    sealed_inner: Option<Arc<Vec<u8>>>,
    /// A sealed (v2) folder pack with a large (SGWK) body: read a body star at a time.
    sealed_body: Option<Arc<PackPieces>>,
    uid: u32,
    gid: u32,
}

impl VaultFs {
    /// Open a mountable source: `.sg1`, SGDR pack, or vault tip (`--vault` / `.sgv`).
    pub fn open(
        input: &Path,
        pass: Option<&str>,
        wards: &[(String, String)],
        prefer_vault: bool,
    ) -> Result<Self> {
        Self::open_keys(input, pass, wards, prefer_vault, &[])
    }

    pub fn open_keys(
        input: &Path,
        pass: Option<&str>,
        wards: &[(String, String)],
        prefer_vault: bool,
        identities: &[Identity],
    ) -> Result<Self> {
        let sky = if prefer_vault {
            None
        } else {
            crate::names::sky_dir(input)
        };
        let seal = match &sky {
            Some(d) => crate::constellation::find_card(d)
                .ok_or_else(|| crate::Error::Msg("no constellation card".into()))?,
            None => resolve_seal(input, prefer_vault)?,
        };
        let mut fs = VaultFs {
            seal: seal.clone(),
            log_dir: None,
            pass: pass.map(|s| s.to_string()),
            wards: wards.to_vec(),
            identities: identities.to_vec(),
            nodes: HashMap::new(),
            by_path: HashMap::new(),
            next_ino: 2,
            cache: Mutex::new(Cache::default()),
            sealed_inner: None,
            sealed_body: None,
            uid: current_uid(),
            gid: current_gid(),
        };
        fs.nodes.insert(
            1,
            Node {
                name: String::new(),
                parent: 1,
                kind: NodeKind::Dir,
                children: Vec::new(),
            },
        );
        fs.by_path.insert(String::new(), 1);

        if let Some(d) = sky {
            fs.build_constellation(&d)?;
        } else if is_dir_pack(&seal) {
            fs.build_dir_pack()?;
        } else {
            fs.build_single()?;
        }
        Ok(fs)
    }

    /// Open a `kind=log` container: one file per live segment (tombstones absent).
    /// Filenames are zero-padded seqs (`0000000007`), matching on-disk segment basenames without `.sg1`.
    /// Compaction members stay addressable under their original seq (same as `log read --seq`).
    pub fn open_log(input: &Path, pass: Option<&str>, identities: &[Identity]) -> Result<Self> {
        // A private INDEX is opened with the same keys `log ls` / `log read` take; without them
        // (or with wrong ones) `list_with` refuses, so no sizes or paths are shown.
        let listing = if crate::seglog::Log::open(input)?.privindex {
            if pass.is_none() && identities.is_empty() {
                return Err(crate::Error::Msg(
                    "this log has a private INDEX: give --pass / --pass-file / --identity to mount it".into(),
                ));
            }
            crate::seglog::list_with(input, pass, identities)?
        } else {
            crate::seglog::list(input)?
        };
        if listing.entries.iter().any(|e| e.is_locked()) {
            return Err(crate::Error::Msg(
                "the private INDEX did not open with these keys (wrong --pass / --identity?)"
                    .into(),
            ));
        }
        let log_dir = listing.log.dir.clone();
        let mut fs = VaultFs {
            seal: log_dir.clone(),
            log_dir: Some(log_dir),
            pass: pass.map(|s| s.to_string()),
            wards: Vec::new(),
            identities: identities.to_vec(),
            nodes: HashMap::new(),
            by_path: HashMap::new(),
            next_ino: 2,
            cache: Mutex::new(Cache::default()),
            sealed_inner: None,
            sealed_body: None,
            uid: current_uid(),
            gid: current_gid(),
        };
        fs.nodes.insert(
            1,
            Node {
                name: String::new(),
                parent: 1,
                kind: NodeKind::Dir,
                children: Vec::new(),
            },
        );
        fs.by_path.insert(String::new(), 1);
        for e in &listing.entries {
            if !listing.state.is_seg(e.seq) {
                continue;
            }
            if listing.state.deleted_by(e.seq).is_some() {
                continue;
            }
            let name = crate::seglog::mount_name(e.seq);
            fs.add_file("", &name, e.size, FileSrc::LogSeg { seq: e.seq })?;
        }
        Ok(fs)
    }

    /// True when this VFS is a segment-log view.
    pub fn is_log(&self) -> bool {
        self.log_dir.is_some()
    }

    pub fn seal_path(&self) -> &Path {
        &self.seal
    }

    pub fn list_dir(&self, path: &str) -> Result<Vec<(String, bool, u64)>> {
        let ino = self
            .lookup_path(path)
            .ok_or_else(|| crate::Error::Msg(format!("no such path in mount: {path:?}")))?;
        let node = self
            .nodes
            .get(&ino)
            .ok_or_else(|| crate::Error::Msg(format!("missing inode {ino}")))?;
        match &node.kind {
            NodeKind::Dir => {
                let mut out = Vec::new();
                for &c in &node.children {
                    let n = &self.nodes[&c];
                    let (is_dir, size) = match &n.kind {
                        NodeKind::Dir => (true, 0u64),
                        NodeKind::File { size, .. } => (false, *size),
                    };
                    out.push((n.name.clone(), is_dir, size));
                }
                out.sort_by(|a, b| a.0.cmp(&b.0));
                Ok(out)
            }
            NodeKind::File { .. } => Err(crate::Error::Msg("not a directory".into())),
        }
    }

    /// The whole of one file, in memory. For large files prefer [`VaultFs::read_range`]
    /// or [`VaultFs::copy_file_to`], which hold one chunk star at a time.
    pub fn read_file(&self, path: &str) -> Result<Arc<Vec<u8>>> {
        let ino = self
            .lookup_path(path)
            .ok_or_else(|| crate::Error::Msg(format!("no such path in mount: {path:?}")))?;
        match self.body(ino)? {
            Body::Whole(d) => Ok(d),
            Body::Pack(p) => {
                let mut out = Vec::new();
                self.copy_body_to(ino, &p, &mut out)?;
                Ok(Arc::new(out))
            }
        }
    }

    /// Up to `size` bytes of one file starting at `offset` (fewer at its end, none past
    /// it). A large-file member opens only the chunk stars the range covers.
    pub fn read_range(&self, path: &str, offset: u64, size: usize) -> Result<Vec<u8>> {
        let ino = self
            .lookup_path(path)
            .ok_or_else(|| crate::Error::Msg(format!("no such path in mount: {path:?}")))?;
        self.read_at(ino, offset, size)
    }

    /// Write one whole file to `w`, one chunk star at a time for a large-file member.
    /// Returns the bytes written.
    pub fn copy_file_to<W: Write>(&self, path: &str, w: &mut W) -> Result<u64> {
        let ino = self
            .lookup_path(path)
            .ok_or_else(|| crate::Error::Msg(format!("no such path in mount: {path:?}")))?;
        self.copy_ino_to(ino, w)
    }

    pub fn file_size(&self, path: &str) -> Result<u64> {
        let ino = self
            .lookup_path(path)
            .ok_or_else(|| crate::Error::Msg(format!("no such path in mount: {path:?}")))?;
        match &self.nodes[&ino].kind {
            NodeKind::File { size, .. } => Ok(*size),
            NodeKind::Dir => Err(crate::Error::Msg("is a directory".into())),
        }
    }

    /// Materialize a tree under `dest`. Source `.sg1` is never modified.
    /// When `writable`, cleartext gets normal write bits and `dirty` sidecar is written.
    pub fn export_dir(&self, dest: &Path) -> Result<u32> {
        self.export_dir_ex(dest, false, None)
    }

    pub fn export_dir_ex(
        &self,
        dest: &Path,
        writable: bool,
        dirty: Option<&vault::DirtyMeta>,
    ) -> Result<u32> {
        if dest.exists() {
            if !dest.is_dir() {
                return Err(crate::Error::Msg(format!(
                    "export dest exists and is not a directory: {}",
                    dest.display()
                )));
            }
            // Refuse non-empty dest to avoid clobber surprises.
            let empty = fs::read_dir(dest)
                .map_err(|e| crate::Error::Msg(e.to_string()))?
                .next()
                .is_none();
            if !empty {
                return Err(crate::Error::Msg(format!(
                    "export dest is not empty: {}",
                    dest.display()
                )));
            }
        } else {
            fs::create_dir_all(dest).map_err(|e| crate::Error::Msg(e.to_string()))?;
        }
        let mut n = 0u32;
        for (path, ino) in &self.by_path {
            if path.is_empty() {
                continue;
            }
            let node = &self.nodes[ino];
            let out = dest.join(path);
            match &node.kind {
                NodeKind::Dir => {
                    fs::create_dir_all(&out).map_err(|e| crate::Error::Msg(e.to_string()))?;
                }
                NodeKind::File { .. } => {
                    if let Some(parent) = out.parent() {
                        fs::create_dir_all(parent).map_err(|e| crate::Error::Msg(e.to_string()))?;
                    }
                    self.export_file(*ino, &out)?;
                    n += 1;
                }
            }
        }
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let (dir_mode, file_mode) = if writable {
                (0o755, 0o644)
            } else {
                (0o555, 0o444)
            };
            for (path, ino) in &self.by_path {
                if path.is_empty() {
                    continue;
                }
                let out = dest.join(path);
                let mode = match &self.nodes[ino].kind {
                    NodeKind::Dir => dir_mode,
                    NodeKind::File { .. } => file_mode,
                };
                let _ = fs::set_permissions(&out, fs::Permissions::from_mode(mode));
            }
            // Export root needs write bit when dirty so the sidecar (and later edits) work.
            if writable {
                let _ = fs::set_permissions(dest, fs::Permissions::from_mode(0o755));
            }
        }
        if writable {
            let meta = match dirty {
                Some(m) => m.clone(),
                None => vault::DirtyMeta {
                    source: self.seal.clone(),
                    seal: self.seal.clone(),
                    live: None,
                    vault: false,
                    kind: if is_dir_pack(&self.seal) {
                        "folder".into()
                    } else {
                        "single".into()
                    },
                },
            };
            meta.write(dest)?;
        }
        Ok(n)
    }

    fn build_single(&mut self) -> Result<()> {
        // A v3 encrypted mark shows its name and size only after unlock.
        if let Ok(Some((name, size))) =
            crate::work::payload_label_keys(&self.seal, self.pass.as_deref(), &[], &self.identities)
        {
            if !name.is_empty() {
                let name = sanitize_name(&name);
                self.add_file("", &name, size, FileSrc::Whole)?;
                return Ok(());
            }
        }
        let name = payload_name(&self.seal).unwrap_or_else(|_| {
            self.seal
                .file_stem()
                .and_then(|s| s.to_str())
                .unwrap_or("payload")
                .to_string()
        });
        let name = sanitize_name(&name);
        // Only the head is needed for the size: read a bounded peek first. A classic
        // seal whose header is not found there (damaged, a copy further in) falls back
        // to the whole file, as before, rather than showing a wrong size.
        let bytes = peek_file(&self.seal, crate::header::KEYSTONE_SPAN as u64 + 64)?;
        let size = if is_work_pack(&self.seal) {
            // work head has orig len
            if bytes.len() >= 17 {
                u64::from_le_bytes(bytes[9..17].try_into().unwrap_or([0; 8]))
            } else {
                0
            }
        } else {
            match locate_header(&bytes) {
                Ok((h, _, _)) => h.orig_len,
                Err(_) => {
                    let whole =
                        fs::read(&self.seal).map_err(|e| crate::Error::Msg(e.to_string()))?;
                    locate_header(&whole)
                        .map(|(h, _, _)| h.orig_len)
                        .unwrap_or(0)
                }
            }
        };
        self.add_file("", &name, size, FileSrc::Whole)?;
        Ok(())
    }

    /// Constellation: the tree is the card's list names (`docs/a.txt`); each file decodes its
    /// star on read. Nothing on disk changes.
    fn build_constellation(&mut self, sky: &Path) -> Result<()> {
        let entries = crate::names::sky_entries(sky, self.pass.as_deref(), &self.identities)?;
        for e in entries {
            let rel = e.name.replace('\\', "/");
            if rel.contains("..") || Path::new(&rel).is_absolute() {
                return Err(crate::Error::Msg(format!(
                    "refusing unsafe name on the list: {rel}"
                )));
            }
            let parts: Vec<&str> = rel.split('/').filter(|s| !s.is_empty()).collect();
            let Some((last, dirs)) = parts.split_last() else {
                continue;
            };
            let mut parent = String::new();
            for seg in dirs {
                self.ensure_dir(&parent, seg)?;
                parent = if parent.is_empty() {
                    (*seg).to_string()
                } else {
                    format!("{parent}/{seg}")
                };
            }
            self.add_file(&parent, last, e.size, FileSrc::Member { star: e.star })?;
        }
        Ok(())
    }

    fn build_dir_pack(&mut self) -> Result<()> {
        let large_body = match crate::folder::sealed_dir_body_loc(&self.seal)? {
            Some((count, off, len)) if len >= 4 => {
                let mut mag = [0u8; 4];
                let mut f = crate::packhead::FileSrc::open(&self.seal)?;
                f.read_at(off, &mut mag)?;
                (mag == WORK_MAGIC).then_some((count, off, len))
            }
            _ => None,
        };
        let entries = if let Some((count, off, len)) = large_body {
            // One pass over the body: check every star (one in memory), keep only the
            // star map, and list the members from the same stream.
            let home = PackHome::File {
                path: self.seal.clone(),
                base: off,
                len,
            };
            let pass = self.pass.clone();
            let ids = self.identities.clone();
            let (body, entries) = self.open_pack_with(home, pass.as_deref(), |r| {
                crate::folder::list_inner_stream(r, count, pass.as_deref(), &ids)
            })?;
            self.sealed_body = Some(Arc::new(body));
            entries
        } else if crate::folder::is_sealed_dir_pack(&self.seal) {
            let inner = crate::folder::open_sealed_inner(
                &self.seal,
                self.pass.as_deref(),
                &[],
                &self.identities,
            )?;
            let entries = crate::folder::list_v1_bytes(&inner)?;
            self.sealed_inner = Some(Arc::new(inner));
            entries
        } else {
            list_dir_pack(&self.seal)?
        };
        for e in entries {
            self.add_entry(&e)?;
        }
        Ok(())
    }

    fn add_entry(&mut self, e: &DirEntry) -> Result<()> {
        let rel = e.path.replace('\\', "/");
        if rel.contains("..") || Path::new(&rel).is_absolute() {
            return Err(crate::Error::Msg(format!(
                "refusing unsafe path in Tome: {rel}"
            )));
        }
        // Ensure parent dirs exist.
        let mut parent = String::new();
        let parts: Vec<&str> = rel.split('/').filter(|s| !s.is_empty()).collect();
        if parts.is_empty() {
            return Ok(());
        }
        for (i, seg) in parts.iter().enumerate() {
            let is_last = i + 1 == parts.len();
            let path = if parent.is_empty() {
                (*seg).to_string()
            } else {
                format!("{parent}/{seg}")
            };
            if is_last {
                let size = e.orig.unwrap_or(0);
                self.add_file(&parent, seg, size, FileSrc::Entry { rel: rel.clone() })?;
            } else {
                self.ensure_dir(&parent, seg)?;
                parent = path;
            }
        }
        Ok(())
    }

    fn ensure_dir(&mut self, parent_path: &str, name: &str) -> Result<u64> {
        let full = if parent_path.is_empty() {
            name.to_string()
        } else {
            format!("{parent_path}/{name}")
        };
        if let Some(&ino) = self.by_path.get(&full) {
            return Ok(ino);
        }
        let parent_ino = *self
            .by_path
            .get(parent_path)
            .ok_or_else(|| crate::Error::Msg(format!("missing parent {parent_path:?}")))?;
        let ino = self.next_ino;
        self.next_ino += 1;
        // Every inode in `by_path` is inserted into `nodes` together with it, so the parent is
        // always there; a broken table is refused rather than panicking.
        self.nodes
            .get_mut(&parent_ino)
            .ok_or_else(|| crate::Error::Msg(format!("internal: no inode for {parent_path:?}")))?
            .children
            .push(ino);
        self.nodes.insert(
            ino,
            Node {
                name: name.to_string(),
                parent: parent_ino,
                kind: NodeKind::Dir,
                children: Vec::new(),
            },
        );
        self.by_path.insert(full, ino);
        Ok(ino)
    }

    fn add_file(&mut self, parent_path: &str, name: &str, size: u64, src: FileSrc) -> Result<u64> {
        // Create missing ancestor dirs when parent_path has segments.
        if !parent_path.is_empty() && !self.by_path.contains_key(parent_path) {
            let mut cur = String::new();
            for seg in parent_path.split('/').filter(|s| !s.is_empty()) {
                self.ensure_dir(&cur, seg)?;
                if cur.is_empty() {
                    cur = seg.to_string();
                } else {
                    cur = format!("{cur}/{seg}");
                }
            }
        }
        let parent_ino = *self
            .by_path
            .get(parent_path)
            .ok_or_else(|| crate::Error::Msg(format!("missing parent {parent_path:?}")))?;
        let full = if parent_path.is_empty() {
            name.to_string()
        } else {
            format!("{parent_path}/{name}")
        };
        if self.by_path.contains_key(&full) {
            return Err(crate::Error::Msg(format!("duplicate path {full}")));
        }
        let ino = self.next_ino;
        self.next_ino += 1;
        // Same invariant as `ensure_dir`: refuse a broken inode table instead of panicking.
        self.nodes
            .get_mut(&parent_ino)
            .ok_or_else(|| crate::Error::Msg(format!("internal: no inode for {parent_path:?}")))?
            .children
            .push(ino);
        self.nodes.insert(
            ino,
            Node {
                name: name.to_string(),
                parent: parent_ino,
                kind: NodeKind::File { size, src },
                children: Vec::new(),
            },
        );
        self.by_path.insert(full, ino);
        Ok(ino)
    }

    fn lookup_path(&self, path: &str) -> Option<u64> {
        let p = normalize_rel(path);
        self.by_path.get(&p).copied()
    }

    /// How inode `ino`'s bytes are held, opening (and caching) it on first use.
    fn body(&self, ino: u64) -> Result<Body> {
        if let Some(b) = self.lock_cache().bodies.get(&ino).cloned() {
            return Ok(b);
        }
        let body = match self.locate(ino)? {
            Located::Whole(d) => Body::Whole(d),
            Located::Pack(home, pass) => {
                Body::Pack(Arc::new(self.open_pack(home, pass.as_deref())?))
            }
        };
        let mut c = self.lock_cache();
        match &body {
            Body::Whole(d) => c.keep_whole(ino, d),
            Body::Pack(_) => {
                c.bodies.insert(ino, body.clone());
            }
        }
        Ok(body)
    }

    /// Find inode `ino`'s bytes: a classic member is decoded whole here, a large-file
    /// member is only located (nothing of it is read yet).
    fn locate(&self, ino: u64) -> Result<Located> {
        let node = self
            .nodes
            .get(&ino)
            .ok_or_else(|| crate::Error::Msg(format!("missing inode {ino}")))?;
        let src = match &node.kind {
            NodeKind::File { src, .. } => src.clone(),
            NodeKind::Dir => return Err(crate::Error::Msg("is a directory".into())),
        };
        let body = match src {
            FileSrc::Whole => self.body_of_file(&self.seal, self.pass.as_deref())?,
            FileSrc::Member { star } => {
                let star = star.ok_or_else(|| {
                    crate::Error::Msg(format!(
                        "star for {} is missing (see `sigil doctor`)",
                        node.name
                    ))
                })?;
                self.body_of_file(&star, self.pass.as_deref())?
            }
            FileSrc::Entry { rel } => {
                let file_pass = pass_for(&rel, self.pass.as_deref(), &self.wards);
                self.body_of_entry(&rel, file_pass)?
            }
            FileSrc::LogSeg { seq } => {
                let dir = self
                    .log_dir
                    .as_ref()
                    .ok_or_else(|| crate::Error::Msg("internal: LogSeg without log_dir".into()))?;
                let opts = crate::seglog::ReadOpts {
                    pass: self.pass.as_deref(),
                    identities: &self.identities,
                };
                let out = crate::seglog::read_range(
                    dir,
                    seq,
                    seq,
                    &opts,
                    crate::seglog::ReadMode::Single,
                )?;
                let data = out
                    .parts
                    .into_iter()
                    .next()
                    .map(|(_, b)| b)
                    .ok_or_else(|| crate::Error::Msg(format!("segment {seq} produced no bytes")))?;
                Located::Whole(Arc::new(data))
            }
        };
        Ok(body)
    }

    fn lock_cache(&self) -> std::sync::MutexGuard<'_, Cache> {
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
    }

    /// A whole `.sg1` or constellation star: a large-file pack is read in pieces, a
    /// classic seal is decoded whole.
    fn body_of_file(&self, path: &Path, pass: Option<&str>) -> Result<Located> {
        if is_work_pack(path) {
            let len = fs::metadata(path)
                .map_err(|e| crate::Error::Msg(e.to_string()))?
                .len();
            let home = PackHome::File {
                path: path.to_path_buf(),
                base: 0,
                len,
            };
            return Ok(Located::Pack(home, pass.map(str::to_string)));
        }
        Ok(Located::Whole(Arc::new(decode_whole(
            path,
            pass,
            &self.identities,
        )?)))
    }

    /// One Tome member: located in place (a plain Tome on disk, or a Warded Tome's
    /// decrypted inner pack); a large-file member is read in pieces from there.
    fn body_of_entry(&self, rel: &str, pass: Option<String>) -> Result<Located> {
        if let Some(body) = &self.sealed_body {
            let total = body.spans.last().map(|s| s.0 + s.1).unwrap_or(0);
            let mut cur = SrcCursor {
                src: HomeSrc::Body {
                    fs: self,
                    base: 0,
                    len: total,
                },
                pos: 0,
            };
            let (off, len) = locate_entry_star(&mut cur, total, rel)?;
            let mut mag = [0u8; 4];
            if len >= 4 {
                self.pieces_fill(BODY_KEY, body, off, &mut mag)?;
            }
            if mag == WORK_MAGIC {
                let home = PackHome::Body { base: off, len };
                return Ok(Located::Pack(home, pass));
            }
            // A classic member is one AES-GCM message, at most the Tome's `--chunk` long.
            let n =
                usize::try_from(len).map_err(|_| crate::Error::Msg("member too large".into()))?;
            let mut star = vec![0u8; n];
            self.pieces_fill(BODY_KEY, body, off, &mut star)?;
            return Ok(Located::Whole(Arc::new(decode_star(
                &star,
                pass.as_deref(),
                &self.identities,
            )?)));
        }
        if let Some(inner) = &self.sealed_inner {
            let (off, len) = locate_entry_star(
                &mut io::Cursor::new(inner.as_slice()),
                inner.len() as u64,
                rel,
            )?;
            let (a, b) = (off as usize, (off + len) as usize);
            let star = &inner[a..b];
            if star.starts_with(&WORK_MAGIC) {
                let home = PackHome::Inner { base: off, len };
                return Ok(Located::Pack(home, pass));
            }
            return Ok(Located::Whole(Arc::new(decode_star(
                star,
                pass.as_deref(),
                &self.identities,
            )?)));
        }
        let size = fs::metadata(&self.seal)
            .map_err(|e| crate::Error::Msg(e.to_string()))?
            .len();
        let mut f = io::BufReader::new(
            fs::File::open(&self.seal).map_err(|e| crate::Error::Msg(e.to_string()))?,
        );
        let (off, len) = locate_entry_star(&mut f, size, rel)?;
        let mut mag = [0u8; 4];
        let is_pack = len >= 4 && {
            f.seek(SeekFrom::Start(off))
                .map_err(|e| crate::Error::Msg(e.to_string()))?;
            f.read_exact(&mut mag)
                .map_err(|e| crate::Error::Msg(e.to_string()))?;
            mag == WORK_MAGIC
        };
        if is_pack {
            let home = PackHome::File {
                path: self.seal.clone(),
                base: off,
                len,
            };
            return Ok(Located::Pack(home, pass));
        }
        // A classic member is one AES-GCM message, at most the Tome's `--chunk` long.
        let n = usize::try_from(len).map_err(|_| crate::Error::Msg("member too large".into()))?;
        let mut star = vec![0u8; n];
        f.seek(SeekFrom::Start(off))
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        f.read_exact(&mut star)
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        Ok(Located::Whole(Arc::new(decode_star(
            &star,
            pass.as_deref(),
            &self.identities,
        )?)))
    }

    /// A readable source for `home`.
    fn home_src(&self, home: &PackHome) -> Result<HomeSrc<'_>> {
        match home {
            PackHome::File { path, base, len } => {
                let f = crate::packhead::FileSrc::open(path)?;
                if base.checked_add(*len).is_none_or(|e| e > f.size()) {
                    return Err(crate::Error::Msg(
                        "large-file member runs past the end of its file".into(),
                    ));
                }
                Ok(HomeSrc::File {
                    f,
                    base: *base,
                    len: *len,
                })
            }
            PackHome::Body { base, len } => Ok(HomeSrc::Body {
                fs: self,
                base: *base,
                len: *len,
            }),
            PackHome::Inner { base, len } => {
                let inner = self
                    .sealed_inner
                    .as_ref()
                    .ok_or_else(|| crate::Error::Msg("internal: no Warded Tome body".into()))?;
                let (a, b) = (*base as usize, (*base + *len) as usize);
                let slice = inner
                    .get(a..b)
                    .ok_or_else(|| crate::Error::Msg("member runs past the Tome body".into()))?;
                Ok(HomeSrc::Mem(slice))
            }
        }
    }

    /// Check a large-file pack end to end, one star in memory at a time, and record
    /// where each star's plaintext sits. Bounded by the pack's star count.
    fn open_pack(&self, home: PackHome, pass: Option<&str>) -> Result<PackPieces> {
        Ok(self.open_pack_with(home, pass, |_| Ok(()))?.0)
    }

    /// Like [`VaultFs::open_pack`], handing `f` the plaintext as a stream on the same
    /// pass (so a caller that needs to read it once, such as listing a Warded Tome or
    /// exporting a member, does not decrypt it twice). Whatever `f` leaves unread is
    /// read and checked before anything is returned.
    fn open_pack_with<T>(
        &self,
        home: PackHome,
        pass: Option<&str>,
        f: impl FnOnce(&mut dyn Read) -> Result<T>,
    ) -> Result<(PackPieces, T)> {
        crate::refuse_empty_open_pass(pass)?;
        let mut src = self.home_src(&home)?;
        let layout = crate::packhead::layout(&mut src)?;
        let (spans, t) = {
            let mut r = SpanReader {
                r: PackReader::new(&mut src, &layout, pass, &[], &self.identities),
                spans: Vec::with_capacity(layout.stars.len()),
                at: 0,
                buf: Vec::new(),
                pos: 0,
            };
            let t = f(&mut r)?;
            // The pack's total is checked at its end: read to it before trusting `t`.
            io::copy(&mut r, &mut io::sink()).map_err(|e| crate::Error::Msg(e.to_string()))?;
            (r.spans, t)
        };
        Ok((
            PackPieces {
                home,
                layout,
                spans,
                pass: pass.map(str::to_string),
            },
            t,
        ))
    }

    /// Plaintext of star `i` of a large-file member, from the small star cache or
    /// opened (and checked) again.
    fn pack_star(&self, ino: u64, p: &PackPieces, i: usize) -> Result<Arc<Vec<u8>>> {
        if let Some(hit) = self.lock_cache().star((ino, i)) {
            return Ok(hit);
        }
        let at = *p
            .layout
            .stars
            .get(i)
            .ok_or_else(|| crate::Error::Msg(format!("no star {i} in this member")))?;
        let mut src = self.home_src(&p.home)?;
        let (plain, _) = crate::work::open_star_checked(
            &mut src,
            &p.layout,
            i,
            at,
            p.pass.as_deref(),
            &[],
            &self.identities,
        )?;
        let want = p.spans.get(i).map(|s| s.1).unwrap_or(u64::MAX);
        if plain.len() as u64 != want {
            return Err(crate::Error::Msg(format!(
                "star {i} changed since this member was opened; refusing"
            )));
        }
        let plain = Arc::new(plain);
        self.lock_cache().keep_star((ino, i), plain.clone());
        Ok(plain)
    }

    /// Fill `buf` exactly with the plaintext of `p` from `offset` (an error past its
    /// end). Opens only the stars the range covers; bounded by the star count.
    fn pieces_fill(&self, key: u64, p: &PackPieces, offset: u64, buf: &mut [u8]) -> Result<()> {
        let total = p.spans.last().map(|s| s.0 + s.1).unwrap_or(0);
        if offset
            .checked_add(buf.len() as u64)
            .is_none_or(|e| e > total)
        {
            return Err(crate::Error::Msg(
                "read past the end of a large member".into(),
            ));
        }
        let mut done = 0usize;
        // First star whose plaintext ends after `offset`.
        let mut i = p.spans.partition_point(|s| s.0 + s.1 <= offset);
        // Each pass copies a non-empty piece or skips an empty star; at most one pass per star.
        while done < buf.len() && i < p.spans.len() {
            let (s_off, s_len) = p.spans[i];
            if s_len > 0 {
                let plain = self.pack_star(key, p, i)?;
                let pos = offset + done as u64;
                let from = usize::try_from(pos - s_off)
                    .map_err(|_| crate::Error::Msg("offset out of range".into()))?;
                let take = (buf.len() - done).min(plain.len().saturating_sub(from));
                buf[done..done + take].copy_from_slice(&plain[from..from + take]);
                done += take;
            }
            i += 1;
        }
        if done != buf.len() {
            return Err(crate::Error::Msg("large member ended early".into()));
        }
        Ok(())
    }

    /// Up to `size` bytes of inode `ino` from `offset`.
    fn read_at(&self, ino: u64, offset: u64, size: usize) -> Result<Vec<u8>> {
        match self.body(ino)? {
            Body::Whole(d) => {
                let Ok(start) = usize::try_from(offset) else {
                    return Ok(Vec::new());
                };
                if start >= d.len() {
                    return Ok(Vec::new());
                }
                let end = start.saturating_add(size).min(d.len());
                Ok(d[start..end].to_vec())
            }
            Body::Pack(p) => {
                let total = p.spans.last().map(|s| s.0 + s.1).unwrap_or(0);
                if offset >= total || size == 0 {
                    return Ok(Vec::new());
                }
                let want = (size as u64).min(total - offset) as usize;
                let mut out = vec![0u8; want];
                self.pieces_fill(ino, &p, offset, &mut out)?;
                Ok(out)
            }
        }
    }

    /// Write inode `ino` to the file `out`, all or nothing (a hidden part file renamed
    /// into place only after every check passed). A large-file member not opened yet is
    /// checked and written on one pass, one star in memory at a time.
    fn export_file(&self, ino: u64, out: &Path) -> Result<u64> {
        let cached = self.lock_cache().bodies.get(&ino).cloned();
        let located = match cached {
            Some(Body::Whole(d)) => Located::Whole(d),
            Some(Body::Pack(_)) => {
                return write_part(out, |w| self.copy_ino_to(ino, w));
            }
            None => self.locate(ino)?,
        };
        match located {
            Located::Whole(d) => write_part(out, |w| {
                w.write_all(&d)
                    .map_err(|e| crate::Error::Msg(e.to_string()))?;
                Ok(d.len() as u64)
            }),
            Located::Pack(home, pass) => write_part(out, |w| {
                let (_, n) = self.open_pack_with(home, pass.as_deref(), |r| {
                    io::copy(r, w).map_err(|e| crate::Error::Msg(e.to_string()))
                })?;
                Ok(n)
            }),
        }
    }

    /// Write all of inode `ino` to `w`; a large-file member goes one star at a time.
    fn copy_ino_to<W: Write>(&self, ino: u64, w: &mut W) -> Result<u64> {
        match self.body(ino)? {
            Body::Whole(d) => {
                w.write_all(&d)
                    .map_err(|e| crate::Error::Msg(e.to_string()))?;
                Ok(d.len() as u64)
            }
            Body::Pack(p) => self.copy_body_to(ino, &p, w),
        }
    }

    /// Every star of a large-file member, in order, each opened and checked again.
    /// Bounded by the star count.
    fn copy_body_to<W: Write>(&self, ino: u64, p: &PackPieces, w: &mut W) -> Result<u64> {
        let mut n = 0u64;
        for i in 0..p.spans.len() {
            let plain = self.pack_star(ino, p, i)?;
            w.write_all(&plain)
                .map_err(|e| crate::Error::Msg(e.to_string()))?;
            n += plain.len() as u64;
        }
        Ok(n)
    }

    fn child_by_name(&self, parent: u64, name: &str) -> Option<u64> {
        let node = self.nodes.get(&parent)?;
        node.children
            .iter()
            .find(|&&c| self.nodes[&c].name == name)
            .copied()
    }
}

fn resolve_seal(input: &Path, prefer_vault: bool) -> Result<PathBuf> {
    let name = input.file_name().and_then(|n| n.to_str()).unwrap_or("");
    if name.ends_with(VAULT_SUFFIX)
        || prefer_vault
        || (input.is_dir() && input.join(vault::CHART_NAME).is_file())
    {
        let (seal, _tip) = vault::tip_seal_path(input)?;
        return Ok(seal);
    }
    if input.is_file() {
        return Ok(input.to_path_buf());
    }
    // Live path with a vault sidecar → tip when no bare .sg1.
    let vault_dir = vault::vault_dir_for(input);
    if vault_dir.join(vault::CHART_NAME).is_file() {
        let (seal, _tip) = vault::tip_seal_path(input)?;
        return Ok(seal);
    }
    Err(crate::Error::Msg(format!(
        "mount needs a .sg1 / SGDR pack, or a vault tip (got {})",
        input.display()
    )))
}

fn decode_whole(seal: &Path, pass: Option<&str>, identities: &[Identity]) -> Result<Vec<u8>> {
    if is_work_pack(seal) {
        // Unsealed in memory: plaintext never touches the temp folder.
        let mut data = Vec::new();
        crate::work::unseal_path_into(seal, &mut data, pass, &[], identities)?;
        Ok(data)
    } else {
        let bytes = fs::read(seal).map_err(|e| crate::Error::Msg(e.to_string()))?;
        unseal_ex_keys(&bytes, pass, &[], identities)
    }
}

fn decode_star(star: &[u8], pass: Option<&str>, identities: &[Identity]) -> Result<Vec<u8>> {
    if star.starts_with(&crate::work::WORK_MAGIC) {
        let mut data = Vec::new();
        crate::work::unseal_bytes_into(star, &mut data, pass, &[], identities)?;
        Ok(data)
    } else {
        unseal_ex_keys(star, pass, &[], identities)
    }
}

/// Write `out` all or nothing: bytes go to a new hidden part file beside it (a unique
/// name, created exclusively, so it can never replace another exported file), renamed
/// over `out` only if `f` succeeds; on any error the part file is removed. Unlike the
/// archive writers this does not sync to disk (an export is a view, made again from the
/// seal at will).
fn write_part<T>(
    out: &Path,
    f: impl FnOnce(&mut io::BufWriter<fs::File>) -> Result<T>,
) -> Result<T> {
    let io_err = |e: io::Error| crate::Error::Msg(e.to_string());
    let part = crate::folder::scratch_beside(out, "sigil-part");
    let result = (|| {
        let file = fs::OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&part)
            .map_err(io_err)?;
        let mut w = io::BufWriter::new(file);
        let v = f(&mut w)?;
        w.flush().map_err(io_err)?;
        drop(w);
        fs::rename(&part, out).map_err(io_err)?;
        Ok(v)
    })();
    if result.is_err() {
        let _ = fs::remove_file(&part);
    }
    result
}

/// The first `n` bytes of `path` (fewer when it is shorter).
fn peek_file(path: &Path, n: u64) -> Result<Vec<u8>> {
    let f = fs::File::open(path).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let mut out = Vec::new();
    f.take(n)
        .read_to_end(&mut out)
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    Ok(out)
}

fn pass_for(rel: &str, default: Option<&str>, wards: &[(String, String)]) -> Option<String> {
    for (p, w) in wards {
        if p == rel {
            return Some(w.clone());
        }
    }
    default.map(|s| s.to_string())
}

fn normalize_rel(path: &str) -> String {
    let p = path.trim().trim_start_matches("./").trim_start_matches("/");
    p.replace('\\', "/")
        .split('/')
        .filter(|s| !s.is_empty() && *s != ".")
        .collect::<Vec<_>>()
        .join("/")
}

fn sanitize_name(name: &str) -> String {
    let base = name
        .replace('\\', "/")
        .rsplit('/')
        .next()
        .unwrap_or(name)
        .to_string();
    if base.is_empty() || base == "." || base == ".." {
        "payload".into()
    } else {
        base
    }
}

fn current_uid() -> u32 {
    #[cfg(unix)]
    {
        extern "C" {
            fn getuid() -> u32;
        }
        // SAFETY: POSIX `getuid(2)` takes no arguments, touches no caller memory, cannot
        // fail (POSIX: "shall always be successful"); `uid_t` is a 32-bit unsigned integer on
        // every Unix target this crate builds for (Linux, macOS, the BSDs), so the `u32`
        // return type matches the C ABI. libc is already linked via std/fuser.
        unsafe { getuid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

fn current_gid() -> u32 {
    #[cfg(unix)]
    {
        extern "C" {
            fn getgid() -> u32;
        }
        // SAFETY: POSIX `getgid(2)` takes no arguments, touches no caller memory and always
        // succeeds; `gid_t` is a 32-bit unsigned integer on every supported Unix target, so
        // the declared signature matches the C ABI.
        unsafe { getgid() }
    }
    #[cfg(not(unix))]
    {
        0
    }
}

/// Run FUSE mount (blocks until unmounted). Unix only.
#[cfg(unix)]
pub fn mount_fuse(fs: VaultFs, mountpoint: &Path) -> Result<()> {
    use fuser::{Config, MountOption, SessionACL};
    if !mountpoint.is_dir() {
        return Err(crate::Error::Msg(format!(
            "mountpoint must be a directory: {}",
            mountpoint.display()
        )));
    }
    let mut cfg = Config::default();
    cfg.mount_options = vec![
        MountOption::RO,
        MountOption::FSName("sigil".into()),
        MountOption::DefaultPermissions,
    ];
    cfg.acl = SessionACL::Owner;
    let fuse = FuseFs {
        inner: Arc::new(fs),
    };
    fuser::mount(fuse, mountpoint, &cfg).map_err(|e| {
        crate::Error::Msg(format!(
            "FUSE mount failed ({e}). On Linux: need /dev/fuse + fusermount3.              Fallback: `sigil mount … --export-dir /tmp/view`."
        ))
    })
}

#[cfg(not(unix))]
pub fn mount_fuse(_fs: VaultFs, _mountpoint: &Path) -> Result<()> {
    Err(crate::Error::Msg(
        "FUSE mount is Unix-only. Use --export-dir on this platform.".into(),
    ))
}

/// Unmount via fusermount3 / fusermount.
pub fn umount(mountpoint: &Path) -> Result<()> {
    let mp = mountpoint
        .to_str()
        .ok_or_else(|| crate::Error::Msg("mountpoint is not utf-8".into()))?;
    for bin in ["fusermount3", "fusermount"] {
        let status = std::process::Command::new(bin).args(["-u", mp]).status();
        match status {
            Ok(s) if s.success() => return Ok(()),
            Ok(s) => {
                return Err(crate::Error::Msg(format!(
                    "{bin} -u failed (exit {:?})",
                    s.code()
                )));
            }
            Err(_) => continue,
        }
    }
    Err(crate::Error::Msg(
        "fusermount3/fusermount not found — install fuse3".into(),
    ))
}

#[cfg(unix)]
struct FuseFs {
    inner: Arc<VaultFs>,
}

#[cfg(unix)]
impl fuser::Filesystem for FuseFs {
    fn lookup(
        &self,
        _req: &fuser::Request,
        parent: fuser::INodeNo,
        name: &std::ffi::OsStr,
        reply: fuser::ReplyEntry,
    ) {
        let Some(name) = name.to_str() else {
            reply.error(fuser::Errno::ENOENT);
            return;
        };
        let Some(ino) = self.inner.child_by_name(u64::from(parent), name) else {
            reply.error(fuser::Errno::ENOENT);
            return;
        };
        match self.attr_for(ino) {
            Ok(attr) => reply.entry(&TTL, &attr, fuser::Generation(0)),
            Err(_) => reply.error(fuser::Errno::ENOENT),
        }
    }

    fn getattr(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        _fh: Option<fuser::FileHandle>,
        reply: fuser::ReplyAttr,
    ) {
        match self.attr_for(u64::from(ino)) {
            Ok(attr) => reply.attr(&TTL, &attr),
            Err(_) => reply.error(fuser::Errno::ENOENT),
        }
    }

    fn open(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        flags: fuser::OpenFlags,
        reply: fuser::ReplyOpen,
    ) {
        use fuser::OpenAccMode;
        match flags.acc_mode() {
            OpenAccMode::O_RDONLY => {}
            OpenAccMode::O_WRONLY | OpenAccMode::O_RDWR => {
                reply.error(fuser::Errno::EACCES);
                return;
            }
        }
        if !self.inner.nodes.contains_key(&u64::from(ino)) {
            reply.error(fuser::Errno::ENOENT);
            return;
        }
        reply.opened(fuser::FileHandle(0), fuser::FopenFlags::empty());
    }

    fn read(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        _fh: fuser::FileHandle,
        offset: u64,
        size: u32,
        _flags: fuser::OpenFlags,
        _lock_owner: Option<fuser::LockOwner>,
        reply: fuser::ReplyData,
    ) {
        match self.inner.read_at(u64::from(ino), offset, size as usize) {
            Ok(data) => reply.data(&data),
            Err(_) => reply.error(fuser::Errno::EIO),
        }
    }

    fn readdir(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        _fh: fuser::FileHandle,
        offset: u64,
        mut reply: fuser::ReplyDirectory,
    ) {
        let ino = u64::from(ino);
        let Some(node) = self.inner.nodes.get(&ino) else {
            reply.error(fuser::Errno::ENOENT);
            return;
        };
        if !matches!(node.kind, NodeKind::Dir) {
            reply.error(fuser::Errno::ENOTDIR);
            return;
        }
        let mut entries: Vec<(u64, fuser::FileType, String)> = Vec::new();
        entries.push((ino, fuser::FileType::Directory, ".".into()));
        entries.push((node.parent, fuser::FileType::Directory, "..".into()));
        for &c in &node.children {
            let n = &self.inner.nodes[&c];
            let kind = match n.kind {
                NodeKind::Dir => fuser::FileType::Directory,
                NodeKind::File { .. } => fuser::FileType::RegularFile,
            };
            entries.push((c, kind, n.name.clone()));
        }
        for (i, (child, kind, name)) in entries.into_iter().enumerate().skip(offset as usize) {
            if reply.add(fuser::INodeNo(child), (i + 1) as u64, kind, &name) {
                break;
            }
        }
        reply.ok();
    }

    fn opendir(
        &self,
        _req: &fuser::Request,
        ino: fuser::INodeNo,
        _flags: fuser::OpenFlags,
        reply: fuser::ReplyOpen,
    ) {
        match self.inner.nodes.get(&u64::from(ino)) {
            Some(n) if matches!(n.kind, NodeKind::Dir) => {
                reply.opened(fuser::FileHandle(0), fuser::FopenFlags::empty());
            }
            Some(_) => reply.error(fuser::Errno::ENOTDIR),
            None => reply.error(fuser::Errno::ENOENT),
        }
    }
}

#[cfg(unix)]
impl FuseFs {
    fn attr_for(&self, ino: u64) -> io::Result<fuser::FileAttr> {
        let node = self
            .inner
            .nodes
            .get(&ino)
            .ok_or_else(|| io::Error::from_raw_os_error(libc_enoent()))?;
        let now = SystemTime::now();
        let (kind, size, perm) = match &node.kind {
            NodeKind::Dir => (fuser::FileType::Directory, 0u64, 0o555u16),
            NodeKind::File { size, .. } => (fuser::FileType::RegularFile, *size, 0o444u16),
        };
        Ok(fuser::FileAttr {
            ino: fuser::INodeNo(ino),
            size,
            blocks: size.div_ceil(512),
            atime: now,
            mtime: now,
            ctime: now,
            crtime: UNIX_EPOCH,
            kind,
            perm,
            nlink: if matches!(node.kind, NodeKind::Dir) {
                2
            } else {
                1
            },
            uid: self.inner.uid,
            gid: self.inner.gid,
            rdev: 0,
            flags: 0,
            blksize: 512,
        })
    }
}

#[cfg(unix)]
fn libc_enoent() -> i32 {
    2
}

/// Whether /dev/fuse looks usable for a smoke mount.
pub fn fuse_available() -> bool {
    #[cfg(unix)]
    {
        Path::new("/dev/fuse").exists()
            && (which_bin("fusermount3").is_some() || which_bin("fusermount").is_some())
    }
    #[cfg(not(unix))]
    {
        false
    }
}

fn which_bin(name: &str) -> Option<PathBuf> {
    std::env::var_os("PATH").and_then(|paths| {
        for p in std::env::split_paths(&paths) {
            let cand = p.join(name);
            if cand.is_file() {
                return Some(cand);
            }
        }
        None
    })
}

/// Convenience: open + FUSE mount, or export-dir when `export` is Some.
pub fn run_mount(
    input: &Path,
    mountpoint: &Path,
    pass: Option<&str>,
    wards: &[(String, String)],
    prefer_vault: bool,
    export: Option<&Path>,
) -> Result<()> {
    run_mount_keys(
        input,
        mountpoint,
        pass,
        wards,
        prefer_vault,
        export,
        &[],
        false,
    )
}

// Justification: each parameter is an independent user-facing seal option threaded
// straight from the CLI (mode, passphrase, covenant, geas, chunking, wards, recipients...).
// Bundling them into an options struct is a public-API refactor tracked separately;
// this PR keeps signatures stable.
#[allow(clippy::too_many_arguments)]
pub fn run_mount_keys(
    input: &Path,
    mountpoint: &Path,
    pass: Option<&str>,
    wards: &[(String, String)],
    prefer_vault: bool,
    export: Option<&Path>,
    identities: &[Identity],
    writable: bool,
) -> Result<()> {
    if writable && export.is_none() {
        return Err(crate::Error::Msg(
            "--writable requires --export-dir (FUSE stays read-only this slice)".into(),
        ));
    }
    // Segment log: one file per live segment (always read-only).
    if crate::seglog::is_log(input) {
        return run_log_mount(
            input,
            mountpoint,
            pass,
            export,
            identities,
            writable,
            prefer_vault,
        );
    }
    let sky = if prefer_vault {
        None
    } else {
        crate::names::sky_dir(input)
    };
    if sky.is_some() && writable {
        return Err(crate::Error::Msg(
            "--writable is for vault versions; a constellation is a list of separate stars (use `constellation add` / `remove`)".into(),
        ));
    }
    let seal_path = match &sky {
        Some(d) => crate::constellation::find_card(d)
            .ok_or_else(|| crate::Error::Msg("no constellation card".into()))?,
        None => resolve_seal(input, prefer_vault)?,
    };
    let before = sha_of(&seal_path)?;
    let fs = VaultFs::open_keys(input, pass, wards, prefer_vault, identities)?;
    if let Some(dest) = export {
        let dirty = if writable {
            Some(vault::dirty_meta_for(input, fs.seal_path(), prefer_vault)?)
        } else {
            None
        };
        let n = fs.export_dir_ex(dest, writable, dirty.as_ref())?;
        let after = sha_of(fs.seal_path())?;
        if before != after {
            return Err(crate::Error::Msg(
                "seal changed during export — this should never happen".into(),
            ));
        }
        if writable {
            crate::human_line(&format!(
                "exported {n} file(s) → {}  (writable dirty tree; seal intact)",
                dest.display()
            ));
            crate::human_line(&format!(
                "re-seal: sigil vault commit --from-export {}",
                dest.display()
            ));
        } else {
            crate::human_line(&format!(
                "exported {n} file(s) → {}  (seal intact, read-only view)",
                dest.display()
            ));
        }
        crate::human_line(&format!("source {}", fs.seal_path().display()));
        return Ok(());
    }
    crate::human_line(&format!(
        "mounting {} → {} (read-only FUSE; Ctrl-C or `sigil umount` to leave)",
        fs.seal_path().display(),
        mountpoint.display()
    ));
    let seal = fs.seal_path().to_path_buf();
    mount_fuse(fs, mountpoint)?;
    let after = sha_of(&seal)?;
    if before != after {
        let _ = writeln!(
            io::stderr(),
            "warning: seal digest changed while mounted (unexpected)"
        );
    } else {
        crate::human_line("unmounted; seal unchanged");
    }
    Ok(())
}

fn run_log_mount(
    input: &Path,
    mountpoint: &Path,
    pass: Option<&str>,
    export: Option<&Path>,
    identities: &[Identity],
    writable: bool,
    prefer_vault: bool,
) -> Result<()> {
    if writable {
        return Err(crate::Error::Msg(
            "--writable is for vault versions; a segment log mount is always read-only (use `sigil log append`)".into(),
        ));
    }
    if prefer_vault {
        return Err(crate::Error::Msg(
            "--vault does not apply to a segment log".into(),
        ));
    }
    let log = crate::seglog::Log::open(input)?;
    let index_path = log.dir.join(crate::seglog::INDEX_FILE);
    let before = sha_of(&index_path)?;
    let fs = VaultFs::open_log(input, pass, identities)?;
    if let Some(dest) = export {
        let n = fs.export_dir(dest)?;
        let after = sha_of(&index_path)?;
        if before != after {
            return Err(crate::Error::Msg(
                "log INDEX changed during export — this should never happen".into(),
            ));
        }
        crate::human_line(&format!(
            "exported {n} live segment(s) → {}  (log intact, read-only view)",
            dest.display()
        ));
        crate::human_line(&format!("source {}", fs.seal_path().display()));
        return Ok(());
    }
    crate::human_line(&format!(
        "mounting log {} → {} (read-only FUSE; one file per live segment; Ctrl-C or `sigil umount` to leave)",
        fs.seal_path().display(),
        mountpoint.display()
    ));
    let dir = fs.seal_path().to_path_buf();
    mount_fuse(fs, mountpoint)?;
    let after = sha_of(&index_path)?;
    if before != after {
        let _ = writeln!(
            io::stderr(),
            "warning: log INDEX digest changed while mounted (unexpected)"
        );
    } else {
        println!("unmounted; log unchanged ({})", dir.display());
    }
    Ok(())
}

fn sha_of(path: &Path) -> Result<[u8; 32]> {
    crate::sha256_path(path)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{inscribe_dir, seal, Mode};

    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "sigil-mount-{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn noise(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    /// Read `path` through the VFS in odd-sized pieces that cross star boundaries.
    fn read_in_pieces(vfs: &VaultFs, path: &str, total: usize) -> Vec<u8> {
        let mut out = Vec::new();
        let step = 50_001;
        while out.len() < total {
            let got = vfs.read_range(path, out.len() as u64, step).unwrap();
            assert!(!got.is_empty(), "short read at {}", out.len());
            out.extend_from_slice(&got);
        }
        assert!(vfs.read_range(path, total as u64, 10).unwrap().is_empty());
        out
    }

    /// A Tome (plain and Warded, the Warded one with a large body) whose big member is
    /// stored as a large-file pack: reads in pieces, whole, and an export all give the
    /// member's bytes, and only stars are held, never the member.
    #[test]
    fn large_members_read_in_pieces() {
        let d = tmp("pieces");
        let src = d.join("src");
        fs::create_dir_all(src.join("m")).unwrap();
        let big = noise(700_000, 11);
        fs::write(src.join("m/big.bin"), &big).unwrap();
        fs::write(src.join("small.txt"), b"small").unwrap();
        for (tag, pass) in [("plain", None), ("warded", Some("pw"))] {
            let pack = d.join(format!("{tag}.sg1"));
            inscribe_dir(&src, &pack, Mode::Seal, pass, "", &[], 64 * 1024, &[]).unwrap();
            let before = crate::sha256_path(&pack).unwrap();
            let vfs = VaultFs::open(&pack, pass, &[], false).unwrap();
            assert_eq!(
                vfs.sealed_body.is_some(),
                pass.is_some(),
                "{tag}: large body"
            );
            assert!(vfs.sealed_inner.is_none(), "{tag}: body never held whole");
            assert_eq!(
                vfs.file_size("m/big.bin").unwrap(),
                big.len() as u64,
                "{tag}"
            );
            assert_eq!(read_in_pieces(&vfs, "m/big.bin", big.len()), big, "{tag}");
            assert_eq!(
                vfs.read_range("m/big.bin", 65_530, 20).unwrap(),
                &big[65_530..65_550]
            );
            assert_eq!(&vfs.read_file("m/big.bin").unwrap()[..], &big[..], "{tag}");
            assert_eq!(&vfs.read_file("small.txt").unwrap()[..], b"small", "{tag}");
            let mut copy = Vec::new();
            assert_eq!(
                vfs.copy_file_to("m/big.bin", &mut copy).unwrap(),
                big.len() as u64
            );
            assert_eq!(copy, big);
            let dest = d.join(format!("{tag}-out"));
            assert_eq!(vfs.export_dir(&dest).unwrap(), 2);
            assert_eq!(fs::read(dest.join("m/big.bin")).unwrap(), big, "{tag}");
            assert_eq!(fs::read(dest.join("small.txt")).unwrap(), b"small", "{tag}");
            // A fresh VFS exports on one streamed pass (nothing opened beforehand).
            let fresh = VaultFs::open(&pack, pass, &[], false).unwrap();
            let dest2 = d.join(format!("{tag}-out2"));
            assert_eq!(fresh.export_dir(&dest2).unwrap(), 2);
            assert_eq!(fs::read(dest2.join("m/big.bin")).unwrap(), big, "{tag}");
            let held = vfs.lock_cache().stars.len();
            assert!(held <= STAR_CACHE, "{tag}: {held} stars held");
            assert_eq!(
                crate::sha256_path(&pack).unwrap(),
                before,
                "{tag}: seal unchanged"
            );
        }
        // A single file sealed as a large-file pack.
        let single = d.join("single.sg1");
        crate::work::inscribe_path(
            &src.join("m/big.bin"),
            &single,
            Mode::Seal,
            None,
            "",
            &[],
            64 * 1024,
            None,
            crate::DEFAULT_PIECE,
            crate::work::DEFAULT_OVERTURE_MB,
            None,
        )
        .unwrap();
        let vfs = VaultFs::open(&single, None, &[], false).unwrap();
        assert_eq!(read_in_pieces(&vfs, "big.bin", big.len()), big);
        let _ = fs::remove_dir_all(&d);
    }

    /// Damage fails closed: a star changed after the member was opened is refused when
    /// read (never served as wrong bytes), and a member damaged beforehand exports
    /// nothing (no file, no part file).
    #[test]
    fn changed_or_damaged_large_member_is_refused() {
        let d = tmp("pieces-bad");
        let src = d.join("src");
        fs::create_dir_all(&src).unwrap();
        let big = noise(500_000, 23);
        fs::write(src.join("big.bin"), &big).unwrap();
        let pack = d.join("t.sg1");
        // Glyph mode carries no parity, so any change is beyond repair.
        inscribe_dir(&src, &pack, Mode::Glyph, None, "", &[], 64 * 1024, &[]).unwrap();
        let vfs = VaultFs::open(&pack, None, &[], false).unwrap();
        // Open the member (full check) and read its first piece.
        assert_eq!(vfs.read_range("big.bin", 0, 100).unwrap(), &big[..100]);
        // Change bytes inside a later star, in place.
        let mut raw = fs::read(&pack).unwrap();
        let at = raw.len() * 3 / 4;
        for b in &mut raw[at..at + 64] {
            *b ^= 0x5a;
        }
        fs::write(&pack, &raw).unwrap();
        let tail_off = (big.len() * 3 / 4) as u64;
        let mut refused = false;
        for off in (tail_off.saturating_sub(70_000)..big.len() as u64).step_by(30_000) {
            match vfs.read_range("big.bin", off, 30_000) {
                Ok(got) => {
                    let o = off as usize;
                    assert_eq!(got, &big[o..o + got.len()], "wrong bytes served at {off}");
                }
                Err(_) => refused = true,
            }
        }
        assert!(refused, "a changed star was never refused");
        // A fresh view of the damaged Tome: export writes nothing for the member.
        let fresh = VaultFs::open(&pack, None, &[], false).unwrap();
        let dest = d.join("out");
        assert!(fresh.export_dir(&dest).is_err());
        let left: Vec<_> = fs::read_dir(&dest).unwrap().collect();
        assert!(left.is_empty(), "export left {left:?}");
        let _ = fs::remove_dir_all(&d);
    }

    /// Whole-held members are dropped oldest first past the cache budget, but the one
    /// being read always stays (a member larger than the budget still opens).
    #[test]
    fn whole_cache_is_bounded_but_keeps_the_newest() {
        let mut c = Cache::default();
        let big = Arc::new(vec![0u8; (WHOLE_CACHE_BYTES / 2 + 1) as usize]);
        c.keep_whole(10, &big);
        c.keep_whole(11, &big);
        assert!(!c.bodies.contains_key(&10) && c.bodies.contains_key(&11));
        let huge = Arc::new(vec![0u8; (WHOLE_CACHE_BYTES + 1) as usize]);
        c.keep_whole(12, &huge);
        assert!(c.bodies.contains_key(&12) && c.bodies.len() == 1);
        assert_eq!(c.whole_bytes, huge.len() as u64);
        for i in 0..20 {
            c.keep_star((1, i), Arc::new(vec![1u8; 8]));
        }
        assert_eq!(c.stars.len(), STAR_CACHE);
        assert!(c.star((1, 19)).is_some() && c.star((1, 0)).is_none());
    }

    #[test]
    fn vfs_single_file_roundtrip() {
        let d = tmp("single");
        let mark = d.join("m.sg1");
        let bytes = seal(b"hello-mount", Mode::Glyph, None, "hello.txt", false).unwrap();
        fs::write(&mark, &bytes).unwrap();
        let before = crate::sha256_path(&mark).unwrap();
        let vfs = VaultFs::open(&mark, None, &[], false).unwrap();
        let listing = vfs.list_dir("").unwrap();
        assert_eq!(listing.len(), 1);
        assert_eq!(listing[0].0, "hello.txt");
        assert!(!listing[0].1);
        let data = vfs.read_file("hello.txt").unwrap();
        assert_eq!(&data[..], b"hello-mount");
        assert_eq!(crate::sha256_path(&mark).unwrap(), before);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn vfs_dir_pack_and_ward() {
        let d = tmp("dir");
        let src = d.join("src");
        fs::create_dir_all(src.join("photos")).unwrap();
        fs::write(src.join("a.txt"), b"alpha").unwrap();
        fs::write(src.join("photos/secret.jpg"), b"secret-bytes").unwrap();
        let pack = d.join("tree.sg1");
        inscribe_dir(
            &src,
            &pack,
            Mode::Glyph,
            Some("house"),
            "",
            &[],
            4 * 1024 * 1024,
            &[("photos/secret.jpg".into(), "room".into())],
        )
        .unwrap();
        let before = crate::sha256_path(&pack).unwrap();
        let wards = vec![("photos/secret.jpg".into(), "room".into())];
        let vfs = VaultFs::open(&pack, Some("house"), &wards, false).unwrap();
        let root = vfs.list_dir("").unwrap();
        let names: Vec<_> = root.iter().map(|e| e.0.as_str()).collect();
        assert!(names.contains(&"a.txt"));
        assert!(names.contains(&"photos"));
        let photos = vfs.list_dir("photos").unwrap();
        assert_eq!(photos.len(), 1);
        assert_eq!(photos[0].0, "secret.jpg");
        assert_eq!(&vfs.read_file("a.txt").unwrap()[..], b"alpha");
        assert_eq!(
            &vfs.read_file("photos/secret.jpg").unwrap()[..],
            b"secret-bytes"
        );
        assert_eq!(crate::sha256_path(&pack).unwrap(), before);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn export_dir_leaves_seal_intact() {
        let d = tmp("export");
        let mark = d.join("m.sg1");
        let bytes = seal(b"export-me", Mode::Seal, None, "x.bin", false).unwrap();
        fs::write(&mark, &bytes).unwrap();
        let before = crate::sha256_path(&mark).unwrap();
        let vfs = VaultFs::open(&mark, None, &[], false).unwrap();
        let dest = d.join("view");
        let n = vfs.export_dir(&dest).unwrap();
        assert_eq!(n, 1);
        assert_eq!(fs::read(dest.join("x.bin")).unwrap(), b"export-me");
        assert_eq!(crate::sha256_path(&mark).unwrap(), before);
        // read-only bit when unix
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dest.join("x.bin"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o222, 0, "export should not be writable");
        }
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn nested_sg1_appears_as_file() {
        let d = tmp("nest");
        let inner = seal(b"inner-payload", Mode::Glyph, None, "inner.txt", false).unwrap();
        let src = d.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("inner.sg1"), &inner).unwrap();
        fs::write(src.join("plain.txt"), b"plain").unwrap();
        let pack = d.join("outer.sg1");
        inscribe_dir(
            &src,
            &pack,
            Mode::Glyph,
            None,
            "",
            &[],
            4 * 1024 * 1024,
            &[],
        )
        .unwrap();
        let vfs = VaultFs::open(&pack, None, &[], false).unwrap();
        let listing = vfs.list_dir("").unwrap();
        let names: Vec<_> = listing.iter().map(|e| e.0.clone()).collect();
        assert!(names.contains(&"inner.sg1".to_string()));
        assert!(names.contains(&"plain.txt".to_string()));
        // Nested seal appears as file whose content is the unsealed payload (= inner .sg1 bytes).
        let nested = vfs.read_file("inner.sg1").unwrap();
        assert_eq!(&nested[..], &inner[..]);
        assert_eq!(&vfs.read_file("plain.txt").unwrap()[..], b"plain");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn mount_export_encrypt_to_identity() {
        let d = tmp("id-export");
        let alice = crate::Identity::generate().unwrap();
        let mark = d.join("m.sg1");
        let bytes = crate::seal_kn_to(
            b"mount-id-clear",
            Mode::Seal,
            None,
            "secret.bin",
            false,
            "",
            &[],
            None,
            crate::DEFAULT_PIECE,
            &[alice.public()],
        )
        .unwrap();
        fs::write(&mark, &bytes).unwrap();
        let before = crate::sha256_path(&mark).unwrap();
        let vfs = VaultFs::open_keys(&mark, None, &[], false, &[alice]).unwrap();
        let dest = d.join("view");
        let n = vfs.export_dir(&dest).unwrap();
        assert_eq!(n, 1);
        assert_eq!(
            fs::read(dest.join("secret.bin")).unwrap(),
            b"mount-id-clear"
        );
        assert_eq!(crate::sha256_path(&mark).unwrap(), before);
        assert!(VaultFs::open_keys(&mark, None, &[], false, &[]).is_ok());
        // listing works without identity; read should fail without matching key
        let vfs_no = VaultFs::open(&mark, None, &[], false).unwrap();
        assert!(vfs_no.read_file("secret.bin").is_err());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn export_dir_writable_and_commit_roundtrip() {
        use crate::vault::{self, DIRTY_NAME};
        let d = tmp("writable");
        let live = d.join("notes.txt");
        fs::write(&live, b"v1-clear").unwrap();
        vault::track(&live, Mode::Glyph, None, &[]).unwrap();
        let tip = vault::tip_seal_path(&live).unwrap().0;
        let before = crate::sha256_path(&tip).unwrap();

        let vfs = VaultFs::open_keys(&live, None, &[], true, &[]).unwrap();
        let dest = d.join("dirty");
        let meta = vault::dirty_meta_for(&live, vfs.seal_path(), true).unwrap();
        assert!(meta.vault);
        let n = vfs.export_dir_ex(&dest, true, Some(&meta)).unwrap();
        assert_eq!(n, 1);
        assert!(dest.join(DIRTY_NAME).is_file());
        assert_eq!(crate::sha256_path(&tip).unwrap(), before);

        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dest.join("notes.txt"))
                .unwrap()
                .permissions()
                .mode();
            assert_ne!(mode & 0o222, 0, "writable export should allow writes");
        }

        fs::write(dest.join("notes.txt"), b"v2-edited").unwrap();
        let c = vault::commit_from_export(&dest, Mode::Glyph, None, false, &[]).unwrap();
        assert_eq!(c.version, 2);
        assert_eq!(fs::read(&live).unwrap(), b"v2-edited");
        assert_eq!(vault::status(&live).unwrap().tip, 2);
        // Durable tip seal advanced; v1 immutable still there
        assert!(vault::version_seal_path(&live, 1).unwrap().is_file());
        assert_ne!(
            crate::sha256_path(&vault::tip_seal_path(&live).unwrap().0).unwrap(),
            before
        );
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn export_dir_readonly_still_non_writable() {
        let d = tmp("ro-bits");
        let mark = d.join("m.sg1");
        let bytes = seal(b"ro", Mode::Glyph, None, "x.bin", false).unwrap();
        fs::write(&mark, &bytes).unwrap();
        let vfs = VaultFs::open(&mark, None, &[], false).unwrap();
        let dest = d.join("view");
        vfs.export_dir(&dest).unwrap();
        assert!(!dest.join(crate::vault::DIRTY_NAME).exists());
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(dest.join("x.bin"))
                .unwrap()
                .permissions()
                .mode();
            assert_eq!(mode & 0o222, 0);
        }
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn log_mount_lists_live_segments_and_export() {
        let d = tmp("log-basic");
        let log_path = d.join("ev");
        crate::seglog::init(&log_path, None).unwrap();
        for i in 1..=3u64 {
            crate::seglog::append(
                &log_path,
                format!("batch {i}\n").as_bytes(),
                &crate::seglog::AppendOpts::default(),
            )
            .unwrap();
        }
        let index = d.join("ev.sigil").join(crate::seglog::INDEX_FILE);
        let before = crate::sha256_path(&index).unwrap();
        let vfs = VaultFs::open_log(&log_path, None, &[]).unwrap();
        assert!(vfs.is_log());
        let listing = vfs.list_dir("").unwrap();
        let names: Vec<_> = listing.iter().map(|e| e.0.as_str()).collect();
        assert_eq!(names, vec!["0000000001", "0000000002", "0000000003"]);
        assert_eq!(&vfs.read_file("0000000002").unwrap()[..], b"batch 2\n");
        let dest = d.join("view");
        let n = vfs.export_dir(&dest).unwrap();
        assert_eq!(n, 3);
        assert_eq!(fs::read(dest.join("0000000001")).unwrap(), b"batch 1\n");
        assert_eq!(crate::sha256_path(&index).unwrap(), before);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn log_mount_honours_tombstones_and_compaction() {
        let d = tmp("log-tomb");
        let log_path = d.join("ev");
        crate::seglog::init(&log_path, None).unwrap();
        for i in 1..=4u64 {
            crate::seglog::append(
                &log_path,
                format!("batch {i}\n").as_bytes(),
                &crate::seglog::AppendOpts::default(),
            )
            .unwrap();
        }
        crate::seglog::tombstone(
            &log_path,
            crate::seglog::TombTarget::Seq(2),
            Some("gone"),
            None,
        )
        .unwrap();
        let copts = crate::seglog::CompactOpts {
            apply: true,
            ..Default::default()
        };
        crate::seglog::compact(&log_path, &copts).unwrap();
        let vfs = VaultFs::open_log(&log_path, None, &[]).unwrap();
        let listing = vfs.list_dir("").unwrap();
        let names: Vec<_> = listing.iter().map(|e| e.0.clone()).collect();
        // seq 2 deleted; live batches still under original seq names
        assert!(!names.iter().any(|n| n == "0000000002"));
        assert!(names.contains(&"0000000001".to_string()));
        assert!(names.contains(&"0000000003".to_string()));
        assert!(names.contains(&"0000000004".to_string()));
        assert_eq!(&vfs.read_file("0000000003").unwrap()[..], b"batch 3\n");
        assert_eq!(&vfs.read_file("0000000001").unwrap()[..], b"batch 1\n");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn log_mount_needs_pass_for_sealed_segments() {
        let d = tmp("log-pass");
        let log_path = d.join("ev");
        crate::seglog::init(&log_path, None).unwrap();
        let opts = crate::seglog::AppendOpts {
            pass: Some("house"),
            ..Default::default()
        };
        crate::seglog::append(&log_path, b"secret-batch\n", &opts).unwrap();
        let vfs = VaultFs::open_log(&log_path, None, &[]).unwrap();
        assert!(vfs
            .list_dir("")
            .unwrap()
            .iter()
            .any(|e| e.0 == "0000000001"));
        assert!(vfs.read_file("0000000001").is_err());
        let vfs = VaultFs::open_log(&log_path, Some("house"), &[]).unwrap();
        assert_eq!(&vfs.read_file("0000000001").unwrap()[..], b"secret-batch\n");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn log_mount_writable_refused() {
        let d = tmp("log-ro");
        let log_path = d.join("ev");
        crate::seglog::init(&log_path, None).unwrap();
        crate::seglog::append(&log_path, b"x\n", &crate::seglog::AppendOpts::default()).unwrap();
        let dest = d.join("view");
        let err = run_mount_keys(
            &log_path,
            &d.join("mnt"),
            None,
            &[],
            false,
            Some(&dest),
            &[],
            true,
        )
        .unwrap_err()
        .to_string();
        assert!(err.contains("--writable"), "{err}");
        // read-only export still works
        run_mount_keys(
            &log_path,
            &d.join("mnt"),
            None,
            &[],
            false,
            Some(&dest),
            &[],
            false,
        )
        .unwrap();
        assert_eq!(fs::read(dest.join("0000000001")).unwrap(), b"x\n");
        let _ = fs::remove_dir_all(&d);
    }
}
