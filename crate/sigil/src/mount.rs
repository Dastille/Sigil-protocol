//! Mount of a `.sg1` / SGDR pack, vault tip, or segment log so apps see normal paths.
//!
//! Durable seals stay intact: cleartext lives only in RAM (FUSE) or an export
//! directory. Use `--export-dir --writable` for a dirty cleartext tree, then
//! `sigil vault commit --from-export` to re-seal as a new vault version.
//! FUSE remains read-only. Segment logs (`kind=log`) mount read-only as one file
//! per live segment (tombstones omitted; compaction members keep their original
//! seq names); always available via `--export-dir`.

use crate::folder::{is_dir_pack, list_dir_pack, read_dir_entry_star, DirEntry};
use crate::keys::Identity;
use crate::vault::{self, VAULT_SUFFIX};
use crate::work::{is_work_pack, payload_name, unseal_path_keys};
use crate::{locate_header, unseal_ex_keys, Result};
use std::collections::HashMap;
use std::fs;
use std::io::{self, Write};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

const TTL: Duration = Duration::from_secs(1);

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
    cache: Mutex<HashMap<u64, Arc<Vec<u8>>>>,
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
            cache: Mutex::new(HashMap::new()),
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
        let listing = crate::seglog::list(input)?;
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
            cache: Mutex::new(HashMap::new()),
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

    pub fn read_file(&self, path: &str) -> Result<Arc<Vec<u8>>> {
        let ino = self
            .lookup_path(path)
            .ok_or_else(|| crate::Error::Msg(format!("no such path in mount: {path:?}")))?;
        self.read_ino(ino)
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
                    let data = self.read_ino(*ino)?;
                    fs::write(&out, data.as_ref()).map_err(|e| crate::Error::Msg(e.to_string()))?;
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
        let size = if is_work_pack(&self.seal) {
            // work head has orig len
            let bytes = fs::read(&self.seal).map_err(|e| crate::Error::Msg(e.to_string()))?;
            if bytes.len() >= 17 {
                u64::from_le_bytes(bytes[9..17].try_into().unwrap_or([0; 8]))
            } else {
                0
            }
        } else {
            let bytes = fs::read(&self.seal).map_err(|e| crate::Error::Msg(e.to_string()))?;
            locate_header(&bytes)
                .map(|(h, _, _)| h.orig_len)
                .unwrap_or(0)
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
        let entries = list_dir_pack(&self.seal)?;
        for e in entries {
            self.add_entry(&e)?;
        }
        Ok(())
    }

    fn add_entry(&mut self, e: &DirEntry) -> Result<()> {
        let rel = e.path.replace('\\', "/");
        if rel.contains("..") || Path::new(&rel).is_absolute() {
            return Err(crate::Error::Msg(format!(
                "refusing unsafe path in folder pack: {rel}"
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

    fn read_ino(&self, ino: u64) -> Result<Arc<Vec<u8>>> {
        if let Some(c) = self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .get(&ino)
            .cloned()
        {
            return Ok(c);
        }
        let node = self
            .nodes
            .get(&ino)
            .ok_or_else(|| crate::Error::Msg(format!("missing inode {ino}")))?;
        let src = match &node.kind {
            NodeKind::File { src, .. } => src.clone(),
            NodeKind::Dir => return Err(crate::Error::Msg("is a directory".into())),
        };
        let data = match src {
            FileSrc::Whole => decode_whole(&self.seal, self.pass.as_deref(), &self.identities)?,
            FileSrc::Member { star } => {
                let star = star.ok_or_else(|| {
                    crate::Error::Msg(format!(
                        "star for {} is missing (see `sigil doctor`)",
                        node.name
                    ))
                })?;
                decode_whole(&star, self.pass.as_deref(), &self.identities)?
            }
            FileSrc::Entry { rel } => {
                let star = read_dir_entry_star(&self.seal, &rel)?;
                let file_pass = pass_for(&rel, self.pass.as_deref(), &self.wards);
                decode_star(&star, file_pass.as_deref(), &self.identities)?
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
                out.parts
                    .into_iter()
                    .next()
                    .map(|(_, b)| b)
                    .ok_or_else(|| crate::Error::Msg(format!("segment {seq} produced no bytes")))?
            }
        };
        let arc = Arc::new(data);
        self.cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .insert(ino, arc.clone());
        Ok(arc)
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
        let tmp = std::env::temp_dir().join(format!(
            "sigil-mount-wk-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        unseal_path_keys(seal, &tmp, pass, &[], identities)?;
        let data = fs::read(&tmp).map_err(|e| crate::Error::Msg(e.to_string()))?;
        let _ = fs::remove_file(&tmp);
        Ok(data)
    } else {
        let bytes = fs::read(seal).map_err(|e| crate::Error::Msg(e.to_string()))?;
        unseal_ex_keys(&bytes, pass, &[], identities)
    }
}

fn decode_star(star: &[u8], pass: Option<&str>, identities: &[Identity]) -> Result<Vec<u8>> {
    if star.starts_with(&crate::work::WORK_MAGIC) {
        let tmp = std::env::temp_dir().join(format!(
            "sigil-mount-star-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .map(|d| d.subsec_nanos())
                .unwrap_or(0)
        ));
        fs::write(&tmp, star).map_err(|e| crate::Error::Msg(e.to_string()))?;
        let out = tmp.with_extension("bin");
        unseal_path_keys(&tmp, &out, pass, &[], identities)?;
        let data = fs::read(&out).map_err(|e| crate::Error::Msg(e.to_string()))?;
        let _ = fs::remove_file(&tmp);
        let _ = fs::remove_file(&out);
        Ok(data)
    } else {
        unseal_ex_keys(star, pass, &[], identities)
    }
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
            "FUSE mount failed ({e}). On Parrot/Linux: need /dev/fuse + fusermount3.              Fallback: `sigil mount … --export-dir /tmp/view`."
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
        match self.inner.read_ino(u64::from(ino)) {
            Ok(data) => {
                let start = offset as usize;
                if start >= data.len() {
                    reply.data(&[]);
                    return;
                }
                let end = (start + size as usize).min(data.len());
                reply.data(&data[start..end]);
            }
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
            println!(
                "exported {n} file(s) → {}  (writable dirty tree; seal intact)",
                dest.display()
            );
            println!(
                "re-seal: sigil vault commit --from-export {}",
                dest.display()
            );
        } else {
            println!(
                "exported {n} file(s) → {}  (seal intact, read-only view)",
                dest.display()
            );
        }
        println!("source {}", fs.seal_path().display());
        return Ok(());
    }
    println!(
        "mounting {} → {} (read-only FUSE; Ctrl-C or `sigil umount` to leave)",
        fs.seal_path().display(),
        mountpoint.display()
    );
    let seal = fs.seal_path().to_path_buf();
    mount_fuse(fs, mountpoint)?;
    let after = sha_of(&seal)?;
    if before != after {
        let _ = writeln!(
            io::stderr(),
            "warning: seal digest changed while mounted (unexpected)"
        );
    } else {
        println!("unmounted; seal unchanged");
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
    if log.privindex {
        return Err(crate::Error::Msg(
            "mounting a log with a private INDEX is not supported yet; use `sigil log read LOG --seq N` (with --pass / --identity)".into(),
        ));
    }
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
        println!(
            "exported {n} live segment(s) → {}  (log intact, read-only view)",
            dest.display()
        );
        println!("source {}", fs.seal_path().display());
        return Ok(());
    }
    println!(
        "mounting log {} → {} (read-only FUSE; one file per live segment; Ctrl-C or `sigil umount` to leave)",
        fs.seal_path().display(),
        mountpoint.display()
    );
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
