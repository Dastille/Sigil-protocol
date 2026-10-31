//! `sigil log add LOG DIR`: back a folder up into a segment log, sealing only what is new or
//! changed since the last add.
//!
//! Every regular file under `DIR` (recursive, symlinks and special files skipped and reported)
//! becomes **its own segment**, made by the same sealing path as `sigil log append`, and its INDEX
//! line carries one additive key, `path=<relative path>` (`%XX`-escaped bytes, `/`-separated). The
//! line is otherwise an ordinary `log=1` segment line (`size` / `sha` are the file's plain length
//! and SHA-256), so a log that never uses `add` is byte-identical to before, older sigils read,
//! verify, mend and prove these entries like any other and simply ignore `path=`.
//!
//! **What "already sealed" means.** For each relative path the latest entry the HEAD vouches for
//! (`trusted_len`: on a signed log, only entries covered by a valid signature) gives a size and a
//! SHA-256. A file is *unchanged* only if its size matches **and** the SHA-256 of its current bytes
//! matches **and** the segment file holding that entry is present and its header carries the
//! true-name the INDEX recorded. Size is used only as a shortcut to "changed" (never to "skip"),
//! modification times are not used at all. Anything else is sealed again, so a tampered or stale
//! INDEX / source can only cause an extra copy, never a silent skip of different content.
//!
//! **Nothing is ever deleted.** A path whose latest entry is live but which is no longer in `DIR`
//! is reported as "missing from source (kept)"; no tombstone is written. A changed file is a new
//! segment (a new version); the old one stays. A path whose latest version was tombstoned and whose
//! bytes are still exactly that version is not re-added behind the user's back ("deleted earlier,
//! not re-added"), mirroring `log adopt`.
//!
//! **Skipping parts of the folder.** `--exclude PATTERN` (repeatable) and a `.sigilignore` file at
//! the top of `DIR` (one pattern per line, `#` comments) name files and folders to leave out; a
//! matching folder is skipped with everything under it, unread (see [`super::Excluder`] for the
//! pattern language). Excluded paths that are already in the log are **left alone**: they are not
//! "missing from source", nothing is tombstoned, and they are counted as "excluded, kept". A bad
//! pattern refuses the run before anything is read or written.
//!
//! Crash safety: segments are written as unindexed files (and keys into the ring for a
//! `--segment-keys` log), then their INDEX lines are appended in one write (the commit point), then
//! HEAD. A run commits a **checkpoint** every `checkpoint_files` files or `checkpoint_bytes` plain
//! bytes, so a crash during a very large first add loses at most one checkpoint: run it again and
//! the committed files are recognised as unchanged.

use std::collections::{BTreeMap, BTreeSet};
use std::ffi::OsStr;
use std::fs;
use std::io::Read;
use std::path::{Path, PathBuf};

use super::*;

/// Default checkpoint: commit after this many files…
pub const ADD_CHECKPOINT_FILES: usize = 1000;
/// …or after this many plain bytes, whichever comes first.
pub const ADD_CHECKPOINT_BYTES: u64 = 1 << 30;

/// Options for [`add`].
pub struct AddOpts<'a> {
    /// ECC mode of the new segments (as for `append`).
    pub mode: Mode,
    /// Passphrase that seals each new segment (in a `--segment-keys` log: wraps its key).
    pub pass: Option<&'a str>,
    /// Encrypt-to recipients of each new segment (in a `--segment-keys` log: wrap its key).
    pub recipients: &'a [PublicIdentity],
    /// Signing key (required exactly when the log is signed; not needed for a dry run).
    pub identity: Option<&'a Identity>,
    /// Plan only: read and hash, write nothing, take no lock.
    pub dry_run: bool,
    /// Skip patterns (`--exclude`), applied with those of `DIR/.sigilignore`.
    pub exclude: &'a [String],
    /// Do not read `DIR/.sigilignore` (only `exclude` applies).
    pub no_ignore_file: bool,
    /// Commit a checkpoint after this many sealed files (0 = [`ADD_CHECKPOINT_FILES`]).
    pub checkpoint_files: usize,
    /// Commit a checkpoint after this many plain bytes (0 = [`ADD_CHECKPOINT_BYTES`]).
    pub checkpoint_bytes: u64,
    /// Private INDEX: extra identities that may open the index key (besides `pass` / `identity`).
    pub unlock: &'a [Identity],
    /// Use and refresh the size+mtime cache (`ADDCACHE`): skip hashing files whose stamp is
    /// unchanged since they last matched the log. Refused for a private INDEX.
    pub cache: bool,
}

impl Default for AddOpts<'_> {
    fn default() -> Self {
        AddOpts {
            mode: Mode::Reflection,
            pass: None,
            recipients: &[],
            identity: None,
            dry_run: false,
            exclude: &[],
            no_ignore_file: false,
            checkpoint_files: 0,
            checkpoint_bytes: 0,
            unlock: &[],
            cache: false,
        }
    }
}

/// Why a file is sealed by this run.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AddWhy {
    /// The path is not in the log yet.
    New,
    /// The path is in the log (latest version: segment `prev`) with different content.
    Changed { prev: u64 },
    /// Same content as segment `prev`, but that segment's file is missing or is not the star the
    /// INDEX recorded; a fresh copy is sealed rather than trusting it.
    Reseal { prev: u64, why: String },
}

/// One file this run seals (or, in a dry run, would seal).
#[derive(Clone, Debug)]
pub struct AddItem {
    /// Path relative to `DIR`, `/`-separated (raw bytes of the file name).
    pub rel: Vec<u8>,
    /// Plain size (from the bytes sealed; in a dry run, from the file system).
    pub size: u64,
    /// New, changed, or sealed again.
    pub why: AddWhy,
    /// The new segment (0 in a dry run).
    pub seq: u64,
}

/// Outcome of [`add`].
#[derive(Debug, Default)]
pub struct AddReport {
    /// The log container.
    pub dir: PathBuf,
    /// The source folder as given.
    pub source: PathBuf,
    /// Files sealed (or to be sealed), in stable order (byte order of the relative path).
    pub items: Vec<AddItem>,
    /// Files whose latest segment already holds exactly their bytes.
    pub unchanged: usize,
    /// Of `unchanged`, files not hashed because the `--cache` stamp matched.
    pub cache_hits: usize,
    /// Paths still live in the log but no longer in `DIR`: `(path, latest segment)`. Kept, never tombstoned.
    pub missing: Vec<(Vec<u8>, u64)>,
    /// Symlinks, devices, pipes, sockets and nested sigil containers: `(path, what)`. Not added.
    pub special: Vec<(Vec<u8>, String)>,
    /// Files (or folders) that could not be read: `(path, error)`. Not added; exit code 1.
    pub unreadable: Vec<(Vec<u8>, String)>,
    /// Paths whose bytes equal a version that was tombstoned: `(path, segment, tombstone)`. Not re-added.
    pub deleted: Vec<(Vec<u8>, u64, u64)>,
    /// Files and folders skipped by an exclude pattern while walking `DIR` (a folder stands for its
    /// whole subtree, which is not read): `(path, is folder, pattern, where the pattern came from)`.
    pub excluded: Vec<(Vec<u8>, bool, String, String)>,
    /// Paths still live in the log that an exclude pattern now covers: `(path, latest segment)`.
    /// Left alone: not missing, never tombstoned.
    pub excluded_kept: Vec<(Vec<u8>, u64)>,
    /// Patterns in force (`--exclude` plus `.sigilignore`), and how many came from the file.
    pub patterns: (usize, usize),
    /// Checkpoints committed (INDEX writes).
    pub commits: usize,
    /// Merkle root of the last HEAD written (`None` when nothing was committed).
    pub root: Option<[u8; 32]>,
    /// That HEAD is signed.
    pub signed: bool,
    /// This was a `--dry-run`.
    pub dry_run: bool,
    /// Things worth telling the user (lagging HEAD re-covered, unvouched entries, …).
    pub notes: Vec<String>,
}

impl AddReport {
    fn count(&self, f: impl Fn(&AddWhy) -> bool) -> usize {
        self.items.iter().filter(|i| f(&i.why)).count()
    }

    /// Files new to the log.
    pub fn added(&self) -> usize {
        self.count(|w| *w == AddWhy::New)
    }

    /// Files sealed as a new version of a path already in the log.
    pub fn changed(&self) -> usize {
        self.count(|w| matches!(w, AddWhy::Changed { .. }))
    }

    /// Files sealed again because the log's copy is missing or not what the INDEX recorded.
    pub fn resealed(&self) -> usize {
        self.count(|w| matches!(w, AddWhy::Reseal { .. }))
    }

    /// Human-readable report: one line per sealed / missing / skipped file, then the summary line.
    pub fn render(&self) -> String {
        let mut s = String::new();
        let arrow = |seq: u64| {
            if self.dry_run {
                String::new()
            } else {
                format!(" → segment {seq}")
            }
        };
        for i in &self.items {
            let what = match &i.why {
                AddWhy::New => "new".to_string(),
                AddWhy::Changed { prev } => format!("changed (was segment {prev})"),
                AddWhy::Reseal { prev, why } => format!("sealed again ({why}; was segment {prev})"),
            };
            s.push_str(&format!(
                "  + {}  {} bytes  {what}{}\n",
                show_path(&i.rel),
                i.size,
                arrow(i.seq)
            ));
        }
        for (p, seq, t) in &self.deleted {
            s.push_str(&format!(
                "  = {}  same bytes as segment {seq}, deleted by entry {t}; not re-added\n",
                show_path(p)
            ));
        }
        for (p, seq) in &self.missing {
            s.push_str(&format!(
                "  ! {}  missing from source (kept: segment {seq})\n",
                show_path(p)
            ));
        }
        for (p, dir, pat, from) in &self.excluded {
            s.push_str(&format!(
                "  x {}{}  excluded by {pat:?} ({from})\n",
                show_path(p),
                if *dir { "/" } else { "" }
            ));
        }
        if self.dry_run {
            for (p, seq) in &self.excluded_kept {
                s.push_str(&format!(
                    "  ~ {}  excluded, kept in log (segment {seq}; not tombstoned)\n",
                    show_path(p)
                ));
            }
        }
        for (p, what) in &self.special {
            s.push_str(&format!("  - {}  skipped: {what}\n", show_path(p)));
        }
        for (p, e) in &self.unreadable {
            s.push_str(&format!(
                "  ? {}  unreadable, not added: {e}\n",
                show_path(p)
            ));
        }
        let mut tail = format!(
            "log add {} from {}: {}added {}, changed {}, unchanged {}, missing {}, skipped-special {}",
            self.dir.display(),
            self.source.display(),
            if self.dry_run { "would have " } else { "" },
            self.added(),
            self.changed(),
            self.unchanged,
            self.missing.len(),
            self.special.len()
        );
        if self.cache_hits > 0 {
            tail.push_str(&format!(" ({} not re-hashed: --cache)", self.cache_hits));
        }
        if !self.excluded.is_empty() {
            tail.push_str(&format!(", excluded {}", self.excluded.len()));
        }
        if !self.excluded_kept.is_empty() {
            tail.push_str(&format!(", excluded-kept {}", self.excluded_kept.len()));
            if !self.dry_run {
                tail.push_str(" (listed by --dry-run)");
            }
        }
        if self.resealed() > 0 {
            tail.push_str(&format!(", sealed again {}", self.resealed()));
        }
        if !self.deleted.is_empty() {
            tail.push_str(&format!(", deleted-not-re-added {}", self.deleted.len()));
        }
        if !self.unreadable.is_empty() {
            tail.push_str(&format!(", unreadable {}", self.unreadable.len()));
        }
        if self.dry_run {
            tail.push_str("  (dry run: nothing written)");
        } else if let Some(r) = &self.root {
            tail.push_str(&format!("  root {}…", &hex32(r)[..16]));
            if self.signed {
                tail.push_str(" (signed)");
            }
        } else {
            tail.push_str("  (nothing to do: log unchanged)");
        }
        s.push_str(&tail);
        s.push('\n');
        s
    }
}

/// A regular file found under the source folder.
struct Found {
    rel: Vec<u8>,
    abs: PathBuf,
    size: u64,
    stamp: Option<Stamp>,
}

/// Raw bytes of one file name (exact on Unix; must be Unicode elsewhere).
fn name_bytes(n: &OsStr) -> Option<Vec<u8>> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        Some(n.as_bytes().to_vec())
    }
    #[cfg(not(unix))]
    {
        n.to_str().map(|s| s.as_bytes().to_vec())
    }
}

fn join_rel(parent: &[u8], name: &[u8]) -> Vec<u8> {
    let mut r = parent.to_vec();
    if !r.is_empty() {
        r.push(b'/');
    }
    r.extend_from_slice(name);
    r
}

/// Walk `root` (no symlinks followed); regular files sorted by relative path bytes. Entries an
/// exclude pattern matches are recorded in `rep.excluded` and not descended into.
fn walk(root: &Path, ex: &Excluder, rep: &mut AddReport) -> Vec<Found> {
    let mut found = Vec::new();
    let mut stack: Vec<(PathBuf, Vec<u8>)> = vec![(root.to_path_buf(), Vec::new())];
    while let Some((dir, rel)) = stack.pop() {
        let rd = match fs::read_dir(&dir) {
            Ok(rd) => rd,
            Err(e) => {
                rep.unreadable.push((rel, format!("folder: {e}")));
                continue;
            }
        };
        for ent in rd {
            let ent = match ent {
                Ok(e) => e,
                Err(e) => {
                    rep.unreadable.push((rel.clone(), format!("folder: {e}")));
                    continue;
                }
            };
            let abs = ent.path();
            let Some(name) = name_bytes(&ent.file_name()) else {
                let r = join_rel(&rel, ent.file_name().to_string_lossy().as_bytes());
                rep.special
                    .push((r, "file name is not valid Unicode on this system".into()));
                continue;
            };
            let r = join_rel(&rel, &name);
            let md = match fs::symlink_metadata(&abs) {
                Ok(m) => m,
                Err(e) => {
                    rep.unreadable.push((r, e.to_string()));
                    continue;
                }
            };
            let ft = md.file_type();
            if let Some(p) = ex.matching(&r, ft.is_dir()) {
                rep.excluded
                    .push((r, ft.is_dir(), p.text.clone(), p.origin.clone()));
                continue;
            }
            if ft.is_symlink() {
                rep.special.push((r, "symbolic link (not followed)".into()));
            } else if ft.is_dir() {
                if container::is_container(&abs) {
                    rep.special.push((r, "sigil container (not added)".into()));
                } else {
                    stack.push((abs, r));
                }
            } else if ft.is_file() {
                found.push(Found {
                    rel: r,
                    abs,
                    size: md.len(),
                    stamp: Stamp::of(&md),
                });
            } else {
                rep.special
                    .push((r, "special file (device, pipe or socket)".into()));
            }
        }
    }
    found.sort_by(|a, b| a.rel.cmp(&b.rel));
    rep.special.sort();
    rep.unreadable.sort();
    rep.excluded.sort();
    found
}

/// SHA-256 of a file, streamed (the file is not held in memory).
fn hash_file(p: &Path) -> std::io::Result<[u8; 32]> {
    use sha2::{Digest, Sha256};
    let mut f = fs::File::open(p)?;
    let mut h = Sha256::new();
    let mut buf = vec![0u8; 1 << 20];
    loop {
        let n = f.read(&mut buf)?;
        if n == 0 {
            break;
        }
        h.update(&buf[..n]);
    }
    Ok(h.finalize().into())
}

/// Header of the star in segment file `h` (the front copy, else a spare the way `verify` finds it).
fn segment_header(log: &Log, h: u64) -> std::result::Result<crate::Header, String> {
    let p = log.segment_path(h);
    let mut f = fs::File::open(&p).map_err(|_| format!("segment {h} file is missing"))?;
    let mut buf = vec![0u8; crate::HEADER_SIZE];
    if f.read_exact(&mut buf).is_ok() {
        if let Ok(hd) = crate::read_header(&buf) {
            return Ok(hd);
        }
    }
    let all = fs::read(&p).map_err(|_| format!("segment {h} file is unreadable"))?;
    crate::locate_header(&all)
        .map(|(hd, _, _)| hd)
        .map_err(|_| format!("segment {h} file is not readable as a star"))
}

/// The file holding segment `seq` (itself, or the compaction segment it moved into) is present and
/// its header carries the true-name the INDEX recorded for that file. Keyless, reads one header.
fn segment_holds(
    log: &Log,
    entries: &[Entry],
    st: &State,
    seq: u64,
) -> std::result::Result<(), String> {
    let h = st.holder_of(seq);
    let e = h
        .checked_sub(1)
        .and_then(|i| entries.get(i as usize))
        .ok_or_else(|| format!("segment {h} is not in the INDEX"))?;
    if segment_header(log, h)?.digest != e.star_digest() {
        return Err(format!(
            "segment {h} file is not the star the INDEX recorded"
        ));
    }
    Ok(())
}

/// The newest `log add` entry whose segment was sealed encrypted (`--pass` / `--to`), if the
/// newest one was. Used to refuse quietly storing new files unencrypted next to encrypted ones.
fn newest_add_encrypted(log: &Log, entries: &[Entry], st: &State) -> Option<u64> {
    let e = entries
        .iter()
        .rev()
        .find(|e| e.op == Op::Seg && e.path().is_some() && st.deleted_by(e.seq).is_none())?;
    let hd = segment_header(log, st.holder_of(e.seq)).ok()?;
    hd.encrypted().then_some(e.seq)
}

/// A file planned for sealing.
struct Planned {
    found: Found,
    why: AddWhy,
}

/// Seal the new and changed files of folder `src` into the log at `path` (see the module docs).
pub fn add(path: &Path, src: &Path, opts: &AddOpts<'_>) -> Result<AddReport> {
    let mut log = Log::open(path)?;
    // a private INDEX must be opened to know what is already sealed (a dry run too)
    if log.privindex {
        unlock_for_write(&mut log, opts.pass, opts.identity, opts.unlock)?;
    }
    if !src.is_dir() {
        return Err(err(format!(
            "{}: not a folder (use `sigil log append` for one file)",
            src.display()
        )));
    }
    let abs_src = fs::canonicalize(src).map_err(io)?;
    if abs_src.ancestors().any(container::is_container) {
        return Err(err(format!(
            "{} is inside a sigil container; add a folder of ordinary files",
            src.display()
        )));
    }
    let ex = Excluder::new(opts.exclude, &abs_src, !opts.no_ignore_file).map_err(err)?;
    if opts.cache && log.privindex {
        return Err(err(
            "--cache is refused for a private INDEX: the cache file would show names and sizes in clear",
        ));
    }
    if !opts.dry_run || opts.identity.is_some() {
        signer_gate(&log, opts.identity)?;
    }
    if log.segkeys
        && !opts.dry_run
        && opts.pass.filter(|p| !p.is_empty()).is_none()
        && opts.recipients.is_empty()
    {
        return Err(err(
            "this log has per-segment keys: give --pass and/or --to so each new segment's key can be wrapped and kept in the key ring",
        ));
    }
    let mut rep = AddReport {
        dir: log.dir.clone(),
        source: src.to_path_buf(),
        dry_run: opts.dry_run,
        patterns: (ex.patterns.len(), ex.from_file),
        ..Default::default()
    };
    let _guard = if opts.dry_run {
        None
    } else {
        Some(lock(&log)?)
    };
    // the same consistency checks as every writer (damaged chain, HEAD ahead of INDEX, …); reads only
    let (idx, notes) = prepare_write(&log)?;
    if !opts.dry_run {
        signer_gate_at(&log, &idx.entries, opts.identity)?;
    }
    if !opts.dry_run {
        rep.notes = notes; // (a dry run repairs nothing, so "trimmed" / "rewritten" notes do not apply)
    }

    // what the log holds: latest version of every path, from entries the HEAD vouches for
    let trusted = trusted_len(&log, &idx);
    let mut held: BTreeMap<Vec<u8>, (u64, u64, [u8; 32])> = BTreeMap::new();
    for e in idx.entries.iter().take(trusted) {
        if let (Op::Seg, Some(p)) = (&e.op, e.path()) {
            held.insert(p, (e.seq, e.size, e.sha));
        }
    }
    let unvouched = idx.entries[trusted.min(idx.entries.len())..]
        .iter()
        .filter(|e| e.path().is_some())
        .count();
    if unvouched > 0 {
        rep.notes.push(format!(
            "{unvouched} INDEX entr{} with a path {} not covered by a valid HEAD{}; their files are treated as not yet in the log (run `sigil log verify`)",
            if unvouched == 1 { "y" } else { "ies" },
            if unvouched == 1 { "is" } else { "are" },
            if log.signer.is_some() { " signature" } else { "" }
        ));
    }
    let st = &idx.state;
    let cache = if opts.cache {
        let c = AddCache::load(&log.dir, &abs_src);
        if let Some(why) = &c.ignored {
            rep.notes
                .push(format!("add cache ignored ({why}); hashing every file"));
        }
        c
    } else {
        AddCache::default()
    };
    // stamps (taken before reading) of files whose bytes are known to equal a version
    let mut keep: BTreeMap<Vec<u8>, addcache::CacheHit> = BTreeMap::new();
    let mut stamps: BTreeMap<Vec<u8>, Stamp> = BTreeMap::new();

    // plan
    let found = walk(&abs_src, &ex, &mut rep);
    let mut seen: BTreeSet<Vec<u8>> = rep
        .special
        .iter()
        .chain(rep.unreadable.iter())
        .map(|(p, _)| p.clone())
        .collect();
    let mut plan: Vec<Planned> = Vec::new();
    for f in found {
        seen.insert(f.rel.clone());
        if let Some(s) = f.stamp {
            stamps.insert(f.rel.clone(), s);
        }
        let why = match held.get(&f.rel) {
            None => AddWhy::New,
            // a different size is certainly different content (a shortcut to "changed", never to "skip")
            Some(&(seq, size, _)) if size != f.size => AddWhy::Changed { prev: seq },
            Some(&(seq, _, sha)) => {
                let hit = cache.fresh(&f.rel, f.stamp, seq, &sha);
                let now_sha = if hit {
                    sha
                } else {
                    match hash_file(&f.abs) {
                        Ok(h) => h,
                        Err(e) => {
                            rep.unreadable.push((f.rel, e.to_string()));
                            continue;
                        }
                    }
                };
                if now_sha != sha {
                    AddWhy::Changed { prev: seq }
                } else if let Some(t) = st.deleted_by(seq) {
                    rep.deleted.push((f.rel, seq, t));
                    continue;
                } else {
                    match segment_holds(&log, &idx.entries, st, seq) {
                        Ok(()) => {
                            rep.unchanged += 1;
                            if hit {
                                rep.cache_hits += 1;
                            }
                            if let Some(stamp) = f.stamp {
                                keep.insert(f.rel, addcache::CacheHit { stamp, seq, sha });
                            }
                            continue;
                        }
                        Err(why) => AddWhy::Reseal { prev: seq, why },
                    }
                }
            }
        };
        plan.push(Planned { found: f, why });
    }
    for (p, &(seq, _, _)) in &held {
        if !seen.contains(p) && st.deleted_by(seq).is_none() {
            // excluded paths are left alone: neither missing nor tombstoned
            if ex.excluded(p).is_some() {
                rep.excluded_kept.push((p.clone(), seq));
            } else {
                rep.missing.push((p.clone(), seq));
            }
        }
    }
    let protect = opts.pass.filter(|p| !p.is_empty()).is_some() || !opts.recipients.is_empty();
    if !plan.is_empty() && !protect {
        if let Some(seq) = newest_add_encrypted(&log, &idx.entries, st) {
            let msg = format!(
                "the newest file in this log (segment {seq}) was sealed with --pass / --to; give --pass / --to again so new files are not stored unencrypted"
            );
            if !opts.dry_run {
                return Err(err(msg));
            }
            rep.notes.push(msg);
        }
    }
    if opts.dry_run {
        rep.items = plan
            .into_iter()
            .map(|p| AddItem {
                rel: p.found.rel,
                size: p.found.size,
                why: p.why,
                seq: 0,
            })
            .collect();
        return Ok(rep);
    }
    seal_plan(&log, idx, plan, opts, &mut rep)?;
    if opts.cache && rep.unreadable.is_empty() {
        // sealed files: the INDEX now holds the SHA-256 of the bytes actually read
        let fresh = read_index(&log)?;
        for it in &rep.items {
            let e = it
                .seq
                .checked_sub(1)
                .and_then(|i| fresh.entries.get(i as usize));
            if let (Some(e), Some(&stamp)) = (e, stamps.get(&it.rel)) {
                if e.size == stamp.size {
                    keep.insert(
                        it.rel.clone(),
                        addcache::CacheHit {
                            stamp,
                            seq: e.seq,
                            sha: e.sha,
                        },
                    );
                }
            }
        }
        AddCache::save(&log.dir, &abs_src, &keep)?;
    }
    Ok(rep)
}

/// Seal the planned files one at a time (only one file's bytes in memory) and commit them in
/// checkpoints. On an error the uncommitted segment files and key records are removed again.
fn seal_plan(
    log: &Log,
    mut idx: ParsedIndex,
    plan: Vec<Planned>,
    opts: &AddOpts<'_>,
    rep: &mut AddReport,
) -> Result<()> {
    let max_files = if opts.checkpoint_files == 0 {
        ADD_CHECKPOINT_FILES
    } else {
        opts.checkpoint_files
    };
    let max_bytes = if opts.checkpoint_bytes == 0 {
        ADD_CHECKPOINT_BYTES
    } else {
        opts.checkpoint_bytes
    };
    let mut next = idx.entries.len() as u64 + 1;
    let mut bodies: Vec<String> = Vec::new();
    let mut written: Vec<PathBuf> = Vec::new();
    let mut keyed: Vec<u64> = Vec::new();
    let mut pending: Vec<AddItem> = Vec::new();
    let mut pending_bytes = 0u64;
    let total = plan.len();
    for (k, p) in plan.into_iter().enumerate() {
        let step = (|| -> Result<bool> {
            let data = match fs::read(&p.found.abs) {
                Ok(d) => d,
                Err(e) => {
                    rep.unreadable.push((p.found.rel.clone(), e.to_string()));
                    return Ok(false);
                }
            };
            let seq = next;
            let (sealed, key) =
                seal_segment(log, seq, &data, opts.mode, opts.pass, opts.recipients)?;
            // the INDEX line first: a private log refuses an unencrypted star before it is written
            let body = if log.privindex {
                private::sealed_body(
                    log,
                    seq,
                    now(),
                    "",
                    &sealed,
                    &Hidden {
                        size: data.len() as u64,
                        sha: sha256(&data),
                        path: Some(p.found.rel.clone()),
                        reason: None,
                    },
                )?
            } else {
                format!(
                    "seq={seq} t={} size={} sha={} path={}{}",
                    now(),
                    data.len(),
                    hex32(&sha256(&data)),
                    enc_bytes(&p.found.rel),
                    star_field(&sealed)
                )
            };
            let seg = log.segment_path(seq);
            write_atomic(&seg, &sealed)?;
            written.push(seg);
            if let Some(m) = &key {
                keyed.push(seq);
                keyring::put(log, seq, m, opts.pass, opts.recipients)?;
            }
            bodies.push(body);
            pending_bytes += data.len() as u64;
            pending.push(AddItem {
                rel: p.found.rel.clone(),
                size: data.len() as u64,
                why: p.why.clone(),
                seq,
            });
            next += 1;
            Ok(true)
        })();
        let last = k + 1 == total;
        let res = step.and_then(|_| {
            if !bodies.is_empty()
                && (last || bodies.len() >= max_files || pending_bytes >= max_bytes)
            {
                let taken = std::mem::take(&mut idx);
                let (_entries, head) = commit(log, taken, &bodies, opts.identity)?;
                rep.commits += 1;
                rep.root = Some(head.root);
                rep.signed = head.sig.is_some();
                rep.items.append(&mut pending);
                bodies.clear();
                written.clear();
                keyed.clear();
                pending_bytes = 0;
                if !last {
                    idx = read_index(log)?;
                    if let Some((line, _, msg)) = &idx.error {
                        return Err(err(format!(
                            "INDEX unreadable after a checkpoint (line {line}: {msg})"
                        )));
                    }
                }
            }
            Ok(())
        });
        if let Err(e) = res {
            for w in &written {
                let _ = fs::remove_file(w);
            }
            if !keyed.is_empty() {
                let _ = keyring::destroy(log, &keyed);
            }
            let done = rep.items.len();
            return Err(if done > 0 {
                err(format!(
                    "{e} ({done} file(s) were already committed; run `sigil log add` again to continue)"
                ))
            } else {
                e
            });
        }
    }
    rep.unreadable.sort();
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sigil-add-unit-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn path_token_round_trips_any_bytes() {
        let raw: &[u8] = b"a b/=%\x00\x7f\xff/\xc3\xa9t\xc3\xa9.jpg";
        let t = enc_bytes(raw);
        assert!(!t.contains(' ') && !t.contains('=') && t.is_ascii(), "{t}");
        assert_eq!(dec_bytes(&t).unwrap(), raw);
        assert_eq!(dec_bytes("a%2"), None, "short escape");
        assert_eq!(dec_bytes("a%+1"), None, "non-hex escape");
    }

    #[test]
    fn checkpoints_commit_in_parts_and_rerun_is_a_no_op() {
        let d = tmp("ckpt");
        let src = d.join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        for (i, n) in ["e", "d", "sub/c", "b", "a"].iter().enumerate() {
            fs::write(src.join(n), format!("file {i}\n")).unwrap();
        }
        init_with(&d.join("ev"), None, false).unwrap();
        let opts = AddOpts {
            checkpoint_files: 2,
            ..Default::default()
        };
        let r = add(&d.join("ev"), &src, &opts).unwrap();
        assert_eq!((r.added(), r.commits), (5, 3));
        let l = list(&d.join("ev")).unwrap();
        let paths: Vec<Vec<u8>> = l.entries.iter().filter_map(|e| e.path()).collect();
        let want: Vec<&[u8]> = vec![b"a", b"b", b"d", b"e", b"sub/c"];
        assert_eq!(paths, want, "stable byte order across checkpoints");
        assert_eq!(l.head.as_ref().map(|h| h.seq), Some(5));
        let again = add(&d.join("ev"), &src, &opts).unwrap();
        assert_eq!((again.added(), again.unchanged, again.commits), (0, 5, 0));
        assert!(again.root.is_none());
    }

    #[test]
    fn byte_budget_also_cuts_checkpoints() {
        let d = tmp("bytes");
        let src = d.join("src");
        fs::create_dir_all(&src).unwrap();
        for n in ["a", "b", "c"] {
            fs::write(src.join(n), vec![7u8; 100]).unwrap();
        }
        init_with(&d.join("ev"), None, false).unwrap();
        let opts = AddOpts {
            checkpoint_bytes: 150,
            ..Default::default()
        };
        let r = add(&d.join("ev"), &src, &opts).unwrap();
        assert_eq!((r.added(), r.commits), (3, 2));
    }

    #[test]
    fn default_checkpoints() {
        assert_eq!(ADD_CHECKPOINT_FILES, 1000);
        assert_eq!(ADD_CHECKPOINT_BYTES, 1 << 30);
    }

    #[test]
    fn failed_run_removes_uncommitted_files_and_rerun_resumes() {
        let d = tmp("fail");
        let src = d.join("src");
        fs::create_dir_all(&src).unwrap();
        for n in ["a", "b", "c", "d"] {
            fs::write(src.join(n), format!("{n}\n")).unwrap();
        }
        let log = init_with(&d.join("ev"), None, false).unwrap();
        // block segment 3: its `.part` temp path is a folder, so writing it fails
        let mut blocker = log.segment_path(3).into_os_string();
        blocker.push(".part");
        fs::create_dir_all(&blocker).unwrap();
        let opts = AddOpts {
            checkpoint_files: 1,
            ..Default::default()
        };
        let e = add(&d.join("ev"), &src, &opts).unwrap_err().to_string();
        assert!(e.contains("2 file(s) were already committed"), "{e}");
        assert_eq!(list(&d.join("ev")).unwrap().entries.len(), 2);
        assert!(!log.dir.join(LOCK_FILE).exists(), "lock released");
        // one big checkpoint: c is sealed as segment 3, d fails at 4, so segment 3 is removed again
        fs::remove_dir_all(&blocker).unwrap();
        let mut blocker4 = log.segment_path(4).into_os_string();
        blocker4.push(".part");
        fs::create_dir_all(&blocker4).unwrap();
        fs::write(src.join("e"), "e\n").unwrap();
        let opts2 = AddOpts::default();
        assert!(add(&d.join("ev"), &src, &opts2).is_err());
        assert!(!log.segment_path(3).exists(), "uncommitted segment removed");
        assert_eq!(list(&d.join("ev")).unwrap().entries.len(), 2);
        // fixed: the run picks up where it stopped
        fs::remove_dir_all(&blocker4).unwrap();
        let r = add(&d.join("ev"), &src, &opts2).unwrap();
        assert_eq!((r.added(), r.unchanged), (3, 2));
    }
}
