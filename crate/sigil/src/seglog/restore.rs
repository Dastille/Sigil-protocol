//! `sigil log restore LOG PATH`: get a file, or a whole folder, back **by the path `log add`
//! recorded** (`path=` on its INDEX line), instead of by seq.
//!
//! * `PATH` naming a file restores the **latest version** of that path. `PATH` naming a folder
//!   (a prefix ending at a `/` boundary; `.` or `/` for everything) restores the latest version of
//!   every path under it, relative to that folder.
//! * Only entries the HEAD vouches for count (the rule `add` and `gc` use). A path whose latest
//!   version was tombstoned or shredded is **deleted**: restoring it alone is refused; in a folder
//!   it is left out and listed (never an older version in its place).
//! * Every file is read through the same checked reader as `log read` (true-name of the segment
//!   header, plain size and SHA-256 against the INDEX, compaction members cut out and re-hashed).
//!   All files are read and checked **before anything is written**; then a single file goes to a
//!   temporary name renamed into place, a folder is built in a temporary sibling folder renamed
//!   into place. An existing destination is refused. So a failure leaves nothing behind.
//! * Paths from the INDEX are untrusted: an empty, `.` or `..` component, an absolute path or a
//!   NUL byte is refused.
//! * Private INDEX / encrypted segments: the same `--pass` / `--identity` `log read` needs.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::*;

/// `(full log path, path relative to the restored folder, seq)`.
type Picked = (Vec<u8>, Vec<u8>, u64);

/// What [`restore`] wrote.
#[derive(Debug, Default)]
pub struct RestoreReport {
    /// The file or folder created.
    pub out: PathBuf,
    /// `true` when a folder was restored.
    pub folder: bool,
    /// Files written: `(path relative to the restored folder, or the full log path for one file, seq, size)`.
    pub files: Vec<(Vec<u8>, u64, u64)>,
    /// Paths under the folder whose latest version is deleted: `(path, segment, tombstone)`. Not written.
    pub deleted: Vec<(Vec<u8>, u64, u64)>,
}

impl RestoreReport {
    pub fn render(&self) -> String {
        let mut s = String::new();
        for (p, seq, size) in &self.files {
            s.push_str(&format!(
                "  + {}  {size} bytes  (segment {seq})\n",
                show_path(p)
            ));
        }
        for (p, seq, t) in &self.deleted {
            s.push_str(&format!(
                "  - {}  deleted (segment {seq}, by entry {t}); not restored\n",
                show_path(p)
            ));
        }
        s.push_str(&format!(
            "log restore: {} file(s), {} byte(s) → {}{}\n",
            self.files.len(),
            self.files.iter().map(|f| f.2).sum::<u64>(),
            self.out.display(),
            if self.deleted.is_empty() {
                String::new()
            } else {
                format!(", {} deleted path(s) left out", self.deleted.len())
            }
        ));
        s
    }
}

/// Normalise the user's PATH: `/`-separated, no leading/trailing `/`, `.` / `` = the whole log.
fn want_of(p: &str) -> Vec<u8> {
    let t = p.trim_matches('/');
    if t == "." {
        Vec::new()
    } else {
        t.as_bytes().to_vec()
    }
}

/// A relative path from the INDEX turned into a safe relative file system path.
fn safe_rel(rel: &[u8]) -> Result<PathBuf> {
    let bad = || {
        err(format!(
            "refusing unsafe path in the INDEX: {}",
            show_path(rel)
        ))
    };
    if rel.is_empty() || rel.contains(&0) {
        return Err(bad());
    }
    let mut out = PathBuf::new();
    for c in rel.split(|b| *b == b'/') {
        if c.is_empty() || c == b"." || c == b".." {
            return Err(bad());
        }
        #[cfg(unix)]
        {
            use std::os::unix::ffi::OsStrExt;
            out.push(std::ffi::OsStr::from_bytes(c));
        }
        #[cfg(not(unix))]
        {
            let s = std::str::from_utf8(c).map_err(|_| bad())?;
            if s.contains(['\\', ':']) {
                return Err(bad());
            }
            out.push(s);
        }
    }
    Ok(out)
}

fn tmp_beside(dest: &Path) -> Result<PathBuf> {
    let name = dest
        .file_name()
        .ok_or_else(|| err(format!("{}: not a file name", dest.display())))?;
    let mut n = std::ffi::OsString::from(".");
    n.push(name);
    n.push(format!(".sigil-restore-{}", std::process::id()));
    Ok(dest.with_file_name(n))
}

/// Restore `want` (a path `log add` recorded, or a folder of them) into `out` (default: its last
/// component in the current folder). See the module docs.
pub fn restore(
    path: &Path,
    want: &str,
    out: Option<&Path>,
    opts: &ReadOpts<'_>,
) -> Result<RestoreReport> {
    restore_version(path, want, out, opts, &Version::default())
}

/// Which version [`restore_version`] takes. Default: the latest of each path.
#[derive(Debug, Default, Clone, Copy)]
pub struct Version {
    /// The newest version appended at or before these unix seconds (file or folder).
    pub at: Option<u64>,
    /// Exactly this entry, which must be a version of the file `want` (file only).
    pub seq: Option<u64>,
}

/// [`restore`] an older version: as it was at `ver.at`, or the entry `ver.seq`. A version picked
/// that way that is deleted now is refused (file) or left out (folder), never swapped for an older one.
pub fn restore_version(
    path: &Path,
    want: &str,
    out: Option<&Path>,
    opts: &ReadOpts<'_>,
    ver: &Version,
) -> Result<RestoreReport> {
    let mut log = Log::open(path)?;
    if log.privindex {
        log.unlock_index(opts.pass, opts.identities)?;
    }
    let loaded = load(&log, &CheckOpts::default());
    if let Some(f) = loaded
        .findings
        .iter()
        .find(|f| f.severity == Severity::Error)
    {
        return Err(err(format!(
            "refusing to restore: {} {}: {}",
            f.code, f.subject, f.message
        )));
    }
    let entries = &loaded.index.entries;
    let st = &loaded.index.state;
    let trusted = trusted_len(&log, &loaded.index).min(entries.len());
    // latest vouched version of every path
    let mut latest: BTreeMap<Vec<u8>, u64> = BTreeMap::new();
    let mut any = false;
    for e in &entries[..trusted] {
        if let (Op::Seg, Some(p)) = (&e.op, e.path()) {
            any = true;
            if ver.at.is_none_or(|t| e.time <= t) {
                latest.insert(p, e.seq);
            }
        }
    }
    if !any {
        return Err(err(
            if log.privindex && entries.iter().any(|e| e.is_locked()) {
                "no entry with a path is readable (private INDEX: give --pass / --identity)"
                    .to_string()
            } else {
                "this log has no entries with a path (only `sigil log add` records paths; use `log read --seq`)".to_string()
            },
        ));
    }
    let w = want_of(want);
    if let Some(seq) = ver.seq {
        let e = entries[..trusted]
            .iter()
            .find(|e| e.seq == seq)
            .ok_or_else(|| {
                err(format!(
                    "seq {seq} is not among the {trusted} entries this log vouches for"
                ))
            })?;
        if !matches!(e.op, Op::Seg) || e.path().as_deref() != Some(w.as_slice()) || w.is_empty() {
            return Err(err(format!(
                "segment {seq} is not a version of the file {} (see `sigil log ls`)",
                show_path(&w)
            )));
        }
        latest.clear();
        latest.insert(w.clone(), seq);
    } else if let Some(t) = ver.at {
        let pre = if w.is_empty() {
            Vec::new()
        } else {
            [w.as_slice(), b"/"].concat()
        };
        if !latest.keys().any(|p| *p == w || p.starts_with(&pre)) {
            return Err(err(format!(
                "no version of {:?} at or before {} (see `sigil log ls`)",
                show_path(&w),
                iso_utc(t)
            )));
        }
    }
    let dead = |seq: u64| st.deleted_by(seq).or_else(|| st.shredded_by(seq));
    // exact file?
    let (folder, picked): (bool, Vec<Picked>) = match latest.get(&w) {
        Some(&seq) if !w.is_empty() => {
            if dead(seq).is_some() {
                return Err(err(format!(
                    "{}: the {} version (segment {seq}) is deleted: {}",
                    show_path(&w),
                    if ver.seq.is_some() {
                        "chosen".to_string()
                    } else if let Some(t) = ver.at {
                        iso_utc(t)
                    } else {
                        "latest".to_string()
                    },
                    deleted_msg(entries, st, seq)
                )));
            }
            (false, vec![(w.clone(), w.clone(), seq)])
        }
        _ => {
            let mut pre = w.clone();
            if !pre.is_empty() {
                pre.push(b'/');
            }
            let v: Vec<_> = latest
                .iter()
                .filter_map(|(p, s)| {
                    p.strip_prefix(pre.as_slice())
                        .map(|r| (p.clone(), r.to_vec(), *s))
                })
                .collect();
            if v.is_empty() {
                return Err(err(format!(
                    "no file or folder {:?} in this log (see `sigil log ls`)",
                    show_path(&w)
                )));
            }
            (true, v)
        }
    };
    let dest = match out {
        Some(o) => o.to_path_buf(),
        None => {
            let last = w.rsplit(|b| *b == b'/').next().unwrap_or_default();
            if last.is_empty() {
                return Err(err("give -o DIR to restore the whole log"));
            }
            safe_rel(last)?
        }
    };
    if fs::symlink_metadata(&dest).is_ok() {
        return Err(err(format!(
            "{} already exists; restore never overwrites (choose another -o)",
            dest.display()
        )));
    }
    // read + check everything first
    let mut rd = Reader::new(&log, entries, st, opts);
    let mut rep = RestoreReport {
        out: dest.clone(),
        folder,
        ..Default::default()
    };
    let mut data: Vec<(PathBuf, Vec<u8>)> = Vec::new();
    for (full, rel, seq) in picked {
        if let Some(t) = dead(seq) {
            rep.deleted.push((full, seq, t));
            continue;
        }
        let rel_path = if folder {
            safe_rel(&rel)?
        } else {
            PathBuf::new()
        };
        let bytes = rd
            .member(seq)
            .map_err(|e| err(format!("{}: {e}", show_path(&full))))?;
        rep.files
            .push((if folder { rel } else { full }, seq, bytes.len() as u64));
        data.push((rel_path, bytes));
    }
    if rep.files.is_empty() {
        return Err(err(format!(
            "every file under {} is deleted; nothing to restore",
            show_path(&w)
        )));
    }
    // write to a temporary sibling, then rename into place
    let tmp = tmp_beside(&dest)?;
    let res = (|| -> Result<()> {
        if folder {
            for (rel, bytes) in &data {
                let f = tmp.join(rel);
                if let Some(parent) = f.parent() {
                    fs::create_dir_all(parent).map_err(io)?;
                }
                fs::write(&f, bytes).map_err(io)?;
            }
            if data.is_empty() {
                fs::create_dir_all(&tmp).map_err(io)?;
            }
        } else if let Some((_, bytes)) = data.first() {
            fs::write(&tmp, bytes).map_err(io)?;
        }
        if fs::symlink_metadata(&dest).is_ok() {
            return Err(err(format!("{} appeared while restoring", dest.display())));
        }
        fs::rename(&tmp, &dest).map_err(io)
    })();
    if let Err(e) = res {
        let _ = if folder {
            fs::remove_dir_all(&tmp)
        } else {
            fs::remove_file(&tmp)
        };
        return Err(e);
    }
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn index_paths_cannot_escape_the_destination() {
        for bad in [
            &b""[..],
            b"/etc/passwd",
            b"../x",
            b"a/../../x",
            b"a/./b",
            b"a//b",
            b"a/",
            b"a\0b",
            b"..",
        ] {
            assert!(safe_rel(bad).is_err(), "{bad:?}");
        }
        assert_eq!(
            safe_rel(b"a/b c/d.txt").ok(),
            Some(PathBuf::from("a").join("b c").join("d.txt"))
        );
        assert_eq!(want_of("."), b"");
        assert_eq!(want_of("/a/b/"), b"a/b");
    }
}
