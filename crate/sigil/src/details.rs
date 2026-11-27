//! File details in a Tome: per-file permissions and modified times, and the empty
//! folders of the packed tree.
//!
//! Written by default inside the protected or Warded body of a Tome (head versions 4
//! and 5), in front of the folder list:
//!
//! `SGMT | fmt u8 (1) | len u32 | files u32 | folders u32 | files x detail |
//!  folders x (detail | name_len u16 | name)`, where `detail` is
//! `mode u32 | secs i64 | nanos u32` (16 bytes) and `len` counts every byte after it.
//!
//! The block is inside the body, so it has the body's repair data and checks (and, in a
//! Warded Tome, its encryption). `files` details are in folder-list order. A block with
//! another `fmt`, or larger than [`MAX_LEN`], is skipped whole (its `len` is honoured)
//! and the files are restored without details: a newer or oversized block never stops
//! a restore. Builds made before details existed refuse head versions 4 and 5 ("unknown
//! Tome version"), so they never restore such a Tome half-understood.
//!
//! Restore applies details safely: the permission bits are limited by the process
//! umask and never include set-user-ID, set-group-ID or sticky unless the caller asks
//! for exact modes; folder names are checked like member names; nothing is applied
//! through a symbolic link. On Windows only modified times are applied.

use crate::Result;
use std::fs;
use std::io::Read;
use std::path::Path;
use std::time::{Duration, SystemTime, UNIX_EPOCH};

pub(crate) const MAGIC: [u8; 4] = *b"SGMT";
/// The details format this build writes and reads.
pub(crate) const FMT: u8 = 1;
/// Largest details block read; a larger one is skipped (about 16 million files).
pub(crate) const MAX_LEN: u64 = 256 * 1024 * 1024;
/// Bytes of one detail record.
const DETAIL_LEN: usize = 16;

fn io(e: std::io::Error) -> crate::Error {
    crate::Error::Msg(e.to_string())
}

/// Permissions and modified time of one file or folder.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub struct FileDetail {
    /// Unix mode bits (permission, set-ID and sticky bits; no file type). 0 on Windows.
    pub mode: u32,
    /// Modified time: seconds since 1970-01-01 UTC (negative before it).
    pub secs: i64,
    /// Nanoseconds within `secs` (below 1e9; anything else means "no time").
    pub nanos: u32,
}

impl FileDetail {
    /// Details of an existing path (links followed, as the folder walk does).
    pub(crate) fn of(meta: &fs::Metadata) -> FileDetail {
        let (secs, nanos) = match meta.modified() {
            Ok(t) => match t.duration_since(UNIX_EPOCH) {
                Ok(d) => (i64::try_from(d.as_secs()).unwrap_or(i64::MAX), d.subsec_nanos()),
                Err(e) => {
                    let d = e.duration();
                    // Before 1970: floor to whole seconds below, nanos counted upward.
                    let s = i64::try_from(d.as_secs()).unwrap_or(i64::MAX);
                    if d.subsec_nanos() == 0 {
                        (-s, 0)
                    } else {
                        (-s - 1, 1_000_000_000 - d.subsec_nanos())
                    }
                }
            },
            Err(_) => (0, u32::MAX),
        };
        FileDetail {
            mode: mode_of(meta),
            secs,
            nanos,
        }
    }

    /// The modified time, when one was stored.
    pub fn modified(&self) -> Option<SystemTime> {
        if self.nanos >= 1_000_000_000 {
            return None;
        }
        if self.secs >= 0 {
            UNIX_EPOCH.checked_add(Duration::new(self.secs as u64, self.nanos))
        } else {
            UNIX_EPOCH
                .checked_sub(Duration::from_secs(self.secs.unsigned_abs()))?
                .checked_add(Duration::from_nanos(u64::from(self.nanos)))
        }
    }

    fn put(&self, out: &mut Vec<u8>) {
        out.extend_from_slice(&self.mode.to_le_bytes());
        out.extend_from_slice(&self.secs.to_le_bytes());
        out.extend_from_slice(&self.nanos.to_le_bytes());
    }

    fn get(b: &[u8]) -> Option<FileDetail> {
        if b.len() < DETAIL_LEN {
            return None;
        }
        Some(FileDetail {
            mode: u32::from_le_bytes(b[0..4].try_into().ok()?),
            secs: i64::from_le_bytes(b[4..12].try_into().ok()?),
            nanos: u32::from_le_bytes(b[12..16].try_into().ok()?),
        })
    }
}

#[cfg(unix)]
fn mode_of(meta: &fs::Metadata) -> u32 {
    use std::os::unix::fs::PermissionsExt;
    meta.permissions().mode() & 0o7777
}

#[cfg(not(unix))]
fn mode_of(_meta: &fs::Metadata) -> u32 {
    0
}

/// An empty folder kept in a Tome (relative path, `/` separators).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct EmptyFolder {
    pub rel: String,
    pub detail: FileDetail,
}

/// Every file detail of one Tome.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct Details {
    /// One per member, in folder-list order.
    pub files: Vec<FileDetail>,
    /// Folders with nothing stored under them.
    pub folders: Vec<EmptyFolder>,
}

/// What reading a details block found.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Found {
    /// No details block: a Tome written without details.
    None,
    /// A block this build reads.
    Read(Details),
    /// A block skipped whole (newer format, or larger than [`MAX_LEN`]): why.
    Skipped(String),
}

impl Found {
    pub(crate) fn details(&self) -> Option<&Details> {
        match self {
            Found::Read(d) => Some(d),
            _ => None,
        }
    }
}

/// The block as written in front of a body's folder list.
pub(crate) fn encode(d: &Details) -> Result<Vec<u8>> {
    let mut body = Vec::with_capacity(8 + d.files.len() * DETAIL_LEN);
    let files = u32::try_from(d.files.len())
        .map_err(|_| crate::Error::Msg("too many files for one Tome".into()))?;
    let folders = u32::try_from(d.folders.len())
        .map_err(|_| crate::Error::Msg("too many empty folders for one Tome".into()))?;
    body.extend_from_slice(&files.to_le_bytes());
    body.extend_from_slice(&folders.to_le_bytes());
    for f in &d.files {
        f.put(&mut body);
    }
    for e in &d.folders {
        let nb = e.rel.as_bytes();
        let nlen = u16::try_from(nb.len())
            .map_err(|_| crate::Error::Msg("an empty folder's path is too long for a Tome".into()))?;
        e.detail.put(&mut body);
        body.extend_from_slice(&nlen.to_le_bytes());
        body.extend_from_slice(nb);
    }
    let len = u32::try_from(body.len())
        .map_err(|_| crate::Error::Msg("file details too large for one Tome".into()))?;
    if u64::from(len) > MAX_LEN {
        return Err(crate::Error::Msg("file details too large for one Tome".into()));
    }
    let mut out = Vec::with_capacity(9 + body.len());
    out.extend_from_slice(&MAGIC);
    out.push(FMT);
    out.extend_from_slice(&len.to_le_bytes());
    out.extend_from_slice(&body);
    Ok(out)
}

/// Parse the bytes after `len` (`files | folders | ...`), `count` members expected.
fn parse(b: &[u8], count: u32) -> std::result::Result<Details, String> {
    if b.len() < 8 {
        return Err("details block too short".into());
    }
    let files = u32::from_le_bytes([b[0], b[1], b[2], b[3]]);
    let folders = u32::from_le_bytes([b[4], b[5], b[6], b[7]]);
    if files != count {
        return Err(format!(
            "details block lists {files} files, the folder list {count}"
        ));
    }
    let need = (files as usize)
        .checked_mul(DETAIL_LEN)
        .and_then(|n| n.checked_add(8))
        .filter(|&n| n <= b.len())
        .ok_or("details block cut short")?;
    let mut off = 8usize;
    let mut out = Details {
        files: Vec::with_capacity(files as usize),
        folders: Vec::new(),
    };
    while off < need {
        if out.files.len() % 65_536 == 0 && crate::repair_ctl::stop_requested() {
            return Err("stopped (Ctrl-C)".into());
        }
        out.files
            .push(FileDetail::get(&b[off..]).ok_or("details block cut short")?);
        off += DETAIL_LEN;
    }
    for i in 0..folders {
        if i % 65_536 == 0 && crate::repair_ctl::stop_requested() {
            return Err("stopped (Ctrl-C)".into());
        }
        let detail = FileDetail::get(&b[off.min(b.len())..]).ok_or("details block cut short")?;
        off += DETAIL_LEN;
        if off + 2 > b.len() {
            return Err("details block cut short".into());
        }
        let nlen = u16::from_le_bytes([b[off], b[off + 1]]) as usize;
        off += 2;
        if off + nlen > b.len() {
            return Err("details block cut short".into());
        }
        let rel = std::str::from_utf8(&b[off..off + nlen])
            .map_err(|_| "an empty folder name is not valid UTF-8".to_string())?
            .to_string();
        off += nlen;
        out.folders.push(EmptyFolder { rel, detail });
    }
    if off != b.len() {
        return Err("details block has bytes after its last record".into());
    }
    Ok(out)
}

/// Read the start of a body's plaintext: an optional details block, then the folder
/// list's 9-byte head (`SGDR | 1 | count`). `count` is the Tome's member count. Reads
/// exactly the block's bytes, so `r` is left at the first member either way.
pub(crate) fn read_start(r: &mut dyn Read, count: u32) -> Result<(Found, [u8; 9])> {
    let mut first = [0u8; 4];
    r.read_exact(&mut first).map_err(io)?;
    let mut head = [0u8; 9];
    if first != MAGIC {
        head[..4].copy_from_slice(&first);
        r.read_exact(&mut head[4..]).map_err(io)?;
        return Ok((Found::None, head));
    }
    let mut fl = [0u8; 5];
    r.read_exact(&mut fl).map_err(io)?;
    let fmt = fl[0];
    let len = u64::from(u32::from_le_bytes([fl[1], fl[2], fl[3], fl[4]]));
    let found = if fmt != FMT || len > MAX_LEN {
        let skipped = copy_to_sink(r, len)?;
        if skipped != len {
            return Err(crate::Error::Msg("Tome body cut short inside its file details".into()));
        }
        Found::Skipped(if fmt != FMT {
            format!("file details in format {fmt}, newer than this sigil reads")
        } else {
            "file details block larger than this sigil reads".into()
        })
    } else {
        let mut b = Vec::new();
        r.take(len).read_to_end(&mut b).map_err(io)?;
        if b.len() as u64 != len {
            return Err(crate::Error::Msg("Tome body cut short inside its file details".into()));
        }
        crate::repair_ctl::check()?;
        match parse(&b, count) {
            Ok(d) => Found::Read(d),
            Err(why) => Found::Skipped(why),
        }
    };
    r.read_exact(&mut head).map_err(io)?;
    Ok((found, head))
}

fn copy_to_sink(r: &mut dyn Read, len: u64) -> Result<u64> {
    let mut buf = vec![0u8; 64 * 1024];
    let mut left = len;
    while left > 0 {
        crate::repair_ctl::check()?;
        let want = usize::try_from(left.min(buf.len() as u64)).unwrap_or(buf.len());
        let n = match r.read(&mut buf[..want]) {
            Ok(0) => break,
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(io(e)),
        };
        left -= n as u64;
    }
    Ok(len - left)
}

/// Split an in-memory body plaintext: remove a leading details block (if any) from
/// `inner`, leaving the folder list at its start.
pub(crate) fn split(inner: &mut Vec<u8>, count: u32) -> Result<Found> {
    if inner.len() < 4 || inner[0..4] != MAGIC {
        return Ok(Found::None);
    }
    let mut cur = std::io::Cursor::new(&inner[..]);
    let (found, _) = read_start(&mut cur, count)?;
    let start = usize::try_from(cur.position()).unwrap_or(inner.len()).saturating_sub(9);
    inner.drain(..start);
    Ok(found)
}

/// Byte length of the details block at the start of `head` (0 when there is none);
/// `None` when `head` is too short to say.
pub(crate) fn block_len(head: &[u8]) -> Option<u64> {
    if head.len() < 4 || head[0..4] != MAGIC {
        return Some(0);
    }
    if head.len() < 9 {
        return None;
    }
    Some(9 + u64::from(u32::from_le_bytes([head[5], head[6], head[7], head[8]])))
}

/// How restore applies details.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct RestoreOpts {
    /// Apply stored modes exactly, set-user-ID, set-group-ID and sticky bits included,
    /// and without the umask limit. Off by default.
    pub exact_modes: bool,
}

/// The mode a restored file gets: the stored permission bits limited by what the
/// process umask allows (read on `created`, the mode a new file got from it), with the
/// set-ID and sticky bits dropped; or the stored mode exactly with `exact`.
pub fn restore_mode(stored: u32, created: u32, exact: bool) -> u32 {
    if exact {
        return stored & 0o7777;
    }
    let created = created & 0o777;
    // The umask's read bits decide execute too: a class that may read may execute.
    let allowed = created | ((created & 0o444) >> 2);
    stored & 0o777 & allowed
}

/// Apply `d` to an open file the restore just wrote. Best effort: a file system that
/// keeps no permissions or times leaves the file as written.
pub(crate) fn apply_to_file(f: &fs::File, d: &FileDetail, opts: RestoreOpts) {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(m) = f.metadata() {
            let mode = restore_mode(d.mode, m.permissions().mode(), opts.exact_modes);
            let _ = f.set_permissions(fs::Permissions::from_mode(mode));
        }
    }
    #[cfg(not(unix))]
    let _ = opts;
    if let Some(t) = d.modified() {
        let _ = f.set_modified(t);
    }
}

/// Apply `d` to a folder this restore created at `dir` (never through a link).
pub(crate) fn apply_to_dir(dir: &Path, d: &FileDetail, opts: RestoreOpts) {
    match fs::symlink_metadata(dir) {
        Ok(m) if m.is_dir() => {}
        _ => return,
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        if let Ok(m) = fs::symlink_metadata(dir) {
            let mode = restore_mode(d.mode, m.permissions().mode(), opts.exact_modes);
            let _ = fs::set_permissions(dir, fs::Permissions::from_mode(mode));
        }
    }
    #[cfg(not(unix))]
    let _ = opts;
    if let Some(t) = d.modified() {
        if let Ok(f) = fs::File::open(dir) {
            let _ = f.set_modified(t);
        }
    }
}

/// A stored empty-folder path is safe to create under the output folder: valid name
/// rules of member names, and no `.`, `..` or absolute part.
pub(crate) fn safe_folder(rel: &str) -> bool {
    crate::tome_guard::bad_name(rel.as_bytes()).is_none()
        && !Path::new(rel).is_absolute()
        && !rel.contains('\\')
        && rel.split('/').all(|p| p != "." && p != "..")
}

#[cfg(test)]
mod tests {
    use super::*;

    fn d(mode: u32, secs: i64, nanos: u32) -> FileDetail {
        FileDetail { mode, secs, nanos }
    }

    #[test]
    fn round_trip_and_split() {
        let det = Details {
            files: vec![d(0o600, 981_173_106, 5), d(0o755, -10, 999_999_999)],
            folders: vec![EmptyFolder {
                rel: "a/empty".into(),
                detail: d(0o700, 1, 0),
            }],
        };
        let mut v = encode(&det).unwrap();
        v.extend_from_slice(b"SGDR\x01\x02\x00\x00\x00rest");
        let found = split(&mut v, 2).unwrap();
        assert_eq!(found, Found::Read(det));
        assert_eq!(&v[..], b"SGDR\x01\x02\x00\x00\x00rest");
        assert_eq!(block_len(b"SGDR\x01"), Some(0));
    }

    #[test]
    fn mismatched_count_or_newer_format_is_skipped_not_fatal() {
        let det = Details {
            files: vec![d(0o644, 0, 0)],
            folders: vec![],
        };
        let mut v = encode(&det).unwrap();
        v.extend_from_slice(b"SGDR\x01\x02\x00\x00\x00");
        let mut w = v.clone();
        assert!(matches!(split(&mut w, 2).unwrap(), Found::Skipped(_)));
        assert_eq!(&w[..4], b"SGDR");
        v[4] = 9;
        assert!(matches!(split(&mut v, 1).unwrap(), Found::Skipped(_)));
        assert_eq!(&v[..4], b"SGDR");
    }

    #[test]
    fn cut_short_block_is_an_error() {
        let det = Details {
            files: vec![d(0o644, 0, 0)],
            folders: vec![],
        };
        let v = encode(&det).unwrap();
        let mut cur = std::io::Cursor::new(&v[..v.len() - 3]);
        assert!(read_start(&mut cur, 1).is_err());
    }

    #[test]
    fn restore_mode_limits_by_umask_and_drops_special_bits() {
        // umask 022: a new file is 0644.
        assert_eq!(restore_mode(0o4755, 0o644, false), 0o755);
        assert_eq!(restore_mode(0o600, 0o644, false), 0o600);
        assert_eq!(restore_mode(0o777, 0o644, false), 0o755);
        assert_eq!(restore_mode(0o1777, 0o644, false), 0o755);
        // umask 077: a new file is 0600.
        assert_eq!(restore_mode(0o755, 0o600, false), 0o700);
        // Exact: everything stored, nothing limited.
        assert_eq!(restore_mode(0o6755, 0o600, true), 0o6755);
    }

    #[test]
    fn folder_names_are_checked() {
        assert!(safe_folder("a/b"));
        assert!(safe_folder(".git/refs"));
        for bad in ["", "/etc", "a/../b", "..", "./a", "a//b", "a\\b"] {
            assert!(!safe_folder(bad), "{bad}");
        }
    }

    #[test]
    fn times_before_1970_and_missing_times() {
        let t = d(0, -1, 500_000_000).modified().unwrap();
        assert_eq!(
            UNIX_EPOCH.duration_since(t).unwrap(),
            Duration::from_millis(500)
        );
        assert!(d(0, 0, u32::MAX).modified().is_none());
    }
}
