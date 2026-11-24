//! `sigil log add --cache`: an opt-in sidecar (`ADDCACHE` in the log folder) that remembers, per
//! path, the file system stamp (size, mtime, ctime, inode) a file had when its bytes were last found
//! equal to the latest version in the log. A later `add --cache` skips hashing a file whose stamp is
//! unchanged and whose latest version is still that same entry (seq + SHA-256).
//!
//! It is a speed-up, **not** a cryptographic check: content can change without the stamp changing
//! (tools that restore mtimes, coarse file systems, clock games). So:
//! * a stamp only counts if it was at least [`RACY_NS`] older than the cache write (a file written
//!   in the same moment as the scan could change again within the timestamp resolution);
//! * any difference in size, mtime, ctime or inode, a different latest seq/SHA, a cache for another
//!   source folder, or an unreadable / malformed cache means: hash the file as without the cache;
//! * a file that is sealed is always read and hashed in full; the INDEX gets its real SHA-256.
//! * private INDEX logs refuse `--cache` (the cache would show names and sizes in clear).

use std::collections::BTreeMap;
use std::fs;
use std::path::Path;

use super::*;

/// The sidecar's file name inside the log folder.
pub const ADD_CACHE_FILE: &str = "ADDCACHE";
const MAGIC: &str = "sigil-add-cache=1";
/// Stamps younger than this at cache-write time are not trusted (2 s).
pub const RACY_NS: i128 = 2_000_000_000;

/// What the file system says about a file: equal stamps are taken as "not rewritten".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Stamp {
    pub size: u64,
    pub mtime_ns: i128,
    pub ctime_ns: i128,
    pub ino: u64,
}

impl Stamp {
    pub fn of(md: &fs::Metadata) -> Option<Stamp> {
        #[cfg(unix)]
        {
            use std::os::unix::fs::MetadataExt;
            Some(Stamp {
                size: md.len(),
                mtime_ns: i128::from(md.mtime()) * 1_000_000_000 + i128::from(md.mtime_nsec()),
                ctime_ns: i128::from(md.ctime()) * 1_000_000_000 + i128::from(md.ctime_nsec()),
                ino: md.ino(),
            })
        }
        #[cfg(not(unix))]
        {
            let t = md.modified().ok()?;
            let d = t.duration_since(std::time::UNIX_EPOCH).ok()?;
            Some(Stamp {
                size: md.len(),
                mtime_ns: d.as_nanos() as i128,
                ctime_ns: 0,
                ino: 0,
            })
        }
    }
}

/// One remembered file: its stamp and the version (seq, SHA-256) its bytes matched.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct CacheHit {
    pub stamp: Stamp,
    pub seq: u64,
    pub sha: [u8; 32],
}

/// The loaded cache (empty when absent, for another source, or unreadable).
#[derive(Debug, Default)]
pub struct AddCache {
    pub entries: BTreeMap<Vec<u8>, CacheHit>,
    /// Why the file on disk was ignored, if it was (for a note).
    pub ignored: Option<String>,
}

fn now_ns() -> i128 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_nanos() as i128)
        .unwrap_or(0)
}

fn src_tag(src: &Path) -> String {
    hex::encode(src.to_string_lossy().as_bytes())
}

impl AddCache {
    /// Load `ADDCACHE` for source folder `src` (canonical). Never fails: problems mean "no cache".
    pub fn load(dir: &Path, src: &Path) -> AddCache {
        let p = dir.join(ADD_CACHE_FILE);
        let text = match fs::read_to_string(&p) {
            Ok(t) => t,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return AddCache::default(),
            Err(e) => return AddCache::ignored(format!("unreadable ({e})")),
        };
        match Self::parse(&text, src) {
            Ok(c) => c,
            Err(why) => AddCache::ignored(why),
        }
    }

    fn ignored(why: String) -> AddCache {
        AddCache {
            entries: BTreeMap::new(),
            ignored: Some(why),
        }
    }

    fn parse(text: &str, src: &Path) -> std::result::Result<AddCache, String> {
        let mut lines = text.lines();
        let head = lines.next().unwrap_or_default();
        let f: Vec<&str> = head.split(' ').collect();
        let get = |k: &str| {
            f.iter()
                .find_map(|x| x.strip_prefix(k).and_then(|v| v.strip_prefix('=')))
        };
        if f.first() != Some(&MAGIC) {
            return Err("not a sigil add cache".into());
        }
        if get("src") != Some(src_tag(src).as_str()) {
            return Ok(AddCache::ignored("made for another source folder".into()));
        }
        let written: i128 = get("written")
            .and_then(|v| v.parse().ok())
            .ok_or("bad header")?;
        let mut entries = BTreeMap::new();
        for (n, l) in lines.enumerate() {
            let bad = || format!("line {} malformed", n + 2);
            let v: Vec<&str> = l.split(' ').collect();
            if v.len() != 7 {
                return Err(bad());
            }
            let path = hex::decode(v[0]).map_err(|_| bad())?;
            let num = |s: &str| s.parse::<i128>().map_err(|_| bad());
            let stamp = Stamp {
                size: v[2].parse().map_err(|_| bad())?,
                mtime_ns: num(v[3])?,
                ctime_ns: num(v[4])?,
                ino: v[5].parse().map_err(|_| bad())?,
            };
            let hit = CacheHit {
                stamp,
                seq: v[1].parse().map_err(|_| bad())?,
                sha: parse_hex32(v[6]).ok_or_else(bad)?,
            };
            // racy: changed too close to the cache write to trust the stamp
            if stamp.mtime_ns >= written - RACY_NS || stamp.ctime_ns >= written - RACY_NS {
                continue;
            }
            entries.insert(path, hit);
        }
        Ok(AddCache {
            entries,
            ignored: None,
        })
    }

    /// `true` when `path` with `stamp` is remembered as matching exactly version (`seq`, `sha`).
    pub fn fresh(&self, path: &[u8], stamp: Option<Stamp>, seq: u64, sha: &[u8; 32]) -> bool {
        match (self.entries.get(path), stamp) {
            (Some(h), Some(s)) => h.stamp == s && h.seq == seq && h.sha == *sha,
            _ => false,
        }
    }

    /// Write the cache (owner-only, temp + rename). Stamps are those taken before reading.
    pub fn save(dir: &Path, src: &Path, rows: &BTreeMap<Vec<u8>, CacheHit>) -> Result<()> {
        let mut s = format!("{MAGIC} written={} src={}\n", now_ns(), src_tag(src));
        for (p, h) in rows {
            s.push_str(&format!(
                "{} {} {} {} {} {} {}\n",
                hex::encode(p),
                h.seq,
                h.stamp.size,
                h.stamp.mtime_ns,
                h.stamp.ctime_ns,
                h.stamp.ino,
                hex::encode(h.sha)
            ));
        }
        let fin = dir.join(ADD_CACHE_FILE);
        let tmp = dir.join(format!("{ADD_CACHE_FILE}.part"));
        let mut o = fs::OpenOptions::new();
        o.write(true).create(true).truncate(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        {
            use std::io::Write;
            let mut f = o.open(&tmp).map_err(io)?;
            f.write_all(s.as_bytes()).map_err(io)?;
            f.sync_all().map_err(io)?;
        }
        fs::rename(&tmp, &fin).map_err(io)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn st(m: i128) -> Stamp {
        Stamp {
            size: 3,
            mtime_ns: m,
            ctime_ns: m,
            ino: 7,
        }
    }

    #[test]
    fn parse_rejects_and_racy() {
        let src = Path::new("/x");
        let old = st(1_000);
        let row = |s: Stamp| {
            format!(
                "{} 4 {} {} {} {} {}\n",
                hex::encode("a"),
                s.size,
                s.mtime_ns,
                s.ctime_ns,
                s.ino,
                hex::encode([9u8; 32])
            )
        };
        let w = 10 * RACY_NS;
        let ok = format!("{MAGIC} written={w} src={}\n{}", src_tag(src), row(old));
        let c = AddCache::parse(&ok, src).unwrap_or_default();
        assert!(c.fresh(b"a", Some(old), 4, &[9; 32]));
        assert!(!c.fresh(b"a", Some(st(1_001)), 4, &[9; 32]));
        assert!(!c.fresh(b"a", Some(old), 5, &[9; 32]));
        assert!(!c.fresh(b"a", Some(old), 4, &[8; 32]));
        assert!(!c.fresh(b"a", None, 4, &[9; 32]));
        let racy = format!(
            "{MAGIC} written={w} src={}\n{}",
            src_tag(src),
            row(st(w - 1))
        );
        assert!(AddCache::parse(&racy, src)
            .unwrap_or_default()
            .entries
            .is_empty());
        assert!(AddCache::parse(&ok, Path::new("/y"))
            .unwrap_or_default()
            .entries
            .is_empty());
        assert!(AddCache::parse(&format!("{ok}junk\n"), src).is_err());
        assert!(AddCache::parse("nope\n", src).is_err());
    }
}
