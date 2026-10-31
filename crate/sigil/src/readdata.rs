//! `sigil verify --read-data-subset P`: open a sampled share of a mark's parts all the
//! way to the original bytes (decrypt + true-name check), not just headers.
//!
//! Sampling is evenly spaced and rolling: the start offset moves each day, so repeated
//! runs at 10% cover every part in about ten days (like restic `--read-data-subset`).
use std::path::Path;

use crate::keys::Identity;
use crate::{Error, Result};

/// What a deep read looked at, and what it found.
#[derive(Debug, Clone)]
pub struct ReadDataReceipt {
    /// `"sg1"` (one part), `"work"` (large-file pack) or `"folder"` (folder pack member).
    pub kind: &'static str,
    pub percent: f64,
    pub offset: u64,
    pub total_parts: u32,
    /// Part numbers opened, in order.
    pub checked: Vec<u32>,
    pub bytes_read: u64,
    /// Part number and why it would not open.
    pub failed: Vec<(u32, String)>,
    /// Folder pack: picked members not deep-read here (a nested folder pack), with why.
    /// Never counted as opened.
    pub skipped: Vec<(u32, String)>,
}

impl ReadDataReceipt {
    pub fn ok(&self) -> bool {
        self.failed.is_empty()
    }
}

/// Parse `10%`, `10`, or `2.5%` into a percentage in (0, 100].
pub fn parse_subset(v: &str) -> std::result::Result<f64, String> {
    let t = v.trim();
    let t = t.strip_suffix('%').unwrap_or(t).trim();
    let p: f64 = t
        .parse()
        .map_err(|_| format!("--read-data-subset wants a percentage like 10% (got {v:?})"))?;
    if !(p > 0.0 && p <= 100.0) {
        return Err(format!(
            "--read-data-subset must be more than 0% and at most 100% (got {v:?})"
        ));
    }
    Ok(p)
}

/// Which part numbers to open out of `n`: `ceil(n * percent / 100)` of them (at least
/// one), evenly spaced, shifted by `offset`.
pub fn pick_parts(n: u32, percent: f64, offset: u64) -> Vec<u32> {
    if n == 0 {
        return Vec::new();
    }
    let want = ((f64::from(n) * percent / 100.0).ceil() as u64).clamp(1, u64::from(n));
    let n64 = u64::from(n);
    let mut out: Vec<u32> = (0..want)
        .map(|j| ((offset % n64 + j * n64 / want) % n64) as u32)
        .collect();
    out.sort_unstable();
    out.dedup();
    out
}

/// Today's rolling offset (days since 1970).
pub fn rolling_offset() -> u64 {
    std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs() / 86_400)
        .unwrap_or(0)
}

/// Deep-read a sampled subset of a plain `.sg1` or a large-file work pack. Plain bytes
/// are kept in memory only and dropped; nothing is written to disk.
pub fn read_data_subset(
    input: &Path,
    pass: Option<&str>,
    identities: &[Identity],
    percent: f64,
    offset: u64,
) -> Result<ReadDataReceipt> {
    if input.is_dir() {
        return Err(Error::Msg(
            "--read-data is for one .sg1 or a large-file pack, not a folder".into(),
        ));
    }
    if crate::is_dir_pack(input) {
        return read_dir_pack(input, pass, identities, percent, offset);
    }
    if crate::is_work_pack(input) {
        let (head, locs) = crate::index_pack_keys(input, pass, &[], identities)
            .or_else(|_| crate::index_pack(input))?;
        let picks = pick_parts(head.stars, percent, offset);
        let mut r = ReadDataReceipt {
            kind: "work",
            percent,
            offset,
            total_parts: head.stars,
            checked: Vec::new(),
            bytes_read: 0,
            failed: Vec::new(),
            skipped: Vec::new(),
        };
        for i in picks {
            r.checked.push(i);
            match locs.iter().find(|l| l.index == i) {
                None => r.failed.push((i, "part missing".into())),
                Some(loc) => match crate::unseal_star_at_keys(input, loc, pass, &[], identities) {
                    Ok(plain) => r.bytes_read += plain.len() as u64,
                    Err(e) => r.failed.push((i, e.to_string())),
                },
            }
        }
        return Ok(r);
    }
    let data = std::fs::read(input).map_err(|e| Error::Msg(e.to_string()))?;
    let mut r = ReadDataReceipt {
        kind: "sg1",
        percent,
        offset,
        total_parts: 1,
        checked: vec![0],
        bytes_read: 0,
        failed: Vec::new(),
        skipped: Vec::new(),
    };
    match crate::unseal_ex_keys(&data, pass, &[], identities) {
        Ok(plain) => r.bytes_read = plain.len() as u64,
        Err(e) => r.failed.push((0, e.to_string())),
    }
    Ok(r)
}

/// Deep-read sampled members of a folder pack (plain or sealed). Each picked member is
/// opened to its original bytes; a member locked with its own ward key, a wrong key or
/// damage counts as failed (fail closed). Nested folder packs are listed as skipped.
fn read_dir_pack(
    input: &Path,
    pass: Option<&str>,
    identities: &[Identity],
    percent: f64,
    offset: u64,
) -> Result<ReadDataReceipt> {
    let n = crate::folder::dir_member_count(input)?;
    let picks = pick_parts(n, percent, offset);
    let stars = crate::folder::dir_pick_stars(input, pass, identities, &picks)?;
    let mut r = ReadDataReceipt {
        kind: "folder",
        percent,
        offset,
        total_parts: n,
        checked: Vec::new(),
        bytes_read: 0,
        failed: Vec::new(),
        skipped: Vec::new(),
    };
    for i in &picks {
        let Some(s) = stars.iter().find(|s| s.index == *i) else {
            r.failed.push((*i, "member missing".into()));
            continue;
        };
        if s.star.starts_with(&crate::folder::DIR_MAGIC) {
            r.skipped.push((
                *i,
                format!("{}: nested folder pack (verify it on its own)", s.path),
            ));
            continue;
        }
        r.checked.push(*i);
        let opened = if s.star.starts_with(&crate::work::WORK_MAGIC) {
            let mut v = Vec::new();
            crate::work::unseal_bytes_into(&s.star, &mut v, pass, &[], identities).map(|_| v)
        } else {
            crate::unseal_ex_keys(&s.star, pass, &[], identities)
        };
        match opened {
            Ok(plain) => r.bytes_read += plain.len() as u64,
            Err(e) => r.failed.push((*i, format!("{}: {e}", s.path))),
        }
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn subset_parse() {
        assert_eq!(parse_subset("10%"), Ok(10.0));
        assert_eq!(parse_subset("100"), Ok(100.0));
        assert!(parse_subset("0%").is_err());
        assert!(parse_subset("101%").is_err());
        assert!(parse_subset("abc").is_err());
    }

    #[test]
    fn picks_cover_everything_over_rolling_days() {
        assert_eq!(pick_parts(10, 100.0, 3), (0..10).collect::<Vec<_>>());
        assert_eq!(pick_parts(10, 10.0, 0), vec![0]);
        assert_eq!(pick_parts(0, 10.0, 0), Vec::<u32>::new());
        let mut seen = std::collections::BTreeSet::new();
        for day in 0..10 {
            let p = pick_parts(10, 10.0, day);
            assert_eq!(p.len(), 1);
            seen.extend(p);
        }
        assert_eq!(seen.len(), 10);
        assert_eq!(pick_parts(3, 1.0, 7).len(), 1);
    }
}
