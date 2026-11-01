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

/// Why a sampled part would not open. Only `Damaged` is evidence of bit-rot; the key
/// causes mean the bytes were never checked.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Cause {
    /// No key was given for an encrypted part.
    KeyNeeded,
    /// A key was given but no key slot accepted it (wrong key, or a member with its own
    /// ward key inside a folder pack).
    WrongKey,
    /// Missing, torn or failed authentication with a key that was accepted (or ambiguous).
    Damaged,
}

impl Cause {
    /// `key-needed`, `wrong-key` or `damaged` (the JSON `cause`).
    pub fn as_str(self) -> &'static str {
        match self {
            Cause::KeyNeeded => "key-needed",
            Cause::WrongKey => "wrong-key",
            Cause::Damaged => "damaged",
        }
    }
}

/// Sort an open error into a cause. Anything not clearly a key refusal is `Damaged`
/// (fail closed: an unknown error never reads as "just a key problem").
pub fn cause_of(why: &str) -> Cause {
    if why.contains("passphrase or --identity required")
        || why.contains("member names are hidden")
        || why.contains("this pack is locked")
    {
        Cause::KeyNeeded
    } else if why.contains("could not unwrap CEK") {
        Cause::WrongKey
    } else {
        Cause::Damaged
    }
}

impl ReadDataReceipt {
    pub fn ok(&self) -> bool {
        self.failed.is_empty()
    }

    /// Every failure is a key refusal (none is damage): the copy was not shown damaged.
    pub fn key_only(&self) -> bool {
        !self.failed.is_empty()
            && self
                .failed
                .iter()
                .all(|(_, w)| cause_of(w) != Cause::Damaged)
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
    read_data_subset_wards(input, pass, identities, &[], percent, offset)
}

/// [`read_data_subset`] with per-file ward passwords (`PATH`, password) for folder pack
/// members locked with their own `--ward` key. Wards are refused for anything else.
pub fn read_data_subset_wards(
    input: &Path,
    pass: Option<&str>,
    identities: &[Identity],
    wards: &[(String, String)],
    percent: f64,
    offset: u64,
) -> Result<ReadDataReceipt> {
    if !wards.is_empty() && !crate::is_dir_pack(input) {
        return Err(Error::Msg(
            "--ward-file is for members of a folder pack; this is not one".into(),
        ));
    }
    if input.is_dir() {
        return Err(Error::Msg(
            "--read-data is for one .sg1 or a large-file pack, not a folder".into(),
        ));
    }
    if crate::is_dir_pack(input) {
        return read_dir_pack(input, pass, identities, wards, percent, offset);
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

/// Counts plain bytes without keeping them.
struct Count(u64);
impl std::io::Write for Count {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.0 += b.len() as u64;
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

/// Deep-read sampled members of a constellation (folder, card or `.sigil` container).
/// Each member is a part: its star file (or bytes packed in the card) is opened to the
/// original bytes and dropped. A locked card needs its key first; an atlas bag is refused.
pub fn read_constellation(
    input: &Path,
    pass: Option<&str>,
    identities: &[Identity],
    percent: f64,
    offset: u64,
) -> Result<ReadDataReceipt> {
    let resolved = crate::container::sky_for_read(input);
    let input = resolved.as_path();
    if crate::is_atlas_file(input) {
        return Err(Error::Msg(
            "--read-data on an atlas bag is not supported yet: verify the constellation folder it was packed from (plain `verify` still checks the bag)".into(),
        ));
    }
    let (chart, dir) = crate::constellation::load_chart_keys(input, pass, identities)?;
    let card = if input.is_dir() {
        crate::constellation::find_card(input)
    } else if crate::is_constellation_mark(input) {
        Some(input.to_path_buf())
    } else {
        crate::constellation::find_card(&dir)
    };
    let by_digest = crate::constellation::index_stars(&dir, card.as_deref());
    let n = u32::try_from(chart.members.len())
        .map_err(|_| Error::Msg("constellation has too many members".into()))?;
    let picks = pick_parts(n, percent, offset);
    let mut r = ReadDataReceipt {
        kind: "constellation",
        percent,
        offset,
        total_parts: n,
        checked: Vec::new(),
        bytes_read: 0,
        failed: Vec::new(),
        skipped: Vec::new(),
    };
    for i in picks {
        let Some(m) = chart.members.get(i as usize) else {
            continue;
        };
        r.checked.push(i);
        let mut sink = Count(0);
        let opened = if !m.bytes.is_empty() {
            if m.bytes.starts_with(&crate::work::WORK_MAGIC) {
                crate::work::unseal_bytes_into(&m.bytes, &mut sink, pass, &[], identities)
                    .map(|_| ())
            } else {
                crate::unseal_ex_keys(&m.bytes, pass, &[], identities).map(|p| {
                    sink.0 = p.len() as u64;
                })
            }
        } else {
            match crate::constellation::find_member_star(&dir, m, &by_digest) {
                None => Err(Error::Msg("star missing".into())),
                Some(star) => {
                    crate::work::unseal_path_into(&star, &mut sink, pass, &[], identities)
                        .map(|_| ())
                }
            }
        };
        match opened {
            Ok(()) => r.bytes_read += sink.0,
            Err(e) => r.failed.push((i, format!("{}: {e}", m.name))),
        }
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
    wards: &[(String, String)],
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
        // A warded member opens with its own password (as `unseal --ward-file` does).
        let ward_pw = wards
            .iter()
            .find(|(p, _)| p.trim().trim_start_matches("./") == s.path)
            .map(|(_, w)| w.as_str());
        let (key, ids): (Option<&str>, &[Identity]) = match ward_pw {
            Some(w) => (Some(w), &[]),
            None => (pass, identities),
        };
        let opened = if s.star.starts_with(&crate::work::WORK_MAGIC) {
            let mut v = Vec::new();
            crate::work::unseal_bytes_into(&s.star, &mut v, key, &[], ids).map(|_| v)
        } else {
            crate::unseal_ex_keys(&s.star, key, &[], ids)
        };
        match opened {
            Ok(plain) => r.bytes_read += plain.len() as u64,
            Err(e) => {
                let why = e.to_string();
                let ward = ward_pw.is_none()
                    && (pass.is_some() || !identities.is_empty())
                    && cause_of(&why) == Cause::WrongKey;
                let why = if ward_pw.is_some() && cause_of(&why) == Cause::WrongKey {
                    format!(
                        "{}: {why} (the --ward-file password did not open it)",
                        s.path
                    )
                } else if ward {
                    format!(
                        "{}: {why} (this member may be locked with its own --ward key; give --ward-file {}=PWFILE)",
                        s.path, s.path
                    )
                } else {
                    format!("{}: {why}", s.path)
                };
                r.failed.push((*i, why));
            }
        }
    }
    Ok(r)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn causes_fail_closed() {
        assert_eq!(
            cause_of("passphrase or --identity required"),
            Cause::KeyNeeded
        );
        assert_eq!(
            cause_of("a.txt: could not unwrap CEK — need matching --identity or passphrase"),
            Cause::WrongKey
        );
        assert_eq!(cause_of("part missing"), Cause::Damaged);
        assert_eq!(
            cause_of("wrong passphrase/identity, label edited, or past repair"),
            Cause::Damaged
        );
        assert_eq!(cause_of(""), Cause::Damaged);
    }

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
