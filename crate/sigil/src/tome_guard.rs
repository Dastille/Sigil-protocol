//! Checks that keep a damaged plain-Tome folder list from giving wrong output.
//!
//! A plain Tome stores its folder list in the clear between the members: the member
//! count, then for each member its name length, name and star length. Those bytes have no
//! repair data or checksum of their own (each member star has both). These checks are
//! decoder-only (the layout is unchanged); they turn folder-list damage into a clear
//! refusal, `folder list damaged` (exit 2, nothing written), instead of files restored
//! under a wrong name, one file overwriting another, or members silently left out:
//!
//! * a name no Inscribe writes: empty, not UTF-8, or with an empty folder part;
//! * a name that disagrees with the member's own protected header. A classic member star
//!   keeps the first 16 bytes of the path; the first chunk star of a large-file member
//!   keeps the first 16 bytes of `file-name.0000`. Encrypted stars keep no name in the
//!   clear and are not checked this way (a Warded Tome's list is inside its locked body);
//! * two members with the same name;
//! * another complete member after the last one the count allows (a lowered count);
//! * a stored length that runs past the end of the file while later members are still
//!   there: a damaged length, not a cut-off copy.
//!
//! The header comparison covers only the first 16 bytes of a path (or of a large file's
//! own name); damage further into a long name is caught only when it breaks UTF-8 or
//! makes two names equal.

use crate::packhead::{self, Src};
use crate::Result;

/// Start of every folder-list refusal (exit 2).
pub const LIST_DAMAGED: &str = "folder list damaged";

/// A folder-list refusal.
pub(crate) fn damaged(why: impl std::fmt::Display) -> crate::Error {
    crate::Error::Msg(format!(
        "{LIST_DAMAGED}: {why} (the member data may still be intact)"
    ))
}

/// Why `raw` cannot be a member name any Inscribe wrote, or `None`.
pub(crate) fn bad_name(raw: &[u8]) -> Option<&'static str> {
    let Ok(s) = std::str::from_utf8(raw) else {
        return Some("a member name is not valid UTF-8");
    };
    if s.is_empty() {
        return Some("a member name is empty");
    }
    if s.split('/').any(str::is_empty) {
        return Some("a member name has an empty folder part");
    }
    None
}

/// Bytes of a star enough to read its header (the primary copy or a Keystone copy).
pub(crate) const STAR_PEEK: usize = crate::header::KEYSTONE_SPAN + 64;

/// What a star header keeps of `name`: its first 16 bytes, trailing zero bytes dropped.
pub(crate) fn header_prefix(name: &str) -> String {
    let b = name.as_bytes();
    let cut = &b[..b.len().min(16)];
    let end = cut.iter().rposition(|&x| x != 0).map_or(0, |i| i + 1);
    String::from_utf8_lossy(&cut[..end]).into_owned()
}

/// The name a plain star's protected header carries, when it carries one.
pub(crate) fn header_name(star_head: &[u8]) -> Option<String> {
    let (h, _, _) = crate::locate_header(star_head).ok()?;
    if h.encrypted() || h.private_label() || h.name.is_empty() {
        return None;
    }
    Some(h.name)
}

fn mismatch(rel: &str, header: &str) -> crate::Error {
    damaged(format!(
        "the list names a member '{}', but that member's own header names '{}'",
        crate::shown::name(rel),
        crate::shown::name(header)
    ))
}

/// Check a classic member star (whole, or at least its first [`STAR_PEEK`] bytes)
/// against its folder-list name. A star whose header cannot be read is left to its own
/// checks (it is then damaged, and `sigil mend` reports that).
pub(crate) fn check_classic(rel: &str, star_head: &[u8]) -> Result<()> {
    match header_name(star_head) {
        Some(h) if h != header_prefix(rel) => Err(mismatch(rel, &h)),
        _ => Ok(()),
    }
}

/// Check a large-file member (its whole pack in `src`) against its folder-list name: the
/// first chunk star of a plain pack is named `file-name.0000`. A pack whose layout
/// cannot be read is left to its own checks.
pub(crate) fn check_pack(rel: &str, src: &mut dyn Src) -> Result<()> {
    let mut src = crate::folder::DynSrc(src);
    let Ok(l) = packhead::layout(&mut src) else {
        return Ok(());
    };
    let Some(&(off, len)) = l.stars.first() else {
        return Ok(());
    };
    let mut head = vec![0u8; usize::try_from(len).unwrap_or(usize::MAX).min(STAR_PEEK)];
    if src.read_at(off, &mut head).is_err() {
        return Ok(());
    }
    let Some(h) = header_name(&head) else {
        return Ok(());
    };
    let base = rel.rsplit('/').next().unwrap_or(rel);
    // `file` is the name a pack gets when its file name is not valid UTF-8.
    let ok = [
        format!("{base}.0000"),
        base.to_string(),
        "file.0000".to_string(),
    ]
    .iter()
    .any(|n| header_prefix(n) == h);
    if ok {
        Ok(())
    } else {
        Err(mismatch(rel, &h))
    }
}

/// Check a member star that is either a classic star (`star`) or a large-file pack.
pub(crate) fn check_star_bytes(rel: &str, star: &[u8]) -> Result<()> {
    if star.starts_with(&crate::work::WORK_MAGIC) {
        check_pack(rel, &mut packhead::MemSrc(star))
    } else {
        check_classic(rel, star)
    }
}

/// Refuse a second member with the same name (one would overwrite the other), or a
/// name out of the order Inscribe writes names in.
pub(crate) fn check_unique(seen: &mut ListNames, rel: &str) -> Result<()> {
    if !seen.seen.insert(rel.to_string()) {
        return Err(damaged(format!(
            "two members are both named '{}'",
            crate::shown::name(rel)
        )));
    }
    // Inscribe has always written members depth-first with each folder's entries sorted
    // by name, so the names rise strictly, compared folder part by folder part. A name
    // that breaks that order was damaged. Names with U+FFFD (a file name that was not
    // UTF-8 when sealed) may sort differently, so they restart the comparison.
    let last = seen.last.take();
    if rel.contains('\u{fffd}') {
        return Ok(());
    }
    if let Some(prev) = last {
        if rel.split('/').cmp(prev.split('/')) != std::cmp::Ordering::Greater {
            return Err(damaged(format!(
                "the member '{}' is out of the order Inscribe writes names in (it follows '{}')",
                crate::shown::name(rel),
                crate::shown::name(&prev)
            )));
        }
    }
    seen.last = Some(rel.to_string());
    Ok(())
}

/// Names already read from a folder list, for [`check_unique`].
#[derive(Default)]
pub(crate) struct ListNames {
    seen: std::collections::HashSet<String>,
    last: Option<String>,
}

/// True when a complete member starts at `off` in `src`: a name an Inscribe could
/// write, a star length that fits in the file, and a star whose header (or large-file
/// pack head) parses. Reads at most one name and [`STAR_PEEK`] bytes.
pub(crate) fn member_at<S: Src + ?Sized>(src: &mut S, off: u64) -> bool {
    let size = src.size();
    let mut lb = [0u8; 2];
    if off.checked_add(2).is_none_or(|e| e > size) || src.read_at(off, &mut lb).is_err() {
        return false;
    }
    let nlen = u64::from(u16::from_le_bytes(lb));
    let name_off = off + 2;
    if nlen == 0 || name_off + nlen + 8 > size {
        return false;
    }
    let mut name = vec![0u8; nlen as usize];
    let mut sl = [0u8; 8];
    if src.read_at(name_off, &mut name).is_err()
        || bad_name(&name).is_some()
        || src.read_at(name_off + nlen, &mut sl).is_err()
    {
        return false;
    }
    let star = name_off + nlen + 8;
    let slen = u64::from_le_bytes(sl);
    if slen < 4 || slen > size - star {
        return false;
    }
    let mut head = vec![0u8; usize::try_from(slen).unwrap_or(usize::MAX).min(STAR_PEEK)];
    if src.read_at(star, &mut head).is_err() {
        return false;
    }
    if head.starts_with(&crate::work::WORK_MAGIC) {
        crate::work::read_head(&mut &head[..]).is_ok()
    } else {
        crate::locate_header(&head).is_ok()
    }
}

/// After the last member the count allows, at `off`: refuse when another complete
/// member follows (the count was lowered). Bytes that are not a member are left alone.
pub(crate) fn check_no_member_after<S: Src + ?Sized>(
    src: &mut S,
    off: u64,
    count: u32,
) -> Result<()> {
    if off < src.size() && member_at(src, off) {
        return Err(damaged(format!(
            "the member count says {count}, but another member follows the last one"
        )));
    }
    Ok(())
}

/// Magic at the start of every classic star header.
const STAR_MAGIC: &[u8] = b"SGIL";

/// Longest name the scan in [`later_member`] tries (most paths are far shorter).
const SCAN_NAME: usize = 4096;
/// How far past a member's start [`later_member`] looks.
const SCAN_BYTES: u64 = 64 << 20;
/// Star magics [`later_member`] tries before it stops.
const SCAN_HITS: usize = 4096;
/// CPU-time budget of one [`later_member`] scan.
const SCAN_SECS: u64 = 3;

/// A member whose star (at `start`) claims to run past the end of the file: is a
/// complete member still found after `start`? Then the stored length is wrong (folder
/// list damage), not a cut-off copy. Bounded: at most [`SCAN_BYTES`] past `start`,
/// [`SCAN_HITS`] star magics, names up to [`SCAN_NAME`] bytes, [`SCAN_SECS`] seconds, and
/// Ctrl-C. When a bound is hit the answer is "no" (the copy is reported as cut off,
/// as before).
pub(crate) fn later_member<S: Src + ?Sized>(src: &mut S, start: u64) -> Result<bool> {
    let size = src.size();
    let end = size.min(start.saturating_add(SCAN_BYTES));
    let t0 = std::time::Instant::now();
    let keep = SCAN_NAME + 2 + 8;
    let window = packhead::COPY_WINDOW;
    let mut buf: Vec<u8> = Vec::new();
    let mut buf_off = start;
    let mut next = start;
    let mut hits = 0usize;
    while next < end {
        crate::repair_ctl::check()?;
        if t0.elapsed().as_secs() >= SCAN_SECS {
            return Ok(false);
        }
        let n = usize::try_from((end - next).min(window as u64)).unwrap_or(window);
        let mut chunk = vec![0u8; n];
        if src.read_at(next, &mut chunk).is_err() {
            return Ok(false);
        }
        // Keep the tail of the previous window so a name may straddle the boundary.
        let drop = buf.len().saturating_sub(keep + 3);
        buf.drain(..drop);
        buf_off += drop as u64;
        let scan_from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk);
        next += n as u64;
        let mut i = scan_from;
        while i + 4 <= buf.len() {
            let m = &buf[i..i + 4];
            if m == STAR_MAGIC || m == crate::work::WORK_MAGIC {
                hits += 1;
                if hits > SCAN_HITS {
                    return Ok(false);
                }
                // A member head ends right before its star: u16 name length, name, u64 length.
                for v in 1..=SCAN_NAME.min(i.saturating_sub(10)) {
                    let h = i - 10 - v;
                    if usize::from(u16::from_le_bytes([buf[h], buf[h + 1]])) == v {
                        let at = buf_off + h as u64;
                        if at > start && member_at(src, at) {
                            return Ok(true);
                        }
                    }
                }
            }
            i += 1;
        }
    }
    Ok(false)
}

/// A Tome whose first bytes (`SGDR` and the version) are damaged, so it no longer reads
/// as a Tome: `Some(why)` when its magic is at most two bits away from `SGDR` (or the
/// version byte is unknown) and the rest of the file still has a Tome's shape (a Warded
/// Tome's body length and body, or a plain Tome's first complete member). Other readers
/// would take such a file for a damaged single archive and could call it repairable.
pub fn damaged_tome_head(path: &std::path::Path) -> Option<String> {
    let mut src = packhead::FileSrc::open(path).ok()?;
    let size = src.size();
    let mut head = [0u8; 21];
    if size < head.len() as u64 || src.read_at(0, &mut head).is_err() {
        return None;
    }
    let flips: u32 = head[..4]
        .iter()
        .zip(crate::folder::DIR_MAGIC.iter())
        .map(|(a, b)| (a ^ b).count_ones())
        .sum();
    let known = (1..=3).contains(&head[4]);
    if !((flips == 0 && !known) || (flips > 0 && flips <= 2 && known)) {
        return None;
    }
    let body_len = u64::from_le_bytes(head[9..17].try_into().ok()?);
    let body = &head[17..21];
    let warded = body_len == size - 17 && (body == STAR_MAGIC || body == crate::work::WORK_MAGIC);
    if (warded || member_at(&mut src, 9)) && flips == 0 {
        Some(crate::folder::unknown_version(head[4]))
    } else if warded || member_at(&mut src, 9) {
        Some(
            "Tome head damaged: the first bytes that mark it as a Tome are changed, though the rest still has a Tome's shape"
                .into(),
        )
    } else {
        None
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn names_no_inscribe_writes_are_flagged() {
        assert!(bad_name(b"a/b/c.txt").is_none());
        assert!(bad_name("caf\u{e9}.txt".as_bytes()).is_none());
        assert!(bad_name(b"").is_some());
        assert!(bad_name(b"a//b").is_some());
        assert!(bad_name(b"/abs").is_some());
        assert!(bad_name(b"dir/").is_some());
        assert!(bad_name(&[b'a', 0xff, b'b']).is_some());
    }

    #[test]
    fn header_prefix_is_the_first_sixteen_bytes() {
        assert_eq!(header_prefix("short.txt"), "short.txt");
        assert_eq!(
            header_prefix("level00-folder-with-a-long-name/x"),
            "level00-folder-w"
        );
    }
}
