//! Find the stars of a large-file pack (SGWK), rebuilding a damaged pack head.
//!
//! A work pack is `head | (u64 length, chunk star)* | SGFC facet list` (see
//! `docs/FAIL-CLOSED.md` and `docs/PACK-HEAD-REPAIR.md`). The head and the length
//! framing are not Reed–Solomon coded. Every chunk star is a complete seal with
//! its own protected header (length + SHA-256 of the chunk), and the SGFC list
//! records each chunk's SHA-256 in pack order.
//!
//! [`layout`] first reads the pack exactly as before. Only when that fails, or
//! the head disagrees with the stars and the facet list, does it rebuild the
//! head from evidence that is already in every pack, old or new:
//!
//! * the SGFC list gives the star count and the order (chunk SHA-256s);
//! * the framing must tile the file exactly from some head length up to the list;
//! * each star's own header must carry the listed SHA-256, in that order;
//! * the total size is the sum of the stars' own lengths.
//!
//! Nothing is guessed: a rebuild needs a unique head length at which every star
//! matches the list, otherwise the original error is returned. Reordered or
//! swapped stars never match the list, so they are still refused.

use crate::work::{choose_overture, read_head, WorkHead, DEFAULT_OVERTURE_MB, WORK_MAGIC};
use crate::Result;
use std::fs::File;
use std::io::{Read, Seek, SeekFrom};
use std::path::Path;

/// Longest SGWK head: magic 4, version 1, chunk 4, total 8, name length 1,
/// name 255, stars 4, overture 4.
pub(crate) const MAX_HEAD: u64 = 281;
/// Shortest SGWK head: version 1 (no overture field) with an empty name.
const MIN_HEAD: u64 = 22;
/// Enough of a star to parse its header (CDC star lengths vary).
const PEEK: u64 = (crate::header::KEYSTONE_SPAN + 64) as u64;
/// Bytes of a star's header name (`name.0000` is cut to this many bytes).
const STAR_NAME_BYTES: usize = 16;
/// Smallest possible framed star: a keystone span plus its 8-byte length.
const MIN_STAR: u64 = crate::header::KEYSTONE_SPAN as u64 + 8;
/// Block size for the backward search for the facet list.
const SCAN_BLOCK: u64 = 1 << 20;

fn msg(s: impl Into<String>) -> crate::Error {
    crate::Error::Msg(s.into())
}

/// Random-access bytes: a file on disk or a pack already in memory.
pub(crate) trait Src {
    /// Total length in bytes.
    fn size(&self) -> u64;
    /// Fill `buf` from `off`; an error if that runs past the end.
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<()>;
}

/// A pack held in memory.
pub(crate) struct MemSrc<'a>(pub &'a [u8]);

impl Src for MemSrc<'_> {
    fn size(&self) -> u64 {
        self.0.len() as u64
    }
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<()> {
        let slice = usize::try_from(off)
            .ok()
            .and_then(|a| self.0.get(a..a.checked_add(buf.len())?))
            .ok_or_else(|| msg("read past the end of the pack"))?;
        buf.copy_from_slice(slice);
        Ok(())
    }
}

/// A pack on disk.
pub(crate) struct FileSrc {
    f: File,
    len: u64,
}

impl FileSrc {
    /// Open `path` for random-access reads.
    pub(crate) fn open(path: &Path) -> Result<Self> {
        let f = File::open(path).map_err(|e| msg(e.to_string()))?;
        let len = f.metadata().map_err(|e| msg(e.to_string()))?.len();
        Ok(FileSrc { f, len })
    }
}

impl Src for FileSrc {
    fn size(&self) -> u64 {
        self.len
    }
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<()> {
        if off
            .checked_add(buf.len() as u64)
            .is_none_or(|e| e > self.len)
        {
            return Err(msg("read past the end of the pack"));
        }
        self.f
            .seek(SeekFrom::Start(off))
            .map_err(|e| msg(e.to_string()))?;
        self.f.read_exact(buf).map_err(|e| msg(e.to_string()))
    }
}

/// Where the pack head used for reading came from.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum HeadSource {
    /// The head on disk parsed and agrees with the stars and the facet list.
    Intact,
    /// The head on disk was damaged; it was rebuilt from the SGFC facet list and
    /// the chunk stars' own headers (works for every pack ever written).
    FacetList,
}

/// State of the SGFC facet list at the end of the pack.
pub(crate) enum Trailer {
    /// Nothing after the last star.
    Missing,
    /// A well-formed list with one SHA-256 per star.
    Valid(Vec<[u8; 32]>),
    /// Bytes after the last star that are not a well-formed list for this star count.
    Damaged,
}

/// Where everything in a pack is, with the head to trust.
pub(crate) struct PackLayout {
    /// The head to use (the on-disk one, or the rebuilt one).
    pub head: WorkHead,
    /// That head serialised; a mend writes these bytes.
    pub head_bytes: Vec<u8>,
    /// `(offset, length)` of each star's bytes (after its 8-byte length).
    pub stars: Vec<(u64, u64)>,
    /// Offset of the bytes after the last star.
    pub trailer_off: u64,
    /// The facet list.
    pub trailer: Trailer,
    /// Where `head` came from.
    pub source: HeadSource,
}

impl PackLayout {
    /// The facet SHA-256s when the list is well formed.
    pub(crate) fn facets(&self) -> Option<&[[u8; 32]]> {
        match &self.trailer {
            Trailer::Valid(f) => Some(f),
            _ => None,
        }
    }
}

/// Serialise a head in the current (version 2) layout.
pub(crate) fn head_to_bytes(h: &WorkHead) -> Vec<u8> {
    let nb = h.name.as_bytes();
    let nlen = nb.len().min(255);
    let mut out = Vec::with_capacity(26 + nlen);
    out.extend_from_slice(&WORK_MAGIC);
    out.push(2);
    out.extend_from_slice(&h.chunk_size.to_le_bytes());
    out.extend_from_slice(&h.orig_total.to_le_bytes());
    out.push(nlen as u8);
    out.extend_from_slice(&nb[..nlen]);
    out.extend_from_slice(&h.stars.to_le_bytes());
    out.extend_from_slice(&h.overture.to_le_bytes());
    out
}

fn read_u64<S: Src>(src: &mut S, off: u64) -> Result<u64> {
    let mut b = [0u8; 8];
    src.read_at(off, &mut b)?;
    Ok(u64::from_le_bytes(b))
}

/// Walk `n` length-framed stars from `start`; every star must end by `limit`.
fn tile<S: Src>(src: &mut S, start: u64, n: u32, limit: u64) -> Result<Vec<(u64, u64)>> {
    // `n` is untrusted; every star needs an 8-byte length, so cap the pre-allocation.
    let mut stars = Vec::with_capacity((n as u64).min(limit / 8) as usize);
    let mut off = start;
    for i in 0..n {
        let damaged = || {
            msg(format!(
                "work pack truncated or framing damaged at star {i} of {n} \
                 (length missing or past the end); not RS-coded, refusing"
            ))
        };
        if off.checked_add(8).is_none_or(|e| e > limit) {
            return Err(damaged());
        }
        let len = read_u64(src, off)?;
        let end = (off + 8)
            .checked_add(len)
            .filter(|&e| e <= limit)
            .ok_or_else(damaged)?;
        stars.push((off + 8, len));
        off = end;
    }
    Ok(stars)
}

fn read_trailer<S: Src>(src: &mut S, off: u64, n: u32) -> Result<Trailer> {
    let tlen = src.size().saturating_sub(off);
    if tlen == 0 {
        return Ok(Trailer::Missing);
    }
    if tlen != 8 + 32 * n as u64 {
        return Ok(Trailer::Damaged);
    }
    let mut t = vec![0u8; tlen as usize];
    src.read_at(off, &mut t)?;
    if &t[..4] != b"SGFC" || t[4..8] != n.to_le_bytes() {
        return Ok(Trailer::Damaged);
    }
    Ok(Trailer::Valid(digests(&t[8..])))
}

fn digests(b: &[u8]) -> Vec<[u8; 32]> {
    b.as_chunks::<32>().0.to_vec()
}

/// A star's own header: `(chunk SHA-256, chunk length, header name)`.
fn star_header<S: Src>(src: &mut S, off: u64, len: u64) -> Result<([u8; 32], u64, String)> {
    let mut peek = vec![0u8; len.min(PEEK) as usize];
    src.read_at(off, &mut peek)?;
    if let Ok((h, _, _)) = crate::locate_header(&peek) {
        return Ok((h.digest, h.orig_len, h.name));
    }
    // Primary header and keystone spares gone: embers sit throughout the star.
    let mut star = vec![0u8; len as usize];
    src.read_at(off, &mut star)?;
    let (h, _, _) = crate::locate_header(&star)?;
    Ok((h.digest, h.orig_len, h.name))
}

/// The pack name, when star 0's header name `name.0000` holds all of it.
fn name_from_star0(star0_name: &str) -> Option<String> {
    star0_name.strip_suffix(".0000").map(str::to_string)
}

/// What star 0's header name should be for a pack called `name`.
fn star0_name_for(name: &str) -> String {
    let full = format!("{name}.0000");
    let b = full.as_bytes();
    String::from_utf8_lossy(&b[..b.len().min(STAR_NAME_BYTES)]).into_owned()
}

/// Read the pack as laid out by its head; no repair.
fn strict<S: Src>(src: &mut S) -> Result<PackLayout> {
    let size = src.size();
    let mut hb = vec![0u8; MAX_HEAD.min(size) as usize];
    src.read_at(0, &mut hb)?;
    let mut cur = std::io::Cursor::new(&hb[..]);
    let head = read_head(&mut cur)?;
    let head_len = cur.position();
    let stars = tile(src, head_len, head.stars, size)?;
    let trailer_off = stars.last().map(|&(o, l)| o + l).unwrap_or(head_len);
    let trailer = read_trailer(src, trailer_off, head.stars)?;
    hb.truncate(head_len as usize);
    Ok(PackLayout {
        head,
        head_bytes: hb,
        stars,
        trailer_off,
        trailer,
        source: HeadSource::Intact,
    })
}

/// Find a well-formed SGFC list that ends exactly at the end of the pack.
fn find_facet_list<S: Src>(src: &mut S) -> Result<(u64, Vec<[u8; 32]>)> {
    let size = src.size();
    let none = || msg("no SGFC facet list at the end of the pack");
    if size < MIN_HEAD + 8 + 40 {
        return Err(none());
    }
    // The list for k stars starts at size - 8 - 32k; try k = 1, 2, ... walking back
    // through the file one block at a time.
    let mut block: Vec<u8> = Vec::new();
    let mut block_start = size;
    let mut k: u64 = 1;
    while let Some(p) = size.checked_sub(8 + 32 * k).filter(|&p| p >= MIN_HEAD) {
        // Every star is at least a keystone span plus its 8-byte length, which bounds
        // how long a real list can be (and how far back a non-pack is searched).
        if k > u32::MAX as u64 || k.saturating_mul(32 + MIN_STAR) > size {
            break;
        }
        if p < block_start {
            let end = (p + 8).min(size);
            let start = end.saturating_sub(SCAN_BLOCK);
            block = vec![0u8; (end - start) as usize];
            src.read_at(start, &mut block)?;
            block_start = start;
        }
        let i = (p - block_start) as usize;
        if block.get(i..i + 4) == Some(b"SGFC")
            && block.get(i + 4..i + 8) == Some(&(k as u32).to_le_bytes()[..])
        {
            let mut list = vec![0u8; 32 * k as usize];
            src.read_at(p + 8, &mut list)?;
            return Ok((p, digests(&list)));
        }
        k += 1;
    }
    Err(none())
}

/// A head length that tiles: `(head length, star spans, (chunk length, header name) per star)`.
type Candidate = (u64, Vec<(u64, u64)>, Vec<(u64, String)>);

/// Rebuild the head from the facet list and the stars' own headers.
fn from_facets<S: Src>(src: &mut S) -> Result<PackLayout> {
    let (trailer_off, facets) = find_facet_list(src)?;
    let n = facets.len() as u32;
    let mut found: Option<Candidate> = None;
    for head_len in MIN_HEAD..=MAX_HEAD.min(trailer_off) {
        let Ok(stars) = tile(src, head_len, n, trailer_off) else {
            continue;
        };
        if stars.last().map(|&(o, l)| o + l) != Some(trailer_off) {
            continue;
        }
        let mut hdrs = Vec::with_capacity(stars.len());
        for (i, &(off, len)) in stars.iter().enumerate() {
            match star_header(src, off, len) {
                Ok((d, l, name)) if d == facets[i] => hdrs.push((l, name)),
                _ => break,
            }
        }
        if hdrs.len() != stars.len() {
            continue;
        }
        if found.is_some() {
            return Err(msg(
                "pack head damaged and the stars fit more than one head length; refusing",
            ));
        }
        found = Some((head_len, stars, hdrs));
    }
    let (_, stars, hdrs) = found.ok_or_else(|| {
        msg("pack head damaged and the stars do not match the SGFC facet list; refusing")
    })?;
    let orig_total = hdrs.iter().try_fold(0u64, |a, (l, _)| a.checked_add(*l));
    let orig_total = orig_total.ok_or_else(|| msg("pack star lengths overflow"))?;
    let chunk_size = hdrs
        .iter()
        .map(|(l, _)| *l)
        .max()
        .unwrap_or(0)
        .clamp(64 * 1024, u32::MAX as u64) as u32;
    let name = hdrs
        .first()
        .and_then(|(_, nm)| name_from_star0(nm))
        .unwrap_or_default();
    let head = WorkHead {
        version: 2,
        chunk_size,
        orig_total,
        name,
        stars: n,
        overture: choose_overture(n, orig_total, chunk_size, DEFAULT_OVERTURE_MB),
    };
    Ok(PackLayout {
        head_bytes: head_to_bytes(&head),
        head,
        stars,
        trailer_off,
        trailer: Trailer::Valid(facets),
        source: HeadSource::FacetList,
    })
}

/// A head that parsed and tiled can still carry a wrong total or name. When the
/// facet list is valid and every star's header matches it, those two fields are
/// checked against the stars and corrected. (Chunk size and overture are advisory
/// and cannot be checked from the stars.)
fn cross_check<S: Src>(src: &mut S, l: &mut PackLayout) {
    let Some(facets) = l.facets() else {
        return;
    };
    let mut total = 0u64;
    let mut star0_name = None;
    for (i, &(off, len)) in l.stars.iter().enumerate() {
        match star_header(src, off, len) {
            Ok((d, ln, name)) if d == facets[i] => {
                total = match total.checked_add(ln) {
                    Some(t) => t,
                    None => return,
                };
                if i == 0 {
                    star0_name = Some(name);
                }
            }
            // Swapped stars or an unreadable header: leave it to the readers to refuse.
            _ => return,
        }
    }
    let mut fixed = false;
    if total != l.head.orig_total {
        l.head.orig_total = total;
        fixed = true;
    }
    if let Some(s0) = star0_name {
        if star0_name_for(&l.head.name) != s0 {
            if let Some(name) = name_from_star0(&s0) {
                l.head.name = name;
                fixed = true;
            }
        }
    }
    if fixed {
        l.head.version = 2;
        l.head_bytes = head_to_bytes(&l.head);
        l.source = HeadSource::FacetList;
    }
}

/// Lay out a pack, rebuilding its head when needed (see the module docs).
///
/// Returns the strict reader's error when the head is damaged and cannot be
/// rebuilt, so messages for unrepairable packs are unchanged.
pub(crate) fn layout<S: Src>(src: &mut S) -> Result<PackLayout> {
    match strict(src) {
        Ok(mut l) => {
            if matches!(l.trailer, Trailer::Damaged) {
                // A wrong star count leaves the real list stranded in the "trailer".
                if let Ok(r) = from_facets(src) {
                    return Ok(r);
                }
                return Ok(l);
            }
            cross_check(src, &mut l);
            Ok(l)
        }
        Err(e) => from_facets(src).map_err(|_| e),
    }
}

/// Lay out the pack at `path` (see [`layout`]).
pub(crate) fn layout_path(path: &Path) -> Result<PackLayout> {
    layout(&mut FileSrc::open(path)?)
}

/// Rebuild the layout of bytes that do not start with the SGWK magic but may be
/// a pack whose head is damaged. Only the facet-list rebuild is tried.
pub(crate) fn recover_bytes(bytes: &[u8]) -> Option<PackLayout> {
    from_facets(&mut MemSrc(bytes)).ok()
}

/// Like [`recover_bytes`] for a file on disk.
pub(crate) fn recover_path(path: &Path) -> Option<PackLayout> {
    from_facets(&mut FileSrc::open(path).ok()?).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::work::{mend_pack_path, mend_pack_to, unseal_path_keys};

    const PASS: &str = "fixture pass";

    fn plain() -> Vec<u8> {
        let mut x = 0x2545f4914f6cdd1du64;
        (0..200_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    fn fixture(name: &str) -> Vec<u8> {
        let p = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pack-v0");
        std::fs::read(p.join(name)).unwrap()
    }

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "sigil-packhead-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn head_len(pack: &[u8]) -> usize {
        let mut cur = std::io::Cursor::new(pack);
        read_head(&mut cur).unwrap();
        cur.position() as usize
    }

    /// Unseal `bytes` through the file path; Ok(plain) or Err, never a partial file.
    fn open(dir: &Path, bytes: &[u8], pass: Option<&str>) -> std::result::Result<Vec<u8>, String> {
        let p = dir.join("in.sg1");
        let out = dir.join("out.bin");
        let _ = std::fs::remove_file(&out);
        std::fs::write(&p, bytes).unwrap();
        match unseal_path_keys(&p, &out, pass, &[], &[]) {
            Ok(n) => {
                let got = std::fs::read(&out).unwrap();
                assert_eq!(got.len() as u64, n);
                Ok(got)
            }
            Err(e) => {
                assert!(!out.exists(), "no output on failure");
                assert!(!dir.join("out.bin.sigil-part").exists(), "no part file");
                Err(e.to_string())
            }
        }
    }

    #[test]
    fn fixture_plain_matches_recorded_hash() {
        assert_eq!(
            hex::encode(crate::sha256(&plain())),
            "cfbeeed4da2dee64b1042ee3af314220eedab7c2bae804647b9d961e6fb388bf"
        );
    }

    #[test]
    fn old_fixtures_open_exactly_and_mend_leaves_them_byte_identical() {
        let dir = tmp("compat");
        let want = plain();
        for (name, pass) in [
            ("pack-v2-reflection.sg1", None),
            ("pack-v2-pass.sg1", Some(PASS)),
        ] {
            let pack = fixture(name);
            let l = layout(&mut MemSrc(&pack)).unwrap();
            assert_eq!(l.source, HeadSource::Intact, "{name}");
            assert_eq!(l.head_bytes, pack[..head_len(&pack)], "{name}");
            assert_eq!(l.head.stars, 4);
            assert_eq!(open(&dir, &pack, pass).unwrap(), want, "{name}");
            let p = dir.join("m-in.sg1");
            std::fs::write(&p, &pack).unwrap();
            let rep = mend_pack_path(&p, &dir.join("m-out.sg1"), false).unwrap();
            assert!(rep.mended.is_empty() && rep.head == HeadSource::Intact);
            assert_eq!(
                std::fs::read(dir.join("m-out.sg1")).unwrap(),
                pack,
                "{name}"
            );
            let mut out = Vec::new();
            let m = mend_pack_to(&pack, &mut out, pass, &[], &[]).unwrap();
            assert!(m.healed.is_none());
            assert_eq!(out, want);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn version_1_head_still_opens() {
        // Version 1 heads have no overture field. Rewrite the fixture's head as v1.
        let dir = tmp("v1");
        let pack = fixture("pack-v2-reflection.sg1");
        let hl = head_len(&pack);
        let mut v1 = pack[..hl - 4].to_vec();
        v1[4] = 1;
        v1.extend_from_slice(&pack[hl..]);
        let l = layout(&mut MemSrc(&v1)).unwrap();
        assert_eq!(l.source, HeadSource::Intact);
        assert_eq!(l.head.version, 1);
        assert_eq!(open(&dir, &v1, None).unwrap(), plain());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Every single byte of the head, three ways: the pack opens exactly, and a
    /// mend writes back the original head byte for byte.
    #[test]
    fn head_damaged_at_every_offset_is_rebuilt_old_format() {
        let dir = tmp("every");
        let want = plain();
        let pack = fixture("pack-v2-reflection.sg1");
        let hl = head_len(&pack);
        // Bytes 5..9 (chunk size) and the last 4 (overture) are advisory: nothing in
        // the stars can check them, so damage there is carried, not detected.
        let advisory = |i: usize| (5..9).contains(&i) || i >= hl - 4;
        for i in 0..hl {
            for how in 0..3 {
                let mut bad = pack.clone();
                match how {
                    0 => bad[i] ^= 0xff,
                    1 => bad[i] = 0,
                    _ => bad[i] ^= 0x01,
                }
                if bad == pack {
                    continue;
                }
                assert_eq!(
                    open(&dir, &bad, None).unwrap_or_else(|e| panic!("offset {i} way {how}: {e}")),
                    want,
                    "offset {i} way {how}"
                );
                if advisory(i) {
                    continue;
                }
                let p = dir.join("bad.sg1");
                std::fs::write(&p, &bad).unwrap();
                let fixed = dir.join("fixed.sg1");
                let rep = mend_pack_path(&p, &fixed, false)
                    .unwrap_or_else(|e| panic!("mend offset {i} way {how}: {e}"));
                assert_eq!(rep.head, HeadSource::FacetList, "offset {i} way {how}");
                assert_eq!(std::fs::read(&fixed).unwrap(), pack, "offset {i} way {how}");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn whole_head_wiped_is_rebuilt_including_encrypted() {
        let dir = tmp("wipe");
        let want = plain();
        for (name, pass) in [
            ("pack-v2-reflection.sg1", None),
            ("pack-v2-pass.sg1", Some(PASS)),
        ] {
            let pack = fixture(name);
            let hl = head_len(&pack);
            let mut bad = pack.clone();
            bad[..hl].fill(0);
            assert_eq!(open(&dir, &bad, pass).unwrap(), want, "{name}");
            // In-memory mend (folder packs) hands back the repaired pack.
            let mut out = Vec::new();
            let m = mend_pack_to(&bad, &mut out, pass, &[], &[]).unwrap();
            assert_eq!(out, want);
            assert_eq!(m.head, HeadSource::FacetList);
            assert_eq!(m.healed.unwrap(), pack, "{name}");
            // Range reads and the index work through the rebuilt head too.
            let p = dir.join("wiped.sg1");
            std::fs::write(&p, &bad).unwrap();
            let (head, locs) = crate::work::index_pack(&p).unwrap();
            assert_eq!((head.stars, head.orig_total, locs.len()), (4, 200_000, 4));
            // Advisory fields of a head rebuilt from scratch: largest chunk, default overture.
            assert_eq!((head.chunk_size, head.overture), (65536, 4));
            assert_eq!(crate::work::payload_name(&p).unwrap(), "plain.bin");
            let r = dir.join("range.bin");
            crate::work::unseal_range_keys(&p, &r, pass, &[], 1, 2, &[]).unwrap();
            assert_eq!(std::fs::read(&r).unwrap(), want[65536..3 * 65536]);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn wrong_or_missing_key_still_fails_closed_after_rebuild() {
        let dir = tmp("key");
        let pack = fixture("pack-v2-pass.sg1");
        let mut bad = pack.clone();
        bad[..4].fill(0);
        let e = open(&dir, &bad, Some("not the pass")).unwrap_err();
        assert!(e.contains("star 0"), "{e}");
        assert!(open(&dir, &bad, None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn spans(pack: &[u8]) -> Vec<(usize, usize)> {
        layout(&mut MemSrc(pack))
            .unwrap()
            .stars
            .iter()
            .map(|&(o, n)| (o as usize, (o + n) as usize))
            .collect()
    }

    #[test]
    fn swapped_or_reordered_stars_are_refused_even_with_the_head_gone() {
        let dir = tmp("swap");
        let pack = fixture("pack-v2-reflection.sg1");
        let sp = spans(&pack);
        let hl = head_len(&pack);
        for (a, b) in [(0, 1), (1, 2), (0, 2)] {
            let mut stars: Vec<&[u8]> = sp.iter().map(|&(x, y)| &pack[x..y]).collect();
            stars.swap(a, b);
            let mut bad = vec![0u8; hl]; // head wiped as well
            for st in stars {
                bad.extend_from_slice(&(st.len() as u64).to_le_bytes());
                bad.extend_from_slice(st);
            }
            bad.extend_from_slice(&pack[sp[3].1..]);
            assert!(open(&dir, &bad, None).is_err(), "swap {a}<->{b}");
            assert!(mend_pack_to(&bad, &mut Vec::new(), None, &[], &[]).is_err());
            let p = dir.join("sw.sg1");
            std::fs::write(&p, &bad).unwrap();
            assert!(mend_pack_path(&p, &dir.join("o.sg1"), false).is_err());
            assert!(!dir.join("o.sg1").exists());
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn old_format_refuses_when_the_evidence_is_gone() {
        let dir = tmp("refuse");
        let pack = fixture("pack-v2-reflection.sg1");
        let hl = head_len(&pack);
        let sp = spans(&pack);
        let n = pack.len();
        // Head and star 0's length framing gone.
        let mut a = pack.clone();
        a[..hl + 8].fill(0);
        assert!(open(&dir, &a, None).is_err());
        // Head and facet list both damaged: no evidence of count or order.
        let mut b = pack.clone();
        b[..4].fill(0);
        b[n - 32 * 4 - 8] = b'X';
        assert!(open(&dir, &b, None).is_err());
        // Head damaged and the pack truncated at many points.
        let mut c = pack.clone();
        c[..hl].fill(0);
        for cut in [
            hl + 4,
            sp[0].1,
            sp[0].1 + 4,
            sp[1].1 + 9,
            sp[3].1,
            n - 1,
            n - 32,
        ] {
            assert!(open(&dir, &c[..cut], None).is_err(), "cut at {cut}");
            assert!(
                crate::pieces::mend_bytes(&c[..cut]).is_err(),
                "mend cut at {cut}"
            );
        }
        // Only star 0 survives behind its framing: never returned as "the file".
        let e = open(&dir, &c[..sp[0].1], None).unwrap_err();
        assert!(e.contains("one part of a large-file pack"), "{e}");
        // A bit flip inside a star's framing length is never guessed past.
        let mut d = pack.clone();
        d[0] ^= 1;
        d[sp[2].0 - 3] ^= 0x40;
        assert!(open(&dir, &d, None).is_err());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn facet_list_damaged_old_format_opens_but_mend_refuses() {
        // Unchanged behaviour: every star still verifies on its own, but without a
        // list there is no evidence of order for a rewrite.
        let dir = tmp("facets");
        let pack = fixture("pack-v2-reflection.sg1");
        let n = pack.len();
        let mut bad = pack.clone();
        bad[n - 5] ^= 0xff;
        bad[n - 32 * 4 - 8] = b'X';
        assert_eq!(open(&dir, &bad, None).unwrap(), plain());
        let p = dir.join("f.sg1");
        std::fs::write(&p, &bad).unwrap();
        let e = mend_pack_path(&p, &dir.join("o.sg1"), false).unwrap_err();
        assert!(e.to_string().contains("facet trailer"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn long_name_cannot_come_back_from_the_stars_but_the_data_does() {
        let dir = tmp("longname");
        let want = plain();
        let src = dir.join("a-rather-long-file-name.bin");
        std::fs::write(&src, &want).unwrap();
        let out = dir.join("long.sg1");
        crate::work::inscribe_path(
            &src,
            &out,
            crate::Mode::Reflection,
            None,
            "",
            &[],
            64 * 1024,
            None,
            0,
            0,
            None,
        )
        .unwrap();
        let mut bad = std::fs::read(&out).unwrap();
        bad[..4].fill(0);
        std::fs::write(&out, &bad).unwrap();
        assert_eq!(crate::work::payload_name(&out).unwrap(), "payload.bin");
        assert_eq!(open(&dir, &bad, None).unwrap(), want);
        // "plain.bin" (9 bytes, up to 11 fit) plus ".0000" fits the 16-byte star name.
        let pack = fixture("pack-v2-reflection.sg1");
        let mut b = pack.clone();
        b[..4].fill(0);
        assert_eq!(recover_bytes(&b).unwrap().head.name, "plain.bin");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn single_seal_is_not_mistaken_for_a_pack() {
        let one = crate::seal(&plain(), crate::Mode::Seal, None, "x.bin", false).unwrap();
        assert!(recover_bytes(&one).is_none());
        let mut junk = one.clone();
        junk.extend_from_slice(b"SGFC\x01\x00\x00\x00");
        junk.extend_from_slice(&[7u8; 32]);
        assert!(recover_bytes(&junk).is_none());
    }
}
