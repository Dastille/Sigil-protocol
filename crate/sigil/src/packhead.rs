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
//! When the 8-byte length prefixes between stars are damaged, [`layout`] also
//! rebuilds that framing (decoder-only; the `.sg1` layout is unchanged). A
//! rebuilt length is accepted only after the same confirmation: the star's
//! own SHA-256 matches the SGFC list, and any intact guard names this index,
//! this head and this pack. Reordered, swapped, truncated or forged lengths
//! that point at a different valid-looking star are refused. Scans of
//! untrusted input are capped (24 MiB per star, 64 MiB and 3 seconds per
//! rebuild, 64 magic hits, a reused 1 MiB window).
//!
//! Nothing is guessed: a rebuild needs a unique head length at which every star
//! matches the list, otherwise the original error is returned. Reordered or
//! swapped stars never match the list, so they are still refused.
//!
//! Packs written since pack-head guards were added also carry a **guard** after
//! each star's seal, inside the star's framed length (old readers skip it as
//! trailing bytes): a SHA-256-checked copy of the whole head plus the star's own
//! index and file offset. Any one intact guard restores the head byte for byte,
//! and the guards prove the star order even when the facet list is damaged too.

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
    /// The head on disk was damaged; it was restored byte for byte from a guard
    /// copy stored after a chunk star (packs written with guards).
    Guard,
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
    /// The stars carry guards (written since guards were added).
    pub guarded: bool,
    /// The guards' pack id (zero when unguarded).
    pub pack_id: [u8; 16],
    /// The facet list was damaged and has been rebuilt from the stars' own
    /// headers, in the order their guards prove.
    pub facets_rebuilt: bool,
    /// The per-star length prefixes were rebuilt. Set only after every star
    /// was confirmed against the SGFC list (and any intact guard).
    pub framing_rebuilt: bool,
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
        if len < MIN_STAR_BYTES {
            return Err(damaged());
        }
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
        guarded: false,
        pack_id: [0u8; 16],
        facets_rebuilt: false,
        framing_rebuilt: false,
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
        guarded: false,
        pack_id: [0u8; 16],
        facets_rebuilt: false,
        framing_rebuilt: false,
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

const GUARD_MAGIC: [u8; 4] = *b"SGHG";
const GUARD_TAIL: [u8; 4] = *b"GHGS";
const GUARD_VERSION: u8 = 1;
/// Guard bytes besides the head copy: magic 4, version 1, index 4, star offset 8,
/// seal length 8, pack id 16, head length 2, SHA-256 32, record length 4, tail magic 4.
const GUARD_FIXED: usize = 83;
/// Offset of the head length inside a guard (the head copy follows it).
const GUARD_HEAD_LEN_AT: usize = 41;
/// Largest guard (with the longest possible head).
pub(crate) const MAX_GUARD: usize = GUARD_FIXED + MAX_HEAD as usize;

/// A pack-head guard found after a star's seal.
pub(crate) struct Guard {
    /// The star's index in the pack.
    pub index: u32,
    /// File offset of the star's 8-byte length when the guard was written
    /// (informational: a mend by a pre-guard binary can shift later stars).
    #[allow(dead_code)]
    pub star_off: u64,
    /// Bytes of seal in front of the guard.
    pub seal_len: u64,
    /// Random id shared by every star of one pack (written once per seal), so a
    /// star from another pack with the same name and size is not taken as ours.
    pub pack_id: [u8; 16],
    /// The full pack head.
    pub head: Vec<u8>,
}

/// A fresh random pack id for a new pack.
pub(crate) fn new_pack_id() -> Result<[u8; 16]> {
    let mut id = [0u8; 16];
    getrandom::getrandom(&mut id).map_err(|e| msg(e.to_string()))?;
    Ok(id)
}

/// The guard written after star `index`'s seal (see the module docs). A
/// SHA-256 over every field before it makes damage detectable; it is not a MAC.
pub(crate) fn guard_bytes(
    index: u32,
    star_off: u64,
    seal_len: u64,
    pack_id: &[u8; 16],
    head: &[u8],
) -> Vec<u8> {
    let mut g = Vec::with_capacity(GUARD_FIXED + head.len());
    g.extend_from_slice(&GUARD_MAGIC);
    g.push(GUARD_VERSION);
    g.extend_from_slice(&index.to_le_bytes());
    g.extend_from_slice(&star_off.to_le_bytes());
    g.extend_from_slice(&seal_len.to_le_bytes());
    g.extend_from_slice(pack_id);
    g.extend_from_slice(&(head.len() as u16).to_le_bytes());
    g.extend_from_slice(head);
    let check = crate::sha256(&g);
    g.extend_from_slice(&check);
    let total = (g.len() + 8) as u32;
    g.extend_from_slice(&total.to_le_bytes());
    g.extend_from_slice(&GUARD_TAIL);
    g
}

fn le_u32(b: &[u8], at: usize) -> Option<u32> {
    let mut a = [0u8; 4];
    a.copy_from_slice(b.get(at..at + 4)?);
    Some(u32::from_le_bytes(a))
}

fn le_u64(b: &[u8], at: usize) -> Option<u64> {
    let mut a = [0u8; 8];
    a.copy_from_slice(b.get(at..at + 8)?);
    Some(u64::from_le_bytes(a))
}

/// Parse one complete guard record (exactly its bytes).
fn parse_guard(rec: &[u8]) -> Option<Guard> {
    if rec.len() < GUARD_FIXED || rec.len() > MAX_GUARD || rec[..4] != GUARD_MAGIC {
        return None;
    }
    if rec[4] != GUARD_VERSION || rec[rec.len() - 4..] != GUARD_TAIL {
        return None;
    }
    let at = GUARD_HEAD_LEN_AT;
    let head_len = u16::from_le_bytes([rec[at], rec[at + 1]]) as usize;
    if GUARD_FIXED + head_len != rec.len() || le_u32(rec, rec.len() - 8)? as usize != rec.len() {
        return None;
    }
    let body = at + 2 + head_len;
    let mut pack_id = [0u8; 16];
    pack_id.copy_from_slice(&rec[25..41]);
    if crate::sha256(&rec[..body]) != rec[body..body + 32] {
        return None;
    }
    Some(Guard {
        index: le_u32(rec, 5)?,
        star_off: le_u64(rec, 9)?,
        seal_len: le_u64(rec, 17)?,
        pack_id,
        head: rec[at + 2..body].to_vec(),
    })
}

/// The guard at the end of `star` (its framed bytes), if intact.
pub(crate) fn guard_of_star(star: &[u8]) -> Option<Guard> {
    let n = star.len();
    if n < GUARD_FIXED || star[n - 4..] != GUARD_TAIL {
        return None;
    }
    let len = le_u32(star, n - 8)? as usize;
    let rec = star.get(n.checked_sub(len)?..)?;
    let g = parse_guard(rec)?;
    (g.seal_len == (n - len) as u64).then_some(g)
}

fn star_guard<S: Src>(src: &mut S, off: u64, len: u64) -> Option<Guard> {
    let t = len.min(MAX_GUARD as u64);
    let mut tail = vec![0u8; t as usize];
    src.read_at(off + len - t, &mut tail).ok()?;
    let n = tail.len();
    if n < GUARD_FIXED || tail[n - 4..] != GUARD_TAIL {
        return None;
    }
    let glen = le_u32(&tail, n - 8)? as u64;
    let g = parse_guard(tail.get(n.checked_sub(glen as usize)?..)?)?;
    (g.seal_len.checked_add(glen) == Some(len)).then_some(g)
}

/// Bytes of seal at the front of a star (everything before its guard).
pub(crate) fn seal_part(star: &[u8]) -> &[u8] {
    if let Some(g) = guard_of_star(star) {
        return &star[..g.seal_len as usize];
    }
    // Guard damaged or absent: the seal ends where its own header says.
    // Trailing pieces are counted by [`sgts_then_sgkt_len`] (SGTS spare, then
    // SGKT trailer). Asking for the Keystone trailer first misses both.
    match crate::locate_header(star) {
        Ok((h, prefix, _)) => &star[..seal_len_after_header(&h, prefix, star)],
        Err(_) => star,
    }
}

/// Lay the pack out again from a trusted head (a guard copy).
fn layout_with_head<S: Src>(src: &mut S, head_bytes: &[u8]) -> Result<PackLayout> {
    let mut cur = std::io::Cursor::new(head_bytes);
    let head = read_head(&mut cur)?;
    if cur.position() != head_bytes.len() as u64 {
        return Err(msg("guard head copy has trailing bytes"));
    }
    let start = head_bytes.len() as u64;
    let stars = tile(src, start, head.stars, src.size())?;
    let trailer_off = stars.last().map(|&(o, l)| o + l).unwrap_or(start);
    let trailer = read_trailer(src, trailer_off, head.stars)?;
    Ok(PackLayout {
        head,
        head_bytes: head_bytes.to_vec(),
        stars,
        trailer_off,
        trailer,
        source: HeadSource::Guard,
        guarded: true,
        pack_id: [0u8; 16],
        facets_rebuilt: false,
        framing_rebuilt: false,
    })
}

/// Check a layout against its stars' guards. Returns `Ok(false)` when no star
/// has a guard (a pack written before guards). Refuses stars whose guard puts
/// them somewhere else (swapped / reordered / spliced), restores the head from
/// the guards when the on-disk one differs, and rebuilds a damaged facet list
/// when every star's guard is intact.
fn apply_guards<S: Src>(src: &mut S, l: &mut PackLayout) -> Result<bool> {
    // A head restored from a guard is laid out once more and checked again.
    for _ in 0..2 {
        let guards: Vec<Option<Guard>> = l
            .stars
            .iter()
            .map(|&(o, n)| star_guard(src, o, n))
            .collect();
        if guards.iter().all(Option::is_none) {
            return Ok(false);
        }
        let mut head: Option<&[u8]> = None;
        let mut pack_id: Option<[u8; 16]> = None;
        for (i, g) in guards.iter().enumerate() {
            let Some(g) = g else { continue };
            // The index, not the recorded offset: a mend by a pre-guard binary drops
            // the guard of each star it heals, which shifts every later star.
            if g.index as usize != i {
                return Err(msg(format!(
                    "chunk star {i} is out of place (its guard says it is star {}); \
                     swapped or reordered stars; refusing",
                    g.index
                )));
            }
            let same_pack = pack_id.is_none_or(|id| id == g.pack_id);
            pack_id = Some(g.pack_id);
            match head {
                None if same_pack => head = Some(&g.head),
                Some(h) if same_pack && h == g.head.as_slice() => {}
                _ => return Err(msg(
                    "chunk stars carry different pack heads (stars from different packs); refusing",
                )),
            }
        }
        let Some(head) = head else { return Ok(false) };
        if head != l.head_bytes.as_slice() {
            *l = layout_with_head(src, head)?;
            continue;
        }
        l.guarded = true;
        l.pack_id = pack_id.unwrap_or_default();
        // Every star's place is proven by its guard, so the stars' own headers say
        // what the facet list should be; a missing or damaged list is rebuilt.
        if guards.iter().all(Option::is_some) {
            let from_stars: Option<Vec<[u8; 32]>> = l
                .stars
                .iter()
                .map(|&(o, n)| star_header(src, o, n).ok().map(|h| h.0))
                .collect();
            if let Some(f) = from_stars {
                if l.facets() != Some(f.as_slice()) {
                    l.trailer = Trailer::Valid(f);
                    l.facets_rebuilt = true;
                }
            }
        }
        return Ok(true);
    }
    Err(msg(
        "pack head guards disagree with the pack layout; refusing",
    ))
}

/// Find the first intact, correctly placed guard anywhere in the file and lay
/// the pack out from its head copy.
fn from_guards<S: Src>(src: &mut S) -> Result<PackLayout> {
    let size = src.size();
    let none = || msg("no intact pack-head guard found");
    let mut off = 0u64;
    while off < size {
        let n = SCAN_BLOCK.min(size - off);
        let mut block = vec![0u8; n as usize];
        src.read_at(off, &mut block)?;
        let mut i = 0usize;
        while let Some(hit) = block[i..].windows(4).position(|w| w == GUARD_MAGIC) {
            let p = off + (i + hit) as u64;
            i += hit + 1;
            let mut rec = vec![0u8; (MAX_GUARD as u64).min(size - p) as usize];
            if src.read_at(p, &mut rec).is_err() || rec.len() < GUARD_FIXED {
                continue;
            }
            let at = GUARD_HEAD_LEN_AT;
            let head_len = u16::from_le_bytes([rec[at], rec[at + 1]]) as usize;
            let Some(g) = rec.get(..GUARD_FIXED + head_len).and_then(parse_guard) else {
                continue;
            };
            // It must end a framed star: the 8-byte length in front of its seal covers
            // exactly the seal plus this guard. (Not the recorded offset, which a
            // pre-guard mend may have shifted.)
            let rec_len = (GUARD_FIXED + head_len) as u64;
            let placed = p
                .checked_sub(g.seal_len + 8)
                .and_then(|o| read_u64(src, o).ok())
                == g.seal_len.checked_add(rec_len);
            if !placed {
                // Length prefix gone or wrong: a checksum-valid guard can still
                // supply the head, and rebuild confirms every star against SGFC.
                if let Ok(r) = try_rebuild_framing(src, &g.head, HeadSource::Guard) {
                    return Ok(r);
                }
                continue;
            }
            let mut l = match layout_with_head(src, &g.head) {
                Ok(l) if !matches!(l.trailer, Trailer::Damaged) => l,
                _ => match try_rebuild_framing(src, &g.head, HeadSource::Guard) {
                    Ok(r) => return Ok(r),
                    Err(_) => match layout_with_head(src, &g.head) {
                        Ok(l) => l,
                        Err(_) => continue,
                    },
                },
            };
            if apply_guards(src, &mut l)? {
                l.source = HeadSource::Guard;
                return Ok(l);
            }
        }
        if off + n >= size {
            break;
        }
        // Overlap so a magic split across blocks is still seen.
        off += n - 3;
    }
    Err(none())
}

/// Smallest accepted on-disk star (a header). A zeroed length prefix used to
/// be taken as a 0-byte star, which landed the walk early and blamed the SGFC
/// list even when that list was intact.
const MIN_STAR_BYTES: u64 = crate::header::HEADER_SIZE as u64;
/// Bytes read from the front of a star when looking for its header.
const FRONT_PEEK: u64 = 4096;
/// Per-star search ceiling when a length prefix is gone.
///
/// CDC Media max payload is 8 MiB, Seal expands 2×, and headers, an SGTS spare,
/// an SGKT trailer and a pack-head guard add well under 2 MiB. Measured Seal
/// stars for an 8 MiB payload stay under 18 MiB. 24 MiB is the hard cap so a
/// crafted `chunk_size` cannot force a multi-gigabyte scan.
const MAX_STAR_SCAN: u64 = 24 * 1024 * 1024;
/// Hard cap on total bytes read by framing scans in one rebuild (all stars).
const MAX_FRAMING_SCAN_BYTES: u64 = 64 * 1024 * 1024;
/// Wall-clock cap for one framing rebuild of untrusted input. There is no
/// environment override: hitting this or [`MAX_FRAMING_SCAN_BYTES`] refuses
/// the pack (fail-closed).
const FRAMING_SCAN_SECS: u64 = 3;
/// A real star has one `SGHG` guard and at most `n` (16) `SGEM` Ember headers.
/// A crafted file filled with those magics is abandoned after this many hits.
const MAX_MAGIC_HITS: u32 = 64;

/// Time, memory and size budget for scans of untrusted pack bytes.
struct ScanBudget {
    started: std::time::Instant,
    bytes: u64,
    buf: Vec<u8>,
}

impl ScanBudget {
    fn new() -> Self {
        Self {
            started: std::time::Instant::now(),
            bytes: 0,
            buf: vec![0u8; SCAN_BLOCK as usize],
        }
    }

    fn exhausted(&self) -> bool {
        self.started.elapsed() >= std::time::Duration::from_secs(FRAMING_SCAN_SECS)
            || self.bytes >= MAX_FRAMING_SCAN_BYTES
    }

    fn charge(&mut self, n: u64) -> bool {
        self.bytes = self.bytes.saturating_add(n);
        !self.exhausted()
    }

    /// Read `n` bytes at `off` into the reused 1 MiB window. `n` must be
    /// ≤ [`SCAN_BLOCK`]. Charges the size budget; returns `None` when the
    /// budget is exhausted or the read fails.
    fn read_window<'a, S: Src>(&'a mut self, src: &mut S, off: u64, n: u64) -> Option<&'a [u8]> {
        if self.exhausted() || n == 0 || n > SCAN_BLOCK {
            return None;
        }
        let n_usz = n as usize;
        if src.read_at(off, &mut self.buf[..n_usz]).is_err() {
            return None;
        }
        if !self.charge(n) {
            return None;
        }
        Some(&self.buf[..n_usz])
    }
}

fn budget_exceeded(i: u32, n: u32) -> crate::Error {
    msg(format!(
        "work pack framing scan limit reached at star {i} of {n} \
         (could not confirm the star against SGFC within the time and size budget); refusing"
    ))
}

/// Length of the `SGTS` spare (if any) plus the `SGKT` trailer (if any) that
/// follow the shard body. The pack-head guard is not included.
///
/// This is the only place that arithmetic lives. Asking for the Keystone
/// trailer before skipping the spare looks at the spare's magic and returns
/// 0, so both trailers are missed.
fn sgts_then_sgkt_len(file: &[u8], body_end: usize) -> usize {
    let sgts = crate::header::sgto_spare_len_at(file, body_end);
    sgts + crate::header::keystone_trailer_len_at(file, body_end + sgts)
}

/// Length of the seal at the front of `star`, from a header found at `prefix`.
fn seal_len_after_header(h: &crate::Header, prefix: usize, star: &[u8]) -> usize {
    let body_end =
        prefix.saturating_add((h.n as usize).saturating_mul(crate::header::shard_stride(h)));
    body_end
        .saturating_add(sgts_then_sgkt_len(star, body_end))
        .min(star.len())
}

fn read_head_from_bytes(hb: &[u8]) -> Result<WorkHead> {
    let mut cur = std::io::Cursor::new(hb);
    let head = read_head(&mut cur)?;
    if cur.position() != hb.len() as u64 {
        return Err(msg("pack head copy has trailing bytes"));
    }
    Ok(head)
}

/// Rebuild length framing from a known, already-checked head, or return the
/// error from that rebuild. Shared by [`layout`] and [`from_guards`].
fn try_rebuild_framing<S: Src>(
    src: &mut S,
    head_bytes: &[u8],
    source: HeadSource,
) -> Result<PackLayout> {
    rebuild_framing_with_head(
        src,
        read_head_from_bytes(head_bytes)?,
        head_bytes.to_vec(),
        source,
    )
}

/// Error when a rebuild could not confirm a layout. Names framing when the
/// SGFC list is intact at EOF, and both parts when it is not.
fn framing_or_trailer_error<S: Src>(src: &mut S) -> crate::Error {
    match find_facet_list(src) {
        Ok(_) => msg("work pack framing damaged (length prefixes do not tile); \
             SGFC list is intact but stars could not be confirmed; refusing"),
        Err(_) => msg("work pack framing and SGFC facet trailer damaged; \
             cannot confirm stars, refusing"),
    }
}

/// Locate a star's seal header and compute its seal length (and guard length
/// if a guard sits right after the seal). Falls back to a bounded scan for
/// `SGEM` Embers if the front Keystone span was wiped. A candidate is only
/// useful to the caller; acceptance still requires [`confirm_star_len`].
fn seal_len_from_star_at<S: Src>(
    src: &mut S,
    star_start: u64,
    max_len: u64,
    head_len: u64,
    expect_digest: Option<&[u8; 32]>,
    budget: &mut ScanBudget,
) -> Option<(crate::Header, u64, Option<u64>)> {
    if max_len < MIN_STAR_BYTES {
        return None;
    }
    let peek_n = max_len.min(FRONT_PEEK) as usize;
    let mut peek = vec![0u8; peek_n];
    if src.read_at(star_start, &mut peek).is_err() || !budget.charge(peek_n as u64) {
        return None;
    }
    let found = if let Ok((h, prefix, _)) = crate::locate_header(&peek) {
        if expect_digest.is_none_or(|d| h.digest == *d) {
            Some((h, prefix as u64))
        } else {
            return None;
        }
    } else {
        Some(scan_ember_header(
            src,
            star_start,
            max_len,
            expect_digest,
            budget,
        )?)
    };
    let (h, prefix) = found?;
    let stride = crate::header::shard_stride(&h) as u64;
    let body_end = prefix.checked_add((h.n as u64).checked_mul(stride)?)?;
    if body_end > max_len {
        return None;
    }
    let tail_n = max_len.saturating_sub(body_end).min(FRONT_PEEK) as usize;
    let mut tail = vec![0u8; tail_n];
    if tail_n > 0
        && (src.read_at(star_start + body_end, &mut tail).is_err() || !budget.charge(tail_n as u64))
    {
        return None;
    }
    let mut extra = sgts_then_sgkt_len(&tail, 0) as u64;
    // When the spare itself is unreadable, still offer the usual encrypted-v3
    // length as a *candidate*. Confirming it is a later, separate step.
    if extra == 0 && h.encrypted() && h.private_label() {
        if let Some(guess) = guessed_sgts_len(&h, prefix, &peek, &tail) {
            extra = guess;
        }
    }
    let seal_len = body_end + extra;
    let gl = (GUARD_FIXED as u64) + head_len;
    let g_off = extra as usize;
    let guard_len = if tail.get(g_off..g_off + 4) == Some(&GUARD_MAGIC)
        || (star_start + seal_len + gl <= star_start + max_len
            && star_guard(src, star_start, seal_len + gl).is_some())
    {
        Some(gl)
    } else {
        None
    };
    Some((h, seal_len, guard_len))
}

/// Best-effort SGTS length when the spare's own magic is gone, used only to
/// build candidates (never as a verdict on its own).
fn guessed_sgts_len(h: &crate::Header, prefix: u64, peek: &[u8], tail: &[u8]) -> Option<u64> {
    let vow = if h.vow() {
        crate::header::VOW_SIZE as u64
    } else {
        0
    };
    let maps = crate::header::maps_len(h) as u64;
    let sgto_len = prefix.saturating_sub(maps + vow);
    if sgto_len < 12 {
        return None;
    }
    let mut spared = false;
    if let Some(front) = peek.get(maps as usize..(maps + sgto_len) as usize) {
        if crate::keys::read_sgto_at(front, 0)
            .is_some_and(|b| crate::keys::sgto_is_spared(b) && b.len() as u64 == sgto_len)
        {
            spared = true;
        }
    }
    let cand = 8 + sgto_len as usize;
    let kt = crate::header::KEYSTONE_TRAILER_SIZE;
    if spared
        || tail.get(cand..cand + 4) == Some(&b"SGKT"[..])
        || tail.get(cand + kt..cand + kt + 4) == Some(&GUARD_MAGIC)
    {
        Some(cand as u64)
    } else {
        None
    }
}

fn scan_ember_header<S: Src>(
    src: &mut S,
    star_start: u64,
    max_len: u64,
    expect_digest: Option<&[u8; 32]>,
    budget: &mut ScanBudget,
) -> Option<(crate::Header, u64)> {
    let scan_end = star_start.saturating_add(max_len.min(MAX_STAR_SCAN));
    let mut off = star_start;
    let mut hits = 0u32;
    while off < scan_end && !budget.exhausted() {
        let n = SCAN_BLOCK.min(scan_end - off);
        if n < crate::header::HEADER_SIZE as u64 {
            break;
        }
        let Some(block) = budget.read_window(src, off, n) else {
            break;
        };
        let hit = block
            .windows(4)
            .position(|w| w == crate::header::EMBER_MAGIC);
        let p = hit.map(|h| off + h as u64);
        if let Some(p) = p {
            hits += 1;
            if hits > MAX_MAGIC_HITS {
                return None;
            }
            let mut hdr = [0u8; crate::header::HEADER_SIZE];
            let parsed = if src.read_at(p, &mut hdr).is_ok() && budget.charge(hdr.len() as u64) {
                crate::header::parse_ember_header(&hdr)
            } else {
                None
            };
            if let Some((eh, slot)) = parsed {
                if expect_digest.is_none_or(|d| eh.digest == *d) {
                    let stride = crate::header::shard_stride(&eh) as u64;
                    if stride != 0 && eh.n != 0 {
                        if let Some(prefix) = (p - star_start).checked_sub(slot as u64 * stride) {
                            if prefix >= crate::header::maps_len(&eh) as u64 {
                                return Some((eh, prefix));
                            }
                        }
                    }
                }
            }
            off = p.saturating_add(1);
            continue;
        }
        if off + n >= scan_end {
            break;
        }
        off += n - 3;
    }
    None
}

/// Scan forward from `star_start` for a guard carrying `index`, matching
/// `head_bytes` and `pack_id`, and sitting at `star_start + g.seal_len`.
fn find_guard_for_star<S: Src>(
    src: &mut S,
    star_start: u64,
    max_len: u64,
    index: u32,
    head_bytes: &[u8],
    pack_id: Option<[u8; 16]>,
    budget: &mut ScanBudget,
) -> Option<u64> {
    let rec_len = (GUARD_FIXED + head_bytes.len()) as u64;
    let scan_end = star_start.saturating_add(max_len.min(MAX_STAR_SCAN));
    let mut off = star_start;
    let mut hits = 0u32;
    while off < scan_end && !budget.exhausted() {
        let n = SCAN_BLOCK.min(scan_end - off);
        if n < rec_len {
            break;
        }
        let Some(block) = budget.read_window(src, off, n) else {
            break;
        };
        let found = block
            .windows(4)
            .position(|w| w == GUARD_MAGIC)
            .map(|hit| off + hit as u64);
        if found.is_some() {
            hits += 1;
            if hits > MAX_MAGIC_HITS {
                return None;
            }
        }
        // Re-read the candidate outside the window borrow.
        if let Some(p) = found {
            let mut rec = vec![0u8; rec_len as usize];
            if src.read_at(p, &mut rec).is_ok() && budget.charge(rec_len) {
                if let Some(g) = parse_guard(&rec) {
                    if g.index == index
                        && g.head == head_bytes
                        && pack_id.is_none_or(|id| id == g.pack_id)
                        && p.checked_sub(star_start) == Some(g.seal_len)
                    {
                        if let Some(total) = g.seal_len.checked_add(rec_len) {
                            if total <= max_len {
                                return Some(total);
                            }
                        }
                    }
                }
            }
            // Continue scanning after this hit.
            off = p.saturating_add(1);
            continue;
        }
        if off + n >= scan_end {
            break;
        }
        off += n - 3;
    }
    None
}

/// Quick check whether `next_len_off` begins a star matching `next_facet`.
/// Used only to disambiguate candidate lengths; it is not a verdict on its own.
fn next_star_plausible<S: Src>(
    src: &mut S,
    next_len_off: u64,
    limit: u64,
    next_facet: &[u8; 32],
    is_last_next: bool,
    budget: &mut ScanBudget,
) -> bool {
    let Some(next_start) = next_len_off.checked_add(8) else {
        return false;
    };
    if next_start + MIN_STAR_BYTES > limit {
        return false;
    }
    if is_last_next {
        let rem = limit - next_start;
        return star_header(src, next_start, rem).is_ok_and(|(d, _, _)| d == *next_facet);
    }
    let peek_n = (limit - next_start).min(FRONT_PEEK) as usize;
    let mut peek = vec![0u8; peek_n];
    if src.read_at(next_start, &mut peek).is_ok() && budget.charge(peek_n as u64) {
        if let Ok((h, _, _)) = crate::locate_header(&peek) {
            return h.digest == *next_facet;
        }
    }
    if let Ok(nl) = read_u64(src, next_len_off) {
        if nl >= MIN_STAR_BYTES && next_start.checked_add(nl).is_some_and(|e| e < limit) {
            return star_header(src, next_start, nl).is_ok_and(|(d, _, _)| d == *next_facet);
        }
    }
    false
}

/// Inputs shared by every [`confirm_star_len`] call in one rebuild.
struct ConfirmCtx<'a, S: Src> {
    src: &'a mut S,
    head_bytes: &'a [u8],
    head_len: u64,
    gl_default: u64,
    guard_len_opt: &'a mut Option<u64>,
    pack_id_opt: &'a mut Option<[u8; 16]>,
    budget: &'a mut ScanBudget,
}

/// Accept `cand_len` only when the star's own SHA-256 matches `facets[i]` and
/// any intact guard names this index, this head and this pack. This is the
/// only acceptance decision for a rebuilt length.
fn confirm_star_len<S: Src>(
    ctx: &mut ConfirmCtx<'_, S>,
    star_start: u64,
    cand_len: u64,
    max_len: u64,
    i: u32,
    facets_i: &[u8; 32],
) -> Result<bool> {
    if cand_len < MIN_STAR_BYTES || cand_len > max_len {
        return Ok(false);
    }
    if let Some(g) = star_guard(ctx.src, star_start, cand_len) {
        if g.index != i {
            return Err(msg(format!(
                "chunk star {i} is out of place (its guard says it is star {}); \
                 swapped or reordered stars; refusing",
                g.index
            )));
        }
        if g.head != ctx.head_bytes || ctx.pack_id_opt.is_some_and(|id| id != g.pack_id) {
            return Err(msg(
                "chunk stars carry different pack heads (stars from different packs); refusing",
            ));
        }
        let Ok((d, _, _)) = star_header(ctx.src, star_start, cand_len) else {
            return Ok(false);
        };
        if d != *facets_i {
            return Err(msg(format!(
                "chunk star {i} true-name does not match the pack facet \
                 (swapped star or damaged trailer); refusing"
            )));
        }
        *ctx.guard_len_opt = Some(ctx.gl_default);
        *ctx.pack_id_opt = Some(g.pack_id);
        return Ok(true);
    }
    let Some((_, seal_len, g_opt)) = seal_len_from_star_at(
        ctx.src,
        star_start,
        cand_len,
        ctx.head_len,
        Some(facets_i),
        ctx.budget,
    ) else {
        return Ok(false);
    };
    if let Some(gl) = g_opt {
        if cand_len == seal_len + gl {
            *ctx.guard_len_opt = Some(gl);
            return Ok(true);
        }
        return Ok(false);
    }
    if let Some(gl) = *ctx.guard_len_opt {
        let kt = crate::header::KEYSTONE_TRAILER_SIZE as u64;
        return Ok(cand_len == seal_len + gl || cand_len == seal_len + kt + gl);
    }
    if cand_len == seal_len + ctx.gl_default {
        *ctx.guard_len_opt = Some(ctx.gl_default);
        return Ok(true);
    }
    Ok(cand_len == seal_len)
}

/// Rebuild per-star length framing given a known `head`, confirming every star
/// against its own protected header (`h.digest`) and the `SGFC` facet list
/// (and any intact guards). Decoder-only: the on-disk format is unchanged.
fn rebuild_framing_with_head<S: Src>(
    src: &mut S,
    head: WorkHead,
    head_bytes: Vec<u8>,
    source: HeadSource,
) -> Result<PackLayout> {
    let n = head.stars;
    if n == 0 {
        return Err(msg("work pack has 0 stars; refusing"));
    }
    let (trailer_off, facets) = find_facet_list(src).map_err(|_| {
        msg("work pack framing and SGFC facet trailer damaged; cannot confirm stars, refusing")
    })?;
    if facets.len() != n as usize {
        return Err(msg(format!(
            "work pack head says {n} stars but SGFC facet list has {}; refusing",
            facets.len()
        )));
    }
    let head_len = head_bytes.len() as u64;
    let gl_default = (GUARD_FIXED as u64) + head_len;
    let mut guard_len_opt: Option<u64> = (source == HeadSource::Guard).then_some(gl_default);
    let mut pack_id_opt: Option<[u8; 16]> = None;
    let mut typical_len: Option<u64> = None;
    let mut stars: Vec<(u64, u64)> = Vec::with_capacity(n as usize);
    let mut pos = head_len;
    let mut rebuilt_framing = false;
    let mut budget = ScanBudget::new();

    for i in 0..n {
        if budget.exhausted() {
            return Err(budget_exceeded(i, n));
        }
        let Some(star_start) = pos.checked_add(8) else {
            return Err(msg(format!(
                "work pack truncated or framing damaged at star {i} of {n}; refusing"
            )));
        };
        let min_rem = (n - 1 - i) as u64 * (8 + MIN_STAR_BYTES);
        let Some(max_end) = trailer_off.checked_sub(min_rem) else {
            return Err(msg(format!(
                "work pack truncated or framing damaged at star {i} of {n}; refusing"
            )));
        };
        if star_start + MIN_STAR_BYTES > max_end {
            return Err(msg(format!(
                "work pack truncated or framing damaged at star {i} of {n}; refusing"
            )));
        }
        let max_len = max_end - star_start;
        let raw_len = read_u64(src, pos).ok();
        let facet = &facets[i as usize];

        if i == n - 1 {
            let cand_len = trailer_off - star_start;
            // The last star's span is uniquely determined, but it is accepted
            // only after the same confirmation as every other star.
            if !confirm_star_len(
                &mut ConfirmCtx {
                    src,
                    head_bytes: &head_bytes,
                    head_len,
                    gl_default,
                    guard_len_opt: &mut guard_len_opt,
                    pack_id_opt: &mut pack_id_opt,
                    budget: &mut budget,
                },
                star_start,
                cand_len,
                max_len.max(cand_len),
                i,
                facet,
            )? {
                // Header may be unreadable (sector wipe). An Ember or the
                // remainder still has to carry the listed SHA-256.
                let Some((h, _, _)) = seal_len_from_star_at(
                    src,
                    star_start,
                    cand_len,
                    head_len,
                    Some(facet),
                    &mut budget,
                ) else {
                    return Err(msg(format!(
                        "chunk star {i} of {n} could not be confirmed against SGFC after framing rebuild; refusing"
                    )));
                };
                if h.digest != *facet {
                    return Err(msg(format!(
                        "chunk star {i} true-name does not match the pack facet \
                         (swapped star or damaged trailer); refusing"
                    )));
                }
            }
            if raw_len != Some(cand_len) {
                rebuilt_framing = true;
            }
            stars.push((star_start, cand_len));
            pos = trailer_off;
            break;
        }

        let mut chosen: Option<u64> = None;
        if let Some(rl) = raw_len {
            if confirm_star_len(
                &mut ConfirmCtx {
                    src,
                    head_bytes: &head_bytes,
                    head_len,
                    gl_default,
                    guard_len_opt: &mut guard_len_opt,
                    pack_id_opt: &mut pack_id_opt,
                    budget: &mut budget,
                },
                star_start,
                rl,
                max_len,
                i,
                facet,
            )? {
                chosen = Some(rl);
            }
        }
        if chosen.is_none() {
            if let Some(tl) = typical_len {
                if Some(tl) != raw_len
                    && confirm_star_len(
                        &mut ConfirmCtx {
                            src,
                            head_bytes: &head_bytes,
                            head_len,
                            gl_default,
                            guard_len_opt: &mut guard_len_opt,
                            pack_id_opt: &mut pack_id_opt,
                            budget: &mut budget,
                        },
                        star_start,
                        tl,
                        max_len,
                        i,
                        facet,
                    )?
                {
                    chosen = Some(tl);
                }
            }
        }
        if chosen.is_none() {
            if let Some(cl) = find_guard_for_star(
                src,
                star_start,
                max_len,
                i,
                &head_bytes,
                pack_id_opt,
                &mut budget,
            ) {
                if confirm_star_len(
                    &mut ConfirmCtx {
                        src,
                        head_bytes: &head_bytes,
                        head_len,
                        gl_default,
                        guard_len_opt: &mut guard_len_opt,
                        pack_id_opt: &mut pack_id_opt,
                        budget: &mut budget,
                    },
                    star_start,
                    cl,
                    max_len,
                    i,
                    facet,
                )? {
                    chosen = Some(cl);
                }
            }
        }
        if chosen.is_none() {
            if let Some((_, seal_len, g_opt)) =
                seal_len_from_star_at(src, star_start, max_len, head_len, Some(facet), &mut budget)
            {
                let kt = crate::header::KEYSTONE_TRAILER_SIZE as u64;
                let mut opts = Vec::new();
                if let Some(gl) = g_opt {
                    opts.push(seal_len + gl);
                } else if let Some(gl) = guard_len_opt {
                    opts.push(seal_len + gl);
                    opts.push(seal_len + kt + gl);
                } else {
                    opts.push(seal_len + gl_default);
                    opts.push(seal_len);
                    opts.push(seal_len + kt + gl_default);
                    opts.push(seal_len + kt);
                }
                for cand in opts {
                    if cand <= max_len
                        && next_star_plausible(
                            src,
                            star_start + cand,
                            trailer_off,
                            &facets[(i + 1) as usize],
                            i + 1 == n - 1,
                            &mut budget,
                        )
                        && confirm_star_len(
                            &mut ConfirmCtx {
                                src,
                                head_bytes: &head_bytes,
                                head_len,
                                gl_default,
                                guard_len_opt: &mut guard_len_opt,
                                pack_id_opt: &mut pack_id_opt,
                                budget: &mut budget,
                            },
                            star_start,
                            cand,
                            max_len,
                            i,
                            facet,
                        )?
                    {
                        chosen = Some(cand);
                        break;
                    }
                }
            }
        }

        if budget.exhausted() && chosen.is_none() {
            return Err(budget_exceeded(i, n));
        }
        let Some(cand_len) = chosen else {
            return Err(msg(format!(
                "work pack framing damaged at star {i} of {n} \
                 (could not locate or confirm star {i} against SGFC); refusing"
            )));
        };
        if raw_len != Some(cand_len) {
            rebuilt_framing = true;
        }
        if typical_len.is_none() {
            typical_len = Some(cand_len);
        }
        stars.push((star_start, cand_len));
        pos = star_start + cand_len;
    }

    if pos != trailer_off {
        return Err(msg(
            "work pack framing rebuild did not align with the SGFC facet list; refusing",
        ));
    }

    let mut l = PackLayout {
        head,
        head_bytes,
        stars,
        trailer_off,
        trailer: Trailer::Valid(facets),
        source,
        guarded: guard_len_opt.is_some(),
        pack_id: pack_id_opt.unwrap_or([0u8; 16]),
        facets_rebuilt: false,
        framing_rebuilt: rebuilt_framing,
    };
    apply_guards(src, &mut l)?;
    cross_check(src, &mut l);
    Ok(l)
}

/// Lay out a pack, rebuilding its head and/or length framing when needed
/// (see the module docs). Decoder-only; the `.sg1` format is unchanged.
///
/// Returns the most specific error when the pack cannot be rebuilt, so
/// refusals name the real damaged part. Existing errors (I/O, a torn star
/// later in mend, a wrong key) are not rewritten here.
pub(crate) fn layout<S: Src>(src: &mut S) -> Result<PackLayout> {
    let mut l = match strict(src) {
        Ok(l) => l,
        Err(e) => {
            // If the head itself parsed cleanly, try rebuilding framing with it.
            let size = src.size();
            let mut hb = vec![0u8; MAX_HEAD.min(size) as usize];
            if src.read_at(0, &mut hb).is_ok() {
                let mut cur = std::io::Cursor::new(&hb[..]);
                if let Ok(head) = read_head(&mut cur) {
                    let hl = cur.position() as usize;
                    hb.truncate(hl);
                    if read_head_from_bytes(&hb).is_ok() && head.stars > 0 {
                        if let Ok(r) = try_rebuild_framing(src, &hb, HeadSource::Intact) {
                            return Ok(r);
                        }
                    }
                }
            }
            return from_guards(src)
                .or_else(|_| from_facets(src))
                .map_err(|_| e);
        }
    };
    // Guarded pack: the guards are authoritative for head, order and facets.
    let guarded = apply_guards(src, &mut l)?;
    if matches!(l.trailer, Trailer::Damaged) {
        // Damaged framing can strand the real SGFC list in the "trailer".
        if let Ok(r) = try_rebuild_framing(src, &l.head_bytes, l.source) {
            return Ok(r);
        }
        if let Ok(r) = from_guards(src).or_else(|_| from_facets(src)) {
            return Ok(r);
        }
        // A well-formed list still in the file means the failure is framing.
        // Old unguarded packs whose list is genuinely gone still open; mend
        // refuses the list.
        if find_facet_list(src).is_ok() {
            return Err(framing_or_trailer_error(src));
        }
        return Ok(l);
    }
    if guarded {
        return Ok(l);
    }
    cross_check(src, &mut l);
    Ok(l)
}

/// Lay out the pack at `path` (see [`layout`]).
pub(crate) fn layout_path(path: &Path) -> Result<PackLayout> {
    layout(&mut FileSrc::open(path)?)
}

/// Rebuild the layout of bytes that do not start with the SGWK magic but may be
/// a pack whose head is damaged (guards first, then the facet list).
pub(crate) fn recover_bytes(bytes: &[u8]) -> Option<PackLayout> {
    let mut src = MemSrc(bytes);
    from_guards(&mut src)
        .or_else(|_| from_facets(&mut src))
        .ok()
}

/// Like [`recover_bytes`] for a file on disk.
pub(crate) fn recover_path(path: &Path) -> Option<PackLayout> {
    let mut src = FileSrc::open(path).ok()?;
    from_guards(&mut src)
        .or_else(|_| from_facets(&mut src))
        .ok()
}

#[cfg(test)]
pub(crate) mod tests {
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
        let guarded = std::fs::read(&out).unwrap();
        // With guards (new packs) the whole name comes back from a guard copy.
        let mut bad = guarded.clone();
        bad[..4].fill(0);
        std::fs::write(&out, &bad).unwrap();
        assert_eq!(
            crate::work::payload_name(&out).unwrap(),
            "a-rather-long-file-name.bin"
        );
        // Without guards (packs written before them) only the facet list is left.
        let mut bad = strip_guards(&guarded);
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

    /// The same pack as written before guards existed: every star cut back to its seal.
    pub(crate) fn strip_guards(pack: &[u8]) -> Vec<u8> {
        let l = layout(&mut MemSrc(pack)).unwrap();
        assert!(l.guarded);
        let mut out = l.head_bytes.clone();
        for &(o, n) in &l.stars {
            let star = &pack[o as usize..(o + n) as usize];
            let seal = &star[..guard_of_star(star).unwrap().seal_len as usize];
            out.extend_from_slice(&(seal.len() as u64).to_le_bytes());
            out.extend_from_slice(seal);
        }
        out.extend_from_slice(&pack[l.trailer_off as usize..]);
        out
    }

    /// A new (guarded) pack of `plain()`, 4 stars of 64 KiB chunks.
    fn new_pack(dir: &Path, name: &str, pass: Option<&str>, mode: crate::Mode) -> Vec<u8> {
        let src = dir.join(name);
        std::fs::write(&src, plain()).unwrap();
        let out = dir.join("new.sg1");
        let (_, stars, is_work) = crate::work::inscribe_path(
            &src,
            &out,
            mode,
            pass,
            "",
            &[],
            64 * 1024,
            None,
            0,
            0,
            None,
        )
        .unwrap();
        assert!(is_work && stars == 4);
        std::fs::read(&out).unwrap()
    }

    fn star_ranges(pack: &[u8]) -> Vec<(usize, usize)> {
        layout(&mut MemSrc(pack))
            .unwrap()
            .stars
            .iter()
            .map(|&(o, n)| (o as usize, (o + n) as usize))
            .collect()
    }

    /// Mend `bytes` to a file; return (report, mended bytes).
    fn mend(dir: &Path, bytes: &[u8]) -> (crate::work::PackMendReport, Vec<u8>) {
        let p = dir.join("mend-in.sg1");
        let o = dir.join("mend-out.sg1");
        std::fs::write(&p, bytes).unwrap();
        let rep = mend_pack_path(&p, &o, false).unwrap();
        (rep, std::fs::read(&o).unwrap())
    }

    #[test]
    fn new_packs_carry_a_guard_per_star_that_old_readers_skip() {
        let dir = tmp("guard-shape");
        let pack = new_pack(&dir, "plain.bin", None, crate::Mode::Reflection);
        let l = layout(&mut MemSrc(&pack)).unwrap();
        assert!(l.guarded && l.source == HeadSource::Intact && !l.facets_rebuilt);
        let hl = l.head_bytes.len();
        // Same head, framing and facet list as before guards; only the stars grew.
        assert_eq!(l.head_bytes, fixture("pack-v2-reflection.sg1")[..hl]);
        for (i, &(o, n)) in l.stars.iter().enumerate() {
            let star = &pack[o as usize..(o + n) as usize];
            let g = guard_of_star(star).unwrap();
            assert_eq!((g.index as usize, g.star_off + 8), (i, o));
            assert_eq!(seal_part(star).len() as u64, g.seal_len);
            assert_eq!(g.head, l.head_bytes);
            // Space cost: 83 bytes + one copy of the head per star.
            assert_eq!(star.len() as u64 - g.seal_len, (GUARD_FIXED + hl) as u64);
            // What a pre-guard reader does with a star: it still opens and mends.
            let plain_part = crate::unseal_ex_keys(star, None, &[], &[]).unwrap();
            assert_eq!(
                plain_part.len() as u64,
                (65536u64).min(200_000 - 65536 * i as u64)
            );
            assert!(crate::pieces::mend_bytes(star).is_ok());
            assert!(!crate::work::star_torn(star));
        }
        // Stripping the guards gives the exact pre-guard layout.
        let old = strip_guards(&pack);
        let lo = layout(&mut MemSrc(&old)).unwrap();
        assert!(!lo.guarded && lo.source == HeadSource::Intact);
        assert_eq!(open(&dir, &old, None).unwrap(), plain());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn new_pack_head_damaged_at_every_offset_is_restored_byte_for_byte() {
        // With guards even the advisory fields (chunk size, overture) and long names
        // come back exactly.
        let dir = tmp("guard-every");
        let want = plain();
        let pack = new_pack(
            &dir,
            "a-rather-long-file-name.bin",
            None,
            crate::Mode::Reflection,
        );
        let hl = layout(&mut MemSrc(&pack)).unwrap().head_bytes.len();
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
                let (rep, fixed) = mend(&dir, &bad);
                assert_eq!(rep.head, HeadSource::Guard, "offset {i} way {how}");
                assert_eq!(fixed, pack, "offset {i} way {how}");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn head_and_facet_list_both_damaged_are_restored_from_guards() {
        let dir = tmp("guard-both");
        let want = plain();
        for (pass, mode) in [
            (None, crate::Mode::Reflection),
            (Some(PASS), crate::Mode::Seal),
        ] {
            let pack = new_pack(&dir, "plain.bin", pass, mode);
            let n = pack.len();
            let hl = layout(&mut MemSrc(&pack)).unwrap().head_bytes.len();
            // Facet list only.
            let mut f = pack.clone();
            f[n - 40..n - 8].fill(0x5a);
            let (rep, fixed) = mend(&dir, &f);
            assert!(rep.facets_rebuilt && rep.head == HeadSource::Intact);
            assert_eq!(fixed, pack);
            // Head wiped and the facet list's magic, count and digests damaged.
            let mut both = pack.clone();
            both[..hl].fill(0);
            both[n - 32 * 4 - 8..n - 32 * 4].fill(0xee);
            both[n - 7] ^= 0x80;
            assert_eq!(open(&dir, &both, pass).unwrap(), want);
            let (rep, fixed) = mend(&dir, &both);
            assert!(rep.facets_rebuilt && rep.head == HeadSource::Guard);
            assert_eq!(fixed, pack);
            // In-memory mend (folder packs) hands back the same repaired pack.
            let mut out = Vec::new();
            let m = mend_pack_to(&both, &mut out, pass, &[], &[]).unwrap();
            assert_eq!(out, want);
            assert_eq!(m.healed.unwrap(), pack);
            // Facet list cut off entirely: rebuilt and re-appended.
            let cut = &pack[..n - 32 * 4 - 8];
            let (rep, fixed) = mend(&dir, cut);
            assert!(rep.facets_rebuilt);
            assert_eq!(fixed, pack);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn any_one_intact_guard_is_enough_and_damaged_guards_are_rewritten() {
        let dir = tmp("guard-one");
        let pack = new_pack(&dir, "plain.bin", None, crate::Mode::Reflection);
        let sp = star_ranges(&pack);
        let hl = sp[0].0 - 8;
        let mut bad = pack.clone();
        bad[..hl].fill(0xff);
        for &(_, end) in &sp[..3] {
            bad[end - 20] ^= 0x04; // break the guards of stars 0, 1, 2 (inside their SHA-256)
        }
        assert_eq!(open(&dir, &bad, None).unwrap(), plain());
        let (rep, fixed) = mend(&dir, &bad);
        assert_eq!(rep.head, HeadSource::Guard);
        assert_eq!(fixed, pack, "head and the three guards rewritten exactly");
        // A pre-guard binary's mend heals star 0 into a bare seal (no guard), which
        // shifts every later star; the new reader still opens it, and a new mend
        // puts the guard back (byte-identical to the original).
        let mut shifted = pack[..hl].to_vec();
        for (i, &(a, b)) in sp.iter().enumerate() {
            let star = if i == 0 {
                seal_part(&pack[a..b])
            } else {
                &pack[a..b]
            };
            shifted.extend_from_slice(&(star.len() as u64).to_le_bytes());
            shifted.extend_from_slice(star);
        }
        shifted.extend_from_slice(&pack[sp[3].1..]);
        assert_eq!(open(&dir, &shifted, None).unwrap(), plain());
        let mut both = shifted.clone();
        both[..hl].fill(0);
        assert_eq!(open(&dir, &both, None).unwrap(), plain());
        let (rep, fixed) = mend(&dir, &shifted);
        assert_eq!((rep.guards_restored, rep.head), (1, HeadSource::Intact));
        assert_eq!(fixed, pack);
        assert_eq!(mend(&dir, &both).1, pack);
        // Every guard broken: the facet list rebuild still works (as for old packs).
        let mut none = pack.clone();
        none[..4].fill(0);
        for &(_, end) in &sp {
            none[end - 20] ^= 0x04;
        }
        assert_eq!(open(&dir, &none, None).unwrap(), plain());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn guarded_pack_bit_flips_in_stars_and_head_heal_together() {
        let dir = tmp("guard-flips");
        let pack = new_pack(&dir, "plain.bin", None, crate::Mode::Seal);
        let sp = star_ranges(&pack);
        let mut bad = pack.clone();
        bad[2] ^= 0x10; // magic
        bad[13] ^= 0x01; // total
        for &(a, b) in &sp {
            let mid = a + (b - a) / 2;
            bad[mid] ^= 0x20;
            bad[mid + 1000] ^= 0x01;
        }
        let (rep, fixed) = mend(&dir, &bad);
        assert_eq!(rep.head, HeadSource::Guard);
        assert_eq!(rep.mended, vec![0, 1, 2, 3]);
        assert_eq!(fixed, pack);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn guarded_pack_swapped_spliced_or_truncated_is_refused() {
        let dir = tmp("guard-refuse");
        let pack = new_pack(&dir, "plain.bin", None, crate::Mode::Reflection);
        let other = {
            let src = dir.join("other.bin");
            std::fs::write(&src, plain().iter().map(|b| b ^ 1).collect::<Vec<u8>>()).unwrap();
            let out = dir.join("other.sg1");
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
            std::fs::read(&out).unwrap()
        };
        let sp = star_ranges(&pack);
        let osp = star_ranges(&other);
        let hl = sp[0].0 - 8;
        let refused = |bytes: &[u8], what: &str| {
            assert!(open(&dir, bytes, None).is_err(), "{what}: unseal");
            assert!(
                mend_pack_to(bytes, &mut Vec::new(), None, &[], &[]).is_err(),
                "{what}: memory mend"
            );
            let p = dir.join("r.sg1");
            std::fs::write(&p, bytes).unwrap();
            assert!(
                mend_pack_path(&p, &dir.join("r-out.sg1"), false).is_err(),
                "{what}"
            );
            assert!(!dir.join("r-out.sg1").exists());
        };
        // Swapped equal-length stars, with and without the head and facet list.
        for (a, b) in [(0, 1), (1, 2)] {
            let mut sw = pack.clone();
            let first = pack[sp[a].0..sp[a].1].to_vec();
            sw[sp[a].0..sp[a].1].copy_from_slice(&pack[sp[b].0..sp[b].1]);
            sw[sp[b].0..sp[b].1].copy_from_slice(&first);
            refused(&sw, "swap");
            let n = sw.len();
            sw[..hl].fill(0);
            sw[n - 50] ^= 1;
            refused(&sw, "swap, head and facets damaged");
        }
        // A star spliced in from another pack of the same shape.
        assert_eq!(sp[1].1 - sp[1].0, osp[1].1 - osp[1].0);
        let mut sp1 = pack.clone();
        sp1[sp[1].0..sp[1].1].copy_from_slice(&other[osp[1].0..osp[1].1]);
        refused(&sp1, "splice");
        // Same name and size (so the same head), different content, and the facet
        // list damaged so it cannot catch the splice: the pack id still does.
        let twin_dir = dir.join("twin");
        std::fs::create_dir_all(&twin_dir).unwrap();
        let src = twin_dir.join("plain.bin");
        std::fs::write(&src, plain().iter().map(|b| b ^ 1).collect::<Vec<u8>>()).unwrap();
        let tout = twin_dir.join("t.sg1");
        crate::work::inscribe_path(
            &src,
            &tout,
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
        let twin = std::fs::read(&tout).unwrap();
        let tsp = star_ranges(&twin);
        assert_eq!(twin[..hl], pack[..hl], "same head");
        assert_eq!(tsp[2].1 - tsp[2].0, sp[2].1 - sp[2].0);
        let mut tw = pack.clone();
        tw[sp[2].0..sp[2].1].copy_from_slice(&twin[tsp[2].0..tsp[2].1]);
        let n = tw.len();
        tw[n - 32 * 4 - 8] = b'X';
        refused(&tw, "twin splice, facet list damaged");
        let e = open(&dir, &tw, None).unwrap_err();
        assert!(e.contains("different packs"), "{e}");
        // Truncated at many points, head intact or wiped.
        let n = pack.len();
        for wipe in [false, true] {
            let mut t = pack.clone();
            if wipe {
                t[..hl].fill(0);
            }
            for cut in [
                hl,
                sp[0].1,
                sp[0].1 + 4,
                sp[1].1 - 10,
                sp[2].1 + 8,
                sp[3].1 - 1,
            ] {
                assert!(
                    open(&dir, &t[..cut], None).is_err(),
                    "cut {cut} wipe {wipe}"
                );
            }
            // Only (part of) the facet list cut off: every star is there and checks
            // out on its own, so the file comes back whole.
            for cut in [sp[3].1, n - 1] {
                assert_eq!(open(&dir, &t[..cut], None).unwrap(), plain(), "cut {cut}");
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn guarded_pack_wrong_key_fails_closed_and_keyless_mend_works() {
        let dir = tmp("guard-key");
        let pack = new_pack(&dir, "plain.bin", Some(PASS), crate::Mode::Seal);
        let mut bad = pack.clone();
        bad[..4].fill(0);
        assert!(open(&dir, &bad, Some("wrong")).is_err());
        assert!(open(&dir, &bad, None).is_err());
        // mend needs no key and restores the head.
        let (rep, fixed) = mend(&dir, &bad);
        assert_eq!(rep.head, HeadSource::Guard);
        assert_eq!(fixed, pack);
        assert_eq!(open(&dir, &bad, Some(PASS)).unwrap(), plain());
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn cdc_pack_is_guarded_too() {
        let dir = tmp("guard-cdc");
        let mut x = 0x9e3779b97f4a7c15u64;
        let data: Vec<u8> = (0..10_000_000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        let src = dir.join("c.bin");
        std::fs::write(&src, &data).unwrap();
        let out = dir.join("c.sg1");
        let (_, stars, is_work) = crate::work::inscribe_path(
            &src,
            &out,
            crate::Mode::Reflection,
            None,
            "",
            &[],
            0,
            None,
            0,
            0,
            Some(crate::cdc::DEDUP),
        )
        .unwrap();
        assert!(is_work && stars >= 2, "{stars}");
        let pack = std::fs::read(&out).unwrap();
        assert!(layout(&mut MemSrc(&pack)).unwrap().guarded);
        let mut bad = pack.clone();
        bad[..30].fill(0);
        assert_eq!(open(&dir, &bad, None).unwrap(), data);
        let (rep, fixed) = mend(&dir, &bad);
        assert_eq!(rep.head, HeadSource::Guard);
        assert_eq!(fixed, pack);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn framing_rebuild_heals_zeroed_flipped_and_sector_wiped_lengths_and_stays_fail_closed() {
        let dir = tmp("framing-rebuild");
        let want = plain();
        let pack = new_pack(&dir, "plain.bin", None, crate::Mode::Reflection);
        let sp = star_ranges(&pack);

        // 1. Zeroed u64 length on star 1, plus front 4 KiB of star 1 wiped
        //    (primary + keystone). The exact mend path must restore it.
        let mut bad = pack.clone();
        let len_off = sp[1].0 - 8;
        bad[len_off..sp[1].0 + 3600].fill(0);
        assert_eq!(open(&dir, &bad, None).unwrap(), want);
        let (rep, fixed) = mend(&dir, &bad);
        assert!(
            rep.framing_rebuilt,
            "framing_rebuilt must be set on this path"
        );
        assert_eq!(rep.mended, vec![1]);
        assert_eq!(fixed, pack);
        assert!(crate::work::pack_mend_summary(&rep).contains("length framing rebuilt"));

        // 2. Bit-flipped u64 length on star 2 (-4096), which used to blame SGFC.
        let mut flipped = pack.clone();
        let orig_len = u64::from_le_bytes(flipped[sp[2].0 - 8..sp[2].0].try_into().unwrap());
        flipped[sp[2].0 - 8..sp[2].0].copy_from_slice(&(orig_len - 4096).to_le_bytes());
        assert_eq!(open(&dir, &flipped, None).unwrap(), want);
        let (rep2, fixed2) = mend(&dir, &flipped);
        assert!(rep2.framing_rebuilt);
        assert_eq!(fixed2, pack);

        // 3. Framing damaged on star 1 + star 1 guard wiped; confirmed by Ember + SGFC.
        let mut no_guard = pack.clone();
        no_guard[sp[1].0 - 8..sp[1].0].fill(0);
        no_guard[sp[1].1 - 30..sp[1].1].fill(0);
        assert_eq!(open(&dir, &no_guard, None).unwrap(), want);
        let (rep3, fixed3) = mend(&dir, &no_guard);
        assert!(rep3.framing_rebuilt);
        assert_eq!(rep3.guards_restored, 1);
        assert_eq!(fixed3, pack);

        // 4. Fail closed: framing damaged + swapped stars must still be refused.
        let mut sw = pack.clone();
        let a = pack[sp[1].0..sp[1].1].to_vec();
        sw[sp[1].0..sp[1].1].copy_from_slice(&pack[sp[2].0..sp[2].1]);
        sw[sp[2].0..sp[2].1].copy_from_slice(&a);
        sw[sp[1].0 - 8..sp[1].0].fill(0);
        assert!(open(&dir, &sw, None).is_err());
        let p = dir.join("sw.sg1");
        std::fs::write(&p, &sw).unwrap();
        assert!(mend_pack_path(&p, &dir.join("sw-out.sg1"), false).is_err());

        // 5. Fail closed: framing damaged + SGFC digest corrupted on that star must be refused.
        let mut bad_sgfc = pack.clone();
        bad_sgfc[sp[1].0 - 8..sp[1].0].fill(0);
        bad_sgfc[pack.len() - 32 * 3 - 1] ^= 0xff; // flip digest of star 1 in SGFC
        assert!(open(&dir, &bad_sgfc, None).is_err());
        std::fs::write(&p, &bad_sgfc).unwrap();
        assert!(mend_pack_path(&p, &dir.join("sgfc-out.sg1"), false).is_err());

        // 6. Fail closed: framing damaged + truncated pack must be refused naming framing/star.
        let mut trunc = pack[..sp[2].1 - 100].to_vec();
        trunc[sp[1].0 - 8..sp[1].0].fill(0);
        std::fs::write(&p, &trunc).unwrap();
        let e = mend_pack_path(&p, &dir.join("tr-out.sg1"), false)
            .unwrap_err()
            .to_string();
        assert!(e.contains("framing") || e.contains("truncated"), "{e}");

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn framing_rebuild_wrong_key_on_encrypted_pack_stays_fail_closed() {
        let dir = tmp("framing-wrong-key");
        let want = plain();
        let pack = new_pack(&dir, "enc.bin", Some(PASS), crate::Mode::Seal);
        let sp = star_ranges(&pack);
        let mut bad = pack.clone();
        bad[sp[1].0 - 8..sp[1].0].fill(0);
        assert_eq!(open(&dir, &bad, Some(PASS)).unwrap(), want);
        let err = open(&dir, &bad, Some("wrong-pass")).unwrap_err();
        assert!(
            err.contains("pass")
                || err.contains("key")
                || err.contains("refusing")
                || err.contains("wrong")
                || err.contains("decrypt")
                || err.contains("MAC")
                || err.contains("seal")
                || err.contains("auth")
                || err.contains("Ward")
                || err.contains("Warded"),
            "wrong key must fail closed, got: {err}"
        );
        let (rep, fixed) = mend(&dir, &bad);
        assert!(rep.framing_rebuilt);
        assert_eq!(fixed, pack);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn framing_rebuild_crafted_worst_case_scan_is_bounded() {
        let dir = tmp("framing-worst");
        let pack = new_pack(&dir, "plain.bin", None, crate::Mode::Seal);
        let hl = head_len(&pack);
        let sgfc_at = pack.windows(4).rposition(|w| w == b"SGFC").expect("SGFC");
        let mut crafted = pack[..hl].to_vec();
        crafted.extend_from_slice(&0u64.to_le_bytes());
        let fill = 32 * 1024 * 1024;
        crafted.reserve(fill + pack.len() - sgfc_at);
        for _ in 0..(fill / 4) {
            crafted.extend_from_slice(b"SGHG");
        }
        crafted.extend_from_slice(&pack[sgfc_at..]);

        let start = std::time::Instant::now();
        let mut src = MemSrc(&crafted);
        match layout(&mut src) {
            Ok(_) => panic!("crafted magic-filled pack must be refused"),
            Err(e) => {
                let s = e.to_string();
                assert!(
                    s.contains("refusing")
                        || s.contains("scan limit")
                        || s.contains("framing")
                        || s.contains("budget"),
                    "refusal must name the bound or framing, got: {s}"
                );
            }
        }
        let dt = start.elapsed();
        assert!(
            dt <= std::time::Duration::from_secs(FRAMING_SCAN_SECS + 2),
            "worst-case scan took {dt:?}, cap is {FRAMING_SCAN_SECS}s + 2s slack"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn framing_rebuild_seeded_property_saved_bytes_equal_original_or_refused() {
        let dir = tmp("framing-prop");
        let want = plain();
        let pack = new_pack(&dir, "plain.bin", None, crate::Mode::Reflection);
        let sp = star_ranges(&pack);
        assert!(sp.len() >= 3, "plain() must produce at least 3 stars");
        for seed in 0u64..24 {
            let kind = seed % 6;
            let mut bad = pack.clone();
            let (start, end) = sp[1];
            match kind {
                0 => bad[start - 8..start].fill(0),
                1 => {
                    let orig = u64::from_le_bytes(bad[start - 8..start].try_into().unwrap());
                    let bit = 1u64 << (seed % 63);
                    bad[start - 8..start].copy_from_slice(&(orig ^ bit).to_le_bytes());
                }
                2 => {
                    let hi = (start + 4096).min(bad.len());
                    bad[start - 8..hi].fill(0);
                }
                3 => {
                    let forged = ((end - start) as u64 / 2).max(MIN_STAR_BYTES);
                    bad[start - 8..start].copy_from_slice(&forged.to_le_bytes());
                }
                4 => {
                    bad[start - 8..start].fill(0);
                    let cut = (end - 50).max(start + MIN_STAR_BYTES as usize);
                    bad.truncate(cut);
                }
                5 => {
                    let (s2, e2) = sp[2];
                    if e2 - s2 == end - start {
                        let a = bad[start..end].to_vec();
                        bad[start..end].copy_from_slice(&pack[s2..e2]);
                        bad[s2..e2].copy_from_slice(&a);
                    }
                    bad[start - 8..start].fill(0);
                }
                _ => unreachable!(),
            }
            match open(&dir, &bad, None) {
                Ok(got) => {
                    assert_eq!(got, want, "seed {seed} kind {kind}: wrong bytes");
                    let (_rep, fixed) = mend(&dir, &bad);
                    if kind != 5 {
                        assert_eq!(fixed, pack, "seed {seed} kind {kind}: mend bytes");
                    }
                }
                Err(s) => {
                    assert!(
                        s.contains("framing")
                            || s.contains("truncated")
                            || s.contains("refusing")
                            || s.contains("swapped")
                            || s.contains("out of place")
                            || s.contains("true-name")
                            || s.contains("facet")
                            || s.contains("star"),
                        "seed {seed} kind {kind}: refused without naming the part: {s}"
                    );
                    let p = dir.join(format!("p{seed}.sg1"));
                    std::fs::write(&p, &bad).unwrap();
                    assert!(
                        mend_pack_path(&p, &dir.join(format!("o{seed}.sg1")), false).is_err(),
                        "seed {seed} kind {kind}: mend must also refuse"
                    );
                }
            }
        }
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
