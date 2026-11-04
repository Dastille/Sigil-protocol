//! Scatter a .sg1 into piece files. Deluge adds extra (rateless) pieces.
//! Gather rebuilds a normal .sg1 from any k distinct pieces — originals or rain.

use crate::header::{
    locate_header, shard_stride, write_ember, write_header, GradedShard, Header, HEADER_SIZE,
    VOW_SIZE,
};
use crate::{header, merkle, rs, sha256, Result};
use std::fs;
use std::path::Path;

pub const PIECE_MAGIC: [u8; 4] = *b"SGPC";
const MAX_INDEX: usize = 254;

fn write_piece(dir: &Path, index: u8, n: u8, k: u8, map: &[u8], body: &[u8]) -> Result<()> {
    let mut out = Vec::new();
    out.extend_from_slice(&PIECE_MAGIC);
    out.push(1);
    out.push(index);
    out.push(n);
    out.push(k);
    out.extend_from_slice(&(map.len() as u32).to_le_bytes());
    out.extend_from_slice(map);
    out.extend_from_slice(&(body.len() as u32).to_le_bytes());
    out.extend_from_slice(body);
    fs::write(dir.join(format!("piece-{index:03}.sgp")), out)
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    Ok(())
}

fn pack_stride(hdr: &[u8], h: &Header, shard: &[u8], index: u8, vow: Option<&[u8]>) -> Vec<u8> {
    let mut body = Vec::new();
    if h.ember() {
        body.extend_from_slice(&write_ember(hdr, index));
    }
    if let Some(v) = vow {
        body.extend_from_slice(v);
    }
    body.extend_from_slice(shard);
    body.extend_from_slice(&crc32fast::hash(shard).to_le_bytes());
    body
}

fn shard_from_stride(h: &Header, body: &[u8]) -> Option<Vec<u8>> {
    let lead = if h.ember() { HEADER_SIZE } else { 0 } + if h.vow() { VOW_SIZE } else { 0 };
    let sl = h.shard_len as usize;
    if lead + sl + 4 > body.len() {
        return None;
    }
    let shard = body[lead..lead + sl].to_vec();
    let crc = u32::from_le_bytes(body[lead + sl..lead + sl + 4].try_into().ok()?);
    if crc32fast::hash(&shard) == crc {
        Some(shard)
    } else {
        None
    }
}

/// Write piece-000.sgp … into dir. Each piece carries a copy of the map so any k can Gather.
pub fn scatter(file: &[u8], dir: &Path) -> Result<u8> {
    deluge(file, 0, dir, false, None)
}

/// Extra rain pieces. `from` is the first new index (default: n).
/// Different people should pick different `from` so C gets mixed coupons.
pub fn deluge(file: &[u8], extra: u8, dir: &Path, only_rain: bool, from: Option<u8>) -> Result<u8> {
    if file.len() >= 4 && &file[0..4] == b"SGWK" {
        return Err(crate::Error::Msg(
            "this is a work pack of many Sigils. Deluge each star.sg1.".into(),
        ));
    }
    let (h, prefix, _) = locate_header(file)?;
    if h.mode() == crate::Mode::Glyph && extra > 0 {
        return Err(crate::Error::Msg(
            "Glyph has no rain. Use Reflection or Seal.".into(),
        ));
    }
    let stride = shard_stride(&h);
    let map = &file[..prefix.min(file.len())];
    fs::create_dir_all(dir).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let n = h.n as usize;
    let k = h.k as usize;
    let mut wrote = 0u8;
    if !only_rain {
        for i in 0..n {
            let off = prefix + i * stride;
            let body = if off + stride <= file.len() {
                file[off..off + stride].to_vec()
            } else {
                vec![0u8; stride]
            };
            write_piece(dir, i as u8, h.n, h.k, map, &body)?;
            wrote += 1;
        }
    }
    if extra > 0 && h.mode() != crate::Mode::Glyph {
        let live = header::gather_live_shards(file, &h, prefix);
        let mut parts: Vec<(usize, Vec<u8>)> = Vec::new();
        for (i, s) in live.iter().enumerate() {
            if let Some(sh) = s {
                parts.push((i, sh.clone()));
            }
        }
        if parts.len() < k {
            return Err(crate::Error::Msg(format!(
                "need {k} live pieces in the Sigil to rain more, have {}",
                parts.len()
            )));
        }
        let payload = rs::decode_indexed(&parts, k, h.folded_len as usize, h.version >= 2)?;
        let hdr = write_header(&h);
        let vow = if h.vow() && prefix >= VOW_SIZE {
            Some(&file[prefix - VOW_SIZE..prefix])
        } else {
            None
        };
        let start = from.map(|x| x as usize).unwrap_or(n).clamp(n, MAX_INDEX);
        let last = (start + extra as usize).min(MAX_INDEX + 1);
        for i in start..last {
            let path = dir.join(format!("piece-{i:03}.sgp"));
            if path.exists() {
                continue;
            }
            let shard = rs::encode_shard_index(&payload, k, i, h.version >= 2)?;
            let body = pack_stride(&hdr, &h, &shard, i as u8, vow);
            write_piece(dir, i as u8, h.n, h.k, map, &body)?;
            wrote += 1;
        }
    }
    let man = format!(
        "n={}\nk={}\nshard_len={}\nname={}\npieces={wrote}\n",
        h.n, h.k, h.shard_len, h.name
    );
    fs::write(dir.join("manifest.txt"), man).map_err(|e| crate::Error::Msg(e.to_string()))?;
    Ok(wrote)
}

pub const VESSEL: &str = "VESSEL";

/// How many distinct good pieces, and how many are required (k of n).
pub fn tally(dir: &Path) -> Result<(usize, usize, usize)> {
    let (shards, k, n, ..) = scan(dir)?;
    Ok((shards.len(), k, n))
}

pub fn write_vessel(dir: &Path, found: usize, k: usize) -> Result<()> {
    let body = format!("full\nfound={found}\nneed={k}\n");
    fs::write(dir.join(VESSEL), body).map_err(|e| crate::Error::Msg(e.to_string()))?;
    Ok(())
}

pub fn vessel_present(dir: &Path) -> bool {
    dir.join(VESSEL).is_file()
}

/// (data pieces by index, k, n, true-name digest, parity pieces by index).
type ScanResult = (
    Vec<(usize, Vec<u8>)>,
    usize,
    usize,
    Vec<u8>,
    Vec<(usize, Vec<u8>)>,
);

fn scan(dir: &Path) -> Result<ScanResult> {
    scan_dirs(&[dir])
}

/// One `.sgp` file as read from disk (header fields not yet trusted).
struct Candidate {
    file: String,
    index: usize,
    n: u8,
    k: u8,
    map: Vec<u8>,
    body: Vec<u8>,
}

fn read_candidate(path: &Path, file: String) -> Result<Option<Candidate>> {
    let raw = fs::read(path).map_err(|e| crate::Error::Msg(e.to_string()))?;
    if raw.len() < 16 || raw[0..4] != PIECE_MAGIC {
        return Ok(None);
    }
    let index = raw[5] as usize;
    let map_len = u32::from_le_bytes(raw[8..12].try_into().map_err(crate::short_field)?) as usize;
    let Some(map_end) = 12usize.checked_add(map_len) else {
        return Ok(None);
    };
    if map_end + 4 > raw.len() {
        return Ok(None);
    }
    let body_len = u32::from_le_bytes(
        raw[map_end..map_end + 4]
            .try_into()
            .map_err(crate::short_field)?,
    ) as usize;
    let start = map_end + 4;
    let Some(body_end) = start.checked_add(body_len) else {
        return Ok(None);
    };
    if body_end > raw.len() || index > MAX_INDEX {
        return Ok(None);
    }
    Ok(Some(Candidate {
        file,
        index,
        n: raw[6],
        k: raw[7],
        map: raw[12..map_end].to_vec(),
        body: raw[start..body_end].to_vec(),
    }))
}

/// Collect pieces from one or more folders (e.g. cold-USB `usb-*` dirs).
///
/// Every piece carries its own copy of the map, so pieces are grouped by the file
/// header their map decodes to. Pieces of more than one file are refused rather than
/// mixed. Within the file, a damaged copy of a piece never hides a good copy of the
/// same piece in another folder (or under another name): for each index the first
/// copy whose checksum holds is used. Folders are read in the order given and file
/// names in sorted order, so the result does not depend on directory listing order.
fn scan_dirs(dirs: &[&Path]) -> Result<ScanResult> {
    let mut cands: Vec<Candidate> = Vec::new();
    for dir in dirs {
        let rd = match fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        let mut names: Vec<std::path::PathBuf> = Vec::new();
        for ent in rd {
            let ent = ent.map_err(|e| crate::Error::Msg(e.to_string()))?;
            if ent.file_name().to_string_lossy().ends_with(".sgp") {
                names.push(ent.path());
            }
        }
        names.sort();
        for path in names {
            if let Some(c) = read_candidate(&path, path.display().to_string())? {
                cands.push(c);
            }
        }
    }
    if cands.is_empty() {
        return Err(crate::Error::Msg("no pieces yet".into()));
    }
    // Group by decoded header: (header bytes, header, member indices).
    let mut groups: Vec<(Vec<u8>, Header, Vec<usize>)> = Vec::new();
    for (ci, c) in cands.iter().enumerate() {
        let Ok((h, _, _)) = locate_header(&c.map) else {
            continue;
        };
        if h.n != c.n || h.k != c.k {
            continue;
        }
        let key = write_header(&h);
        match groups.iter_mut().find(|(gk, _, _)| *gk == key) {
            Some((_, _, members)) => members.push(ci),
            None => groups.push((key, h, vec![ci])),
        }
    }
    if groups.len() > 1 {
        let files: Vec<String> = groups
            .iter()
            .map(|(_, h, m)| {
                let first = m.first().map(|&i| cands[i].file.as_str()).unwrap_or("?");
                format!("{:?} ({} piece(s), e.g. {first})", h.name, m.len())
            })
            .collect();
        return Err(crate::Error::Msg(format!(
            "these folders hold pieces of more than one file: {}. Gather each file from its own pieces.",
            files.join("; ")
        )));
    }
    let Some((_, h, members)) = groups.into_iter().next() else {
        return Err(crate::Error::Msg(
            "no readable piece map: every piece header is damaged".into(),
        ));
    };
    // Most common exact map copy among this file's pieces (first seen wins a tie).
    let mut maps: Vec<(&[u8], usize)> = Vec::new();
    for &ci in &members {
        let m = cands[ci].map.as_slice();
        match maps.iter_mut().find(|(x, _)| *x == m) {
            Some((_, count)) => *count += 1,
            None => maps.push((m, 1)),
        }
    }
    let mut best: Option<(&[u8], usize)> = None;
    for &(m, count) in &maps {
        if best.is_none_or(|(_, c)| count > c) {
            best = Some((m, count));
        }
    }
    let map = best.map(|(m, _)| m.to_vec()).unwrap_or_default();
    let mut shards: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut parts: Vec<(usize, Vec<u8>)> = Vec::new();
    for &ci in &members {
        let c = &cands[ci];
        if shards.iter().any(|(i, _)| *i == c.index) {
            continue;
        }
        if let Some(sh) = shard_from_stride(&h, &c.body) {
            shards.push((c.index, sh));
            parts.retain(|(i, _)| *i != c.index);
            parts.push((c.index, c.body.clone()));
        } else if !parts.iter().any(|(i, _)| *i == c.index) {
            // Kept only as a last resort (Glyph copies the raw stride); a later good
            // copy of the same index replaces it.
            parts.push((c.index, c.body.clone()));
        }
    }
    let k = h.k as usize;
    let n = h.n as usize;
    if k == 0 || n == 0 {
        return Err(crate::Error::Msg("piece headers missing k/n".into()));
    }
    Ok((shards, k, n, map, parts))
}

/// Rewrite a healthy classic mark (keystone / SGTO / vow / ember / shards) from payload shards.
fn assemble_mark(
    h: &Header,
    shards: &[Vec<u8>],
    vow: Option<&[u8]>,
    sgto: Option<&[u8]>,
) -> Vec<u8> {
    let hdr = write_header(h);
    let mut out = if h.keystone() {
        header::wrap_keystone(&hdr)
    } else {
        hdr.clone()
    };
    if let Some(s) = sgto {
        out.extend_from_slice(s);
    }
    if let Some(v) = vow {
        out.extend_from_slice(v);
    }
    for (i, s) in shards.iter().enumerate() {
        let body = pack_stride(&hdr, h, s, i as u8, vow);
        out.extend_from_slice(&body);
    }
    out
}

fn sgto_from_prefix(file: &[u8], h: &Header) -> Option<Vec<u8>> {
    header::sgto_slice(h, file).map(|s| s.to_vec())
}

fn vow_from_prefix(file: &[u8], h: &Header, prefix: usize) -> Option<Vec<u8>> {
    if !h.vow() {
        return None;
    }
    let vow_off = prefix.saturating_sub(VOW_SIZE);
    if let Some(slice) = file.get(vow_off..vow_off + VOW_SIZE) {
        if header::read_vow(slice).is_some() {
            return Some(slice.to_vec());
        }
    }
    // Ember stride may still carry the Vow when the front map is gone.
    let ember_vow = prefix + HEADER_SIZE;
    if let Some(slice) = file.get(ember_vow..ember_vow + VOW_SIZE) {
        if header::read_vow(slice).is_some() {
            return Some(slice.to_vec());
        }
    }
    None
}

/// In-place mend: rebuild a healthy .sg1 from ≥k CRC-good shards in a torn mark.
/// Glyph requires every shard; Seal/Reflection need any k.
pub fn mend_bytes(file: &[u8]) -> Result<Vec<u8>> {
    mend_bytes_ex(file, false).map(|(bytes, _)| bytes)
}

/// Soft-capable mend. When `soft`, falls back after hard CRC-kill fails to
/// per-column errors-and-erasures repair ([`rs::decode_column_errors`], which
/// fixes scattered bit flips), then graded Soft shards + GMD-lite. Every path
/// is accepted only if the Merkle binding (and true name when not encrypted)
/// match. Returns `(mark, used_soft_salvage)`.
pub fn mend_bytes_ex(file: &[u8], soft: bool) -> Result<(Vec<u8>, bool)> {
    if file.len() >= 4 && &file[0..4] == b"SGWK" {
        return Err(crate::Error::Msg(
            "this is a work pack of many Sigils; use `sigil mend` on the file (work::mend_pack_path)".into(),
        ));
    }
    let (h, prefix, _) = locate_header(file)?;
    header::ensure_single_seal(file, &h, prefix)?;
    let n = h.n as usize;
    let k = h.k as usize;
    let vow = vow_from_prefix(file, &h, prefix);
    let sgto = sgto_from_prefix(file, &h);

    if h.mode() == crate::Mode::Glyph {
        let live = header::gather_live_shards(file, &h, prefix);
        let live_count = live.iter().filter(|s| s.is_some()).count();
        let Some(shards) = live.into_iter().collect::<Option<Vec<Vec<u8>>>>() else {
            return Err(crate::Error::Msg(format!(
                "Glyph needs all {n} shards, have {live_count}"
            )));
        };
        return Ok((
            assemble_mark(&h, &shards, vow.as_deref(), sgto.as_deref()),
            false,
        ));
    }

    let live = header::gather_live_shards(file, &h, prefix);
    let live_count = live.iter().filter(|s| s.is_some()).count();
    if live_count >= k {
        let parts: Vec<(usize, Vec<u8>)> = live
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|b| (i, b.clone())))
            .collect();
        match rs::decode_indexed(&parts, k, h.folded_len as usize, h.version >= 2) {
            Ok(payload) if accept_folded(&h, &payload) => {
                let shards: Vec<Vec<u8>> = (0..n)
                    .map(|i| rs::encode_shard_index(&payload, k, i, h.version >= 2))
                    .collect::<Result<_>>()?;
                return Ok((
                    assemble_mark(&h, &shards, vow.as_deref(), sgto.as_deref()),
                    false,
                ));
            }
            Ok(_) if !soft => {
                return Err(crate::Error::Msg(
                    "hard mend failed true-name/Merkle check (try --soft)".into(),
                ));
            }
            Err(e) if !soft => return Err(e),
            _ => {}
        }
    } else if !soft {
        return Err(crate::Error::Msg(format!(
            "need {k} live shards to mend, have {live_count}"
        )));
    }

    // Soft path: keep CRC-failed bodies, stripe GMD-lite, gate on true-name/Merkle.
    let graded = header::gather_graded_shards(file, &h, prefix);
    let present = graded.iter().filter(|g| g.is_present()).count();
    if present < k {
        return Err(crate::Error::Msg(format!(
            "soft mend needs {k} shards with some data, have {present} (hard live {live_count})"
        )));
    }
    // Column repair first: decode every byte column on its own (errors and
    // erasures), so scattered bit flips cost a symbol each, not a whole shard.
    // Same acceptance gate as every other path (Merkle binding + true name).
    let systematic = h.version >= 2;
    let bodies: Vec<(usize, Vec<u8>)> = graded
        .iter()
        .enumerate()
        .filter_map(|(i, g)| g.body().map(|b| (i, b.to_vec())))
        .collect();
    if let Ok((payload, _rep)) = rs::decode_column_errors(
        &bodies,
        k,
        h.shard_len as usize,
        h.folded_len as usize,
        systematic,
    ) {
        if accept_folded(&h, &payload) {
            let shards: Vec<Vec<u8>> = (0..n)
                .map(|i| rs::encode_shard_index(&payload, k, i, systematic))
                .collect::<Result<_>>()?;
            return Ok((
                assemble_mark(&h, &shards, vow.as_deref(), sgto.as_deref()),
                true,
            ));
        }
    }
    drop(bodies);

    let parts: Vec<rs::SoftPart> = graded
        .iter()
        .enumerate()
        .filter_map(|(i, g)| match g {
            GradedShard::Hard(b) => Some(rs::SoftPart {
                index: i,
                body: b.clone(),
                hard: true,
            }),
            GradedShard::Soft(b) => Some(rs::SoftPart {
                index: i,
                body: b.clone(),
                hard: false,
            }),
            GradedShard::Missing => None,
        })
        .collect();

    let payload = rs::decode_soft(&parts, k, n, h.folded_len as usize, systematic, |p| {
        accept_folded(&h, p)
    })?;
    let shards: Vec<Vec<u8>> = (0..n)
        .map(|i| rs::encode_shard_index(&payload, k, i, systematic))
        .collect::<Result<_>>()?;
    Ok((
        assemble_mark(&h, &shards, vow.as_deref(), sgto.as_deref()),
        true,
    ))
}

/// What a multi-copy mend found: how many good shards each copy held and how many
/// distinct good shards they held together.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CopiesMend {
    /// The rebuilt, healthy `.sg1` bytes.
    pub bytes: Vec<u8>,
    /// Good (CRC-checked) shards found in each copy, in the order given.
    pub live_per_copy: Vec<usize>,
    /// Whether each copy's own front header (or a Keystone spare) was readable.
    pub header_per_copy: Vec<bool>,
    /// Distinct good shards across all copies.
    pub live_combined: usize,
    /// Shards in the Sigil.
    pub n: usize,
    /// Shards needed to rebuild it.
    pub k: usize,
}

/// Rebuild one healthy `.sg1` from two or more damaged copies of the **same** Sigil.
///
/// Each copy may have lost different shards; the good shards are pooled by index and
/// the result is decoded as usual. Fails closed:
/// - fewer than two copies, or no copy with a readable header, is refused;
/// - copies whose readable headers differ are refused (not copies of one Sigil);
/// - two copies holding different CRC-good bytes for the same shard are refused;
/// - work packs, folder packs and stacked seals are refused (mend them one at a time);
/// - the rebuilt payload must match the header's Merkle root (and, when not
///   encrypted, the plaintext length and SHA-256), or nothing is returned.
///
/// A copy whose own header is unreadable still contributes shards, located with the
/// header taken from another copy; its shards are still CRC-checked and the
/// result still has to pass the Merkle check.
pub fn mend_copies(copies: &[&[u8]]) -> Result<CopiesMend> {
    if copies.len() < 2 {
        return Err(crate::Error::Msg(
            "multi-copy mend needs at least two copies".into(),
        ));
    }
    for c in copies {
        if c.len() >= 4 && &c[0..4] == b"SGWK" {
            return Err(crate::Error::Msg(
                "a large-file work pack can only be mended one copy at a time".into(),
            ));
        }
    }
    let located: Vec<Option<(Header, usize)>> = copies
        .iter()
        .map(|c| locate_header(c).ok().map(|(h, p, _)| (h, p)))
        .collect();
    let Some((ref_idx, (h, _))) = located
        .iter()
        .enumerate()
        .find_map(|(i, l)| l.as_ref().map(|v| (i, v.clone())))
    else {
        return Err(crate::Error::Msg(
            "no copy has a readable header; cannot tell where the shards are".into(),
        ));
    };
    let ref_hdr = write_header(&h);
    for (i, l) in located.iter().enumerate() {
        if let Some((hi, prefix)) = l {
            if write_header(hi) != ref_hdr {
                return Err(crate::Error::Msg(format!(
                    "copy {} is not a copy of the same Sigil as copy {} (headers differ); refusing to mix them",
                    i + 1,
                    ref_idx + 1
                )));
            }
            header::ensure_single_seal(copies[i], hi, *prefix)?;
        }
    }
    let n = h.n as usize;
    let k = h.k as usize;
    let mut pooled: Vec<Option<Vec<u8>>> = vec![None; n];
    let mut live_per_copy = Vec::with_capacity(copies.len());
    let mut vow: Option<Vec<u8>> = None;
    let mut sgto: Option<Vec<u8>> = None;
    for (i, c) in copies.iter().enumerate() {
        let prefix = match &located[i] {
            Some((_, p)) => *p,
            None => header::body_prefix_file(&h, c),
        };
        let live = header::gather_live_shards(c, &h, prefix);
        live_per_copy.push(live.iter().filter(|s| s.is_some()).count());
        for (slot, shard) in pooled.iter_mut().zip(live) {
            let Some(shard) = shard else { continue };
            match slot {
                Some(have) if *have != shard => {
                    return Err(crate::Error::Msg(format!(
                        "copy {} holds a different shard than an earlier copy (same position, both pass their checks); refusing to mix them",
                        i + 1
                    )));
                }
                Some(_) => {}
                None => *slot = Some(shard),
            }
        }
        if vow.is_none() {
            vow = vow_from_prefix(c, &h, prefix);
        }
        if sgto.is_none() {
            sgto = sgto_from_prefix(c, &h);
        }
    }
    let live_combined = pooled.iter().filter(|s| s.is_some()).count();
    let header_per_copy: Vec<bool> = located.iter().map(|l| l.is_some()).collect();
    let need = if h.mode() == crate::Mode::Glyph { n } else { k };
    if live_combined < need {
        return Err(crate::Error::Msg(format!(
            "NOT recoverable from these copies: together they hold {live_combined} good shards, {need} needed"
        )));
    }
    let systematic = h.version >= 2;
    let shards: Vec<Vec<u8>> = if h.mode() == crate::Mode::Glyph {
        let all: Vec<Vec<u8>> = pooled.into_iter().flatten().collect();
        let leaves: Vec<[u8; 32]> = all.iter().map(|s| sha256(s)).collect();
        if merkle::merkle_root(&leaves) != h.merkle {
            return Err(crate::Error::Msg(
                "pooled shards fail the Merkle check; refusing to write a result".into(),
            ));
        }
        all
    } else {
        let parts: Vec<(usize, Vec<u8>)> = pooled
            .into_iter()
            .enumerate()
            .filter_map(|(i, s)| s.map(|b| (i, b)))
            .collect();
        let payload = rs::decode_indexed(&parts, k, h.folded_len as usize, systematic)?;
        if !accept_folded(&h, &payload) {
            return Err(crate::Error::Msg(
                "pooled shards fail the true-name/Merkle check; refusing to write a result".into(),
            ));
        }
        (0..n)
            .map(|i| rs::encode_shard_index(&payload, k, i, systematic))
            .collect::<Result<_>>()?
    };
    Ok(CopiesMend {
        bytes: assemble_mark(&h, &shards, vow.as_deref(), sgto.as_deref()),
        live_per_copy,
        header_per_copy,
        live_combined,
        n,
        k,
    })
}

fn accept_folded(h: &Header, payload: &[u8]) -> bool {
    if payload.len() != h.folded_len as usize {
        return false;
    }
    let systematic = h.version >= 2;
    let n = h.n as usize;
    let k = h.k as usize;
    // A shape that cannot be re-encoded is not accepted (fail closed).
    let Ok(shards) = (0..n)
        .map(|i| rs::encode_shard_index(payload, k, i, systematic))
        .collect::<Result<Vec<Vec<u8>>>>()
    else {
        return false;
    };
    let leaves: Vec<[u8; 32]> = shards.iter().map(|s| sha256(s)).collect();
    if merkle::merkle_root(&leaves) != h.merkle {
        return false;
    }
    if !h.encrypted() {
        let unfolded = crate::chaos::unfold(payload, &h.salt);
        let plain = if h.compressed() {
            match inflate_local(&unfolded) {
                Ok(p) => p,
                Err(_) => return false,
            }
        } else {
            unfolded
        };
        if plain.len() != h.orig_len as usize || sha256(&plain) != h.digest {
            return false;
        }
    }
    true
}

fn inflate_local(data: &[u8]) -> Result<Vec<u8>> {
    use flate2::read::DeflateDecoder;
    use std::io::Read;
    let mut d = DeflateDecoder::new(data);
    let mut out = Vec::new();
    d.read_to_end(&mut out)
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    Ok(out)
}

pub fn gather(dir: &Path) -> Result<Vec<u8>> {
    gather_dirs(&[dir])
}

/// Rebuild a healthy .sg1 from pieces spread across several folders.
pub fn gather_dirs(dirs: &[&Path]) -> Result<Vec<u8>> {
    let (mut shards, k, n, map, parts) = scan_dirs(dirs)?;
    let (h, _, _) = locate_header(&map)?;
    if h.mode() == crate::Mode::Glyph {
        if shards.len() < n {
            return Err(crate::Error::Msg(format!(
                "Glyph needs all {n} pieces, have {}",
                shards.len()
            )));
        }
        shards.sort_by_key(|(i, _)| *i);
        let mut out = map;
        let stride = shard_stride(&h);
        for i in 0..n {
            if let Some((_, body)) = parts.iter().find(|(idx, _)| *idx == i) {
                out.extend_from_slice(body);
            } else {
                out.extend_from_slice(&vec![0u8; stride]);
            }
        }
        return Ok(out);
    }
    if shards.len() < k {
        return Err(crate::Error::Msg(format!(
            "need {k} pieces, have {}",
            shards.len()
        )));
    }
    let payload = rs::decode_indexed(&shards, k, h.folded_len as usize, h.version >= 2)?;
    let prefix = header::body_prefix_file(&h, &map);
    let vow = if h.vow() && map.len() >= prefix {
        if prefix >= VOW_SIZE {
            Some(map[prefix - VOW_SIZE..prefix].to_vec())
        } else {
            None
        }
    } else {
        None
    };
    let rebuilt: Vec<Vec<u8>> = (0..n)
        .map(|i| rs::encode_shard_index(&payload, k, i, h.version >= 2))
        .collect::<Result<_>>()?;
    Ok(assemble_mark(
        &h,
        &rebuilt,
        vow.as_deref(),
        sgto_from_prefix(&map, &h).as_deref(),
    ))
}

#[cfg(test)]
mod scan_tests {
    use super::*;

    fn tmp(tag: &str) -> crate::staging::TempDir {
        crate::staging::TempDir::create(tag).unwrap()
    }

    fn mark(seed: u8) -> Vec<u8> {
        let data: Vec<u8> = (0..5000u32).map(|i| (i as u8) ^ seed).collect();
        crate::seal(&data, crate::Mode::Seal, None, "scan.bin", false).unwrap()
    }

    fn flip_shard(path: &Path) {
        let mut raw = fs::read(path).unwrap();
        let last = raw.len() - 10;
        raw[last] ^= 0xFF;
        fs::write(path, raw).unwrap();
    }

    /// A damaged copy in the first folder must not hide a good copy in the second.
    #[test]
    fn damaged_first_copy_does_not_hide_good_copy() {
        let file = mark(1);
        let ta = tmp("a");
        let tb = tmp("b");
        let (a, b) = (ta.path().to_path_buf(), tb.path().to_path_buf());
        scatter(&file, &a).unwrap();
        scatter(&file, &b).unwrap();
        let (h, _, _) = locate_header(&file).unwrap();
        let k = h.k as usize;
        // Remove all but k pieces from b, damage the same k in a, drop the rest of a.
        let mut kept = 0;
        for i in 0..h.n as usize {
            let name = format!("piece-{i:03}.sgp");
            if kept < k {
                flip_shard(&a.join(&name));
                kept += 1;
            } else {
                fs::remove_file(a.join(&name)).unwrap();
                fs::remove_file(b.join(&name)).unwrap();
            }
        }
        // a alone: every piece damaged, gather fails closed.
        assert!(gather_dirs(&[a.as_path()]).is_err());
        // a then b: b's good copies are used.
        let back = gather_dirs(&[a.as_path(), b.as_path()]).unwrap();
        assert_eq!(
            crate::unseal(&back, None).unwrap(),
            crate::unseal(&file, None).unwrap()
        );
        let (shards, ..) = scan_dirs(&[a.as_path(), b.as_path()]).unwrap();
        assert_eq!(shards.len(), k);
    }

    /// Pieces of two different files are refused, not mixed.
    #[test]
    fn pieces_of_two_files_are_refused() {
        let ta = tmp("one");
        let tb = tmp("two");
        let (a, b) = (ta.path().to_path_buf(), tb.path().to_path_buf());
        scatter(&mark(1), &a).unwrap();
        scatter(&mark(2), &b).unwrap();
        let e = gather_dirs(&[a.as_path(), b.as_path()])
            .unwrap_err()
            .to_string();
        assert!(e.contains("more than one file"), "{e}");
    }

    /// A piece whose map copy is unreadable is skipped; the others still gather.
    #[test]
    fn piece_with_damaged_map_is_skipped() {
        let file = mark(3);
        let ta = tmp("map");
        let a = ta.path().to_path_buf();
        scatter(&file, &a).unwrap();
        let p = a.join("piece-000.sgp");
        let mut raw = fs::read(&p).unwrap();
        for b in raw.iter_mut().skip(12).take(64) {
            *b = 0;
        }
        fs::write(&p, raw).unwrap();
        let back = gather_dirs(&[a.as_path()]).unwrap();
        assert_eq!(
            crate::unseal(&back, None).unwrap(),
            crate::unseal(&file, None).unwrap()
        );
    }

    /// Truncated piece files are ignored, never read past their end.
    #[test]
    fn truncated_piece_is_ignored() {
        let file = mark(4);
        let ta = tmp("trunc");
        let a = ta.path().to_path_buf();
        scatter(&file, &a).unwrap();
        let p = a.join("piece-001.sgp");
        let raw = fs::read(&p).unwrap();
        fs::write(&p, &raw[..raw.len() / 2]).unwrap();
        let back = gather_dirs(&[a.as_path()]).unwrap();
        assert_eq!(
            crate::unseal(&back, None).unwrap(),
            crate::unseal(&file, None).unwrap()
        );
    }
}
