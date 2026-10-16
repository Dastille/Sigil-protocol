//! Scatter a .sg1 into piece files. Deluge adds extra (rateless) pieces.
//! Gather rebuilds a normal .sg1 from any k distinct pieces — originals or rain.

use crate::header::{
    locate_header, shard_stride, write_ember, write_header, GradedShard, Header,
    HEADER_SIZE, VOW_SIZE,
};
use crate::{header, merkle, rs, sha256, Result};
use std::fs;
use std::path::Path;

pub const PIECE_MAGIC: [u8; 4] = *b"SGPC";
const MAX_INDEX: usize = 254;

fn write_piece(
    dir: &Path,
    index: u8,
    n: u8,
    k: u8,
    map: &[u8],
    body: &[u8],
) -> Result<()> {
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
    fs::write(dir.join(format!("piece-{index:03}.sgp")), out).map_err(|e| crate::Error::Msg(e.to_string()))?;
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
            "this is a work pack of many marks. Deluge each star.sg1.".into(),
        ));
    }
    let (h, prefix, _) = locate_header(file)?;
    if h.mode() == crate::Mode::Glyph {
        if extra > 0 {
            return Err(crate::Error::Msg(
                "Glyph has no rain. Use Reflection or Seal.".into(),
            ));
        }
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
                "need {k} live pieces in the mark to rain more, have {}",
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
            let shard = rs::encode_shard_index(&payload, k, i, h.version >= 2);
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

fn scan(dir: &Path) -> Result<(Vec<(usize, Vec<u8>)>, usize, usize, Vec<u8>, Vec<(usize, Vec<u8>)>)> {
    scan_dirs(&[dir])
}

/// Collect pieces from one or more folders (e.g. cold-USB `usb-*` dirs).
fn scan_dirs(dirs: &[&Path]) -> Result<(Vec<(usize, Vec<u8>)>, usize, usize, Vec<u8>, Vec<(usize, Vec<u8>)>)> {
    let mut parts: Vec<(usize, Vec<u8>)> = Vec::new();
    let mut map: Option<Vec<u8>> = None;
    let mut k = 0u8;
    let mut n = 0u8;
    for dir in dirs {
        let rd = match fs::read_dir(dir) {
            Ok(rd) => rd,
            Err(_) => continue,
        };
        for ent in rd {
            let ent = ent.map_err(|e| crate::Error::Msg(e.to_string()))?;
            let name = ent.file_name();
            let name = name.to_string_lossy();
            if !name.ends_with(".sgp") {
                continue;
            }
            let raw = fs::read(ent.path()).map_err(|e| crate::Error::Msg(e.to_string()))?;
            if raw.len() < 16 || raw[0..4] != PIECE_MAGIC {
                continue;
            }
            let index = raw[5] as usize;
            n = raw[6];
            k = raw[7];
            let map_len = u32::from_le_bytes(raw[8..12].try_into().unwrap()) as usize;
            if 12 + map_len + 4 > raw.len() {
                continue;
            }
            if map.is_none() {
                map = Some(raw[12..12 + map_len].to_vec());
            }
            let body_len = u32::from_le_bytes(raw[12 + map_len..16 + map_len].try_into().unwrap()) as usize;
            let start = 16 + map_len;
            if start + body_len > raw.len() {
                continue;
            }
            let body = raw[start..start + body_len].to_vec();
            if index <= MAX_INDEX && !parts.iter().any(|(i, _)| *i == index) {
                parts.push((index, body));
            }
        }
    }
    let map = map.ok_or(crate::Error::Msg("no pieces yet".into()))?;
    let k = k as usize;
    let n = n as usize;
    if k == 0 || n == 0 {
        return Err(crate::Error::Msg("piece headers missing k/n".into()));
    }
    let (h, _, _) = locate_header(&map)?;
    let mut shards: Vec<(usize, Vec<u8>)> = Vec::new();
    for (index, body) in &parts {
        if let Some(sh) = shard_from_stride(&h, body) {
            if !shards.iter().any(|(i, _)| i == index) {
                shards.push((*index, sh));
            }
        }
    }
    Ok((shards, k, n, map, parts))
}

/// Rewrite a healthy classic mark (keystone / SGTO / vow / ember / shards) from payload shards.
fn assemble_mark(h: &Header, shards: &[Vec<u8>], vow: Option<&[u8]>, sgto: Option<&[u8]>) -> Vec<u8> {
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

/// Soft-capable mend. When `soft`, falls back to graded Soft shards + GMD-lite
/// after hard CRC-kill fails. Returns `(mark, used_soft_salvage)`.
pub fn mend_bytes_ex(file: &[u8], soft: bool) -> Result<(Vec<u8>, bool)> {
    if file.len() >= 4 && &file[0..4] == b"SGWK" {
        return Err(crate::Error::Msg(
            "this is a work pack of many marks; use `sigil mend` on the file (work::mend_pack_path)".into(),
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
        if live.iter().any(|s| s.is_none()) {
            return Err(crate::Error::Msg(format!(
                "Glyph needs all {n} shards, have {live_count}"
            )));
        }
        let shards: Vec<Vec<u8>> = live.into_iter().map(|s| s.expect("checked")).collect();
        return Ok((assemble_mark(&h, &shards, vow.as_deref(), sgto.as_deref()), false));
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
                    .collect();
                return Ok((assemble_mark(&h, &shards, vow.as_deref(), sgto.as_deref()), false));
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

    let systematic = h.version >= 2;
    let payload = rs::decode_soft(
        &parts,
        k,
        n,
        h.folded_len as usize,
        systematic,
        |p| accept_folded(&h, p),
    )?;
    let shards: Vec<Vec<u8>> = (0..n)
        .map(|i| rs::encode_shard_index(&payload, k, i, systematic))
        .collect();
    Ok((assemble_mark(&h, &shards, vow.as_deref(), sgto.as_deref()), true))
}

fn accept_folded(h: &Header, payload: &[u8]) -> bool {
    if payload.len() != h.folded_len as usize {
        return false;
    }
    let systematic = h.version >= 2;
    let n = h.n as usize;
    let k = h.k as usize;
    let shards: Vec<Vec<u8>> = (0..n)
        .map(|i| rs::encode_shard_index(payload, k, i, systematic))
        .collect();
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
            return Err(crate::Error::Msg(format!("Glyph needs all {n} pieces, have {}", shards.len())));
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
        return Err(crate::Error::Msg(format!("need {k} pieces, have {}", shards.len())));
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
        .collect();
    Ok(assemble_mark(&h, &rebuilt, vow.as_deref(), sgto_from_prefix(&map, &h).as_deref()))
}
