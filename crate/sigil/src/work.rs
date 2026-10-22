//! Streamed work pack for files too big for one in-memory mark.
//! Magic SGWK. Each record is a complete .sg1 star of one chunk.

use crate::cdc::{self, ChunkRange, Profile as CdcProfile};
use crate::keys::{Identity, PublicIdentity};
use crate::packhead::{self, HeadSource, PackLayout, Src};
use crate::{seal_kn_to, unseal_ex_keys, Mode, Result, DEFAULT_PIECE};
use std::fs::File;
use std::io::{BufReader, BufWriter, Read, Seek, SeekFrom, Write};
use std::path::Path;

pub const WORK_MAGIC: [u8; 4] = *b"SGWK";
pub const DEFAULT_CHUNK: u32 = 4 * 1024 * 1024;
pub const OVERTURE: &str = "OVERTURE";
pub const DEFAULT_OVERTURE_MB: u32 = 64;

pub fn is_work_pack(path: &Path) -> bool {
    let mut mag = [0u8; 4];
    match File::open(path).and_then(|mut f| f.read_exact(&mut mag)) {
        Ok(()) => mag == WORK_MAGIC,
        Err(_) => false,
    }
}

/// New encrypted packs hide the name and total on the outside (v3 private label).
fn encrypting(pass: Option<&str>, recipients: &[PublicIdentity]) -> bool {
    pass.is_some_and(|p| !p.is_empty()) || !recipients.is_empty()
}

/// Name a chunk star carries (inside its ciphertext when encrypted): the whole
/// name on an encrypted pack's first star, `name.NNNN` otherwise.
fn star_name(name: &str, i: usize, enc: bool) -> String {
    if enc && i == 0 {
        name.to_string()
    } else {
        format!("{name}.{i:04}")
    }
}

/// Private-label options for chunk star `i`: the first star of an encrypted pack
/// records the pack's real total inside its ciphertext.
fn star_opts(i: usize, enc: bool, total: u64) -> crate::privacy::SealOpts {
    crate::privacy::SealOpts {
        group_total: if enc && i == 0 { total } else { 0 },
        ..Default::default()
    }
}

/// Outer head for a new pack: an encrypted pack shows no name and no total.
fn outer_head(name: &str, orig: u64, enc: bool) -> (String, u64) {
    if enc {
        (String::new(), 0)
    } else {
        (name.to_string(), orig)
    }
}

/// The pack's outer head hides its total (v3 encrypted pack).
pub fn total_hidden(head: &WorkHead) -> bool {
    head.orig_total == 0 && head.stars > 0
}

/// Per-star length to index with when the star's own label hides its size:
/// the chunk size (exact for every fixed-chunk star but the last).
fn star_len_for(h: &crate::Header, head_chunk: u32, remain: u64, hidden: bool) -> u32 {
    if h.private_label() {
        if hidden {
            head_chunk
        } else {
            remain.min(head_chunk as u64) as u32
        }
    } else {
        h.orig_len.min(if hidden { u64::MAX } else { remain }) as u32
    }
}

/// A chunk star matches its SGFC facet: the label's keyed fingerprint for a v3
/// star, the SHA-256 of the opened bytes for older stars.
fn facet_ok(star: &[u8], plain: &[u8], facet: &[u8; 32]) -> Result<bool> {
    let (h, _, _) = crate::locate_header(star)?;
    Ok(if h.private_label() {
        h.digest == *facet
    } else {
        crate::sha256(plain) == *facet
    })
}

/// Expected total after opening every star: the head's, or (hidden) the one
/// recorded inside the first star.
fn expect_total(head: &WorkHead, star0: Option<&crate::privacy::SealMeta>) -> Result<u64> {
    if !total_hidden(head) {
        return Ok(head.orig_total);
    }
    star0
        .map(|m| m.group_total)
        .ok_or_else(|| crate::Error::Msg("pack total hidden and first star unreadable".into()))
}

pub struct WorkHead {
    pub version: u8,
    pub chunk_size: u32,
    pub orig_total: u64,
    pub name: String,
    pub stars: u32,
    pub overture: u32,
}

pub fn choose_overture(stars: u32, orig: u64, chunk: u32, overture_mb: u32) -> u32 {
    if stars == 0 {
        return 0;
    }
    if overture_mb == 0 {
        return stars;
    }
    let want = (overture_mb as u64).saturating_mul(1024 * 1024).min(orig);
    let n = want.div_ceil(chunk.max(1) as u64).max(1) as u32;
    n.min(stars)
}

/// Parse an SGWK head (version 1 or 2) from the start of `r`.
pub(crate) fn read_head<R: Read>(r: &mut R) -> Result<WorkHead> {
    let mut mag = [0u8; 4];
    r.read_exact(&mut mag)
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    if mag != WORK_MAGIC {
        return Err(crate::Error::Msg("not a work pack (SGWK)".into()));
    }
    let mut one = [0u8; 1];
    r.read_exact(&mut one)
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    if one[0] != 1 && one[0] != 2 {
        return Err(crate::Error::Msg(format!(
            "unknown work version {}",
            one[0]
        )));
    }
    let ver = one[0];
    let mut buf4 = [0u8; 4];
    r.read_exact(&mut buf4)
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    let chunk_size = u32::from_le_bytes(buf4);
    let mut buf8 = [0u8; 8];
    r.read_exact(&mut buf8)
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    let orig_total = u64::from_le_bytes(buf8);
    r.read_exact(&mut one)
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    let mut name = vec![0u8; one[0] as usize];
    if !name.is_empty() {
        r.read_exact(&mut name)
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
    }
    r.read_exact(&mut buf4)
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    let stars = u32::from_le_bytes(buf4);
    let overture = if ver == 2 {
        r.read_exact(&mut buf4)
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        u32::from_le_bytes(buf4).min(stars).max(1)
    } else {
        choose_overture(stars, orig_total, chunk_size, DEFAULT_OVERTURE_MB)
    };
    Ok(WorkHead {
        version: ver,
        chunk_size,
        orig_total,
        name: String::from_utf8_lossy(&name).into_owned(),
        stars,
        overture,
    })
}

/// Inscribe any size: one .sg1 if it fits in one chunk, else an SGWK pack.
/// When `cdc` is set, FastCDC picks variable star boundaries (opt-in).
// Justification: each parameter is an independent user-facing seal option threaded
// straight from the CLI (mode, passphrase, covenant, geas, chunking, wards, recipients...).
// Bundling them into an options struct is a public-API refactor tracked separately;
// this PR keeps signatures stable.
#[allow(clippy::too_many_arguments)]
pub fn inscribe_path(
    input: &Path,
    output: &Path,
    mode: Mode,
    pass: Option<&str>,
    covenant: &str,
    geas: &[[u8; 32]],
    chunk: u32,
    shards: Option<u8>,
    piece_bytes: u32,
    overture_mb: u32,
    cdc: Option<CdcProfile>,
) -> Result<(u64, u32, bool)> {
    inscribe_path_to(
        input,
        output,
        mode,
        pass,
        covenant,
        geas,
        chunk,
        shards,
        piece_bytes,
        overture_mb,
        cdc,
        &[],
    )
}

/// Like `inscribe_path`, with optional encrypt-to recipients on every star.
// Justification: each parameter is an independent user-facing seal option threaded
// straight from the CLI (mode, passphrase, covenant, geas, chunking, wards, recipients...).
// Bundling them into an options struct is a public-API refactor tracked separately;
// this PR keeps signatures stable.
#[allow(clippy::too_many_arguments)]
pub fn inscribe_path_to(
    input: &Path,
    output: &Path,
    mode: Mode,
    pass: Option<&str>,
    covenant: &str,
    geas: &[[u8; 32]],
    chunk: u32,
    shards: Option<u8>,
    piece_bytes: u32,
    overture_mb: u32,
    cdc: Option<CdcProfile>,
    recipients: &[PublicIdentity],
) -> Result<(u64, u32, bool)> {
    let meta = std::fs::metadata(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let orig = meta.len();
    let piece_bytes = if piece_bytes == 0 {
        DEFAULT_PIECE
    } else {
        piece_bytes
    };
    let name = input
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("file")
        .to_string();

    let ranges: Vec<ChunkRange> = if let Some(profile) = cdc {
        let data = std::fs::read(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
        let r = cdc::chunk_ranges(&data, profile);
        // Drop the full buffer; re-read per star below for large files would be better,
        // but we already hold `data` — seal from slices of it.
        return inscribe_ranges(
            &data,
            &name,
            output,
            mode,
            pass,
            covenant,
            geas,
            shards,
            piece_bytes,
            overture_mb,
            &r,
            profile.max as u32,
            recipients,
        );
    } else {
        let chunk = chunk.max(64 * 1024);
        if orig <= chunk as u64 {
            let data = std::fs::read(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
            let out = seal_kn_to(
                &data,
                mode,
                pass,
                &name,
                false,
                covenant,
                geas,
                shards,
                piece_bytes,
                recipients,
            )?;
            std::fs::write(output, out).map_err(|e| crate::Error::Msg(e.to_string()))?;
            return Ok((orig, 1, false));
        }
        let mut r = Vec::new();
        let mut off = 0u64;
        while off < orig {
            let n = (orig - off).min(chunk as u64) as usize;
            r.push(ChunkRange {
                offset: off as usize,
                length: n,
            });
            off += n as u64;
        }
        r
    };

    // Fixed chunking path: stream from disk (no full read).
    let chunk = chunk.max(64 * 1024);
    let stars = ranges.len() as u32;
    let overture = choose_overture(stars, orig, chunk, overture_mb);
    let mut reader =
        BufReader::new(File::open(input).map_err(|e| crate::Error::Msg(e.to_string()))?);
    let enc = encrypting(pass, recipients);
    let (outer_name, outer_total) = outer_head(&name, orig, enc);
    let head_bytes = packhead::head_to_bytes(&WorkHead {
        version: 2,
        chunk_size: chunk,
        orig_total: outer_total,
        name: outer_name,
        stars,
        overture,
    });
    let mut writer =
        BufWriter::new(File::create(output).map_err(|e| crate::Error::Msg(e.to_string()))?);
    writer
        .write_all(&head_bytes)
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    let mut pos = head_bytes.len() as u64;
    let pack_id = packhead::new_pack_id()?;
    let mut buf = vec![0u8; chunk as usize];
    let mut facets = Vec::new();
    for (i, range) in ranges.iter().enumerate() {
        let n = range.length;
        reader
            .read_exact(&mut buf[..n])
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        let sealed = crate::seal_kn_to_opts(
            &buf[..n],
            mode,
            pass,
            &star_name(&name, i, enc),
            false,
            covenant,
            geas,
            shards,
            piece_bytes,
            recipients,
            &star_opts(i, enc, orig),
        )?;
        pos = write_star(&mut writer, pos, i as u32, &sealed, &head_bytes, &pack_id)?;
        if let Ok((h, _, _)) = crate::locate_header(&sealed) {
            facets.push(h.digest);
        } else {
            facets.push([0u8; 32]);
        }
    }
    writer
        .write_all(b"SGFC")
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    writer
        .write_all(&(facets.len() as u32).to_le_bytes())
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    for d in &facets {
        writer
            .write_all(d)
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
    }
    writer
        .flush()
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    Ok((orig, stars, true))
}

/// The SGFC facet list for `facets`.
fn facet_trailer(facets: &[[u8; 32]]) -> Vec<u8> {
    let mut t = Vec::with_capacity(8 + 32 * facets.len());
    t.extend_from_slice(b"SGFC");
    t.extend_from_slice(&(facets.len() as u32).to_le_bytes());
    for d in facets {
        t.extend_from_slice(d);
    }
    t
}

/// Write star `index` at file offset `pos`: its 8-byte length, its seal, then a
/// pack-head guard (copy of the head + index + offset, see `packhead`). Returns
/// the offset after it.
fn write_star<W: Write>(
    w: &mut W,
    pos: u64,
    index: u32,
    sealed: &[u8],
    head_bytes: &[u8],
    pack_id: &[u8; 16],
) -> Result<u64> {
    let io = |e: std::io::Error| crate::Error::Msg(e.to_string());
    let guard = packhead::guard_bytes(index, pos, sealed.len() as u64, pack_id, head_bytes);
    let len = (sealed.len() + guard.len()) as u64;
    w.write_all(&len.to_le_bytes()).map_err(io)?;
    w.write_all(sealed).map_err(io)?;
    w.write_all(&guard).map_err(io)?;
    Ok(pos + 8 + len)
}

// Justification: each parameter is an independent user-facing seal option threaded
// straight from the CLI (mode, passphrase, covenant, geas, chunking, wards, recipients...).
// Bundling them into an options struct is a public-API refactor tracked separately;
// this PR keeps signatures stable.
#[allow(clippy::too_many_arguments)]
fn inscribe_ranges(
    data: &[u8],
    name: &str,
    output: &Path,
    mode: Mode,
    pass: Option<&str>,
    covenant: &str,
    geas: &[[u8; 32]],
    shards: Option<u8>,
    piece_bytes: u32,
    overture_mb: u32,
    ranges: &[ChunkRange],
    header_chunk: u32,
    recipients: &[PublicIdentity],
) -> Result<(u64, u32, bool)> {
    let orig = data.len() as u64;
    if ranges.len() <= 1 {
        let slice = if ranges.is_empty() {
            data
        } else {
            &data[ranges[0].offset..ranges[0].end()]
        };
        let out = seal_kn_to(
            slice,
            mode,
            pass,
            name,
            false,
            covenant,
            geas,
            shards,
            piece_bytes,
            recipients,
        )?;
        std::fs::write(output, out).map_err(|e| crate::Error::Msg(e.to_string()))?;
        return Ok((orig, 1, false));
    }
    let stars = ranges.len() as u32;
    let chunk = header_chunk.max(64 * 1024);
    let overture = choose_overture(stars, orig, chunk, overture_mb);
    let enc = encrypting(pass, recipients);
    let (outer_name, outer_total) = outer_head(name, orig, enc);
    let head_bytes = packhead::head_to_bytes(&WorkHead {
        version: 2,
        chunk_size: chunk,
        orig_total: outer_total,
        name: outer_name,
        stars,
        overture,
    });
    let mut writer =
        BufWriter::new(File::create(output).map_err(|e| crate::Error::Msg(e.to_string()))?);
    writer
        .write_all(&head_bytes)
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    let mut pos = head_bytes.len() as u64;
    let pack_id = packhead::new_pack_id()?;
    let mut facets = Vec::new();
    for (i, range) in ranges.iter().enumerate() {
        let slice = &data[range.offset..range.end()];
        let sealed = crate::seal_kn_to_opts(
            slice,
            mode,
            pass,
            &star_name(name, i, enc),
            false,
            covenant,
            geas,
            shards,
            piece_bytes,
            recipients,
            &star_opts(i, enc, orig),
        )?;
        pos = write_star(&mut writer, pos, i as u32, &sealed, &head_bytes, &pack_id)?;
        if let Ok((h, _, _)) = crate::locate_header(&sealed) {
            facets.push(h.digest);
        } else {
            facets.push([0u8; 32]);
        }
    }
    writer
        .write_all(b"SGFC")
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    writer
        .write_all(&(facets.len() as u32).to_le_bytes())
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    for d in &facets {
        writer
            .write_all(d)
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
    }
    writer
        .flush()
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    Ok((orig, stars, true))
}

pub struct Facet {
    pub index: u32,
    pub orig_off: u64,
    pub orig_len: u32,
    pub digest: [u8; 32],
}

/// Chunk true names from the SGFC trailer, or by walking stars.
pub fn read_facet_digests(input: &Path) -> Result<Vec<[u8; 32]>> {
    let mut f = File::open(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let len = f
        .metadata()
        .map_err(|e| crate::Error::Msg(e.to_string()))?
        .len();
    let head = read_head(&mut f)?;
    let n = head.stars as u64;
    let trailer = 4 + 4 + 32 * n;
    if len >= trailer && f.seek(SeekFrom::End(-(trailer as i64))).is_ok() {
        let mut mag = [0u8; 4];
        if f.read_exact(&mut mag).is_ok() && mag == *b"SGFC" {
            let mut nb = [0u8; 4];
            if f.read_exact(&mut nb).is_ok() {
                let cnt = u32::from_le_bytes(nb);
                if cnt == head.stars {
                    let mut out = Vec::with_capacity(cnt as usize);
                    let mut ok = true;
                    for _ in 0..cnt {
                        let mut d = [0u8; 32];
                        if f.read_exact(&mut d).is_err() {
                            ok = false;
                            break;
                        }
                        out.push(d);
                    }
                    if ok {
                        return Ok(out);
                    }
                }
            }
        }
    }
    Ok(scry_facets(input)?.into_iter().map(|f| f.digest).collect())
}

/// Bao-style slice list: each work-pack star is a checkable 4 MiB facet.
pub fn scry_facets(input: &Path) -> Result<Vec<Facet>> {
    let mut reader =
        BufReader::new(File::open(input).map_err(|e| crate::Error::Msg(e.to_string()))?);
    let head = read_head(&mut reader)?;
    let mut out = Vec::new();
    let mut remain = head.orig_total;
    let mut orig_off = 0u64;
    for i in 0..head.stars {
        let mut lenb = [0u8; 8];
        reader
            .read_exact(&mut lenb)
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        let len = u64::from_le_bytes(lenb) as usize;
        let mut star = vec![0u8; len];
        reader
            .read_exact(&mut star)
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        let (digest, orig_len) = match crate::locate_header(&star) {
            Ok((h, _, _)) => (
                h.digest,
                star_len_for(&h, head.chunk_size, remain, total_hidden(&head)),
            ),
            Err(_) => ([0u8; 32], remain.min(head.chunk_size as u64) as u32),
        };
        out.push(Facet {
            index: i,
            orig_off,
            orig_len,
            digest,
        });
        orig_off += orig_len as u64;
        remain = remain.saturating_sub(orig_len as u64);
    }
    Ok(out)
}

#[derive(Clone)]
pub struct StarLoc {
    pub index: u32,
    pub file_off: u64,
    pub star_len: u64,
    pub orig_off: u64,
    pub orig_len: u32,
}

/// Locate every chunk star of a pack (stops quietly at a partly copied tail).
///
/// When the pack head does not parse, the head is rebuilt from the facet list
/// and the stars' own headers (see `packhead`); if that fails too, the original
/// error is returned.
pub fn index_pack(input: &Path) -> Result<(WorkHead, Vec<StarLoc>)> {
    let mut f = File::open(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let head = match read_head(&mut f) {
        Ok(h) => h,
        Err(e) => {
            return match packhead::layout_path(input) {
                Ok(l) => index_from_layout(input, l),
                Err(_) => Err(e),
            }
        }
    };
    let mut loc = Vec::new();
    let mut remain = head.orig_total;
    let mut orig_off = 0u64;
    for i in 0..head.stars {
        let mut lenb = [0u8; 8];
        if f.read_exact(&mut lenb).is_err() {
            break;
        }
        let star_len = u64::from_le_bytes(lenb);
        let file_off = match f.stream_position() {
            Ok(o) => o,
            Err(_) => break,
        };
        // Read enough of the star to parse the header (CDC lengths vary).
        let peek_n = (star_len as usize).min(crate::header::KEYSTONE_SPAN + 64);
        let mut peek = vec![0u8; peek_n];
        if f.read_exact(&mut peek).is_err() {
            break;
        }
        let orig_len = crate::locate_header(&peek)
            .map(|(h, _, _)| star_len_for(&h, head.chunk_size, remain, total_hidden(&head)))
            .unwrap_or(remain.min(head.chunk_size as u64) as u32);
        let leftover = star_len as i64 - peek_n as i64;
        if leftover > 0 && std::io::Seek::seek(&mut f, SeekFrom::Current(leftover)).is_err() {
            break;
        }
        loc.push(StarLoc {
            index: i,
            file_off,
            star_len,
            orig_off,
            orig_len,
        });
        orig_off += orig_len as u64;
        remain = remain.saturating_sub(orig_len as u64);
    }
    Ok((head, loc))
}

/// Like [`index_pack`], with exact offsets for a pack whose head hides its total
/// (v3 encrypted): opens the first star for the real total. Every star but the last
/// is then taken as `chunk_size` long (true for fixed chunking); readers that slice
/// by these offsets must check each opened star's length ([`StarLoc::orig_len`]).
/// A total that cannot be tiled that way (CDC packs) opens every star to measure it.
pub fn index_pack_keys(
    input: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    identities: &[Identity],
) -> Result<(WorkHead, Vec<StarLoc>)> {
    let (mut head, mut locs) = index_pack(input)?;
    if !total_hidden(&head) || locs.is_empty() {
        return Ok((head, locs));
    }
    let total = payload_label_keys(input, pass, companions, identities)?
        .map(|(_, t)| t)
        .ok_or_else(|| crate::Error::Msg("this pack is locked: give its key".into()))?;
    let n = locs.len() as u64;
    let chunk = head.chunk_size as u64;
    let fixed_last = total.checked_sub((n - 1) * chunk);
    let lens: Vec<u64> = match fixed_last {
        Some(last) if last > 0 && last <= chunk => (0..n)
            .map(|i| if i + 1 == n { last } else { chunk })
            .collect(),
        _ => {
            let mut v = Vec::with_capacity(locs.len());
            for l in &locs {
                v.push(unseal_star_at_keys(input, l, pass, companions, identities)?.len() as u64);
            }
            v
        }
    };
    let mut off = 0u64;
    for (l, len) in locs.iter_mut().zip(lens) {
        l.orig_off = off;
        l.orig_len = u32::try_from(len).map_err(|_| crate::Error::Msg("star too large".into()))?;
        off += len;
    }
    head.orig_total = total;
    Ok((head, locs))
}

/// Star locations from a (possibly rebuilt) layout.
fn index_from_layout(input: &Path, l: PackLayout) -> Result<(WorkHead, Vec<StarLoc>)> {
    let mut src = packhead::FileSrc::open(input)?;
    let mut loc = Vec::with_capacity(l.stars.len());
    let mut remain = l.head.orig_total;
    let mut orig_off = 0u64;
    for (i, &(file_off, star_len)) in l.stars.iter().enumerate() {
        let mut peek = vec![0u8; star_len.min(crate::header::KEYSTONE_SPAN as u64 + 64) as usize];
        src.read_at(file_off, &mut peek)?;
        let orig_len = crate::locate_header(&peek)
            .map(|(h, _, _)| star_len_for(&h, l.head.chunk_size, remain, total_hidden(&l.head)))
            .unwrap_or(remain.min(l.head.chunk_size as u64) as u32);
        loc.push(StarLoc {
            index: i as u32,
            file_off,
            star_len,
            orig_off,
            orig_len,
        });
        orig_off += orig_len as u64;
        remain = remain.saturating_sub(orig_len as u64);
    }
    Ok((l.head, loc))
}

pub fn unseal_star_at(
    input: &Path,
    loc: &StarLoc,
    pass: Option<&str>,
    companions: &[Vec<u8>],
) -> Result<Vec<u8>> {
    unseal_star_at_keys(input, loc, pass, companions, &[])
}

pub fn unseal_star_at_keys(
    input: &Path,
    loc: &StarLoc,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    identities: &[Identity],
) -> Result<Vec<u8>> {
    let mut f = File::open(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
    std::io::Seek::seek(&mut f, SeekFrom::Start(loc.file_off))
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    let mut star = vec![0u8; loc.star_len as usize];
    f.read_exact(&mut star)
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    unseal_ex_keys(&star, pass, companions, identities)
}

pub fn unseal_range(
    input: &Path,
    output: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    from_star: u32,
    to_star: u32,
) -> Result<(u64, u32)> {
    unseal_range_keys(input, output, pass, companions, from_star, to_star, &[])
}

pub fn unseal_range_keys(
    input: &Path,
    output: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    from_star: u32,
    to_star: u32,
    identities: &[Identity],
) -> Result<(u64, u32)> {
    let (head, locs) = index_pack(input)?;
    if !locs
        .iter()
        .any(|l| l.index >= from_star && l.index <= to_star)
    {
        return Err(crate::Error::Msg(format!(
            "no slices in {from_star}..{to_star} (pack has 0..{})",
            head.stars.saturating_sub(1)
        )));
    }
    write_atomic(output, |writer| {
        let mut written = 0u64;
        let mut n = 0u32;
        for loc in &locs {
            if loc.index < from_star || loc.index > to_star {
                continue;
            }
            let plain = unseal_star_at_keys(input, loc, pass, companions, identities)?;
            writer
                .write_all(&plain)
                .map_err(|e| crate::Error::Msg(e.to_string()))?;
            written += plain.len() as u64;
            n += 1;
        }
        Ok((written, n))
    })
}

/// Write each star as its own .sg1 in a folder (for torrent/IPFS of large work).
// Justification: each parameter is an independent user-facing seal option threaded
// straight from the CLI (mode, passphrase, covenant, geas, chunking, wards, recipients...).
// Bundling them into an options struct is a public-API refactor tracked separately;
// this PR keeps signatures stable.
#[allow(clippy::too_many_arguments)]
pub fn inscribe_stars_dir(
    input: &Path,
    dir: &Path,
    mode: Mode,
    pass: Option<&str>,
    covenant: &str,
    geas: &[[u8; 32]],
    chunk: u32,
    shards: Option<u8>,
    piece_bytes: u32,
    overture_mb: u32,
    cdc: Option<CdcProfile>,
) -> Result<(u64, u32)> {
    inscribe_stars_dir_to(
        input,
        dir,
        mode,
        pass,
        covenant,
        geas,
        chunk,
        shards,
        piece_bytes,
        overture_mb,
        cdc,
        &[],
    )
}

/// Like `inscribe_stars_dir`, with optional encrypt-to recipients on every star.
// Justification: each parameter is an independent user-facing seal option threaded
// straight from the CLI (mode, passphrase, covenant, geas, chunking, wards, recipients...).
// Bundling them into an options struct is a public-API refactor tracked separately;
// this PR keeps signatures stable.
#[allow(clippy::too_many_arguments)]
pub fn inscribe_stars_dir_to(
    input: &Path,
    dir: &Path,
    mode: Mode,
    pass: Option<&str>,
    covenant: &str,
    geas: &[[u8; 32]],
    chunk: u32,
    shards: Option<u8>,
    piece_bytes: u32,
    overture_mb: u32,
    cdc: Option<CdcProfile>,
    recipients: &[PublicIdentity],
) -> Result<(u64, u32)> {
    std::fs::create_dir_all(dir).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let orig = std::fs::metadata(input)
        .map_err(|e| crate::Error::Msg(e.to_string()))?
        .len();
    let piece_bytes = if piece_bytes == 0 {
        DEFAULT_PIECE
    } else {
        piece_bytes
    };
    let name = input.file_name().and_then(|s| s.to_str()).unwrap_or("file");
    let enc = encrypting(pass, recipients);
    // An encrypted star folder's manifest shows no name or size (both are inside star 0).
    let (man_name, man_orig) = outer_head(name, orig, enc);
    if orig == 0 {
        let sealed = seal_kn_to(
            &[],
            mode,
            pass,
            name,
            false,
            covenant,
            geas,
            shards,
            piece_bytes,
            recipients,
        )?;
        std::fs::write(dir.join("star-0000.sg1"), sealed)
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        return Ok((0, 1));
    }
    if let Some(profile) = cdc {
        let data = std::fs::read(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
        let r = cdc::chunk_ranges(&data, profile);
        let stars = r.len().max(1) as u32;
        let chunk = profile.max as u32;
        for (i, range) in r.iter().enumerate() {
            let slice = &data[range.offset..range.end()];
            let sealed = crate::seal_kn_to_opts(
                slice,
                mode,
                pass,
                &star_name(name, i, enc),
                false,
                covenant,
                geas,
                shards,
                piece_bytes,
                recipients,
                &star_opts(i, enc, orig),
            )?;
            std::fs::write(dir.join(format!("star-{i:04}.sg1")), sealed)
                .map_err(|e| crate::Error::Msg(e.to_string()))?;
        }
        let ov = choose_overture(stars, orig, chunk, overture_mb);
        let man = format!(
            "name={man_name}\nstars={stars}\norig={man_orig}\nchunk={chunk}\ncdc={}\noverture={ov}\n",
            profile.name
        );
        std::fs::write(dir.join("manifest.txt"), man)
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        let mut boot =
            String::from("Overture — copy these first; you can start before the rest arrives.\n");
        for i in 0..ov {
            boot.push_str(&format!("star-{i:04}.sg1\n"));
        }
        std::fs::write(dir.join(OVERTURE), boot).map_err(|e| crate::Error::Msg(e.to_string()))?;
        return Ok((orig, stars));
    }
    let chunk = chunk.max(64 * 1024);
    let stars = orig.div_ceil(chunk as u64).max(1) as u32;
    let mut reader =
        BufReader::new(File::open(input).map_err(|e| crate::Error::Msg(e.to_string()))?);
    let mut buf = vec![0u8; chunk as usize];
    let mut remain = orig;
    let mut i = 0u32;
    while remain > 0 {
        let n = remain.min(chunk as u64) as usize;
        reader
            .read_exact(&mut buf[..n])
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        let sealed = crate::seal_kn_to_opts(
            &buf[..n],
            mode,
            pass,
            &star_name(name, i as usize, enc),
            false,
            covenant,
            geas,
            shards,
            piece_bytes,
            recipients,
            &star_opts(i as usize, enc, orig),
        )?;
        std::fs::write(dir.join(format!("star-{i:04}.sg1")), sealed)
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        remain -= n as u64;
        i += 1;
    }
    let ov = choose_overture(stars, orig, chunk, overture_mb);
    let man =
        format!("name={man_name}\nstars={stars}\norig={man_orig}\nchunk={chunk}\noverture={ov}\n");
    std::fs::write(dir.join("manifest.txt"), man).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let mut boot =
        String::from("Overture — copy these first; you can start before the rest arrives.\n");
    for i in 0..ov {
        boot.push_str(&format!("star-{i:04}.sg1\n"));
    }
    std::fs::write(dir.join(OVERTURE), boot).map_err(|e| crate::Error::Msg(e.to_string()))?;
    Ok((orig, stars))
}

/// Outcome of [`mend_pack_path`].
#[derive(Debug)]
pub struct PackMendReport {
    /// Number of chunk stars in the pack.
    pub stars: u32,
    /// Indexes of chunk stars that were healed.
    pub mended: Vec<u32>,
    /// At least one star needed soft-RS salvage.
    pub soft_used: bool,
    /// Every star's header true-name matched the SGFC facet trailer.
    pub facets_checked: bool,
    /// Size of the mended pack in bytes.
    pub bytes: u64,
    /// Where the pack head came from; anything but [`HeadSource::Intact`] means
    /// the head was damaged and the output carries a rebuilt one.
    pub head: HeadSource,
    /// The facet list was damaged and the output carries one rebuilt from the
    /// stars' own headers, in the order their guards prove (guarded packs only).
    pub facets_rebuilt: bool,
    /// Stars of a guarded pack whose guard was missing or damaged and has been
    /// written again (for example after a mend by a pre-guard binary).
    pub guards_restored: u32,
}

/// Heal one chunk star without keys: returns `Some(healed)` when it was torn.
/// A healed star must verify clean (all shards, Merkle) and keep its true-name.
fn mend_chunk_star(i: u32, stars: u32, star: &[u8], soft: bool) -> Result<Option<(Vec<u8>, bool)>> {
    if !star_torn(star) {
        return Ok(None);
    }
    let (healed, used_soft) = crate::pieces::mend_bytes_ex(star, soft).map_err(|e| {
        crate::Error::Msg(format!(
            "chunk star {i} of {stars} is too damaged to mend: {e}"
        ))
    })?;
    match crate::verify(&healed) {
        Ok((_, true, _, _, _)) => Ok(Some((healed, used_soft))),
        _ => Err(crate::Error::Msg(format!(
            "chunk star {i} of {stars} did not verify clean after mend"
        ))),
    }
}

/// Lay out the pack at `input` for mend: a damaged facet trailer is refused.
fn mend_layout<S: Src>(src: &mut S) -> Result<PackLayout> {
    let l = packhead::layout(src)?;
    if matches!(l.trailer, packhead::Trailer::Damaged) {
        return Err(crate::Error::Msg(
            "work pack facet trailer (SGFC) damaged; not RS-coded, refusing".into(),
        ));
    }
    Ok(l)
}

/// Standalone, key-free mend of a whole SGWK large-file pack (`sigil mend`).
///
/// Streams star by star (one chunk in memory at a time), heals every torn chunk
/// star with the same RS mend as a single mark, and checks every star's header
/// true-name against the SGFC facet trailer when present. Output goes to a temp
/// file beside `output` and is renamed into place only when every star is clean,
/// so `output` may equal `input`. A damaged pack head is rebuilt from the facet
/// list and the stars' own headers when that is unambiguous (see
/// `docs/PACK-HEAD-REPAIR.md`); damaged per-star length framing or a damaged
/// facet trailer is refused, never guessed. Nothing is decrypted, so Warded /
/// encrypt-to packs mend without a passphrase or identity.
pub fn mend_pack_path(input: &Path, output: &Path, soft: bool) -> Result<PackMendReport> {
    let io = |e: std::io::Error| crate::Error::Msg(e.to_string());
    let mut src = packhead::FileSrc::open(input)?;
    let l = mend_layout(&mut src)?;
    let n = l.head.stars;
    let facets = l.facets().map(<[[u8; 32]]>::to_vec);
    let mut trailer = vec![0u8; (src.size() - l.trailer_off) as usize];
    src.read_at(l.trailer_off, &mut trailer)?;

    // Heal + write to a temp file beside the output.
    let mut tmp = output.as_os_str().to_os_string();
    tmp.push(".mend-part");
    let tmp = std::path::PathBuf::from(tmp);
    let result = (|| -> Result<PackMendReport> {
        let mut w = BufWriter::new(File::create(&tmp).map_err(io)?);
        w.write_all(&l.head_bytes).map_err(io)?;
        let mut pos = l.head_bytes.len() as u64;
        let mut mended = Vec::new();
        let mut soft_used = false;
        let mut guards_restored = 0u32;
        for (i, &(start, len)) in l.stars.iter().enumerate() {
            let i = i as u32;
            let mut star = vec![0u8; len as usize];
            src.read_at(start, &mut star)?;
            if l.guarded {
                if packhead::guard_of_star(&star).is_none() {
                    guards_restored += 1;
                }
                // Heal the seal alone; a fresh guard is written after it below.
                let seal_len = packhead::seal_part(&star).len();
                star.truncate(seal_len);
            }
            if let Some((healed, used_soft)) = mend_chunk_star(i, n, &star, soft)? {
                star = healed;
                soft_used |= used_soft;
                mended.push(i);
            }
            if let Some(f) = &facets {
                let (h, _, _) = crate::locate_header(&star)?;
                if h.digest != f[i as usize] {
                    return Err(crate::Error::Msg(format!(
                        "chunk star {i} true-name does not match the pack facet (swapped star or damaged trailer); refusing"
                    )));
                }
            }
            if l.guarded {
                pos = write_star(&mut w, pos, i, &star, &l.head_bytes, &l.pack_id)?;
            } else {
                w.write_all(&(star.len() as u64).to_le_bytes())
                    .map_err(io)?;
                w.write_all(&star).map_err(io)?;
            }
        }
        match (&facets, l.facets_rebuilt) {
            (Some(f), true) => w.write_all(&facet_trailer(f)).map_err(io)?,
            _ => w.write_all(&trailer).map_err(io)?,
        }
        w.flush().map_err(io)?;
        w.get_ref().sync_all().map_err(io)?;
        Ok(PackMendReport {
            stars: n,
            mended,
            soft_used,
            facets_checked: facets.is_some(),
            bytes: 0,
            head: l.source,
            facets_rebuilt: l.facets_rebuilt,
            guards_restored,
        })
    })();
    drop(src);
    match result {
        Ok(mut rep) => {
            std::fs::rename(&tmp, output).map_err(|e| {
                let _ = std::fs::remove_file(&tmp);
                io(e)
            })?;
            rep.bytes = std::fs::metadata(output).map_err(io)?.len();
            Ok(rep)
        }
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

/// Outcome of [`mend_pack_to`].
// `written` and `mended` are part of the report and asserted by the tests, but the only
// in-crate caller (folder::unseal_dir_mend) needs just `healed`; keep them rather than
// lose information callers may want.
#[allow(dead_code)]
pub struct WorkMend {
    /// Plaintext bytes written.
    pub written: u64,
    /// Rebuilt SGWK bytes when at least one star was healed or the pack head was
    /// rebuilt (same layout, same facets).
    pub healed: Option<Vec<u8>>,
    /// Indexes of stars that were mended.
    pub mended: Vec<u32>,
    /// Where the pack head came from.
    pub head: HeadSource,
}

/// True when a star still opens but shards / Merkle (or its primary header) are damaged.
pub fn star_torn(star: &[u8]) -> bool {
    match crate::verify(star) {
        Ok((_, merkle_ok, _, _, recovered)) => !merkle_ok || recovered,
        Err(_) => true,
    }
}

fn span(l: &PackLayout, i: usize) -> (usize, usize) {
    let (o, n) = l.stars[i];
    (o as usize, (o + n) as usize)
}

/// Unseal an in-memory SGWK pack into `out`, mending torn chunk stars on the way.
///
/// Each chunk star is a complete `.sg1`, so it heals with the same RS mend as a
/// single-file mark. A star is mended when it fails to unseal, or opens but still
/// shows damage (bad shard CRC / Merkle / primary header). Healed stars must keep
/// the chunk true-name recorded in the SGFC facet trailer. A damaged pack head is
/// rebuilt from the facet list when that is unambiguous; damaged per-star length
/// framing is refused, never guessed.
pub fn mend_pack_to<W: Write>(
    pack: &[u8],
    out: &mut W,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    identities: &[Identity],
) -> Result<WorkMend> {
    let l = packhead::layout(&mut packhead::MemSrc(pack))?;
    let facets = l.facets();
    let mut healed_stars: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut written = 0u64;
    let mut star0: Option<crate::privacy::SealMeta> = None;
    for i in 0..l.stars.len() {
        let (a, b) = span(&l, i);
        let i = i as u32;
        let star = &pack[a..b];
        let opened = unseal_ex_keys(star, pass, companions, identities);
        let plain = match opened {
            Ok(p) if !star_torn(star) => p,
            opened => match crate::pieces::mend_bytes(star) {
                Ok(healed) => {
                    let p = unseal_ex_keys(&healed, pass, companions, identities)?;
                    if let Some(f) = facets {
                        let (h, _, _) = crate::locate_header(&healed)?;
                        if h.digest != f[i as usize] {
                            return Err(crate::Error::Msg(format!(
                                "mended star {i} does not match the pack's facet true-name"
                            )));
                        }
                    }
                    healed_stars.push((i, healed));
                    p
                }
                // Opened within budget but couldn't be re-sealed clean: keep bytes as-is.
                Err(e) => match opened {
                    Ok(p) => p,
                    Err(_) => {
                        return Err(crate::Error::Msg(format!(
                            "star {i} of {} is too damaged to mend: {e}",
                            l.head.stars
                        )))
                    }
                },
            },
        };
        let cur: &[u8] = match healed_stars.last() {
            Some((j, h)) if *j == i => h,
            _ => star,
        };
        if let Some(f) = facets {
            if !facet_ok(cur, &plain, &f[i as usize])? {
                return Err(crate::Error::Msg(format!(
                    "star {i} true-name does not match the pack facet (swapped or reordered star); refusing"
                )));
            }
        }
        if i == 0 && total_hidden(&l.head) {
            star0 = crate::unseal_meta_keys(cur, pass, companions, identities)?.1;
        }
        out.write_all(&plain)
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        written += plain.len() as u64;
    }
    let expect = expect_total(&l.head, star0.as_ref())?;
    if written != expect {
        return Err(crate::Error::Msg(format!(
            "work length mismatch: got {written} expected {expect}"
        )));
    }
    let mended: Vec<u32> = healed_stars.iter().map(|(i, _)| *i).collect();
    let healed = if healed_stars.is_empty() && l.source == HeadSource::Intact && !l.guarded {
        None
    } else {
        let mut rebuilt = Vec::with_capacity(pack.len());
        rebuilt.extend_from_slice(&l.head_bytes);
        let mut pos = l.head_bytes.len() as u64;
        let mut next = healed_stars.into_iter().peekable();
        for i in 0..l.stars.len() {
            let (a, b) = span(&l, i);
            let replacement = match next.peek() {
                Some((j, _)) if *j as usize == i => next.next().map(|(_, s)| s),
                _ => None,
            };
            if l.guarded {
                let seal: &[u8] = match replacement.as_deref() {
                    Some(r) => r,
                    None => packhead::seal_part(&pack[a..b]),
                };
                pos = write_star(&mut rebuilt, pos, i as u32, seal, &l.head_bytes, &l.pack_id)?;
            } else {
                let star: &[u8] = replacement.as_deref().unwrap_or(&pack[a..b]);
                rebuilt.extend_from_slice(&(star.len() as u64).to_le_bytes());
                rebuilt.extend_from_slice(star);
            }
        }
        match (facets, l.facets_rebuilt) {
            (Some(f), true) => rebuilt.extend_from_slice(&facet_trailer(f)),
            _ => rebuilt.extend_from_slice(&pack[l.trailer_off as usize..]),
        }
        // A clean guarded pack rewrites to exactly the same bytes.
        (rebuilt != pack).then_some(rebuilt)
    };
    Ok(WorkMend {
        written,
        healed,
        mended,
        head: l.source,
    })
}

/// Unseal a single mark or an SGWK pack at `input` to `output` (all-or-nothing).
pub fn unseal_path(
    input: &Path,
    output: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
) -> Result<u64> {
    unseal_path_keys(input, output, pass, companions, &[])
}

/// Like [`unseal_path`], with `--identity` keys.
///
/// A pack whose head is damaged is opened through a rebuilt head when the
/// facet list and the stars' own headers make that unambiguous; otherwise the
/// error stands and nothing is written.
pub fn unseal_path_keys(
    input: &Path,
    output: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    identities: &[Identity],
) -> Result<u64> {
    if is_work_pack(input) {
        let mut src = packhead::FileSrc::open(input)?;
        let l = packhead::layout(&mut src)?;
        return write_atomic(output, |writer| {
            unseal_pack_stream(&mut src, &l, writer, pass, companions, identities)
        });
    }
    let data = std::fs::read(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
    // unseal_ex_keys checks length + SHA-256 against the header and refuses a
    // buffer holding more than one seal (damaged pack head).
    let plain = match unseal_ex_keys(&data, pass, companions, identities) {
        Ok(p) => p,
        Err(e) => {
            // The SGWK magic itself may be what was damaged.
            if let Some(l) = packhead::recover_bytes(&data) {
                let mut src = packhead::MemSrc(&data);
                return write_atomic(output, |writer| {
                    unseal_pack_stream(&mut src, &l, writer, pass, companions, identities)
                });
            }
            return Err(e);
        }
    };
    let n = plain.len() as u64;
    write_atomic(output, |w| {
        w.write_all(&plain)
            .map_err(|e| crate::Error::Msg(e.to_string()))
    })?;
    Ok(n)
}

/// Unseal the seal or SGWK pack at `input` into `writer` (no output file is
/// created; the caller decides where the bytes land). Returns the bytes written.
pub(crate) fn unseal_path_into<W: Write>(
    input: &Path,
    writer: &mut W,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    identities: &[Identity],
) -> Result<u64> {
    if is_work_pack(input) {
        let mut src = packhead::FileSrc::open(input)?;
        let l = packhead::layout(&mut src)?;
        return unseal_pack_stream(&mut src, &l, writer, pass, companions, identities);
    }
    let data = std::fs::read(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
    unseal_bytes_into(&data, writer, pass, companions, identities)
}

/// Unseal an in-memory seal or SGWK pack into `writer`, with the same checks as
/// [`unseal_path_keys`]. Returns the bytes written.
pub(crate) fn unseal_bytes_into<W: Write>(
    data: &[u8],
    writer: &mut W,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    identities: &[Identity],
) -> Result<u64> {
    let mut src = packhead::MemSrc(data);
    if data.starts_with(&WORK_MAGIC) {
        let l = packhead::layout(&mut src)?;
        return unseal_pack_stream(&mut src, &l, writer, pass, companions, identities);
    }
    match unseal_ex_keys(data, pass, companions, identities) {
        Ok(plain) => {
            writer
                .write_all(&plain)
                .map_err(|e| crate::Error::Msg(e.to_string()))?;
            Ok(plain.len() as u64)
        }
        Err(e) => match packhead::recover_bytes(data) {
            Some(l) => unseal_pack_stream(&mut src, &l, writer, pass, companions, identities),
            None => Err(e),
        },
    }
}

/// True when `path` is not a readable SGWK pack as written but its head can be
/// rebuilt (for example the magic itself is damaged). Reads the whole file in
/// the worst case; call it only after the ordinary readers have failed.
pub fn is_damaged_work_pack(path: &Path) -> bool {
    packhead::recover_path(path).is_some()
}

/// Stream every chunk star of an SGWK pack into `writer`, verifying each star
/// (length + SHA-256 in its own header), the SGFC facet true-names when the
/// trailer is present, and the pack's total length.
fn unseal_pack_stream<S: Src, W: Write>(
    src: &mut S,
    l: &PackLayout,
    writer: &mut W,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    identities: &[Identity],
) -> Result<u64> {
    let io = |e: std::io::Error| crate::Error::Msg(e.to_string());
    let n = l.head.stars;
    let facets = l.facets();
    let mut written = 0u64;
    let mut star0: Option<crate::privacy::SealMeta> = None;
    for (i, &(off, len)) in l.stars.iter().enumerate() {
        let mut star = vec![0u8; len as usize];
        src.read_at(off, &mut star).map_err(|_| {
            crate::Error::Msg(format!("work pack truncated inside star {i} of {n}"))
        })?;
        let (plain, meta) = crate::unseal_meta_keys(&star, pass, companions, identities)
            .map_err(|e| crate::Error::Msg(format!("star {i} of {n}: {e}")))?;
        if let Some(f) = facets {
            if crate::locate_header(&star)?.0.digest != f[i] {
                return Err(crate::Error::Msg(format!(
                    "chunk star {i} true-name does not match the pack facet (swapped or reordered star); refusing"
                )));
            }
        }
        if i == 0 {
            star0 = meta;
        }
        writer.write_all(&plain).map_err(io)?;
        written += plain.len() as u64;
    }
    let expect = expect_total(&l.head, star0.as_ref())?;
    if written != expect {
        return Err(crate::Error::Msg(format!(
            "work length mismatch: got {written} expected {expect}"
        )));
    }
    Ok(written)
}

/// Write `output` all-or-nothing: bytes go to `<output>.sigil-part`, which is
/// flushed, synced and renamed over `output` only if `f` succeeds. On any error
/// the part file is removed and an existing `output` is left untouched.
pub(crate) fn write_atomic<T>(
    output: &Path,
    f: impl FnOnce(&mut BufWriter<File>) -> Result<T>,
) -> Result<T> {
    let io = |e: std::io::Error| crate::Error::Msg(e.to_string());
    let mut part = output.as_os_str().to_os_string();
    part.push(".sigil-part");
    let part = std::path::PathBuf::from(part);
    let result = (|| {
        let mut w = BufWriter::new(File::create(&part).map_err(io)?);
        let v = f(&mut w)?;
        let file = w
            .into_inner()
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        file.sync_all().map_err(io)?;
        drop(file);
        std::fs::rename(&part, output).map_err(io)?;
        Ok(v)
    })();
    if result.is_err() {
        let _ = std::fs::remove_file(&part);
    }
    result
}

/// Name stored in a mark or pack ("payload.bin" when none was recorded).
pub fn payload_name(input: &Path) -> Result<String> {
    let mut f = File::open(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let mut mag = [0u8; 4];
    f.read_exact(&mut mag)
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    if mag == WORK_MAGIC {
        drop(f);
        let mut reader =
            BufReader::new(File::open(input).map_err(|e| crate::Error::Msg(e.to_string()))?);
        let head = match read_head(&mut reader) {
            Ok(h) => h,
            Err(e) => packhead::layout_path(input).map_err(|_| e)?.head,
        };
        if head.name.is_empty() {
            return Ok("payload.bin".into());
        }
        return Ok(head.name);
    }
    drop(f);
    let data = std::fs::read(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let (h, prefix, _) = crate::locate_header(&data)?;
    if crate::header::ensure_single_seal(&data, &h, prefix).is_err() {
        // Several seals in a row: a pack whose magic is damaged.
        if let Some(l) = packhead::recover_bytes(&data) {
            if l.head.name.is_empty() {
                return Ok("payload.bin".into());
            }
            return Ok(l.head.name);
        }
    }
    if h.name.is_empty() {
        Ok("payload.bin".into())
    } else {
        Ok(h.name)
    }
}

/// Name and size of a mark's or pack's payload, opening the private label when it
/// is hidden (v3 encrypted mark, or a pack with a hidden head). `Ok(None)` when it
/// is hidden and no key was given; a wrong key is an error.
pub fn payload_label_keys(
    input: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    identities: &[Identity],
) -> Result<Option<(String, u64)>> {
    let keyless = pass.is_none_or(str::is_empty) && identities.is_empty();
    if is_work_pack(input) {
        let (head, locs) = index_pack(input)?;
        if !total_hidden(&head) {
            return Ok(Some((head.name, head.orig_total)));
        }
        if keyless {
            return Ok(None);
        }
        let first = locs
            .first()
            .ok_or_else(|| crate::Error::Msg("pack has no stars".into()))?;
        let mut f = File::open(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
        f.seek(SeekFrom::Start(first.file_off))
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        let mut star = vec![0u8; first.star_len as usize];
        f.read_exact(&mut star)
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        let meta = crate::unseal_meta_keys(&star, pass, companions, identities)?.1;
        return Ok(meta.map(|m| (m.name, m.group_total)));
    }
    let data = std::fs::read(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let (h, _, _) = crate::locate_header(&data)?;
    if !h.private_label() {
        return Ok(Some((h.name, h.orig_len)));
    }
    if keyless {
        return Ok(None);
    }
    let meta = crate::unseal_meta_keys(&data, pass, companions, identities)?.1;
    Ok(meta.map(|m| (m.name, m.orig_len)))
}

/// Suggested filename for De-scribe. Basename only — never a path.
pub fn suggested_output_name(input: &Path) -> String {
    payload_name(input)
        .ok()
        .as_deref()
        .and_then(basename_only)
        .or_else(|| {
            input
                .file_stem()
                .and_then(|s| s.to_str())
                .and_then(basename_only)
        })
        .unwrap_or_else(|| "recovered.bin".into())
}

fn basename_only(name: &str) -> Option<String> {
    let cleaned = name.replace('\\', "/");
    let base = Path::new(&cleaned)
        .file_name()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_default();
    let base = base.trim();
    if base.is_empty() || base == "." || base == ".." {
        None
    } else {
        Some(base.to_string())
    }
}

/// Why a sealed star (classic `.sg1` bytes or an in-memory SGWK pack) cannot be
/// restored without more pieces: `None` when every part has at least `need`
/// intact pieces. Keyless; nothing is decrypted.
pub fn star_bytes_unrecoverable(star: &[u8]) -> Option<String> {
    if star.starts_with(&WORK_MAGIC) {
        let l = match packhead::layout(&mut packhead::MemSrc(star)) {
            Ok(l) => l,
            Err(e) => return Some(format!("large-file pack unreadable: {e}")),
        };
        if (l.stars.len() as u64) < u64::from(l.head.stars) {
            return Some(format!(
                "only {} of {} parts present",
                l.stars.len(),
                l.head.stars
            ));
        }
        for (i, &(o, n)) in l.stars.iter().enumerate() {
            let (a, b) = (o as usize, (o + n) as usize);
            let Some(part) = star.get(a..b) else {
                return Some(format!("part {i} is cut off"));
            };
            if let Some(why) = classic_unrecoverable(part) {
                return Some(format!("part {i}: {why}"));
            }
        }
        return None;
    }
    classic_unrecoverable(star)
}

fn classic_unrecoverable(star: &[u8]) -> Option<String> {
    match crate::verify(star) {
        Ok((h, _, live, k, _)) if live < k => Some(format!("live={live}/{} need={k}", h.n)),
        Ok(_) => None,
        Err(e) => Some(format!("unreadable: {e}")),
    }
}

/// Like [`star_bytes_unrecoverable`] for a file on disk; a large-file pack is
/// checked one part at a time (never loaded whole).
pub fn path_unrecoverable(input: &Path) -> Result<Option<String>> {
    if !is_work_pack(input) {
        let data = std::fs::read(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
        return Ok(classic_unrecoverable(&data));
    }
    let (head, locs) = index_pack(input)?;
    if (locs.len() as u64) < u64::from(head.stars) {
        return Ok(Some(format!(
            "only {} of {} parts present",
            locs.len(),
            head.stars
        )));
    }
    let mut f = File::open(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
    for loc in &locs {
        use std::io::Seek;
        f.seek(std::io::SeekFrom::Start(loc.file_off))
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        let mut part = Vec::new();
        (&mut f)
            .take(loc.star_len)
            .read_to_end(&mut part)
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        if (part.len() as u64) < loc.star_len {
            return Ok(Some(format!("part {} is cut off", loc.index)));
        }
        if let Some(why) = classic_unrecoverable(&part) {
            return Ok(Some(format!("part {}: {why}", loc.index)));
        }
    }
    Ok(None)
}

/// [`scry_path`] plus a recoverability verdict. When the file can no longer be
/// restored, the report's first line starts with `NOT recoverable` (not `ok`)
/// and the verdict is `Some(reason)`.
pub fn scry_path_checked(input: &Path) -> Result<(String, Option<String>)> {
    let s = scry_path(input)?;
    let bad = path_unrecoverable(input)?;
    Ok(match bad {
        None => (s, None),
        Some(why) => {
            let s = match s.strip_prefix("ok  ") {
                Some(rest) => format!("NOT recoverable  {rest}"),
                None => format!("{s}\nNOT recoverable: {why}"),
            };
            (s, Some(why))
        }
    })
}

pub fn scry_path(input: &Path) -> Result<String> {
    let mut f = File::open(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let mut mag = [0u8; 4];
    f.read_exact(&mut mag)
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    if mag == WORK_MAGIC {
        drop(f);
        let mut reader =
            BufReader::new(File::open(input).map_err(|e| crate::Error::Msg(e.to_string()))?);
        let head = read_head(&mut reader)?;
        let hidden = total_hidden(&head);
        let mut s = format!(
            "work  name={} orig={} chunk={} stars={} overture={}/{} (first ~{} MiB to start)",
            if hidden {
                "(locked)"
            } else {
                head.name.as_str()
            },
            if hidden {
                "(locked)".to_string()
            } else {
                head.orig_total.to_string()
            },
            head.chunk_size,
            head.stars,
            head.overture,
            head.stars,
            (head.overture as u64 * head.chunk_size as u64) / (1024 * 1024)
        );
        drop(reader);
        if let Ok(facets) = scry_facets(input) {
            for f in facets {
                let tag = if f.index < head.overture {
                    "overture"
                } else {
                    "follow"
                };
                s.push_str(&format!(
                    "\nfacet {:>5}  {tag}  off={}  {} bytes  {}",
                    f.index,
                    f.orig_off,
                    f.orig_len,
                    hex::encode(f.digest)
                ));
            }
        }
        return Ok(s);
    }
    drop(f);
    let data = std::fs::read(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let (h, merkle_ok, live, k, recovered) = crate::verify(&data)?;
    let mut s = if h.private_label() {
        // v3: name, size, SHA-256 and entropy are inside the lock; shown only after unlock.
        format!(
            "ok  v{}  live={live}/{} need={k} merkle={} keystone={} label=private (name, size and fingerprint inside the lock)",
            h.version,
            h.n,
            if merkle_ok { "closed" } else { "open" },
            if recovered { "recovered" } else { "intact" },
        )
    } else {
        format!(
            "ok  v{}  live={live}/{} need={k} merkle={} keystone={} orig={} entropy={} name={}",
            h.version,
            h.n,
            if merkle_ok { "closed" } else { "open" },
            if recovered { "recovered" } else { "intact" },
            h.orig_len,
            h.entropy_milli,
            h.name
        )
    };
    if let Ok(a) = crate::verify_attestation(input) {
        s.push('\n');
        s.push_str(&a);
    }
    Ok(s)
}

/// How many bytes of this pack to copy before Play is possible.
pub fn overture_report(input: &Path) -> Result<String> {
    let mut mag = [0u8; 4];
    File::open(input)
        .and_then(|mut f| f.read_exact(&mut mag))
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    if mag == WORK_MAGIC {
        let (head, locs) = index_pack(input)?;
        let have = locs.len() as u32;
        let end = locs
            .iter()
            .filter(|l| l.index < head.overture)
            .map(|l| l.file_off + l.star_len)
            .max()
            .unwrap_or(0);
        let ready = have >= head.overture;
        return Ok(format!(
            "Overture: first {} of {} slices (~{} MiB of payload).\nCopy the first {} bytes of this file to start.\nOn disk now: {have} slices. {}",
            head.overture,
            head.stars,
            (head.overture as u64 * head.chunk_size as u64) / (1024 * 1024),
            end,
            if ready {
                "Boot is here — you can Play / mount while the rest arrives."
            } else {
                "Boot is not complete yet."
            }
        ));
    }
    if input.is_dir() {
        let ov = input.join(OVERTURE);
        if ov.exists() {
            return std::fs::read_to_string(&ov).map_err(|e| crate::Error::Msg(e.to_string()));
        }
        return Err(crate::Error::Msg("no OVERTURE list in this folder".into()));
    }
    Ok("This is one small mark — copy the whole file; there is no separate boot.".into())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn tmp(tag: &str) -> std::path::PathBuf {
        let d = std::env::temp_dir().join(format!(
            "sigil-work-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn data(n: usize) -> Vec<u8> {
        let mut x = 0x9e3779b97f4a7c15u64;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    /// (start, end) of each chunk star inside an SGWK pack.
    pub(crate) fn star_spans(pack: &[u8]) -> Vec<(usize, usize)> {
        let mut cur = std::io::Cursor::new(pack);
        let head = read_head(&mut cur).unwrap();
        let mut off = cur.position() as usize;
        let mut v = Vec::new();
        for _ in 0..head.stars {
            let len = u64::from_le_bytes(pack[off..off + 8].try_into().unwrap()) as usize;
            off += 8;
            v.push((off, off + len));
            off += len;
        }
        v
    }

    /// Zero shard `shard` of the star starting at `star_off` (past Keystone/header).
    pub(crate) fn smash_shard(pack: &mut [u8], star_off: usize, star_end: usize, shard: usize) {
        let (h, prefix, _) = crate::locate_header(&pack[star_off..star_end]).unwrap();
        let stride = crate::header::shard_stride(&h);
        let a = star_off + prefix + shard * stride;
        assert!(a + stride <= star_end);
        pack[a..a + stride].fill(0);
        pack[a] = 3;
    }

    fn make_pack(dir: &Path, n: usize, recipients: &[PublicIdentity]) -> (Vec<u8>, Vec<u8>) {
        let d = data(n);
        let src = dir.join("big.bin");
        std::fs::write(&src, &d).unwrap();
        let out = dir.join("big.sg1");
        let (_, stars, is_work) = inscribe_path_to(
            &src,
            &out,
            Mode::Seal,
            None,
            "",
            &[],
            64 * 1024,
            None,
            DEFAULT_PIECE,
            0,
            None,
            recipients,
        )
        .unwrap();
        assert!(is_work && stars >= 4, "want a multi-star work pack");
        (d, std::fs::read(&out).unwrap())
    }

    #[test]
    fn mend_pack_heals_torn_chunk_stars_and_keeps_layout() {
        let dir = tmp("mend");
        let (d, pack) = make_pack(&dir, 300 * 1024, &[]);
        let spans = star_spans(&pack);
        let mut torn = pack.clone();
        smash_shard(&mut torn, spans[1].0, spans[1].1, 0);
        smash_shard(&mut torn, spans[3].0, spans[3].1, 2);
        assert!(star_torn(&torn[spans[1].0..spans[1].1]));

        let mut out = Vec::new();
        let m = mend_pack_to(&torn, &mut out, None, &[], &[]).unwrap();
        assert_eq!(out, d);
        assert_eq!(m.written, d.len() as u64);
        assert_eq!(m.mended, vec![1, 3]);
        let healed = m.healed.expect("healed pack");
        assert_eq!(healed.len(), pack.len(), "same layout");
        assert_eq!(&healed[..spans[0].0], &pack[..spans[0].0], "same head");
        assert_eq!(
            read_facet_digests_bytes(&healed),
            read_facet_digests_bytes(&pack)
        );
        for (a, b) in star_spans(&healed) {
            assert!(!star_torn(&healed[a..b]));
        }
        // Healed pack opens with the ordinary streaming path and needs no more mending.
        let hp = dir.join("healed.sg1");
        std::fs::write(&hp, &healed).unwrap();
        unseal_path_keys(&hp, &dir.join("o.bin"), None, &[], &[]).unwrap();
        assert_eq!(std::fs::read(dir.join("o.bin")).unwrap(), d);
        let mut again = Vec::new();
        let m2 = mend_pack_to(&healed, &mut again, None, &[], &[]).unwrap();
        assert!(m2.healed.is_none() && m2.mended.is_empty());
        let _ = std::fs::remove_dir_all(&dir);
    }

    fn read_facet_digests_bytes(pack: &[u8]) -> Vec<u8> {
        let i = pack.len() - pack.windows(4).rev().position(|w| w == b"SGFC").unwrap() - 4;
        pack[i..].to_vec()
    }

    #[test]
    fn mend_pack_refuses_too_damaged_star_and_bad_framing() {
        let dir = tmp("refuse");
        let (_, pack) = make_pack(&dir, 300 * 1024, &[]);
        let spans = star_spans(&pack);
        let (h, _, _) = crate::locate_header(&pack[spans[2].0..spans[2].1]).unwrap();
        let mut torn = pack.clone();
        // Seal tolerates n-k losses; smash one more than that.
        for s in 0..=(h.n - h.k) as usize {
            smash_shard(&mut torn, spans[2].0, spans[2].1, s);
        }
        let mut out = Vec::new();
        let e = mend_pack_to(&torn, &mut out, None, &[], &[])
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("star 2"), "{e}");

        let mut framing = pack.clone();
        framing[spans[1].0 - 8..spans[1].0].copy_from_slice(&u64::MAX.to_le_bytes());
        let e = mend_pack_to(&framing, &mut Vec::new(), None, &[], &[])
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("framing"), "{e}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mend_pack_encrypt_to_member() {
        let dir = tmp("mend-to");
        let id = Identity::generate().unwrap();
        let (d, pack) = make_pack(&dir, 260 * 1024, &[id.public()]);
        let spans = star_spans(&pack);
        let mut torn = pack.clone();
        smash_shard(&mut torn, spans[0].0, spans[0].1, 1);
        assert!(
            mend_pack_to(&torn, &mut Vec::new(), None, &[], &[]).is_err(),
            "needs identity"
        );
        let mut out = Vec::new();
        let m = mend_pack_to(&torn, &mut out, None, &[], &[id]).unwrap();
        assert_eq!(out, d);
        assert_eq!(m.mended, vec![0]);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mend_pack_path_heals_all_torn_chunks_in_place() {
        let dir = tmp("mendpath");
        let (d, pack) = make_pack(&dir, 300 * 1024, &[]);
        let spans = star_spans(&pack);
        let mut torn = pack.clone();
        smash_shard(&mut torn, spans[0].0, spans[0].1, 1);
        smash_shard(&mut torn, spans[2].0, spans[2].1, 0);
        smash_shard(&mut torn, spans[4].0, spans[4].1, 3);
        let p = dir.join("torn.sg1");
        std::fs::write(&p, &torn).unwrap();
        let rep = mend_pack_path(&p, &p, false).unwrap();
        assert_eq!(rep.mended, vec![0, 2, 4]);
        assert!(rep.facets_checked && !rep.soft_used);
        let healed = std::fs::read(&p).unwrap();
        assert_eq!(healed.len(), pack.len());
        for (a, b) in star_spans(&healed) {
            assert!(!star_torn(&healed[a..b]));
        }
        assert!(!dir.join("torn.sg1.mend-part").exists());
        unseal_path_keys(&p, &dir.join("o.bin"), None, &[], &[]).unwrap();
        assert_eq!(std::fs::read(dir.join("o.bin")).unwrap(), d);
        // Clean pack: nothing to heal, bytes unchanged.
        let rep2 = mend_pack_path(&p, &dir.join("again.sg1"), false).unwrap();
        assert!(rep2.mended.is_empty());
        assert_eq!(std::fs::read(dir.join("again.sg1")).unwrap(), healed);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mend_pack_path_needs_no_keys_for_encrypt_to() {
        let dir = tmp("mendpath-to");
        let id = Identity::generate().unwrap();
        let (d, pack) = make_pack(&dir, 260 * 1024, &[id.public()]);
        let spans = star_spans(&pack);
        let mut torn = pack.clone();
        smash_shard(&mut torn, spans[1].0, spans[1].1, 0);
        let p = dir.join("torn.sg1");
        let out = dir.join("fixed.sg1");
        std::fs::write(&p, &torn).unwrap();
        assert_eq!(mend_pack_path(&p, &out, false).unwrap().mended, vec![1]);
        unseal_path_keys(&out, &dir.join("o.bin"), None, &[], &[id]).unwrap();
        assert_eq!(std::fs::read(dir.join("o.bin")).unwrap(), d);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn mend_pack_path_refuses_cleanly() {
        let dir = tmp("mendpath-refuse");
        let (_, pack) = make_pack(&dir, 300 * 1024, &[]);
        let spans = star_spans(&pack);
        let p = dir.join("in.sg1");
        let out = dir.join("out.sg1");
        let check = |bytes: &[u8], want: &str| {
            std::fs::write(&p, bytes).unwrap();
            let e = mend_pack_path(&p, &out, false)
                .expect_err("should refuse")
                .to_string();
            assert!(e.contains(want), "{e}");
            assert!(!out.exists(), "no output on refusal");
            assert!(!dir.join("out.sg1.mend-part").exists());
            assert_eq!(std::fs::read(&p).unwrap(), bytes, "input untouched");
        };
        // Over budget in star 3.
        let (h, _, _) = crate::locate_header(&pack[spans[3].0..spans[3].1]).unwrap();
        let mut over = pack.clone();
        for s in 0..=(h.n - h.k) as usize {
            smash_shard(&mut over, spans[3].0, spans[3].1, s);
        }
        check(&over, "chunk star 3");
        // Length framing.
        let mut fr = pack.clone();
        fr[spans[2].0 - 8..spans[2].0].copy_from_slice(&(1u64 << 40).to_le_bytes());
        check(&fr, "framing damaged at star 2");
        // Trailer: every star's guard proves the order, so a guarded pack's
        // facet list is rebuilt (old packs still refuse; see packhead tests).
        let mut tr = pack.clone();
        let n = tr.len();
        tr[n - 32 * spans.len() - 8] = b'X';
        std::fs::write(&p, &tr).unwrap();
        let rep = mend_pack_path(&p, &out, false).unwrap();
        assert!(rep.facets_rebuilt && rep.facets_checked);
        assert_eq!(std::fs::read(&out).unwrap(), pack);
        std::fs::remove_file(&out).unwrap();
        // Swapped equal-length stars → facet mismatch.
        let (a0, a1) = spans[0];
        let (b0, b1) = spans[1];
        assert_eq!(a1 - a0, b1 - b0);
        let mut sw = pack.clone();
        let first = pack[a0..a1].to_vec();
        sw[a0..a1].copy_from_slice(&pack[b0..b1]);
        sw[b0..b1].copy_from_slice(&first);
        // Their guards name other positions.
        check(&sw, "out of place");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Rebuild a pack with stars `a` and `b` swapped (framing rewritten).
    fn swap_stars(pack: &[u8], a: usize, b: usize) -> Vec<u8> {
        let spans = star_spans(pack);
        let head_end = spans[0].0 - 8;
        let mut stars: Vec<&[u8]> = spans.iter().map(|&(x, y)| &pack[x..y]).collect();
        stars.swap(a, b);
        let mut out = pack[..head_end].to_vec();
        for st in stars {
            out.extend_from_slice(&(st.len() as u64).to_le_bytes());
            out.extend_from_slice(st);
        }
        out.extend_from_slice(&pack[spans.last().unwrap().1..]);
        out
    }

    #[test]
    fn swapped_stars_refused_by_unseal_and_mend() {
        let dir = tmp("swap");
        let (_, pack) = make_pack(&dir, 300 * 1024, &[]);
        let bad = swap_stars(&pack, 0, 1);
        let p = dir.join("swapped.sg1");
        std::fs::write(&p, &bad).unwrap();
        let out = dir.join("out.bin");
        let e = unseal_path_keys(&p, &out, None, &[], &[])
            .unwrap_err()
            .to_string();
        assert!(e.contains("out of place"), "{e}");
        assert!(!out.exists());
        let e = mend_pack_to(&bad, &mut Vec::new(), None, &[], &[])
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("out of place"), "{e}");
        // Without guards (a pack written before them) the facet list catches it.
        let old = crate::packhead::tests::strip_guards(&pack);
        let bad = swap_stars(&old, 0, 1);
        std::fs::write(&p, &bad).unwrap();
        let e = unseal_path_keys(&p, &out, None, &[], &[])
            .unwrap_err()
            .to_string();
        assert!(e.contains("facet"), "{e}");
        assert!(!out.exists());
    }

    #[test]
    fn damaged_pack_head_refused_in_memory_paths() {
        let dir = tmp("head");
        let (_, pack) = make_pack(&dir, 300 * 1024, &[]);
        let mut torn = pack.clone();
        torn[..4].fill(0);
        let e = unseal_ex_keys(&torn, None, &[], &[])
            .unwrap_err()
            .to_string();
        assert!(e.contains("more than one seal"), "{e}");
        let e = crate::pieces::mend_bytes(&torn).unwrap_err().to_string();
        assert!(e.contains("more than one seal"), "{e}");
    }

    #[test]
    fn single_seal_with_trailing_junk_still_opens_but_two_seals_do_not() {
        let msg: Vec<u8> = data(50_000);
        let one = crate::seal(&msg, Mode::Seal, None, "x.bin", false).unwrap();
        let mut junk = one.clone();
        junk.extend_from_slice(&data(3000));
        assert_eq!(unseal_ex_keys(&junk, None, &[], &[]).unwrap(), msg);
        let mut two = one.clone();
        two.extend_from_slice(&crate::seal(b"other", Mode::Seal, None, "y", false).unwrap());
        assert!(unseal_ex_keys(&two, None, &[], &[]).is_err());
        assert!(crate::pieces::mend_bytes(&two).is_err());
    }

    #[test]
    fn range_unseal_is_all_or_nothing() {
        let dir = tmp("range");
        let (_, pack) = make_pack(&dir, 300 * 1024, &[]);
        let spans = star_spans(&pack);
        let mut torn = pack.clone();
        // Destroy star 2 beyond repair (every shard and every header copy).
        torn[spans[2].0..spans[2].1].fill(0);
        let p = dir.join("torn.sg1");
        std::fs::write(&p, &torn).unwrap();
        let out = dir.join("range.bin");
        assert!(unseal_range_keys(&p, &out, None, &[], 0, 3, &[]).is_err());
        assert!(!out.exists(), "no partial range output");
        let full = dir.join("full.bin");
        assert!(unseal_path_keys(&p, &full, None, &[], &[]).is_err());
        assert!(!full.exists(), "no partial full output");
        // Range that avoids the dead star still works.
        let (_, n) = unseal_range_keys(&p, &out, None, &[], 0, 1, &[]).unwrap();
        assert_eq!(n, 2);
    }
}
