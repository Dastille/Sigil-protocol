//! Streamed work pack for files too big for one in-memory mark.
//! Magic SGWK. Each record is a complete .sg1 star of one chunk.

use crate::cdc::{self, ChunkRange, Profile as CdcProfile};
use crate::keys::{Identity, PublicIdentity};
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

fn read_head<R: Read>(r: &mut R) -> Result<WorkHead> {
    let mut mag = [0u8; 4];
    r.read_exact(&mut mag).map_err(|e| crate::Error::Msg(e.to_string()))?;
    if mag != WORK_MAGIC {
        return Err(crate::Error::Msg("not a work pack (SGWK)".into()));
    }
    let mut one = [0u8; 1];
    r.read_exact(&mut one).map_err(|e| crate::Error::Msg(e.to_string()))?;
    if one[0] != 1 && one[0] != 2 {
        return Err(crate::Error::Msg(format!("unknown work version {}", one[0])));
    }
    let ver = one[0];
    let mut buf4 = [0u8; 4];
    r.read_exact(&mut buf4).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let chunk_size = u32::from_le_bytes(buf4);
    let mut buf8 = [0u8; 8];
    r.read_exact(&mut buf8).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let orig_total = u64::from_le_bytes(buf8);
    r.read_exact(&mut one).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let mut name = vec![0u8; one[0] as usize];
    if !name.is_empty() {
        r.read_exact(&mut name).map_err(|e| crate::Error::Msg(e.to_string()))?;
    }
    r.read_exact(&mut buf4).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let stars = u32::from_le_bytes(buf4);
    let overture = if ver == 2 {
        r.read_exact(&mut buf4).map_err(|e| crate::Error::Msg(e.to_string()))?;
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
        input, output, mode, pass, covenant, geas, chunk, shards, piece_bytes, overture_mb, cdc, &[],
    )
}

/// Like `inscribe_path`, with optional encrypt-to recipients on every star.
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
    let piece_bytes = if piece_bytes == 0 { DEFAULT_PIECE } else { piece_bytes };
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
            &data, &name, output, mode, pass, covenant, geas, shards, piece_bytes, overture_mb, &r, profile.max as u32, recipients,
        );
    } else {
        let chunk = chunk.max(64 * 1024);
        if orig <= chunk as u64 {
            let data = std::fs::read(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
            let out = seal_kn_to(&data, mode, pass, &name, false, covenant, geas, shards, piece_bytes, recipients)?;
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
    let mut reader = BufReader::new(File::open(input).map_err(|e| crate::Error::Msg(e.to_string()))?);
    let mut writer = BufWriter::new(File::create(output).map_err(|e| crate::Error::Msg(e.to_string()))?);
    writer.write_all(&WORK_MAGIC).map_err(|e| crate::Error::Msg(e.to_string()))?;
    writer.write_all(&[2u8]).map_err(|e| crate::Error::Msg(e.to_string()))?;
    writer.write_all(&chunk.to_le_bytes()).map_err(|e| crate::Error::Msg(e.to_string()))?;
    writer.write_all(&orig.to_le_bytes()).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let nb = name.as_bytes();
    let nlen = nb.len().min(255) as u8;
    writer.write_all(&[nlen]).map_err(|e| crate::Error::Msg(e.to_string()))?;
    writer.write_all(&nb[..nlen as usize]).map_err(|e| crate::Error::Msg(e.to_string()))?;
    writer.write_all(&stars.to_le_bytes()).map_err(|e| crate::Error::Msg(e.to_string()))?;
    writer.write_all(&overture.to_le_bytes()).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let mut buf = vec![0u8; chunk as usize];
    let mut facets = Vec::new();
    for (i, range) in ranges.iter().enumerate() {
        let n = range.length;
        reader.read_exact(&mut buf[..n]).map_err(|e| crate::Error::Msg(e.to_string()))?;
        let star_name = format!("{name}.{i:04}");
        let sealed = seal_kn_to(&buf[..n], mode, pass, &star_name, false, covenant, geas, shards, piece_bytes, recipients)?;
        writer
            .write_all(&(sealed.len() as u64).to_le_bytes())
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        writer.write_all(&sealed).map_err(|e| crate::Error::Msg(e.to_string()))?;
        if let Ok((h, _, _)) = crate::locate_header(&sealed) {
            facets.push(h.digest);
        } else {
            facets.push([0u8; 32]);
        }
    }
    writer.write_all(b"SGFC").map_err(|e| crate::Error::Msg(e.to_string()))?;
    writer.write_all(&(facets.len() as u32).to_le_bytes()).map_err(|e| crate::Error::Msg(e.to_string()))?;
    for d in &facets {
        writer.write_all(d).map_err(|e| crate::Error::Msg(e.to_string()))?;
    }
    writer.flush().map_err(|e| crate::Error::Msg(e.to_string()))?;
    Ok((orig, stars, true))
}

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
        let slice = if ranges.is_empty() { data } else { &data[ranges[0].offset..ranges[0].end()] };
        let out = seal_kn_to(slice, mode, pass, name, false, covenant, geas, shards, piece_bytes, recipients)?;
        std::fs::write(output, out).map_err(|e| crate::Error::Msg(e.to_string()))?;
        return Ok((orig, 1, false));
    }
    let stars = ranges.len() as u32;
    let chunk = header_chunk.max(64 * 1024);
    let overture = choose_overture(stars, orig, chunk, overture_mb);
    let mut writer = BufWriter::new(File::create(output).map_err(|e| crate::Error::Msg(e.to_string()))?);
    writer.write_all(&WORK_MAGIC).map_err(|e| crate::Error::Msg(e.to_string()))?;
    writer.write_all(&[2u8]).map_err(|e| crate::Error::Msg(e.to_string()))?;
    writer.write_all(&chunk.to_le_bytes()).map_err(|e| crate::Error::Msg(e.to_string()))?;
    writer.write_all(&orig.to_le_bytes()).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let nb = name.as_bytes();
    let nlen = nb.len().min(255) as u8;
    writer.write_all(&[nlen]).map_err(|e| crate::Error::Msg(e.to_string()))?;
    writer.write_all(&nb[..nlen as usize]).map_err(|e| crate::Error::Msg(e.to_string()))?;
    writer.write_all(&stars.to_le_bytes()).map_err(|e| crate::Error::Msg(e.to_string()))?;
    writer.write_all(&overture.to_le_bytes()).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let mut facets = Vec::new();
    for (i, range) in ranges.iter().enumerate() {
        let slice = &data[range.offset..range.end()];
        let star_name = format!("{name}.{i:04}");
        let sealed = seal_kn_to(slice, mode, pass, &star_name, false, covenant, geas, shards, piece_bytes, recipients)?;
        writer
            .write_all(&(sealed.len() as u64).to_le_bytes())
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        writer.write_all(&sealed).map_err(|e| crate::Error::Msg(e.to_string()))?;
        if let Ok((h, _, _)) = crate::locate_header(&sealed) {
            facets.push(h.digest);
        } else {
            facets.push([0u8; 32]);
        }
    }
    writer.write_all(b"SGFC").map_err(|e| crate::Error::Msg(e.to_string()))?;
    writer.write_all(&(facets.len() as u32).to_le_bytes()).map_err(|e| crate::Error::Msg(e.to_string()))?;
    for d in &facets {
        writer.write_all(d).map_err(|e| crate::Error::Msg(e.to_string()))?;
    }
    writer.flush().map_err(|e| crate::Error::Msg(e.to_string()))?;
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
    let len = f.metadata().map_err(|e| crate::Error::Msg(e.to_string()))?.len();
    let head = read_head(&mut f)?;
    let n = head.stars as u64;
    let trailer = 4 + 4 + 32 * n;
    if len >= trailer {
        if f.seek(SeekFrom::End(-(trailer as i64))).is_ok() {
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
    }
    Ok(scry_facets(input)?.into_iter().map(|f| f.digest).collect())
}

/// Bao-style slice list: each work-pack star is a checkable 4 MiB facet.
pub fn scry_facets(input: &Path) -> Result<Vec<Facet>> {
    let mut reader = BufReader::new(File::open(input).map_err(|e| crate::Error::Msg(e.to_string()))?);
    let head = read_head(&mut reader)?;
    let mut out = Vec::new();
    let mut remain = head.orig_total;
    let mut orig_off = 0u64;
    for i in 0..head.stars {
        let mut lenb = [0u8; 8];
        reader.read_exact(&mut lenb).map_err(|e| crate::Error::Msg(e.to_string()))?;
        let len = u64::from_le_bytes(lenb) as usize;
        let mut star = vec![0u8; len];
        reader.read_exact(&mut star).map_err(|e| crate::Error::Msg(e.to_string()))?;
        let (digest, orig_len) = match crate::locate_header(&star) {
            Ok((h, _, _)) => (h.digest, h.orig_len.min(remain) as u32),
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

pub fn index_pack(input: &Path) -> Result<(WorkHead, Vec<StarLoc>)> {
    let mut f = File::open(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let head = read_head(&mut f)?;
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
            .map(|(h, _, _)| h.orig_len.min(remain) as u32)
            .unwrap_or(remain.min(head.chunk_size as u64) as u32);
        let leftover = star_len as i64 - peek_n as i64;
        if leftover > 0 {
            if std::io::Seek::seek(&mut f, SeekFrom::Current(leftover)).is_err() {
                break;
            }
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

pub fn unseal_star_at(input: &Path, loc: &StarLoc, pass: Option<&str>, companions: &[Vec<u8>]) -> Result<Vec<u8>> {
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
    f.read_exact(&mut star).map_err(|e| crate::Error::Msg(e.to_string()))?;
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
    let mut writer = BufWriter::new(File::create(output).map_err(|e| crate::Error::Msg(e.to_string()))?);
    let mut written = 0u64;
    let mut n = 0u32;
    for loc in &locs {
        if loc.index < from_star || loc.index > to_star {
            continue;
        }
        let plain = unseal_star_at_keys(input, loc, pass, companions, identities)?;
        writer.write_all(&plain).map_err(|e| crate::Error::Msg(e.to_string()))?;
        written += plain.len() as u64;
        n += 1;
    }
    writer.flush().map_err(|e| crate::Error::Msg(e.to_string()))?;
    if n == 0 {
        return Err(crate::Error::Msg(format!(
            "no slices in {from_star}..{to_star} (pack has 0..{})",
            head.stars.saturating_sub(1)
        )));
    }
    Ok((written, n))
}

/// Write each star as its own .sg1 in a folder (for torrent/IPFS of large work).
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
        input, dir, mode, pass, covenant, geas, chunk, shards, piece_bytes, overture_mb, cdc, &[],
    )
}

/// Like `inscribe_stars_dir`, with optional encrypt-to recipients on every star.
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
    let orig = std::fs::metadata(input).map_err(|e| crate::Error::Msg(e.to_string()))?.len();
    let piece_bytes = if piece_bytes == 0 { DEFAULT_PIECE } else { piece_bytes };
    let name = input.file_name().and_then(|s| s.to_str()).unwrap_or("file");
    if orig == 0 {
        let sealed = seal_kn_to(&[], mode, pass, name, false, covenant, geas, shards, piece_bytes, recipients)?;
        std::fs::write(dir.join("star-0000.sg1"), sealed).map_err(|e| crate::Error::Msg(e.to_string()))?;
        return Ok((0, 1));
    }
    if let Some(profile) = cdc {
        let data = std::fs::read(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
        let r = cdc::chunk_ranges(&data, profile);
        let stars = r.len().max(1) as u32;
        let chunk = profile.max as u32;
        for (i, range) in r.iter().enumerate() {
            let slice = &data[range.offset..range.end()];
            let sealed = seal_kn_to(
                slice,
                mode,
                pass,
                &format!("{name}.{i:04}"),
                false,
                covenant,
                geas,
                shards,
                piece_bytes,
                recipients,
            )?;
            std::fs::write(dir.join(format!("star-{i:04}.sg1")), sealed)
                .map_err(|e| crate::Error::Msg(e.to_string()))?;
        }
        let ov = choose_overture(stars, orig, chunk, overture_mb);
        let man = format!(
            "name={name}\nstars={stars}\norig={orig}\nchunk={chunk}\ncdc={}\noverture={ov}\n",
            profile.name
        );
        std::fs::write(dir.join("manifest.txt"), man).map_err(|e| crate::Error::Msg(e.to_string()))?;
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
    let mut reader = BufReader::new(File::open(input).map_err(|e| crate::Error::Msg(e.to_string()))?);
    let mut buf = vec![0u8; chunk as usize];
    let mut remain = orig;
    let mut i = 0u32;
    while remain > 0 {
        let n = remain.min(chunk as u64) as usize;
        reader.read_exact(&mut buf[..n]).map_err(|e| crate::Error::Msg(e.to_string()))?;
        let sealed = seal_kn_to(
            &buf[..n],
            mode,
            pass,
            &format!("{name}.{i:04}"),
            false,
            covenant,
            geas,
            shards,
            piece_bytes,
            recipients,
        )?;
        std::fs::write(dir.join(format!("star-{i:04}.sg1")), sealed)
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        remain -= n as u64;
        i += 1;
    }
    let ov = choose_overture(stars, orig, chunk, overture_mb);
    let man = format!("name={name}\nstars={stars}\norig={orig}\nchunk={chunk}\noverture={ov}\n");
    std::fs::write(dir.join("manifest.txt"), man).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let mut boot =
        String::from("Overture — copy these first; you can start before the rest arrives.\n");
    for i in 0..ov {
        boot.push_str(&format!("star-{i:04}.sg1\n"));
    }
    std::fs::write(dir.join(OVERTURE), boot).map_err(|e| crate::Error::Msg(e.to_string()))?;
    Ok((orig, stars))
}

/// Outcome of [`mend_pack_to`].
pub struct WorkMend {
    /// Plaintext bytes written.
    pub written: u64,
    /// Rebuilt SGWK bytes when at least one star was healed (same layout, same facets).
    pub healed: Option<Vec<u8>>,
    /// Indexes of stars that were mended.
    pub mended: Vec<u32>,
}

/// True when a star still opens but shards / Merkle (or its primary header) are damaged.
pub fn star_torn(star: &[u8]) -> bool {
    match crate::verify(star) {
        Ok((_, merkle_ok, _, _, recovered)) => !merkle_ok || recovered,
        Err(_) => true,
    }
}

/// Unseal an in-memory SGWK pack into `out`, mending torn chunk stars on the way.
///
/// Each chunk star is a complete `.sg1`, so it heals with the same RS mend as a
/// single-file mark. A star is mended when it fails to unseal, or opens but still
/// shows damage (bad shard CRC / Merkle / primary header). Healed stars must keep
/// the chunk true-name recorded in the SGFC facet trailer. The SGWK head, the
/// per-star length framing and the trailer are not RS-coded (like the outer SGDR):
/// damage there is refused, never guessed.
pub fn mend_pack_to<W: Write>(
    pack: &[u8],
    out: &mut W,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    identities: &[Identity],
) -> Result<WorkMend> {
    let mut cur = std::io::Cursor::new(pack);
    let head = read_head(&mut cur)?;
    let head_len = cur.position() as usize;
    let mut off = head_len;
    let mut spans: Vec<(usize, usize)> = Vec::with_capacity(head.stars as usize);
    for i in 0..head.stars {
        let lb = pack.get(off..off + 8).ok_or_else(|| {
            crate::Error::Msg(format!("work pack framing damaged at star {i} (length missing)"))
        })?;
        let len = u64::from_le_bytes(lb.try_into().unwrap()) as usize;
        off += 8;
        let end = off.checked_add(len).filter(|&e| e <= pack.len()).ok_or_else(|| {
            crate::Error::Msg(format!("work pack framing damaged at star {i} (bad length)"))
        })?;
        spans.push((off, end));
        off = end;
    }
    let trailer = &pack[off..];
    let facets: Option<Vec<[u8; 32]>> = {
        let n = head.stars as usize;
        if trailer.len() == 8 + 32 * n
            && &trailer[0..4] == b"SGFC"
            && u32::from_le_bytes(trailer[4..8].try_into().unwrap()) as usize == n
        {
            Some(trailer[8..].chunks(32).map(|c| c.try_into().unwrap()).collect())
        } else {
            None
        }
    };

    let mut healed_stars: Vec<(u32, Vec<u8>)> = Vec::new();
    let mut written = 0u64;
    for (i, &(a, b)) in spans.iter().enumerate() {
        let i = i as u32;
        let star = &pack[a..b];
        let opened = unseal_ex_keys(star, pass, companions, identities);
        let plain = match opened {
            Ok(p) if !star_torn(star) => p,
            opened => match crate::pieces::mend_bytes(star) {
                Ok(healed) => {
                    let p = unseal_ex_keys(&healed, pass, companions, identities)?;
                    if let Some(f) = &facets {
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
                Err(_) if opened.is_ok() => opened.unwrap(),
                Err(e) => {
                    return Err(crate::Error::Msg(format!(
                        "star {i} of {} is too damaged to mend: {e}",
                        head.stars
                    )))
                }
            },
        };
        out.write_all(&plain).map_err(|e| crate::Error::Msg(e.to_string()))?;
        written += plain.len() as u64;
    }
    if written != head.orig_total {
        return Err(crate::Error::Msg(format!(
            "work length mismatch: got {written} expected {}",
            head.orig_total
        )));
    }
    let mended: Vec<u32> = healed_stars.iter().map(|(i, _)| *i).collect();
    let healed = if healed_stars.is_empty() {
        None
    } else {
        let mut rebuilt = Vec::with_capacity(pack.len());
        rebuilt.extend_from_slice(&pack[..head_len]);
        let mut next = healed_stars.into_iter().peekable();
        for (i, &(a, b)) in spans.iter().enumerate() {
            let replacement = match next.peek() {
                Some((j, _)) if *j as usize == i => next.next().map(|(_, s)| s),
                _ => None,
            };
            let star: &[u8] = replacement.as_deref().unwrap_or(&pack[a..b]);
            rebuilt.extend_from_slice(&(star.len() as u64).to_le_bytes());
            rebuilt.extend_from_slice(star);
        }
        rebuilt.extend_from_slice(trailer);
        Some(rebuilt)
    };
    Ok(WorkMend {
        written,
        healed,
        mended,
    })
}

pub fn unseal_path(input: &Path, output: &Path, pass: Option<&str>, companions: &[Vec<u8>]) -> Result<u64> {
    unseal_path_keys(input, output, pass, companions, &[])
}

pub fn unseal_path_keys(
    input: &Path,
    output: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    identities: &[Identity],
) -> Result<u64> {
    let mut reader = BufReader::new(File::open(input).map_err(|e| crate::Error::Msg(e.to_string()))?);
    let mut mag = [0u8; 4];
    reader.read_exact(&mut mag).map_err(|e| crate::Error::Msg(e.to_string()))?;
    if mag == WORK_MAGIC {
        // rewind by reopening — BufReader already consumed 4 bytes; reconstruct
        drop(reader);
        let mut reader = BufReader::new(File::open(input).map_err(|e| crate::Error::Msg(e.to_string()))?);
        let head = read_head(&mut reader)?;
        let mut writer = BufWriter::new(File::create(output).map_err(|e| crate::Error::Msg(e.to_string()))?);
        let mut written = 0u64;
        for _ in 0..head.stars {
            let mut lenb = [0u8; 8];
            reader.read_exact(&mut lenb).map_err(|e| crate::Error::Msg(e.to_string()))?;
            let len = u64::from_le_bytes(lenb) as usize;
            let mut star = vec![0u8; len];
            reader.read_exact(&mut star).map_err(|e| crate::Error::Msg(e.to_string()))?;
            let plain = unseal_ex_keys(&star, pass, companions, identities)?;
            writer.write_all(&plain).map_err(|e| crate::Error::Msg(e.to_string()))?;
            written += plain.len() as u64;
        }
        writer.flush().map_err(|e| crate::Error::Msg(e.to_string()))?;
        if written != head.orig_total {
            return Err(crate::Error::Msg(format!(
                "work length mismatch: got {written} expected {}",
                head.orig_total
            )));
        }
        return Ok(written);
    }
    drop(reader);
    let data = std::fs::read(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let plain = unseal_ex_keys(&data, pass, companions, identities)?;
    let n = plain.len() as u64;
    std::fs::write(output, plain).map_err(|e| crate::Error::Msg(e.to_string()))?;
    Ok(n)
}

pub fn payload_name(input: &Path) -> Result<String> {
    let mut f = File::open(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let mut mag = [0u8; 4];
    f.read_exact(&mut mag).map_err(|e| crate::Error::Msg(e.to_string()))?;
    if mag == WORK_MAGIC {
        drop(f);
        let mut reader = BufReader::new(File::open(input).map_err(|e| crate::Error::Msg(e.to_string()))?);
        let head = read_head(&mut reader)?;
        if head.name.is_empty() {
            return Ok("payload.bin".into());
        }
        return Ok(head.name);
    }
    drop(f);
    let data = std::fs::read(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let (h, _, _) = crate::locate_header(&data)?;
    if h.name.is_empty() {
        Ok("payload.bin".into())
    } else {
        Ok(h.name)
    }
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

pub fn scry_path(input: &Path) -> Result<String> {
    let mut f = File::open(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let mut mag = [0u8; 4];
    f.read_exact(&mut mag).map_err(|e| crate::Error::Msg(e.to_string()))?;
    if mag == WORK_MAGIC {
        drop(f);
        let mut reader = BufReader::new(File::open(input).map_err(|e| crate::Error::Msg(e.to_string()))?);
        let head = read_head(&mut reader)?;
        let mut s = format!(
            "work  name={} orig={} chunk={} stars={} overture={}/{} (first ~{} MiB to start)",
            head.name,
            head.orig_total,
            head.chunk_size,
            head.stars,
            head.overture,
            head.stars,
            (head.overture as u64 * head.chunk_size as u64) / (1024 * 1024)
        );
        drop(reader);
        if let Ok(facets) = scry_facets(input) {
            for f in facets {
                let tag = if f.index < head.overture { "overture" } else { "follow" };
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
    let mut s = format!(
        "ok  v{}  live={live}/{} need={k} merkle={} keystone={} orig={} entropy={} name={}",
        h.version,
        h.n,
        if merkle_ok { "closed" } else { "open" },
        if recovered { "recovered" } else { "intact" },
        h.orig_len,
        h.entropy_milli,
        h.name
    );
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
            &src, &out, Mode::Seal, None, "", &[], 64 * 1024, None, DEFAULT_PIECE, 0, None, recipients,
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
        assert_eq!(read_facet_digests_bytes(&healed), read_facet_digests_bytes(&pack));
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
        let e = mend_pack_to(&torn, &mut out, None, &[], &[]).err().unwrap().to_string();
        assert!(e.contains("star 2"), "{e}");

        let mut framing = pack.clone();
        framing[spans[1].0 - 8..spans[1].0].copy_from_slice(&u64::MAX.to_le_bytes());
        let e = mend_pack_to(&framing, &mut Vec::new(), None, &[], &[]).err().unwrap().to_string();
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
        assert!(mend_pack_to(&torn, &mut Vec::new(), None, &[], &[]).is_err(), "needs identity");
        let mut out = Vec::new();
        let m = mend_pack_to(&torn, &mut out, None, &[], &[id]).unwrap();
        assert_eq!(out, d);
        assert_eq!(m.mended, vec![0]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
