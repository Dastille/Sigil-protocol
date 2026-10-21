//! Folder Inscribe: a directory becomes one SGDR pack of per-file marks.

use crate::keys::{Identity, PublicIdentity};
use crate::staging::Staging;
use crate::{seal_kn_to, unseal_ex_keys, Mode, Result, DEFAULT_PIECE};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Read, Write};
use std::path::{Path, PathBuf};

pub const DIR_MAGIC: [u8; 4] = *b"SGDR";

fn io(e: std::io::Error) -> crate::Error {
    crate::Error::Msg(e.to_string())
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    let rd = fs::read_dir(dir).map_err(io)?;
    let mut ents: Vec<_> = rd.collect::<std::io::Result<Vec<_>>>().map_err(io)?;
    ents.sort_by_key(|e| e.file_name());
    for e in ents {
        let p = e.path();
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') {
            continue;
        }
        if p.is_dir() {
            walk(&p, out)?;
        } else if p.is_file() {
            out.push(p);
        }
    }
    Ok(())
}

fn rel(root: &Path, file: &Path) -> String {
    file.strip_prefix(root)
        .unwrap_or(file)
        .to_string_lossy()
        .replace('\\', "/")
}

/// Sorted `(rel, path)` list of the files a folder Inscribe would pack
/// (dotfiles skipped, `/` separators). Used by vault tree digests.
pub(crate) fn tree_files(root: &Path) -> Result<Vec<(String, PathBuf)>> {
    let mut files = Vec::new();
    walk(root, &mut files)?;
    let mut out: Vec<(String, PathBuf)> = files.into_iter().map(|p| (rel(root, &p), p)).collect();
    out.sort_by(|a, b| a.0.cmp(&b.0));
    Ok(out)
}

// Justification: each parameter is an independent user-facing seal option threaded
// straight from the CLI (mode, passphrase, covenant, geas, chunking, wards, recipients...).
// Bundling them into an options struct is a public-API refactor tracked separately;
// this PR keeps signatures stable.
#[allow(clippy::too_many_arguments)]
pub fn inscribe_dir(
    root: &Path,
    output: &Path,
    mode: Mode,
    pass: Option<&str>,
    covenant: &str,
    geas: &[[u8; 32]],
    chunk: u32,
    wards: &[(String, String)],
) -> Result<(u32, u64)> {
    inscribe_dir_to(root, output, mode, pass, covenant, geas, chunk, wards, &[])
}

/// Like `inscribe_dir`, with encrypt-to recipients applied to every file star.
// Justification: each parameter is an independent user-facing seal option threaded
// straight from the CLI (mode, passphrase, covenant, geas, chunking, wards, recipients...).
// Bundling them into an options struct is a public-API refactor tracked separately;
// this PR keeps signatures stable.
#[allow(clippy::too_many_arguments)]
pub fn inscribe_dir_to(
    root: &Path,
    output: &Path,
    mode: Mode,
    pass: Option<&str>,
    covenant: &str,
    geas: &[[u8; 32]],
    chunk: u32,
    wards: &[(String, String)],
    recipients: &[PublicIdentity],
) -> Result<(u32, u64)> {
    let mut files = Vec::new();
    walk(root, &mut files)?;
    if files.is_empty() {
        return Err(crate::Error::Msg("folder is empty".into()));
    }
    let mut writer = BufWriter::new(File::create(output).map_err(io)?);
    writer.write_all(&DIR_MAGIC).map_err(io)?;
    writer.write_all(&[1u8]).map_err(io)?;
    writer
        .write_all(&(files.len() as u32).to_le_bytes())
        .map_err(io)?;
    let mut total = 0u64;
    for path in &files {
        let rel = rel(root, path);
        let size = path.metadata().map(|m| m.len()).unwrap_or(0);
        total += size;
        let file_pass = pass_for(&rel, pass, wards);
        let star = if size <= chunk as u64 {
            let data = fs::read(path).map_err(io)?;
            seal_kn_to(
                &data,
                mode,
                file_pass.as_deref(),
                &rel,
                false,
                covenant,
                geas,
                None,
                DEFAULT_PIECE,
                recipients,
            )?
        } else {
            let tmp = output.with_extension(format!("tmp-{rel}", rel = rel.replace('/', "_")));
            crate::work::inscribe_path_to(
                path,
                &tmp,
                mode,
                file_pass.as_deref(),
                covenant,
                geas,
                chunk,
                None,
                DEFAULT_PIECE,
                crate::work::DEFAULT_OVERTURE_MB,
                None,
                recipients,
            )?;
            let packed = fs::read(&tmp).map_err(io)?;
            let _ = fs::remove_file(&tmp);
            packed
        };
        let pb = rel.as_bytes();
        let nlen = (pb.len().min(65535)) as u16;
        writer.write_all(&nlen.to_le_bytes()).map_err(io)?;
        writer.write_all(&pb[..nlen as usize]).map_err(io)?;
        writer
            .write_all(&(star.len() as u64).to_le_bytes())
            .map_err(io)?;
        writer.write_all(&star).map_err(io)?;
    }
    writer.flush().map_err(io)?;
    Ok((files.len() as u32, total))
}

pub fn unseal_dir(
    input: &Path,
    dest: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
) -> Result<u32> {
    unseal_dir_only(input, dest, pass, companions, &[], &[])
}

pub fn unseal_dir_only(
    input: &Path,
    dest: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    only: &[String],
    wards: &[(String, String)],
) -> Result<u32> {
    unseal_dir_only_keys(input, dest, pass, companions, only, wards, &[])
}

pub fn unseal_dir_only_keys(
    input: &Path,
    dest: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    only: &[String],
    wards: &[(String, String)],
    identities: &[Identity],
) -> Result<u32> {
    // All-or-nothing: members land as part files and are renamed into place
    // only after every wanted member has unsealed and verified.
    let mut staged = Staging::new();
    staged.make_dir(dest)?;
    let mut reader = BufReader::new(File::open(input).map_err(io)?);
    let mut mag = [0u8; 4];
    reader.read_exact(&mut mag).map_err(io)?;
    if mag != DIR_MAGIC {
        return Err(crate::Error::Msg("not a folder pack (SGDR)".into()));
    }
    let mut ver = [0u8; 1];
    reader.read_exact(&mut ver).map_err(io)?;
    if ver[0] != 1 {
        return Err(crate::Error::Msg(format!(
            "unknown folder pack version {}",
            ver[0]
        )));
    }
    let mut nbuf = [0u8; 4];
    reader.read_exact(&mut nbuf).map_err(io)?;
    let n = u32::from_le_bytes(nbuf);
    let mut got = 0u32;
    for _ in 0..n {
        let mut lb = [0u8; 2];
        reader.read_exact(&mut lb).map_err(io)?;
        let nlen = u16::from_le_bytes(lb) as usize;
        let mut name = vec![0u8; nlen];
        reader.read_exact(&mut name).map_err(io)?;
        let rel = String::from_utf8_lossy(&name).into_owned();
        if rel.contains("..") || Path::new(&rel).is_absolute() {
            return Err(crate::Error::Msg(
                "refusing unsafe path in folder pack".into(),
            ));
        }
        let mut sl = [0u8; 8];
        reader.read_exact(&mut sl).map_err(io)?;
        let slen = u64::from_le_bytes(sl) as usize;
        let mut star = vec![0u8; slen];
        reader.read_exact(&mut star).map_err(io)?;
        if !wanted(&rel, only) {
            continue;
        }
        let out_path = dest.join(&rel);
        let file_pass = pass_for(&rel, pass, wards);
        if star.starts_with(&crate::work::WORK_MAGIC) {
            staged.write_with(&out_path, |w| {
                crate::work::unseal_bytes_into(
                    &star,
                    w,
                    file_pass.as_deref(),
                    companions,
                    identities,
                )
            })?;
        } else {
            let plain = unseal_ex_keys(&star, file_pass.as_deref(), companions, identities)?;
            staged.write(&out_path, &plain)?;
        }
        got += 1;
    }
    if !only.is_empty() && got == 0 {
        return Err(crate::Error::Msg(
            "nothing matched --only (Scry the pack to see paths)".into(),
        ));
    }
    staged.commit()?;
    Ok(got)
}

/// Parse an SGDR pack, unseal each wanted entry into `dest`, and mend inner stars
/// (classic `.sg1` members and the chunk stars of WORK/SGWK members) that fail to
/// unseal or still show damage.
///
/// Returns `(files_written, healed_pack)`. `healed_pack` is `Some` when at least
/// one star (classic or WORK chunk) was mended; the outer SGDR container is rewritten with healed
/// star bytes (same layout — the pack itself is not RS-coded). Vault
/// [`crate::vault::restore_ex`] persists that pack over the version seal path.
///
/// WORK/SGWK large-file members are mended star-by-star (each chunk star is a
/// full `.sg1`) via [`crate::work::mend_pack_to`]; their SGWK framing is kept.
pub fn unseal_dir_mend_keys(
    input: &Path,
    dest: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    only: &[String],
    wards: &[(String, String)],
    identities: &[Identity],
) -> Result<(u32, Option<Vec<u8>>)> {
    let mut staged = Staging::new();
    staged.make_dir(dest)?;
    let raw = fs::read(input).map_err(io)?;
    let entries = parse_sgdr_entries(&raw)?;
    let mut healed_stars: Vec<(String, Vec<u8>)> = Vec::with_capacity(entries.len());
    let mut any_mended = false;
    let mut got = 0u32;

    for (rel, star) in entries {
        let mut star = star;
        if rel.contains("..") || Path::new(&rel).is_absolute() {
            return Err(crate::Error::Msg(
                "refusing unsafe path in folder pack".into(),
            ));
        }
        let want = wanted(&rel, only);
        if want {
            if star.starts_with(&crate::work::WORK_MAGIC) {
                // WORK/SGWK large-file member: mend torn chunk stars, keep framing.
                let out_path = dest.join(&rel);
                let file_pass = pass_for(&rel, pass, wards);
                let m = staged
                    .write_with(&out_path, |w| {
                        crate::work::mend_pack_to(
                            &star,
                            w,
                            file_pass.as_deref(),
                            companions,
                            identities,
                        )
                    })
                    .map_err(|e| {
                        crate::Error::Msg(format!(
                            "large-file member '{rel}' could not be restored: {e}"
                        ))
                    })?;
                if let Some(healed) = m.healed {
                    star = healed;
                    any_mended = true;
                }
                got += 1;
            } else {
                let file_pass = pass_for(&rel, pass, wards);
                // Classic seal: unseal may succeed within Seal budget while shards
                // remain torn. Mend whenever unseal fails or verify shows damage.
                // (Outer SGDR container is not RS-coded.)
                let opened = unseal_ex_keys(&star, file_pass.as_deref(), companions, identities);
                let plain = match opened {
                    Ok(p) if !crate::work::star_torn(&star) => p,
                    opened => match crate::pieces::mend_bytes(&star) {
                        Ok(healed) => {
                            let p = unseal_ex_keys(
                                &healed,
                                file_pass.as_deref(),
                                companions,
                                identities,
                            )?;
                            star = healed;
                            any_mended = true;
                            p
                        }
                        // Opened within budget but couldn't be re-sealed clean: keep as-is.
                        Err(e) => match opened {
                            Ok(p) => p,
                            Err(_) => {
                                return Err(crate::Error::Msg(format!(
                                    "classic star '{rel}' failed to unseal/verify and could not be mended: {e}"
                                )))
                            }
                        },
                    },
                };
                staged.write(&dest.join(&rel), &plain)?;
                got += 1;
            }
        }
        healed_stars.push((rel, star));
    }

    if !only.is_empty() && got == 0 {
        return Err(crate::Error::Msg(
            "nothing matched --only (Scry the pack to see paths)".into(),
        ));
    }

    let healed_pack = if any_mended {
        Some(encode_sgdr(&healed_stars)?)
    } else {
        None
    };
    staged.commit()?;
    Ok((got, healed_pack))
}

fn parse_sgdr_entries(raw: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    if raw.len() < 9 {
        return Err(crate::Error::Msg("folder pack too short".into()));
    }
    if raw[0..4] != DIR_MAGIC {
        return Err(crate::Error::Msg("not a folder pack (SGDR)".into()));
    }
    if raw[4] != 1 {
        return Err(crate::Error::Msg(format!(
            "unknown folder pack version {}",
            raw[4]
        )));
    }
    let n = u32::from_le_bytes(raw[5..9].try_into().map_err(crate::short_field)?);
    let mut off = 9usize;
    // `n` is untrusted: each entry needs >= 10 bytes, so never pre-allocate beyond that.
    let mut entries = Vec::with_capacity((n as usize).min(raw.len() / 10));
    for _ in 0..n {
        if off + 2 > raw.len() {
            return Err(crate::Error::Msg("truncated folder pack (name len)".into()));
        }
        let nlen =
            u16::from_le_bytes(raw[off..off + 2].try_into().map_err(crate::short_field)?) as usize;
        off += 2;
        if off + nlen + 8 > raw.len() {
            return Err(crate::Error::Msg(
                "truncated folder pack (name/star len)".into(),
            ));
        }
        let name = String::from_utf8_lossy(&raw[off..off + nlen]).into_owned();
        off += nlen;
        let slen = usize::try_from(u64::from_le_bytes(
            raw[off..off + 8].try_into().map_err(crate::short_field)?,
        ))
        .unwrap_or(usize::MAX);
        off += 8;
        if slen > raw.len() - off {
            return Err(crate::Error::Msg(
                "truncated folder pack (star bytes)".into(),
            ));
        }
        let star = raw[off..off + slen].to_vec();
        off += slen;
        entries.push((name, star));
    }
    Ok(entries)
}

fn encode_sgdr(entries: &[(String, Vec<u8>)]) -> Result<Vec<u8>> {
    let mut out = Vec::new();
    out.extend_from_slice(&DIR_MAGIC);
    out.push(1u8);
    out.extend_from_slice(&(entries.len() as u32).to_le_bytes());
    for (rel, star) in entries {
        let pb = rel.as_bytes();
        let nlen = (pb.len().min(65535)) as u16;
        out.extend_from_slice(&nlen.to_le_bytes());
        out.extend_from_slice(&pb[..nlen as usize]);
        out.extend_from_slice(&(star.len() as u64).to_le_bytes());
        out.extend_from_slice(star);
    }
    Ok(out)
}

fn pass_for(rel: &str, default: Option<&str>, wards: &[(String, String)]) -> Option<String> {
    for (p, w) in wards {
        if p == rel {
            return Some(w.clone());
        }
    }
    default.map(|s| s.to_string())
}

fn wanted(rel: &str, only: &[String]) -> bool {
    if only.is_empty() {
        return true;
    }
    only.iter().any(|p| {
        let p = p.trim().trim_start_matches("./");
        rel == p
            || rel.starts_with(&(p.to_string() + "/"))
            || (p.ends_with('/') && rel.starts_with(p))
    })
}

pub fn scry_dir(input: &Path) -> Result<String> {
    let entries = list_dir_pack(input)?;
    let mut dirs: Vec<String> = Vec::new();
    for e in &entries {
        if let Some(p) = e.path.rsplit_once('/').map(|(d, _)| d) {
            let mut cur = String::new();
            for seg in p.split('/') {
                if seg.is_empty() {
                    continue;
                }
                if !cur.is_empty() {
                    cur.push('/');
                }
                cur.push_str(seg);
                let d = format!("{cur}/");
                if !dirs.iter().any(|x| x == &d) {
                    dirs.push(d);
                }
            }
        }
    }
    dirs.sort();
    let mut out = format!("folder  files={} dirs={}\n", entries.len(), dirs.len());
    for d in &dirs {
        out.push_str("dir   ");
        out.push_str(d);
        out.push('\n');
    }
    for e in &entries {
        if e.nest {
            out.push_str("nest  ");
        } else {
            out.push_str("file  ");
        }
        out.push_str(&e.path);
        if let Some(n) = e.orig {
            out.push_str(&format!("  {n} bytes"));
        }
        out.push('\n');
    }
    Ok(out.trim_end().to_string())
}

pub struct DirEntry {
    pub path: String,
    pub orig: Option<u64>,
    /// Likely a nested .sg1 / work pack (by name or peeked magic).
    pub nest: bool,
    /// Payload true-name digest from the entry's star header, when readable.
    pub digest: Option<[u8; 32]>,
}

pub fn list_dir_pack(input: &Path) -> Result<Vec<DirEntry>> {
    let mut reader = BufReader::new(File::open(input).map_err(io)?);
    let mut mag = [0u8; 4];
    reader.read_exact(&mut mag).map_err(io)?;
    if mag != DIR_MAGIC {
        return Err(crate::Error::Msg("not a folder pack".into()));
    }
    let mut ver = [0u8; 1];
    reader.read_exact(&mut ver).map_err(io)?;
    if ver[0] != 1 {
        return Err(crate::Error::Msg(format!(
            "unknown folder pack version {}",
            ver[0]
        )));
    }
    let mut nbuf = [0u8; 4];
    reader.read_exact(&mut nbuf).map_err(io)?;
    let n = u32::from_le_bytes(nbuf);
    let mut entries = Vec::with_capacity(n as usize);
    for _ in 0..n {
        let mut lb = [0u8; 2];
        reader.read_exact(&mut lb).map_err(io)?;
        let nlen = u16::from_le_bytes(lb) as usize;
        let mut name = vec![0u8; nlen];
        reader.read_exact(&mut name).map_err(io)?;
        let path = String::from_utf8_lossy(&name).into_owned();
        let mut sl = [0u8; 8];
        reader.read_exact(&mut sl).map_err(io)?;
        let slen = u64::from_le_bytes(sl);
        let peek_n = slen.min(1024) as usize;
        let mut peek = vec![0u8; peek_n];
        if peek_n > 0 {
            reader.read_exact(&mut peek).map_err(io)?;
        }
        let orig = peek_orig(&peek);
        let (nest, digest) = peek_nest(&peek, &path);
        let mut left = slen.saturating_sub(peek_n as u64);
        let mut buf = vec![0u8; 64 * 1024];
        while left > 0 {
            let take = left.min(buf.len() as u64) as usize;
            reader.read_exact(&mut buf[..take]).map_err(io)?;
            left -= take as u64;
        }
        entries.push(DirEntry {
            path,
            orig,
            nest,
            digest,
        });
    }
    Ok(entries)
}

fn peek_orig(peek: &[u8]) -> Option<u64> {
    if peek.len() >= 4 && peek.starts_with(&crate::work::WORK_MAGIC) {
        // SGWK: after magic+ver+chunk(4)+orig(8)
        if peek.len() >= 4 + 1 + 4 + 8 {
            let orig = u64::from_le_bytes(peek[9..17].try_into().ok()?);
            return Some(orig);
        }
        return None;
    }
    crate::locate_header(peek).ok().map(|(h, _, _)| h.orig_len)
}

pub fn is_dir_pack(path: &Path) -> bool {
    if let Ok(mut f) = File::open(path) {
        let mut mag = [0u8; 4];
        if f.read_exact(&mut mag).is_ok() {
            return mag == DIR_MAGIC;
        }
    }
    false
}

/// True when a relative path looks like a nested seal (by extension).
pub fn looks_like_nest_name(path: &str) -> bool {
    let p = path.trim().replace('\\', "/");
    let base = p.rsplit('/').next().unwrap_or(p.as_str());
    let lower = base.to_ascii_lowercase();
    lower.ends_with(".sg1") || lower.ends_with(".sgwk")
}

/// Peek nest flag + true-name digest from the first bytes of a star.
fn peek_nest(peek: &[u8], path: &str) -> (bool, Option<[u8; 32]>) {
    let mut nest = looks_like_nest_name(path);
    let mut digest = None;
    if peek.starts_with(&crate::work::WORK_MAGIC) || peek.starts_with(&DIR_MAGIC) {
        nest = true;
    } else if let Ok((h, _, _)) = crate::locate_header(peek) {
        digest = Some(h.digest);
        if looks_like_nest_name(&h.name) {
            nest = true;
        }
    }
    (nest, digest)
}

/// Stream one entry's star bytes out of an SGDR pack (no full unpack to disk).
pub fn read_dir_entry_star(input: &Path, want: &str) -> Result<Vec<u8>> {
    let want = want.trim().trim_start_matches("./");
    let mut reader = BufReader::new(File::open(input).map_err(io)?);
    let mut mag = [0u8; 4];
    reader.read_exact(&mut mag).map_err(io)?;
    if mag != DIR_MAGIC {
        return Err(crate::Error::Msg("not a folder pack (SGDR)".into()));
    }
    let mut ver = [0u8; 1];
    reader.read_exact(&mut ver).map_err(io)?;
    if ver[0] != 1 {
        return Err(crate::Error::Msg(format!(
            "unknown folder pack version {}",
            ver[0]
        )));
    }
    let mut nbuf = [0u8; 4];
    reader.read_exact(&mut nbuf).map_err(io)?;
    let n = u32::from_le_bytes(nbuf);
    for _ in 0..n {
        let mut lb = [0u8; 2];
        reader.read_exact(&mut lb).map_err(io)?;
        let nlen = u16::from_le_bytes(lb) as usize;
        let mut name = vec![0u8; nlen];
        reader.read_exact(&mut name).map_err(io)?;
        let rel = String::from_utf8_lossy(&name).into_owned();
        let mut sl = [0u8; 8];
        reader.read_exact(&mut sl).map_err(io)?;
        let slen = u64::from_le_bytes(sl) as usize;
        if rel == want {
            let mut star = vec![0u8; slen];
            if slen > 0 {
                reader.read_exact(&mut star).map_err(io)?;
            }
            return Ok(star);
        }
        let mut left = slen;
        let mut buf = vec![0u8; 64 * 1024];
        while left > 0 {
            let take = left.min(buf.len());
            reader.read_exact(&mut buf[..take]).map_err(io)?;
            left -= take;
        }
    }
    Err(crate::Error::Msg(format!(
        "no entry '{want}' in folder pack (Scry / path to list)"
    )))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Every file under `dir`, relative, sorted (directories omitted).
    fn listing(dir: &Path) -> Vec<String> {
        let mut out = Vec::new();
        if dir.exists() {
            walk(dir, &mut out).unwrap();
        }
        let mut v: Vec<String> = out.iter().map(|p| rel(dir, p)).collect();
        v.sort();
        v
    }

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "sigil-folder-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn noise(n: usize) -> Vec<u8> {
        let mut x = 0x2545f4914f6cdd1du64;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    /// A folder pack of a.txt, m/big.bin (a 4-star work pack) and z.txt.
    fn three_file_pack(root: &Path) -> (PathBuf, Vec<u8>) {
        let src = root.join("src");
        fs::create_dir_all(src.join("m")).unwrap();
        fs::write(src.join("a.txt"), b"alpha").unwrap();
        fs::write(src.join("m/big.bin"), noise(200_000)).unwrap();
        fs::write(src.join("z.txt"), b"omega").unwrap();
        let pack = root.join("f.sg1");
        inscribe_dir(&src, &pack, Mode::Seal, None, "", &[], 64 * 1024, &[]).unwrap();
        let raw = fs::read(&pack).unwrap();
        (pack, raw)
    }

    /// Zero entry `name`'s star bytes inside the raw SGDR pack (beyond repair),
    /// or only `[from..to)` of them.
    fn wreck(raw: &[u8], name: &str, part: Option<(usize, usize)>) -> Vec<u8> {
        let entries = parse_sgdr_entries(raw).unwrap();
        let star = &entries.iter().find(|(r, _)| r == name).unwrap().1;
        let at = raw
            .windows(star.len())
            .position(|w| w == star.as_slice())
            .unwrap();
        let (a, b) = part.unwrap_or((0, star.len()));
        let mut out = raw.to_vec();
        out[at + a..at + b].fill(0);
        out
    }

    #[test]
    fn failed_folder_restore_writes_nothing_and_keeps_existing_files() {
        let root = scratch("atomic");
        let (pack, raw) = three_file_pack(&root);
        let wrecked_last = wreck(&raw, "z.txt", None);
        let big_star_len = parse_sgdr_entries(&raw)
            .unwrap()
            .into_iter()
            .find(|(r, _)| r == "m/big.bin")
            .unwrap()
            .1
            .len();
        // Wreck the middle of the work-pack member (two whole stars' worth).
        let wrecked_mid = wreck(
            &raw,
            "m/big.bin",
            Some((big_star_len / 3, big_star_len * 2 / 3)),
        );
        for (what, bytes) in [
            ("last file", &wrecked_last),
            ("work-pack member", &wrecked_mid),
        ] {
            fs::write(&pack, bytes).unwrap();
            // Fresh destination: nothing at all is left behind, not even the folder.
            let dest = root.join("fresh");
            let _ = fs::remove_dir_all(&dest);
            assert!(unseal_dir(&pack, &dest, None, &[]).is_err(), "{what}");
            assert!(listing(&dest).is_empty(), "{what}: {:?}", listing(&dest));
            assert!(!dest.exists(), "{what}: created folder removed");
            assert!(unseal_dir_mend_keys(&pack, &dest, None, &[], &[], &[], &[]).is_err());
            assert!(
                !dest.exists(),
                "{what}: mend restore left {:?}",
                listing(&dest)
            );
            // Existing destination: its files stay exactly as they were.
            let keep = root.join("keep");
            let _ = fs::remove_dir_all(&keep);
            fs::create_dir_all(&keep).unwrap();
            fs::write(keep.join("a.txt"), b"previous").unwrap();
            assert!(unseal_dir(&pack, &keep, None, &[]).is_err());
            assert!(unseal_dir_mend_keys(&pack, &keep, None, &[], &[], &[], &[]).is_err());
            assert_eq!(listing(&keep), vec!["a.txt".to_string()], "{what}");
            assert_eq!(fs::read(keep.join("a.txt")).unwrap(), b"previous");
        }
        // The intact pack restores all three, replacing the old a.txt.
        fs::write(&pack, &raw).unwrap();
        let keep = root.join("keep");
        assert_eq!(unseal_dir(&pack, &keep, None, &[]).unwrap(), 3);
        assert_eq!(listing(&keep), vec!["a.txt", "m/big.bin", "z.txt"]);
        assert_eq!(fs::read(keep.join("a.txt")).unwrap(), b"alpha");
        assert_eq!(fs::read(keep.join("m/big.bin")).unwrap(), noise(200_000));
        let dest = root.join("mended");
        assert_eq!(
            unseal_dir_mend_keys(&pack, &dest, None, &[], &[], &[], &[])
                .unwrap()
                .0,
            3
        );
        assert_eq!(listing(&dest), vec!["a.txt", "m/big.bin", "z.txt"]);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn wrong_key_folder_restore_writes_nothing() {
        let root = scratch("atomic-key");
        let src = root.join("src");
        fs::create_dir_all(&src).unwrap();
        fs::write(src.join("a.txt"), b"alpha").unwrap();
        fs::write(src.join("b.txt"), b"beta").unwrap();
        let pack = root.join("f.sg1");
        let wards = vec![("b.txt".to_string(), "b-secret".to_string())];
        inscribe_dir(&src, &pack, Mode::Seal, None, "", &[], 64 * 1024, &wards).unwrap();
        let dest = root.join("out");
        let wrong = vec![("b.txt".to_string(), "nope".to_string())];
        assert!(unseal_dir_only(&pack, &dest, None, &[], &[], &wrong).is_err());
        assert!(!dest.exists(), "left {:?}", listing(&dest));
        assert_eq!(
            unseal_dir_only(&pack, &dest, None, &[], &[], &wards).unwrap(),
            2
        );
        assert_eq!(listing(&dest), vec!["a.txt", "b.txt"]);
        let _ = fs::remove_dir_all(&root);
    }

    fn sgdr(count: u32) -> Vec<u8> {
        let mut raw = DIR_MAGIC.to_vec();
        raw.push(1);
        raw.extend_from_slice(&count.to_le_bytes());
        raw
    }

    #[test]
    fn hostile_entry_count_does_not_preallocate() {
        // u32::MAX entries announced, none present: must error, not abort on allocation.
        assert!(parse_sgdr_entries(&sgdr(u32::MAX)).is_err());
    }

    #[test]
    fn hostile_star_length_does_not_overflow() {
        let mut raw = sgdr(1);
        raw.extend_from_slice(&1u16.to_le_bytes());
        raw.push(b'a');
        raw.extend_from_slice(&u64::MAX.to_le_bytes());
        assert!(parse_sgdr_entries(&raw).is_err());
    }
}
