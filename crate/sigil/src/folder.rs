//! Folder Inscribe: a directory becomes one SGDR pack of per-file marks.
//!
//! Two layouts share the `SGDR` magic:
//!
//! - **v1** (plain): `SGDR | 1 | count u32 | { name_len u16 | name | star_len u64 | star }*`.
//!   Member names and per-member star lengths are in the clear. Written for packs
//!   sealed with no `--pass` / `--to` (and for packs whose only keys are per-file wards).
//! - **v2** (sealed directory, default for every encrypted folder pack):
//!   `SGDR | 2 | count u32 | body_len u64 | body`. `body` is one ordinary encrypted
//!   `.sg1` (or SGWK work pack for a large folder) whose plaintext is the complete v1
//!   pack. Names, per-member sizes and the directory tree are inside the AES-256-GCM
//!   lock; only the member count and the total ciphertext length stay visible. The body
//!   carries its own Reed-Solomon repair data, so keyless `mend` / `scry` still work.
//!   Members inside the body are still sealed with the same keys (Glyph mode: the body
//!   already carries the repair budget), so per-file wards keep working.
//!
//! v1 packs (including every encrypted pack written before v2 existed) open unchanged.

use crate::keys::{Identity, PublicIdentity};
use crate::staging::Staging;
use crate::{seal_kn_to, unseal_ex_keys, Mode, Result, DEFAULT_PIECE};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Cursor, Read, Write};
use std::path::{Path, PathBuf};

pub const DIR_MAGIC: [u8; 4] = *b"SGDR";
/// Plain folder pack: member names and sizes in the clear.
pub const DIR_VER_PLAIN: u8 = 1;
/// Sealed directory: the whole v1 pack is encrypted as one body star.
pub const DIR_VER_SEALED: u8 = 2;

const HIDDEN_HINT: &str =
    "encrypted folder pack: member names are hidden; give --pass / --identity to list or open it";

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

/// A sibling scratch path for `output` that no concurrent writer will pick.
fn scratch_beside(output: &Path, tag: &str) -> PathBuf {
    let mut r = [0u8; 8];
    // Only a uniqueness token; fall back to the pid if the RNG is unavailable.
    let token = match getrandom::getrandom(&mut r) {
        Ok(()) => u64::from_le_bytes(r),
        Err(_) => u64::from(std::process::id()),
    };
    let name = output
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "pack".into());
    output.with_file_name(format!(".{name}.{tag}-{}-{token:016x}", std::process::id()))
}

/// Removes a scratch file when dropped (success or error).
struct Scratch(PathBuf);
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_file(&self.0);
    }
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
///
/// With a passphrase or any recipient the pack is written as a sealed directory
/// (v2): names and per-member sizes are hidden. Without either it is a plain v1 pack.
// Justification: see `inscribe_dir`.
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
    let encrypted = pass.is_some() || !recipients.is_empty();
    if !encrypted {
        let mut writer = BufWriter::new(File::create(output).map_err(io)?);
        let total = write_v1(
            root,
            &files,
            &mut writer,
            output,
            mode,
            pass,
            covenant,
            geas,
            chunk,
            wards,
            recipients,
        )?;
        writer.flush().map_err(io)?;
        return Ok((files.len() as u32, total));
    }
    // Sealed directory: build the v1 pack (members sealed with the same keys, Glyph
    // mode because the body carries the repair budget), then seal it as one body.
    let inner = Scratch(scratch_beside(output, "sgdr-inner"));
    let total = {
        let mut w = BufWriter::new(File::create(&inner.0).map_err(io)?);
        let t = write_v1(
            root,
            &files,
            &mut w,
            output,
            Mode::Glyph,
            pass,
            covenant,
            geas,
            chunk,
            wards,
            recipients,
        )?;
        w.flush().map_err(io)?;
        t
    };
    let inner_len = fs::metadata(&inner.0).map_err(io)?.len();
    let body = if inner_len <= chunk as u64 {
        let data = fs::read(&inner.0).map_err(io)?;
        seal_kn_to(
            &data,
            mode,
            pass,
            "folder.sgdr",
            false,
            covenant,
            geas,
            None,
            DEFAULT_PIECE,
            recipients,
        )?
    } else {
        let packed = Scratch(scratch_beside(output, "sgdr-body"));
        crate::work::inscribe_path_to(
            &inner.0,
            &packed.0,
            mode,
            pass,
            covenant,
            geas,
            chunk,
            None,
            DEFAULT_PIECE,
            crate::work::DEFAULT_OVERTURE_MB,
            None,
            recipients,
        )?;
        fs::read(&packed.0).map_err(io)?
    };
    drop(inner);
    let mut writer = BufWriter::new(File::create(output).map_err(io)?);
    writer
        .write_all(&encode_sealed(files.len() as u32, &body))
        .map_err(io)?;
    writer.flush().map_err(io)?;
    Ok((files.len() as u32, total))
}

/// Write a v1 pack of `files` to `writer`; returns the plaintext byte total.
#[allow(clippy::too_many_arguments)]
fn write_v1<W: Write>(
    root: &Path,
    files: &[PathBuf],
    writer: &mut W,
    output: &Path,
    mode: Mode,
    pass: Option<&str>,
    covenant: &str,
    geas: &[[u8; 32]],
    chunk: u32,
    wards: &[(String, String)],
    recipients: &[PublicIdentity],
) -> Result<u64> {
    writer.write_all(&DIR_MAGIC).map_err(io)?;
    writer.write_all(&[DIR_VER_PLAIN]).map_err(io)?;
    writer
        .write_all(&(files.len() as u32).to_le_bytes())
        .map_err(io)?;
    let mut total = 0u64;
    for path in files {
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
            let tmp = Scratch(scratch_beside(output, "member"));
            crate::work::inscribe_path_to(
                path,
                &tmp.0,
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
            fs::read(&tmp.0).map_err(io)?
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
    Ok(total)
}

fn encode_sealed(count: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(17 + body.len());
    out.extend_from_slice(&DIR_MAGIC);
    out.push(DIR_VER_SEALED);
    out.extend_from_slice(&count.to_le_bytes());
    out.extend_from_slice(&(body.len() as u64).to_le_bytes());
    out.extend_from_slice(body);
    out
}

/// Read `SGDR | ver | count` and return `(ver, count)`; rejects unknown versions.
fn read_head<R: Read>(reader: &mut R, not_pack: &str) -> Result<(u8, u32)> {
    let mut mag = [0u8; 4];
    reader.read_exact(&mut mag).map_err(io)?;
    if mag != DIR_MAGIC {
        return Err(crate::Error::Msg(not_pack.into()));
    }
    let mut ver = [0u8; 1];
    reader.read_exact(&mut ver).map_err(io)?;
    if ver[0] != DIR_VER_PLAIN && ver[0] != DIR_VER_SEALED {
        return Err(crate::Error::Msg(format!(
            "unknown folder pack version {}",
            ver[0]
        )));
    }
    let mut nbuf = [0u8; 4];
    reader.read_exact(&mut nbuf).map_err(io)?;
    Ok((ver[0], u32::from_le_bytes(nbuf)))
}

/// Body bytes of a v2 pack whose head was just read. Exact length, no trailing bytes.
fn read_sealed_body<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let mut lb = [0u8; 8];
    reader
        .read_exact(&mut lb)
        .map_err(|_| crate::Error::Msg("truncated sealed folder pack (body length)".into()))?;
    let len = u64::from_le_bytes(lb);
    let mut body = Vec::new();
    // `len` is untrusted: read through `take` so a hostile length cannot pre-allocate.
    reader
        .by_ref()
        .take(len)
        .read_to_end(&mut body)
        .map_err(io)?;
    if (body.len() as u64) != len {
        return Err(crate::Error::Msg(
            "truncated sealed folder pack (body bytes)".into(),
        ));
    }
    let mut extra = [0u8; 1];
    if reader.read(&mut extra).map_err(io)? != 0 {
        return Err(crate::Error::Msg(
            "sealed folder pack has trailing bytes".into(),
        ));
    }
    Ok(body)
}

/// For a sealed-directory (v2) pack: `Some((member_count, body))`; `None` for v1.
pub fn sealed_dir_body(input: &Path) -> Result<Option<(u32, Vec<u8>)>> {
    let mut reader = BufReader::new(File::open(input).map_err(io)?);
    let (ver, n) = read_head(&mut reader, "not a folder pack (SGDR)")?;
    if ver != DIR_VER_SEALED {
        return Ok(None);
    }
    Ok(Some((n, read_sealed_body(&mut reader)?)))
}

/// True when `input` is a sealed-directory (v2) folder pack.
pub fn is_sealed_dir_pack(input: &Path) -> bool {
    let Ok(mut f) = File::open(input) else {
        return false;
    };
    let mut head = [0u8; 5];
    f.read_exact(&mut head).is_ok() && head[0..4] == DIR_MAGIC && head[4] == DIR_VER_SEALED
}

/// Decrypt a v2 body to its inner v1 pack and check it matches the outer count.
/// Fails closed on a wrong key, any tamper (GCM / Merkle), or a mismatched count.
fn open_body(
    count: u32,
    body: &[u8],
    pass: Option<&str>,
    companions: &[Vec<u8>],
    identities: &[Identity],
) -> Result<Vec<u8>> {
    let inner = if body.starts_with(&crate::work::WORK_MAGIC) {
        let mut v = Vec::new();
        crate::work::unseal_bytes_into(body, &mut v, pass, companions, identities)?;
        v
    } else {
        unseal_ex_keys(body, pass, companions, identities)?
    };
    check_inner(count, &inner)?;
    Ok(inner)
}

fn check_inner(count: u32, inner: &[u8]) -> Result<()> {
    let ok = inner.len() >= 9
        && inner[0..4] == DIR_MAGIC
        && inner[4] == DIR_VER_PLAIN
        && inner[5..9] == count.to_le_bytes();
    if ok {
        Ok(())
    } else {
        Err(crate::Error::Msg(
            "sealed folder pack: inner pack does not match its outer header (tampered?)".into(),
        ))
    }
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
    let mut reader = BufReader::new(File::open(input).map_err(io)?);
    let (ver, n) = read_head(&mut reader, "not a folder pack (SGDR)")?;
    if ver == DIR_VER_SEALED {
        if pass.is_none() && identities.is_empty() {
            return Err(crate::Error::Msg(HIDDEN_HINT.into()));
        }
        let body = read_sealed_body(&mut reader)?;
        let inner = open_body(n, &body, pass, companions, identities)?;
        let mut cur = Cursor::new(inner);
        let (_, n) = read_head(&mut cur, "not a folder pack (SGDR)")?;
        return unseal_v1_stream(&mut cur, n, dest, pass, companions, only, wards, identities);
    }
    unseal_v1_stream(
        &mut reader,
        n,
        dest,
        pass,
        companions,
        only,
        wards,
        identities,
    )
}

#[allow(clippy::too_many_arguments)]
fn unseal_v1_stream<R: Read>(
    reader: &mut R,
    n: u32,
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
        let slen = u64::from_le_bytes(sl);
        let mut star = Vec::new();
        reader
            .by_ref()
            .take(slen)
            .read_to_end(&mut star)
            .map_err(io)?;
        if star.len() as u64 != slen {
            return Err(crate::Error::Msg(
                "truncated folder pack (star bytes)".into(),
            ));
        }
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

/// Mend a classic star (unseal; RS-mend when it fails or shows damage).
/// Returns `(plain, Some(healed))` when the star was rewritten.
fn open_classic_mending(
    star: &[u8],
    pass: Option<&str>,
    companions: &[Vec<u8>],
    identities: &[Identity],
    what: &str,
) -> Result<(Vec<u8>, Option<Vec<u8>>)> {
    // Classic seal: unseal may succeed within Seal budget while shards
    // remain torn. Mend whenever unseal fails or verify shows damage.
    let opened = unseal_ex_keys(star, pass, companions, identities);
    match opened {
        Ok(p) if !crate::work::star_torn(star) => Ok((p, None)),
        opened => match crate::pieces::mend_bytes(star) {
            Ok(healed) => {
                let p = unseal_ex_keys(&healed, pass, companions, identities)?;
                Ok((p, Some(healed)))
            }
            // Opened within budget but couldn't be re-sealed clean: keep as-is.
            Err(e) => match opened {
                Ok(p) => Ok((p, None)),
                Err(_) => Err(crate::Error::Msg(format!(
                    "classic star '{what}' failed to unseal/verify and could not be mended: {e}"
                ))),
            },
        },
    }
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
///
/// A sealed-directory (v2) pack mends its body star (the body carries the repair
/// data); the inner pack is authenticated by the body's AES-256-GCM, so it is
/// opened as-is.
pub fn unseal_dir_mend_keys(
    input: &Path,
    dest: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    only: &[String],
    wards: &[(String, String)],
    identities: &[Identity],
) -> Result<(u32, Option<Vec<u8>>)> {
    let raw = fs::read(input).map_err(io)?;
    if raw.len() >= 5 && raw[0..4] == DIR_MAGIC && raw[4] == DIR_VER_SEALED {
        let mut cur = Cursor::new(&raw[..]);
        let (_, n) = read_head(&mut cur, "not a folder pack (SGDR)")?;
        let body = read_sealed_body(&mut cur)?;
        let (inner, healed_body) = if body.starts_with(&crate::work::WORK_MAGIC) {
            let mut v = Vec::new();
            let m = crate::work::mend_pack_to(&body, &mut v, pass, companions, identities)
                .map_err(|e| {
                    crate::Error::Msg(format!("sealed folder body could not be restored: {e}"))
                })?;
            (v, m.healed)
        } else {
            open_classic_mending(&body, pass, companions, identities, "sealed folder body")?
        };
        check_inner(n, &inner)?;
        let entries = parse_sgdr_entries(&inner)?;
        let (got, _) = restore_entries(
            entries, dest, pass, companions, only, wards, identities, false,
        )?;
        return Ok((got, healed_body.map(|b| encode_sealed(n, &b))));
    }
    let entries = parse_sgdr_entries(&raw)?;
    let (got, healed) = restore_entries(
        entries, dest, pass, companions, only, wards, identities, true,
    )?;
    let healed_pack = match healed {
        Some(stars) => Some(encode_sgdr(&stars)?),
        None => None,
    };
    Ok((got, healed_pack))
}

/// Keyless mend of a sealed-directory (v2) pack: heal the body's torn shards and
/// write the healed pack to `output` (via `.mend-part` + rename). Returns a one-line report.
pub fn mend_sealed_dir(input: &Path, output: &Path) -> Result<String> {
    let (n, body) = sealed_dir_body(input)?
        .ok_or_else(|| crate::Error::Msg("not a sealed folder pack".into()))?;
    let healed = if body.starts_with(&crate::work::WORK_MAGIC) {
        let src = Scratch(scratch_beside(output, "mend-body-in"));
        let dst = Scratch(scratch_beside(output, "mend-body-out"));
        fs::write(&src.0, &body).map_err(io)?;
        crate::work::mend_pack_path(&src.0, &dst.0, false)?;
        fs::read(&dst.0).map_err(io)?
    } else {
        crate::pieces::mend_bytes(&body)?
    };
    let mut part = output.as_os_str().to_os_string();
    part.push(".mend-part");
    let part = PathBuf::from(part);
    fs::write(&part, encode_sealed(n, &healed)).map_err(io)?;
    fs::rename(&part, output).map_err(io)?;
    let state = if crate::work::star_torn(&healed) && !healed.starts_with(&crate::work::WORK_MAGIC)
    {
        "open"
    } else {
        "ok"
    };
    Ok(format!(
        "mended {} → {} (sealed folder pack, {n} files, body merkle {state})",
        input.display(),
        output.display()
    ))
}

/// Restore `entries` into `dest` (all-or-nothing). With `mend`, torn member stars
/// are healed and the healed list is returned when anything changed.
#[allow(clippy::too_many_arguments)]
fn restore_entries(
    entries: Vec<(String, Vec<u8>)>,
    dest: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    only: &[String],
    wards: &[(String, String)],
    identities: &[Identity],
    mend: bool,
) -> Result<(u32, Option<Vec<(String, Vec<u8>)>>)> {
    let mut staged = Staging::new();
    staged.make_dir(dest)?;
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
        if wanted(&rel, only) {
            let file_pass = pass_for(&rel, pass, wards);
            if star.starts_with(&crate::work::WORK_MAGIC) {
                // WORK/SGWK large-file member: mend torn chunk stars, keep framing.
                let out_path = dest.join(&rel);
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
            } else if mend {
                let (plain, healed) = open_classic_mending(
                    &star,
                    file_pass.as_deref(),
                    companions,
                    identities,
                    &rel,
                )?;
                if let Some(h) = healed {
                    star = h;
                    any_mended = true;
                }
                staged.write(&dest.join(&rel), &plain)?;
            } else {
                let plain = unseal_ex_keys(&star, file_pass.as_deref(), companions, identities)?;
                staged.write(&dest.join(&rel), &plain)?;
            }
            got += 1;
        }
        healed_stars.push((rel, star));
    }

    if !only.is_empty() && got == 0 {
        return Err(crate::Error::Msg(
            "nothing matched --only (Scry the pack to see paths)".into(),
        ));
    }
    staged.commit()?;
    Ok((got, if any_mended { Some(healed_stars) } else { None }))
}

fn parse_sgdr_entries(raw: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    if raw.len() < 9 {
        return Err(crate::Error::Msg("folder pack too short".into()));
    }
    if raw[0..4] != DIR_MAGIC {
        return Err(crate::Error::Msg("not a folder pack (SGDR)".into()));
    }
    if raw[4] == DIR_VER_SEALED {
        return Err(crate::Error::Msg(HIDDEN_HINT.into()));
    }
    if raw[4] != DIR_VER_PLAIN {
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
    out.push(DIR_VER_PLAIN);
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

/// Keyless Scry of a folder pack. A sealed (v2) pack shows only its member count
/// and the health of its encrypted body.
pub fn scry_dir(input: &Path) -> Result<String> {
    scry_dir_keys(input, None, &[], &[])
}

/// Scry of a folder pack; with a key, a sealed (v2) pack lists its members as v1 does.
pub fn scry_dir_keys(
    input: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    identities: &[Identity],
) -> Result<String> {
    if let Some((n, body)) = sealed_dir_body(input)? {
        let health = scry_body(input, &body)?;
        if pass.is_none() && identities.is_empty() {
            return Ok(format!("folder  {n} files (names hidden)\nbody  {health}"));
        }
        let inner = open_body(n, &body, pass, companions, identities)?;
        let entries = list_v1(&mut Cursor::new(inner))?;
        return Ok(format!("{}\nbody  {health}", render_listing(&entries)));
    }
    Ok(render_listing(&list_dir_pack(input)?))
}

/// Scry line of a sealed body (written to a private scratch file: it is ciphertext).
fn scry_body(input: &Path, body: &[u8]) -> Result<String> {
    let tmp = Scratch(scratch_beside(
        &std::env::temp_dir().join(
            input
                .file_name()
                .unwrap_or_else(|| std::ffi::OsStr::new("pack")),
        ),
        "scry-body",
    ));
    fs::write(&tmp.0, body).map_err(io)?;
    // First line only: later lines (attestation lookup) would describe the scratch path.
    let line = crate::work::scry_path(&tmp.0)?;
    Ok(line.lines().next().unwrap_or_default().to_string())
}

fn render_listing(entries: &[DirEntry]) -> String {
    let mut dirs: Vec<String> = Vec::new();
    for e in entries {
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
    for e in entries {
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
    out.trim_end().to_string()
}

pub struct DirEntry {
    pub path: String,
    pub orig: Option<u64>,
    /// Likely a nested .sg1 / work pack (by name or peeked magic).
    pub nest: bool,
    /// Payload true-name digest from the entry's star header, when readable.
    pub digest: Option<[u8; 32]>,
}

/// Members of a plain (v1) folder pack. A sealed (v2) pack hides them: this errors;
/// use [`list_dir_pack_keys`] with the key.
pub fn list_dir_pack(input: &Path) -> Result<Vec<DirEntry>> {
    let mut reader = BufReader::new(File::open(input).map_err(io)?);
    list_v1(&mut reader)
}

/// Members of any folder pack; a sealed (v2) pack is opened with the given keys.
pub fn list_dir_pack_keys(
    input: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    identities: &[Identity],
) -> Result<Vec<DirEntry>> {
    if let Some((n, body)) = sealed_dir_body(input)? {
        let inner = open_body(n, &body, pass, companions, identities)?;
        return list_v1(&mut Cursor::new(inner));
    }
    list_dir_pack(input)
}

fn list_v1<R: Read>(reader: &mut R) -> Result<Vec<DirEntry>> {
    let (ver, n) = read_head(reader, "not a folder pack")?;
    if ver == DIR_VER_SEALED {
        return Err(crate::Error::Msg(HIDDEN_HINT.into()));
    }
    let mut entries = Vec::with_capacity((n as usize).min(4096));
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
    // A private-label (v3) member keeps its size inside the lock: report none
    // rather than the placeholder 0.
    crate::locate_header(peek)
        .ok()
        .filter(|(h, _, _)| !h.private_label())
        .map(|(h, _, _)| h.orig_len)
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

/// Stream one entry's star bytes out of a plain (v1) SGDR pack (no full unpack to disk).
/// A sealed (v2) pack hides its members: this errors.
pub fn read_dir_entry_star(input: &Path, want: &str) -> Result<Vec<u8>> {
    let mut reader = BufReader::new(File::open(input).map_err(io)?);
    read_entry_star_from(&mut reader, want)
}

/// Decrypt a sealed (v2) pack's body to its inner v1 pack bytes (for mount / nest).
pub(crate) fn open_sealed_inner(
    input: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    identities: &[Identity],
) -> Result<Vec<u8>> {
    match sealed_dir_body(input)? {
        Some((n, body)) => open_body(n, &body, pass, companions, identities),
        None => Err(crate::Error::Msg("not a sealed folder pack".into())),
    }
}

/// Members of an in-memory v1 pack (the inner pack of a sealed directory).
pub(crate) fn list_v1_bytes(inner: &[u8]) -> Result<Vec<DirEntry>> {
    list_v1(&mut Cursor::new(inner))
}

/// One member's star from an in-memory v1 pack.
pub(crate) fn read_entry_star_v1_bytes(inner: &[u8], want: &str) -> Result<Vec<u8>> {
    read_entry_star_from(&mut Cursor::new(inner), want)
}

fn read_entry_star_from<R: Read>(reader: &mut R, want: &str) -> Result<Vec<u8>> {
    let want = want.trim().trim_start_matches("./");
    let (ver, n) = read_head(reader, "not a folder pack (SGDR)")?;
    if ver == DIR_VER_SEALED {
        return Err(crate::Error::Msg(HIDDEN_HINT.into()));
    }
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
            let mut star = Vec::new();
            reader
                .by_ref()
                .take(slen as u64)
                .read_to_end(&mut star)
                .map_err(io)?;
            if star.len() != slen {
                return Err(crate::Error::Msg(
                    "truncated folder pack (star bytes)".into(),
                ));
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

    /// A v1 (names in the clear) encrypted pack, as written before sealed directories.
    fn legacy_v1_encrypted(src: &Path, out: &Path, pass: &str) {
        let mut files = Vec::new();
        walk(src, &mut files).unwrap();
        let mut w = BufWriter::new(File::create(out).unwrap());
        write_v1(
            src,
            &files,
            &mut w,
            out,
            Mode::Seal,
            Some(pass),
            "",
            &[],
            64 * 1024,
            &[],
            &[],
        )
        .unwrap();
        w.flush().unwrap();
    }

    #[test]
    fn legacy_v1_encrypted_pack_opens_lists_and_mends() {
        let root = scratch("legacy-v1");
        let src = root.join("src");
        fs::create_dir_all(src.join("m")).unwrap();
        fs::write(src.join("a.txt"), b"alpha").unwrap();
        fs::write(src.join("m/big.bin"), noise(200_000)).unwrap();
        let pack = root.join("old.sg1");
        legacy_v1_encrypted(&src, &pack, "pw");
        let raw = fs::read(&pack).unwrap();
        assert_eq!(&raw[0..5], b"SGDR\x01");
        let names: Vec<_> = list_dir_pack(&pack)
            .unwrap()
            .into_iter()
            .map(|e| e.path)
            .collect();
        assert_eq!(names, vec!["a.txt", "m/big.bin"]);
        assert!(scry_dir(&pack).unwrap().contains("  m/big.bin"));
        // Torn member star still mends through the vault restore path.
        let torn = wreck(&raw, "a.txt", Some((40, 60)));
        fs::write(&pack, &torn).unwrap();
        let dest = root.join("out");
        let (n, healed) =
            unseal_dir_mend_keys(&pack, &dest, Some("pw"), &[], &[], &[], &[]).unwrap();
        assert_eq!(n, 2);
        assert_eq!(fs::read(dest.join("a.txt")).unwrap(), b"alpha");
        assert_eq!(fs::read(dest.join("m/big.bin")).unwrap(), noise(200_000));
        let healed = healed.expect("torn member mended");
        assert_eq!(&healed[0..5], b"SGDR\x01", "legacy layout kept");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn sealed_pack_round_trip_mend_and_tamper() {
        let root = scratch("sealed");
        let src = root.join("src");
        fs::create_dir_all(src.join("hidden-dir")).unwrap();
        fs::write(src.join("hidden-dir/very-secret-name.txt"), b"s3cret").unwrap();
        fs::write(src.join("b.bin"), noise(5000)).unwrap();
        let pack = root.join("s.sg1");
        inscribe_dir(&src, &pack, Mode::Seal, Some("pw"), "", &[], 64 * 1024, &[]).unwrap();
        let raw = fs::read(&pack).unwrap();
        assert_eq!(&raw[0..5], b"SGDR\x02");
        assert!(!raw.windows(16).any(|w| w == b"very-secret-name"));
        assert!(list_dir_pack(&pack).is_err(), "keyless listing refused");
        assert!(read_dir_entry_star(&pack, "b.bin").is_err());
        let listed: Vec<_> = list_dir_pack_keys(&pack, Some("pw"), &[], &[])
            .unwrap()
            .into_iter()
            .map(|e| e.path)
            .collect();
        assert_eq!(listed, vec!["b.bin", "hidden-dir/very-secret-name.txt"]);
        assert!(list_dir_pack_keys(&pack, Some("nope"), &[], &[]).is_err());
        let s = scry_dir(&pack).unwrap();
        assert!(s.starts_with("folder  2 files (names hidden)"), "{s}");

        // Mend: a few torn shards in the body heal; the healed pack stays v2.
        let (h, prefix, _) = crate::locate_header(&raw[17..]).unwrap();
        let stride = crate::header::shard_stride(&h);
        let mut torn = raw.clone();
        let s0 = 17 + prefix + stride;
        torn[s0..s0 + stride].fill(0);
        fs::write(&pack, &torn).unwrap();
        let dest = root.join("m");
        let (n, healed) =
            unseal_dir_mend_keys(&pack, &dest, Some("pw"), &[], &[], &[], &[]).unwrap();
        assert_eq!(n, 2);
        assert_eq!(
            fs::read(dest.join("hidden-dir/very-secret-name.txt")).unwrap(),
            b"s3cret"
        );
        let healed = healed.expect("body mended");
        assert_eq!(&healed[0..5], b"SGDR\x02");
        assert!(!crate::work::star_torn(&healed[17..]));
        // Wrong key on the mend path writes nothing and returns no healed pack.
        let wk = root.join("wk");
        assert!(unseal_dir_mend_keys(&pack, &wk, Some("x"), &[], &[], &[], &[]).is_err());
        assert!(!wk.exists());
        // Truncated pack: refused, nothing written.
        fs::write(&pack, &raw[..raw.len() - 1]).unwrap();
        let t = root.join("t");
        assert!(unseal_dir(&pack, &t, Some("pw"), &[]).is_err());
        assert!(unseal_dir_mend_keys(&pack, &t, Some("pw"), &[], &[], &[], &[]).is_err());
        assert!(!t.exists());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn sealed_pack_hostile_body_length_is_refused() {
        let root = scratch("sealed-hostile");
        let mut raw = DIR_MAGIC.to_vec();
        raw.push(DIR_VER_SEALED);
        raw.extend_from_slice(&3u32.to_le_bytes());
        raw.extend_from_slice(&u64::MAX.to_le_bytes());
        raw.extend_from_slice(b"short");
        let p = root.join("h.sg1");
        fs::write(&p, &raw).unwrap();
        assert!(sealed_dir_body(&p).is_err());
        assert!(unseal_dir(&p, &root.join("o"), Some("pw"), &[]).is_err());
        assert!(scry_dir(&p).is_err());
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn unknown_folder_pack_version_is_refused() {
        let root = scratch("ver3");
        let mut raw = sgdr(0);
        raw[4] = 3;
        let p = root.join("v.sg1");
        fs::write(&p, &raw).unwrap();
        assert!(list_dir_pack(&p).is_err());
        assert!(unseal_dir(&p, &root.join("o"), None, &[]).is_err());
        let _ = fs::remove_dir_all(&root);
    }
}
