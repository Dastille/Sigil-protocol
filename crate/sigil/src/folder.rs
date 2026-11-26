//! Folder Inscribe: a directory becomes one SGDR pack of per-file marks.
//!
//! Two layouts share the `SGDR` magic:
//!
//! - **v1** (plain): `SGDR | 1 | count u32 | { name_len u16 | name | star_len u64 | star }*`.
//!   Member names and per-member star lengths are in the clear. Written for packs
//!   sealed with no `--pass` / `--to`. A pack whose only keys are per-file wards is
//!   refused by default (its names would show); [`inscribe_dir_to_names_visible`] is the
//!   explicit opt-in that still writes one.
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
use crate::packhead::{self, Src};
use crate::staging::Staging;
use crate::{seal_kn_to, unseal_ex_keys, Mode, Result, DEFAULT_PIECE};
use std::fs::{self, File};
use std::io::{BufReader, BufWriter, Cursor, Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

pub const DIR_MAGIC: [u8; 4] = *b"SGDR";
/// Plain folder pack: member names and sizes in the clear.
pub const DIR_VER_PLAIN: u8 = 1;
/// Sealed directory: the whole v1 pack is encrypted as one body star.
pub const DIR_VER_SEALED: u8 = 2;
/// Protected plain Tome: the whole v1 pack (folder list and members) is one body star,
/// like a Warded Tome's, but not encrypted. The body's repair data and SHA-256 checks
/// cover the folder list. No key is needed; it guards against accidental damage only,
/// not a deliberate forger (a Ward does that).
pub const DIR_VER_PROTECTED: u8 = 3;

/// True for the Tome layouts that keep the v1 pack inside one body star (v2 and v3).
pub(crate) fn has_body(ver: u8) -> bool {
    ver == DIR_VER_SEALED || ver == DIR_VER_PROTECTED
}

/// Error for a Warded Tome whose locked body is cut short (contains "truncated Tome").
const TRUNCATED_WARDED: &str = "truncated Tome (its body is cut off; incomplete copy or transfer)";

/// A v1-only reader was handed a protected (v3) Tome: its list is inside the body.
const PROTECTED_AS_V1: &str =
    "this Tome keeps its folder list inside its protected body; this operation reads only the older plain layout";

const HIDDEN_HINT: &str =
    "Warded Tome: member names are hidden; give --pass / --identity to list or open it";

fn io(e: std::io::Error) -> crate::Error {
    crate::Error::Msg(e.to_string())
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    walk_noting(dir, dir, out, &mut None)
}

/// Why a path under a folder was not packed into a Tome.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum SkipReason {
    /// A file whose name starts with `.` (dotfiles are not stored).
    HiddenFile,
    /// A folder whose name starts with `.`; it is not entered, so nothing under it is stored.
    HiddenFolder,
    /// Not a regular file or folder: a named pipe, socket or device.
    Special,
    /// A symbolic link whose target does not exist (links to files and folders are followed).
    BrokenLink,
    /// A folder with nothing stored under it (a Tome keeps files, not empty folders).
    EmptyFolder,
}

impl SkipReason {
    /// Short label for reports.
    pub fn label(self) -> &'static str {
        match self {
            SkipReason::HiddenFile => "hidden file",
            SkipReason::HiddenFolder => "hidden folder",
            SkipReason::Special => "special file",
            SkipReason::BrokenLink => "broken link",
            SkipReason::EmptyFolder => "empty folder",
        }
    }
}

/// One path a folder Inscribe left out, relative to the folder (`/` separators).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Skipped {
    /// Path relative to the packed folder.
    pub rel: String,
    /// Why it was left out.
    pub reason: SkipReason,
}

/// Most skipped paths kept by name in a [`SkipReport`]; the rest are only counted, so
/// a folder with millions of dotfiles cannot exhaust memory. The count stays exact.
pub const MAX_SKIPS_LISTED: usize = 10_000;

/// Everything a folder Inscribe of the same folder leaves out, from [`tree_skips`].
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct SkipReport {
    /// The first [`MAX_SKIPS_LISTED`] skipped paths, in walk order.
    pub listed: Vec<Skipped>,
    /// Exact number of skipped paths (may exceed `listed.len()`).
    pub total: u64,
    /// Regular files that will be stored and have an executable bit set. Permissions
    /// are not stored, so these restore without it.
    pub executables: u64,
}

impl SkipReport {
    fn note(&mut self, root: &Path, path: &Path, reason: SkipReason) {
        self.total += 1;
        if self.listed.len() < MAX_SKIPS_LISTED {
            self.listed.push(Skipped {
                rel: rel(root, path),
                reason,
            });
        }
    }

    /// Skipped paths per reason, in [`SkipReason`] order, zero counts omitted. Counts only
    /// the listed paths; `total` is exact.
    pub fn counts(&self) -> Vec<(SkipReason, u64)> {
        let order = [
            SkipReason::HiddenFile,
            SkipReason::HiddenFolder,
            SkipReason::Special,
            SkipReason::BrokenLink,
            SkipReason::EmptyFolder,
        ];
        order
            .iter()
            .map(|r| {
                (
                    *r,
                    self.listed.iter().filter(|s| s.reason == *r).count() as u64,
                )
            })
            .filter(|(_, n)| *n > 0)
            .collect()
    }
}

/// What a folder Inscribe of `root` would leave out: dotfiles and dot-folders, special
/// files, broken links and empty folders. Uses the same walk as the Inscribe itself, so
/// the report matches what is packed. Reads directory entries and metadata only.
pub fn tree_skips(root: &Path) -> Result<SkipReport> {
    let mut files = Vec::new();
    let mut report = Some(SkipReport::default());
    walk_noting(root, root, &mut files, &mut report)?;
    Ok(report.unwrap_or_default())
}

/// The folder walk every Inscribe uses (sorted, dot-names skipped, links followed),
/// noting each left-out path in `skips` when it is `Some`. Returns nothing extra so
/// the packed list is identical with or without a report.
fn walk_noting(
    root: &Path,
    dir: &Path,
    out: &mut Vec<PathBuf>,
    skips: &mut Option<SkipReport>,
) -> Result<()> {
    let rd = fs::read_dir(dir).map_err(io)?;
    let mut ents: Vec<_> = rd.collect::<std::io::Result<Vec<_>>>().map_err(io)?;
    ents.sort_by_key(|e| e.file_name());
    let before = out.len();
    for e in ents {
        let p = e.path();
        let name = e.file_name();
        let name = name.to_string_lossy();
        if name.starts_with('.') {
            if let Some(r) = skips.as_mut() {
                let reason = if p.is_dir() {
                    SkipReason::HiddenFolder
                } else {
                    SkipReason::HiddenFile
                };
                r.note(root, &p, reason);
            }
            continue;
        }
        if p.is_dir() {
            walk_noting(root, &p, out, skips)?;
        } else if p.is_file() {
            if let Some(r) = skips.as_mut() {
                if is_executable(&p) {
                    r.executables += 1;
                }
            }
            out.push(p);
        } else if let Some(r) = skips.as_mut() {
            // Neither a file nor a folder once links are followed.
            let reason = match fs::symlink_metadata(&p) {
                Ok(m) if m.file_type().is_symlink() => SkipReason::BrokenLink,
                _ => SkipReason::Special,
            };
            r.note(root, &p, reason);
        }
    }
    if out.len() == before && dir != root {
        if let Some(r) = skips.as_mut() {
            r.note(root, dir, SkipReason::EmptyFolder);
        }
    }
    Ok(())
}

#[cfg(unix)]
fn is_executable(p: &Path) -> bool {
    use std::os::unix::fs::PermissionsExt;
    fs::metadata(p)
        .map(|m| m.permissions().mode() & 0o111 != 0)
        .unwrap_or(false)
}

#[cfg(not(unix))]
fn is_executable(_p: &Path) -> bool {
    false
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
pub(crate) fn scratch_beside(output: &Path, tag: &str) -> PathBuf {
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
pub(crate) struct Scratch(pub(crate) PathBuf);
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

/// Why a folder pack locked only by per-file wards is refused by default.
pub const WARD_ONLY_REFUSED: &str = "a Tome locked only with --ward would show every file name and size to anyone: add --pass (or --to) to hide them (the wards still lock their files), or add --ward-names-visible to accept visible names";

/// True when per-file wards are the only keys: no folder passphrase, no recipient.
fn ward_only(
    pass: Option<&str>,
    wards: &[(String, String)],
    recipients: &[PublicIdentity],
) -> bool {
    !wards.is_empty() && pass.is_none() && recipients.is_empty()
}

/// Like `inscribe_dir`, with encrypt-to recipients applied to every file star.
///
/// With a passphrase or any recipient the pack is written as a sealed directory
/// (v2): names and per-member sizes are hidden. Without either it is a protected plain
/// Tome (v3): the folder list sits inside the repair-protected body, unencrypted. Set
/// `SIGIL_OLD_TOME_LAYOUT=1` (or call [`inscribe_dir_old_layout`]) for the older v1
/// layout that sigil builds made before Tome v3 can read.
///
/// Safe by default: per-file `wards` with no passphrase and no recipient would leave
/// the warded files' names and sizes in the clear, so that is refused before anything
/// is written ([`WARD_ONLY_REFUSED`]). Use [`inscribe_dir_to_names_visible`] to opt in.
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
    if ward_only(pass, wards, recipients) {
        return Err(crate::Error::Msg(WARD_ONLY_REFUSED.into()));
    }
    let protect = !old_layout_requested()?;
    inscribe_dir_any(
        root, output, mode, pass, covenant, geas, chunk, wards, recipients, protect,
    )
}

/// Environment opt-out for every Tome writer that has no flag of its own (Vault folder
/// commits, library callers): `SIGIL_OLD_TOME_LAYOUT=1` writes the older v1 layout for a
/// Tome without a key. Unset, empty or `0` keeps the default (v3). Any other value is
/// refused, so a typo never silently picks a layout.
pub fn old_layout_requested() -> Result<bool> {
    #[cfg(test)]
    if test_layout::OLD.with(|c| c.get()) {
        return Ok(true);
    }
    match std::env::var("SIGIL_OLD_TOME_LAYOUT") {
        Err(std::env::VarError::NotPresent) => Ok(false),
        Ok(v) if v.is_empty() || v == "0" => Ok(false),
        Ok(v) if v == "1" => Ok(true),
        _ => Err(crate::Error::Msg(
            "SIGIL_OLD_TOME_LAYOUT must be 0 or 1 (1 writes the older Tome layout); nothing was written".into(),
        )),
    }
}

/// Unit tests that exercise the v1 layout through writers without a layout argument
/// (Vault commits): [`test_layout::old`] makes this thread write v1 while `f` runs.
#[cfg(test)]
pub(crate) mod test_layout {
    use std::cell::Cell;
    thread_local! {
        pub(crate) static OLD: Cell<bool> = const { Cell::new(false) };
    }
    pub(crate) fn old<T>(f: impl FnOnce() -> T) -> T {
        OLD.with(|c| c.set(true));
        let t = f();
        OLD.with(|c| c.set(false));
        t
    }
}

/// Like [`inscribe_dir_to`] (or [`inscribe_dir_to_names_visible`] with `names_visible`),
/// always writing a Tome without a passphrase or recipient as a protected plain Tome
/// (v3), whatever `SIGIL_OLD_TOME_LAYOUT` says. Older sigil versions refuse v3
/// ("unknown Tome version 3").
// Justification: see `inscribe_dir`.
#[allow(clippy::too_many_arguments)]
pub fn inscribe_dir_protected(
    root: &Path,
    output: &Path,
    mode: Mode,
    pass: Option<&str>,
    covenant: &str,
    geas: &[[u8; 32]],
    chunk: u32,
    wards: &[(String, String)],
    recipients: &[PublicIdentity],
    names_visible: bool,
) -> Result<(u32, u64)> {
    if !names_visible && ward_only(pass, wards, recipients) {
        return Err(crate::Error::Msg(WARD_ONLY_REFUSED.into()));
    }
    inscribe_dir_any(
        root, output, mode, pass, covenant, geas, chunk, wards, recipients, true,
    )
}

/// Explicit opt-in: write a folder pack locked only by per-file `wards` with its names
/// readable without a key (a protected plain Tome, v3, by default; v1 with
/// `SIGIL_OLD_TOME_LAYOUT=1`). The warded files' contents are encrypted, but every
/// member name and size, and the unwarded files, are readable without any key. Same as
/// [`inscribe_dir_to`] in every other case.
// Justification: see `inscribe_dir`.
#[allow(clippy::too_many_arguments)]
pub fn inscribe_dir_to_names_visible(
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
    let protect = !old_layout_requested()?;
    inscribe_dir_any(
        root, output, mode, pass, covenant, geas, chunk, wards, recipients, protect,
    )
}

/// The older layout on request (`sigil seal --old-tome-layout`): a Tome without a
/// passphrase or recipient is written as v1 (folder list outside the repair data), which
/// sigil builds made before Tome v3 can read. With a key it is v2, as always.
/// `names_visible` as in [`inscribe_dir_protected`].
// Justification: see `inscribe_dir`.
#[allow(clippy::too_many_arguments)]
pub fn inscribe_dir_old_layout(
    root: &Path,
    output: &Path,
    mode: Mode,
    pass: Option<&str>,
    covenant: &str,
    geas: &[[u8; 32]],
    chunk: u32,
    wards: &[(String, String)],
    recipients: &[PublicIdentity],
    names_visible: bool,
) -> Result<(u32, u64)> {
    if !names_visible && ward_only(pass, wards, recipients) {
        return Err(crate::Error::Msg(WARD_ONLY_REFUSED.into()));
    }
    inscribe_dir_any(
        root, output, mode, pass, covenant, geas, chunk, wards, recipients, false,
    )
}

// Justification: see `inscribe_dir`.
#[allow(clippy::too_many_arguments)]
fn inscribe_dir_any(
    root: &Path,
    output: &Path,
    mode: Mode,
    pass: Option<&str>,
    covenant: &str,
    geas: &[[u8; 32]],
    chunk: u32,
    wards: &[(String, String)],
    recipients: &[PublicIdentity],
    protect: bool,
) -> Result<(u32, u64)> {
    crate::refuse_empty_seal_pass(pass)?;
    let mut files = Vec::new();
    walk(root, &mut files)?;
    if files.is_empty() {
        return Err(crate::Error::Msg("folder is empty".into()));
    }
    let encrypted = pass.is_some() || !recipients.is_empty();
    let ver = if encrypted {
        DIR_VER_SEALED
    } else {
        DIR_VER_PROTECTED
    };
    if !encrypted && !protect {
        // Through a part file: a member that fails (a failing random source, a read
        // error) leaves nothing at `output`.
        let (part, mut writer) = crate::work::open_part(output)?;
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
        crate::work::finish_part(part, writer, output)?;
        return Ok((files.len() as u32, total));
    }
    // Sealed directory: build the v1 pack (members sealed with the same keys, Glyph
    // mode because the body carries the repair budget), then seal it as one body.
    let inner = Scratch(scratch_beside(output, "sgdr-inner"));
    let total = {
        // Holds member names in the clear until it is sealed: owner-only, created exclusively.
        let mut w = BufWriter::new(crate::staging::create_private(&inner.0)?);
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
    if inner_len <= chunk as u64 {
        // A classic body is one in-memory seal; it is at most `chunk` bytes.
        let data = fs::read(&inner.0).map_err(io)?;
        let body = seal_kn_to(
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
        )?;
        drop(inner);
        let mut writer = BufWriter::new(File::create(output).map_err(io)?);
        writer
            .write_all(&encode_sealed(ver, files.len() as u32, &body))
            .map_err(io)?;
        writer.flush().map_err(io)?;
        return Ok((files.len() as u32, total));
    }
    {
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
        drop(inner);
        // Large body: copy the work pack into place a window at a time, never whole.
        let mut body = packhead::FileSrc::open(&packed.0)?;
        let body_len = body.size();
        let mut writer = BufWriter::new(File::create(output).map_err(io)?);
        writer
            .write_all(&encode_sealed_head(ver, files.len() as u32, body_len))
            .map_err(io)?;
        packhead::copy_range(&mut body, 0, body_len, &mut writer)?;
        writer.flush().map_err(io)?;
    }
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
        let pb = rel.as_bytes();
        let nlen = (pb.len().min(65535)) as u16;
        if size <= chunk as u64 {
            // A classic member is one in-memory seal; it is at most `chunk` bytes.
            let data = fs::read(path).map_err(io)?;
            let star = seal_kn_to(
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
            )?;
            writer.write_all(&nlen.to_le_bytes()).map_err(io)?;
            writer.write_all(&pb[..nlen as usize]).map_err(io)?;
            writer
                .write_all(&(star.len() as u64).to_le_bytes())
                .map_err(io)?;
            writer.write_all(&star).map_err(io)?;
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
            // Large member: copy its work pack in a window at a time, never whole.
            let mut star = packhead::FileSrc::open(&tmp.0)?;
            let slen = star.size();
            writer.write_all(&nlen.to_le_bytes()).map_err(io)?;
            writer.write_all(&pb[..nlen as usize]).map_err(io)?;
            writer.write_all(&slen.to_le_bytes()).map_err(io)?;
            packhead::copy_range(&mut star, 0, slen, writer)?;
        }
    }
    Ok(total)
}

fn encode_sealed(ver: u8, count: u32, body: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(SEALED_HEAD_LEN + body.len());
    out.extend_from_slice(&encode_sealed_head(ver, count, body.len() as u64));
    out.extend_from_slice(body);
    out
}

/// Bytes before a Warded Tome's body: `SGDR | 2 | count u32 | body_len u64`.
const SEALED_HEAD_LEN: usize = 17;

/// The 17 bytes in front of a Warded Tome's body of `body_len` bytes.
fn encode_sealed_head(ver: u8, count: u32, body_len: u64) -> [u8; SEALED_HEAD_LEN] {
    let mut out = [0u8; SEALED_HEAD_LEN];
    out[0..4].copy_from_slice(&DIR_MAGIC);
    out[4] = ver;
    out[5..9].copy_from_slice(&count.to_le_bytes());
    out[9..17].copy_from_slice(&body_len.to_le_bytes());
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
    if ver[0] != DIR_VER_PLAIN && !has_body(ver[0]) {
        return Err(crate::Error::Msg(unknown_version(ver[0])));
    }
    let mut nbuf = [0u8; 4];
    reader.read_exact(&mut nbuf).map_err(io)?;
    Ok((ver[0], u32::from_le_bytes(nbuf)))
}

/// Error for a Tome version this build does not know (a newer layout, or damage).
pub(crate) fn unknown_version(v: u8) -> String {
    format!(
        "unknown Tome version {v}: made by a newer sigil, or damaged (update sigil and try again; nothing was read)"
    )
}

/// Body bytes of a v2 pack whose head was just read. Exact length, no trailing bytes.
fn read_sealed_body<R: Read>(reader: &mut R) -> Result<Vec<u8>> {
    let mut lb = [0u8; 8];
    reader
        .read_exact(&mut lb)
        .map_err(|_| crate::Error::Msg(TRUNCATED_WARDED.into()))?;
    let len = u64::from_le_bytes(lb);
    let mut body = Vec::new();
    // `len` is untrusted: read through `take` so a hostile length cannot pre-allocate.
    reader
        .by_ref()
        .take(len)
        .read_to_end(&mut body)
        .map_err(io)?;
    if (body.len() as u64) != len {
        return Err(crate::Error::Msg(TRUNCATED_WARDED.into()));
    }
    let mut extra = [0u8; 1];
    if reader.read(&mut extra).map_err(io)? != 0 {
        return Err(crate::Error::Msg(
            "Tome has extra bytes after its body (edited or damaged)".into(),
        ));
    }
    Ok(body)
}

/// For a sealed-directory (v2) pack: `Some((member_count, body_offset, body_len))`;
/// `None` for v1. Same checks as [`sealed_dir_body`] (a cut-off body or bytes after
/// it are refused) without reading the body.
pub fn sealed_dir_body_loc(input: &Path) -> Result<Option<(u32, u64, u64)>> {
    let mut reader = BufReader::new(File::open(input).map_err(io)?);
    let (ver, n) = read_head(&mut reader, "not a Tome archive (SGDR)")?;
    if !has_body(ver) {
        return Ok(None);
    }
    let mut lb = [0u8; 8];
    reader
        .read_exact(&mut lb)
        .map_err(|_| crate::Error::Msg(TRUNCATED_WARDED.into()))?;
    let len = u64::from_le_bytes(lb);
    let size = fs::metadata(input).map_err(io)?.len();
    let avail = size.saturating_sub(SEALED_HEAD_LEN as u64);
    if len > avail {
        return Err(crate::Error::Msg(TRUNCATED_WARDED.into()));
    }
    if len < avail {
        return Err(crate::Error::Msg(
            "Tome has extra bytes after its body (edited or damaged)".into(),
        ));
    }
    Ok(Some((n, SEALED_HEAD_LEN as u64, len)))
}

/// Open a Warded Tome's body (`len` bytes at `off` of `tome`) and hand `f` its
/// plaintext, the inner v1 pack, positioned just after the inner `SGDR | 1 | count`
/// head (already checked against the outer `count`).
///
/// A large body (an SGWK work pack) is decrypted one chunk star at a time, so memory
/// stays at one chunk whatever the Tome's size; after `f` returns, the rest of the body
/// is read so the pack's total-length check runs before anything is trusted. A small
/// body is one classic seal and is opened in memory as before (it is at most the
/// `--chunk` it was sealed with). Fails closed on a wrong key or any tamper.
#[allow(clippy::too_many_arguments)]
fn with_inner<T>(
    tome: &mut packhead::FileSrc,
    count: u32,
    off: u64,
    len: u64,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    identities: &[Identity],
    f: impl FnOnce(&mut dyn Read) -> Result<T>,
) -> Result<T> {
    let mut body = packhead::SubSrc::new(tome, off, len)?;
    let mut mag = [0u8; 4];
    if len >= 4 {
        body.read_at(0, &mut mag)?;
    }
    if mag == crate::work::WORK_MAGIC {
        let l = packhead::layout(&mut body)?;
        let mut r = crate::work::PackReader::new(&mut body, &l, pass, companions, identities);
        let mut head = [0u8; 9];
        r.read_exact(&mut head).map_err(io)?;
        check_inner(count, &head)?;
        let t = f(&mut r)?;
        // The pack's total length is checked at its end: read to it before trusting `t`.
        std::io::copy(&mut r, &mut std::io::sink()).map_err(io)?;
        return Ok(t);
    }
    let mut b = vec![0u8; len as usize];
    body.read_at(0, &mut b)?;
    let inner = unseal_ex_keys(&b, pass, companions, identities)?;
    drop(b);
    check_inner(count, &inner)?;
    let mut cur = Cursor::new(inner);
    cur.set_position(9);
    f(&mut cur)
}

/// Where the members of a plain (v1) pack are read from: the Tome file itself (members
/// are then read in place), or a stream (a Warded Tome's decrypted body), whose large
/// members are copied to a private scratch file one window at a time.
enum V1Source<'a> {
    /// A plain Tome on disk; `pos` is the next unread byte.
    File { src: packhead::FileSrc, pos: u64 },
    /// A stream; large members are spooled to scratch files named after `beside`
    /// (beside the output) or in the system temp folder when `beside` is `None`.
    Stream {
        r: &'a mut dyn Read,
        beside: Option<&'a Path>,
    },
}

/// One member star of a plain (v1) pack.
enum StarBytes {
    /// A classic seal, read into memory (one AES-GCM message; never larger than the
    /// bytes actually present).
    Mem(Vec<u8>),
    /// A large-file member in place in the Tome file: `(offset, length)`.
    Window(u64, u64),
    /// A large-file member copied to a scratch file (removed when `_file` drops).
    Spool {
        _file: SpoolFile,
        src: packhead::FileSrc,
    },
}

/// A spooled member's scratch file, removed when dropped.
enum SpoolFile {
    Beside(Scratch),
    Temp(crate::staging::TempFile),
}

/// Error for a member cut off before its stated length.
const TRUNCATED_MEMBER: &str = "truncated Tome (cut off mid-archive; incomplete copy or transfer)";

/// A member length that runs past the end of the file while later members follow.
const LENGTH_PAST_END: &str =
    "a member's stored length runs past the end of the file, but later members are still there (a damaged length, not a cut-off copy)";

impl V1Source<'_> {
    /// Fill `buf` from the member list (names and lengths).
    fn read_exact(&mut self, buf: &mut [u8]) -> Result<()> {
        match self {
            V1Source::File { src, pos } => {
                src.read_at(*pos, buf)
                    .map_err(|_| crate::Error::Msg("failed to fill whole buffer".into()))?;
                *pos += buf.len() as u64;
                Ok(())
            }
            V1Source::Stream { r, .. } => r.read_exact(buf).map_err(io),
        }
    }

    /// The next `len` bytes, as a member star (`want`) or skipped (`None`). A truncated
    /// member is refused. Memory: a classic star, or one copy window for a large one.
    fn star(&mut self, len: u64, want: bool) -> Result<Option<StarBytes>> {
        match self {
            V1Source::File { src, pos } => {
                let start = *pos;
                if start.checked_add(len).is_none_or(|e| e > src.size()) {
                    if crate::tome_guard::later_member(src, start)? {
                        return Err(crate::tome_guard::damaged(LENGTH_PAST_END));
                    }
                    return Err(crate::Error::Msg(TRUNCATED_MEMBER.into()));
                }
                *pos = start + len;
                if !want {
                    return Ok(None);
                }
                let mut mag = [0u8; 4];
                if len >= 4 {
                    src.read_at(start, &mut mag)?;
                }
                if mag == crate::work::WORK_MAGIC {
                    return Ok(Some(StarBytes::Window(start, len)));
                }
                let mut v = vec![0u8; len as usize];
                src.read_at(start, &mut v)?;
                Ok(Some(StarBytes::Mem(v)))
            }
            V1Source::Stream { r, beside } => {
                if !want {
                    let got = std::io::copy(&mut r.by_ref().take(len), &mut std::io::sink())
                        .map_err(io)?;
                    if got != len {
                        return Err(crate::Error::Msg(TRUNCATED_MEMBER.into()));
                    }
                    return Ok(None);
                }
                let mut head = Vec::with_capacity(4);
                r.by_ref()
                    .take(len.min(4))
                    .read_to_end(&mut head)
                    .map_err(io)?;
                if head.as_slice() != crate::work::WORK_MAGIC {
                    // Classic star: read the rest; `take` bounds it by what is present.
                    let mut v = head;
                    r.by_ref()
                        .take(len - v.len() as u64)
                        .read_to_end(&mut v)
                        .map_err(io)?;
                    if v.len() as u64 != len {
                        return Err(crate::Error::Msg(TRUNCATED_MEMBER.into()));
                    }
                    return Ok(Some(StarBytes::Mem(v)));
                }
                let (spool, file) = match beside {
                    Some(b) => {
                        let sc = Scratch(scratch_beside(b, "member-spool"));
                        let f = crate::staging::create_private(&sc.0)?;
                        (SpoolFile::Beside(sc), f)
                    }
                    None => {
                        let t = crate::staging::TempFile::reserve("member-spool")?;
                        let f = fs::OpenOptions::new()
                            .write(true)
                            .open(t.path())
                            .map_err(io)?;
                        (SpoolFile::Temp(t), f)
                    }
                };
                let mut w = BufWriter::new(file);
                w.write_all(&head).map_err(io)?;
                let rest = len - head.len() as u64;
                let got = copy_bounded(&mut r.by_ref().take(rest), &mut w)?;
                if got != rest {
                    return Err(crate::Error::Msg(TRUNCATED_MEMBER.into()));
                }
                w.flush().map_err(io)?;
                drop(w);
                let path = match &spool {
                    SpoolFile::Beside(sc) => sc.0.clone(),
                    SpoolFile::Temp(t) => t.path().to_path_buf(),
                };
                let src = packhead::FileSrc::open(&path)?;
                Ok(Some(StarBytes::Spool { _file: spool, src }))
            }
        }
    }

    /// After the last of `count` members: refuse when another complete member follows
    /// (a lowered count). A stream (a Warded Tome's authenticated inner list) is not checked.
    fn after_members(&mut self, count: u32) -> Result<()> {
        match self {
            V1Source::File { src, pos } => {
                crate::tome_guard::check_no_member_after(src, *pos, count)
            }
            V1Source::Stream { .. } => Ok(()),
        }
    }

    /// Run `f` on a large-file member's bytes in place (a window of the Tome file or
    /// its spooled copy). `Mem` stars are handled by the caller.
    fn with_src<T>(
        &mut self,
        star: &mut StarBytes,
        f: impl FnOnce(&mut DynSrc<'_>) -> Result<T>,
    ) -> Result<T> {
        match (self, star) {
            (V1Source::File { src, .. }, StarBytes::Window(off, len)) => {
                let mut w = packhead::SubSrc::new(src, *off, *len)?;
                f(&mut DynSrc(&mut w))
            }
            (_, StarBytes::Spool { src, .. }) => f(&mut DynSrc(src)),
            (_, StarBytes::Mem(v)) => f(&mut DynSrc(&mut packhead::MemSrc(v))),
            _ => Err(crate::Error::Msg("member window without its Tome".into())),
        }
    }
}

/// A `&mut dyn Src` usable where a sized source is wanted.
pub(crate) struct DynSrc<'a>(pub &'a mut dyn Src);

impl Src for DynSrc<'_> {
    fn size(&self) -> u64 {
        self.0.size()
    }
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<()> {
        self.0.read_at(off, buf)
    }
}

/// Copy `r` into `w` one [`packhead::COPY_WINDOW`] at a time until `r` ends; returns
/// the bytes copied. Stops on Ctrl-C. `r` must itself be bounded (a `take`).
fn copy_bounded<R: Read + ?Sized, W: Write>(r: &mut R, w: &mut W) -> Result<u64> {
    let mut buf = vec![0u8; packhead::COPY_WINDOW];
    let mut total = 0u64;
    loop {
        crate::repair_ctl::check()?;
        let n = match r.read(&mut buf) {
            Ok(0) => return Ok(total),
            Ok(n) => n,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(io(e)),
        };
        w.write_all(&buf[..n]).map_err(io)?;
        total += n as u64;
    }
}

/// For a sealed-directory (v2) pack: `Some((member_count, body))`; `None` for v1.
pub fn sealed_dir_body(input: &Path) -> Result<Option<(u32, Vec<u8>)>> {
    let mut reader = BufReader::new(File::open(input).map_err(io)?);
    let (ver, n) = read_head(&mut reader, "not a Tome archive (SGDR)")?;
    if !has_body(ver) {
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
    f.read_exact(&mut head).is_ok() && head[0..4] == DIR_MAGIC && has_body(head[4])
}

/// The Tome version byte of `input` (1 plain, 2 Warded, 3 protected plain), when it
/// starts with `SGDR`.
pub fn tome_version(input: &Path) -> Option<u8> {
    let mut f = File::open(input).ok()?;
    let mut head = [0u8; 5];
    f.read_exact(&mut head).ok()?;
    (head[0..4] == DIR_MAGIC).then_some(head[4])
}

/// True when opening `input` needs a key: a Warded (v2) Tome and no key given.
fn locked_without_key(input: &Path, pass: Option<&str>, identities: &[Identity]) -> bool {
    tome_version(input) == Some(DIR_VER_SEALED) && pass.is_none() && identities.is_empty()
}

/// For readers of a plain v1 list only: refuse a Tome whose list is inside a body.
fn v1_only(ver: u8) -> Result<()> {
    match ver {
        DIR_VER_SEALED => Err(crate::Error::Msg(HIDDEN_HINT.into())),
        DIR_VER_PROTECTED => Err(crate::Error::Msg(PROTECTED_AS_V1.into())),
        _ => Ok(()),
    }
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
            "Tome: the contents of its body do not match its outer header (edited or damaged)"
                .into(),
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
    crate::refuse_empty_open_pass(pass)?;
    let mut reader = BufReader::new(File::open(input).map_err(io)?);
    let (ver, n) = read_head(&mut reader, "not a Tome archive (SGDR)")?;
    drop(reader);
    if has_body(ver) {
        if ver == DIR_VER_SEALED && pass.is_none() && identities.is_empty() {
            return Err(crate::Error::Msg(HIDDEN_HINT.into()));
        }
        let (count, off, len) = sealed_dir_body_loc(input)?.ok_or_else(|| {
            crate::Error::Msg("not a Tome with a body (Warded or protected)".into())
        })?;
        let mut tome = packhead::FileSrc::open(input)?;
        let mut staged = Staging::new();
        let got = with_inner(
            &mut tome,
            count,
            off,
            len,
            pass,
            companions,
            identities,
            |r| {
                let mut src = V1Source::Stream {
                    r,
                    beside: Some(dest),
                };
                unseal_v1_members(
                    &mut src,
                    count,
                    &mut staged,
                    dest,
                    pass,
                    companions,
                    only,
                    wards,
                    identities,
                )
            },
        )?;
        staged.commit()?;
        return Ok(got);
    }
    let mut src = V1Source::File {
        src: packhead::FileSrc::open(input)?,
        pos: 9,
    };
    let mut staged = Staging::new();
    let got = unseal_v1_members(
        &mut src,
        n,
        &mut staged,
        dest,
        pass,
        companions,
        only,
        wards,
        identities,
    )?;
    staged.commit()?;
    Ok(got)
}

/// Unseal the `n` members of a v1 pack from `src` into `staged` (the caller commits).
/// One member is held at a time: a classic star in memory, a large-file member read in
/// place or from a scratch copy, one chunk star at a time.
#[allow(clippy::too_many_arguments)]
fn unseal_v1_members(
    src: &mut V1Source<'_>,
    n: u32,
    staged: &mut Staging,
    dest: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    only: &[String],
    wards: &[(String, String)],
    identities: &[Identity],
) -> Result<u32> {
    // All-or-nothing: members land as part files and are renamed into place
    // only after every wanted member has unsealed and verified (by the caller).
    staged.make_dir(dest)?;
    let mut got = 0u32;
    let mut seen = crate::tome_guard::ListNames::default();
    // `n` is untrusted, but every member reads at least 10 bytes, so a short file ends
    // the loop with a truncation error long before `n` is reached.
    for _ in 0..n {
        crate::repair_ctl::check()?;
        let mut lb = [0u8; 2];
        src.read_exact(&mut lb)?;
        let nlen = u16::from_le_bytes(lb) as usize;
        let mut name = vec![0u8; nlen];
        src.read_exact(&mut name)?;
        if let Some(why) = crate::tome_guard::bad_name(&name) {
            return Err(crate::tome_guard::damaged(why));
        }
        let rel = String::from_utf8_lossy(&name).into_owned();
        crate::tome_guard::check_unique(&mut seen, &rel)?;
        if rel.contains("..") || Path::new(&rel).is_absolute() {
            return Err(crate::Error::Msg("refusing unsafe path in Tome".into()));
        }
        let mut sl = [0u8; 8];
        src.read_exact(&mut sl)?;
        let slen = u64::from_le_bytes(sl);
        let want = wanted(&rel, only);
        let Some(mut star) = src.star(slen, want)? else {
            continue;
        };
        let out_path = dest.join(&rel);
        let file_pass = pass_for(&rel, pass, wards);
        match &star {
            StarBytes::Mem(v) => {
                crate::tome_guard::check_classic(&rel, v)?;
                let plain = unseal_ex_keys(v, file_pass.as_deref(), companions, identities)?;
                staged.write(&out_path, &plain)?;
            }
            _ => {
                src.with_src(&mut star, |s| crate::tome_guard::check_pack(&rel, s))?;
                src.with_src(&mut star, |s| {
                    staged.write_with(&out_path, |w| {
                        crate::work::unseal_src_into(
                            s,
                            w,
                            file_pass.as_deref(),
                            companions,
                            identities,
                        )
                    })
                })?;
            }
        }
        got += 1;
    }
    src.after_members(n)?;
    if !only.is_empty() && got == 0 {
        return Err(crate::Error::Msg(
            "nothing matched --only (run sigil scry on the Tome to see paths)".into(),
        ));
    }
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
    crate::refuse_empty_open_pass(pass)?;
    let raw = fs::read(input).map_err(io)?;
    if raw.len() >= 5 && raw[0..4] == DIR_MAGIC && has_body(raw[4]) {
        let ver = raw[4];
        let mut cur = Cursor::new(&raw[..]);
        let (_, n) = read_head(&mut cur, "not a Tome archive (SGDR)")?;
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
        return Ok((got, healed_body.map(|b| encode_sealed(ver, n, &b))));
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
/// `soft` adds the deeper bit-rot repair (as plain `sigil mend` does for a single
/// `.sg1` and for plain Tome members) when the quick repair fails.
pub fn mend_sealed_dir(input: &Path, output: &Path, soft: bool) -> Result<String> {
    // The 17-byte head is outside the body's repair data. Its body length is rebuilt
    // from the file size, and (protected v3 only, where no key is needed) its member
    // count from the inner list's own head inside the healed body.
    let (ver, mut n, stored_len) = {
        let mut reader = BufReader::new(File::open(input).map_err(io)?);
        let (ver, n) = read_head(&mut reader, "not a Tome archive (SGDR)")?;
        if !has_body(ver) {
            return Err(crate::Error::Msg(
                "not a Tome with a body (Warded or protected)".into(),
            ));
        }
        let mut lb = [0u8; 8];
        reader
            .read_exact(&mut lb)
            .map_err(|_| crate::Error::Msg(TRUNCATED_WARDED.into()))?;
        (ver, n, u64::from_le_bytes(lb))
    };
    let mut tome = packhead::FileSrc::open(input)?;
    let off = SEALED_HEAD_LEN as u64;
    let len = tome.size().saturating_sub(off);
    let mut mag = [0u8; 4];
    if len >= 4 {
        tome.read_at(off, &mut mag)?;
    }
    let mut part = output.as_os_str().to_os_string();
    part.push(".mend-part");
    // Removed on any error; after the rename below there is nothing left to remove.
    let part = Scratch(PathBuf::from(part));
    let inner_count = |head: &[u8]| -> Option<u32> {
        (head.len() >= 9 && head[0..4] == DIR_MAGIC && head[4] == DIR_VER_PLAIN)
            .then(|| u32::from_le_bytes([head[5], head[6], head[7], head[8]]))
    };
    let state = if mag == crate::work::WORK_MAGIC {
        // Large body: heal it through scratch files, copying a window at a time.
        let src = Scratch(scratch_beside(output, "mend-body-in"));
        {
            let mut w = BufWriter::new(File::create(&src.0).map_err(io)?);
            packhead::copy_range(&mut tome, off, len, &mut w)?;
            w.flush().map_err(io)?;
        }
        let dst = Scratch(scratch_beside(output, "mend-body-out"));
        crate::work::mend_pack_path(&src.0, &dst.0, soft)?;
        drop(src);
        let mut healed = packhead::FileSrc::open(&dst.0)?;
        let hlen = healed.size();
        if ver == DIR_VER_PROTECTED {
            let l = packhead::layout(&mut healed)?;
            let mut r = crate::work::PackReader::new(&mut healed, &l, None, &[], &[]);
            let mut head = [0u8; 9];
            r.read_exact(&mut head).map_err(io)?;
            n = inner_count(&head).ok_or_else(|| {
                crate::Error::Msg("the healed body of this Tome holds no folder list".into())
            })?;
        }
        let mut w = BufWriter::new(File::create(&part.0).map_err(io)?);
        w.write_all(&encode_sealed_head(ver, n, hlen)).map_err(io)?;
        packhead::copy_range(&mut healed, 0, hlen, &mut w)?;
        w.flush().map_err(io)?;
        "ok"
    } else {
        // A classic body is one in-memory seal (at most the `--chunk` it was sealed with).
        let mut body = vec![0u8; len as usize];
        tome.read_at(off, &mut body)?;
        let (healed, _) = crate::pieces::mend_bytes_ex(&body, soft).map_err(|e| {
            crate::Error::Msg(format!("the body of this Tome is too damaged to mend: {e}"))
        })?;
        drop(body);
        if ver == DIR_VER_PROTECTED {
            let inner = unseal_ex_keys(&healed, None, &[], &[])?;
            n = inner_count(&inner).ok_or_else(|| {
                crate::Error::Msg("the healed body of this Tome holds no folder list".into())
            })?;
        }
        fs::write(&part.0, encode_sealed(ver, n, &healed)).map_err(io)?;
        if crate::work::star_torn(&healed) {
            "open"
        } else {
            "ok"
        }
    };
    let mut fixed = Vec::new();
    if stored_len != len {
        fixed.push("body length");
    }
    let mut head_n = [0u8; 4];
    tome.read_at(5, &mut head_n)?;
    if u32::from_le_bytes(head_n) != n {
        fixed.push("member count");
    }
    fs::rename(&part.0, output).map_err(io)?;
    let kind = if ver == DIR_VER_PROTECTED {
        "protected Tome"
    } else {
        "sealed Tome"
    };
    let head = if fixed.is_empty() {
        String::new()
    } else {
        format!(", head {} rebuilt", fixed.join(" and "))
    };
    Ok(format!(
        "mended {} → {} ({kind}, {n} files, body merkle {state}{head})",
        input.display(),
        output.display()
    ))
}

/// `sigil mend` for a plain (v1, unencrypted-envelope) folder pack: heal each member star
/// the way a lone `.sg1` / large-file pack is healed, then write the pack again with the
/// same layout. All-or-nothing: if any damaged member cannot be healed (Merkle + true
/// name checked), nothing is written and the error names that member.
pub fn mend_plain_dir(input: &Path, output: &Path, soft: bool) -> Result<String> {
    let mut tome = packhead::FileSrc::open(input)?;
    let entries = index_v1(&mut tome).map_err(|e| {
        let e = e.to_string();
        if e.starts_with(crate::tome_guard::LIST_DAMAGED) {
            crate::Error::Msg(e)
        } else {
            crate::Error::Msg(format!("truncated or unreadable Tome index: {e}"))
        }
    })?;
    let total = entries.len();
    let mut mended: Vec<String> = Vec::new();
    let mut soft_used = false;
    let mut part = output.as_os_str().to_os_string();
    part.push(".mend-part");
    // Removed on any error (nothing is written to `output`); renamed into place at the end.
    let part = Scratch(PathBuf::from(part));
    let mut w = BufWriter::new(File::create(&part.0).map_err(io)?);
    w.write_all(&DIR_MAGIC).map_err(io)?;
    w.write_all(&[DIR_VER_PLAIN]).map_err(io)?;
    w.write_all(&(total as u32).to_le_bytes()).map_err(io)?;
    // One member at a time: a classic star in memory, a large-file member through
    // scratch files a window at a time. `entries` came from a bounded index pass.
    for (rel, off, len) in entries {
        crate::repair_ctl::check()?;
        let mut mag = [0u8; 4];
        if len >= 4 {
            tome.read_at(off, &mut mag)?;
        }
        if mag == crate::work::WORK_MAGIC {
            let src = Scratch(scratch_beside(output, "mend-member-in"));
            let dst = Scratch(scratch_beside(output, "mend-member-out"));
            {
                let mut sw = BufWriter::new(File::create(&src.0).map_err(io)?);
                packhead::copy_range(&mut tome, off, len, &mut sw)?;
                sw.flush().map_err(io)?;
            }
            let r = crate::work::mend_pack_path(&src.0, &dst.0, soft).map_err(|e| {
                crate::Error::Msg(format!("member '{rel}' is too damaged to mend: {e}"))
            })?;
            drop(src);
            soft_used |= r.soft_used;
            if r.mended.is_empty() {
                let mut win = packhead::SubSrc::new(&mut tome, off, len)?;
                crate::tome_guard::check_pack(&rel, &mut win)?;
            } else {
                crate::tome_guard::check_pack(&rel, &mut packhead::FileSrc::open(&dst.0)?)?;
            }
            if r.mended.is_empty() {
                write_member_head(&mut w, &rel, len)?;
                packhead::copy_range(&mut tome, off, len, &mut w)?;
            } else {
                mended.push(rel.clone());
                let mut healed = packhead::FileSrc::open(&dst.0)?;
                let hlen = healed.size();
                write_member_head(&mut w, &rel, hlen)?;
                packhead::copy_range(&mut healed, 0, hlen, &mut w)?;
            }
            continue;
        }
        let mut star = vec![0u8; len as usize];
        tome.read_at(off, &mut star)?;
        if crate::work::star_torn(&star) {
            let (h, used) = crate::pieces::mend_bytes_ex(&star, soft).map_err(|e| {
                crate::Error::Msg(format!("member '{rel}' is too damaged to mend: {e}"))
            })?;
            if crate::work::star_torn(&h) {
                return Err(crate::Error::Msg(format!(
                    "member '{rel}' is still damaged after mend; nothing written"
                )));
            }
            soft_used |= used;
            mended.push(rel.clone());
            star = h;
        }
        crate::tome_guard::check_classic(&rel, &star)?;
        write_member_head(&mut w, &rel, star.len() as u64)?;
        w.write_all(&star).map_err(io)?;
    }
    w.flush().map_err(io)?;
    drop(w);
    fs::rename(&part.0, output).map_err(io)?;
    Ok(format!(
        "mended {} → {} (Tome, {total} files, {} healed{}{})",
        input.display(),
        output.display(),
        mended.len(),
        if mended.is_empty() {
            String::new()
        } else {
            format!(
                ": {}",
                mended
                    .iter()
                    .map(|m| crate::shown::name(m))
                    .collect::<Vec<_>>()
                    .join(", ")
            )
        },
        if soft_used { ", soft salvage" } else { "" }
    ))
}

/// Write one v1 member head (`name_len u16 | name | star_len u64`), exactly as
/// [`encode_sgdr`] does.
fn write_member_head<W: Write>(w: &mut W, rel: &str, star_len: u64) -> Result<()> {
    let pb = rel.as_bytes();
    let nlen = (pb.len().min(65535)) as u16;
    w.write_all(&nlen.to_le_bytes()).map_err(io)?;
    w.write_all(&pb[..nlen as usize]).map_err(io)?;
    w.write_all(&star_len.to_le_bytes()).map_err(io)
}

/// Members of the plain (v1) Tome at `input` as `(path, star offset, star length)`,
/// reading only the member heads (see [`index_v1`]).
pub(crate) fn member_locs(input: &Path) -> Result<Vec<(String, u64, u64)>> {
    index_v1(&mut packhead::FileSrc::open(input)?)
}

/// Members of the plain (v1) Tome in `src` as `(path, star offset, star length)`, with
/// the same checks and messages as [`parse_sgdr_entries`], reading only the member
/// heads (never a star). Bounded: every member needs at least 10 bytes of `src`.
fn index_v1<S: Src>(src: &mut S) -> Result<Vec<(String, u64, u64)>> {
    let size = src.size();
    if size < 9 {
        return Err(crate::Error::Msg(
            "truncated Tome (too short to hold its header)".into(),
        ));
    }
    let mut head = [0u8; 9];
    src.read_at(0, &mut head)?;
    if head[0..4] != DIR_MAGIC {
        return Err(crate::Error::Msg("not a Tome archive (SGDR)".into()));
    }
    v1_only(head[4])?;
    if head[4] != DIR_VER_PLAIN {
        return Err(crate::Error::Msg(unknown_version(head[4])));
    }
    let n = u32::from_le_bytes([head[5], head[6], head[7], head[8]]);
    let mut off = 9u64;
    let mut entries = Vec::with_capacity((n as u64).min(size / 10) as usize);
    let mut seen = crate::tome_guard::ListNames::default();
    for _ in 0..n {
        crate::repair_ctl::check()?;
        if off + 2 > size {
            return Err(crate::Error::Msg(
                "truncated Tome (cut off inside member list)".into(),
            ));
        }
        let mut lb = [0u8; 2];
        src.read_at(off, &mut lb)?;
        let nlen = u64::from(u16::from_le_bytes(lb));
        off += 2;
        if off + nlen + 8 > size {
            return Err(crate::Error::Msg(
                "truncated Tome (cut off inside member header)".into(),
            ));
        }
        let mut name = vec![0u8; nlen as usize];
        src.read_at(off, &mut name)?;
        if let Some(why) = crate::tome_guard::bad_name(&name) {
            return Err(crate::tome_guard::damaged(why));
        }
        off += nlen;
        let mut sl = [0u8; 8];
        src.read_at(off, &mut sl)?;
        off += 8;
        let slen = u64::from_le_bytes(sl);
        if slen > size - off {
            if crate::tome_guard::later_member(src, off)? {
                return Err(crate::tome_guard::damaged(LENGTH_PAST_END));
            }
            return Err(crate::Error::Msg(
                "truncated Tome (cut off mid-archive; incomplete copy or transfer)".into(),
            ));
        }
        let rel = String::from_utf8_lossy(&name).into_owned();
        crate::tome_guard::check_unique(&mut seen, &rel)?;
        entries.push((rel, off, slen));
        off += slen;
    }
    crate::tome_guard::check_no_member_after(src, off, n)?;
    Ok(entries)
}

/// True for a plain (v1) folder pack: `SGDR` + version 1.
pub fn is_plain_dir_pack(input: &Path) -> bool {
    let Ok(mut f) = File::open(input) else {
        return false;
    };
    let mut head = [0u8; 5];
    f.read_exact(&mut head).is_ok() && head[0..4] == DIR_MAGIC && head[4] == DIR_VER_PLAIN
}

/// One folder-pack member: `(relative path, star bytes)`.
type Member = (String, Vec<u8>);

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
) -> Result<(u32, Option<Vec<Member>>)> {
    let mut staged = Staging::new();
    staged.make_dir(dest)?;
    let mut healed_stars: Vec<(String, Vec<u8>)> = Vec::with_capacity(entries.len());
    let mut any_mended = false;
    let mut got = 0u32;

    for (rel, star) in entries {
        let mut star = star;
        if rel.contains("..") || Path::new(&rel).is_absolute() {
            return Err(crate::Error::Msg("refusing unsafe path in Tome".into()));
        }
        crate::tome_guard::check_star_bytes(&rel, &star)?;
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
            "nothing matched --only (run sigil scry on the Tome to see paths)".into(),
        ));
    }
    staged.commit()?;
    Ok((got, if any_mended { Some(healed_stars) } else { None }))
}

fn parse_sgdr_entries(raw: &[u8]) -> Result<Vec<(String, Vec<u8>)>> {
    if raw.len() < 9 {
        return Err(crate::Error::Msg(
            "truncated Tome (too short to hold its header)".into(),
        ));
    }
    if raw[0..4] != DIR_MAGIC {
        return Err(crate::Error::Msg("not a Tome archive (SGDR)".into()));
    }
    v1_only(raw[4])?;
    if raw[4] != DIR_VER_PLAIN {
        return Err(crate::Error::Msg(unknown_version(raw[4])));
    }
    let n = u32::from_le_bytes(raw[5..9].try_into().map_err(crate::short_field)?);
    let mut off = 9usize;
    // `n` is untrusted: each entry needs >= 10 bytes, so never pre-allocate beyond that.
    let mut entries = Vec::with_capacity((n as usize).min(raw.len() / 10));
    let mut seen = crate::tome_guard::ListNames::default();
    for _ in 0..n {
        if off + 2 > raw.len() {
            return Err(crate::Error::Msg(
                "truncated Tome (cut off inside member list)".into(),
            ));
        }
        let nlen =
            u16::from_le_bytes(raw[off..off + 2].try_into().map_err(crate::short_field)?) as usize;
        off += 2;
        if off + nlen + 8 > raw.len() {
            return Err(crate::Error::Msg(
                "truncated Tome (cut off inside member header)".into(),
            ));
        }
        if let Some(why) = crate::tome_guard::bad_name(&raw[off..off + nlen]) {
            return Err(crate::tome_guard::damaged(why));
        }
        let name = String::from_utf8_lossy(&raw[off..off + nlen]).into_owned();
        crate::tome_guard::check_unique(&mut seen, &name)?;
        off += nlen;
        let slen = usize::try_from(u64::from_le_bytes(
            raw[off..off + 8].try_into().map_err(crate::short_field)?,
        ))
        .unwrap_or(usize::MAX);
        off += 8;
        if slen > raw.len() - off {
            if crate::tome_guard::later_member(&mut packhead::MemSrc(raw), off as u64)? {
                return Err(crate::tome_guard::damaged(LENGTH_PAST_END));
            }
            return Err(crate::Error::Msg(
                "truncated Tome (cut off mid-archive; incomplete copy or transfer)".into(),
            ));
        }
        let star = raw[off..off + slen].to_vec();
        off += slen;
        entries.push((name, star));
    }
    crate::tome_guard::check_no_member_after(&mut packhead::MemSrc(raw), off as u64, n)?;
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
    if let Some((n, off, len)) = sealed_dir_body_loc(input)? {
        let mut tome = packhead::FileSrc::open(input)?;
        let health = scry_body_at(&mut tome, off, len)?;
        if locked_without_key(input, pass, identities) {
            return Ok(format!("folder  {n} files (names hidden)\nbody  {health}"));
        }
        let entries = with_inner(&mut tome, n, off, len, pass, companions, identities, |r| {
            list_v1_members(r, n, Some((pass, identities)))
        })?;
        return Ok(format!("{}\nbody  {health}", render_listing(&entries)));
    }
    Ok(render_listing(&list_dir_pack(input)?))
}

/// [`scry_dir_keys`] plus a keyless recoverability verdict: `Some(reason)` when a
/// member (plain Tome) or the locked body (Warded Tome) cannot be restored by `sigil mend`
/// (see [`crate::recovery::assess_tome`]).
pub fn scry_dir_checked(
    input: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    identities: &[Identity],
) -> Result<(String, Option<String>)> {
    let text = scry_dir_keys(input, pass, companions, identities)?;
    let mut budget = crate::recovery::ProbeBudget::from_env()?;
    let (condition, insp) = crate::recovery::assess_tome(input, &mut budget)?;
    Ok(dir_report(input, text, &condition, insp.as_ref()))
}

/// A Tome's Scry text with its verdict line: `needs mend: …` for members (or the locked
/// body) that `sigil mend` should repair, `NOT recoverable: …` (and `Some(reason)`) when
/// this copy cannot be restored.
pub fn dir_report(
    input: &Path,
    text: String,
    condition: &crate::recovery::Condition,
    insp: Option<&crate::recovery::TomeInspection>,
) -> (String, Option<String>) {
    use crate::recovery::Condition;
    let names = || -> String {
        match insp {
            Some(i) => i
                .torn
                .iter()
                .chain(i.repairable.iter().map(|(r, _)| r))
                .chain(i.unconfirmed.iter().map(|(r, _)| r))
                .map(|r| crate::shown::name(r))
                .collect::<Vec<_>>()
                .join(", "),
            None => "Tome body".into(),
        }
    };
    let run = crate::mend_out::mend_command(input);
    match condition {
        Condition::Healthy => (text, None),
        Condition::Torn(_) => (
            format!(
                "{text}\nneeds mend: {} (damaged but repairable, like merkle=open on one file; run: {run})",
                names()
            ),
            None,
        ),
        Condition::Repairable(_) => (
            format!("{text}\nneeds mend: {} (will not open until repaired; run: {run})", names()),
            None,
        ),
        Condition::Unconfirmed { .. } => (
            format!(
                "{text}\nneeds mend: {} (will not open as-is; run {run} to find out whether it can be repaired)",
                names()
            ),
            None,
        ),
        Condition::Unrecoverable(why) => (format!("{text}\nNOT recoverable: {why}"), Some(why.clone())),
    }
}

/// Scry line of the sealed body at `off..off + len` of `tome`, copied a window at a
/// time to a private scratch file (it is ciphertext), never held in memory whole.
fn scry_body_at(tome: &mut packhead::FileSrc, off: u64, len: u64) -> Result<String> {
    let mut mag = [0u8; 4];
    if len >= 4 {
        tome.read_at(off, &mut mag)?;
    }
    if mag == crate::work::WORK_MAGIC {
        // A large body's first Scry line is what its pack head says: read only the head
        // (at most `packhead::MAX_HEAD` bytes), never the body.
        let head_len = len.min(packhead::MAX_HEAD);
        let mut head = vec![0u8; head_len as usize];
        tome.read_at(off, &mut head)?;
        let h = crate::work::read_head(&mut Cursor::new(head))?;
        return Ok(crate::work::work_head_line(&h));
    }
    // A classic body is one seal of at most the `--chunk` it was sealed with: Scry it
    // through a private scratch copy (ciphertext), as before.
    let mut body = vec![0u8; len as usize];
    tome.read_at(off, &mut body)?;
    let tmp = crate::staging::TempFile::with_bytes("scry-body", &body)?;
    drop(body);
    let line = crate::work::scry_path(tmp.path())?;
    // First line only: later lines (attestation lookup) would describe the scratch path.
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
        out.push_str(&crate::shown::name(d));
        out.push('\n');
    }
    for e in entries {
        if e.nest {
            out.push_str("nest  ");
        } else {
            out.push_str("file  ");
        }
        out.push_str(&crate::shown::name(&e.path));
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
    // A protected plain Tome (v3) needs no key: list its body's inner pack.
    if tome_version(input) == Some(DIR_VER_PROTECTED) {
        return list_dir_pack_keys(input, None, &[], &[]);
    }
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
    if let Some((n, off, len)) = sealed_dir_body_loc(input)? {
        let mut tome = packhead::FileSrc::open(input)?;
        return with_inner(&mut tome, n, off, len, pass, companions, identities, |r| {
            list_v1_members(r, n, Some((pass, identities)))
        });
    }
    list_dir_pack(input)
}

fn list_v1<R: Read>(reader: &mut R) -> Result<Vec<DirEntry>> {
    let (ver, n) = read_head(reader, "not a Tome")?;
    v1_only(ver)?;
    list_v1_members(reader, n, None)
}

/// Keys used to fill in the sizes of members whose label is locked.
type SizeKeys<'a> = (Option<&'a str>, &'a [Identity]);

/// List the `n` members of a v1 pack from `reader` (positioned after its head),
/// peeking 1 KiB of each star and skipping the rest one 64 KiB window at a time.
/// With `keys`, a member whose size is inside its lock is opened to read it (one
/// member at a time: a classic star in memory, a large one through a scratch copy),
/// as [`fill_sizes_v1_bytes`] does for an in-memory pack.
fn list_v1_members<R: Read + ?Sized>(
    reader: &mut R,
    n: u32,
    keys: Option<SizeKeys<'_>>,
) -> Result<Vec<DirEntry>> {
    let keys = keys.filter(|(p, ids)| !(p.is_none_or(str::is_empty) && ids.is_empty()));
    let mut entries = Vec::with_capacity((n as usize).min(4096));
    let mut seen = crate::tome_guard::ListNames::default();
    for _ in 0..n {
        crate::repair_ctl::check()?;
        let mut lb = [0u8; 2];
        reader.read_exact(&mut lb).map_err(io)?;
        let nlen = u16::from_le_bytes(lb) as usize;
        let mut name = vec![0u8; nlen];
        reader.read_exact(&mut name).map_err(io)?;
        if let Some(why) = crate::tome_guard::bad_name(&name) {
            return Err(crate::tome_guard::damaged(why));
        }
        let path = String::from_utf8_lossy(&name).into_owned();
        crate::tome_guard::check_unique(&mut seen, &path)?;
        let mut sl = [0u8; 8];
        reader.read_exact(&mut sl).map_err(io)?;
        let slen = u64::from_le_bytes(sl);
        let peek_n = slen.min(1024) as usize;
        let mut peek = vec![0u8; peek_n];
        if peek_n > 0 {
            reader.read_exact(&mut peek).map_err(io)?;
        }
        let mut orig = peek_orig(&peek);
        let (nest, digest) = peek_nest(&peek, &path);
        let left = slen.saturating_sub(peek_n as u64);
        match keys {
            Some((pass, ids)) if orig.is_none() => {
                orig = star_size_streamed(reader, peek, left, pass, ids)?;
            }
            _ => {
                let mut left = left;
                let mut buf = vec![0u8; 64 * 1024];
                while left > 0 {
                    let take = left.min(buf.len() as u64) as usize;
                    reader.read_exact(&mut buf[..take]).map_err(io)?;
                    left -= take as u64;
                }
            }
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

/// Size of the large-file member read from `r`, like [`crate::work::payload_label_keys`]:
/// the head's total, or with a key the total inside the first chunk star's lock. `None`
/// when it cannot be read (a damaged head is not rebuilt here; the listing then shows
/// no size). The first star is read only when its framed length fits its pack's chunk.
fn work_member_size<R: Read + ?Sized>(
    r: &mut R,
    pass: Option<&str>,
    identities: &[Identity],
) -> Option<u64> {
    let mut r = r;
    let head = crate::work::read_head(&mut r).ok()?;
    if !crate::work::total_hidden(&head) {
        return Some(head.orig_total);
    }
    if pass.is_none_or(str::is_empty) && identities.is_empty() {
        return None;
    }
    let mut lb = [0u8; 8];
    r.read_exact(&mut lb).ok()?;
    let star_len = u64::from_le_bytes(lb);
    // Display only: a first star far larger than its chunk (with any repair budget and
    // guard) is not read into memory; the listing then shows no size.
    if star_len > 8 * u64::from(head.chunk_size) + (1 << 20) {
        return None;
    }
    let mut star = Vec::new();
    r.take(star_len).read_to_end(&mut star).ok()?;
    if star.len() as u64 != star_len {
        return None;
    }
    let meta = crate::unseal_meta_keys(&star, pass, &[], identities)
        .ok()?
        .1;
    meta.map(|m| m.group_total)
}

/// Read the rest (`left` bytes) of a member star that starts with `peek`, and open its
/// locked label for the size, as [`star_size_keys`] does. A large-file member goes
/// through a private scratch copy (sealed bytes), never memory.
fn star_size_streamed<R: Read + ?Sized>(
    reader: &mut R,
    peek: Vec<u8>,
    left: u64,
    pass: Option<&str>,
    identities: &[Identity],
) -> Result<Option<u64>> {
    if peek.starts_with(&crate::work::WORK_MAGIC) {
        // A large-file member's size is in its pack head, or (locked) in its first chunk
        // star: read those in order from the stream, then skip the rest a window at a
        // time. Nothing is copied to disk and at most one chunk star is in memory.
        let mut rest = reader.take(left);
        let size = {
            let mut r = (&peek[..]).chain(&mut rest);
            let size = work_member_size(&mut r, pass, identities);
            copy_bounded(&mut r, &mut std::io::sink())?;
            size
        };
        if rest.limit() != 0 {
            return Err(crate::Error::Msg(TRUNCATED_MEMBER.into()));
        }
        return Ok(size);
    }
    let mut star = peek;
    reader.take(left).read_to_end(&mut star).map_err(io)?;
    if (star.len() as u64) < left {
        return Err(crate::Error::Msg(TRUNCATED_MEMBER.into()));
    }
    Ok(star_size_keys(&star, pass, identities))
}

fn peek_orig(peek: &[u8]) -> Option<u64> {
    if peek.starts_with(&crate::work::WORK_MAGIC) {
        // A large-file member: its total is in the pack head, unless the head hides it
        // (locked pack: total written as the placeholder 0 with stars > 0). Report none
        // then, so a key can fill it in (or the listing shows no size), never "0 bytes".
        let head = crate::work::read_head(&mut &peek[..]).ok()?;
        return (!crate::work::total_hidden(&head)).then_some(head.orig_total);
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
///
/// A star that starts with the SGWK magic is how a Tome stores any member larger
/// than its `--chunk` (a large-file member), so the magic alone says nothing about
/// whether the member's *content* is a seal: such a member is a nest only when its
/// name says so (`.sg1` / `.sgwk`), like any other member.
fn peek_nest(peek: &[u8], path: &str) -> (bool, Option<[u8; 32]>) {
    let mut nest = looks_like_nest_name(path);
    let mut digest = None;
    if peek.starts_with(&crate::work::WORK_MAGIC) {
        // Large-file member: the name check above is the only signal.
    } else if peek.starts_with(&DIR_MAGIC) {
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
        None => Err(crate::Error::Msg(
            "not a Tome with a body (Warded or protected)".into(),
        )),
    }
}

/// In-memory folder pack bytes ready to list: a sealed (v2) pack is opened with the
/// given keys (fails closed with the hidden-names hint when no key is given, or on a
/// wrong key / tamper); a plain (v1) pack or any other bytes are returned unchanged.
pub(crate) fn unlock_dir_bytes(
    data: Vec<u8>,
    pass: Option<&str>,
    identities: &[Identity],
) -> Result<Vec<u8>> {
    if data.len() < 5 || data[0..4] != DIR_MAGIC || !has_body(data[4]) {
        return Ok(data);
    }
    if data[4] == DIR_VER_SEALED && pass.is_none() && identities.is_empty() {
        return Err(crate::Error::Msg(HIDDEN_HINT.into()));
    }
    let mut reader = Cursor::new(&data[..]);
    let (_, n) = read_head(&mut reader, "not a Tome archive (SGDR)")?;
    let body = read_sealed_body(&mut reader)?;
    open_body(n, &body, pass, &[], identities)
}

/// Size of one member star, opening its private label with the key when it is hidden.
/// `None` when the label stays locked (no key, or a member with its own ward key).
fn star_size_keys(star: &[u8], pass: Option<&str>, identities: &[Identity]) -> Option<u64> {
    if star.starts_with(&crate::work::WORK_MAGIC) {
        let tmp = crate::staging::TempFile::with_bytes("dir-size", star).ok()?;
        return crate::work::payload_label_keys(tmp.path(), pass, &[], identities)
            .ok()
            .flatten()
            .map(|(_, n)| n);
    }
    crate::seal_meta_keys(star, pass, identities)
        .ok()
        .map(|m| m.orig_len)
}

/// Fill hidden member sizes of an in-memory v1 pack when a key is given. This opens
/// each hidden member (one decrypt per member, one member in memory at a time).
/// Keyless: entries are left as they are (no new disclosure).
pub(crate) fn fill_sizes_v1_bytes(
    inner: &[u8],
    entries: &mut [DirEntry],
    pass: Option<&str>,
    identities: &[Identity],
) -> Result<()> {
    if (pass.is_none_or(str::is_empty) && identities.is_empty())
        || entries.iter().all(|e| e.orig.is_some())
    {
        return Ok(());
    }
    let mut reader = Cursor::new(inner);
    let (ver, n) = read_head(&mut reader, "not a Tome archive (SGDR)")?;
    v1_only(ver)?;
    for _ in 0..n {
        let mut lb = [0u8; 2];
        reader.read_exact(&mut lb).map_err(io)?;
        let mut name = vec![0u8; u16::from_le_bytes(lb) as usize];
        reader.read_exact(&mut name).map_err(io)?;
        let rel = String::from_utf8_lossy(&name).into_owned();
        let mut sl = [0u8; 8];
        reader.read_exact(&mut sl).map_err(io)?;
        let start = reader.position() as usize;
        let end = start
            .checked_add(u64::from_le_bytes(sl) as usize)
            .filter(|e| *e <= inner.len())
            .ok_or_else(|| {
                crate::Error::Msg(
                    "truncated Tome (cut off mid-archive; incomplete copy or transfer)".into(),
                )
            })?;
        reader.set_position(end as u64);
        if let Some(e) = entries
            .iter_mut()
            .find(|e| e.path == rel && e.orig.is_none())
        {
            e.orig = star_size_keys(&inner[start..end], pass, identities);
        }
    }
    Ok(())
}

/// Members of an in-memory v1 pack (the inner pack of a sealed directory).
pub(crate) fn list_v1_bytes(inner: &[u8]) -> Result<Vec<DirEntry>> {
    list_v1(&mut Cursor::new(inner))
}

/// One member's star from an in-memory v1 pack.
pub(crate) fn read_entry_star_v1_bytes(inner: &[u8], want: &str) -> Result<Vec<u8>> {
    read_entry_star_from(&mut Cursor::new(inner), want)
}

/// List a Warded Tome's members from its decrypted body read as a stream (`r` at the
/// body's first byte): the inner head is checked against the outer member `count`, and
/// members whose size is inside their lock are opened with the keys to read it, as
/// [`list_dir_pack_keys`] does. Reads exactly the inner pack's framing and members.
pub(crate) fn list_inner_stream<R: Read + ?Sized>(
    r: &mut R,
    count: u32,
    pass: Option<&str>,
    identities: &[Identity],
) -> Result<Vec<DirEntry>> {
    let mut head = [0u8; 9];
    r.read_exact(&mut head).map_err(io)?;
    check_inner(count, &head)?;
    list_v1_members(r, count, Some((pass, identities)))
}

/// Where entry `want`'s star sits in a plain (v1) Tome read from `reader`: `(offset,
/// length)` from the start of `reader`, which holds `size` bytes. Seeks past the other
/// members instead of reading them, so finding a member costs one small read per
/// member before it. Fails closed (an error, nothing guessed) when a length runs past
/// `size`. The loop runs at most the head's member count, and each step moves forward
/// by at least the 10 bytes of a member's framing, so it is bounded by `size` as well.
pub(crate) fn locate_entry_star<R: Read + Seek>(
    reader: &mut R,
    size: u64,
    want: &str,
) -> Result<(u64, u64)> {
    let want = want.trim().trim_start_matches("./");
    let (ver, n) = read_head(reader, "not a Tome archive (SGDR)")?;
    v1_only(ver)?;
    let truncated = || {
        crate::Error::Msg(
            "truncated Tome (cut off mid-archive; incomplete copy or transfer)".into(),
        )
    };
    let mut pos = 9u64;
    let mut seen = crate::tome_guard::ListNames::default();
    for _ in 0..n {
        let mut lb = [0u8; 2];
        reader.read_exact(&mut lb).map_err(|_| truncated())?;
        let nlen = u16::from_le_bytes(lb) as usize;
        let mut name = vec![0u8; nlen];
        reader.read_exact(&mut name).map_err(|_| truncated())?;
        // The members before (and at) the one wanted get the same list checks as unseal.
        if let Some(why) = crate::tome_guard::bad_name(&name) {
            return Err(crate::tome_guard::damaged(why));
        }
        crate::tome_guard::check_unique(&mut seen, &String::from_utf8_lossy(&name))?;
        let mut sl = [0u8; 8];
        reader.read_exact(&mut sl).map_err(|_| truncated())?;
        let slen = u64::from_le_bytes(sl);
        pos += 2 + nlen as u64 + 8;
        let end = pos
            .checked_add(slen)
            .filter(|e| *e <= size)
            .ok_or_else(truncated)?;
        if String::from_utf8_lossy(&name) == want {
            return Ok((pos, slen));
        }
        reader.seek(SeekFrom::Start(end)).map_err(io)?;
        pos = end;
    }
    Err(crate::Error::Msg(format!(
        "no entry '{want}' in Tome (run sigil scry or sigil path to list)"
    )))
}

fn read_entry_star_from<R: Read>(reader: &mut R, want: &str) -> Result<Vec<u8>> {
    let want = want.trim().trim_start_matches("./");
    let (ver, n) = read_head(reader, "not a Tome archive (SGDR)")?;
    v1_only(ver)?;
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
                    "truncated Tome (cut off mid-archive; incomplete copy or transfer)".into(),
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
        "no entry '{want}' in Tome (run sigil scry or sigil path to list)"
    )))
}

/// What [`seal_dir_names`] did.
#[derive(Debug)]
pub struct SealNamesReport {
    pub files: u32,
    /// Members that were encrypted in the old pack, and how many of them the given keys opened.
    pub encrypted_members: usize,
    pub opened_members: usize,
    pub out_bytes: u64,
}

/// Turn an old v1 folder pack (names in the clear) into a sealed-directory v2 pack: the whole v1
/// pack becomes the encrypted body, exactly as `inscribe` builds a v2 pack. Members are copied as
/// they are (not decrypted or re-sealed). Refuses a v2 pack, an existing `output`, and no key.
/// Fails closed when the pack has encrypted members and `check_pass` / `check_ids` open none of
/// them, unless `allow_new_key` (e.g. a ward-only pack, whose members open only with their wards).
#[allow(clippy::too_many_arguments)]
pub fn seal_dir_names(
    input: &Path,
    output: &Path,
    mode: Mode,
    pass: Option<&str>,
    recipients: &[PublicIdentity],
    check_pass: Option<&str>,
    check_ids: &[Identity],
    allow_new_key: bool,
) -> Result<SealNamesReport> {
    crate::refuse_empty_seal_pass(pass)?;
    if pass.is_none() && recipients.is_empty() {
        return Err(crate::Error::Msg(
            "give --pass-file and/or --to: the member names are sealed under that key".into(),
        ));
    }
    if output.exists() {
        return Err(crate::Error::Msg(format!(
            "{} already exists; choose a new output (the old pack is never changed in place)",
            output.display()
        )));
    }
    let raw = fs::read(input).map_err(io)?;
    if raw.len() >= 5 && raw[0..4] == DIR_MAGIC && raw[4] == DIR_VER_SEALED {
        return Err(crate::Error::Msg(
            "this Tome already seals its names (SGDR v2); nothing to do".into(),
        ));
    }
    // A protected plain Tome (v3) keeps its v1 pack in an unencrypted body: open it.
    let raw = if raw.len() >= 5 && raw[0..4] == DIR_MAGIC && raw[4] == DIR_VER_PROTECTED {
        open_sealed_inner(input, None, &[], &[])?
    } else {
        raw
    };
    let mut entries = parse_sgdr_entries(&raw)?;
    let mut encrypted = 0usize;
    let mut opened = 0usize;
    let mut clear = Vec::new();
    for (i, (_, star)) in entries.iter().enumerate() {
        let open = |p: Option<&str>, ids: &[Identity]| -> bool {
            if star.starts_with(&crate::work::WORK_MAGIC) {
                let mut sink = Vec::new();
                crate::work::unseal_bytes_into(star, &mut sink, p, &[], ids).is_ok()
            } else {
                unseal_ex_keys(star, p, &[], ids).is_ok()
            }
        };
        if open(None, &[]) {
            clear.push(i);
            continue;
        }
        encrypted += 1;
        if opened == 0
            && (check_pass.is_some() || !check_ids.is_empty())
            && open(check_pass, check_ids)
        {
            opened += 1;
        }
    }
    if encrypted > 0 && opened == 0 && !allow_new_key {
        return Err(crate::Error::Msg(
            "the given key opens none of this pack's encrypted members (wrong key?); nothing was written. \
             For a ward-only pack, add --allow-new-key to seal the names under a new key"
                .into(),
        ));
    }
    let count = u32::try_from(entries.len())
        .map_err(|_| crate::Error::Msg("Tome has too many members".into()))?;
    // A sealed directory's members open with its key: clear members are sealed now (Glyph mode,
    // as `inscribe` does inside a body); encrypted members are copied as they are.
    for &i in &clear {
        let Some((name, star)) = entries.get_mut(i) else {
            continue;
        };
        if star.starts_with(&crate::work::WORK_MAGIC) {
            return Err(crate::Error::Msg(format!(
                "member {name} is a large unencrypted work pack; re-inscribe the folder with --pass-file / --to instead"
            )));
        }
        let plain = unseal_ex_keys(star, None, &[], &[])?;
        *star = seal_kn_to(
            &plain,
            Mode::Glyph,
            pass,
            name,
            false,
            "",
            &[],
            None,
            DEFAULT_PIECE,
            recipients,
        )?;
    }
    let inner_raw = encode_sgdr(&entries)?;
    let body = if inner_raw.len() <= crate::work::DEFAULT_CHUNK as usize {
        seal_kn_to(
            &inner_raw,
            mode,
            pass,
            "folder.sgdr",
            false,
            "",
            &[],
            None,
            DEFAULT_PIECE,
            recipients,
        )?
    } else {
        // holds member names in the clear until sealed: owner-only, created exclusively
        let inner = Scratch(scratch_beside(output, "sgdr-inner"));
        {
            let mut w = crate::staging::create_private(&inner.0)?;
            w.write_all(&inner_raw).map_err(io)?;
        }
        let packed = Scratch(scratch_beside(output, "sgdr-body"));
        crate::work::inscribe_path_to(
            &inner.0,
            &packed.0,
            mode,
            pass,
            "",
            &[],
            crate::work::DEFAULT_CHUNK,
            None,
            DEFAULT_PIECE,
            crate::work::DEFAULT_OVERTURE_MB,
            None,
            recipients,
        )?;
        fs::read(&packed.0).map_err(io)?
    };
    let out = encode_sealed(DIR_VER_SEALED, count, &body);
    let tmp = Scratch(scratch_beside(output, "sgdr-out"));
    fs::write(&tmp.0, &out).map_err(io)?;
    fs::rename(&tmp.0, output).map_err(io)?;
    Ok(SealNamesReport {
        files: count,
        encrypted_members: encrypted,
        opened_members: opened,
        out_bytes: out.len() as u64,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A large-file member's pack head as it starts a member star.
    fn work_head_bytes(orig: u64, stars: u32) -> Vec<u8> {
        let mut b = crate::work::WORK_MAGIC.to_vec();
        b.push(1);
        b.extend_from_slice(&4_194_304u32.to_le_bytes());
        b.extend_from_slice(&orig.to_le_bytes());
        b.push(0);
        b.extend_from_slice(&stars.to_le_bytes());
        b
    }

    #[test]
    fn peek_orig_reports_large_member_size_but_not_the_hidden_placeholder() {
        assert_eq!(peek_orig(&work_head_bytes(5_000_000, 2)), Some(5_000_000));
        // Locked pack: total written as 0 with stars > 0 means "hidden", not empty.
        assert_eq!(peek_orig(&work_head_bytes(0, 2)), None);
        // A truly empty large-file pack (no stars) is 0 bytes.
        assert_eq!(peek_orig(&work_head_bytes(0, 0)), Some(0));
        // A head cut short (damaged or tiny star) gives no size rather than a guess.
        let full = work_head_bytes(5_000_000, 2);
        for cut in 0..full.len() {
            assert_eq!(peek_orig(&full[..cut]), None, "cut at {cut}");
        }
    }

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
        test_layout::old(|| inscribe_dir(&src, &pack, Mode::Seal, None, "", &[], 64 * 1024, &[]))
            .unwrap();
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
        // Ward-only is refused by default; this exercises the opt-in (old v1) layout.
        assert!(inscribe_dir(&src, &pack, Mode::Seal, None, "", &[], 64 * 1024, &wards).is_err());
        assert!(!pack.exists(), "refused seal left a file behind");
        inscribe_dir_to_names_visible(
            &src,
            &pack,
            Mode::Seal,
            None,
            "",
            &[],
            64 * 1024,
            &wards,
            &[],
        )
        .unwrap();
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

    /// The skip report names every path a Tome leaves out, and the packed list is the
    /// same with or without a report (the vault tree digest relies on that walk).
    #[cfg(unix)]
    #[test]
    fn tree_skips_lists_everything_left_out() {
        use std::os::unix::fs::PermissionsExt;
        let root = scratch("skips");
        let src = root.join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::create_dir_all(src.join(".git/objects")).unwrap();
        fs::create_dir_all(src.join("empty")).unwrap();
        fs::create_dir_all(src.join("only-dots")).unwrap();
        fs::write(src.join("a.txt"), b"a").unwrap();
        fs::write(src.join("sub/b.txt"), b"b").unwrap();
        fs::write(src.join(".env"), b"x").unwrap();
        fs::write(src.join(".git/objects/o"), b"x").unwrap();
        fs::write(src.join("only-dots/.keep"), b"").unwrap();
        fs::write(src.join("run.sh"), b"#!/bin/sh\n").unwrap();
        fs::set_permissions(src.join("run.sh"), fs::Permissions::from_mode(0o755)).unwrap();
        std::os::unix::fs::symlink("nowhere", src.join("dangling")).unwrap();
        std::os::unix::fs::symlink("a.txt", src.join("good-link")).unwrap();
        let _sock = std::os::unix::net::UnixListener::bind(src.join("sock")).unwrap();
        let rep = tree_skips(&src).unwrap();
        let got: Vec<(String, SkipReason)> = rep
            .listed
            .iter()
            .map(|s| (s.rel.clone(), s.reason))
            .collect();
        assert_eq!(
            got,
            vec![
                (".env".into(), SkipReason::HiddenFile),
                (".git".into(), SkipReason::HiddenFolder),
                ("dangling".into(), SkipReason::BrokenLink),
                ("empty".into(), SkipReason::EmptyFolder),
                ("only-dots/.keep".into(), SkipReason::HiddenFile),
                ("only-dots".into(), SkipReason::EmptyFolder),
                ("sock".into(), SkipReason::Special),
            ]
        );
        assert_eq!(rep.total, 7);
        assert_eq!(rep.executables, 1);
        assert_eq!(rep.counts().iter().map(|c| c.1).sum::<u64>(), 7);
        // Same packed list as the plain walk (and so as the vault tree digest).
        let packed: Vec<String> = tree_files(&src).unwrap().into_iter().map(|f| f.0).collect();
        assert_eq!(packed, vec!["a.txt", "good-link", "run.sh", "sub/b.txt"]);
        let pack = root.join("t.sg1");
        let (n, _) = inscribe_dir(&src, &pack, Mode::Seal, None, "", &[], 0, &[]).unwrap();
        assert_eq!(n, 4);
        let listed: Vec<String> = list_dir_pack(&pack)
            .unwrap()
            .into_iter()
            .map(|e| e.path)
            .collect();
        assert_eq!(listed, packed);
        // A clean folder reports nothing.
        let clean = tree_skips(&src.join("sub")).unwrap();
        assert_eq!(clean, SkipReport::default());
        let _ = fs::remove_dir_all(&root);
    }

    /// Past [`MAX_SKIPS_LISTED`] names the report only counts, and the count stays exact.
    #[test]
    fn tree_skips_caps_the_list_but_not_the_count() {
        let root = scratch("skips-cap");
        fs::create_dir_all(&root).unwrap();
        fs::write(root.join("keep.txt"), b"k").unwrap();
        let n = MAX_SKIPS_LISTED + 7;
        for i in 0..n {
            fs::write(root.join(format!(".d{i:06}")), b"").unwrap();
        }
        let rep = tree_skips(&root).unwrap();
        assert_eq!(rep.listed.len(), MAX_SKIPS_LISTED);
        assert_eq!(rep.total, n as u64);
        let _ = fs::remove_dir_all(&root);
    }

    /// A large-file member (stored as an SGWK pack because it is over `--chunk`) is a
    /// plain file in every listing, plain or Warded; only a member whose name says
    /// it is a seal (`.sg1`) is a nest, large or not. Regression: every large member
    /// used to be listed as `nest`.
    #[test]
    fn large_member_is_a_file_not_a_nest() {
        let root = scratch("large-not-nest");
        let src = root.join("src");
        fs::create_dir_all(src.join("m")).unwrap();
        fs::write(src.join("a.txt"), b"alpha").unwrap();
        fs::write(src.join("m/big.bin"), noise(200_000)).unwrap();
        // A real nested seal that is itself larger than the Tome's chunk.
        let loose = root.join("loose.bin");
        fs::write(&loose, noise(150_000)).unwrap();
        crate::work::inscribe_path(
            &loose,
            &src.join("inner.sg1"),
            Mode::Seal,
            None,
            "",
            &[],
            64 * 1024,
            None,
            DEFAULT_PIECE,
            crate::work::DEFAULT_OVERTURE_MB,
            None,
        )
        .unwrap();
        assert!(fs::metadata(src.join("inner.sg1")).unwrap().len() > 64 * 1024);
        let flags = |entries: Vec<DirEntry>| -> Vec<(String, bool)> {
            entries.into_iter().map(|e| (e.path, e.nest)).collect()
        };
        let want = vec![
            ("a.txt".to_string(), false),
            ("inner.sg1".to_string(), true),
            ("m/big.bin".to_string(), false),
        ];
        let plain = root.join("plain.sg1");
        test_layout::old(|| inscribe_dir(&src, &plain, Mode::Seal, None, "", &[], 64 * 1024, &[]))
            .unwrap();
        let raw = fs::read(&plain).unwrap();
        let big_star = parse_sgdr_entries(&raw)
            .unwrap()
            .into_iter()
            .find(|(r, _)| r == "m/big.bin")
            .unwrap()
            .1;
        assert!(
            big_star.starts_with(&crate::work::WORK_MAGIC),
            "stored large"
        );
        assert_eq!(flags(list_dir_pack(&plain).unwrap()), want);
        let report = scry_dir(&plain).unwrap();
        assert!(report.contains("file  m/big.bin"), "{report}");
        assert!(report.contains("nest  inner.sg1"), "{report}");
        assert!(!report.contains("nest  m/big.bin"), "{report}");
        let warded = root.join("warded.sg1");
        inscribe_dir(
            &src,
            &warded,
            Mode::Seal,
            Some("pw"),
            "",
            &[],
            64 * 1024,
            &[],
        )
        .unwrap();
        let listed = list_dir_pack_keys(&warded, Some("pw"), &[], &[]).unwrap();
        assert_eq!(flags(listed), want);
        let _ = fs::remove_dir_all(&root);
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

#[cfg(test)]
mod seal_names_tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sigil-folder-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// An old pass-encrypted v1 pack (names in the clear, as written before sealed directories)
    /// becomes a v2 pack: names hidden, members copied byte-for-byte, opens with the same pass.
    #[test]
    fn seal_names_of_a_legacy_encrypted_pack() {
        let d = scratch("seal-names");
        let src = d.join("src");
        fs::create_dir_all(src.join("sub")).unwrap();
        fs::write(src.join("sub/payroll-2025.csv"), b"alice,100\n").unwrap();
        fs::write(src.join("notes.txt"), b"hello").unwrap();
        let mut files = Vec::new();
        walk(&src, &mut files).unwrap();
        let old = d.join("old.sg1");
        {
            let mut w = File::create(&old).unwrap();
            write_v1(
                &src,
                &files,
                &mut w,
                &old,
                Mode::Reflection,
                Some("pw"),
                "",
                &[],
                4 << 20,
                &[],
                &[],
            )
            .unwrap();
        }
        let old_bytes = fs::read(&old).unwrap();
        assert!(old_bytes.windows(11).any(|w| w == b"payroll-202"));
        let new = d.join("new.sg1");
        // wrong key: refused, nothing written
        let e = seal_dir_names(
            &old,
            &new,
            Mode::Reflection,
            Some("other"),
            &[],
            Some("other"),
            &[],
            false,
        )
        .unwrap_err();
        assert!(e.to_string().contains("opens none"), "{e}");
        assert!(!new.exists());
        let r = seal_dir_names(
            &old,
            &new,
            Mode::Reflection,
            Some("pw"),
            &[],
            Some("pw"),
            &[],
            false,
        )
        .unwrap();
        assert_eq!((r.files, r.encrypted_members), (2, 2));
        assert_eq!(fs::read(&old).unwrap(), old_bytes, "input untouched");
        let nb = fs::read(&new).unwrap();
        assert!(!nb.windows(11).any(|w| w == b"payroll-202"));
        assert!(is_sealed_dir_pack(&new));
        // members are the old stars, byte-for-byte, inside the body
        let (n, body) = sealed_dir_body(&new).unwrap().unwrap();
        assert_eq!(
            open_body(n, &body, Some("pw"), &[], &[]).unwrap(),
            old_bytes
        );
        let out = d.join("out");
        assert_eq!(unseal_dir(&new, &out, Some("pw"), &[]).unwrap(), 2);
        assert_eq!(
            fs::read(out.join("sub/payroll-2025.csv")).unwrap(),
            b"alice,100\n"
        );
        // already v2, existing output: refused
        assert!(seal_dir_names(
            &new,
            &d.join("x.sg1"),
            Mode::Reflection,
            Some("pw"),
            &[],
            Some("pw"),
            &[],
            false
        )
        .is_err());
        assert!(seal_dir_names(
            &old,
            &new,
            Mode::Reflection,
            Some("pw"),
            &[],
            Some("pw"),
            &[],
            false
        )
        .is_err());
    }
}

/// One member's star bytes picked out of a folder pack for a deep read.
pub struct PickedStar {
    pub index: u32,
    pub path: String,
    pub star: Vec<u8>,
}

/// Member count of any folder pack (plain or sealed), without a key.
pub fn dir_member_count(input: &Path) -> Result<u32> {
    let mut reader = BufReader::new(File::open(input).map_err(io)?);
    let (_, n) = read_head(&mut reader, "not a Tome archive (SGDR)")?;
    Ok(n)
}

/// Star bytes of the members at `picks` (0-based, in pack order). A sealed (v2) pack is
/// opened with the keys first and fails closed without one, on a wrong key or tamper.
/// Only the picked stars are kept in memory.
pub fn dir_pick_stars(
    input: &Path,
    pass: Option<&str>,
    identities: &[Identity],
    picks: &[u32],
) -> Result<Vec<PickedStar>> {
    fn walk<R: Read>(reader: &mut R, picks: &[u32]) -> Result<Vec<PickedStar>> {
        let (ver, n) = read_head(reader, "not a Tome archive (SGDR)")?;
        v1_only(ver)?;
        let mut out = Vec::new();
        for i in 0..n {
            let mut lb = [0u8; 2];
            reader.read_exact(&mut lb).map_err(io)?;
            let mut name = vec![0u8; u16::from_le_bytes(lb) as usize];
            reader.read_exact(&mut name).map_err(io)?;
            let mut sl = [0u8; 8];
            reader.read_exact(&mut sl).map_err(io)?;
            let slen = u64::from_le_bytes(sl);
            if picks.contains(&i) {
                let mut star = Vec::new();
                reader
                    .by_ref()
                    .take(slen)
                    .read_to_end(&mut star)
                    .map_err(io)?;
                if star.len() as u64 != slen {
                    return Err(crate::Error::Msg(
                        "truncated Tome (cut off mid-archive; incomplete copy or transfer)".into(),
                    ));
                }
                out.push(PickedStar {
                    index: i,
                    path: String::from_utf8_lossy(&name).into_owned(),
                    star,
                });
            } else {
                let got = std::io::copy(&mut reader.by_ref().take(slen), &mut std::io::sink())
                    .map_err(io)?;
                if got != slen {
                    return Err(crate::Error::Msg(
                        "truncated Tome (cut off mid-archive; incomplete copy or transfer)".into(),
                    ));
                }
            }
        }
        Ok(out)
    }
    if let Some((n, body)) = sealed_dir_body(input)? {
        if locked_without_key(input, pass, identities) {
            return Err(crate::Error::Msg(HIDDEN_HINT.into()));
        }
        let inner = open_body(n, &body, pass, &[], identities)?;
        return walk(&mut Cursor::new(&inner[..]), picks);
    }
    let mut reader = BufReader::new(File::open(input).map_err(io)?);
    walk(&mut reader, picks)
}

/// Tomes are read one member (and one chunk star) at a time: these check that the
/// streamed readers give the same bytes and the same refusals as before.
#[cfg(test)]
mod stream_tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "sigil-folder-stream-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn noise(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    fn files_under(dir: &Path) -> Vec<PathBuf> {
        let mut out = Vec::new();
        if dir.exists() {
            walk(dir, &mut out).unwrap();
        }
        out
    }

    /// `src/` with a.txt, m/big.bin (300 kB, a work pack at a 64 KiB chunk) and z.txt.
    fn tree(root: &Path) -> (PathBuf, Vec<u8>) {
        let src = root.join("src");
        fs::create_dir_all(src.join("m")).unwrap();
        let big = noise(300_000, 7);
        fs::write(src.join("a.txt"), b"alpha").unwrap();
        fs::write(src.join("m/big.bin"), &big).unwrap();
        fs::write(src.join("z.txt"), b"omega").unwrap();
        (src, big)
    }

    fn check_tree(out: &Path, big: &[u8]) {
        assert_eq!(fs::read(out.join("a.txt")).unwrap(), b"alpha");
        assert_eq!(fs::read(out.join("m/big.bin")).unwrap(), big);
        assert_eq!(fs::read(out.join("z.txt")).unwrap(), b"omega");
    }

    #[test]
    fn sealed_head_is_the_front_of_encode_sealed() {
        let full = encode_sealed(DIR_VER_SEALED, 3, b"body");
        assert_eq!(
            &full[..SEALED_HEAD_LEN],
            &encode_sealed_head(DIR_VER_SEALED, 3, 4)
        );
        assert_eq!(&full[SEALED_HEAD_LEN..], b"body");
    }

    #[test]
    fn warded_tome_with_large_body_streams_and_fails_closed() {
        let d = scratch("warded");
        let (src, big) = tree(&d);
        let pack = d.join("w.sg1");
        inscribe_dir_to(
            &src,
            &pack,
            Mode::Seal,
            Some("pw"),
            "",
            &[],
            64 * 1024,
            &[],
            &[],
        )
        .unwrap();
        let (n, off, len) = sealed_dir_body_loc(&pack).unwrap().unwrap();
        assert_eq!((n, off), (3, SEALED_HEAD_LEN as u64));
        let raw = fs::read(&pack).unwrap();
        assert_eq!(
            &raw[17..21],
            &crate::work::WORK_MAGIC,
            "body must be a work pack"
        );
        assert_eq!(len, raw.len() as u64 - 17);

        let out = d.join("out");
        assert_eq!(
            unseal_dir_only_keys(&pack, &out, Some("pw"), &[], &[], &[], &[]).unwrap(),
            3
        );
        check_tree(&out, &big);

        // Listing with the key reads each locked size from the stream.
        let listed = list_dir_pack_keys(&pack, Some("pw"), &[], &[]).unwrap();
        let sizes: Vec<_> = listed.iter().map(|e| (e.path.clone(), e.orig)).collect();
        assert!(sizes.iter().any(|(p, _)| p == "m/big.bin"), "{sizes:?}");
        assert!(sizes.contains(&("a.txt".into(), Some(5))), "{sizes:?}");
        let text = scry_dir_keys(&pack, None, &[], &[]).unwrap();
        assert!(
            text.contains("3 files (names hidden)") && text.contains("work  name="),
            "{text}"
        );

        // Wrong key: refused, nothing written.
        let o2 = d.join("o2");
        assert!(unseal_dir_only_keys(&pack, &o2, Some("nope"), &[], &[], &[], &[]).is_err());
        assert!(files_under(&o2).is_empty());

        // Tamper beyond repair near the end of the body (after the members): refused,
        // nothing written, even though earlier members already decrypted.
        let mut bad = raw.clone();
        let at = bad.len() - bad.len() / 5;
        for b in &mut bad[at..at + 40_000] {
            *b ^= 0x5a;
        }
        let badp = d.join("bad.sg1");
        fs::write(&badp, &bad).unwrap();
        let o3 = d.join("o3");
        match unseal_dir_only_keys(&badp, &o3, Some("pw"), &[], &[], &[], &[]) {
            Err(_) => assert!(files_under(&o3).is_empty()),
            Ok(_) => check_tree(&o3, &big),
        }

        // Truncated: refused before anything is decrypted.
        let cut = d.join("cut.sg1");
        fs::write(&cut, &raw[..raw.len() - 100]).unwrap();
        let e =
            unseal_dir_only_keys(&cut, &d.join("o4"), Some("pw"), &[], &[], &[], &[]).unwrap_err();
        assert!(e.to_string().contains("truncated Tome"), "{e}");
        let extra = d.join("extra.sg1");
        let mut more = raw.clone();
        more.push(0);
        fs::write(&extra, &more).unwrap();
        assert!(
            unseal_dir_only_keys(&extra, &d.join("o5"), Some("pw"), &[], &[], &[], &[])
                .unwrap_err()
                .to_string()
                .contains("extra bytes")
        );
    }

    #[test]
    fn plain_tome_large_member_is_read_in_place_and_fails_closed() {
        let d = scratch("plain");
        let (src, big) = tree(&d);
        let pack = d.join("p.sg1");
        inscribe_dir(&src, &pack, Mode::Seal, None, "", &[], 64 * 1024, &[]).unwrap();
        let raw = fs::read(&pack).unwrap();
        let out = d.join("out");
        assert_eq!(unseal_dir(&pack, &out, None, &[]).unwrap(), 3);
        check_tree(&out, &big);

        // --only skips the large member without reading it into memory.
        let only = d.join("only");
        assert_eq!(
            unseal_dir_only(&pack, &only, None, &[], &["z.txt".into()], &[]).unwrap(),
            1
        );
        assert_eq!(fs::read(only.join("z.txt")).unwrap(), b"omega");

        // Cut inside the large member: refused, nothing written.
        let cut = d.join("cut.sg1");
        fs::write(&cut, &raw[..raw.len() / 2]).unwrap();
        let o2 = d.join("o2");
        let e = unseal_dir(&cut, &o2, None, &[]).unwrap_err();
        assert!(e.to_string().contains("truncated Tome"), "{e}");
        assert!(files_under(&o2).is_empty());

        // Heavy damage inside the large member: refused with nothing written, or (when
        // repair covers it) the exact bytes; never wrong bytes.
        let mut bad = raw.clone();
        let at = raw.len() / 2;
        for b in &mut bad[at..at + 70_000] {
            *b = 0;
        }
        let badp = d.join("bad.sg1");
        fs::write(&badp, &bad).unwrap();
        let o3 = d.join("o3");
        match unseal_dir(&badp, &o3, None, &[]) {
            Err(_) => assert!(files_under(&o3).is_empty()),
            Ok(_) => check_tree(&o3, &big),
        }
    }

    #[test]
    fn mend_of_a_healthy_tome_is_byte_identical_and_heals_damage() {
        let d = scratch("mend");
        let (src, big) = tree(&d);
        let pack = d.join("p.sg1");
        test_layout::old(|| inscribe_dir(&src, &pack, Mode::Seal, None, "", &[], 64 * 1024, &[]))
            .unwrap();
        let raw = fs::read(&pack).unwrap();
        let same = d.join("same.sg1");
        mend_plain_dir(&pack, &same, true).unwrap();
        assert_eq!(fs::read(&same).unwrap(), raw);

        // A burst inside the large member is healed; the healed Tome opens exactly.
        let mut bad = raw.clone();
        let at = raw.len() / 2;
        for b in &mut bad[at..at + 2_000] {
            *b ^= 0xff;
        }
        let badp = d.join("bad.sg1");
        fs::write(&badp, &bad).unwrap();
        let fixed = d.join("fixed.sg1");
        let msg = mend_plain_dir(&badp, &fixed, true).unwrap();
        assert!(msg.contains("1 healed"), "{msg}");
        let out = d.join("out");
        unseal_dir(&fixed, &out, None, &[]).unwrap();
        check_tree(&out, &big);
        assert!(!d.join("fixed.sg1.mend-part").exists());

        // Warded Tome: the large body is healed through scratch files.
        let w = d.join("w.sg1");
        inscribe_dir_to(
            &src,
            &w,
            Mode::Seal,
            Some("pw"),
            "",
            &[],
            64 * 1024,
            &[],
            &[],
        )
        .unwrap();
        let wraw = fs::read(&w).unwrap();
        let wsame = d.join("wsame.sg1");
        mend_sealed_dir(&w, &wsame, false).unwrap();
        let mut wbad = wraw.clone();
        let at = wraw.len() / 2;
        for b in &mut wbad[at..at + 2_000] {
            *b ^= 0xff;
        }
        let wbadp = d.join("wbad.sg1");
        fs::write(&wbadp, &wbad).unwrap();
        let wfixed = d.join("wfixed.sg1");
        mend_sealed_dir(&wbadp, &wfixed, false).unwrap();
        let wout = d.join("wout");
        unseal_dir_only_keys(&wfixed, &wout, Some("pw"), &[], &[], &[], &[]).unwrap();
        check_tree(&wout, &big);
        assert_eq!(fs::read(&wfixed).unwrap(), fs::read(&wsame).unwrap());
    }

    /// Scattered bit rot touches every shard of a Warded Tome's locked body, so the quick
    /// repair (whole shards that pass their CRC) has nothing to work with. The deeper
    /// repair that plain `sigil mend` uses for a single `.sg1` must also heal the body.
    #[test]
    fn warded_tome_scattered_bit_rot_needs_and_gets_the_deep_repair() {
        let d = scratch("warded-bitrot");
        let src = d.join("src");
        fs::create_dir_all(src.join("a/b")).unwrap();
        let mut x = 0x2545_f491_4f6c_dd1du64;
        let mut want = Vec::new();
        for i in 0..6 {
            let bytes: Vec<u8> = (0..30_000)
                .map(|_| {
                    x ^= x << 13;
                    x ^= x >> 7;
                    x ^= x << 17;
                    x as u8
                })
                .collect();
            let rel = format!("a/b/f{i}.bin");
            fs::write(src.join(&rel), &bytes).unwrap();
            want.push((rel, bytes));
        }
        for (mode, body_chunk) in [(Mode::Reflection, 4 * 1024 * 1024), (Mode::Seal, 64 * 1024)] {
            let w = d.join("w.sg1");
            let _ = fs::remove_file(&w);
            inscribe_dir_to(&src, &w, mode, Some("pw"), "", &[], body_chunk, &[], &[]).unwrap();
            let mut bad = fs::read(&w).unwrap();
            // One flipped bit every 3001 bytes of the body: every shard gets hit.
            let mut at = SEALED_HEAD_LEN + 1000;
            while at < bad.len() {
                bad[at] ^= 0x10;
                at += 3001;
            }
            let badp = d.join("bad.sg1");
            fs::write(&badp, &bad).unwrap();
            let quick = d.join("quick.sg1");
            let _ = fs::remove_file(&quick);
            assert!(mend_sealed_dir(&badp, &quick, false).is_err(), "{mode:?}");
            assert!(!quick.exists());
            let fixed = d.join("fixed.sg1");
            let _ = fs::remove_file(&fixed);
            mend_sealed_dir(&badp, &fixed, true).unwrap();
            let out = d.join("out");
            let _ = fs::remove_dir_all(&out);
            unseal_dir_only_keys(&fixed, &out, Some("pw"), &[], &[], &[], &[]).unwrap();
            for (rel, bytes) in &want {
                assert_eq!(&fs::read(out.join(rel)).unwrap(), bytes, "{mode:?} {rel}");
            }
            let n = fs::read_dir(out.join("a/b")).unwrap().count();
            assert_eq!(n, want.len());
        }
    }

    #[test]
    fn hostile_member_count_ends_at_the_file_end() {
        let d = scratch("hostile");
        let p = d.join("h.sg1");
        let mut b = DIR_MAGIC.to_vec();
        b.push(DIR_VER_PLAIN);
        b.extend_from_slice(&u32::MAX.to_le_bytes());
        b.extend_from_slice(&[0u8; 64]);
        fs::write(&p, &b).unwrap();
        let t0 = std::time::Instant::now();
        assert!(unseal_dir(&p, &d.join("o"), None, &[]).is_err());
        assert!(mend_plain_dir(&p, &d.join("m.sg1"), false).is_err());
        assert!(!d.join("m.sg1").exists() && !d.join("m.sg1.mend-part").exists());
        let insp =
            crate::recovery::inspect_plain_tome(&p, &mut crate::recovery::ProbeBudget::disabled())
                .unwrap();
        // Zero bytes read as an empty name: folder-list damage, never healthy.
        assert!(insp.truncated.is_some() || insp.list_damaged.is_some());
        assert!(matches!(
            insp.condition(),
            crate::recovery::Condition::Unrecoverable(_)
        ));
        // A member claiming more bytes than the file holds is refused, not buffered.
        let mut c = DIR_MAGIC.to_vec();
        c.push(DIR_VER_PLAIN);
        c.extend_from_slice(&1u32.to_le_bytes());
        c.extend_from_slice(&1u16.to_le_bytes());
        c.push(b'x');
        c.extend_from_slice(&u64::MAX.to_le_bytes());
        c.extend_from_slice(b"SGWK");
        let q = d.join("q.sg1");
        fs::write(&q, &c).unwrap();
        assert!(unseal_dir(&q, &d.join("o2"), None, &[])
            .unwrap_err()
            .to_string()
            .contains("truncated Tome"));
        assert!(t0.elapsed() < std::time::Duration::from_secs(5));
    }

    #[test]
    fn copy_range_and_sub_src_stay_in_bounds() {
        let data = noise(3 * packhead::COPY_WINDOW + 17, 3);
        let mut m = packhead::MemSrc(&data);
        let mut out = Vec::new();
        packhead::copy_range(&mut m, 5, data.len() as u64 - 5, &mut out).unwrap();
        assert_eq!(out, &data[5..]);
        assert!(packhead::copy_range(&mut m, 6, data.len() as u64 - 5, &mut Vec::new()).is_err());
        assert!(packhead::SubSrc::new(&mut m, u64::MAX, 2).is_err());
        let mut s = packhead::SubSrc::new(&mut m, 10, 100).unwrap();
        assert_eq!(s.size(), 100);
        let mut b = [0u8; 10];
        s.read_at(90, &mut b).unwrap();
        assert_eq!(&b, &data[100..110]);
        assert!(s.read_at(91, &mut b).is_err());
    }
}
