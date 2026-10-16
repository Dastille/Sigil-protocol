//! Boot Keystone: Scry a live-USB mark, De-scribe if the squashfs was chewed, then the stub continues.
//!
//! Firmware cannot boot a `.sg1`. The stick stays a normal live USB (GRUB + kernel + initrd).
//! We wrap `filesystem.squashfs` as a Seal. After the medium is mounted and before the
//! squashfs is, initrd runs `sigil boot mend`. Intact → continue. Chewed → De-scribe.
//! Too damaged → stop. Sigil will not guess.

use crate::attest::verify_attestation;
use crate::header::locate_header;
use crate::work::{index_pack, inscribe_path, is_work_pack, read_facet_digests, unseal_path};
use crate::{sha256, sha256_path, verify, Mode, Result, DEFAULT_CHUNK};
use std::fs::{self, File};
use std::io::{Read, Write};
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};

const SQUASH_NAMES: &[&str] = &[
    "live/filesystem.squashfs",
    "casper/filesystem.squashfs",
    "live/filesystem.erofs",
    "casper/filesystem.erofs",
];

#[derive(Debug, Clone)]
pub struct BootFind {
    pub mark: PathBuf,
    pub payload: PathBuf,
}

#[derive(Debug, Clone)]
pub enum BootOutcome {
    Intact { find: BootFind },
    Mended { find: BootFind, wrote: PathBuf },
}

pub fn find_boot_mark(root: &Path) -> Option<BootFind> {
    for rel in SQUASH_NAMES {
        let payload = root.join(rel);
        let mark = with_sg1(&payload);
        if mark.is_file() {
            return Some(BootFind { mark, payload });
        }
    }
    for dir in ["live", "casper", ""] {
        let base = if dir.is_empty() {
            root.to_path_buf()
        } else {
            root.join(dir)
        };
        let rd = match fs::read_dir(&base) {
            Ok(r) => r,
            Err(_) => continue,
        };
        for ent in rd.flatten() {
            let p = ent.path();
            let name = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if !name.ends_with(".sg1") {
                continue;
            }
            if name.contains("squashfs") || name.contains("erofs") || name.ends_with(".iso.sg1") {
                let payload = strip_sg1(&p);
                return Some(BootFind { mark: p, payload });
            }
        }
    }
    None
}

fn with_sg1(p: &Path) -> PathBuf {
    let mut s = p.as_os_str().to_os_string();
    s.push(".sg1");
    PathBuf::from(s)
}

fn strip_sg1(p: &Path) -> PathBuf {
    let s = p.to_string_lossy();
    if let Some(rest) = s.strip_suffix(".sg1") {
        PathBuf::from(rest)
    } else {
        p.to_path_buf()
    }
}

/// Wrap the live squashfs as a Seal (default) next to it.
pub fn prepare_boot(
    root: &Path,
    mode: Mode,
    pass: Option<&str>,
    only_mark: bool,
) -> Result<BootFind> {
    let payload = find_squashfs(root).ok_or_else(|| {
        crate::Error::Msg(
            "no filesystem.squashfs (or erofs) under live/ or casper/. Mount the USB and pass that folder."
                .into(),
        )
    })?;
    let mark = with_sg1(&payload);
    inscribe_path(
        &payload,
        &mark,
        mode,
        pass,
        "boot",
        &[],
        DEFAULT_CHUNK,
        None,
        0,
        64,
        None,
    )?;
    if only_mark {
        fs::remove_file(&payload).map_err(|e| crate::Error::Msg(e.to_string()))?;
    }
    Ok(BootFind { mark, payload })
}

fn find_squashfs(root: &Path) -> Option<PathBuf> {
    for rel in SQUASH_NAMES {
        let p = root.join(rel);
        if p.is_file() {
            return Some(p);
        }
    }
    for dir in ["live", "casper"] {
        let rd = fs::read_dir(root.join(dir)).ok()?;
        for ent in rd.flatten() {
            let p = ent.path();
            let n = p.file_name().and_then(|s| s.to_str()).unwrap_or("");
            if n.ends_with(".squashfs") || n.ends_with(".erofs") {
                return Some(p);
            }
        }
    }
    None
}

/// Scry the mark. If the payload is missing or not itself, De-scribe. Refuse if too damaged.
pub fn mend_boot(root: &Path, pass: Option<&str>, stage: &Path) -> Result<BootOutcome> {
    let find = find_boot_mark(root)
        .ok_or_else(|| crate::Error::Msg("no boot mark (.sg1) on this medium".into()))?;
    mend_find(&find, pass, stage)
}

pub fn mend_find(find: &BootFind, pass: Option<&str>, stage: &Path) -> Result<BootOutcome> {
    refuse_if_attest_forged(&find.mark)?;

    // Prefer an intact squashfs over unpacking, even if the mark is a bit chewed —
    // as long as we can still read the true name from a Keystone or Ember.
    if find.payload.is_file() && payload_is_itself(&find.mark, &find.payload).unwrap_or(false) {
        return Ok(BootOutcome::Intact { find: find.clone() });
    }

    scry_or_refuse(&find.mark)?;

    fs::create_dir_all(stage).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let tmp = stage.join("payload.tmp");
    let dest = stage.join(find.payload.file_name().unwrap_or_default());
    unseal_path(&find.mark, &tmp, pass, &[]).map_err(|e| {
        crate::Error::Msg(format!(
            "De-scribe failed (Ward wrong, or too damaged to repair): {e}"
        ))
    })?;
    fs::rename(&tmp, &dest).map_err(|e| crate::Error::Msg(e.to_string()))?;

    let wrote = place_payload(&find.payload, &dest)?;
    write_status(stage, &format!("mended {}", wrote.display()))?;
    Ok(BootOutcome::Mended {
        find: find.clone(),
        wrote,
    })
}

fn refuse_if_attest_forged(mark: &Path) -> Result<()> {
    match verify_attestation(mark) {
        Ok(s) if s.contains("FAILED") => Err(crate::Error::Msg(format!(
            "Attest refused this mark — {s}. Will not boot it."
        ))),
        _ => Ok(()),
    }
}

fn scry_or_refuse(mark: &Path) -> Result<()> {
    if is_work_pack(mark) {
        let (head, locs) = index_pack(mark)?;
        if locs.len() as u32 != head.stars {
            return Err(crate::Error::Msg(format!(
                "too damaged to boot: work pack incomplete, {} of {} stars readable. Sigil will not guess.",
                locs.len(),
                head.stars
            )));
        }
        return Ok(());
    }
    let data = fs::read(mark).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let (h, _merkle_ok, live, k, _) = verify(&data)?;
    if live < k {
        return Err(crate::Error::Msg(format!(
            "too damaged to boot: {live}/{} pieces live, need {k}. Sigil will not guess.",
            h.n
        )));
    }
    Ok(())
}

fn payload_is_itself(mark: &Path, payload: &Path) -> Result<bool> {
    if !payload.is_file() {
        return Ok(false);
    }
    if is_work_pack(mark) {
        let (head, _) = match index_pack(mark) {
            Ok(x) => x,
            Err(_) => return Ok(false),
        };
        let meta = fs::metadata(payload).map_err(|e| crate::Error::Msg(e.to_string()))?;
        if meta.len() != head.orig_total {
            return Ok(false);
        }
        let digests = match read_facet_digests(mark) {
            Ok(d) => d,
            Err(_) => return Ok(false),
        };
        return payload_matches_facets(payload, head.chunk_size, &digests);
    }
    let data = match fs::read(mark) {
        Ok(d) => d,
        Err(_) => return Ok(false),
    };
    let (h, _, _) = match locate_header(&data) {
        Ok(x) => x,
        Err(_) => return Ok(false),
    };
    Ok(sha256_path(payload)? == h.digest)
}

fn payload_matches_facets(payload: &Path, chunk: u32, digests: &[[u8; 32]]) -> Result<bool> {
    let mut f = File::open(payload).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let mut buf = vec![0u8; chunk.max(1) as usize];
    for expect in digests {
        let n = f
            .read(&mut buf)
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        if n == 0 || sha256(&buf[..n]) != *expect {
            return Ok(false);
        }
    }
    let mut extra = [0u8; 1];
    let n = f
        .read(&mut extra)
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    Ok(n == 0)
}

/// Put the recovered payload where live-boot looks. Bind-mount if the medium is read-only.
fn place_payload(wanted: &Path, recovered: &Path) -> Result<PathBuf> {
    if wanted == recovered {
        return Ok(recovered.to_path_buf());
    }
    if let Some(parent) = wanted.parent() {
        if parent.is_dir() && parent_writable(parent) {
            let tmp = wanted.with_file_name(format!(
                ".{}.writing",
                wanted
                    .file_name()
                    .and_then(|s| s.to_str())
                    .unwrap_or("payload")
            ));
            fs::copy(recovered, &tmp).map_err(|e| crate::Error::Msg(e.to_string()))?;
            fs::rename(&tmp, wanted).map_err(|e| crate::Error::Msg(e.to_string()))?;
            return Ok(wanted.to_path_buf());
        }
        if wanted.exists() {
            let _ = Command::new("mount")
                .arg("--bind")
                .arg(recovered)
                .arg(wanted)
                .status();
        }
    }
    Ok(recovered.to_path_buf())
}

fn parent_writable(dir: &Path) -> bool {
    let probe = dir.join(".sigil-write-probe");
    match File::create(&probe) {
        Ok(mut f) => {
            let _ = f.write_all(b"ok");
            let _ = fs::remove_file(&probe);
            true
        }
        Err(_) => false,
    }
}

fn write_status(stage: &Path, line: &str) -> Result<()> {
    let _ = fs::create_dir_all(stage);
    let _ = fs::write(stage.join("status"), format!("{line}\n"));
    Ok(())
}

/// Try each block device: mount, look for a boot mark, mend.
pub fn mend_scan(stage: &Path, pass: Option<&str>) -> Result<BootOutcome> {
    if let Ok(env) = std::env::var("SIGIL_MEDIUM") {
        let p = PathBuf::from(env);
        if p.is_dir() {
            return mend_boot(&p, pass, stage);
        }
    }
    for known in [
        "/lib/live/mount/medium",
        "/run/live/medium",
        "/run/initramfs/live",
        "/cdrom",
        "/mnt",
    ] {
        let p = Path::new(known);
        if p.is_dir() && find_boot_mark(p).is_some() {
            return mend_boot(p, pass, stage);
        }
    }
    let mnts = stage.join("mnt");
    fs::create_dir_all(&mnts).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let mut last = crate::Error::Msg("no boot mark on any disk".into());
    for (i, dev) in list_block_devices().into_iter().enumerate() {
        let mp = mnts.join(format!("{i}"));
        let _ = fs::create_dir_all(&mp);
        let ok = Command::new("mount")
            .args(["-o", "ro"])
            .arg(&dev)
            .arg(&mp)
            .status()
            .map(|s| s.success())
            .unwrap_or(false);
        if !ok {
            continue;
        }
        if find_boot_mark(&mp).is_none() {
            let _ = Command::new("umount").arg(&mp).status();
            continue;
        }
        let _ = Command::new("mount")
            .arg("-o")
            .arg("remount,rw")
            .arg(&mp)
            .status();
        match mend_boot(&mp, pass, stage) {
            Ok(o) => return Ok(o),
            Err(e) => {
                last = e;
                let _ = Command::new("umount").arg(&mp).status();
            }
        }
    }
    Err(last)
}

fn list_block_devices() -> Vec<PathBuf> {
    let mut out = Vec::new();
    for by in ["/dev/disk/by-label", "/dev/disk/by-uuid", "/dev/disk/by-id"] {
        if let Ok(rd) = fs::read_dir(by) {
            for ent in rd.flatten() {
                out.push(ent.path());
            }
        }
    }
    if out.is_empty() {
        if let Ok(rd) = fs::read_dir("/dev") {
            for ent in rd.flatten() {
                let n = ent.file_name();
                let n = n.to_string_lossy();
                if (n.starts_with("sd")
                    || n.starts_with("vd")
                    || n.starts_with("nvme")
                    || n.starts_with("mmcblk")
                    || n.starts_with("xvd"))
                    && n.chars()
                        .last()
                        .map(|c| c.is_ascii_digit())
                        .unwrap_or(false)
                {
                    out.push(ent.path());
                }
            }
        }
    }
    out
}

/// Copy this `sigil` binary onto the stick next to the squashfs so live-premount can find it.
pub fn copy_sigil_binary(root: &Path, bin: &Path) -> Result<PathBuf> {
    let dest_dir = if root.join("live").is_dir() {
        root.join("live")
    } else if root.join("casper").is_dir() {
        root.join("casper")
    } else {
        let live = root.join("live");
        fs::create_dir_all(&live).map_err(|e| crate::Error::Msg(e.to_string()))?;
        live
    };
    let dest = dest_dir.join("sigil");
    fs::copy(bin, &dest).map_err(|e| crate::Error::Msg(e.to_string()))?;
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(&dest)
            .map_err(|e| crate::Error::Msg(e.to_string()))?
            .permissions();
        perm.set_mode(0o755);
        fs::set_permissions(&dest, perm).map_err(|e| crate::Error::Msg(e.to_string()))?;
    }
    Ok(dest)
}

fn find_initrd(root: &Path) -> Option<PathBuf> {
    const NAMES: &[&str] = &[
        "live/initrd.img",
        "casper/initrd.img",
        "casper/initrd",
        "casper/initrd.lz",
        "casper/initrd.gz",
    ];
    for n in NAMES {
        let p = root.join(n);
        if p.is_file() {
            return Some(p);
        }
    }
    for dir in ["live", "casper"] {
        let Ok(rd) = fs::read_dir(root.join(dir)) else {
            continue;
        };
        for ent in rd.flatten() {
            let n = ent.file_name().to_string_lossy().to_lowercase();
            if n.starts_with("initrd") {
                return Some(ent.path());
            }
        }
    }
    None
}

fn detect_compress(path: &Path) -> &'static str {
    let mut magic = [0u8; 4];
    if let Ok(mut f) = File::open(path) {
        let _ = f.read_exact(&mut magic);
    }
    match magic {
        [0x1f, 0x8b, ..] => "gzip",
        [0xfd, 0x37, 0x7a, 0x58] => "xz",
        [0x28, 0xb5, 0x2f, 0xfd] => "zstd",
        [0x02, 0x21, 0x4c, 0x18] | [0x04, 0x22, 0x4d, 0x18] => "lz4",
        _ if magic.starts_with(b"07") => "cpio",
        _ => "gzip",
    }
}

fn initrd_inner(unpacked: &Path) -> PathBuf {
    for c in ["main", "unpacked"] {
        let p = unpacked.join(c);
        if p.is_dir()
            && (p.join("init").exists() || p.join("scripts").is_dir() || p.join("bin").is_dir())
        {
            return p;
        }
    }
    unpacked.to_path_buf()
}

fn unix_exec(path: &Path) -> Result<()> {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mut perm = fs::metadata(path)
            .map_err(|e| crate::Error::Msg(e.to_string()))?
            .permissions();
        perm.set_mode(0o755);
        fs::set_permissions(path, perm).map_err(|e| crate::Error::Msg(e.to_string()))?;
    }
    let _ = path;
    Ok(())
}

fn fallback_unpack(initrd: &Path, dest: &Path) -> Result<()> {
    let kind = detect_compress(initrd);
    if kind == "cpio" {
        let file = File::open(initrd).map_err(|e| crate::Error::Msg(e.to_string()))?;
        let st = Command::new("cpio")
            .args(["-id", "--quiet"])
            .current_dir(dest)
            .stdin(Stdio::from(file))
            .status()
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        if !st.success() {
            return Err(crate::Error::Msg(
                "cpio could not unpack this initrd".into(),
            ));
        }
        return Ok(());
    }
    let decomp = match kind {
        "xz" => "xzcat",
        "zstd" => "zstdcat",
        "lz4" => "lz4cat",
        _ => "zcat",
    };
    let mut child = Command::new(decomp)
        .arg(initrd)
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .map_err(|e| {
            crate::Error::Msg(format!(
                "could not unpack initrd ({e}). Install initramfs-tools (unmkinitramfs) or {decomp}."
            ))
        })?;
    let stdout = child
        .stdout
        .take()
        .ok_or_else(|| crate::Error::Msg("decompress pipe".into()))?;
    let st = Command::new("cpio")
        .args(["-id", "--quiet"])
        .current_dir(dest)
        .stdin(Stdio::from(stdout))
        .status()
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    let _ = child.wait();
    if !st.success() {
        return Err(crate::Error::Msg(
            "could not unpack initrd (need unmkinitramfs or gzip/cpio)".into(),
        ));
    }
    Ok(())
}

fn repack_initrd(inner: &Path, dest: &Path, kind: &str) -> Result<()> {
    let mut find = Command::new("find")
        .arg(".")
        .current_dir(inner)
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| crate::Error::Msg(format!("find: {e}")))?;
    let find_out = find
        .stdout
        .take()
        .ok_or_else(|| crate::Error::Msg("find pipe".into()))?;
    let mut cpio = Command::new("cpio")
        .args(["-H", "newc", "-o", "--quiet"])
        .current_dir(inner)
        .stdin(Stdio::from(find_out))
        .stdout(Stdio::piped())
        .spawn()
        .map_err(|e| crate::Error::Msg(format!("cpio: {e}")))?;
    let cpio_out = cpio
        .stdout
        .take()
        .ok_or_else(|| crate::Error::Msg("cpio pipe".into()))?;
    let dest_f = File::create(dest).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let st = if kind == "cpio" {
        let mut out = dest_f;
        let mut src = cpio_out;
        std::io::copy(&mut src, &mut out).map_err(|e| crate::Error::Msg(e.to_string()))?;
        cpio.wait().map_err(|e| crate::Error::Msg(e.to_string()))?
    } else {
        let compressor = match kind {
            "xz" => "xz",
            "zstd" => "zstd",
            "lz4" => "lz4",
            _ => "gzip",
        };
        Command::new(compressor)
            .arg("-c")
            .stdin(Stdio::from(cpio_out))
            .stdout(Stdio::from(dest_f))
            .status()
            .map_err(|e| crate::Error::Msg(format!("{compressor}: {e}")))?
    };
    let _ = find.wait();
    let _ = cpio.wait();
    if !st.success() {
        return Err(crate::Error::Msg("could not repack initrd".into()));
    }
    Ok(())
}

/// Unpack the USB's initrd, drop `sigil` + live-premount hook in, repack. Backs up to `*.bak` once.
pub fn inject_initrd(root: &Path, sigil_bin: &Path) -> Result<PathBuf> {
    let initrd = find_initrd(root).ok_or_else(|| {
        crate::Error::Msg("no initrd on this stick (live/initrd.img or casper/initrd)".into())
    })?;
    let tmp = std::env::temp_dir().join(format!("sigil-initrd-{}", std::process::id()));
    let _ = fs::remove_dir_all(&tmp);
    let unpacked = tmp.join("root");
    fs::create_dir_all(&unpacked).map_err(|e| crate::Error::Msg(e.to_string()))?;

    let unpacked_ok = Command::new("unmkinitramfs")
        .arg(&initrd)
        .arg(&unpacked)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !unpacked_ok {
        fallback_unpack(&initrd, &unpacked)?;
    }

    let inner = initrd_inner(&unpacked);
    let bin_dest = inner.join("bin");
    fs::create_dir_all(&bin_dest).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let placed = bin_dest.join("sigil");
    fs::copy(sigil_bin, &placed).map_err(|e| crate::Error::Msg(e.to_string()))?;
    unix_exec(&placed)?;

    for (rel, body) in [
        ("scripts/live-premount/sigil", SCRIPT_LIVE_PREMOUNT),
        ("scripts/init-premount/sigil", SCRIPT_INIT_PREMOUNT),
    ] {
        let dest = inner.join(rel);
        if let Some(p) = dest.parent() {
            fs::create_dir_all(p).map_err(|e| crate::Error::Msg(e.to_string()))?;
        }
        fs::write(&dest, body).map_err(|e| crate::Error::Msg(e.to_string()))?;
        unix_exec(&dest)?;
    }

    let kind = detect_compress(&initrd);
    let bak = PathBuf::from(format!("{}.bak", initrd.display()));
    if !bak.exists() {
        fs::copy(&initrd, &bak).map_err(|e| crate::Error::Msg(e.to_string()))?;
    }
    let new_img = tmp.join("new.img");
    repack_initrd(&inner, &new_img, kind)?;
    fs::copy(&new_img, &initrd).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let _ = fs::remove_dir_all(&tmp);
    Ok(initrd)
}

pub const HOOK_INITRAMFS: &str = include_str!("../boot/initramfs-hook.sh");
pub const SCRIPT_LIVE_PREMOUNT: &str = include_str!("../boot/live-premount.sh");
pub const SCRIPT_INIT_PREMOUNT: &str = include_str!("../boot/init-premount.sh");
pub const HOOK_DRACUT_SETUP: &str = include_str!("../boot/dracut-setup.sh");
pub const HOOK_DRACUT_MEND: &str = include_str!("../boot/dracut-mend.sh");

pub fn install_hooks(prefix: &Path) -> Result<Vec<PathBuf>> {
    let mut wrote = Vec::new();
    let pairs: &[(&str, &str)] = &[
        ("share/initramfs-tools/hooks/sigil", HOOK_INITRAMFS),
        (
            "share/initramfs-tools/scripts/live-premount/sigil",
            SCRIPT_LIVE_PREMOUNT,
        ),
        (
            "share/initramfs-tools/scripts/init-premount/sigil",
            SCRIPT_INIT_PREMOUNT,
        ),
        (
            "lib/dracut/modules.d/90sigil/module-setup.sh",
            HOOK_DRACUT_SETUP,
        ),
        ("lib/dracut/modules.d/90sigil/mend.sh", HOOK_DRACUT_MEND),
    ];
    for (rel, body) in pairs {
        let dest = prefix.join(rel);
        if let Some(p) = dest.parent() {
            fs::create_dir_all(p).map_err(|e| crate::Error::Msg(e.to_string()))?;
        }
        fs::write(&dest, body).map_err(|e| crate::Error::Msg(e.to_string()))?;
        unix_exec(&dest)?;
        wrote.push(dest);
    }
    Ok(wrote)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Mode;

    fn boot_tmp(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("sigil-boot-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("live")).unwrap();
        dir
    }

    fn fake_squash(dir: &Path, payload: &[u8]) -> PathBuf {
        let squash = dir.join("live/filesystem.squashfs");
        fs::write(&squash, payload).unwrap();
        squash
    }

    #[test]
    fn prepare_damage_mend() {
        let dir = boot_tmp("mend");
        let payload: Vec<u8> = (0..80_000u32).map(|i| (i % 251) as u8).collect();
        let squash = fake_squash(&dir, &payload);

        let find = prepare_boot(&dir, Mode::Seal, None, false).unwrap();
        assert!(find.mark.is_file());
        assert_eq!(fs::read(&squash).unwrap(), payload);

        let stage = dir.join("stage");
        match mend_boot(&dir, None, &stage).unwrap() {
            BootOutcome::Intact { .. } => {}
            other => panic!("expected intact, got {other:?}"),
        }

        fs::write(&squash, b"chewed").unwrap();
        match mend_boot(&dir, None, &stage).unwrap() {
            BootOutcome::Mended { .. } => {}
            other => panic!("expected mended, got {other:?}"),
        }
        assert_eq!(fs::read(&squash).unwrap(), payload);

        let bytes = fs::read(&find.mark).unwrap();
        let mut torn = bytes.clone();
        if torn.len() > 200 {
            torn[200..].fill(0xAA);
        }
        fs::write(&find.mark, &torn).unwrap();
        fs::remove_file(&squash).unwrap();
        let err = mend_boot(&dir, None, &stage).unwrap_err().to_string();
        assert!(
            err.contains("too damaged")
                || err.contains("will not guess")
                || err.contains("De-scribe failed"),
            "{err}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn work_pack_facet_skips_unpack_then_mends() {
        let dir = boot_tmp("work");
        let payload: Vec<u8> = (0..200_000u32).map(|i| (i % 251) as u8).collect();
        let squash = fake_squash(&dir, &payload);
        let mark = dir.join("live/filesystem.squashfs.sg1");
        let (orig, stars, work) = inscribe_path(
            &squash,
            &mark,
            Mode::Seal,
            None,
            "boot",
            &[],
            64 * 1024,
            None,
            0,
            64,
            None,
        )
        .unwrap();
        assert!(work);
        assert_eq!(orig, payload.len() as u64);
        assert!(stars > 1);

        let find = BootFind {
            mark: mark.clone(),
            payload: squash.clone(),
        };
        let stage = dir.join("stage");
        match mend_find(&find, None, &stage).unwrap() {
            BootOutcome::Intact { .. } => {}
            other => panic!("expected intact work pack, got {other:?}"),
        }

        let mut chewed = payload.clone();
        chewed[1000] ^= 0xff;
        fs::write(&squash, &chewed).unwrap();
        match mend_find(&find, None, &stage).unwrap() {
            BootOutcome::Mended { .. } => {}
            other => panic!("expected mended work pack, got {other:?}"),
        }
        assert_eq!(fs::read(&squash).unwrap(), payload);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn no_mark_is_clean_error() {
        let dir = boot_tmp("empty");
        let err = mend_boot(&dir, None, &dir.join("s"))
            .unwrap_err()
            .to_string();
        assert!(err.contains("no boot mark"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn install_hooks_writes_scripts() {
        let dir = boot_tmp("hooks");
        let wrote = install_hooks(&dir).unwrap();
        assert!(wrote.len() >= 5);
        assert!(dir
            .join("share/initramfs-tools/scripts/live-premount/sigil")
            .is_file());
        assert!(dir.join("lib/dracut/modules.d/90sigil/mend.sh").is_file());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn copy_helper_lands_in_live() {
        let dir = boot_tmp("helper");
        let src = dir.join("dummy-sigil");
        fs::write(&src, b"#!/bin/sh\n").unwrap();
        let dest = copy_sigil_binary(&dir, &src).unwrap();
        assert_eq!(dest, dir.join("live/sigil"));
        assert!(dest.is_file());
        let _ = fs::remove_dir_all(&dir);
    }
}
