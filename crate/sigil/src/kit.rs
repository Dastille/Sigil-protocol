//! Cold-USB kits — Option A placement only (no Azure LRC codec).
//!
//! Keep Seal (8,16). Round-robin the 16 shards across N USB directories
//! (default 4 → 4 shards/USB). Losing one USB = 4 shards gone = within Seal
//! budget. The KIT manifest records star_id / shard_id / usb_id.

use crate::header::{locate_header, Header};
use crate::pieces::{gather_dirs, scatter};
use crate::{hex32, Mode, Result};
use std::fs;
use std::path::{Path, PathBuf};

pub const KIT_MANIFEST: &str = "KIT";
pub const DEFAULT_DRIVES: usize = 4;

#[derive(Clone, Debug)]
pub struct PlaceReport {
    pub drives: usize,
    pub pieces: u8,
    pub per_drive: Vec<usize>,
    pub star_id: String,
    pub name: String,
    pub n: u8,
    pub k: u8,
}

pub fn is_kit_dir(path: &Path) -> bool {
    path.join(KIT_MANIFEST).is_file()
}

fn usb_dirs(kit: &Path) -> Result<Vec<PathBuf>> {
    let mut dirs = Vec::new();
    let rd = fs::read_dir(kit).map_err(|e| crate::Error::Msg(e.to_string()))?;
    for ent in rd {
        let ent = ent.map_err(|e| crate::Error::Msg(e.to_string()))?;
        let name = ent.file_name();
        let name = name.to_string_lossy();
        if name.starts_with("usb-") && ent.path().is_dir() {
            dirs.push(ent.path());
        }
    }
    dirs.sort();
    Ok(dirs)
}

fn budget_ok(h: &Header, drives: usize) -> Result<usize> {
    let n = h.n as usize;
    let k = h.k as usize;
    if drives == 0 {
        return Err(crate::Error::Msg("need at least 1 drive".into()));
    }
    // Round-robin: drive i gets ceil((n - i) / drives) shards.
    let max_on_one = n.div_ceil(drives);
    let erasures = n.saturating_sub(k);
    if max_on_one > erasures {
        return Err(crate::Error::Msg(format!(
            "one USB would hold {max_on_one} shards but this mark only survives {erasures} losses \
             (k={k} n={n}). Use more --drives, or Seal (8,16) with 4 USBs."
        )));
    }
    Ok(max_on_one)
}

/// Spread a mark's classic pieces across `drives` USB folders (Option A).
pub fn place(file: &[u8], kit: &Path, drives: usize) -> Result<PlaceReport> {
    let drives = if drives == 0 { DEFAULT_DRIVES } else { drives };
    let (h, _, _) = locate_header(file)?;
    if h.mode() == Mode::Glyph {
        return Err(crate::Error::Msg(
            "Glyph has no repair budget for a cold-USB kit. Use Seal (or Reflection with enough drives)."
                .into(),
        ));
    }
    let _per = budget_ok(&h, drives)?;
    let n = h.n as usize;

    fs::create_dir_all(kit).map_err(|e| crate::Error::Msg(e.to_string()))?;
    // Clear prior usb-* layout so place is idempotent for this kit root.
    for d in usb_dirs(kit)? {
        let _ = fs::remove_dir_all(&d);
    }
    let _ = fs::remove_file(kit.join(KIT_MANIFEST));

    let staging = kit.join(".sigil-kit-staging");
    let _ = fs::remove_dir_all(&staging);
    scatter(file, &staging)?;

    let mut per_drive = vec![0usize; drives];
    let mut lines: Vec<String> = Vec::with_capacity(n);
    for i in 0..n {
        let usb = i % drives;
        let dest_dir = kit.join(format!("usb-{usb}"));
        fs::create_dir_all(&dest_dir).map_err(|e| crate::Error::Msg(e.to_string()))?;
        let src = staging.join(format!("piece-{i:03}.sgp"));
        let dst = dest_dir.join(format!("piece-{i:03}.sgp"));
        if let Err(e) = fs::rename(&src, &dst) {
            fs::copy(&src, &dst).map_err(|e2| {
                crate::Error::Msg(format!("place piece {i}: rename {e}; copy {e2}"))
            })?;
            let _ = fs::remove_file(&src);
        }
        per_drive[usb] += 1;
        lines.push(format!("shard={i} usb={usb}"));
    }
    let _ = fs::remove_dir_all(&staging);

    let star_id = hex32(&h.digest);
    let man = format!(
        "sigil-cold-usb=1\noption=A\nstar_id={star_id}\nname={}\nn={}\nk={}\nshard_len={}\ndrives={drives}\n{}\n",
        h.name,
        h.n,
        h.k,
        h.shard_len,
        lines.join("\n")
    );
    fs::write(kit.join(KIT_MANIFEST), man).map_err(|e| crate::Error::Msg(e.to_string()))?;

    Ok(PlaceReport {
        drives,
        pieces: n as u8,
        per_drive,
        star_id,
        name: h.name.clone(),
        n: h.n,
        k: h.k,
    })
}

/// Rebuild a healthy .sg1 from whatever `usb-*` folders remain in the kit.
pub fn mend(kit: &Path) -> Result<Vec<u8>> {
    let dirs = usb_dirs(kit)?;
    if dirs.is_empty() {
        return Err(crate::Error::Msg(
            "no usb-* folders in this kit (copy remaining drives back under the kit root)".into(),
        ));
    }
    let refs: Vec<&Path> = dirs.iter().map(|p| p.as_path()).collect();
    gather_dirs(&refs)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{seal, unseal, Mode};

    #[test]
    fn seal_across_four_usbs_survive_one_loss() {
        let msg = b"cold-usb option A - true name must hold after one drive dies";
        let sg1 = seal(msg, Mode::Seal, None, "mark.bin", false).unwrap();
        let (h0, _, _) = locate_header(&sg1).unwrap();
        assert_eq!(h0.n, 16);
        assert_eq!(h0.k, 8);

        let dir = std::env::temp_dir().join(format!(
            "sigil-kit-{}-{}",
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        let report = place(&sg1, &dir, 4).unwrap();
        assert_eq!(report.drives, 4);
        assert_eq!(report.pieces, 16);
        assert_eq!(report.per_drive, vec![4, 4, 4, 4]);
        assert!(is_kit_dir(&dir));
        assert_eq!(report.star_id, hex32(&h0.digest));

        for i in 0..4 {
            let usb = dir.join(format!("usb-{i}"));
            assert!(usb.is_dir(), "missing {}", usb.display());
            let count = fs::read_dir(&usb)
                .unwrap()
                .filter(|e| {
                    e.as_ref()
                        .ok()
                        .and_then(|e| e.file_name().to_str().map(|n| n.ends_with(".sgp")))
                        .unwrap_or(false)
                })
                .count();
            assert_eq!(count, 4, "usb-{i} piece count");
        }

        // Lose usb-2 entirely.
        fs::remove_dir_all(dir.join("usb-2")).unwrap();
        assert!(!dir.join("usb-2").exists());

        let healed = mend(&dir).unwrap();
        let (h1, _, _) = locate_header(&healed).unwrap();
        assert_eq!(h1.digest, h0.digest, "true-name must match");
        let plain = unseal(&healed, None).unwrap();
        assert_eq!(plain, msg);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn too_few_drives_rejected() {
        let sg1 = seal(b"budget check", Mode::Seal, None, "x.bin", false).unwrap();
        let dir = std::env::temp_dir().join(format!("sigil-kit-bad-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        // 2 drives → 8 shards each, but Seal only survives 8 erasures — equal is OK.
        // 1 drive → 16 shards on one stick, over budget.
        let err = place(&sg1, &dir, 1).unwrap_err();
        assert!(err.to_string().contains("survives"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }
}
