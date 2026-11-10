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

    // ---- Frost Rune confidentiality: what one drive leaks (2026-11-10) ----
    //
    // A piece file carries the header (map + Ember) with the fold salt, and Seal uses
    // systematic RS, so data pieces 0..k-1 are slices of the folded body. The fold is
    // not a cipher: anyone with ONE drive can unfold its data pieces without any key.

    fn noise_bytes(len: usize, seed: u8) -> Vec<u8> {
        // SHA-256 counter stream: incompressible, deterministic.
        let mut out = Vec::with_capacity(len + 32);
        let mut i = 0u64;
        while out.len() < len {
            let mut block = vec![seed];
            block.extend_from_slice(&i.to_le_bytes());
            out.extend_from_slice(&crate::sha256(&block));
            i += 1;
        }
        out.truncate(len);
        out
    }

    /// Parse one .sgp piece file into (header, piece index, shard bytes) with no key.
    fn read_piece_keyless(path: &Path) -> (Header, usize, Vec<u8>) {
        let raw = fs::read(path).unwrap();
        assert_eq!(&raw[0..4], b"SGPC");
        let index = raw[5] as usize;
        let map_len = u32::from_le_bytes(raw[8..12].try_into().unwrap()) as usize;
        let map = &raw[12..12 + map_len];
        let (h, _, _) = locate_header(map).unwrap();
        let at = 12 + map_len;
        let body_len = u32::from_le_bytes(raw[at..at + 4].try_into().unwrap()) as usize;
        let body = &raw[at + 4..at + 4 + body_len];
        let lead = if h.ember() {
            crate::header::HEADER_SIZE
        } else {
            0
        } + if h.vow() { crate::header::VOW_SIZE } else { 0 };
        let sl = h.shard_len as usize;
        (h, index, body[lead..lead + sl].to_vec())
    }

    /// Undo the fold for one data shard using only the salt from the piece's own header.
    fn unfold_data_shard(h: &Header, index: usize, shard: &[u8]) -> Vec<u8> {
        let sl = h.shard_len as usize;
        let mut buf = vec![0u8; (index + 1) * sl];
        buf[index * sl..].copy_from_slice(shard);
        crate::chaos::unfold(&buf, &h.salt)[index * sl..].to_vec()
    }

    fn contains(hay: &[u8], needle: &[u8]) -> bool {
        hay.windows(needle.len()).any(|w| w == needle)
    }

    fn drive_pieces(usb: &Path) -> Vec<PathBuf> {
        let mut v: Vec<PathBuf> = fs::read_dir(usb)
            .unwrap()
            .map(|e| e.unwrap().path())
            .filter(|p| p.extension().map(|x| x == "sgp").unwrap_or(false))
            .collect();
        v.sort();
        v
    }

    // Two markers with no shared 3-byte run, so deflate finds nothing and stores the bytes.
    const MARK0: &[u8] = b"Plaintext:alpha";
    const MARK4: &[u8] = b"SECRET#4ZQV";

    fn marked_payload() -> Vec<u8> {
        // 64 KiB of incompressible bytes, marker in data piece 0 and data piece 4.
        let mut data = noise_bytes(64 * 1024, 7);
        data[100..100 + MARK0.len()].copy_from_slice(MARK0);
        data[4 * 8192 + 100..4 * 8192 + 100 + MARK4.len()].copy_from_slice(MARK4);
        data
    }

    #[test]
    fn unencrypted_seal_piece_on_one_frost_drive_is_readable_without_key() {
        let data = marked_payload();
        let sg1 = seal(&data, Mode::Seal, None, "plain.bin", false).unwrap();
        let dir = crate::staging::TempDir::create("sigil-kit-plainleak").unwrap();
        let report = place(&sg1, dir.path(), 4).unwrap();
        assert_eq!((report.k, report.n), (8, 16));
        assert_eq!(report.name, "plain.bin", "plain header names the file");

        // Only usb-0 is in the attacker's hands: pieces 0, 4, 8, 12.
        let usb0 = dir.path().join("usb-0");
        let mut seen = Vec::new();
        for p in drive_pieces(&usb0) {
            let raw = fs::read(&p).unwrap();
            let (h, index, shard) = read_piece_keyless(&p);
            assert_eq!(h.flags & 1, 0, "payload must be stored, not deflated");
            // The literal bytes are folded, so a plain grep does not find them ...
            assert!(!contains(&raw, MARK0) && !contains(&raw, MARK4));
            if index < h.k as usize {
                // ... but unfolding with the salt from the same file does.
                let clear = unfold_data_shard(&h, index, &shard);
                let m = if index == 0 { MARK0 } else { MARK4 };
                assert!(contains(&clear, m), "piece {index} not readable");
                let sl = h.shard_len as usize;
                assert_eq!(&clear[..sl - 1], &data[index * sl..(index + 1) * sl - 1]);
                seen.push(index);
            }
        }
        assert_eq!(
            seen,
            vec![0, 4],
            "one drive holds two data pieces in the clear"
        );
    }

    #[test]
    fn unencrypted_compressed_text_piece_is_readable_without_key() {
        let mut text = String::new();
        for i in 0..4000 {
            text.push_str(&format!(
                "line {i}: my bank PIN is not here but this sentence is\n"
            ));
        }
        let sg1 = seal(text.as_bytes(), Mode::Seal, None, "notes.txt", false).unwrap();
        let dir = crate::staging::TempDir::create("sigil-kit-plainleak-z").unwrap();
        place(&sg1, dir.path(), 4).unwrap();
        let p = dir.path().join("usb-0").join("piece-000.sgp");
        let (h, index, shard) = read_piece_keyless(&p);
        assert_eq!(index, 0);
        assert_eq!(h.flags & 1, 1, "text should have been deflated");
        let z = unfold_data_shard(&h, 0, &shard);
        let mut out = Vec::new();
        // The piece holds a prefix of the deflate stream; read what it gives.
        let _ =
            std::io::Read::read_to_end(&mut flate2::read::DeflateDecoder::new(&z[..]), &mut out);
        assert!(
            contains(
                &out,
                b"line 0: my bank PIN is not here but this sentence is"
            ),
            "inflated {} bytes, no text",
            out.len()
        );
    }

    #[test]
    fn passphrase_seal_piece_on_one_frost_drive_shows_no_plaintext() {
        let data = marked_payload();
        let sg1 = seal(
            &data,
            Mode::Seal,
            Some("frost rune test pass"),
            "plain.bin",
            false,
        )
        .unwrap();
        let dir = crate::staging::TempDir::create("sigil-kit-encleak").unwrap();
        place(&sg1, dir.path(), 4).unwrap();
        for usb in 0..4 {
            for p in drive_pieces(&dir.path().join(format!("usb-{usb}"))) {
                let raw = fs::read(&p).unwrap();
                assert!(!contains(&raw, MARK0) && !contains(&raw, MARK4));
                assert!(!contains(&raw, b"plain.bin"), "file name must not show");
                let (h, index, shard) = read_piece_keyless(&p);
                assert!(h.name.is_empty());
                if index < h.k as usize {
                    let clear = unfold_data_shard(&h, index, &shard);
                    assert!(!contains(&clear, MARK0), "piece {index}");
                    assert!(!contains(&clear, MARK4), "piece {index}");
                }
            }
        }
    }
}
