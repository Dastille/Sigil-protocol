//! CLI regression: a damaged large-file pack must never unseal (or mend) to a
//! silently truncated file. Either the whole file comes back byte-exact, or the
//! command exits nonzero with a clear error and leaves no output behind.
mod common;
use std::path::Path;
use std::process::Command;

fn sigil(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(common::pass_via_file(args))
        .output()
        .expect("run sigil")
}

fn setup(tag: &str) -> (common::Scratch, Vec<u8>) {
    let dir = common::scratch(&format!("cli-fc-{tag}"));
    let mut x = 0x2545f4914f6cdd1du64;
    // 6 MB: two 4 MiB chunk stars, the shape from the original bug report.
    let data: Vec<u8> = (0..6_000_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    std::fs::write(dir.join("a.bin"), &data).unwrap();
    let o = sigil(
        &dir,
        &[
            "seal", "--mode", "seal", "--shards", "254", "-o", "a.sg1", "a.bin",
        ],
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    (dir, data)
}

fn no_leftovers(dir: &Path, name: &str) {
    assert!(!dir.join(name).exists(), "{name} must not be written");
    assert!(
        !dir.join(format!("{name}.sigil-part")).exists(),
        "part file must be removed"
    );
}

#[test]
fn damaged_pack_head_fails_closed_not_truncated() {
    let (dir, data) = setup("head");
    let o = sigil(&dir, &["unseal", "a.sg1", "-o", "ok.bin"]);
    assert!(o.status.success());
    assert_eq!(std::fs::read(dir.join("ok.bin")).unwrap(), data);

    let original = std::fs::read(dir.join("a.sg1")).unwrap();
    let mut pack = original.clone();
    pack[..50].fill(0); // pack head (magic, sizes) gone; first chunk star mostly intact
    std::fs::write(dir.join("torn.sg1"), &pack).unwrap();

    // Guards carry a checksummed copy of the head, and SGFC names both chunk
    // stars. layout() restores the head and framing only after that
    // confirmation, so unseal must return the original 6 MB — not the first
    // star alone (the old truncated-success bug this test was written to
    // catch). The fail-closed contract is unchanged: never a short file.
    let o = sigil(&dir, &["unseal", "torn.sg1", "-o", "out.bin"]);
    assert!(
        o.status.success(),
        "guard-restored head must unseal, stderr: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert_eq!(
        std::fs::read(dir.join("out.bin")).unwrap(),
        data,
        "must be the original 6 MB, not a truncated first star"
    );
    std::fs::remove_file(dir.join("out.bin")).unwrap();

    // mend must not collapse it into a healthy-looking single-chunk seal.
    // With an intact guard it restores the original two-star work pack.
    let o = sigil(&dir, &["mend", "torn.sg1", "-o", "m.sg1"]);
    assert!(
        o.status.success(),
        "mend should restore from the guard: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    let mended = std::fs::read(dir.join("m.sg1")).unwrap();
    assert!(
        mended.starts_with(b"SGWK"),
        "mend must write a work pack, not a lone star"
    );
    let nlen = mended[17] as usize;
    let nstars = u32::from_le_bytes(mended[18 + nlen..18 + nlen + 4].try_into().unwrap());
    assert!(
        nstars >= 2,
        "must not collapse to a single-chunk seal, got {nstars}"
    );
    let o = sigil(&dir, &["unseal", "m.sg1", "-o", "mended.bin"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(std::fs::read(dir.join("mended.bin")).unwrap(), data);

    // Head and SGFC both gone: confirmation is impossible, so unseal and mend
    // must refuse and write nothing (the original fail-closed path).
    let mut no_confirm = original.clone();
    no_confirm[..50].fill(0);
    let n = no_confirm.len();
    no_confirm[n - 4096..].fill(0);
    std::fs::write(dir.join("gone.sg1"), &no_confirm).unwrap();
    let o = sigil(&dir, &["unseal", "gone.sg1", "-o", "gone.bin"]);
    assert!(
        !o.status.success(),
        "must exit nonzero when confirmation is impossible, stdout: {}",
        String::from_utf8_lossy(&o.stdout)
    );
    no_leftovers(&dir, "gone.bin");
    std::fs::write(dir.join("keep.bin"), b"previous").unwrap();
    let o = sigil(&dir, &["unseal", "gone.sg1", "-o", "keep.bin"]);
    assert!(!o.status.success());
    assert_eq!(std::fs::read(dir.join("keep.bin")).unwrap(), b"previous");
    let o = sigil(&dir, &["mend", "gone.sg1", "-o", "m2.sg1"]);
    assert!(
        !o.status.success(),
        "mend must refuse when confirmation is impossible: {}",
        String::from_utf8_lossy(&o.stdout)
    );
    assert!(!dir.join("m2.sg1").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn truncated_pack_fails_closed_and_leaves_nothing() {
    let (dir, data) = setup("trunc");
    let pack = std::fs::read(dir.join("a.sg1")).unwrap();
    for (i, cut) in [pack.len() / 2, pack.len() - 10, pack.len() * 3 / 4, 100]
        .into_iter()
        .enumerate()
    {
        let name = format!("cut{i}.sg1");
        std::fs::write(dir.join(&name), &pack[..cut]).unwrap();
        let o = sigil(&dir, &["unseal", &name, "-o", "out.bin"]);
        if o.status.success() {
            // Only the unprotected facet trailer was cut: every chunk is still
            // there and verified, so the whole file must come back exactly.
            assert_eq!(
                std::fs::read(dir.join("out.bin")).unwrap(),
                data,
                "cut at {cut}"
            );
            std::fs::remove_file(dir.join("out.bin")).unwrap();
        } else {
            no_leftovers(&dir, "out.bin");
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}
