//! CLI regression: a damaged large-file pack must never unseal (or mend) to a
//! silently truncated file. Either the whole file comes back byte-exact, or the
//! command exits nonzero with a clear error and leaves no output behind.
use std::path::{Path, PathBuf};
use std::process::Command;

fn sigil(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(args)
        .output()
        .expect("run sigil")
}

fn setup(tag: &str) -> (PathBuf, Vec<u8>) {
    let dir = std::env::temp_dir().join(format!("sigil-cli-fc-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
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

    let mut pack = std::fs::read(dir.join("a.sg1")).unwrap();
    pack[..50].fill(0); // pack head (magic, sizes) gone; first chunk star intact
    std::fs::write(dir.join("torn.sg1"), &pack).unwrap();

    let o = sigil(&dir, &["unseal", "torn.sg1", "-o", "out.bin"]);
    assert!(
        !o.status.success(),
        "must exit nonzero, stdout: {}",
        String::from_utf8_lossy(&o.stdout)
    );
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(
        err.contains("more than one seal"),
        "clear error, got: {err}"
    );
    no_leftovers(&dir, "out.bin");

    // An existing output file is left untouched on failure.
    std::fs::write(dir.join("keep.bin"), b"previous").unwrap();
    let o = sigil(&dir, &["unseal", "torn.sg1", "-o", "keep.bin"]);
    assert!(!o.status.success());
    assert_eq!(std::fs::read(dir.join("keep.bin")).unwrap(), b"previous");

    // mend must not "heal" it into a healthy-looking single-chunk seal either.
    let o = sigil(&dir, &["mend", "torn.sg1", "-o", "m.sg1"]);
    assert!(
        !o.status.success(),
        "mend must refuse: {}",
        String::from_utf8_lossy(&o.stdout)
    );
    assert!(!dir.join("m.sg1").exists());
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
