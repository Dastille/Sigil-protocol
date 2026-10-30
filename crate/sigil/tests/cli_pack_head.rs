//! CLI: a large-file pack whose head is damaged is rebuilt from the facet list
//! and the stars' own headers (old packs included), and refused when it cannot be.
mod common;
use std::path::Path;
use std::process::Command;

fn sigil(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(args)
        .output()
        .expect("run sigil")
}

fn text(o: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn plain() -> Vec<u8> {
    let mut x = 0x2545f4914f6cdd1du64;
    (0..200_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn setup(tag: &str) -> (common::Scratch, Vec<u8>) {
    let dir = common::scratch(&format!("cli-ph-{tag}"));
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pack-v0");
    let pack = std::fs::read(fx.join("pack-v2-reflection.sg1")).unwrap();
    (dir, pack)
}

#[test]
fn old_pack_with_wiped_magic_unseals_and_mends_back_byte_exact() {
    let (dir, pack) = setup("magic");
    let mut bad = pack.clone();
    bad[..4].fill(0);
    std::fs::write(dir.join("torn.sg1"), &bad).unwrap();

    let o = sigil(&dir, &["unseal", "torn.sg1", "-o", "out.bin"]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(std::fs::read(dir.join("out.bin")).unwrap(), plain());

    let o = sigil(&dir, &["mend", "torn.sg1", "-o", "fixed.sg1"]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("pack head rebuilt"), "{}", text(&o));
    assert_eq!(std::fs::read(dir.join("fixed.sg1")).unwrap(), pack);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn old_pack_with_wrong_total_in_head_mends_in_place() {
    let (dir, pack) = setup("total");
    let mut bad = pack.clone();
    bad[9] ^= 0x10; // low byte of the stored total size
    std::fs::write(dir.join("p.sg1"), &bad).unwrap();
    let o = sigil(&dir, &["mend", "p.sg1", "-o", "p.sg1"]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(std::fs::read(dir.join("p.sg1")).unwrap(), pack);
    assert!(!dir.join("p.sg1.mend-part").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unrebuildable_head_still_fails_closed() {
    let (dir, pack) = setup("refuse");
    let mut bad = pack.clone();
    bad[..60].fill(0); // head and star 0's length framing gone
    std::fs::write(dir.join("torn.sg1"), &bad).unwrap();
    let o = sigil(&dir, &["unseal", "torn.sg1", "-o", "out.bin"]);
    assert!(!o.status.success());
    assert!(text(&o).contains("more than one seal"), "{}", text(&o));
    assert!(!dir.join("out.bin").exists());
    assert!(!dir.join("out.bin.sigil-part").exists());
    let o = sigil(&dir, &["mend", "torn.sg1", "-o", "m.sg1"]);
    assert!(!o.status.success());
    assert!(!dir.join("m.sg1").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn new_pack_with_head_and_facet_list_wiped_comes_back_byte_exact() {
    let (dir, _) = setup("guard");
    std::fs::write(dir.join("plain.bin"), plain()).unwrap();
    let o = sigil(
        &dir,
        &["seal", "--chunk", "65536", "-o", "new.sg1", "plain.bin"],
    );
    assert!(o.status.success(), "{}", text(&o));
    let pack = std::fs::read(dir.join("new.sg1")).unwrap();
    let mut bad = pack.clone();
    let n = bad.len();
    bad[..35].fill(0); // the whole head ("plain.bin": 26 + 9 bytes)
    bad[n - 32 * 4 - 8..].fill(0xaa); // facet list gone
    std::fs::write(dir.join("torn.sg1"), &bad).unwrap();

    let o = sigil(&dir, &["unseal", "torn.sg1", "-o", "out.bin"]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(std::fs::read(dir.join("out.bin")).unwrap(), plain());

    let o = sigil(&dir, &["mend", "torn.sg1", "-o", "fixed.sg1"]);
    assert!(o.status.success(), "{}", text(&o));
    let t = text(&o);
    assert!(
        t.contains("restored from a guard copy") && t.contains("facet list rebuilt"),
        "{t}"
    );
    assert_eq!(std::fs::read(dir.join("fixed.sg1")).unwrap(), pack);
    let _ = std::fs::remove_dir_all(&dir);
}
