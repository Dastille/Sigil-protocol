//! `sigil mend` on a plain (v1) folder pack: heals damaged member stars (small `.sg1`
//! members and large-file members) back to the original bytes, leaves a healthy pack
//! byte-identical, and fails closed (no output) when a member is beyond repair.
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn sigil(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run sigil")
}

fn ok(dir: &Path, args: &[&str]) -> String {
    let o = sigil(dir, args);
    let t = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(o.status.success(), "{args:?}: {t}");
    t
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sigil-mendv1-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

fn data(n: usize, seed: u64) -> Vec<u8> {
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

/// Find where `needle` (a member's file bytes are sealed, so use the name) sits.
fn find(hay: &[u8], needle: &[u8]) -> usize {
    hay.windows(needle.len())
        .position(|w| w == needle)
        .expect("member name in pack")
}

fn pack(d: &Path, big: bool) -> (Vec<u8>, Vec<u8>) {
    let a = data(if big { 9 * 1024 * 1024 } else { 200_000 }, 3);
    let b = data(5_000, 9);
    std::fs::create_dir_all(d.join("f")).expect("mkdir");
    std::fs::write(d.join("f/a.bin"), &a).expect("w");
    std::fs::write(d.join("f/b.txt"), &b).expect("w");
    ok(d, &["seal", "f", "-o", "f.sg1"]);
    let raw = std::fs::read(d.join("f.sg1")).expect("r");
    assert_eq!(&raw[..5], b"SGDR\x01", "plain v1 folder pack");
    (a, b)
}

fn flip(raw: &mut [u8], from: usize, count: usize, stride: usize) {
    for i in 0..count {
        raw[from + i * stride] ^= 0xa5;
    }
}

fn restored(d: &Path, mark: &str, a: &[u8], b: &[u8]) {
    let out = format!("out-{mark}");
    ok(d, &["unseal", mark, "-o", &out]);
    assert_eq!(std::fs::read(d.join(&out).join("a.bin")).expect("a"), a);
    assert_eq!(std::fs::read(d.join(&out).join("b.txt")).expect("b"), b);
}

#[test]
fn mend_heals_small_members_byte_identical() {
    let d = scratch("small");
    let (a, b) = pack(&d, false);
    let good = std::fs::read(d.join("f.sg1")).expect("r");
    let mut raw = good.clone();
    let at = find(&raw, b"a.bin") + 5 + 8 + 2000;
    flip(&mut raw, at, 10, 40);
    std::fs::write(d.join("d.sg1"), &raw).expect("w");
    let t = ok(&d, &["mend", "d.sg1", "-o", "m.sg1"]);
    assert!(t.contains("1 healed: a.bin"), "{t}");
    assert_eq!(std::fs::read(d.join("m.sg1")).expect("m"), good);
    restored(&d, "m.sg1", &a, &b);
    // Healthy pack: nothing healed, byte-identical.
    let t = ok(&d, &["mend", "f.sg1", "-o", "h.sg1"]);
    assert!(t.contains("0 healed"), "{t}");
    assert_eq!(std::fs::read(d.join("h.sg1")).expect("h"), good);
}

#[test]
fn mend_heals_a_large_file_member() {
    let d = scratch("big");
    let (a, b) = pack(&d, true);
    let mut raw = std::fs::read(d.join("f.sg1")).expect("r");
    let at = find(&raw, b"a.bin") + 5 + 8 + 300_000;
    flip(&mut raw, at, 10, 64);
    std::fs::write(d.join("d.sg1"), &raw).expect("w");
    let t = ok(&d, &["mend", "d.sg1", "-o", "m.sg1"]);
    assert!(t.contains("1 healed: a.bin"), "{t}");
    restored(&d, "m.sg1", &a, &b);
}

#[test]
fn mend_fails_closed_when_a_member_is_beyond_repair() {
    let d = scratch("dead");
    pack(&d, false);
    let mut raw = std::fs::read(d.join("f.sg1")).expect("r");
    let at = find(&raw, b"a.bin") + 5 + 8;
    // Wipe most of the member star: far past what its parity can fix.
    for x in raw.iter_mut().skip(at).take(180_000) {
        *x = 0;
    }
    std::fs::write(d.join("d.sg1"), &raw).expect("w");
    let o = sigil(&d, &["mend", "d.sg1", "-o", "m.sg1"]);
    assert!(!o.status.success());
    assert!(
        String::from_utf8_lossy(&o.stderr).contains("a.bin"),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(!d.join("m.sg1").exists());
    assert!(!d.join("m.sg1.mend-part").exists());
}
