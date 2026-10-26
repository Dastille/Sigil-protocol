//! CLI: `sigil constellation scry` / `sigil scry` on a constellation report
//! `NOT recoverable` and exit 2 when a member cannot be restored from this copy
//! (star missing or beyond repair), and stay `ok` (exit 0) when every star is
//! healthy or only repairably damaged. Fail-closed: a missing star never passes.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sigil::container;

fn sigil_cmd(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .env_remove("SIGIL_SOFT_AUTHENTICATOR")
        .args(args)
        .output()
        .expect("run sigil")
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

/// Scratch dir under Cargo's per-target temp dir (not a guessable /tmp name).
fn scratch(tag: &str) -> PathBuf {
    let d = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join(format!("scry-verdict-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn noise(n: usize, mut x: u64) -> Vec<u8> {
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// A container constellation `Sky.sigil` with two stars (a.txt, sub/big.bin).
fn make_sky(tag: &str) -> (PathBuf, Vec<u8>) {
    let dir = scratch(tag);
    fs::create_dir_all(dir.join("docs/sub")).unwrap();
    fs::write(dir.join("docs/a.txt"), b"alpha alpha alpha").unwrap();
    let big = noise(200_000, 0x9e37_79b9_7f4a_7c15);
    fs::write(dir.join("docs/sub/big.bin"), &big).unwrap();
    let o = sigil_cmd(&dir, &["constellation", "add", "Sky", "docs"]);
    assert!(o.status.success(), "{}", text(&o));
    (dir, big)
}

fn assert_ok(dir: &Path, args: &[&str]) -> String {
    let o = sigil_cmd(dir, args);
    let t = text(&o);
    assert_eq!(o.status.code(), Some(0), "{args:?}: {t}");
    assert!(!t.contains("NOT recoverable"), "{args:?}: {t}");
    t
}

fn assert_not_recoverable(dir: &Path, args: &[&str]) -> String {
    let o = sigil_cmd(dir, args);
    let t = text(&o);
    assert_eq!(o.status.code(), Some(2), "{args:?}: {t}");
    assert!(t.contains("NOT recoverable"), "{args:?}: {t}");
    t
}

#[test]
fn healthy_constellation_scry_is_ok() {
    let (dir, _) = make_sky("healthy");
    let t = assert_ok(&dir, &["constellation", "scry", "Sky"]);
    assert!(t.contains("stars=2") && !t.contains("MISSING"), "{t}");
    assert_ok(&dir, &["scry", "Sky.sigil"]);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn missing_star_is_not_recoverable() {
    let (dir, big) = make_sky("missing");
    let star = container::star_path(&dir.join("Sky.sigil"), &sigil::sha256(&big));
    assert!(star.is_file(), "{}", star.display());
    fs::remove_file(&star).unwrap();
    let t = assert_not_recoverable(&dir, &["constellation", "scry", "Sky"]);
    assert!(
        t.contains("MISSING") && t.contains("1 star(s) missing"),
        "{t}"
    );
    assert!(t.contains("big.bin"), "names the lost member: {t}");
    let t = assert_not_recoverable(&dir, &["scry", "Sky.sigil"]);
    assert!(t.contains("too damaged"), "{t}");
    // --json reports the failure with exit 2 too.
    let o = sigil_cmd(&dir, &["--json", "scry", "Sky.sigil"]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn wiped_star_is_not_recoverable() {
    let (dir, big) = make_sky("wiped");
    let star = container::star_path(&dir.join("Sky.sigil"), &sigil::sha256(&big));
    let len = fs::metadata(&star).unwrap().len() as usize;
    fs::write(&star, vec![0u8; len]).unwrap();
    let t = assert_not_recoverable(&dir, &["constellation", "scry", "Sky"]);
    assert!(t.contains("beyond repair") && t.contains("big.bin"), "{t}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn truncated_star_is_not_recoverable() {
    let (dir, big) = make_sky("trunc");
    let star = container::star_path(&dir.join("Sky.sigil"), &sigil::sha256(&big));
    let bytes = fs::read(&star).unwrap();
    fs::write(&star, &bytes[..bytes.len() / 3]).unwrap();
    let t = assert_not_recoverable(&dir, &["constellation", "scry", "Sky"]);
    assert!(t.contains("beyond repair") && t.contains("big.bin"), "{t}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn repairable_bit_flip_stays_ok() {
    let (dir, big) = make_sky("flip");
    let star = container::star_path(&dir.join("Sky.sigil"), &sigil::sha256(&big));
    let mut bytes = fs::read(&star).unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0x40;
    fs::write(&star, &bytes).unwrap();
    // One flipped byte is within the repair margin: scry must not cry wolf...
    assert_ok(&dir, &["constellation", "scry", "Sky"]);
    // ...and the data really does come back.
    let o = sigil_cmd(&dir, &["de-scribe", "-o", "out", "Sky.sigil"]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(fs::read(dir.join("out/sub/big.bin")).unwrap(), big);
    let _ = fs::remove_dir_all(&dir);
}
