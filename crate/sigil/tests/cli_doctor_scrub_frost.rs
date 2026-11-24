//! CLI: `sigil doctor --scrub` must fail closed on Frost Rune pieces (`.sgp`), which it
//! cannot check. It used to report `0 Sigil(s) … 0 clean` and exit 0.
mod common;
use std::path::Path;
use std::process::{Command, Output};

fn sigil(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(common::pass_via_file(args))
        .output()
        .expect("run sigil")
}

fn place_kit(dir: &Path) {
    std::fs::write(dir.join("cold.bin"), vec![7u8; 20_000]).unwrap();
    assert!(sigil(dir, &["seal", "-o", "cold.sg1", "cold.bin"])
        .status
        .success());
    let out = sigil(dir, &["frost", "place", "-o", "kit", "cold.sg1"]);
    assert!(out.status.success(), "{out:?}");
    assert!(dir.join("kit/KIT").is_file());
}

#[test]
fn scrub_on_frost_kit_root_exits_3_and_says_not_checked() {
    let dir = common::scratch("cli-scrub-frost");
    place_kit(&dir);
    let out = sigil(&dir, &["doctor", "--scrub", "kit"]);
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(out.status.code(), Some(3), "{text}");
    assert!(text.contains("NOT CHECKED"), "{text}");
    assert!(text.contains("sigil frost mend"), "{text}");
}

#[test]
fn scrub_on_one_frost_drive_folder_exits_3() {
    let dir = common::scratch("cli-scrub-frost-usb");
    place_kit(&dir);
    let out = sigil(&dir, &["doctor", "--scrub", "kit/usb-0"]);
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(out.status.code(), Some(3), "{text}");
    assert!(text.contains("NOT CHECKED"), "{text}");
}

#[test]
fn scrub_mixed_folder_still_scrubs_sg1_then_exits_3() {
    let dir = common::scratch("cli-scrub-frost-mixed");
    place_kit(&dir);
    std::fs::create_dir_all(dir.join("kit/plain")).unwrap();
    std::fs::copy(dir.join("cold.sg1"), dir.join("kit/plain/cold.sg1")).unwrap();
    let out = sigil(&dir, &["doctor", "--scrub", "kit"]);
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(out.status.code(), Some(3), "{text}");
    assert!(text.contains("cold.sg1: ok"), "{text}");
    assert!(text.contains("NOT CHECKED"), "{text}");
}

#[test]
fn scrub_with_json_is_refused_not_ignored() {
    let dir = common::scratch("cli-scrub-json");
    std::fs::create_dir_all(dir.join("v")).unwrap();
    let out = sigil(&dir, &["doctor", "--scrub", "--json", "v"]);
    assert!(!out.status.success());
    assert!(out.stdout.is_empty());
    let err = String::from_utf8_lossy(&out.stderr);
    assert!(err.contains("cannot be used with"), "{err}");
}

#[test]
fn scrub_plain_sg1_folder_still_exits_0() {
    let dir = common::scratch("cli-scrub-plain");
    std::fs::create_dir_all(dir.join("v")).unwrap();
    std::fs::write(dir.join("a.bin"), b"plain").unwrap();
    assert!(sigil(&dir, &["seal", "-o", "v/a.sg1", "a.bin"])
        .status
        .success());
    let out = sigil(&dir, &["doctor", "--scrub", "v"]);
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(!text.contains("NOT CHECKED"), "{text}");
}
