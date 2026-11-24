//! CLI: `sigil doctor --scrub` must fail closed when it checks nothing. An empty folder,
//! a folder with no `.sg1` files, a missing path or a file instead of a folder used to
//! print `0 Sigil(s) … 0 clean` and exit 0 (or a bare OS error). All now exit 3 ("could
//! not check", same as `sigil doctor`) with a plain message; a good folder still exits 0.
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

fn all_text(out: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    )
}

#[test]
fn scrub_empty_folder_exits_3_nothing_checked() {
    let dir = common::scratch("cli-scrub-empty");
    std::fs::create_dir_all(dir.join("empty")).unwrap();
    let out = sigil(&dir, &["doctor", "--scrub", "empty"]);
    let text = all_text(&out);
    assert_eq!(out.status.code(), Some(3), "{text}");
    assert!(
        text.contains("no Sigil files found in empty, nothing was checked"),
        "{text}"
    );
}

#[test]
fn scrub_folder_with_only_non_sigil_files_exits_3() {
    let dir = common::scratch("cli-scrub-nonsigil");
    std::fs::create_dir_all(dir.join("docs/sub")).unwrap();
    std::fs::write(dir.join("docs/a.txt"), b"hello").unwrap();
    std::fs::write(dir.join("docs/sub/b.jpg"), vec![1u8; 500]).unwrap();
    let out = sigil(&dir, &["doctor", "--scrub", "docs"]);
    let text = all_text(&out);
    assert_eq!(out.status.code(), Some(3), "{text}");
    assert!(
        text.contains("no Sigil files found in docs, nothing was checked"),
        "{text}"
    );
}

#[test]
fn scrub_missing_folder_exits_3_with_plain_error() {
    let dir = common::scratch("cli-scrub-missing");
    let out = sigil(&dir, &["doctor", "--scrub", "not-here"]);
    let text = all_text(&out);
    assert_eq!(out.status.code(), Some(3), "{text}");
    assert!(text.contains("no such folder: not-here"), "{text}");
    assert!(text.contains("nothing was checked"), "{text}");
    assert!(!text.contains("0 clean"), "{text}");
}

#[test]
fn scrub_file_instead_of_folder_exits_3_with_plain_error() {
    let dir = common::scratch("cli-scrub-file");
    std::fs::write(dir.join("a.bin"), vec![3u8; 4_000]).unwrap();
    assert!(sigil(&dir, &["seal", "-o", "a.sg1", "a.bin"])
        .status
        .success());
    let out = sigil(&dir, &["doctor", "--scrub", "a.sg1"]);
    let text = all_text(&out);
    assert_eq!(out.status.code(), Some(3), "{text}");
    assert!(text.contains("a.sg1 is not a folder"), "{text}");
    assert!(text.contains("nothing was checked"), "{text}");
}

#[test]
fn scrub_good_folder_still_exits_0_with_unchanged_output() {
    let dir = common::scratch("cli-scrub-good");
    std::fs::create_dir_all(dir.join("good")).unwrap();
    std::fs::write(dir.join("a.bin"), vec![5u8; 4_000]).unwrap();
    assert!(sigil(&dir, &["seal", "-o", "good/a.sg1", "a.bin"])
        .status
        .success());
    let out = sigil(&dir, &["doctor", "--scrub", "good"]);
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(out.status.code(), Some(0), "{text}");
    assert!(text.contains("a.sg1: ok"), "{text}");
    assert!(
        text.ends_with("scrub: 1 Sigil(s), 0 repaired, 0 uncorrectable, 1 clean\n"),
        "{text}"
    );
    assert!(!text.contains("nothing was checked"), "{text}");
}
