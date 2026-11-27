//! CLI: a folder Inscribe lists every path it leaves out of the Tome on stderr and in
//! its summary, still exits 0 by default (existing scripts keep working), and with
//! `--fail-on-skip` refuses before writing anything.
#![cfg(unix)]
mod common;
use std::path::Path;
use std::process::{Command, Output};

fn sigil(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(args)
        .output()
        .expect("run sigil")
}

fn text(o: &Output) -> (String, String) {
    (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    )
}

fn tree(dir: &Path) {
    let src = dir.join("src");
    std::fs::create_dir_all(src.join(".cache")).unwrap();
    std::fs::create_dir_all(src.join("empty")).unwrap();
    std::fs::write(src.join("a.txt"), b"alpha").unwrap();
    std::fs::write(src.join(".env"), b"SECRET=1").unwrap();
    std::fs::write(src.join(".cache/x"), b"x").unwrap();
    std::os::unix::fs::symlink("missing", src.join("dangling")).unwrap();
}

#[test]
fn skipped_paths_are_listed_and_the_tome_is_still_written() {
    let dir = common::scratch("tome-skips");
    tree(&dir);
    let o = sigil(&dir, &["inscribe", "src", "-o", "t.sg1"]);
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}\n{err}");
    // Empty folders are kept with the file details (the default), so not listed.
    assert!(
        err.contains("WARNING: 3 path(s) in src are not packed"),
        "{err}"
    );
    for line in [
        "hidden file    .env",
        "hidden folder  .cache/",
        "broken link    dangling",
        "add --dotfiles to pack them",
    ] {
        assert!(err.contains(line), "missing {line:?} in:\n{err}");
    }
    assert!(!err.contains("empty folder"), "{err}");
    assert!(out.contains("(3 not packed: listed on stderr)"), "{out}");
    assert!(dir.join("t.sg1").is_file());
    // The JSON result carries the count.
    let o = sigil(&dir, &["inscribe", "src", "-o", "j.sg1", "--json"]);
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}\n{err}");
    assert!(out.contains("\"not_packed\":3"), "{out}");
    // Without file details an empty folder is left out again, and listed.
    let o = sigil(
        &dir,
        &["inscribe", "src", "-o", "n.sg1", "--no-file-details"],
    );
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}\n{err}");
    assert!(err.contains("empty folder   empty/"), "{err}");
    assert!(out.contains("(4 not packed: listed on stderr)"), "{out}");
    // With --dotfiles the dotfiles are packed and no longer listed.
    let o = sigil(&dir, &["inscribe", "src", "-o", "d.sg1", "--dotfiles"]);
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}\n{err}");
    assert!(err.contains("WARNING: 1 path(s)"), "{err}");
    assert!(
        !err.contains(".env") && !err.contains("--dotfiles"),
        "{err}"
    );
}

#[test]
fn fail_on_skip_refuses_and_writes_nothing() {
    let dir = common::scratch("tome-skips-fail");
    tree(&dir);
    let o = sigil(&dir, &["inscribe", "src", "-o", "t.sg1", "--fail-on-skip"]);
    let (out, err) = text(&o);
    assert_eq!(o.status.code(), Some(1), "{out}\n{err}");
    assert!(err.contains("Nothing was written"), "{err}");
    assert!(err.contains("hidden file    .env"), "{err}");
    assert!(!dir.join("t.sg1").exists());
    // Only for folders.
    let o = sigil(
        &dir,
        &["inscribe", "src/a.txt", "-o", "f.sg1", "--fail-on-skip"],
    );
    assert!(!o.status.success());
    assert!(!dir.join("f.sg1").exists());
}

#[test]
fn a_clean_folder_says_nothing_extra_and_passes_fail_on_skip() {
    let dir = common::scratch("tome-skips-clean");
    std::fs::create_dir_all(dir.join("src/sub")).unwrap();
    std::fs::write(dir.join("src/a.txt"), b"a").unwrap();
    std::fs::write(dir.join("src/sub/b.txt"), b"b").unwrap();
    let o = sigil(&dir, &["inscribe", "src", "-o", "t.sg1", "--fail-on-skip"]);
    let (out, err) = text(&o);
    assert!(o.status.success(), "{out}\n{err}");
    assert!(!err.contains("WARNING"), "{err}");
    assert!(!out.contains("not packed"), "{out}");
    assert!(dir.join("t.sg1").is_file());
}
