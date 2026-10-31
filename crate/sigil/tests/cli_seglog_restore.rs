//! `sigil log restore LOG PATH`: a file or a folder back by the path `log add` recorded.
mod common;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

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

fn ok(dir: &Path, args: &[&str]) -> String {
    let o = sigil_cmd(dir, args);
    assert!(o.status.success(), "{args:?}: {}", text(&o));
    text(&o)
}

/// Fails with exit code 2 (check-proof's "does not verify") or 1 (usage / refusal).
fn fails(dir: &Path, args: &[&str]) -> String {
    let o = sigil_cmd(dir, args);
    assert!(
        !o.status.success(),
        "expected failure {args:?}: {}",
        text(&o)
    );
    text(&o)
}

fn tmp(tag: &str) -> common::Scratch {
    common::scratch(&format!("log-restore-{tag}"))
}

fn put(d: &Path, rel: &str, body: &[u8]) {
    let p = d.join("photos").join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, body).unwrap();
}

#[test]
fn file_and_folder_restore_byte_exact_latest_version() {
    let d = tmp("plain");
    ok(&d, &["log", "init", "ev"]);
    let bin: Vec<u8> = (0..=255u8).cycle().take(5000).collect();
    put(&d, "2024/trip/beach.jpg", &bin);
    put(&d, "2024/notes.txt", b"v1\n");
    put(&d, "top.txt", b"top\n");
    ok(&d, &["log", "add", "ev", "photos"]);
    put(&d, "2024/notes.txt", b"version two\n");
    ok(&d, &["log", "add", "ev", "photos"]);
    fs::remove_dir_all(d.join("photos")).unwrap();

    let o = ok(
        &d,
        &["log", "restore", "ev", "2024/notes.txt", "-o", "n.txt"],
    );
    assert!(o.contains("1 file(s)"), "{o}");
    assert_eq!(fs::read(d.join("n.txt")).unwrap(), b"version two\n");
    // default output name; refuses to overwrite
    ok(&d, &["log", "restore", "ev", "top.txt"]);
    assert_eq!(fs::read(d.join("top.txt")).unwrap(), b"top\n");
    assert!(fails(&d, &["log", "restore", "ev", "top.txt"]).contains("never overwrites"));

    ok(&d, &["log", "restore", "ev", "2024", "-o", "back"]);
    assert_eq!(fs::read(d.join("back/trip/beach.jpg")).unwrap(), bin);
    assert_eq!(
        fs::read(d.join("back/notes.txt")).unwrap(),
        b"version two\n"
    );
    assert!(!d.join("back/top.txt").exists());
    ok(&d, &["log", "restore", "ev", ".", "-o", "all"]);
    assert_eq!(fs::read(d.join("all/2024/trip/beach.jpg")).unwrap(), bin);
    assert_eq!(fs::read(d.join("all/top.txt")).unwrap(), b"top\n");
    assert!(fails(&d, &["log", "restore", "ev", "."]).contains("-o"));

    // missing paths; a name prefix is not a folder
    assert!(
        fails(&d, &["log", "restore", "ev", "nope.txt", "-o", "x"]).contains("no file or folder")
    );
    assert!(fails(&d, &["log", "restore", "ev", "20", "-o", "x"]).contains("no file or folder"));
    assert!(!d.join("x").exists());
}

#[test]
fn deleted_and_corrupt_fail_closed() {
    let d = tmp("tomb");
    ok(&d, &["log", "init", "ev"]);
    put(&d, "a/one.txt", b"one\n");
    put(&d, "a/two.txt", b"two\n");
    ok(&d, &["log", "add", "ev", "photos"]);
    ok(&d, &["log", "tombstone", "ev", "--seq", "1"]);
    let e = fails(&d, &["log", "restore", "ev", "a/one.txt", "-o", "o"]);
    assert!(e.contains("deleted"), "{e}");
    assert!(!d.join("o").exists());
    let o = ok(&d, &["log", "restore", "ev", "a", "-o", "fa"]);
    assert!(o.contains("deleted") && o.contains("1 deleted path"), "{o}");
    assert!(!d.join("fa/one.txt").exists());
    assert_eq!(fs::read(d.join("fa/two.txt")).unwrap(), b"two\n");

    // a corrupted segment beyond repair: nothing written
    let seg = d.join("ev.sigil/segments/0000/0000000002.sg1");
    fs::write(&seg, b"garbage").unwrap();
    let e = fails(&d, &["log", "restore", "ev", "a", "-o", "fb"]);
    assert!(!e.is_empty());
    assert!(!d.join("fb").exists());
    let leftovers: Vec<_> = fs::read_dir(&*d)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains("sigil-restore"))
        .collect();
    assert!(leftovers.is_empty());
}

#[test]
fn shredded_and_private_need_keys() {
    let d = tmp("keys");
    ok(&d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    put(&d, "a.jpg", b"one\n");
    put(&d, "b.jpg", b"two\n");
    ok(&d, &["log", "init", "ev", "--segment-keys"]);
    ok(&d, &["log", "add", "ev", "photos", "--to", "me.pub"]);
    assert!(!fails(&d, &["log", "restore", "ev", "b.jpg", "-o", "nb"]).is_empty());
    assert!(!d.join("nb").exists());
    ok(
        &d,
        &[
            "log",
            "restore",
            "ev",
            "b.jpg",
            "-o",
            "kb",
            "--identity",
            "me.sgk",
        ],
    );
    assert_eq!(fs::read(d.join("kb")).unwrap(), b"two\n");
    ok(&d, &["log", "shred", "ev", "--seq", "1"]);
    let e = fails(
        &d,
        &[
            "log",
            "restore",
            "ev",
            "a.jpg",
            "-o",
            "ka",
            "--identity",
            "me.sgk",
        ],
    );
    assert!(e.contains("deleted"), "{e}");

    // private INDEX: paths are sealed; without the pass nothing is found
    let p = tmp("private");
    put(&p, "x/secret.txt", b"s3cret\n");
    ok(&p, &["log", "init", "ev", "--pass", "pw"]);
    ok(&p, &["log", "add", "ev", "photos", "--pass", "pw"]);
    let e = fails(&p, &["log", "restore", "ev", "x", "-o", "o"]);
    assert!(!e.contains("secret.txt"), "{e}");
    ok(
        &p,
        &["log", "restore", "ev", "x", "-o", "o", "--pass", "pw"],
    );
    assert_eq!(fs::read(p.join("o/secret.txt")).unwrap(), b"s3cret\n");
}
