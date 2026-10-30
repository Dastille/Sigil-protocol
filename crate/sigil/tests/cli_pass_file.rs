//! CLI: `--pass-file PATH` gives scripts a passphrase without putting it on the command
//! line, and a literal `--pass VALUE` warns. Every claim in docs/START.md
//! "Passphrases in scripts" is checked here.
mod common;
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const WARN: &str = "WARNING: a passphrase given as --pass VALUE is visible";

fn sigil(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(args)
        .stdin(Stdio::null())
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

fn ok(dir: &Path, args: &[&str]) -> Output {
    let o = sigil(dir, args);
    assert!(o.status.success(), "{args:?}: {}", text(&o));
    o
}

fn fails(dir: &Path, args: &[&str]) -> String {
    let o = sigil(dir, args);
    assert!(!o.status.success(), "{args:?} should fail: {}", text(&o));
    text(&o)
}

fn tmp(tag: &str) -> common::Scratch {
    let d = common::scratch(&format!("passfile-{tag}"));
    d
}

/// A passphrase file only the owner can read (mode 600), as the docs tell people to make.
fn secret(path: &Path, body: &str) {
    std::fs::write(path, body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

fn data() -> Vec<u8> {
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    (0..50_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

#[test]
fn pass_file_round_trips_both_ways_with_pass() {
    let d = tmp("rt");
    let src = data();
    std::fs::write(d.join("a.bin"), &src).unwrap();
    // First line only; one trailing CRLF is stripped; later lines ignored.
    secret(&d.join("pw"), "correct horse\r\nnot this line\n");

    let o = ok(&d, &["seal", "--pass-file", "pw", "-o", "a.sg1", "a.bin"]);
    assert!(!text(&o).contains(WARN), "{}", text(&o));
    // Same passphrase typed as --pass opens it (so the file meant "correct horse").
    let o = ok(
        &d,
        &["unseal", "--pass", "correct horse", "-o", "b.bin", "a.sg1"],
    );
    assert!(text(&o).contains(WARN), "{}", text(&o));
    assert_eq!(std::fs::read(d.join("b.bin")).unwrap(), src);

    // And the other way: sealed with --pass, opened with --pass-file (no trailing newline).
    secret(&d.join("pw2"), "correct horse");
    ok(
        &d,
        &["seal", "--pass", "correct horse", "-o", "c.sg1", "a.bin"],
    );
    ok(
        &d,
        &["unseal", "--pass-file", "pw2", "-o", "c.bin", "c.sg1"],
    );
    assert_eq!(std::fs::read(d.join("c.bin")).unwrap(), src);
    // scry needs the key too and takes the file.
    ok(&d, &["scry", "--pass-file", "pw", "c.sg1"]);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn empty_missing_and_wrong_pass_files_fail_closed() {
    let d = tmp("bad");
    std::fs::write(d.join("a.bin"), data()).unwrap();
    secret(&d.join("empty"), "");
    secret(&d.join("blank"), "\n");
    for f in ["empty", "blank"] {
        let e = fails(&d, &["seal", "--pass-file", f, "-o", "x.sg1", "a.bin"]);
        assert!(e.contains("is empty"), "{e}");
        assert!(!d.join("x.sg1").exists());
    }
    let e = fails(&d, &["seal", "--pass-file", "nope", "-o", "x.sg1", "a.bin"]);
    assert!(e.contains("cannot read passphrase file"), "{e}");
    assert!(!d.join("x.sg1").exists());

    secret(&d.join("pw"), "right\n");
    secret(&d.join("wrong"), "wrong\n");
    ok(&d, &["seal", "--pass-file", "pw", "-o", "a.sg1", "a.bin"]);
    let e = fails(
        &d,
        &["unseal", "--pass-file", "wrong", "-o", "out", "a.sg1"],
    );
    assert!(!e.contains("right") && !e.contains("wrong\n"), "{e}");
    assert!(!d.join("out").exists());
    let e = fails(&d, &["unseal", "--pass-file", "nope", "-o", "out", "a.sg1"]);
    assert!(e.contains("cannot read passphrase file"), "{e}");
    assert!(!d.join("out").exists());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn pass_and_pass_file_together_are_rejected() {
    let d = tmp("both");
    std::fs::write(d.join("a.bin"), b"x").unwrap();
    secret(&d.join("pw"), "pw\n");
    let e = fails(
        &d,
        &[
            "seal",
            "--pass",
            "pw",
            "--pass-file",
            "pw",
            "-o",
            "a.sg1",
            "a.bin",
        ],
    );
    assert!(e.contains("cannot be used with"), "{e}");
    assert!(!d.join("a.sg1").exists());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn literal_pass_warns_but_still_works() {
    let d = tmp("warn");
    std::fs::write(d.join("a.bin"), b"hello").unwrap();
    let o = ok(&d, &["seal", "--pass", "pw", "-o", "a.sg1", "a.bin"]);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(err.contains(WARN), "{err}");
    assert!(
        err.contains("--pass-file PATH") && err.contains("--pass -"),
        "{err}"
    );
    assert!(
        !err.contains(" pw "),
        "the warning must not repeat the passphrase: {err}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[cfg(unix)]
#[test]
fn pass_file_readable_by_others_is_refused() {
    use std::os::unix::fs::PermissionsExt;
    let d = tmp("mode");
    std::fs::write(d.join("a.bin"), b"hello").unwrap();
    for mode in [0o644, 0o640, 0o604, 0o620] {
        std::fs::write(d.join("pw"), "pw\n").unwrap();
        std::fs::set_permissions(d.join("pw"), std::fs::Permissions::from_mode(mode)).unwrap();
        let e = fails(&d, &["seal", "--pass-file", "pw", "-o", "a.sg1", "a.bin"]);
        assert!(e.contains("chmod 600"), "{mode:o}: {e}");
        assert!(!d.join("a.sg1").exists());
    }
    // The same rule covers the OpenPGP --passphrase-file.
    let locked = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/tests/fixtures/pgp/locked-sec.asc"
    );
    let e = fails(
        &d,
        &[
            "import-pgp",
            locked,
            "-o",
            "me.sgk",
            "--passphrase-file",
            "pw",
        ],
    );
    assert!(e.contains("chmod 600"), "{e}");
    let _ = std::fs::remove_dir_all(&d);
}

#[cfg(target_os = "linux")]
#[test]
fn pass_file_from_a_pipe() {
    // `--pass-file /dev/stdin` (or `<(pass show …)`): a pipe, never on disk.
    let d = tmp("pipe");
    let src = data();
    std::fs::write(d.join("a.bin"), &src).unwrap();
    let mut c = Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(&d)
        .args(["seal", "--pass-file", "/dev/stdin", "-o", "a.sg1", "a.bin"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .unwrap();
    c.stdin.take().unwrap().write_all(b"piped pw\n").unwrap();
    let o = c.wait_with_output().unwrap();
    assert!(o.status.success(), "{}", text(&o));
    secret(&d.join("pw"), "piped pw\n");
    ok(&d, &["unseal", "--pass-file", "pw", "-o", "b.bin", "a.sg1"]);
    assert_eq!(std::fs::read(d.join("b.bin")).unwrap(), src);
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn tampered_files_still_fail_closed_with_pass_file() {
    let d = tmp("tamper");
    let src = data();
    std::fs::write(d.join("a.bin"), &src).unwrap();
    secret(&d.join("pw"), "pw\n");
    for mode in ["glyph", "reflection", "seal"] {
        let sg = format!("{mode}.sg1");
        ok(
            &d,
            &[
                "seal",
                "--mode",
                mode,
                "--pass-file",
                "pw",
                "-o",
                &sg,
                "a.bin",
            ],
        );
        let good = std::fs::read(d.join(&sg)).unwrap();
        let mut flip = good.clone();
        let mid = flip.len() / 2;
        flip[mid] ^= 0x01;
        std::fs::write(d.join("flip.sg1"), &flip).unwrap();
        std::fs::write(d.join("trunc.sg1"), &good[..good.len() / 2]).unwrap();
        for bad in ["flip.sg1", "trunc.sg1"] {
            let out = d.join("out.bin");
            let _ = std::fs::remove_file(&out);
            let o = sigil(&d, &["unseal", "--pass-file", "pw", "-o", "out.bin", bad]);
            if o.status.success() {
                // Self-repair (reflection/seal parity) may fix one flipped bit: then the
                // bytes must be exactly the original, never something else.
                assert_eq!(std::fs::read(&out).unwrap(), src, "{mode} {bad}");
                assert_ne!(bad, "trunc.sg1", "{mode}: half a file cannot open");
            } else {
                assert!(!out.exists(), "{mode} {bad}: no partial output");
            }
        }
        // glyph has no parity: a flipped bit must be refused.
        if mode == "glyph" {
            let o = sigil(
                &d,
                &["unseal", "--pass-file", "pw", "-o", "g.bin", "flip.sg1"],
            );
            assert!(!o.status.success(), "{}", text(&o));
        }
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn log_init_and_add_take_pass_file() {
    let d = tmp("log");
    std::fs::create_dir_all(d.join("src")).unwrap();
    std::fs::write(d.join("src/a.txt"), "first").unwrap();
    secret(&d.join("pw"), "log pw\n");
    secret(&d.join("bad"), "not it\n");
    let o = ok(&d, &["log", "init", "ev", "--pass-file", "pw"]);
    assert!(!text(&o).contains(WARN));
    ok(&d, &["log", "add", "ev", "src", "--pass-file", "pw"]);
    ok(&d, &["log", "ls", "ev", "--pass-file", "pw"]);
    let e = fails(&d, &["log", "ls", "ev", "--pass-file", "bad"]);
    assert!(e.contains("does not open"), "{e}");
    let _ = std::fs::remove_dir_all(&d);
}

/// Every subcommand (at any depth) whose help lists `--pass` also lists `--pass-file`.
#[test]
fn every_command_with_pass_offers_pass_file() {
    fn help(path: &[String]) -> String {
        let mut args: Vec<&str> = path.iter().map(String::as_str).collect();
        args.push("--help");
        let o = Command::new(env!("CARGO_BIN_EXE_sigil"))
            .args(&args)
            .output()
            .expect("run sigil");
        String::from_utf8_lossy(&o.stdout).into_owned()
    }
    fn walk(path: Vec<String>, seen: &mut usize) {
        let h = help(&path);
        if h.contains("--pass <") {
            *seen += 1;
            assert!(
                h.contains("--pass-file <PATH>"),
                "{path:?} has --pass but no --pass-file"
            );
        }
        if h.contains("--seal-pass <") {
            assert!(h.contains("--seal-pass-file <PATH>"), "{path:?}");
        }
        let Some(i) = h.find("Commands:") else { return };
        for line in h[i..].lines().skip(1) {
            if !line.starts_with("  ") {
                break;
            }
            let name = line.split_whitespace().next().unwrap_or("");
            if name.is_empty() || name == "help" {
                continue;
            }
            let mut next = path.clone();
            next.push(name.to_string());
            walk(next, seen);
        }
    }
    let mut seen = 0;
    walk(Vec::new(), &mut seen);
    assert!(seen >= 25, "found only {seen} commands with --pass");
}
