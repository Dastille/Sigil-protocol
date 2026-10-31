//! A log created with --pass / --to gets a private INDEX by default (`log=5`);
//! `--public-index` opts out with a warning; a log created with no key stays public.
//! Old logs (public and --private-index) keep opening exactly as before.
mod common;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn sigil_cmd(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .env_remove("SIGIL_SOFT_AUTHENTICATOR")
        .args(common::pass_via_file(args))
        .output()
        .expect("run sigil")
}

fn ok(dir: &Path, args: &[&str]) -> (String, String) {
    let o = sigil_cmd(dir, args);
    let (out, err) = (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    );
    assert!(o.status.success(), "{args:?}: {out}{err}");
    (out, err)
}

fn fails(dir: &Path, args: &[&str]) -> String {
    let o = sigil_cmd(dir, args);
    assert!(!o.status.success(), "expected failure {args:?}");
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn tmp(tag: &str) -> common::Scratch {
    let d = common::scratch(&format!("log-privdef-{tag}"));
    fs::create_dir_all(d.join("photos/2024")).unwrap();
    fs::write(d.join("photos/2024/holiday-beach.jpg"), "beach day").unwrap();
    d
}

fn manifest(d: &Path, log: &str) -> String {
    fs::read_to_string(d.join(format!("{log}.sigil/CONTAINER"))).unwrap()
}

fn index(d: &Path, log: &str) -> String {
    fs::read_to_string(d.join(format!("{log}.sigil/INDEX"))).unwrap()
}

#[test]
fn keyed_log_is_private_by_default_and_round_trips() {
    let d = tmp("pass");
    let (out, _) = ok(&d, &["log", "init", "ev", "--pass", "pw"]);
    assert!(out.contains("private INDEX"), "{out}");
    let m = manifest(&d, "ev");
    assert!(m.contains("log=5") && m.contains("privindex=1"), "{m}");
    ok(&d, &["log", "add", "ev", "photos", "--pass", "pw"]);
    let idx = index(&d, "ev");
    assert!(!idx.contains("holiday-beach"), "name leaked: {idx}");
    assert!(!idx.contains("size=9 "), "size leaked: {idx}");
    let (ls, _) = ok(&d, &["log", "ls", "ev"]);
    assert!(ls.contains("sealed") && !ls.contains("holiday"), "{ls}");
    let (ls, _) = ok(&d, &["log", "ls", "ev", "--pass", "pw"]);
    assert!(ls.contains("2024/holiday-beach.jpg"), "{ls}");
    let (r, _) = ok(
        &d,
        &[
            "log", "read", "ev", "--seq", "1", "--pass", "pw", "-o", "back.jpg",
        ],
    );
    let _ = r;
    assert_eq!(fs::read(d.join("back.jpg")).unwrap(), b"beach day");
    ok(&d, &["log", "verify", "ev"]);

    // Wrong key and tamper fail closed.
    assert!(fails(&d, &["log", "ls", "ev", "--pass", "nope"]).contains("does not open"));
    let good = index(&d, "ev");
    let at = good.find(" box=").unwrap() + 30;
    let mut b = good.clone().into_bytes();
    b[at] = if b[at] == b'a' { b'b' } else { b'a' };
    fs::write(d.join("ev.sigil/INDEX"), &b).unwrap();
    let o = sigil_cmd(&d, &["log", "verify", "ev", "--pass", "pw"]);
    assert!(!o.status.success(), "flipped box must fail verify");
    fs::write(d.join("ev.sigil/INDEX"), &good[..good.len() - 10]).unwrap();
    let o = sigil_cmd(&d, &["log", "verify", "ev", "--pass", "pw"]);
    assert!(!o.status.success(), "truncated INDEX must fail verify");
    fs::write(d.join("ev.sigil/INDEX"), &good).unwrap();
    ok(&d, &["log", "verify", "ev", "--pass", "pw"]);
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn encrypt_to_log_is_private_by_default() {
    let d = tmp("to");
    ok(&d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    ok(
        &d,
        &[
            "log",
            "init",
            "ev",
            "--identity",
            "me.sgk",
            "--to",
            "me.pub",
        ],
    );
    assert!(manifest(&d, "ev").contains("privindex=1"));
    ok(
        &d,
        &[
            "log",
            "add",
            "ev",
            "photos",
            "--to",
            "me.pub",
            "--identity",
            "me.sgk",
        ],
    );
    assert!(!index(&d, "ev").contains("holiday-beach"));
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn public_index_opts_out_with_a_warning() {
    let d = tmp("public");
    let (_, err) = ok(&d, &["log", "init", "ev", "--pass", "pw", "--public-index"]);
    assert!(err.contains("WARNING: --public-index"), "{err}");
    assert!(err.contains("not used by a public INDEX"), "{err}");
    let m = manifest(&d, "ev");
    assert!(!m.contains("privindex"), "{m}");
    ok(&d, &["log", "add", "ev", "photos", "--pass", "pw"]);
    assert!(index(&d, "ev").contains("holiday-beach"));
    // Without a key: same warning, no key note.
    let (_, err) = ok(&d, &["log", "init", "ev2", "--public-index"]);
    assert!(err.contains("WARNING: --public-index"), "{err}");
    assert!(!err.contains("not used"), "{err}");
    // Both flags: refused before anything is written.
    fails(
        &d,
        &[
            "log",
            "init",
            "ev3",
            "--pass",
            "pw",
            "--private-index",
            "--public-index",
        ],
    );
    assert!(!d.join("ev3.sigil").exists());
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn keyless_log_stays_public_and_says_so() {
    let d = tmp("keyless");
    let (out, _) = ok(&d, &["log", "init", "ev"]);
    assert!(out.contains("public INDEX"), "{out}");
    assert!(!manifest(&d, "ev").contains("privindex"));
    ok(&d, &["log", "add", "ev", "photos"]);
    let (ls, _) = ok(&d, &["log", "ls", "ev"]);
    assert!(ls.contains("2024/holiday-beach.jpg"), "{ls}");
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn explicit_private_index_flag_still_works() {
    let d = tmp("explicit");
    ok(
        &d,
        &["log", "init", "ev", "--private-index", "--pass", "pw"],
    );
    let m = manifest(&d, "ev");
    assert!(m.contains("log=5") && m.contains("privindex=1"), "{m}");
    let _ = fs::remove_dir_all(&d);
}
