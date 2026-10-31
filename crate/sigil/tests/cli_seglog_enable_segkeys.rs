//! `sigil log enable-segment-keys LOG`: per-segment keys turned on for an existing log (`log=8`).
mod common;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn run(d: &Path, a: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(d)
        .env_remove("SIGIL_SOFT_AUTHENTICATOR")
        .args(a)
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
fn ok(d: &Path, a: &[&str]) -> String {
    let o = run(d, a);
    assert!(o.status.success(), "{a:?}: {}", text(&o));
    text(&o)
}
fn fails(d: &Path, a: &[&str]) -> String {
    let o = run(d, a);
    assert!(!o.status.success(), "expected failure {a:?}: {}", text(&o));
    text(&o)
}
fn pw(d: &Path, name: &str, v: &str) {
    fs::write(d.join(name), format!("{v}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
}
fn read(d: &Path, log: &str, seq: &str, extra: &[&str]) -> Output {
    let o = format!("out-{log}-{seq}");
    let mut a = vec!["log", "read", log, "--seq", seq, "-o", &o];
    a.extend_from_slice(extra);
    run(d, &a)
}
fn verify_code(d: &Path, a: &[&str]) -> i32 {
    run(d, a).status.code().unwrap_or(-1)
}

#[test]
fn public_log_gets_segment_keys_going_forward() {
    let d = common::scratch("enable-segkeys");
    pw(&d, "pw", "secret");
    ok(&d, &["log", "init", "ev"]);
    fs::write(d.join("a.txt"), "old clear batch\n").unwrap();
    ok(&d, &["log", "append", "ev", "a.txt"]);
    fails(&d, &["log", "enable-segment-keys", "ev", "--pass", "x"]);
    let out = ok(&d, &["log", "enable-segment-keys", "ev"]);
    assert!(out.contains("from seq 2"), "{out}");
    let m = fs::read_to_string(d.join("ev.sigil/CONTAINER")).unwrap();
    assert!(
        m.contains("log=8") && m.contains("segkeys=1") && m.contains("segkeys-from=2"),
        "{m}"
    );
    assert!(ok(&d, &["log", "enable-segment-keys", "ev"]).contains("already on"));
    // a new append needs a key to wrap its segment key
    fs::write(d.join("b.txt"), "new secret batch\n").unwrap();
    fails(&d, &["log", "append", "ev", "b.txt"]);
    ok(&d, &["log", "append", "ev", "b.txt", "--pass-file", "pw"]);
    assert!(d.join("ev.sigil/keys").is_dir());
    let seg2 = fs::read(d.join("ev.sigil/segments/0000/0000000002.sg1")).unwrap();
    assert!(!seg2.windows(10).any(|w| w == b"new secret"));
    // the old segment opens as before; the new one only with its key
    assert!(read(&d, "ev", "1", &[]).status.success());
    assert!(!read(&d, "ev", "2", &[]).status.success());
    pw(&d, "bad", "wrong");
    assert!(!read(&d, "ev", "2", &["--pass-file", "bad"])
        .status
        .success());
    assert!(read(&d, "ev", "2", &["--pass-file", "pw"]).status.success());
    assert_eq!(fs::read(d.join("out-ev-2")).unwrap(), b"new secret batch\n");
    assert_eq!(
        verify_code(&d, &["log", "verify", "ev", "--pass-file", "pw"]),
        0
    );
    assert_ne!(verify_code(&d, &["log", "verify", "ev"]), 2);
    // shred: only keyed segments have a key to destroy
    let e = fails(&d, &["log", "shred", "ev", "--seq", "1"]);
    assert!(e.contains("before segment keys"), "{e}");
    ok(&d, &["log", "shred", "ev", "--seq", "2"]);
    assert!(!read(&d, "ev", "2", &["--pass-file", "pw"]).status.success());
    assert_ne!(
        verify_code(&d, &["log", "verify", "ev", "--pass-file", "pw"]),
        2
    );
    // compaction re-seals the old clear batch under its own key
    fs::write(d.join("c.txt"), "third\n").unwrap();
    ok(&d, &["log", "append", "ev", "c.txt", "--pass-file", "pw"]);
    ok(
        &d,
        &[
            "log",
            "compact",
            "ev",
            "--apply",
            "--pass-file",
            "pw",
            "--seal-pass-file",
            "pw",
        ],
    );
    assert!(read(&d, "ev", "1", &["--pass-file", "pw"]).status.success());
    assert_eq!(fs::read(d.join("out-ev-1")).unwrap(), b"old clear batch\n");
    assert_eq!(
        verify_code(&d, &["log", "verify", "ev", "--pass-file", "pw"]),
        0
    );
}

#[test]
fn private_log_needs_its_index_key() {
    let d = common::scratch("enable-segkeys-priv");
    pw(&d, "pw", "secret");
    pw(&d, "bad", "wrong");
    ok(&d, &["log", "init", "pv", "--pass-file", "pw"]);
    fs::write(d.join("a.txt"), "first\n").unwrap();
    ok(&d, &["log", "append", "pv", "a.txt", "--pass-file", "pw"]);
    fails(&d, &["log", "enable-segment-keys", "pv"]);
    fails(
        &d,
        &["log", "enable-segment-keys", "pv", "--pass-file", "bad"],
    );
    let m = fs::read_to_string(d.join("pv.sigil/CONTAINER")).unwrap();
    assert!(!m.contains("segkeys"), "{m}");
    ok(
        &d,
        &["log", "enable-segment-keys", "pv", "--pass-file", "pw"],
    );
    fs::write(d.join("b.txt"), "second\n").unwrap();
    ok(&d, &["log", "append", "pv", "b.txt", "--pass-file", "pw"]);
    for (s, body) in [("1", "first\n"), ("2", "second\n")] {
        assert!(read(&d, "pv", s, &[]).status.code() != Some(0));
        assert!(read(&d, "pv", s, &["--pass-file", "pw"]).status.success());
        assert_eq!(
            fs::read_to_string(d.join(format!("out-pv-{s}"))).unwrap(),
            body
        );
    }
    assert_eq!(
        verify_code(&d, &["log", "verify", "pv", "--pass-file", "pw"]),
        0
    );
    assert_ne!(verify_code(&d, &["log", "verify", "pv"]), 2);
    assert!(ok(
        &d,
        &["log", "enable-segment-keys", "pv", "--pass-file", "pw"]
    )
    .contains("already on"));
}
