//! Private INDEX: tombstone / shred `--reason` sealed under the index key (`log=6`).
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
fn manifest_has(d: &Path, log: &str, kv: &str) -> bool {
    fs::read_to_string(d.join(format!("{log}.sigil/CONTAINER")))
        .unwrap()
        .lines()
        .any(|l| l.trim() == kv)
}

const SECRET: &str = "court order 2026-117 Smith";

#[test]
fn tombstone_reason_sealed_in_private_log() {
    let d = common::scratch("sealed-reason");
    pw(&d, "pw", "secret");
    pw(&d, "bad", "wrong");
    ok(&d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    ok(
        &d,
        &["log", "init", "ev", "--pass-file", "pw", "--to", "me.pub"],
    );
    for (i, b) in ["one\n", "two\n", "three\n"].iter().enumerate() {
        fs::write(d.join("b.txt"), b).unwrap();
        ok(&d, &["log", "append", "ev", "b.txt", "--pass-file", "pw"]);
        let _ = i;
    }
    let before = fs::read_to_string(d.join("ev.sigil/CONTAINER")).unwrap();
    // no key / wrong key: refused, nothing written, format unchanged
    assert!(fails(
        &d,
        &["log", "tombstone", "ev", "--seq", "1", "--reason", SECRET]
    )
    .contains("seals --reason"));
    assert!(!run(
        &d,
        &[
            "log",
            "tombstone",
            "ev",
            "--seq",
            "1",
            "--reason",
            SECRET,
            "--pass-file",
            "bad"
        ]
    )
    .status
    .success());
    assert_eq!(
        fs::read_to_string(d.join("ev.sigil/CONTAINER")).unwrap(),
        before
    );
    assert_eq!(
        ok(&d, &["log", "ls", "ev", "--pass-file", "pw"])
            .matches("tombstone")
            .count(),
        0
    );

    ok(
        &d,
        &[
            "log",
            "tombstone",
            "ev",
            "--seq",
            "1",
            "--reason",
            SECRET,
            "--pass-file",
            "pw",
        ],
    );
    ok(
        &d,
        &[
            "log",
            "tombstone",
            "ev",
            "--seq",
            "2",
            "--reason",
            "dup",
            "--unlock",
            "me.sgk",
        ],
    );
    assert!(
        manifest_has(&d, "ev", "log=6"),
        "{}",
        fs::read_to_string(d.join("ev.sigil/CONTAINER")).unwrap()
    );
    // no leak on disk or without the key
    let idx = fs::read_to_string(d.join("ev.sigil/INDEX")).unwrap();
    assert!(
        !idx.contains("reason=") && !idx.contains("court") && !idx.contains("court%20order"),
        "{idx}"
    );
    let plain = ok(&d, &["log", "ls", "ev"]);
    assert!(
        !plain.contains("court") && plain.contains("reason: sealed"),
        "{plain}"
    );
    // with the key: as today
    let full = ok(&d, &["log", "ls", "ev", "--pass-file", "pw"]);
    assert!(full.contains(SECRET) && full.contains("\"dup\""), "{full}");
    let full2 = ok(&d, &["log", "ls", "ev", "--identity", "me.sgk"]);
    assert!(full2.contains(SECRET), "{full2}");
    let e = fails(
        &d,
        &[
            "log",
            "read",
            "ev",
            "--seq",
            "1",
            "--pass-file",
            "pw",
            "-o",
            "x",
        ],
    );
    assert!(e.contains(SECRET), "{e}");
    // keyless checks still fine; no reason: no key needed
    assert_ne!(run(&d, &["log", "verify", "ev"]).status.code(), Some(2));
    ok(&d, &["log", "tombstone", "ev", "--seq", "3"]);
    // a box moved onto another tombstone line breaks the chain / the box
    let lines: Vec<&str> = idx.lines().collect();
    let tl: Vec<&str> = lines
        .iter()
        .copied()
        .filter(|l| l.contains("op=tomb"))
        .collect();
    let b0 = tl[0]
        .split(" box=")
        .nth(1)
        .unwrap()
        .split(' ')
        .next()
        .unwrap();
    let b1 = tl[1]
        .split(" box=")
        .nth(1)
        .unwrap()
        .split(' ')
        .next()
        .unwrap();
    fs::write(d.join("ev.sigil/INDEX"), idx.replacen(b1, b0, 1)).unwrap();
    assert_eq!(run(&d, &["log", "verify", "ev"]).status.code(), Some(2));
}

#[test]
fn public_log_reason_unchanged_and_no_bump() {
    let d = common::scratch("sealed-reason-pub");
    ok(&d, &["log", "init", "ev"]);
    fs::write(d.join("b.txt"), "x\n").unwrap();
    ok(&d, &["log", "append", "ev", "b.txt"]);
    ok(
        &d,
        &["log", "tombstone", "ev", "--seq", "1", "--reason", "gdpr"],
    );
    assert!(fs::read_to_string(d.join("ev.sigil/INDEX"))
        .unwrap()
        .contains("reason=gdpr"));
    assert!(!manifest_has(&d, "ev", "log=6"));
}

#[test]
fn shred_reason_sealed() {
    let d = common::scratch("sealed-reason-shred");
    pw(&d, "pw", "secret");
    ok(
        &d,
        &["log", "init", "ev", "--segment-keys", "--pass-file", "pw"],
    );
    fs::write(d.join("b.txt"), "x\n").unwrap();
    ok(&d, &["log", "append", "ev", "b.txt", "--pass-file", "pw"]);
    ok(
        &d,
        &[
            "log",
            "shred",
            "ev",
            "--seq",
            "1",
            "--reason",
            SECRET,
            "--pass-file",
            "pw",
        ],
    );
    assert!(!fs::read_to_string(d.join("ev.sigil/INDEX"))
        .unwrap()
        .contains("court"));
    assert!(!ok(&d, &["log", "ls", "ev"]).contains("court"));
    assert!(ok(&d, &["log", "ls", "ev", "--pass-file", "pw"]).contains(SECRET));
}
