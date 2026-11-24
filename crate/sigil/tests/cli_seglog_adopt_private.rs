//! `sigil log adopt` into a private-INDEX log: needs the key; sizes and hashes land sealed.
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
fn pw(d: &Path, name: &str, v: &str) {
    fs::write(d.join(name), format!("{v}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
}
fn sha_hex(b: &[u8]) -> String {
    use sha2::{Digest, Sha256};
    Sha256::digest(b)
        .iter()
        .map(|x| format!("{x:02x}"))
        .collect()
}

#[test]
fn adopt_into_private_log() {
    let d = common::scratch("adopt-priv");
    pw(&d, "pw", "secret");
    pw(&d, "other", "nope");
    fs::create_dir_all(d.join("pile")).unwrap();
    let a = b"day one export\n".to_vec();
    let b = b"day two export, plain star\n".to_vec();
    fs::write(d.join("a.txt"), &a).unwrap();
    fs::write(d.join("b.txt"), &b).unwrap();
    ok(
        &d,
        &["seal", "a.txt", "-o", "pile/day-1.sg1", "--pass-file", "pw"],
    );
    ok(&d, &["seal", "b.txt", "-o", "pile/day-2.sg1"]);
    ok(&d, &["log", "init", "ev", "--pass-file", "pw"]);
    let star1 = fs::read(d.join("pile/day-1.sg1")).unwrap();
    let idx0 = fs::read(d.join("ev.sigil/INDEX")).unwrap();

    // without the key: refused before anything is read or printed
    let o = run(&d, &["log", "adopt", "ev", "pile", "--keep"]);
    assert!(
        !o.status.success() && text(&o).contains("private"),
        "{}",
        text(&o)
    );
    assert!(
        !text(&o).contains("day-1") && !text(&o).contains("bytes"),
        "{}",
        text(&o)
    );
    assert!(!run(
        &d,
        &[
            "log",
            "adopt",
            "ev",
            "pile",
            "--keep",
            "--pass-file",
            "other"
        ]
    )
    .status
    .success());
    assert_eq!(fs::read(d.join("ev.sigil/INDEX")).unwrap(), idx0);

    let o = ok(
        &d,
        &[
            "log",
            "adopt",
            "ev",
            "pile",
            "--keep",
            "--pass-file",
            "pw",
            "--dry-run",
        ],
    );
    assert!(o.contains("would adopt 2"), "{o}");
    assert_eq!(fs::read(d.join("ev.sigil/INDEX")).unwrap(), idx0);
    let o = ok(&d, &["log", "adopt", "ev", "pile", "--pass-file", "pw"]);
    assert!(
        o.contains("adopted 2") && o.contains("re-sealed") && o.contains("removed 2"),
        "{o}"
    );
    // the encrypted v3 star is kept byte-for-byte
    assert_eq!(
        fs::read(d.join("ev.sigil/segments/0000/0000000001.sg1")).unwrap(),
        star1
    );
    // INDEX shows no plain size / hash / src
    let idx = fs::read_to_string(d.join("ev.sigil/INDEX")).unwrap();
    assert!(
        !idx.contains(&sha_hex(&a)) && !idx.contains(&sha_hex(&b)) && !idx.contains("src="),
        "{idx}"
    );
    assert!(!ok(&d, &["log", "ls", "ev"]).contains(&sha_hex(&b)[..16]));
    ok(
        &d,
        &[
            "log",
            "read",
            "ev",
            "--seq",
            "1",
            "-o",
            "o1",
            "--pass-file",
            "pw",
        ],
    );
    ok(
        &d,
        &[
            "log",
            "read",
            "ev",
            "--seq",
            "2",
            "-o",
            "o2",
            "--pass-file",
            "pw",
        ],
    );
    assert_eq!(fs::read(d.join("o1")).unwrap(), a);
    assert_eq!(fs::read(d.join("o2")).unwrap(), b);
    assert_ne!(
        run(&d, &["log", "verify", "ev", "--pass-file", "pw"])
            .status
            .code(),
        Some(2)
    );
    // re-seal never stores the plain star: segment 2 is encrypted
    assert!(!fs::read(d.join("ev.sigil/segments/0000/0000000002.sg1"))
        .unwrap()
        .windows(b.len())
        .any(|w| w == &b[..]));

    // idempotent: the same stars again are "already"
    ok(
        &d,
        &["seal", "a.txt", "-o", "again-a.sg1", "--pass-file", "pw"],
    );
    ok(&d, &["seal", "b.txt", "-o", "again-b.sg1"]);
    let o = ok(
        &d,
        &[
            "log",
            "adopt",
            "ev",
            "again-b.sg1",
            "--keep",
            "--pass-file",
            "pw",
        ],
    );
    assert!(o.contains("already segment 2"), "{o}");
    // a star that does not open with the key: left in place, exit 1, no name in the INDEX
    ok(
        &d,
        &["seal", "a.txt", "-o", "foreign.sg1", "--pass-file", "other"],
    );
    let o = run(
        &d,
        &["log", "adopt", "ev", "foreign.sg1", "--pass-file", "pw"],
    );
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(text(&o).contains("does not open") && d.join("foreign.sg1").exists());
}

#[test]
fn public_adopt_unchanged() {
    let d = common::scratch("adopt-pub");
    fs::write(d.join("a.txt"), "x\n").unwrap();
    ok(&d, &["seal", "a.txt", "-o", "s.sg1"]);
    ok(&d, &["log", "init", "ev"]);
    let o = ok(&d, &["log", "adopt", "ev", "s.sg1"]);
    assert!(o.contains("adopted 1"), "{o}");
    assert!(fs::read_to_string(d.join("ev.sigil/INDEX"))
        .unwrap()
        .contains("src="));
}
