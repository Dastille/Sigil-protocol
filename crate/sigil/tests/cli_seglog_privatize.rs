//! `sigil log privatize SRC DEST`: a public-INDEX log copied into a new private-INDEX log.
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
fn put(d: &Path, rel: &str, body: &str) {
    let p = d.join("photos").join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, body).unwrap();
}
fn pw(d: &Path, name: &str, v: &str) {
    fs::write(d.join(name), format!("{v}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
}
fn no_tmp(d: &Path) {
    let left: Vec<_> = fs::read_dir(d)
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().contains("privatize-"))
        .collect();
    assert!(left.is_empty(), "temp left: {left:?}");
}

#[test]
fn public_signed_log_to_private_copy() {
    let d = common::scratch("privatize");
    pw(&d, "pw", "secret");
    ok(&d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    ok(&d, &["keygen", "-o", "eve.sgk", "--pub-out", "eve.pub"]);
    ok(&d, &["log", "init", "ev", "--identity", "me.sgk"]);
    put(&d, "2024/beach-holiday.jpg", "beach\n");
    put(&d, "taxes.pdf", "taxes\n");
    put(&d, "old.txt", "old\n");
    ok(&d, &["log", "add", "ev", "photos", "--identity", "me.sgk"]);
    fs::write(d.join("raw.txt"), "raw\n").unwrap();
    ok(
        &d,
        &["log", "append", "ev", "raw.txt", "--identity", "me.sgk"],
    );
    let ls = ok(&d, &["log", "ls", "ev"]);
    let old_seq = ls
        .lines()
        .find(|l| l.contains("old.txt"))
        .unwrap()
        .split_whitespace()
        .next()
        .unwrap()
        .to_string();
    ok(
        &d,
        &[
            "log",
            "tombstone",
            "ev",
            "--seq",
            &old_seq,
            "--identity",
            "me.sgk",
        ],
    );
    ok(
        &d,
        &[
            "log",
            "prove",
            "ev",
            "--path",
            "taxes.pdf",
            "-o",
            "old.proof",
        ],
    );
    let index_before = fs::read(d.join("ev.sigil/INDEX")).unwrap();

    // refusals first: nothing left behind
    assert!(
        fails(&d, &["log", "privatize", "ev", "pv", "--sign", "me.sgk"])
            .contains("--pass-file and/or --to")
    );
    assert!(fails(&d, &["log", "privatize", "ev", "pv", "--pass-file", "pw"]).contains("--sign"));
    assert!(fails(
        &d,
        &[
            "log",
            "privatize",
            "ev",
            "pv",
            "--pass-file",
            "pw",
            "--sign",
            "eve.sgk"
        ]
    )
    .contains("signed by"));
    assert!(!d.join("pv.sigil").exists());
    no_tmp(&d);

    let o = ok(
        &d,
        &[
            "log",
            "privatize",
            "ev",
            "pv",
            "--pass-file",
            "pw",
            "--sign",
            "me.sgk",
        ],
    );
    assert!(
        o.contains("3 entries copied") && o.contains("2 skipped"),
        "{o}"
    );
    no_tmp(&d);
    // source untouched; its old receipt still checks
    assert_eq!(fs::read(d.join("ev.sigil/INDEX")).unwrap(), index_before);
    ok(
        &d,
        &[
            "log",
            "check-proof",
            "old.proof",
            "--signer",
            "me.pub",
            "--path",
            "taxes.pdf",
        ],
    );
    // DEST hides names without the key
    let idx = fs::read_to_string(d.join("pv.sigil/INDEX")).unwrap();
    assert!(
        !idx.contains("path=") && !idx.contains(&hex_of("taxes.pdf")),
        "{idx}"
    );
    let plain = ok(&d, &["log", "ls", "pv"]);
    assert!(
        !plain.contains("taxes") && !plain.contains("beach"),
        "{plain}"
    );
    let full = ok(&d, &["log", "ls", "pv", "--pass-file", "pw"]);
    assert!(
        full.contains("taxes.pdf")
            && full.contains("2024/beach-holiday.jpg")
            && !full.contains("old.txt"),
        "{full}"
    );
    // times kept
    let t = |s: &str, name: &str| {
        s.lines()
            .find(|l| l.contains(name))
            .and_then(|l| l.split_whitespace().nth(1))
            .unwrap()
            .to_string()
    };
    assert_eq!(t(&ls, "taxes.pdf"), t(&full, "taxes.pdf"));
    ok(&d, &["log", "verify", "pv", "--signer", "me.pub"]);
    ok(
        &d,
        &[
            "log",
            "restore",
            "pv",
            "taxes.pdf",
            "-o",
            "t.out",
            "--pass-file",
            "pw",
        ],
    );
    assert_eq!(fs::read_to_string(d.join("t.out")).unwrap(), "taxes\n");
    ok(
        &d,
        &[
            "log",
            "prove",
            "pv",
            "--path",
            "taxes.pdf",
            "--pass-file",
            "pw",
            "-o",
            "new.proof",
        ],
    );
    ok(
        &d,
        &[
            "log",
            "check-proof",
            "new.proof",
            "--signer",
            "me.pub",
            "--path",
            "taxes.pdf",
        ],
    );
    // wrong key on DEST: refused
    pw(&d, "bad", "nope");
    assert!(!run(&d, &["log", "ls", "pv", "--pass-file", "bad"])
        .status
        .success());

    // DEST exists; already private
    assert!(fails(
        &d,
        &[
            "log",
            "privatize",
            "ev",
            "pv",
            "--pass-file",
            "pw",
            "--sign",
            "me.sgk"
        ]
    )
    .contains("already exists"));
    assert!(fails(
        &d,
        &[
            "log",
            "privatize",
            "pv",
            "pv2",
            "--pass-file",
            "pw",
            "--sign",
            "me.sgk"
        ]
    )
    .contains("already private"));
}

fn hex_of(s: &str) -> String {
    s.bytes().map(|b| format!("{b:02x}")).collect()
}

#[test]
fn encrypted_segments_need_their_key() {
    let d = common::scratch("privatize-enc");
    pw(&d, "pw", "secret");
    pw(&d, "pw2", "other");
    ok(&d, &["log", "init", "ev"]);
    put(&d, "a.txt", "a\n");
    ok(&d, &["log", "add", "ev", "photos", "--pass-file", "pw"]);
    // source segments under pw; the new pass cannot open them: refused, nothing left
    let e = fails(&d, &["log", "privatize", "ev", "pv", "--pass-file", "pw2"]);
    assert!(e.contains("source entry"), "{e}");
    assert!(!d.join("pv.sigil").exists());
    no_tmp(&d);
    ok(&d, &["log", "privatize", "ev", "pv", "--pass-file", "pw"]);
    let full = ok(&d, &["log", "ls", "pv", "--pass-file", "pw"]);
    assert!(full.contains("a.txt"), "{full}");
}
