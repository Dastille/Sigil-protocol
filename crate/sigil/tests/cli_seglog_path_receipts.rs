//! `sigil log prove --path` / `check-proof --path`: per-file receipts by the path `log add` recorded.
mod common;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn run(dir: &Path, args: &[&str]) -> Output {
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

#[test]
fn signed_public_log_receipts_by_path() {
    let d = common::scratch("path-rcpt");
    ok(&d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    ok(&d, &["keygen", "-o", "eve.sgk", "--pub-out", "eve.pub"]);
    ok(&d, &["log", "init", "ev", "--identity", "me.sgk"]);
    put(&d, "2024/beach.jpg", "beach v1\n");
    put(&d, "notes.txt", "notes\n");
    ok(&d, &["log", "add", "ev", "photos", "--identity", "me.sgk"]);
    put(&d, "2024/beach.jpg", "beach v2\n");
    ok(&d, &["log", "add", "ev", "photos", "--identity", "me.sgk"]);
    fs::write(d.join("v2.jpg"), "beach v2\n").unwrap();
    fs::write(d.join("v1.jpg"), "beach v1\n").unwrap();

    ok(
        &d,
        &[
            "log",
            "prove",
            "ev",
            "--path",
            "2024/beach.jpg",
            "-o",
            "beach.proof",
        ],
    );
    // checked without the log
    fs::rename(d.join("ev.sigil"), d.join("away.sigil")).unwrap();
    let o = ok(
        &d,
        &[
            "log",
            "check-proof",
            "beach.proof",
            "--path",
            "2024/beach.jpg",
            "--file",
            "v2.jpg",
            "--signer",
            "me.pub",
        ],
    );
    assert!(
        o.contains("path 2024/beach.jpg") && o.contains("file matches") && o.contains("signed by"),
        "{o}"
    );
    // the latest version, not the first one
    assert!(fails(
        &d,
        &["log", "check-proof", "beach.proof", "--file", "v1.jpg"]
    )
    .contains("not this entry's bytes"));
    assert!(fails(
        &d,
        &["log", "check-proof", "beach.proof", "--path", "notes.txt"]
    )
    .contains("not \"notes.txt\""));
    assert!(fails(
        &d,
        &["log", "check-proof", "beach.proof", "--signer", "eve.pub"]
    )
    .contains("not by the required key"));
    // a path= rewritten in the proof breaks the chain hash
    let good = fs::read_to_string(d.join("beach.proof")).unwrap();
    fs::write(
        d.join("bad.proof"),
        good.replacen("path=2024/beach.jpg", "path=2024/beach.png", 1),
    )
    .unwrap();
    assert!(fails(&d, &["log", "check-proof", "bad.proof"]).contains("does not verify"));
    fs::rename(d.join("away.sigil"), d.join("ev.sigil")).unwrap();

    // refused: unknown path, a folder, deleted latest version, neither/both selectors
    assert!(fails(&d, &["log", "prove", "ev", "--path", "nope.txt"]).contains("no file"));
    assert!(fails(&d, &["log", "prove", "ev", "--path", "2024"]).contains("no file"));
    assert!(!run(&d, &["log", "prove", "ev"]).status.success());
    assert!(!run(
        &d,
        &["log", "prove", "ev", "--seq", "1", "--path", "notes.txt"]
    )
    .status
    .success());
    let seq = ok(&d, &["log", "prove", "ev", "--path", "notes.txt"]);
    let s = seq
        .lines()
        .find_map(|l| l.strip_prefix("entry=seq="))
        .unwrap();
    let s = s.split_whitespace().next().unwrap().to_string();
    ok(
        &d,
        &[
            "log",
            "tombstone",
            "ev",
            "--seq",
            &s,
            "--identity",
            "me.sgk",
        ],
    );
    let e = fails(&d, &["log", "prove", "ev", "--path", "notes.txt"]);
    assert!(e.contains("deleted"), "{e}");
    // an entry without a path cannot pass --path
    fs::write(d.join("raw.txt"), "raw\n").unwrap();
    ok(
        &d,
        &["log", "append", "ev", "raw.txt", "--identity", "me.sgk"],
    );
    // 1,2 notes/beach v1; 3 beach v2; 4 tombstone; 5 the raw append
    let n = 5;
    ok(
        &d,
        &[
            "log",
            "prove",
            "ev",
            "--seq",
            &n.to_string(),
            "-o",
            "raw.proof",
        ],
    );
    assert!(fails(
        &d,
        &["log", "check-proof", "raw.proof", "--path", "raw.txt"]
    )
    .contains("records no path"));
}

#[test]
fn private_log_path_needs_key() {
    let d = common::scratch("path-rcpt-priv");
    fs::write(d.join("pw"), "pw\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join("pw"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    put(&d, "secret.txt", "s\n");
    ok(&d, &["log", "init", "ev", "--pass-file", "pw"]);
    ok(&d, &["log", "add", "ev", "photos", "--pass-file", "pw"]);
    let e = fails(&d, &["log", "prove", "ev", "--path", "secret.txt"]);
    assert!(!e.contains("secret.txt\"") || e.contains("private"), "{e}");
    ok(
        &d,
        &[
            "log",
            "prove",
            "ev",
            "--path",
            "secret.txt",
            "--pass-file",
            "pw",
            "-o",
            "k.proof",
        ],
    );
    let o = ok(
        &d,
        &["log", "check-proof", "k.proof", "--path", "secret.txt"],
    );
    assert!(o.contains("path secret.txt"), "{o}");
    // without entry-key= the path is sealed: --path refused
    let t = fs::read_to_string(d.join("k.proof")).unwrap();
    let stripped: String = t
        .lines()
        .filter(|l| !l.starts_with("entry-key="))
        .map(|l| format!("{l}\n"))
        .collect();
    fs::write(d.join("s.proof"), stripped).unwrap();
    assert!(fails(
        &d,
        &["log", "check-proof", "s.proof", "--path", "secret.txt"]
    )
    .contains("sealed"));
}
