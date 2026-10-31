//! `sigil log shred --seq M --rewrite`: erase one batch inside a compaction segment by rewriting
//! only that segment file (a tombstone + a one-file compaction).
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
fn snapshot(d: &Path, log: &str) -> Vec<(String, Vec<u8>)> {
    let mut v = Vec::new();
    let mut stack = vec![d.join(format!("{log}.sigil"))];
    while let Some(p) = stack.pop() {
        for e in fs::read_dir(&p).unwrap().flatten() {
            let q = e.path();
            if q.is_dir() {
                stack.push(q);
            } else {
                v.push((q.display().to_string(), fs::read(&q).unwrap()));
            }
        }
    }
    v.sort();
    v
}
fn seg(d: &Path, log: &str, seq: u64) -> std::path::PathBuf {
    d.join(format!("{log}.sigil/segments/0000/{seq:010}.sg1"))
}
fn read_seq(d: &Path, log: &str, seq: &str, extra: &[&str]) -> Output {
    let mut a = vec!["log", "read", log, "--seq", seq];
    a.extend_from_slice(extra);
    run(d, &a)
}

/// Batches 1-3 merged into segment 4 (one file, one key); batch 5 appended on its own.
fn setup(d: &Path, init: &[&str]) {
    let mut a = vec!["log", "init", "ev"];
    a.extend_from_slice(init);
    ok(d, &a);
    for i in 1..=3 {
        let f = format!("f{i}");
        fs::write(d.join(&f), format!("batch {i}\n")).unwrap();
        ok(d, &["log", "append", "ev", &f, "--pass-file", "pw"]);
    }
    ok(
        d,
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
    fs::write(d.join("f4"), "batch 5\n").unwrap();
    ok(d, &["log", "append", "ev", "f4", "--pass-file", "pw"]);
}

#[test]
fn erase_one_batch_of_a_compaction_segment() {
    let d = common::scratch("shred-rewrite");
    pw(&d, "pw", "secret");
    pw(&d, "bad", "wrong");
    setup(&d, &["--segment-keys"]);
    assert!(seg(&d, "ev", 4).exists() && seg(&d, "ev", 5).exists());
    let seg5 = fs::read(seg(&d, "ev", 5)).unwrap();
    // plain shred refuses (shared key) and points at --rewrite
    let e = fails(&d, &["log", "shred", "ev", "--seq", "2"]);
    assert!(e.contains("--rewrite"), "{e}");
    // fail closed: wrong key, no key for the new file, literal passphrase: nothing changes
    let before = snapshot(&d, "ev");
    let e = fails(
        &d,
        &[
            "log",
            "shred",
            "ev",
            "--seq",
            "2",
            "--rewrite",
            "--pass-file",
            "bad",
            "--seal-pass-file",
            "pw",
        ],
    );
    assert!(e.contains("nothing was changed"), "{e}");
    let e = fails(
        &d,
        &[
            "log",
            "shred",
            "ev",
            "--seq",
            "2",
            "--rewrite",
            "--pass-file",
            "pw",
        ],
    );
    assert!(e.contains("nothing was changed"), "{e}");
    fails(
        &d,
        &[
            "log",
            "shred",
            "ev",
            "--seq",
            "2",
            "--rewrite",
            "--pass",
            "secret",
            "--seal-pass-file",
            "pw",
        ],
    );
    assert!(
        before == snapshot(&d, "ev"),
        "a refused erase changed the log"
    );
    let out = ok(
        &d,
        &[
            "log",
            "shred",
            "ev",
            "--seq",
            "2",
            "--rewrite",
            "--pass-file",
            "pw",
            "--seal-pass-file",
            "pw",
            "--reason",
            "gdpr",
        ],
    );
    assert!(out.contains("rewriting only segment file(s) 4"), "{out}");
    // the old file is gone, the separate segment 5 is byte-identical
    assert!(!seg(&d, "ev", 4).exists());
    assert_eq!(fs::read(seg(&d, "ev", 5)).unwrap(), seg5);
    for (s, body) in [("1", "batch 1\n"), ("3", "batch 3\n"), ("5", "batch 5\n")] {
        let o = read_seq(&d, "ev", s, &["--pass-file", "pw"]);
        assert!(o.status.success(), "{}", text(&o));
        assert_eq!(String::from_utf8_lossy(&o.stdout), body);
    }
    let o = read_seq(&d, "ev", "2", &["--pass-file", "pw"]);
    assert!(
        !o.status.success() && text(&o).contains("deleted"),
        "{}",
        text(&o)
    );
    assert!(!read_seq(&d, "ev", "1", &["--pass-file", "bad"])
        .status
        .success());
    let v = run(&d, &["log", "verify", "ev", "--pass-file", "pw"]);
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
    assert!(!text(&v).contains("deleted-data"), "{}", text(&v));
    // already erased: nothing to do
    fails(
        &d,
        &[
            "log",
            "shred",
            "ev",
            "--seq",
            "2",
            "--rewrite",
            "--pass-file",
            "pw",
            "--seal-pass-file",
            "pw",
        ],
    );
}

#[test]
fn rewrite_works_in_a_private_log_without_segment_keys() {
    let d = common::scratch("shred-rewrite-priv");
    pw(&d, "pw", "secret");
    setup(&d, &["--pass-file", "pw"]);
    // no segment keys: plain shred has nothing to destroy, --rewrite still erases the batch
    fails(
        &d,
        &["log", "shred", "ev", "--seq", "1", "--pass-file", "pw"],
    );
    ok(
        &d,
        &[
            "log",
            "shred",
            "ev",
            "--seq",
            "1",
            "--rewrite",
            "--pass-file",
            "pw",
            "--seal-pass-file",
            "pw",
        ],
    );
    assert!(!seg(&d, "ev", 4).exists());
    for (s, body) in [("2", "batch 2\n"), ("3", "batch 3\n"), ("5", "batch 5\n")] {
        let o = read_seq(&d, "ev", s, &["--pass-file", "pw"]);
        assert!(o.status.success(), "{}", text(&o));
        assert_eq!(String::from_utf8_lossy(&o.stdout), body);
    }
    let v = run(&d, &["log", "verify", "ev", "--pass-file", "pw"]);
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
}
