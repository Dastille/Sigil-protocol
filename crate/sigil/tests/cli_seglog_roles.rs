//! Reader vs writer roles of a signed log: the signing key writes; a recipient key (added with
//! `log rewrap --add-to`) opens, lists, reads and verifies, and every write refuses it.
mod common;
use std::fs;
use std::path::{Path, PathBuf};
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
fn pw(d: &Path) {
    fs::write(d.join("pw"), "secret\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join("pw"), fs::Permissions::from_mode(0o600)).unwrap();
    }
}
fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut st = vec![dir.to_path_buf()];
    while let Some(p) = st.pop() {
        for e in fs::read_dir(&p).unwrap().flatten() {
            let q = e.path();
            if q.is_dir() {
                st.push(q)
            } else {
                out.push((q.clone(), fs::read(&q).unwrap()))
            }
        }
    }
    out.sort();
    out
}

fn setup(d: &Path, init: &[&str]) {
    pw(d);
    ok(d, &["keygen", "-o", "owner.sgk", "--pub-out", "owner.pub"]);
    ok(
        d,
        &["keygen", "-o", "reader.sgk", "--pub-out", "reader.pub"],
    );
    ok(d, &["keygen", "-o", "eve.sgk", "--pub-out", "eve.pub"]);
    let mut a = vec![
        "log",
        "init",
        "ev",
        "--identity",
        "owner.sgk",
        "--pass-file",
        "pw",
    ];
    a.extend_from_slice(init);
    ok(d, &a);
    for i in 1..=2 {
        let f = format!("f{i}");
        fs::write(d.join(&f), format!("batch {i}\n")).unwrap();
        ok(
            d,
            &[
                "log",
                "append",
                "ev",
                &f,
                "--identity",
                "owner.sgk",
                "--pass-file",
                "pw",
            ],
        );
    }
}

#[test]
fn reader_reads_writer_writes() {
    let d = common::scratch("roles");
    setup(&d, &["--segment-keys"]);
    // granting access is a write: refused without the signing key, also for a key holder
    let e = fails(
        &d,
        &[
            "log",
            "rewrap",
            "ev",
            "--pass-file",
            "pw",
            "--add-to",
            "reader.pub",
        ],
    );
    assert!(e.contains("signing key"), "{e}");
    ok(
        &d,
        &[
            "log",
            "rewrap",
            "ev",
            "--pass-file",
            "pw",
            "--identity",
            "owner.sgk",
            "--add-to",
            "reader.pub",
        ],
    );
    // reader: list, read, verify, restore-style read of every batch
    let r = ["--identity", "reader.sgk"];
    let ls = ok(&d, &["log", "ls", "ev", r[0], r[1]]);
    assert!(ls.contains("private index: opened"), "{ls}");
    for (s, body) in [("1", "batch 1\n"), ("2", "batch 2\n")] {
        let out = ok(&d, &["log", "read", "ev", "--seq", s, r[0], r[1]]);
        assert!(out.ends_with(body), "{out}");
    }
    let v = run(&d, &["log", "verify", "ev", r[0], r[1]]);
    assert_eq!(v.status.code(), Some(0), "{}", text(&v));
    // reader: every write refused, nothing changes
    let dir = d.join("ev.sigil");
    let before = snapshot(&dir);
    fs::write(d.join("f9"), "evil\n").unwrap();
    fails(
        &d,
        &[
            "log",
            "append",
            "ev",
            "f9",
            r[0],
            r[1],
            "--to",
            "reader.pub",
        ],
    );
    fails(&d, &["log", "tombstone", "ev", "--seq", "1", r[0], r[1]]);
    fails(&d, &["log", "shred", "ev", "--seq", "1", r[0], r[1]]);
    fails(
        &d,
        &[
            "log",
            "compact",
            "ev",
            "--apply",
            r[0],
            r[1],
            "--to",
            "reader.pub",
        ],
    );
    let e = fails(
        &d,
        &["log", "rewrap", "ev", r[0], r[1], "--add-to", "eve.pub"],
    );
    assert!(e.contains("signing key"), "{e}");
    fails(
        &d,
        &[
            "log",
            "rewrap",
            "ev",
            r[0],
            r[1],
            "--remove-to",
            "owner.pub",
        ],
    );
    let e = fails(&d, &["log", "pad", "ev", r[0], r[1]]);
    assert!(e.contains("signing key"), "{e}");
    assert!(before == snapshot(&dir), "a reader changed the log");
    // a dry-run rewrap only reports: allowed
    ok(
        &d,
        &[
            "log",
            "rewrap",
            "ev",
            r[0],
            r[1],
            "--add-to",
            "eve.pub",
            "--dry-run",
        ],
    );
    assert!(before == snapshot(&dir));
    // writer: everything
    ok(&d, &["log", "pad", "ev", "--identity", "owner.sgk"]);
    ok(
        &d,
        &[
            "log",
            "append",
            "ev",
            "f9",
            "--identity",
            "owner.sgk",
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
            "1",
            "--identity",
            "owner.sgk",
            "--pass-file",
            "pw",
        ],
    );
    // the reader still reads what the ring re-wrap gave it (the new segment's key was wrapped
    // to the writer's --pass only, so a reader sees it only after the next rewrap)
    assert!(ok(&d, &["log", "read", "ev", "--seq", "2", r[0], r[1]]).ends_with("batch 2\n"));
    ok(
        &d,
        &[
            "log",
            "rewrap",
            "ev",
            "--pass-file",
            "pw",
            "--identity",
            "owner.sgk",
            "--add-to",
            "reader.pub",
        ],
    );
    assert!(ok(&d, &["log", "read", "ev", "--seq", "3", r[0], r[1]]).ends_with("evil\n"));
    let v = run(&d, &["log", "verify", "ev", r[0], r[1]]);
    assert_ne!(v.status.code(), Some(2), "{}", text(&v));
}

#[test]
fn enable_segment_keys_needs_the_writer() {
    let d = common::scratch("roles-segkeys");
    setup(&d, &[]);
    ok(
        &d,
        &[
            "log",
            "rewrap",
            "ev",
            "--pass-file",
            "pw",
            "--identity",
            "owner.sgk",
            "--add-to",
            "reader.pub",
        ],
    );
    let e = fails(
        &d,
        &[
            "log",
            "enable-segment-keys",
            "ev",
            "--identity",
            "reader.sgk",
        ],
    );
    assert!(e.contains("signing key"), "{e}");
    let e = fails(
        &d,
        &["log", "enable-segment-keys", "ev", "--pass-file", "pw"],
    );
    assert!(e.contains("signing key"), "{e}");
    ok(
        &d,
        &[
            "log",
            "enable-segment-keys",
            "ev",
            "--pass-file",
            "pw",
            "--identity",
            "owner.sgk",
        ],
    );
}

#[test]
fn unsigned_logs_have_no_writer_role() {
    let d = common::scratch("roles-unsigned");
    pw(&d);
    ok(&d, &["log", "init", "ev", "--pass-file", "pw"]);
    // documented: without a signer, any key holder may change the log (and the folder's owner always can)
    ok(&d, &["log", "pad", "ev"]);
}
