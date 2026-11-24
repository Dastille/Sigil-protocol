//! `sigil log rewrap`: add / remove / replace who can open a log's wrapped keys (segment key ring,
//! private-INDEX key) without touching segments, INDEX or HEAD. Passphrases only via files.
mod common;
use std::collections::BTreeMap;
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

fn secret(d: &Path, name: &str, body: &str) {
    fs::write(d.join(name), body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
}

/// Every file under `p` → its bytes.
fn snapshot(p: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![p.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in fs::read_dir(&d).unwrap().flatten() {
            let q = e.path();
            if q.is_dir() {
                stack.push(q);
            } else {
                out.insert(
                    q.strip_prefix(p).unwrap().to_string_lossy().into_owned(),
                    fs::read(&q).unwrap(),
                );
            }
        }
    }
    out
}

fn without_keys(s: &BTreeMap<String, Vec<u8>>) -> BTreeMap<String, Vec<u8>> {
    s.iter()
        .filter(|(k, _)| !k.starts_with("keys") && k.as_str() != "IXKEY.sg1")
        .map(|(k, v)| (k.clone(), v.clone()))
        .collect()
}

fn reads(d: &Path, seq: &str, key: &[&str]) -> bool {
    let out = format!("out-{seq}-{}", key.join("-").replace(['/', '.'], "_"));
    let mut a = vec!["log", "read", "ev", "--seq", seq, "-o", out.as_str()];
    a.extend_from_slice(key);
    let o = run(d, &a);
    let r = o.status.success();
    if r {
        assert_eq!(
            fs::read(d.join(&out)).unwrap(),
            format!("batch {seq}\n").as_bytes()
        );
        fs::remove_file(d.join(&out)).unwrap();
    }
    r
}

#[test]
fn segment_key_ring_add_remove_replace() {
    let d = common::scratch("rewrap-ring");
    for k in ["a", "b", "c", "eve"] {
        ok(
            &d,
            &[
                "keygen",
                "-o",
                &format!("{k}.sgk"),
                "--pub-out",
                &format!("{k}.pub"),
            ],
        );
    }
    ok(
        &d,
        &["log", "init", "ev", "--segment-keys", "--public-index"],
    );
    for i in 1..=3 {
        fs::write(d.join("b.txt"), format!("batch {i}\n")).unwrap();
        ok(&d, &["log", "append", "ev", "b.txt", "--to", "a.pub"]);
    }
    let ev = d.join("ev.sigil");
    let base = without_keys(&snapshot(&ev));
    assert!(!reads(&d, "1", &["--identity", "b.sgk"]));

    // fail closed: wrong current key, nothing to do, removing the only recipient, unknown recipient
    let before = snapshot(&ev);
    let e = fails(
        &d,
        &[
            "log",
            "rewrap",
            "ev",
            "--identity",
            "eve.sgk",
            "--add-to",
            "eve.pub",
        ],
    );
    assert!(
        e.contains("does not open") && e.contains("nothing was re-wrapped"),
        "{e}"
    );
    assert!(
        fails(&d, &["log", "rewrap", "ev", "--identity", "a.sgk"]).contains("nothing to change")
    );
    assert!(fails(&d, &["log", "rewrap", "ev", "--add-to", "b.pub"]).contains("current"));
    let e = fails(
        &d,
        &[
            "log",
            "rewrap",
            "ev",
            "--identity",
            "a.sgk",
            "--remove-to",
            "a.pub",
        ],
    );
    assert!(e.contains("no recipient"), "{e}");
    let e = fails(
        &d,
        &[
            "log",
            "rewrap",
            "ev",
            "--identity",
            "a.sgk",
            "--remove-to",
            "c.pub",
        ],
    );
    assert!(e.contains("none of those keys"), "{e}");
    assert!(fails(
        &d,
        &["log", "rewrap", "ev", "--identity", "a.sgk", "--replace"]
    )
    .contains("no recipient"));
    let o = ok(
        &d,
        &[
            "log",
            "rewrap",
            "ev",
            "--identity",
            "a.sgk",
            "--add-to",
            "b.pub",
            "--dry-run",
        ],
    );
    assert!(o.contains("dry run") && o.contains("3 segment key"), "{o}");
    assert_eq!(snapshot(&ev), before, "refusals and dry run write nothing");

    // add b: both open
    let o = ok(
        &d,
        &[
            "log",
            "rewrap",
            "ev",
            "--identity",
            "a.sgk",
            "--add-to",
            "b.pub",
        ],
    );
    assert!(o.contains("3 segment key(s) in 1 shard"), "{o}");
    for s in ["1", "2", "3"] {
        assert!(reads(&d, s, &["--identity", "a.sgk"]));
        assert!(reads(&d, s, &["--identity", "b.sgk"]));
    }
    // remove a (authorised by b): a locked out, b still opens
    ok(
        &d,
        &[
            "log",
            "rewrap",
            "ev",
            "--identity",
            "b.sgk",
            "--remove-to",
            "a.pub",
        ],
    );
    assert!(!reads(&d, "2", &["--identity", "a.sgk"]));
    assert!(reads(&d, "2", &["--identity", "b.sgk"]));
    // replace with c plus a passphrase file
    secret(&d, "pw", "new ring pass\n");
    ok(
        &d,
        &[
            "log",
            "rewrap",
            "ev",
            "--identity",
            "b.sgk",
            "--replace",
            "--add-to",
            "c.pub",
            "--new-pass-file",
            "pw",
        ],
    );
    assert!(!reads(&d, "3", &["--identity", "b.sgk"]));
    assert!(reads(&d, "3", &["--identity", "c.sgk"]));
    assert!(reads(&d, "3", &["--pass-file", "pw"]));
    // drop the passphrase again
    ok(
        &d,
        &["log", "rewrap", "ev", "--identity", "c.sgk", "--drop-pass"],
    );
    assert!(!reads(&d, "1", &["--pass-file", "pw"]));
    assert!(reads(&d, "1", &["--identity", "c.sgk"]));

    // segments, INDEX, HEAD, CONTAINER untouched; verify still healthy
    assert_eq!(without_keys(&snapshot(&ev)), base);
    let v = ok(&d, &["log", "verify", "ev", "--identity", "c.sgk"]);
    assert!(v.contains("healthy"), "{v}");

    // a damaged ring shard: refused, nothing written
    let shard = ev.join("keys/0000.sg1");
    let mut b = fs::read(&shard).unwrap();
    let n = b.len();
    for x in &mut b[n / 4..n / 4 * 3] {
        *x ^= 0x5a;
    }
    fs::write(&shard, &b).unwrap();
    let before = snapshot(&ev);
    let e = fails(
        &d,
        &[
            "log",
            "rewrap",
            "ev",
            "--identity",
            "c.sgk",
            "--add-to",
            "a.pub",
        ],
    );
    assert!(
        e.contains("key ring") || e.contains("nothing was re-wrapped"),
        "{e}"
    );
    assert_eq!(snapshot(&ev), before);
}

#[test]
fn private_index_key_and_plain_log() {
    let d = common::scratch("rewrap-ix");
    secret(&d, "pw", "old pass\n");
    secret(&d, "pw2", "new pass\n");
    ok(&d, &["log", "init", "ev", "--pass-file", "pw"]);
    fs::write(d.join("b.txt"), "batch 1\n").unwrap();
    ok(&d, &["log", "append", "ev", "b.txt", "--pass-file", "pw"]);
    let e = fails(
        &d,
        &[
            "log",
            "rewrap",
            "ev",
            "--pass-file",
            "pw2",
            "--new-pass-file",
            "pw",
        ],
    );
    assert!(e.contains("does not open"), "{e}");
    let o = ok(
        &d,
        &[
            "log",
            "rewrap",
            "ev",
            "--pass-file",
            "pw",
            "--new-pass-file",
            "pw2",
        ],
    );
    assert!(o.contains("index key"), "{o}");
    // the INDEX now opens only with the new passphrase
    assert!(!run(&d, &["log", "ls", "ev", "--pass-file", "pw"])
        .status
        .success());
    let ls = ok(&d, &["log", "ls", "ev", "--pass-file", "pw2"]);
    assert!(ls.contains("8"), "{ls}");

    // a log without wrapped keys: refused, pointing at compact
    ok(&d, &["log", "init", "plain", "--public-index"]);
    let e = fails(
        &d,
        &[
            "log",
            "rewrap",
            "plain",
            "--pass-file",
            "pw",
            "--new-pass-file",
            "pw2",
        ],
    );
    assert!(e.contains("compact"), "{e}");
}
