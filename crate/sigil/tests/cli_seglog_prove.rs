//! `sigil log prove` / `sigil log check-proof`: portable inclusion receipts for segment logs.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn sigil_cmd(dir: &Path, args: &[&str]) -> Output {
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

fn ok(dir: &Path, args: &[&str]) -> String {
    let o = sigil_cmd(dir, args);
    assert!(o.status.success(), "{args:?}: {}", text(&o));
    text(&o)
}

/// Fails with exit code 2 (check-proof's "does not verify") or 1 (usage / refusal).
fn fails(dir: &Path, args: &[&str]) -> String {
    let o = sigil_cmd(dir, args);
    assert!(
        !o.status.success(),
        "expected failure {args:?}: {}",
        text(&o)
    );
    text(&o)
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sigil-log-prove-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn append_n(d: &Path, n: usize, extra: &[&str]) {
    for i in 1..=n {
        let f = format!("b{i}.txt");
        fs::write(d.join(&f), format!("batch number {i}\n")).unwrap();
        let mut a = vec!["log", "append", "ev", f.as_str()];
        a.extend_from_slice(extra);
        ok(d, &a);
    }
}

fn anchor_of(ls: &str) -> String {
    ls.lines()
        .find_map(|l| l.split("): ").nth(1).filter(|_| l.starts_with("anchor")))
        .unwrap()
        .trim()
        .to_string()
}

#[test]
fn signed_log_every_entry_proves_offline_with_file_and_signer() {
    let d = tmp("signed");
    ok(&d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    ok(&d, &["keygen", "-o", "eve.sgk", "--pub-out", "eve.pub"]);
    ok(&d, &["log", "init", "ev", "--identity", "me.sgk"]);
    append_n(&d, 7, &["--identity", "me.sgk"]);
    for seq in 1..=7 {
        let p = format!("r{seq}.proof");
        ok(
            &d,
            &["log", "prove", "ev", "--seq", &seq.to_string(), "-o", &p],
        );
        // Checked without the log: move it away first.
        if seq == 1 {
            fs::rename(d.join("ev.sigil"), d.join("elsewhere.sigil")).unwrap();
        }
        let b = format!("b{seq}.txt");
        let o = ok(
            &d,
            &["log", "check-proof", &p, "--file", &b, "--signer", "me.pub"],
        );
        assert!(o.contains(&format!("proof ok: entry {seq} ")), "{o}");
        assert!(o.contains("signed by") && o.contains("file matches"), "{o}");
        if seq == 1 {
            fs::rename(d.join("elsewhere.sigil"), d.join("ev.sigil")).unwrap();
        }
    }
    assert!(
        fails(&d, &["log", "check-proof", "r3.proof", "--file", "b4.txt"])
            .contains("not this entry's bytes")
    );
    assert!(fails(
        &d,
        &["log", "check-proof", "r3.proof", "--signer", "eve.pub"]
    )
    .contains("not by the required key"));

    // Tampering with any part is caught.
    let good = fs::read_to_string(d.join("r3.proof")).unwrap();
    let tamper = |from: &str, to: &str| {
        assert!(good.contains(from), "{from}");
        fs::write(d.join("bad.proof"), good.replacen(from, to, 1)).unwrap();
        fails(&d, &["log", "check-proof", "bad.proof"])
    };
    assert!(tamper("size=7\n", "size=8\n").contains("does not verify"));
    assert!(tamper("entry=seq=3 ", "entry=seq=4 ").contains("does not verify"));
    assert!(tamper(" size=", " size=1").contains("does not verify"));
    let path_line = good.lines().find(|l| l.starts_with("path=")).unwrap();
    let flipped = format!(
        "path={}{}",
        if path_line.as_bytes()[5] == b'0' {
            "1"
        } else {
            "0"
        },
        &path_line[6..]
    );
    assert!(tamper(path_line, &flipped).contains("does not verify"));
    let log_line = good.lines().find(|l| l.starts_with("log=")).unwrap();
    assert!(tamper(log_line, "log=00000000000000000000000000000000").contains("does not verify"));
    assert!(fails(&d, &["log", "check-proof", "b1.txt"]).contains("not a sigil log proof"));
}

#[test]
fn unsigned_log_proofs_bind_to_anchors() {
    let d = tmp("unsigned");
    ok(&d, &["log", "init", "ev"]);
    append_n(&d, 3, &[]);
    let a3 = anchor_of(&ok(&d, &["log", "ls", "ev"]));
    assert!(a3.starts_with("3:"), "{a3}");
    append_n(&d, 2, &[]);
    let a5 = anchor_of(&ok(&d, &["log", "ls", "ev"]));
    let now = ok(&d, &["log", "prove", "ev", "--seq", "2"]);
    fs::write(d.join("now.proof"), &now).unwrap();
    assert!(!now.contains("sig="));
    let o = ok(&d, &["log", "check-proof", "now.proof", "--anchor", &a5]);
    assert!(o.contains("unsigned"), "{o}");
    assert!(fails(&d, &["log", "check-proof", "now.proof", "--anchor", &a3]).contains("--at 3"));
    assert!(fails(
        &d,
        &[
            "log",
            "check-proof",
            "now.proof",
            "--signer",
            &"ab".repeat(32)
        ]
    )
    .contains("unsigned"));
    // Against the earlier anchor.
    ok(
        &d,
        &[
            "log",
            "prove",
            "ev",
            "--seq",
            "2",
            "--at",
            "3",
            "-o",
            "old.proof",
        ],
    );
    ok(
        &d,
        &[
            "log",
            "check-proof",
            "old.proof",
            "--anchor",
            &a3,
            "--file",
            "b2.txt",
        ],
    );
    let wrong_root = format!("3:{}", "0".repeat(64));
    assert!(fails(
        &d,
        &["log", "check-proof", "old.proof", "--anchor", &wrong_root]
    )
    .contains("differs"));
    // Out of range.
    assert!(fails(&d, &["log", "prove", "ev", "--seq", "4", "--at", "3"]).contains("not among"));
    assert!(fails(&d, &["log", "prove", "ev", "--seq", "9"]).contains("not among"));
    assert!(fails(&d, &["log", "prove", "ev", "--seq", "1", "--at", "9"]).contains("only 5"));
}

#[test]
fn proofs_survive_tombstone_and_compaction_and_tombstones_are_provable() {
    let d = tmp("tomb");
    ok(&d, &["log", "init", "ev"]);
    append_n(&d, 4, &[]);
    let a4 = anchor_of(&ok(&d, &["log", "ls", "ev"]));
    ok(&d, &["log", "prove", "ev", "--seq", "2", "-o", "two.proof"]);
    ok(
        &d,
        &[
            "log",
            "tombstone",
            "ev",
            "--seq",
            "2",
            "--reason",
            "gdpr request",
        ],
    );
    ok(&d, &["log", "compact", "ev", "--apply"]);
    // The old receipt still checks against the anchor it was cut for ...
    ok(
        &d,
        &[
            "log",
            "check-proof",
            "two.proof",
            "--anchor",
            &a4,
            "--file",
            "b2.txt",
        ],
    );
    // ... and a fresh one against the old anchor reproduces it from the never-rewritten INDEX.
    ok(
        &d,
        &[
            "log",
            "prove",
            "ev",
            "--seq",
            "2",
            "--at",
            "4",
            "-o",
            "two-again.proof",
        ],
    );
    ok(
        &d,
        &["log", "check-proof", "two-again.proof", "--anchor", &a4],
    );
    // The deletion itself has a receipt.
    ok(
        &d,
        &["log", "prove", "ev", "--seq", "5", "-o", "tomb.proof"],
    );
    let o = ok(&d, &["log", "check-proof", "tomb.proof"]);
    assert!(o.contains("entry 5 (tombstone of 2"), "{o}");
    assert!(fails(
        &d,
        &["log", "check-proof", "tomb.proof", "--file", "b2.txt"]
    )
    .contains("tombstone"));
    // The compaction entry (seq 6) proves with the concatenated bytes it holds.
    let mut merged = Vec::new();
    for i in [1, 3, 4] {
        merged.extend(fs::read(d.join(format!("b{i}.txt"))).unwrap());
    }
    fs::write(d.join("merged.bin"), merged).unwrap();
    ok(&d, &["log", "prove", "ev", "--seq", "6", "-o", "c.proof"]);
    let o = ok(
        &d,
        &["log", "check-proof", "c.proof", "--file", "merged.bin"],
    );
    assert!(o.contains("compaction of 1,3-4"), "{o}");
}

#[test]
fn signed_log_without_valid_head_refuses_to_prove() {
    let d = tmp("nohead");
    ok(&d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    ok(&d, &["log", "init", "ev", "--identity", "me.sgk"]);
    append_n(&d, 2, &["--identity", "me.sgk"]);
    fs::remove_file(d.join("ev.sigil/HEAD")).unwrap();
    assert!(fails(&d, &["log", "prove", "ev", "--seq", "1"]).contains("HEAD"));
    // An explicit --at still gives an (unsigned) proof checkable against a pinned anchor.
    let o = ok(&d, &["log", "prove", "ev", "--seq", "1", "--at", "2"]);
    assert!(!o.contains("sig="));
}
