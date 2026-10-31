//! `sigil log prove-consistency` / `check-consistency`: an old anchor is a prefix of a newer state.
mod common;
use std::fs;
use std::path::Path;
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

fn tmp(tag: &str) -> common::Scratch {
    let d = common::scratch(&format!("log-cons-{tag}"));
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

fn root_part(a: &str) -> &str {
    a.split_once(':').unwrap().1
}

#[test]
fn signed_log_old_anchor_is_prefix_of_head_offline() {
    let d = tmp("signed");
    ok(&d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    ok(&d, &["keygen", "-o", "eve.sgk", "--pub-out", "eve.pub"]);
    ok(&d, &["log", "init", "ev", "--identity", "me.sgk"]);
    append_n(&d, 3, &["--identity", "me.sgk"]);
    let a3 = anchor_of(&ok(&d, &["log", "ls", "ev"]));
    assert!(a3.starts_with("3:"), "{a3}");
    for i in 4..=11 {
        let f = format!("b{i}.txt");
        fs::write(d.join(&f), format!("later batch {i}\n")).unwrap();
        ok(&d, &["log", "append", "ev", &f, "--identity", "me.sgk"]);
    }
    let a11 = anchor_of(&ok(&d, &["log", "ls", "ev"]));
    ok(
        &d,
        &["log", "prove-consistency", "ev", &a3, "-o", "c.proof"],
    );
    let good = fs::read_to_string(d.join("c.proof")).unwrap();
    assert!(
        good.starts_with("sigil-log-consistency=1\n") && good.contains("sig="),
        "{good}"
    );
    // the verifier has no log at all
    fs::rename(d.join("ev.sigil"), d.join("away.sigil")).unwrap();
    let o = ok(
        &d,
        &[
            "log",
            "check-consistency",
            "c.proof",
            "--old",
            &a3,
            "--new",
            &a11,
            "--signer",
            "me.pub",
        ],
    );
    assert!(
        o.contains("is a prefix of") && o.contains("signed by"),
        "{o}"
    );
    assert!(fails(
        &d,
        &["log", "check-consistency", "c.proof", "--signer", "eve.pub"]
    )
    .contains("not by the required key"));
    // pins that do not match
    let wrong = format!("3:{}", "ab".repeat(32));
    assert!(fails(
        &d,
        &["log", "check-consistency", "c.proof", "--old", &wrong]
    )
    .contains("differs from the pinned"));
    assert!(
        fails(&d, &["log", "check-consistency", "c.proof", "--old", &a11])
            .contains("old side is 3")
    );

    let tamper = |from: &str, to: &str| {
        assert!(good.contains(from), "{from}");
        fs::write(d.join("bad.proof"), good.replacen(from, to, 1)).unwrap();
        fails(&d, &["log", "check-consistency", "bad.proof"])
    };
    // size regression, other sizes, truncated path, altered roots / leaf / log id
    assert!(tamper("old-size=3\n", "old-size=12\n").contains("size regression"));
    assert!(tamper("old-size=3\n", "old-size=4\n").contains("does not verify"));
    assert!(tamper("new-size=11\n", "new-size=10\n").contains("does not verify"));
    let path_line = good.lines().find(|l| l.starts_with("path=")).unwrap();
    let truncated = path_line.rsplit_once(',').unwrap().0;
    assert!(tamper(path_line, truncated).contains("wrong number of hashes"));
    let flip = |line: &str| {
        let (k, v) = line.split_once('=').unwrap();
        let c = if v.starts_with('0') { "1" } else { "0" };
        format!("{k}={c}{}", &v[1..])
    };
    for key in ["old-root=", "new-root=", "leaf=", "path=", "log="] {
        let l = good.lines().find(|l| l.starts_with(key)).unwrap();
        assert!(tamper(l, &flip(l)).contains("does not verify"), "{key}");
    }
    assert!(fails(&d, &["log", "check-consistency", "b1.txt"])
        .contains("not a sigil consistency proof"));
}

#[test]
fn unsigned_fork_is_not_a_prefix() {
    let d = tmp("fork");
    ok(&d, &["log", "init", "ev"]);
    append_n(&d, 3, &[]);
    let a3 = anchor_of(&ok(&d, &["log", "ls", "ev"]));
    // same log id and first 3 entries, then the histories diverge
    let cp = Command::new("cp")
        .args(["-r", "ev.sigil", "fork.sigil"])
        .current_dir(&d)
        .status()
        .unwrap();
    assert!(cp.success());
    for i in 4..=5 {
        let f = format!("b{i}.txt");
        fs::write(d.join(&f), format!("real {i}\n")).unwrap();
        ok(&d, &["log", "append", "ev", &f]);
        fs::write(d.join(&f), format!("forged {i}\n")).unwrap();
        ok(&d, &["log", "append", "fork", &f]);
    }
    let a5 = anchor_of(&ok(&d, &["log", "ls", "ev"]));
    let f5 = anchor_of(&ok(&d, &["log", "ls", "fork"]));
    assert_ne!(a5, f5);
    for i in 6..=7 {
        let f = format!("b{i}.txt");
        fs::write(d.join(&f), format!("more {i}\n")).unwrap();
        ok(&d, &["log", "append", "fork", &f]);
    }
    // both extend the common anchor 3
    ok(
        &d,
        &["log", "prove-consistency", "ev", &a3, "5", "-o", "ev.proof"],
    );
    ok(
        &d,
        &[
            "log",
            "check-consistency",
            "ev.proof",
            "--old",
            &a3,
            "--new",
            &a5,
        ],
    );
    ok(
        &d,
        &["log", "prove-consistency", "fork", &a3, "-o", "fk3.proof"],
    );
    ok(&d, &["log", "check-consistency", "fk3.proof", "--old", &a3]);
    // the prover refuses to claim the fork extends anchor 5 of the real log
    assert!(fails(&d, &["log", "prove-consistency", "fork", &a5]).contains("not an extension"));
    // a fork proof from its own 5 does not match the real anchor 5
    ok(
        &d,
        &["log", "prove-consistency", "fork", "5", "-o", "fk.proof"],
    );
    assert!(
        fails(&d, &["log", "check-consistency", "fk.proof", "--old", &a5])
            .contains("differs from the pinned")
    );
    // swapping the real root into the proof does not help: the path rebuilds the fork's root
    let p = fs::read_to_string(d.join("fk.proof")).unwrap();
    let forged = p.replacen(root_part(&f5), root_part(&a5), 1);
    assert_ne!(p, forged);
    fs::write(d.join("forged.proof"), forged).unwrap();
    assert!(fails(
        &d,
        &["log", "check-consistency", "forged.proof", "--old", &a5]
    )
    .contains("not a prefix"));
    // size regression refused at the prover; equal sizes are trivially consistent
    assert!(fails(&d, &["log", "prove-consistency", "ev", "5", "3"]).contains("larger than"));
    ok(
        &d,
        &[
            "log",
            "prove-consistency",
            "ev",
            &a5,
            "5",
            "-o",
            "same.proof",
        ],
    );
    ok(
        &d,
        &[
            "log",
            "check-consistency",
            "same.proof",
            "--old",
            &a5,
            "--new",
            &a5,
        ],
    );
    assert!(fails(&d, &["log", "prove-consistency", "ev", "0"]).contains("at least 1"));
    assert!(fails(
        &d,
        &[
            "log",
            "check-consistency",
            "ev.proof",
            "--signer",
            &"ab".repeat(32)
        ]
    )
    .contains("unsigned"));
}
