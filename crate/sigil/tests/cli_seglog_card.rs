//! `sigil log card` / `check-card`: roll-up cards over segment-log HEADs and other cards.
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

fn append(d: &Path, log: &str, body: &str, extra: &[&str]) {
    fs::write(d.join("b.txt"), body).unwrap();
    let mut a = vec!["log", "append", log, "b.txt"];
    a.extend_from_slice(extra);
    ok(d, &a);
}

#[test]
fn daily_logs_roll_up_into_monthly_and_yearly_cards() {
    let d = common::scratch("card");
    ok(&d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    ok(&d, &["keygen", "-o", "eve.sgk", "--pub-out", "eve.pub"]);
    // two signed daily logs and one unsigned
    for day in ["d01", "d02"] {
        ok(&d, &["log", "init", day, "--identity", "me.sgk"]);
        append(&d, day, &format!("{day} a\n"), &["--identity", "me.sgk"]);
        append(&d, day, &format!("{day} b\n"), &["--identity", "me.sgk"]);
    }
    ok(&d, &["log", "init", "d03"]);
    append(&d, "d03", "d03 a\n", &[]);

    ok(
        &d,
        &[
            "log",
            "card",
            "d01",
            "d02",
            "--name",
            "2026-10-a",
            "--identity",
            "me.sgk",
            "-o",
            "m1.card",
        ],
    );
    ok(
        &d,
        &["log", "card", "d03", "--name", "2026-10-b", "-o", "m2.card"],
    );
    ok(
        &d,
        &[
            "log",
            "card",
            "m1.card",
            "m2.card",
            "--name",
            "2026",
            "--identity",
            "me.sgk",
            "-o",
            "y.card",
        ],
    );
    let o = ok(
        &d,
        &[
            "log",
            "check-card",
            "m1.card",
            "--child",
            "d01",
            "--child",
            "d02",
            "--all",
            "--signer",
            "me.pub",
        ],
    );
    assert!(
        o.contains("card OK: 2026-10-a (2 children)") && o.contains("signed by"),
        "{o}"
    );
    let o = ok(
        &d,
        &[
            "log",
            "check-card",
            "y.card",
            "--child",
            "m1.card",
            "--child",
            "m2.card",
            "--all",
        ],
    );
    assert!(o.contains("card file matches"), "{o}");

    // logs keep growing: the card's state is still a prefix
    append(&d, "d01", "d01 c\n", &["--identity", "me.sgk"]);
    ok(&d, &["log", "check-card", "m1.card", "--child", "d01"]);

    // fail closed: wrong signer, missing child, child not on the card, unknown path
    assert!(
        fails(&d, &["log", "check-card", "m1.card", "--signer", "eve.pub"])
            .contains("not by the required key")
    );
    assert!(
        fails(&d, &["log", "check-card", "m2.card", "--signer", "me.pub"]).contains("unsigned")
    );
    assert!(fails(
        &d,
        &["log", "check-card", "m1.card", "--child", "d01", "--all"]
    )
    .contains("missing child-2"));
    assert!(fails(&d, &["log", "check-card", "m1.card", "--child", "d03"]).contains("not a child"));
    assert!(
        fails(&d, &["log", "check-card", "m1.card", "--child", "nope"]).contains("missing child")
    );
    assert!(fails(
        &d,
        &[
            "log",
            "check-card",
            "y.card",
            "--child",
            "m1.card",
            "--child",
            "m1.card"
        ]
    )
    .contains("twice"));
    assert!(fails(&d, &["log", "card", "d01", "d01", "--name", "x"]).contains("twice"));
    assert!(fails(&d, &["log", "card", "d01", "--name", "bad name"]).contains("--name"));

    // a rewritten child: same log id, different history (copy taken before d02 grew, then forked)
    let snap = d.join("fork");
    fs::create_dir(&snap).unwrap();
    let cp = Command::new("cp")
        .args(["-r", "d02.sigil", "fork/d02.sigil"])
        .current_dir(&*d)
        .status()
        .unwrap();
    assert!(cp.success());
    // rebuild the fork with different content: wipe and re-init under the same id is not
    // possible, so truncate history instead (rolled back) and append something else
    let idx = snap.join("d02.sigil/INDEX");
    let t = fs::read_to_string(&idx).unwrap();
    let first: Vec<&str> = t.lines().take(2).collect();
    fs::write(&idx, format!("{}\n", first.join("\n"))).unwrap();
    let _ = fs::remove_file(snap.join("d02.sigil/HEAD"));
    let e = fails(
        &snap,
        &["log", "check-card", "../m1.card", "--child", "d02"],
    );
    assert!(e.contains("rolled back") || e.contains("differs"), "{e}");

    // a tampered card: altered child, reordered children, dropped child, forged signature
    let good = fs::read_to_string(d.join("m1.card")).unwrap();
    let tamper = |s: String| {
        fs::write(d.join("bad.card"), s).unwrap();
        fails(&d, &["log", "check-card", "bad.card"])
    };
    let c1 = good.lines().find(|l| l.starts_with("child-1=")).unwrap();
    let c2 = good.lines().find(|l| l.starts_with("child-2=")).unwrap();
    let swapped = good
        .replace(c1, "@@1")
        .replace(c2, &c1.replacen("child-1=", "child-2=", 1))
        .replace("@@1", &c2.replacen("child-2=", "child-1=", 1));
    assert!(tamper(swapped).contains("does not verify"));
    assert!(tamper(good.replace(c2, "").replace("n=2", "n=1")).contains("does not verify"));
    let sizes = c1.replacen("size=2 ", "size=1 ", 1);
    assert!(tamper(good.replace(c1, &sizes)).contains("does not verify"));
    let root = good.lines().find(|l| l.starts_with("root=")).unwrap();
    let flipped = format!(
        "root={}{}",
        if &root[5..6] == "0" { "1" } else { "0" },
        &root[6..]
    );
    assert!(tamper(good.replace(root, &flipped)).contains("does not verify"));
    let sig = good.lines().find(|l| l.starts_with("sig=")).unwrap();
    let fsig = format!(
        "sig={}{}",
        if &sig[4..5] == "0" { "1" } else { "0" },
        &sig[5..]
    );
    assert!(tamper(good.replace(sig, &fsig)).contains("signature does not verify"));
    // a nested card that was altered no longer matches its parent
    let m2 = fs::read_to_string(d.join("m2.card")).unwrap();
    fs::write(d.join("m2x.card"), &m2).unwrap(); // an identical copy matches
    ok(&d, &["log", "check-card", "y.card", "--child", "m2x.card"]);
    ok(
        &d,
        &[
            "log",
            "card",
            "d02",
            "--name",
            "2026-10-b",
            "-o",
            "other.card",
        ],
    );
    assert!(fails(
        &d,
        &["log", "check-card", "y.card", "--child", "other.card"]
    )
    .contains("does not match"));
}
