//! Card follow-ups: one-child receipts (`log card-prove` / `log check-card-child`) and card
//! consistency (`log check-card-consistency`).
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
    assert_eq!(
        o.status.code(),
        Some(2),
        "expected exit 2 {a:?}: {}",
        text(&o)
    );
    text(&o)
}
fn append(d: &Path, log: &str, body: &str) {
    fs::write(d.join("b.txt"), body).unwrap();
    ok(d, &["log", "append", log, "b.txt", "--identity", "me.sgk"]);
}
fn log_id(d: &Path, card: &str, k: usize) -> String {
    let t = fs::read_to_string(d.join(card)).unwrap();
    let l = t
        .lines()
        .find(|l| l.starts_with(&format!("child-{k}=")))
        .unwrap();
    l.split_whitespace()
        .find_map(|w| w.strip_prefix("log="))
        .unwrap()
        .to_string()
}

fn setup(d: &Path) {
    ok(d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    ok(d, &["keygen", "-o", "eve.sgk", "--pub-out", "eve.pub"]);
    for day in ["d01", "d02", "d03"] {
        ok(d, &["log", "init", day, "--identity", "me.sgk"]);
        append(d, day, &format!("{day} a\n"));
    }
}

#[test]
fn one_child_receipts() {
    let d = common::scratch("card-rcpt");
    setup(&d);
    ok(
        &d,
        &[
            "log",
            "card",
            "d01",
            "d02",
            "d03",
            "--name",
            "m",
            "--identity",
            "me.sgk",
            "-o",
            "m.card",
        ],
    );
    ok(
        &d,
        &[
            "log",
            "card",
            "m.card",
            "d01",
            "--name",
            "y",
            "--identity",
            "me.sgk",
            "-o",
            "y.card",
        ],
    );
    let id2 = log_id(&d, "m.card", 2);

    // by number and by log id: same receipt
    ok(&d, &["log", "card-prove", "m.card", "2", "-o", "r2"]);
    ok(&d, &["log", "card-prove", "m.card", &id2, "-o", "r2b"]);
    assert_eq!(
        fs::read(d.join("r2")).unwrap(),
        fs::read(d.join("r2b")).unwrap()
    );
    let r = fs::read_to_string(d.join("r2")).unwrap();
    assert!(
        !r.contains(&log_id(&d, "m.card", 1)) && !r.contains(&log_id(&d, "m.card", 3)),
        "other children leak"
    );
    let o = ok(
        &d,
        &[
            "log",
            "check-card-child",
            "r2",
            "--signer",
            "me.pub",
            "--expect",
            &id2,
            "--child",
            "d02",
        ],
    );
    assert!(
        o.contains("card receipt OK: child-2 of m") && o.contains("log matches at 1"),
        "{o}"
    );
    // still valid after the log grows (the card's state is a prefix)
    append(&d, "d02", "more\n");
    ok(&d, &["log", "check-card-child", "r2", "--child", "d02"]);
    // nested card child, by name; checked against the card file
    ok(&d, &["log", "card-prove", "y.card", "m", "-o", "rm"]);
    assert!(
        ok(&d, &["log", "check-card-child", "rm", "--child", "m.card"])
            .contains("card file matches")
    );

    // fail closed
    assert!(fails(
        &d,
        &["log", "check-card-child", "r2", "--signer", "eve.pub"]
    )
    .contains("not by the required key"));
    assert!(
        fails(&d, &["log", "check-card-child", "r2", "--expect", "nope"]).contains("not \"nope\"")
    );
    assert!(
        fails(&d, &["log", "check-card-child", "r2", "--child", "d01"])
            .contains("is not the proved child")
    );
    let t = |from: &str, to: &str, name: &str| {
        fs::write(d.join(name), r.replacen(from, to, 1)).unwrap();
        fails(&d, &["log", "check-card-child", name])
    };
    assert!(t("index=2", "index=1", "x1").contains("do not lead to root"));
    assert!(t("n=3", "n=4", "x2").contains("does not verify"));
    assert!(t("size=1 ", "size=2 ", "x3").contains("does not verify"));
    assert!(t("name=m", "name=n", "x4").contains("card signature"));
    let path = r.lines().find(|l| l.starts_with("path=")).unwrap();
    assert!(t(path, "path=", "x5").contains("do not lead to root"));
    assert!(!run(&d, &["log", "card-prove", "m.card", "9"])
        .status
        .success());
    assert!(!run(&d, &["log", "card-prove", "m.card", "nope"])
        .status
        .success());
}

#[test]
fn card_consistency() {
    let d = common::scratch("card-cons");
    setup(&d);
    ok(
        &d,
        &[
            "log",
            "card",
            "d01",
            "d02",
            "--name",
            "m",
            "--identity",
            "me.sgk",
            "-o",
            "old.card",
        ],
    );
    ok(
        &d,
        &[
            "log",
            "card",
            "old.card",
            "--name",
            "y",
            "--identity",
            "me.sgk",
            "-o",
            "yold.card",
        ],
    );
    // d01 grows; prove it with a consistency proof file
    let root1 = {
        let t = fs::read_to_string(d.join("old.card")).unwrap();
        let l = t
            .lines()
            .find(|l| l.starts_with("child-1="))
            .unwrap()
            .to_string();
        l.split_whitespace()
            .find_map(|w| w.strip_prefix("root="))
            .unwrap()
            .to_string()
    };
    append(&d, "d01", "d01 b\n");
    ok(
        &d,
        &[
            "log",
            "card",
            "d01",
            "d02",
            "d03",
            "--name",
            "m",
            "--identity",
            "me.sgk",
            "-o",
            "new.card",
        ],
    );
    ok(
        &d,
        &[
            "log",
            "card",
            "new.card",
            "--name",
            "y",
            "--identity",
            "me.sgk",
            "-o",
            "ynew.card",
        ],
    );

    // unproved growth refused; proved by the log or by a proof file
    assert!(fails(
        &d,
        &["log", "check-card-consistency", "old.card", "new.card"]
    )
    .contains("no proof"));
    let o = ok(
        &d,
        &[
            "log",
            "check-card-consistency",
            "old.card",
            "new.card",
            "--child",
            "d01",
            "--signer",
            "me.pub",
        ],
    );
    assert!(
        o.contains("card consistency OK: m (2 → 3 children)")
            && o.contains("(new)")
            && o.contains("unchanged"),
        "{o}"
    );
    ok(
        &d,
        &[
            "log",
            "prove-consistency",
            "d01",
            &format!("1:{root1}"),
            "-o",
            "c.proof",
        ],
    );
    fs::rename(d.join("d01.sigil"), d.join("away.sigil")).unwrap();
    ok(
        &d,
        &[
            "log",
            "check-card-consistency",
            "old.card",
            "new.card",
            "--proof",
            "c.proof",
        ],
    );
    fs::rename(d.join("away.sigil"), d.join("d01.sigil")).unwrap();
    // nested: needs both versions of the changed card
    assert!(fails(
        &d,
        &["log", "check-card-consistency", "yold.card", "ynew.card"]
    )
    .contains("--pair"));
    ok(
        &d,
        &[
            "log",
            "check-card-consistency",
            "yold.card",
            "ynew.card",
            "--pair",
            "old.card",
            "new.card",
            "--child",
            "d01",
        ],
    );

    // dropped child, swapped direction, other signer, other name
    ok(
        &d,
        &[
            "log",
            "card",
            "d01",
            "--name",
            "m",
            "--identity",
            "me.sgk",
            "-o",
            "drop.card",
        ],
    );
    assert!(fails(
        &d,
        &[
            "log",
            "check-card-consistency",
            "new.card",
            "drop.card",
            "--child",
            "d01"
        ]
    )
    .contains("dropped"));
    assert!(fails(
        &d,
        &[
            "log",
            "check-card-consistency",
            "new.card",
            "old.card",
            "--child",
            "d01"
        ]
    )
    .contains("goes back"));
    ok(
        &d,
        &[
            "log",
            "card",
            "d01",
            "d02",
            "d03",
            "--name",
            "m",
            "--identity",
            "eve.sgk",
            "-o",
            "eve.card",
        ],
    );
    assert!(fails(
        &d,
        &[
            "log",
            "check-card-consistency",
            "old.card",
            "eve.card",
            "--child",
            "d01"
        ]
    )
    .contains("signed by"));
    assert!(fails(
        &d,
        &[
            "log",
            "check-card-consistency",
            "old.card",
            "new.card",
            "--child",
            "d01",
            "--signer",
            "eve.pub"
        ]
    )
    .contains("required key"));
    ok(
        &d,
        &[
            "log",
            "card",
            "d01",
            "d02",
            "--name",
            "other",
            "--identity",
            "me.sgk",
            "-o",
            "o.card",
        ],
    );
    assert!(
        fails(&d, &["log", "check-card-consistency", "old.card", "o.card"])
            .contains("different names")
    );
    // a fork: the card's d01 root at 2 is not what the log has
    let nt = fs::read_to_string(d.join("new.card")).unwrap();
    fs::write(
        d.join("bad.card"),
        nt.replacen("size=2 root=", "size=2 root=00", 1),
    )
    .unwrap();
    assert!(fails(
        &d,
        &[
            "log",
            "check-card-consistency",
            "old.card",
            "bad.card",
            "--child",
            "d01"
        ]
    )
    .contains("does not verify"));
}
