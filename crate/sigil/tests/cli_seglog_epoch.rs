//! `sigil log epoch OLD NEW` / `sigil log check-epoch`: epoch rollover from the command line.
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
fn fails(d: &Path, a: &[&str]) -> (i32, String) {
    let o = run(d, a);
    assert!(!o.status.success(), "expected failure {a:?}: {}", text(&o));
    (o.status.code().unwrap_or(-1), text(&o))
}
fn put(d: &Path, rel: &str, body: &str) {
    let p = d.join("docs").join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, body).unwrap();
}
fn epoch_t(d: &Path, log: &str) -> u64 {
    let idx = fs::read_to_string(d.join(log).join("INDEX")).unwrap();
    let l = idx.lines().nth(1).unwrap();
    assert!(l.contains(" op=epoch "), "{l}");
    l.split_whitespace()
        .find_map(|t| t.strip_prefix("t="))
        .unwrap()
        .parse()
        .unwrap()
}

#[test]
fn backup_log_rollover_restore_and_add() {
    let d = common::scratch("epoch-cli");
    ok(&d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    ok(&d, &["log", "init", "bk", "--identity", "me.sgk"]);
    put(&d, "a.txt", "alpha v1");
    put(&d, "sub/b.txt", "beta");
    put(&d, "gone.txt", "will be deleted");
    ok(&d, &["log", "add", "bk", "docs", "--identity", "me.sgk"]);
    put(&d, "a.txt", "alpha v2");
    ok(&d, &["log", "add", "bk", "docs", "--identity", "me.sgk"]);
    let before = fs::read(d.join("bk.sigil/INDEX")).unwrap();
    let head = fs::read(d.join("bk.sigil/HEAD")).unwrap();

    // no --identity: refused, nothing made
    let (_, e) = fails(&d, &["log", "epoch", "bk", "bk2"]);
    assert!(e.contains("needs --identity"), "{e}");
    assert!(!d.join("bk2.sigil").exists());

    let out = ok(
        &d,
        &[
            "log",
            "epoch",
            "bk",
            "bk2",
            "--identity",
            "me.sgk",
            "--card-out",
            "bk2.card",
        ],
    );
    assert!(
        out.contains("new epoch") && out.contains("Deleting it is your call"),
        "{out}"
    );
    assert_eq!(
        fs::read(d.join("bk.sigil/INDEX")).unwrap(),
        before,
        "archive INDEX untouched"
    );
    assert_eq!(
        fs::read(d.join("bk.sigil/HEAD")).unwrap(),
        head,
        "archive HEAD untouched"
    );
    assert_eq!(
        fs::read(d.join("bk2.card")).unwrap(),
        fs::read(d.join("bk2.sigil/EPOCH.card")).unwrap()
    );
    // --card-out never overwrites; NEW never overwrites
    let (_, e) = fails(
        &d,
        &[
            "log",
            "epoch",
            "bk",
            "bk3",
            "--identity",
            "me.sgk",
            "--card-out",
            "bk2.card",
        ],
    );
    assert!(e.contains("already exists"), "{e}");
    let (_, e) = fails(&d, &["log", "epoch", "bk", "bk2", "--identity", "me.sgk"]);
    assert!(e.contains("already exists"), "{e}");

    let v = ok(&d, &["log", "verify", "bk2"]);
    assert!(
        v.contains("result: healthy") && !v.contains("unknown-file"),
        "{v}"
    );
    let ls = ok(&d, &["log", "ls", "bk2"]);
    assert!(ls.contains("epoch: continues archive"), "{ls}");
    let ls = ok(&d, &["log", "ls", "bk2", "--json"]);
    assert!(
        ls.contains("\"op\":\"epoch\"") && ls.contains("\"prev_size\":4"),
        "{ls}"
    );
    let c = ok(
        &d,
        &[
            "log",
            "check-epoch",
            "bk2",
            "--archive",
            "bk",
            "--signer",
            "me.pub",
        ],
    );
    assert!(
        c.contains("epoch OK") && c.contains("archive checked"),
        "{c}"
    );
    let c = ok(
        &d,
        &["log", "check-epoch", "bk2", "--card", "bk2.card", "--json"],
    );
    assert!(
        c.contains("\"ok\":true") && c.contains("\"archive_size\":null"),
        "{c}"
    );

    // latest versions restore from the new epoch alone
    ok(&d, &["log", "restore", "bk2", "a.txt", "-o", "a.out"]);
    assert_eq!(fs::read_to_string(d.join("a.out")).unwrap(), "alpha v2");
    let t = epoch_t(&d, "bk2.sigil");
    ok(
        &d,
        &[
            "log",
            "restore",
            "bk2",
            "a.txt",
            "--at",
            &t.to_string(),
            "-o",
            "a.at",
        ],
    );
    assert_eq!(fs::read_to_string(d.join("a.at")).unwrap(), "alpha v2");
    // history before the cut needs the archive
    let (_, e) = fails(
        &d,
        &[
            "log",
            "restore",
            "bk2",
            "a.txt",
            "--at",
            &(t - 1).to_string(),
            "-o",
            "x",
        ],
    );
    assert!(
        e.contains("before the epoch cut") && e.contains("archive"),
        "{e}"
    );
    ok(
        &d,
        &["log", "restore", "bk", "a.txt", "--seq", "1", "-o", "a.v1"],
    );
    assert_eq!(fs::read_to_string(d.join("a.v1")).unwrap(), "alpha v1");

    // log add into the new epoch only seals what changed since the copied state
    fs::remove_file(d.join("docs/gone.txt")).unwrap();
    put(&d, "c.txt", "gamma");
    let add = ok(
        &d,
        &[
            "log",
            "add",
            "bk2",
            "docs",
            "--identity",
            "me.sgk",
            "--json",
        ],
    );
    assert!(
        add.contains("\"path\":\"c.txt\"")
            && add.contains("\"unchanged\":2")
            && add.contains("\"missing\":[{\"path\":\"gone.txt\""),
        "{add}"
    );
    assert!(ok(&d, &["log", "verify", "bk2"]).contains("result: healthy"));
    ok(&d, &["log", "check-epoch", "bk2", "--archive", "bk"]);

    // a tampered card: check-epoch exits 2, verify reports the error
    let card = fs::read_to_string(d.join("bk2.sigil/EPOCH.card")).unwrap();
    fs::write(
        d.join("bk2.sigil/EPOCH.card"),
        card.replacen("name=", "name=x", 1),
    )
    .unwrap();
    let (code, e) = fails(&d, &["log", "check-epoch", "bk2"]);
    assert_eq!(code, 2, "{e}");
    let (_, v) = fails(&d, &["log", "verify", "bk2"]);
    assert!(v.contains("epoch-card"), "{v}");
    // the kept copy still checks (card bytes match the line)
    ok(
        &d,
        &[
            "log",
            "check-epoch",
            "bk2",
            "--card",
            "bk2.card",
            "--archive",
            "bk",
        ],
    );
    // a missing archive for the two-step check
    let (code, e) = fails(
        &d,
        &[
            "log",
            "check-epoch",
            "bk2",
            "--card",
            "bk2.card",
            "--archive",
            "nope",
        ],
    );
    assert_eq!(code, 2, "{e}");
}

#[test]
fn not_an_epoch_log_and_json_failure() {
    let d = common::scratch("epoch-cli-neg");
    ok(&d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    ok(&d, &["log", "init", "ev", "--identity", "me.sgk"]);
    let (code, e) = fails(&d, &["log", "check-epoch", "ev", "--json"]);
    assert_eq!(code, 2);
    assert!(
        e.contains("\"ok\":false") && e.contains("not an epoch log"),
        "{e}"
    );
    // an empty log has no HEAD worth closing
    let (_, e) = fails(
        &d,
        &[
            "log",
            "epoch",
            "ev",
            "ev2",
            "--identity",
            "me.sgk",
            "--json",
        ],
    );
    assert!(e.contains("\"ok\":false") && e.contains("no HEAD"), "{e}");
    assert!(!d.join("ev2.sigil").exists());
}
