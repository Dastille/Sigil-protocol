//! `sigil log add-signer`: pin a first signer on a log created unsigned.
mod common;

use std::path::Path;
use std::process::{Command, Output, Stdio};

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(common::pass_via_file(args))
        .stdin(Stdio::null())
        .output()
        .expect("run sigil")
}

fn ok(dir: &Path, args: &[&str]) -> String {
    let o = run(dir, args);
    assert!(
        o.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn fails(dir: &Path, args: &[&str], want: &str) {
    let o = run(dir, args);
    let err = String::from_utf8_lossy(&o.stderr);
    assert!(!o.status.success(), "{args:?} should fail");
    assert!(err.contains(want), "{args:?}: {err}");
}

#[test]
fn add_signer_to_unsigned_log() {
    let d = common::scratch("log-add-signer");
    ok(&d, &["keygen", "-o", "me.sgk"]);
    ok(&d, &["keygen", "-o", "eve.sgk"]);
    std::fs::write(d.join("a.json"), b"{\"a\":1}").expect("w");
    std::fs::write(d.join("junk.sgk"), b"not a key").expect("w");
    ok(&d, &["log", "init", "ev"]);
    ok(&d, &["log", "append", "ev", "a.json"]);

    // a bad identity file is refused and leaves the log unsigned
    let o = run(&d, &["log", "add-signer", "ev", "--identity", "junk.sgk"]);
    assert!(!o.status.success());
    ok(&d, &["log", "append", "ev", "a.json"]);

    let out = ok(&d, &["log", "add-signer", "ev", "--identity", "me.sgk"]);
    assert!(
        out.contains("signer added") && out.contains("2 earlier entries"),
        "{out}"
    );

    // verifies, pinned to the new key, and reports when it was added
    let v = ok(&d, &["log", "verify", "ev", "--signer", "me.sgk.pub"]);
    assert!(v.contains("healthy"), "{v}");
    let o = run(&d, &["log", "verify", "ev", "--signer", "eve.sgk.pub"]);
    assert!(!o.status.success(), "wrong pinned signer must fail");
    let j = ok(&d, &["log", "verify", "ev", "--json"]);
    assert!(j.contains("signer-added"), "{j}");

    // writers now need the key, and only that key
    fails(&d, &["log", "append", "ev", "a.json"], "--identity");
    fails(
        &d,
        &["log", "append", "ev", "a.json", "--identity", "eve.sgk"],
        "pinned",
    );
    ok(
        &d,
        &["log", "append", "ev", "a.json", "--identity", "me.sgk"],
    );
    ok(&d, &["log", "verify", "ev", "--signer", "me.sgk.pub"]);

    // already signed: refused, pointing at rotate-signer
    fails(
        &d,
        &["log", "add-signer", "ev", "--identity", "eve.sgk"],
        "rotate-signer",
    );
    fails(
        &d,
        &["log", "add-signer", "nope", "--identity", "me.sgk"],
        "",
    );

    // and it can still be handed over afterwards
    ok(
        &d,
        &[
            "log",
            "rotate-signer",
            "ev",
            "--identity",
            "me.sgk",
            "--new",
            "eve.sgk.pub",
        ],
    );
    ok(
        &d,
        &["log", "append", "ev", "a.json", "--identity", "eve.sgk"],
    );
    ok(&d, &["log", "verify", "ev", "--signer", "me.sgk.pub"]);
}

#[test]
fn add_signer_to_empty_unsigned_log() {
    let d = common::scratch("log-add-signer-empty");
    ok(&d, &["keygen", "-o", "me.sgk"]);
    std::fs::write(d.join("a.json"), b"x").expect("w");
    ok(&d, &["log", "init", "ev"]);
    let out = ok(&d, &["log", "add-signer", "ev", "--identity", "me.sgk"]);
    assert!(out.contains("0 earlier entries"), "{out}");
    ok(
        &d,
        &["log", "append", "ev", "a.json", "--identity", "me.sgk"],
    );
    ok(&d, &["log", "verify", "ev", "--signer", "me.sgk.pub"]);
}
