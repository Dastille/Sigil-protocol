//! `sigil log rotate-signer`: hand a signed segment log over to a new signing key.
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
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

fn ok(dir: &Path, args: &[&str]) -> String {
    let o = sigil_cmd(dir, args);
    assert!(o.status.success(), "{args:?}: {}", text(&o));
    text(&o)
}

fn fails(dir: &Path, args: &[&str]) -> String {
    let o = sigil_cmd(dir, args);
    assert!(!o.status.success(), "expected failure {args:?}: {}", text(&o));
    text(&o)
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sigil-log-rotate-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn append(d: &Path, i: usize, key: &str) -> String {
    let f = format!("b{i}.txt");
    fs::write(d.join(&f), format!("batch number {i}\n")).unwrap();
    ok(d, &["log", "append", "ev", &f, "--identity", key])
}

fn anchor_of(ls: &str) -> String {
    ls.lines().find_map(|l| l.split("): ").nth(1).filter(|_| l.starts_with("anchor"))).unwrap().trim().to_string()
}

fn keys(d: &Path, names: &[&str]) {
    for n in names {
        ok(d, &["keygen", "-o", &format!("{n}.sgk"), "--pub-out", &format!("{n}.pub")]);
    }
}

#[test]
fn handover_moves_signing_to_the_new_key_and_everything_earlier_stays_verifiable() {
    let d = tmp("main");
    keys(&d, &["a", "b", "c", "eve"]);
    let init = ok(&d, &["log", "init", "ev", "--identity", "a.sgk"]);
    let a_hex = init.split("signer ").nth(1).unwrap().split(')').next().unwrap().trim().to_string();
    for i in 1..=3 {
        append(&d, i, "a.sgk");
    }
    let pre_anchor = anchor_of(&ok(&d, &["log", "ls", "ev"]));
    ok(&d, &["log", "prove", "ev", "--seq", "2", "-o", "pre.proof"]);
    assert!(fs::read_to_string(d.join("ev.sigil/CONTAINER")).unwrap().contains("log=1"));

    // a hands over to b (only b's public key is needed)
    let o = ok(&d, &["log", "rotate-signer", "ev", "--identity", "a.sgk", "--new", "b.pub"]);
    assert!(o.contains("signer handover 4:") && o.contains("signed by the outgoing key"), "{o}");
    let manifest = fs::read_to_string(d.join("ev.sigil/CONTAINER")).unwrap();
    assert!(manifest.contains("log=4") && manifest.contains(&format!("signer={a_hex}")), "init pin stays: {manifest}");
    assert!(fs::read_to_string(d.join("ev.sigil/INDEX")).unwrap().contains(" op=signer from="));
    ok(&d, &["log", "verify", "ev", "--signer", "a.pub"]);

    // the old key may not write any more; the new one must
    assert!(fails(&d, &["log", "append", "ev", "b3.txt", "--identity", "a.sgk"]).contains("current signer"));
    assert!(append(&d, 5, "b.sgk").contains("(signed)"));
    let ls = ok(&d, &["log", "ls", "ev"]);
    assert!(ls.contains("signer handover:") && ls.contains("signer handed over 1 time(s)"), "{ls}");
    let v = ok(&d, &["log", "verify", "ev", "--anchor", &pre_anchor]);
    assert!(v.contains("signer-handovers") && v.contains("handed over 1×"), "{v}");
    ok(&d, &["log", "verify", "ev", "--signer", "a.pub"]);
    ok(&d, &["log", "verify", "ev", "--signer", "b.pub"]);
    assert!(fails(&d, &["log", "verify", "ev", "--signer", "eve.pub"]).contains("head-signer"));
    ok(&d, &["doctor", "ev"]);
    assert!(fails(&d, &["log", "read", "ev", "--seq", "4"]).contains("signer handover record"));
    assert_eq!(ok(&d, &["log", "read", "ev", "--from", "1", "--to", "5"]).matches("batch number").count(), 4);

    // a receipt cut before the handover keeps verifying under the old key
    ok(&d, &["log", "check-proof", "pre.proof", "--signer", "a.pub", "--file", "b2.txt"]);
    assert!(fails(&d, &["log", "check-proof", "pre.proof", "--signer", "b.pub"]).contains("not by the required key"));
    // a receipt cut now carries the handover: either key of the chain may be required
    ok(&d, &["log", "prove", "ev", "--seq", "2", "-o", "post.proof"]);
    let post = fs::read_to_string(d.join("post.proof")).unwrap();
    assert!(post.contains("handover-1=seq=4 ") && !post.contains("handover-2="), "{post}");
    let o = ok(&d, &["log", "check-proof", "post.proof", "--signer", "a.pub", "--file", "b2.txt"]);
    assert!(o.contains("signer handed over:"), "{o}");
    ok(&d, &["log", "check-proof", "post.proof", "--signer", "b.pub"]);
    assert!(fails(&d, &["log", "check-proof", "post.proof", "--signer", "eve.pub"]).contains("nor handed over"));
    // without the handover line the old key no longer reaches HEAD's signer; a forged one is caught
    let stripped: String = post.lines().filter(|l| !l.starts_with("handover-")).map(|l| format!("{l}\n")).collect();
    fs::write(d.join("stripped.proof"), &stripped).unwrap();
    assert!(fails(&d, &["log", "check-proof", "stripped.proof", "--signer", "a.pub"]).contains("not by the required key"));
    ok(&d, &["log", "check-proof", "stripped.proof", "--signer", "b.pub"]);
    let hl = post.lines().find(|l| l.starts_with("handover-1=")).unwrap();
    let sig = hl.split(" sig=").nth(1).unwrap().split(' ').next().unwrap();
    let flipped = format!("{}{}", if sig.starts_with('0') { "1" } else { "0" }, &sig[1..]);
    fs::write(d.join("forged.proof"), post.replace(sig, &flipped)).unwrap();
    assert!(fails(&d, &["log", "check-proof", "forged.proof", "--signer", "a.pub"]).contains("handover-1 signature does not verify"));
    let eve_hex = {
        let eve = ok(&d, &["log", "init", "evelog", "--identity", "eve.sgk"]);
        eve.split("signer ").nth(1).unwrap().split(')').next().unwrap().trim().to_string()
    };
    let b_hex = hl.split(" to=").nth(1).unwrap().split(' ').next().unwrap();
    fs::write(d.join("redirect.proof"), post.replace(&format!("to={b_hex}"), &format!("to={eve_hex}"))).unwrap();
    assert!(fails(&d, &["log", "check-proof", "redirect.proof", "--signer", "a.pub"]).contains("proof does not verify"));
    // the handover entry itself proves (it holds no bytes)
    ok(&d, &["log", "prove", "ev", "--seq", "4", "-o", "h.proof"]);
    assert!(ok(&d, &["log", "check-proof", "h.proof", "--signer", "a.pub"]).contains("signer handover"));
    assert!(fails(&d, &["log", "check-proof", "h.proof", "--file", "b1.txt"]).contains("holds no bytes"));

    // every writer follows the current signer
    ok(&d, &["log", "tombstone", "ev", "--seq", "1", "--identity", "b.sgk"]);
    assert!(fails(&d, &["log", "compact", "ev", "--apply", "--identity", "a.sgk"]).contains("signing key"));
    ok(&d, &["log", "compact", "ev", "--apply", "--identity", "b.sgk"]);
    ok(&d, &["log", "verify", "ev", "--signer", "a.pub", "--anchor", &pre_anchor]);

    // a second handover: b → c; the chain a → b → c is followed end to end
    ok(&d, &["log", "rotate-signer", "ev", "--identity", "b.sgk", "--new", "c.pub"]);
    append(&d, 9, "c.sgk");
    for k in ["a.pub", "b.pub", "c.pub"] {
        ok(&d, &["log", "verify", "ev", "--signer", k]);
    }
    ok(&d, &["log", "prove", "ev", "--seq", "3", "-o", "two.proof"]);
    assert!(fs::read_to_string(d.join("two.proof")).unwrap().contains("handover-2="));
    let o = ok(&d, &["log", "check-proof", "two.proof", "--signer", "a.pub", "--file", "b3.txt"]);
    assert!(o.matches(" → ").count() == 2, "{o}");
    ok(&d, &["gc", "ev"]);
    let _ = fs::remove_dir_all(&d);
}

#[test]
fn rotate_signer_refusals() {
    let d = tmp("refuse");
    keys(&d, &["a", "b", "eve"]);
    ok(&d, &["log", "init", "plain"]);
    assert!(fails(&d, &["log", "rotate-signer", "plain", "--identity", "a.sgk", "--new", "b.pub"]).contains("created unsigned"));
    ok(&d, &["log", "init", "ev", "--identity", "a.sgk"]);
    append(&d, 1, "a.sgk");
    assert!(fails(&d, &["log", "rotate-signer", "ev", "--identity", "eve.sgk", "--new", "eve.pub"]).contains("pinned to"));
    assert!(fails(&d, &["log", "rotate-signer", "ev", "--identity", "a.sgk", "--new", "a.pub"]).contains("already"));
    assert!(fails(&d, &["log", "rotate-signer", "ev", "--identity", "a.sgk", "--new", "nonsense"]).contains("--new"));
    assert!(fails(&d, &["log", "rotate-signer", "ev", "--identity", "a.sgk", "--new", &"ff".repeat(32)]).contains("not a valid"));
    // nothing was written by the refusals: still log=1, no handover
    assert!(fs::read_to_string(d.join("ev.sigil/CONTAINER")).unwrap().contains("log=1"));
    assert!(!fs::read_to_string(d.join("ev.sigil/INDEX")).unwrap().contains("op=signer"));
    let v = ok(&d, &["log", "verify", "ev", "--signer", "a.pub"]);
    assert!(!v.contains("signer-handovers"), "{v}");
    // an edited handover breaks the chain like any other entry
    ok(&d, &["log", "rotate-signer", "ev", "--identity", "a.sgk", "--new", "b.pub"]);
    let idx = fs::read_to_string(d.join("ev.sigil/INDEX")).unwrap();
    let line = idx.lines().find(|l| l.contains("op=signer")).unwrap();
    let b_hex = line.split(" to=").nth(1).unwrap().split(' ').next().unwrap();
    let eve_hex = ok(&d, &["log", "init", "x", "--identity", "eve.sgk"]).split("signer ").nth(1).unwrap().split(')').next().unwrap().trim().to_string();
    fs::write(d.join("ev.sigil/INDEX"), idx.replace(b_hex, &eve_hex)).unwrap();
    assert!(fails(&d, &["log", "verify", "ev"]).contains("index-chain"));
    assert!(fails(&d, &["log", "append", "ev", "b1.txt", "--identity", "eve.sgk"]).contains("INDEX"));
    let _ = fs::remove_dir_all(&d);
}
