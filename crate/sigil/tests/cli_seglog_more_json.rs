//! `--json` on `log compact`, `log check-proof` and `log check-consistency`.
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
fn ok(d: &Path, a: &[&str]) -> String {
    let o = run(d, a);
    assert!(
        o.status.success(),
        "{a:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).to_string()
}
fn pw(d: &Path) {
    fs::write(d.join("pw"), "secret\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join("pw"), fs::Permissions::from_mode(0o600)).unwrap();
    }
}
/// Minimal structural check: balanced braces/brackets outside strings, valid escapes.
fn well_formed(j: &str) {
    let (mut depth, mut in_str, mut esc) = (0i32, false, false);
    for c in j.chars() {
        if in_str {
            if esc {
                assert!("\"\\/bfnrtu".contains(c), "bad escape \\{c} in {j}");
                esc = false;
            } else if c == '\\' {
                esc = true;
            } else if c == '"' {
                in_str = false;
            } else {
                assert!(c as u32 >= 0x20, "raw control char in {j}");
            }
            continue;
        }
        match c {
            '"' => in_str = true,
            '{' | '[' => depth += 1,
            '}' | ']' => depth -= 1,
            _ => {}
        }
        assert!(depth >= 0, "{j}");
    }
    assert!(depth == 0 && !in_str, "{j}");
    assert!(
        j.starts_with("{\"format\":\"sigil-log-") && j.ends_with("}\n"),
        "{j}"
    );
}

fn code(d: &Path, a: &[&str]) -> (i32, String) {
    let o = run(d, a);
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).to_string(),
    )
}

#[test]
fn compact_plan_and_result_as_json() {
    let d = common::scratch("json-compact");
    ok(&d, &["log", "init", "ev"]);
    for i in 1..=3 {
        let f = format!("f{i}");
        fs::write(d.join(&f), format!("{i}\n")).unwrap();
        ok(&d, &["log", "append", "ev", &f]);
    }
    ok(&d, &["log", "tombstone", "ev", "--seq", "2"]);
    let before = fs::read(d.join("ev.sigil/INDEX")).unwrap();
    let j = ok(&d, &["log", "compact", "ev", "--json"]);
    well_formed(&j);
    assert!(
        j.contains("\"format\":\"sigil-log-compact=1\"") && j.contains("\"applied\":false"),
        "{j}"
    );
    assert!(
        j.contains("\"members\":[1,3]") && j.contains("\"new_seq\":5"),
        "{j}"
    );
    assert!(
        j.contains("\"seq\":2,\"path\":\"segments/0000/0000000002.sg1\"")
            && j.contains("\"why\":\"deleted\""),
        "{j}"
    );
    assert!(j.contains("\"root\":null"), "{j}");
    assert_eq!(
        fs::read(d.join("ev.sigil/INDEX")).unwrap(),
        before,
        "dry run wrote"
    );
    let j = ok(&d, &["log", "compact", "ev", "--apply", "--json"]);
    well_formed(&j);
    assert!(
        j.contains("\"applied\":true") && !j.contains("\"root\":null"),
        "{j}"
    );
}

#[test]
fn proof_and_consistency_checks_as_json() {
    let d = common::scratch("json-proofs");
    ok(&d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    ok(&d, &["log", "init", "ev", "--identity", "me.sgk"]);
    fs::create_dir(d.join("dir")).unwrap();
    fs::write(d.join("dir/a \"q\".txt"), "a\n").unwrap();
    ok(&d, &["log", "add", "ev", "dir", "--identity", "me.sgk"]);
    fs::write(d.join("b"), "b\n").unwrap();
    ok(&d, &["log", "append", "ev", "b", "--identity", "me.sgk"]);
    ok(&d, &["log", "prove", "ev", "--seq", "1", "-o", "p1"]);
    let j = ok(
        &d,
        &[
            "log",
            "check-proof",
            "p1",
            "--json",
            "--signer",
            "me.pub",
            "--file",
            "dir/a \"q\".txt",
        ],
    );
    well_formed(&j);
    assert!(
        j.contains("\"ok\":true") && j.contains("\"file_matched\":true"),
        "{j}"
    );
    assert!(j.contains("\"path\":\"a \\\"q\\\".txt\""), "{j}");
    assert!(
        j.contains("\"signed_by\":\"") && j.contains("\"tree_size\":2"),
        "{j}"
    );
    // a failing check: still one JSON object on stdout, exit 2
    let (c, j) = code(&d, &["log", "check-proof", "p1", "--json", "--file", "b"]);
    assert_eq!(c, 2);
    well_formed(&j);
    assert!(
        j.contains("\"ok\":false") && j.contains("\"error\":"),
        "{j}"
    );
    // consistency 1 -> 2
    ok(&d, &["log", "prove-consistency", "ev", "1", "-o", "c1"]);
    let j = ok(
        &d,
        &[
            "log",
            "check-consistency",
            "c1",
            "--json",
            "--signer",
            "me.pub",
        ],
    );
    well_formed(&j);
    assert!(
        j.contains("\"ok\":true") && j.contains("\"old_size\":1") && j.contains("\"new_size\":2"),
        "{j}"
    );
    let bad = format!("1:{}", "00".repeat(32));
    let (c, j) = code(
        &d,
        &["log", "check-consistency", "c1", "--json", "--old", &bad],
    );
    assert_eq!(c, 2);
    well_formed(&j);
    assert!(j.contains("\"ok\":false"), "{j}");
}

#[test]
fn private_proof_json_keeps_sealed_fields_null() {
    let d = common::scratch("json-proof-priv");
    pw(&d);
    ok(&d, &["log", "init", "pv", "--pass-file", "pw"]);
    fs::create_dir(d.join("dir")).unwrap();
    fs::write(d.join("dir/salary.csv"), "1\n").unwrap();
    ok(&d, &["log", "add", "pv", "dir", "--pass-file", "pw"]);
    // a proof cut without the key discloses nothing sealed
    ok(&d, &["log", "prove", "pv", "--seq", "1", "-o", "p1"]);
    let j = ok(&d, &["log", "check-proof", "p1", "--json"]);
    well_formed(&j);
    assert!(
        j.contains("\"sealed\":true") && j.contains("\"size\":null") && j.contains("\"path\":null"),
        "{j}"
    );
    assert!(!j.contains("salary"), "{j}");
}
