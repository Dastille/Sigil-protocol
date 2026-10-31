//! `--json` on `log init`, `log append`, `log tombstone` and `log shred` (plain and `--rewrite`).
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

fn pw2(d: &Path, name: &str, v: &str) {
    fs::write(d.join(name), format!("{v}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
}
/// A failed `--json` run: non-zero exit, one `ok:false` line whose `exit` matches.
fn json_fail(d: &Path, a: &[&str], format: &str) -> String {
    let (c, j) = code(d, a);
    assert_ne!(c, 0, "{a:?}: {j}");
    well_formed(&j);
    assert!(
        j.starts_with(&format!(
            "{{\"format\":\"{format}\",\"ok\":false,\"exit\":{c},\"error\":"
        )),
        "{j}"
    );
    j
}

#[test]
fn public_log_init_append_tombstone_as_json() {
    let d = common::scratch("json-batch-public");
    let j = ok(&d, &["log", "init", "ev", "--json"]);
    well_formed(&j);
    assert!(
        j.starts_with("{\"format\":\"sigil-log-init=1\",\"ok\":true"),
        "{j}"
    );
    assert!(
        j.contains("\"signer\":null") && j.contains("\"private_index\":false"),
        "{j}"
    );
    fs::write(d.join("b \"1\""), "batch one\n").unwrap();
    let j = ok(&d, &["log", "append", "ev", "b \"1\"", "--json"]);
    well_formed(&j);
    assert!(
        j.starts_with("{\"format\":\"sigil-log-append=1\",\"ok\":true,\"seq\":1,\"size\":10"),
        "{j}"
    );
    assert!(
        j.contains("\"sha256\":\"") && j.contains("\"signed\":false"),
        "{j}"
    );
    ok(&d, &["log", "append", "ev", "b \"1\""]);
    let j = ok(
        &d,
        &[
            "log",
            "tombstone",
            "ev",
            "--from",
            "1",
            "--to",
            "2",
            "--reason",
            "old",
            "--json",
        ],
    );
    well_formed(&j);
    assert!(j.starts_with("{\"format\":\"sigil-log-tombstone=1\",\"ok\":true,\"entry\":3,\"deleted\":[1,2],\"already\":[]"), "{j}");
    assert!(j.contains("\"pending_bytes\":20"), "{j}");
    json_fail(
        &d,
        &["log", "tombstone", "ev", "--seq", "1", "--json"],
        "sigil-log-tombstone=1",
    );
    json_fail(
        &d,
        &["log", "append", "missing.log", "b \"1\"", "--json"],
        "sigil-log-append=1",
    );
    json_fail(&d, &["log", "init", "ev", "--json"], "sigil-log-init=1");
    // plain shred needs a segment-keys log
    json_fail(
        &d,
        &["log", "shred", "ev", "--seq", "1", "--json"],
        "sigil-log-shred=1",
    );
}

#[test]
fn private_segment_keys_log_append_shred_as_json() {
    let d = common::scratch("json-batch-private");
    pw2(&d, "pw", "secret");
    pw2(&d, "bad", "wrong");
    let j = ok(
        &d,
        &[
            "log",
            "init",
            "pv",
            "--segment-keys",
            "--pass-file",
            "pw",
            "--json",
        ],
    );
    assert!(
        j.contains("\"segment_keys\":true,\"private_index\":true,\"pad\":false"),
        "{j}"
    );
    fs::write(d.join("b1"), "one\n").unwrap();
    let j = json_fail(
        &d,
        &["log", "append", "pv", "b1", "--pass-file", "bad", "--json"],
        "sigil-log-append=1",
    );
    assert!(!j.contains("secret") && !j.contains("wrong"), "{j}");
    let j = ok(
        &d,
        &["log", "append", "pv", "b1", "--pass-file", "pw", "--json"],
    );
    assert!(j.contains("\"ok\":true,\"seq\":1"), "{j}");
    ok(&d, &["log", "append", "pv", "b1", "--pass-file", "pw"]);
    // a sealed reason stays sealed: not echoed in the JSON
    let j = ok(
        &d,
        &[
            "log",
            "tombstone",
            "pv",
            "--seq",
            "2",
            "--reason",
            "hush-reason",
            "--pass-file",
            "pw",
            "--json",
        ],
    );
    assert!(
        j.contains("\"deleted\":[2]") && !j.contains("hush-reason"),
        "{j}"
    );
    let j = ok(&d, &["log", "shred", "pv", "--seq", "1", "--json"]);
    well_formed(&j);
    assert!(
        j.starts_with("{\"format\":\"sigil-log-shred=1\",\"ok\":true,\"rewrite\":false,\"entry\":4,\"erased\":[1],\"already\":[],\"rewritten\":[]"),
        "{j}"
    );
    assert!(
        j.contains("\"keys_destroyed\":1") && j.contains("\"files_removed\":1"),
        "{j}"
    );
}

#[test]
fn shred_rewrite_as_json() {
    let d = common::scratch("json-batch-rewrite");
    pw2(&d, "pw", "secret");
    ok(&d, &["log", "init", "ev", "--segment-keys"]);
    for i in 1..=3 {
        let f = format!("f{i}");
        fs::write(d.join(&f), format!("batch {i}\n")).unwrap();
        ok(&d, &["log", "append", "ev", &f, "--pass-file", "pw"]);
    }
    ok(
        &d,
        &[
            "log",
            "compact",
            "ev",
            "--apply",
            "--pass-file",
            "pw",
            "--seal-pass-file",
            "pw",
        ],
    );
    let j = ok(
        &d,
        &[
            "log",
            "shred",
            "ev",
            "--seq",
            "2",
            "--rewrite",
            "--pass-file",
            "pw",
            "--seal-pass-file",
            "pw",
            "--json",
        ],
    );
    well_formed(&j);
    assert!(
        j.starts_with("{\"format\":\"sigil-log-shred=1\",\"ok\":true,\"rewrite\":true,"),
        "{j}"
    );
    assert!(
        j.contains("\"erased\":[2]") && j.contains("\"rewritten\":[4]"),
        "{j}"
    );
    assert!(!j.contains("secret"), "{j}");
    assert_eq!(
        ok(
            &d,
            &["log", "read", "ev", "--seq", "1", "--pass-file", "pw"]
        ),
        "batch 1\n"
    );
}
