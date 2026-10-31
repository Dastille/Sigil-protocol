//! `--json` on the prove / card family (file to `-o`, summary on stdout) and on `privatize`, `pad`, `enable-segment-keys`, `add-signer`, `rotate-signer`, `adopt`.
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
fn log_with_two(d: &Path) {
    ok(d, &["log", "init", "ev"]);
    fs::write(d.join("a"), "one\n").unwrap();
    ok(d, &["log", "append", "ev", "a"]);
    ok(d, &["log", "append", "ev", "a"]);
}

#[test]
fn prove_and_card_family_write_the_file_and_describe_it() {
    let d = common::scratch("json-prove-card");
    log_with_two(&d);
    // --json without -o: refused, nothing on stdout but the ok:false line
    let j = json_fail(
        &d,
        &["log", "prove", "ev", "--seq", "1", "--json"],
        "sigil-log-prove=1",
    );
    assert!(
        j.contains("needs -o") && !j.contains("sigil-log-proof"),
        "{j}"
    );
    json_fail(
        &d,
        &["log", "card", "ev.sigil", "--name", "c", "--json"],
        "sigil-log-card=1",
    );
    // prove: same file as without --json; JSON never holds the proof body
    let plain = ok(&d, &["log", "prove", "ev", "--seq", "1"]);
    let j = ok(
        &d,
        &["log", "prove", "ev", "--seq", "1", "-o", "p.txt", "--json"],
    );
    well_formed(&j);
    assert!(
        j.starts_with("{\"format\":\"sigil-log-prove=1\",\"ok\":true,\"output\":\"p.txt\",\"kind\":\"inclusion-proof\",\"seq\":1,\"size\":2"),
        "{j}"
    );
    assert_eq!(fs::read_to_string(d.join("p.txt")).unwrap(), plain);
    let first_line = plain.lines().next().unwrap_or("");
    assert!(!j.contains(first_line), "{j}");
    ok(&d, &["log", "check-proof", "p.txt"]);
    // consistency 1 -> 2
    let j = ok(
        &d,
        &[
            "log",
            "prove-consistency",
            "ev",
            "1",
            "-o",
            "k.txt",
            "--json",
        ],
    );
    well_formed(&j);
    assert!(
        j.contains("\"kind\":\"consistency-proof\",\"old_size\":1") && j.contains("\"new_size\":2"),
        "{j}"
    );
    ok(&d, &["log", "check-consistency", "k.txt"]);
    // card + one-child receipt
    let j = ok(
        &d,
        &[
            "log", "card", "ev.sigil", "--name", "c-1", "-o", "c.txt", "--json",
        ],
    );
    well_formed(&j);
    assert!(
        j.contains("\"kind\":\"card\",\"name\":\"c-1\",\"children\":1")
            && j.contains("\"signer\":null"),
        "{j}"
    );
    ok(&d, &["log", "check-card", "c.txt"]);
    let j = ok(
        &d,
        &["log", "card-prove", "c.txt", "1", "-o", "r.txt", "--json"],
    );
    well_formed(&j);
    assert!(
        j.contains("\"kind\":\"card-child-receipt\",\"card\":\"c-1\",\"child_index\":1"),
        "{j}"
    );
    ok(&d, &["log", "check-card-child", "r.txt"]);
    json_fail(
        &d,
        &["log", "card-prove", "c.txt", "9", "-o", "r2.txt", "--json"],
        "sigil-log-card-prove=1",
    );
    assert!(!d.join("r2.txt").exists());
}

#[test]
fn log_admin_commands_as_json() {
    let d = common::scratch("json-log-admin");
    log_with_two(&d);
    fs::write(d.join("pw"), "admin-secret\n").unwrap();
    {
        #[cfg(unix)]
        use std::os::unix::fs::PermissionsExt;
        #[cfg(unix)]
        fs::set_permissions(d.join("pw"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    ok(&d, &["keygen", "-o", "a.sgk"]);
    ok(&d, &["keygen", "-o", "b.sgk"]);
    // public log cannot pad: ok:false
    json_fail(&d, &["log", "pad", "ev", "--json"], "sigil-log-pad=1");
    // privatize to a padded private copy
    let j = ok(
        &d,
        &[
            "log",
            "privatize",
            "ev",
            "pv",
            "--pass-file",
            "pw",
            "--pad",
            "--json",
        ],
    );
    well_formed(&j);
    assert!(
        j.starts_with("{\"format\":\"sigil-log-privatize=1\",\"ok\":true"),
        "{j}"
    );
    assert!(
        j.contains("\"copied\":2") && j.contains("\"pad\":true"),
        "{j}"
    );
    assert!(!j.contains("admin-secret"), "{j}");
    let j = ok(&d, &["log", "pad", "pv", "--json"]);
    assert_eq!(
        j,
        "{\"format\":\"sigil-log-pad=1\",\"ok\":true,\"changed\":false}\n"
    );
    // segment keys on, then again
    let j = ok(&d, &["log", "enable-segment-keys", "ev", "--json"]);
    assert!(j.contains("\"changed\":true,\"from_seq\":3"), "{j}");
    let j = ok(&d, &["log", "enable-segment-keys", "ev", "--json"]);
    assert!(j.contains("\"changed\":false,\"from_seq\":null"), "{j}");
    // signer added, then handed over
    let j = ok(
        &d,
        &["log", "add-signer", "ev", "--identity", "a.sgk", "--json"],
    );
    well_formed(&j);
    assert!(
        j.contains("\"signer\":\"") && j.contains("\"covered\":"),
        "{j}"
    );
    json_fail(
        &d,
        &[
            "log",
            "rotate-signer",
            "ev",
            "--identity",
            "a.sgk",
            "--new",
            "nope.pub",
            "--json",
        ],
        "sigil-log-rotate-signer=1",
    );
    let j = ok(
        &d,
        &[
            "log",
            "rotate-signer",
            "ev",
            "--identity",
            "a.sgk",
            "--new",
            "b.sgk.pub",
            "--json",
        ],
    );
    well_formed(&j);
    assert!(j.contains("\"handovers\":1"), "{j}");
    // adopt a loose star
    fs::write(d.join("x"), "loose\n").unwrap();
    ok(&d, &["seal", "x", "-o", "x.sg1"]);
    ok(&d, &["log", "init", "ad"]);
    let j = ok(&d, &["log", "adopt", "ad", "x.sg1", "--dry-run", "--json"]);
    assert!(
        j.contains("\"dry_run\":true") && j.contains("\"root\":null"),
        "{j}"
    );
    let j = ok(&d, &["log", "adopt", "ad", "x.sg1", "--json"]);
    well_formed(&j);
    assert!(
        j.contains("\"ok\":true") && j.contains("\"adopted\":1"),
        "{j}"
    );
}
