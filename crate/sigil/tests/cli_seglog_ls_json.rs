//! `sigil log ls --json`: the listing as one JSON object (`sigil-log-ls=1`).
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
    assert!(j.starts_with("{\"format\":\"sigil-log-ls=1\"") && j.ends_with("}\n"));
}

#[test]
fn public_log_listing_as_json() {
    let d = common::scratch("ls-json");
    ok(&d, &["log", "init", "ev"]);
    fs::create_dir(d.join("dir")).unwrap();
    fs::write(d.join("dir/we\"ird\tname.txt"), "a\n").unwrap();
    fs::write(d.join("dir/x.txt"), "xx\n").unwrap();
    ok(&d, &["log", "add", "ev", "dir"]);
    fs::write(d.join("y"), "y\n").unwrap();
    ok(&d, &["log", "append", "ev", "y"]);
    ok(
        &d,
        &[
            "log",
            "tombstone",
            "ev",
            "--seq",
            "3",
            "--reason",
            "no \"more\"",
        ],
    );
    let j = ok(&d, &["log", "ls", "ev", "--json"]);
    well_formed(&j);
    assert!(
        j.contains("\"entries\":4") && j.contains("\"signed\":false"),
        "{j}"
    );
    assert!(j.contains("\"path\":\"we\\\"ird\\tname.txt\""), "{j}");
    assert!(
        j.contains("\"seq\":3,") && j.contains("\"status\":\"deleted\""),
        "{j}"
    );
    assert!(
        j.contains("\"op\":\"tombstone\"") && j.contains("\"deletes\":\"3\""),
        "{j}"
    );
    assert!(j.contains("\"reason\":\"no \\\"more\\\"\""), "{j}");
    assert!(j.contains("\"pending_deleted_bytes\":2"), "{j}");
    // the anchor matches the text listing
    let text = ok(&d, &["log", "ls", "ev"]);
    let anchor = text
        .lines()
        .find_map(|l| l.strip_prefix("anchor (pin elsewhere, check with `verify --anchor`): "))
        .unwrap();
    assert!(j.contains(&format!("\"anchor\":\"{anchor}\"")), "{j}");
    // a missing segment file shows as missing
    fs::remove_file(d.join("ev.sigil/segments/0000/0000000002.sg1")).unwrap();
    let j = ok(&d, &["log", "ls", "ev", "--json"]);
    assert!(
        j.contains("\"seq\":4,") && j.contains("\"status\":\"missing\""),
        "{j}"
    );
}

#[test]
fn private_log_json_hides_sealed_fields_without_key() {
    let d = common::scratch("ls-json-priv");
    pw(&d);
    ok(&d, &["log", "init", "pv", "--pass-file", "pw"]);
    fs::create_dir(d.join("dir")).unwrap();
    fs::write(d.join("dir/salary-2026.csv"), "100\n").unwrap();
    ok(&d, &["log", "add", "pv", "dir", "--pass-file", "pw"]);
    let j = ok(&d, &["log", "ls", "pv", "--json"]);
    well_formed(&j);
    assert!(
        j.contains("\"private_index\":true") && j.contains("\"index_opened\":false"),
        "{j}"
    );
    assert!(
        j.contains("\"size\":null") && j.contains("\"sealed\":true"),
        "{j}"
    );
    assert!(!j.contains("salary"), "{j}");
    let j = ok(&d, &["log", "ls", "pv", "--json", "--pass-file", "pw"]);
    well_formed(&j);
    assert!(
        j.contains("\"index_opened\":true") && j.contains("\"path\":\"salary-2026.csv\""),
        "{j}"
    );
    assert!(j.contains("\"size\":4"), "{j}");
}
