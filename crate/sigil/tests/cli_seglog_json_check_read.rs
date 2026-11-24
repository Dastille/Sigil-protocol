//! `--json` on `log check-card`, `log check-card-child`, `log check-card-consistency` and metadata-only `log read`.
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

fn fail_line(d: &Path, a: &[&str], format: &str, want: i32) -> String {
    let (c, j) = code(d, a);
    assert_eq!(c, want, "{a:?}: {j}");
    well_formed(&j);
    assert!(
        j.starts_with(&format!("{{\"format\":\"{format}\",\"ok\":false,")),
        "{j}"
    );
    j
}

#[test]
fn check_card_family_as_json() {
    let d = common::scratch("json-check-card");
    ok(&d, &["log", "init", "ev"]);
    fs::write(d.join("a"), "one\n").unwrap();
    ok(&d, &["log", "append", "ev", "a"]);
    ok(
        &d,
        &["log", "card", "ev.sigil", "--name", "c-1", "-o", "old.txt"],
    );
    ok(&d, &["log", "append", "ev", "a"]);
    ok(&d, &["log", "init", "ev2"]);
    ok(&d, &["log", "append", "ev2", "a"]);
    ok(
        &d,
        &[
            "log",
            "card",
            "ev.sigil",
            "ev2.sigil",
            "--name",
            "c-1",
            "-o",
            "new.txt",
        ],
    );

    let j = ok(
        &d,
        &[
            "log",
            "check-card",
            "new.txt",
            "--child",
            "ev.sigil",
            "--child",
            "ev2.sigil",
            "--all",
            "--json",
        ],
    );
    well_formed(&j);
    assert!(
        j.starts_with(
            "{\"format\":\"sigil-log-check-card=1\",\"ok\":true,\"name\":\"c-1\",\"children\":2"
        ),
        "{j}"
    );
    assert!(
        j.contains("\"signed_by\":null") && j.contains("\"checked\":[{\"child\":1"),
        "{j}"
    );
    fs::write(d.join("bad.txt"), "not a card\n").unwrap();
    fail_line(
        &d,
        &["log", "check-card", "bad.txt", "--json"],
        "sigil-log-check-card=1",
        2,
    );

    ok(&d, &["log", "card-prove", "new.txt", "1", "-o", "r.txt"]);
    let j = ok(&d, &["log", "check-card-child", "r.txt", "--json"]);
    well_formed(&j);
    assert!(j.starts_with("{\"format\":\"sigil-log-check-card-child=1\",\"ok\":true,\"card\":\"c-1\",\"children\":2,\"child_index\":1"), "{j}");
    assert!(j.contains("\"matched\":null"), "{j}");
    let j = ok(
        &d,
        &[
            "log",
            "check-card-child",
            "r.txt",
            "--child",
            "ev.sigil",
            "--json",
        ],
    );
    assert!(!j.contains("\"matched\":null"), "{j}");
    fail_line(
        &d,
        &[
            "log",
            "check-card-child",
            "r.txt",
            "--child",
            "ev2.sigil",
            "--json",
        ],
        "sigil-log-check-card-child=1",
        2,
    );

    let j = ok(
        &d,
        &[
            "log",
            "check-card-consistency",
            "old.txt",
            "new.txt",
            "--child",
            "ev.sigil",
            "--json",
        ],
    );
    well_formed(&j);
    assert!(j.starts_with("{\"format\":\"sigil-log-check-card-consistency=1\",\"ok\":true,\"name\":\"c-1\",\"old_children\":1,\"new_children\":2"), "{j}");
    assert!(
        j.contains("\"kept\":[\"") && j.contains("\"added\":[\""),
        "{j}"
    );
    fail_line(
        &d,
        &[
            "log",
            "check-card-consistency",
            "new.txt",
            "old.txt",
            "--json",
        ],
        "sigil-log-check-card-consistency=1",
        2,
    );
}

#[test]
fn read_json_is_metadata_only() {
    let d = common::scratch("json-read");
    fs::write(d.join("pw"), "read-secret\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join("pw"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    // public log: append has no path
    ok(&d, &["log", "init", "ev"]);
    fs::write(d.join("a"), "PAYLOAD-ONE\n").unwrap();
    ok(&d, &["log", "append", "ev", "a"]);
    ok(&d, &["log", "append", "ev", "a"]);
    ok(&d, &["log", "tombstone", "ev", "--seq", "1"]);
    let j = fail_line(&d, &["log", "read", "ev", "--json"], "sigil-log-read=1", 1);
    assert!(j.contains("needs -o") && !j.contains("PAYLOAD"), "{j}");
    let j = ok(&d, &["log", "read", "ev", "-o", "out", "--json"]);
    well_formed(&j);
    assert!(!j.contains("PAYLOAD"), "{j}");
    assert!(j.starts_with("{\"format\":\"sigil-log-read=1\",\"ok\":true,\"output\":\"out\",\"bytes\":12,\"segments\":[{\"seq\":2,\"size\":12,\"sha256\":\""), "{j}");
    assert!(
        j.contains("\"path\":null") && j.contains("\"skipped_deleted\":[1]"),
        "{j}"
    );
    assert_eq!(fs::read(d.join("out")).unwrap(), b"PAYLOAD-ONE\n");
    fail_line(
        &d,
        &["log", "read", "ev", "--seq", "1", "-o", "o1", "--json"],
        "sigil-log-read=1",
        1,
    );

    // private log: the path comes from the opened INDEX; without the key nothing is read
    ok(&d, &["log", "init", "pv", "--pass-file", "pw"]);
    fs::create_dir_all(d.join("dir")).unwrap();
    fs::write(d.join("dir/n \"q\".txt"), "PRIVATE-BYTES\n").unwrap();
    ok(&d, &["log", "add", "pv", "dir", "--pass-file", "pw"]);
    let j = ok(
        &d,
        &[
            "log",
            "read",
            "pv",
            "--seq",
            "1",
            "-o",
            "p.out",
            "--pass-file",
            "pw",
            "--json",
        ],
    );
    well_formed(&j);
    assert!(
        j.contains("\"path\":\"n \\\"q\\\".txt\"")
            && !j.contains("PRIVATE")
            && !j.contains("read-secret"),
        "{j}"
    );
    let j = fail_line(
        &d,
        &["log", "read", "pv", "--seq", "1", "-o", "p2.out", "--json"],
        "sigil-log-read=1",
        1,
    );
    assert!(
        !j.contains("n \\\"q\\\"") && !d.join("p2.out").exists(),
        "{j}"
    );
}
