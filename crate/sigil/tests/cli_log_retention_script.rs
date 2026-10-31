//! `scripts/monthly-log-retention.sh`: verify + compaction plan, read-only, cron-friendly exit codes.
#![cfg(unix)]
mod common;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/monthly-log-retention.sh")
}
fn sigil(d: &Path, a: &[&str]) -> String {
    let o = Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(d)
        .args(a)
        .output()
        .expect("sigil");
    assert!(
        o.status.success(),
        "{a:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).to_string()
}
fn retain(d: &Path, a: &[&str]) -> (i32, String) {
    let o: Output = Command::new("bash")
        .arg(script())
        .args(a)
        .current_dir(d)
        .env("SIGIL", env!("CARGO_BIN_EXE_sigil"))
        .output()
        .expect("bash");
    (
        o.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        ),
    )
}
/// Every file under the log folder with its bytes (to prove the run wrote nothing).
fn snapshot(dir: &Path) -> Vec<(PathBuf, Vec<u8>)> {
    let mut out = Vec::new();
    let mut st = vec![dir.to_path_buf()];
    while let Some(p) = st.pop() {
        for e in fs::read_dir(&p).unwrap().flatten() {
            let q = e.path();
            if q.is_dir() {
                st.push(q)
            } else {
                out.push((q.clone(), fs::read(&q).unwrap()))
            }
        }
    }
    out.sort();
    out
}

#[test]
fn healthy_warnings_problems_and_read_only() {
    let d = common::scratch("retain");
    sigil(&d, &["log", "init", "ev"]);
    for b in ["one\n", "two\n", "three\n"] {
        fs::write(d.join("b"), b).unwrap();
        sigil(&d, &["log", "append", "ev", "b"]);
    }
    let (rc, out) = retain(&d, &["ev"]);
    assert_eq!(rc, 0, "{out}");
    assert!(
        out.contains("health=healthy") && out.contains("dry run"),
        "{out}"
    );

    // a tombstone leaves a file to erase: warnings (exit 0, or 1 with --strict); the plan shows it
    sigil(&d, &["log", "tombstone", "ev", "--seq", "1"]);
    let before = snapshot(&d.join("ev.sigil"));
    let (rc, out) = retain(&d, &["ev", "--older-than", "0"]);
    assert_eq!(rc, 0, "{out}");
    assert!(
        out.contains("health=warnings") && out.contains("compaction-plan=ok"),
        "{out}"
    );
    assert!(
        out.to_lowercase().contains("erase"),
        "plan should list the deleted file: {out}"
    );
    let (rc, _) = retain(&d, &["ev", "--strict"]);
    assert_eq!(rc, 1);
    assert_eq!(
        snapshot(&d.join("ev.sigil")),
        before,
        "the check must not change the log"
    );

    // damage: exit 2, summary says PROBLEMS
    let seg = d.join("ev.sigil/segments/0000/0000000002.sg1");
    fs::remove_file(&seg).unwrap();
    let (rc, out) = retain(&d, &["ev"]);
    assert_eq!(rc, 2, "{out}");
    assert!(out.contains("health=PROBLEMS"), "{out}");

    // usage errors: exit 3
    assert_eq!(retain(&d, &[]).0, 3);
    assert_eq!(retain(&d, &["ev", "--bogus"]).0, 3);
    assert_eq!(
        retain(&d, &["ev", "--pass", "x"]).0,
        3,
        "literal passes are not accepted"
    );
}

#[test]
fn private_log_with_pass_file() {
    let d = common::scratch("retain-priv");
    fs::write(d.join("pw"), "secret\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join("pw"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    sigil(&d, &["log", "init", "ev", "--pass-file", "pw"]);
    fs::write(d.join("secret-name.txt"), "x\n").unwrap();
    sigil(
        &d,
        &[
            "log",
            "append",
            "ev",
            "secret-name.txt",
            "--pass-file",
            "pw",
        ],
    );
    let before = snapshot(&d.join("ev.sigil"));
    let (rc, out) = retain(&d, &["ev", "--pass-file", "pw"]);
    assert_eq!(rc, 0, "{out}");
    assert!(out.contains("health=healthy"), "{out}");
    assert_eq!(snapshot(&d.join("ev.sigil")), before);
}
