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

#[test]
fn apply_runs_only_when_healthy_and_with_a_rule() {
    let d = common::scratch("retain-apply");
    fs::write(d.join("pw"), "secret\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join("pw"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    sigil(&d, &["log", "init", "ev", "--pass-file", "pw"]);
    for i in 1..=3 {
        let f = format!("f{i}");
        fs::write(d.join(&f), format!("batch {i}\n")).unwrap();
        sigil(&d, &["log", "append", "ev", &f, "--pass-file", "pw"]);
    }
    sigil(&d, &["log", "tombstone", "ev", "--seq", "2"]);
    let dir = d.join("ev.sigil");
    let before = snapshot(&dir);
    // refused before anything runs: no rule, seal without --apply, literal passphrases
    for a in [
        vec!["ev", "--pass-file", "pw", "--apply"],
        vec!["ev", "--pass-file", "pw", "--seal-pass-file", "pw"],
        vec!["ev", "--pass", "secret", "--apply", "--older-than", "0"],
        vec![
            "ev",
            "--pass-file",
            "pw",
            "--apply",
            "--older-than",
            "0",
            "--seal-pass",
            "x",
        ],
    ] {
        let (c, o) = retain(&d, &a);
        assert_eq!(c, 3, "{a:?}: {o}");
    }
    // warnings + --strict: apply is skipped
    let (c, o) = retain(
        &d,
        &[
            "ev",
            "--pass-file",
            "pw",
            "--apply",
            "--older-than",
            "0",
            "--seal-pass-file",
            "pw",
            "--strict",
        ],
    );
    assert_eq!(c, 1, "{o}");
    assert!(o.contains("applied=SKIPPED"), "{o}");
    // no key for the merged segment: compact refuses, exit 3
    let (c, o) = retain(
        &d,
        &["ev", "--pass-file", "pw", "--apply", "--older-than", "0"],
    );
    assert_eq!(c, 3, "{o}");
    assert!(o.contains("applied=FAILED"), "{o}");
    assert!(
        before == snapshot(&dir),
        "a refused or skipped run changed the log"
    );
    // healthy enough (warnings) + rule + seal key: applied, then verified
    let (c, o) = retain(
        &d,
        &[
            "ev",
            "--pass-file",
            "pw",
            "--apply",
            "--older-than",
            "0",
            "--seal-pass-file",
            "pw",
        ],
    );
    assert_eq!(c, 0, "{o}");
    assert!(o.contains("applied=yes"), "{o}");
    assert!(!dir.join("segments/0000/0000000002.sg1").exists());
    for (s, body) in [("1", "batch 1\n"), ("3", "batch 3\n")] {
        let out = sigil(&d, &["log", "read", "ev", "--seq", s, "--pass-file", "pw"]);
        assert_eq!(out, body);
    }
    // afterwards: healthy, nothing left to drop
    let (c, o) = retain(&d, &["ev", "--pass-file", "pw", "--strict"]);
    assert_eq!(c, 0, "{o}");
    assert!(o.contains("health=healthy"), "{o}");
    // problems: apply is skipped, exit 2
    let segs: Vec<_> = fs::read_dir(dir.join("segments/0000"))
        .unwrap()
        .flatten()
        .collect();
    fs::remove_file(segs[0].path()).unwrap();
    let after_damage = snapshot(&dir);
    let (c, o) = retain(
        &d,
        &[
            "ev",
            "--pass-file",
            "pw",
            "--apply",
            "--older-than",
            "0",
            "--seal-pass-file",
            "pw",
        ],
    );
    assert_eq!(c, 2, "{o}");
    assert!(o.contains("applied=SKIPPED"), "{o}");
    assert!(after_damage == snapshot(&dir));
}
