//! Segment-log mount / --export-dir: one file per live segment, tombstones omitted,
//! compaction members addressable by original seq, decrypt via --pass / --identity.
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
    let d = std::env::temp_dir().join(format!("sigil-log-mount-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn append(d: &Path, name: &str, body: &str) {
    fs::write(d.join("b.txt"), body).unwrap();
    ok(d, &["log", "append", name, "b.txt"]);
}

#[test]
fn export_dir_one_file_per_live_segment() {
    let d = tmp("basic");
    ok(&d, &["log", "init", "ev"]);
    append(&d, "ev", "batch 1\n");
    append(&d, "ev", "batch 2\n");
    append(&d, "ev", "batch 3\n");
    let view = d.join("view");
    fs::create_dir_all(&view).unwrap();
    let out = ok(
        &d,
        &[
            "mount",
            "ev",
            "mnt",
            "--export-dir",
            view.to_str().unwrap(),
        ],
    );
    assert!(out.contains("3 live segment"), "{out}");
    assert_eq!(fs::read(view.join("0000000001")).unwrap(), b"batch 1\n");
    assert_eq!(fs::read(view.join("0000000002")).unwrap(), b"batch 2\n");
    assert_eq!(fs::read(view.join("0000000003")).unwrap(), b"batch 3\n");
    // INDEX unchanged
    let c = d.join("ev.sigil");
    assert!(c.join("INDEX").is_file());
    // plain .sg1 mount still works (non-log) in the same binary path
    ok(&d, &["unseal", c.join("segments/0000/0000000001.sg1").to_str().unwrap(), "-o", "one.txt"]);
    assert_eq!(fs::read(d.join("one.txt")).unwrap(), b"batch 1\n");
}

#[test]
fn export_dir_skips_tombstoned_keeps_compaction_members() {
    let d = tmp("tomb");
    ok(&d, &["log", "init", "ev"]);
    for i in 1..=4 {
        append(&d, "ev", &format!("batch {i}\n"));
    }
    ok(&d, &["log", "tombstone", "ev", "--seq", "2", "--reason", "gone"]);
    ok(&d, &["log", "compact", "ev", "--apply"]);
    let view = d.join("view");
    fs::create_dir_all(&view).unwrap();
    ok(
        &d,
        &[
            "mount",
            "ev.sigil",
            "mnt",
            "--export-dir",
            view.to_str().unwrap(),
        ],
    );
    let names: Vec<_> = fs::read_dir(&view)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert!(!names.iter().any(|n| n == "0000000002"), "{names:?}");
    assert!(names.contains(&"0000000001".to_string()), "{names:?}");
    assert!(names.contains(&"0000000003".to_string()), "{names:?}");
    assert!(names.contains(&"0000000004".to_string()), "{names:?}");
    assert_eq!(fs::read(view.join("0000000003")).unwrap(), b"batch 3\n");
    assert_eq!(fs::read(view.join("0000000001")).unwrap(), b"batch 1\n");
    // matches log read
    assert_eq!(ok(&d, &["log", "read", "ev", "--seq", "3"]), "batch 3\n");
}

#[test]
fn export_dir_passphrase_and_missing_key_error() {
    let d = tmp("pass");
    ok(&d, &["log", "init", "ev"]);
    fs::write(d.join("b.txt"), b"secret\n").unwrap();
    ok(&d, &["log", "append", "ev", "b.txt", "--pass", "house"]);
    let bad = d.join("bad");
    fs::create_dir_all(&bad).unwrap();
    let e = fails(
        &d,
        &[
            "mount",
            "ev",
            "mnt",
            "--export-dir",
            bad.to_str().unwrap(),
        ],
    );
    assert!(
        e.to_lowercase().contains("pass")
            || e.to_lowercase().contains("ward")
            || e.to_lowercase().contains("key")
            || e.to_lowercase().contains("decrypt")
            || e.to_lowercase().contains("identity")
            || e.contains("segment 1"),
        "{e}"
    );
    let view = d.join("view");
    fs::create_dir_all(&view).unwrap();
    ok(
        &d,
        &[
            "mount",
            "ev",
            "mnt",
            "--pass",
            "house",
            "--export-dir",
            view.to_str().unwrap(),
        ],
    );
    assert_eq!(fs::read(view.join("0000000001")).unwrap(), b"secret\n");
}

#[test]
fn export_dir_identity_encrypt_to() {
    let d = tmp("id");
    ok(&d, &["keygen", "-o", "alice.sgk", "--pub-out", "alice.pub"]);
    ok(&d, &["log", "init", "ev"]);
    fs::write(d.join("b.txt"), b"for-alice\n").unwrap();
    ok(
        &d,
        &[
            "log",
            "append",
            "ev",
            "b.txt",
            "--to",
            "alice.pub",
        ],
    );
    let bad = d.join("bad");
    fs::create_dir_all(&bad).unwrap();
    fails(
        &d,
        &[
            "mount",
            "ev",
            "mnt",
            "--export-dir",
            bad.to_str().unwrap(),
        ],
    );
    let view = d.join("view");
    fs::create_dir_all(&view).unwrap();
    ok(
        &d,
        &[
            "mount",
            "ev",
            "mnt",
            "--identity",
            "alice.sgk",
            "--export-dir",
            view.to_str().unwrap(),
        ],
    );
    assert_eq!(fs::read(view.join("0000000001")).unwrap(), b"for-alice\n");
}

#[test]
fn writable_and_vault_flags_refused_for_log() {
    let d = tmp("flags");
    ok(&d, &["log", "init", "ev"]);
    append(&d, "ev", "x\n");
    let view = d.join("view");
    fs::create_dir_all(&view).unwrap();
    let e = fails(
        &d,
        &[
            "mount",
            "ev",
            "mnt",
            "--export-dir",
            view.to_str().unwrap(),
            "--writable",
        ],
    );
    assert!(e.contains("--writable"), "{e}");
    let view2 = d.join("view2");
    fs::create_dir_all(&view2).unwrap();
    let e = fails(
        &d,
        &[
            "mount",
            "ev",
            "mnt",
            "--vault",
            "--export-dir",
            view2.to_str().unwrap(),
        ],
    );
    assert!(e.contains("--vault") || e.contains("segment log"), "{e}");
}
