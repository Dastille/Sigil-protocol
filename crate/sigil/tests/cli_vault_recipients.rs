//! CLI: vaults remember encrypt-to recipients (`to=` CHART lines) across commits.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn sigil(dir: &Path, args: &[&str]) -> Output {
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

fn ok(o: Output) -> String {
    assert!(o.status.success(), "{}", text(&o));
    text(&o)
}

fn fails(o: Output) -> String {
    assert!(!o.status.success(), "expected failure: {}", text(&o));
    text(&o)
}

fn tmp(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("sigil-cli-vrecip-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

fn chart(dir: &Path, live: &str) -> String {
    fs::read_to_string(dir.join(format!("{live}.sgv/CHART"))).unwrap()
}

#[test]
fn single_file_vault_remembers_recipients() {
    let dir = tmp("single");
    ok(sigil(&dir, &["keygen", "-o", "alice.sgk"]));
    ok(sigil(&dir, &["keygen", "-o", "bob.sgk"]));
    fs::write(dir.join("notes.txt"), b"v1 secret").unwrap();
    ok(sigil(&dir, &["vault", "track", "notes.txt", "--to", "alice.sgk.pub"]));
    let c = chart(&dir, "notes.txt");
    assert_eq!(c.matches("\nto=").count(), 1, "{c}");
    assert!(!c.contains("alice"), "CHART stores keys, not paths: {c}");

    // Commit with no --to: still encrypt-to alice.
    fs::write(dir.join("notes.txt"), b"v2 secret edit").unwrap();
    let out = ok(sigil(&dir, &["vault", "commit", "notes.txt"]));
    assert!(out.contains("v2") && out.contains("(remembered)"), "{out}");
    fs::remove_file(dir.join("notes.txt")).unwrap();
    fails(sigil(&dir, &["vault", "restore", "notes.txt"]));
    ok(sigil(&dir, &["vault", "restore", "notes.txt", "--identity", "alice.sgk"]));
    assert_eq!(fs::read(dir.join("notes.txt")).unwrap(), b"v2 secret edit");

    // Writable export → commit --from-export also stays encrypt-to.
    ok(sigil(
        &dir,
        &["mount", "notes.txt", "view", "--vault", "--identity", "alice.sgk", "--export-dir", "ex", "--writable"],
    ));
    let payload = fs::read_dir(dir.join("ex"))
        .unwrap()
        .map(|e| e.unwrap().path())
        .find(|p| !p.file_name().unwrap().to_str().unwrap().starts_with('.'))
        .unwrap();
    fs::write(&payload, b"v3 from export").unwrap();
    let out = ok(sigil(&dir, &["vault", "commit", "--from-export", "ex"]));
    assert!(out.contains("v3") && out.contains("(remembered)"), "{out}");
    fs::remove_file(dir.join("notes.txt")).unwrap();
    fails(sigil(&dir, &["vault", "restore", "notes.txt"]));
    ok(sigil(&dir, &["vault", "restore", "notes.txt", "--identity", "alice.sgk"]));
    assert_eq!(fs::read(dir.join("notes.txt")).unwrap(), b"v3 from export");

    // --to on commit replaces the remembered set (now bob only).
    fs::write(dir.join("notes.txt"), b"v4 for bob").unwrap();
    let out = ok(sigil(&dir, &["vault", "commit", "notes.txt", "--to", "bob.sgk.pub"]));
    assert!(out.contains("(now remembered)"), "{out}");
    fs::write(dir.join("notes.txt"), b"v5 still bob").unwrap();
    ok(sigil(&dir, &["vault", "commit", "notes.txt"]));
    fails(sigil(&dir, &["vault", "restore", "notes.txt", "--identity", "alice.sgk"]));
    ok(sigil(&dir, &["vault", "restore", "notes.txt", "--identity", "bob.sgk"]));
    assert_eq!(fs::read(dir.join("notes.txt")).unwrap(), b"v5 still bob");

    // vault recipients: show, set (two), clear.
    let out = ok(sigil(&dir, &["vault", "recipients", "notes.txt"]));
    assert!(out.contains("1 remembered recipient"), "{out}");
    let out = ok(sigil(&dir, &["vault", "recipients", "notes.txt", "--to", "alice.sgk.pub", "--to", "bob.sgk.pub"]));
    assert!(out.contains("2 remembered recipients"), "{out}");
    let out = ok(sigil(&dir, &["vault", "recipients", "notes.txt", "--clear"]));
    assert!(out.contains("none remembered"), "{out}");
    assert!(chart(&dir, "notes.txt").contains("\nto=-\n"));
    fs::write(dir.join("notes.txt"), b"v6 plain on purpose").unwrap();
    ok(sigil(&dir, &["vault", "commit", "notes.txt"]));
    fs::remove_file(dir.join("notes.txt")).unwrap();
    ok(sigil(&dir, &["vault", "restore", "notes.txt"]));
    assert_eq!(fs::read(dir.join("notes.txt")).unwrap(), b"v6 plain on purpose");
    // Old encrypt-to versions are untouched.
    fails(sigil(&dir, &["vault", "restore", "notes.txt", "--version", "5"]));
    ok(sigil(&dir, &["vault", "restore", "notes.txt", "--version", "5", "--identity", "bob.sgk"]));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn plain_vault_chart_unchanged_and_legacy_guard() {
    let dir = tmp("legacy");
    ok(sigil(&dir, &["keygen", "-o", "alice.sgk"]));
    // Plain vault: no to= lines at all (byte-compatible CHART).
    fs::write(dir.join("plain.txt"), b"p1").unwrap();
    ok(sigil(&dir, &["vault", "track", "plain.txt"]));
    fs::write(dir.join("plain.txt"), b"p2").unwrap();
    ok(sigil(&dir, &["vault", "commit", "plain.txt"]));
    assert!(!chart(&dir, "plain.txt").contains("to="));

    // Simulate a chart made before remembered recipients: strip the to= line.
    fs::write(dir.join("old.txt"), b"o1").unwrap();
    ok(sigil(&dir, &["vault", "track", "old.txt", "--to", "alice.sgk.pub"]));
    let stripped: String = chart(&dir, "old.txt")
        .lines()
        .filter(|l| !l.starts_with("to="))
        .map(|l| format!("{l}\n"))
        .collect();
    fs::write(dir.join("old.txt.sgv/CHART"), stripped).unwrap();
    fs::write(dir.join("old.txt"), b"o2").unwrap();
    let e = fails(sigil(&dir, &["vault", "commit", "old.txt"]));
    assert!(e.contains("encrypt-to") && e.contains("--to"), "{e}");
    // Passing --to once heals it; later commits remember.
    ok(sigil(&dir, &["vault", "commit", "old.txt", "--to", "alice.sgk.pub"]));
    fs::write(dir.join("old.txt"), b"o3").unwrap();
    ok(sigil(&dir, &["vault", "commit", "old.txt"]));
    fails(sigil(&dir, &["vault", "restore", "old.txt"]));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn folder_vault_remembers_recipients() {
    let dir = tmp("folder");
    ok(sigil(&dir, &["keygen", "-o", "alice.sgk"]));
    fs::create_dir_all(dir.join("photos/sub")).unwrap();
    fs::write(dir.join("photos/a.txt"), b"alpha").unwrap();
    fs::write(dir.join("photos/sub/b.txt"), b"beta").unwrap();
    ok(sigil(&dir, &["vault", "track", "photos", "--to", "alice.sgk.pub"]));
    assert!(chart(&dir, "photos").contains("\nto="));
    fs::write(dir.join("photos/a.txt"), b"alpha two").unwrap();
    let out = ok(sigil(&dir, &["vault", "commit", "photos"]));
    assert!(out.contains("v2") && out.contains("(remembered)"), "{out}");
    fs::remove_dir_all(dir.join("photos")).unwrap();
    fails(sigil(&dir, &["vault", "restore", "photos"]));
    ok(sigil(&dir, &["vault", "restore", "photos", "--identity", "alice.sgk"]));
    assert_eq!(fs::read(dir.join("photos/a.txt")).unwrap(), b"alpha two");
    let _ = fs::remove_dir_all(&dir);
}
