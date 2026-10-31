//! `scripts/make-recovery-kit.sh` (SFX-DESIGN.md Option 0): refuses bad input, dry run writes
//! nothing, the kit checks out and holds no secrets, and its binary opens the archive.
#![cfg(unix)]
mod common;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn script() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../scripts/make-recovery-kit.sh")
}
fn kit(d: &Path, a: &[&str]) -> (i32, String) {
    let o = Command::new("bash")
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
fn run(bin: &Path, d: &Path, a: &[&str]) -> String {
    let o = Command::new(bin)
        .current_dir(d)
        .args(a)
        .output()
        .expect("run");
    assert!(
        o.status.success(),
        "{a:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).to_string()
}
fn setup(name: &str) -> common::Scratch {
    let d = common::scratch(name);
    fs::write(d.join("pw"), "hunter2-passphrase\n").unwrap();
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join("pw"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    fs::write(d.join("note.txt"), "keep me\n").unwrap();
    let s = Path::new(env!("CARGO_BIN_EXE_sigil"));
    run(
        s,
        &d,
        &["seal", "note.txt", "-o", "note.sg1", "--pass-file", "pw"],
    );
    run(s, &d, &["keygen", "-o", "me.sgk"]);
    d
}

#[test]
fn refuses_missing_or_secret_inputs() {
    let d = setup("kit-refuse");
    let (c, o) = kit(&d, &[]);
    assert_eq!(c, 2, "{o}");
    assert!(o.contains("no ARCHIVE"), "{o}");
    let (c, o) = kit(&d, &["nope.sg1"]);
    assert_eq!(c, 2, "{o}");
    assert!(o.contains("archive not found"), "{o}");
    let (c, o) = kit(&d, &["note.sg1", "--pass-file", "pw"]);
    assert_eq!(c, 2, "{o}");
    assert!(o.contains("never holds secrets"), "{o}");
    let (c, o) = kit(&d, &["me.sgk"]);
    assert_eq!(c, 2, "{o}");
    let (c, o) = kit(&d, &["note.sg1", "--bin", "pw"]);
    assert_eq!(c, 2, "{o}");
    assert!(o.contains("secret-looking"), "{o}");
    let (c, o) = kit(&d, &["note.sg1", "--bin", "missing-bin"]);
    assert_eq!(c, 2, "{o}");
    let (c, o) = kit(&d, &["note.sg1", "--spec", "no-spec.txt"]);
    assert_eq!(c, 2, "{o}");
    let (c, o) = kit(&d, &["note.sg1", "--dest", "no-dir"]);
    assert_eq!(c, 2, "{o}");
    assert!(!d.join("sigil-recovery").exists());
}

#[test]
fn dry_run_then_kit_checks_out_and_opens_the_archive() {
    let d = setup("kit-make");
    let (c, o) = kit(&d, &["note.sg1", "--dry-run"]);
    assert_eq!(c, 0, "{o}");
    assert!(o.contains("RECOVER.txt") && o.contains("bin/sigil-"), "{o}");
    assert!(!d.join("sigil-recovery").exists(), "dry run wrote");

    let (c, o) = kit(&d, &["note.sg1"]);
    assert_eq!(c, 0, "{o}");
    let k = d.join("sigil-recovery");
    let rec = fs::read_to_string(k.join("RECOVER.txt")).unwrap();
    assert!(
        rec.contains("note.sg1   sha256 ") && rec.contains("mend"),
        "{rec}"
    );
    assert!(!rec.contains('@'), "unfilled placeholder: {rec}");
    assert!(k.join("spec/sigil-v1.txt").is_file());
    let sums = fs::read_to_string(k.join("SHA256SUMS")).unwrap();
    assert_eq!(sums.lines().count(), 4, "{sums}");
    let chk = Command::new("sha256sum")
        .args(["-c", "SHA256SUMS"])
        .current_dir(&k)
        .output();
    if let Ok(chk) = chk {
        assert!(
            chk.status.success(),
            "{}",
            String::from_utf8_lossy(&chk.stdout)
        );
    }

    // no secrets: no key files, the passphrase bytes appear nowhere in the kit
    let mut st = vec![k.clone()];
    while let Some(p) = st.pop() {
        for e in fs::read_dir(&p).unwrap().flatten() {
            let q = e.path();
            if q.is_dir() {
                st.push(q);
                continue;
            }
            let n = q.file_name().unwrap().to_string_lossy().to_string();
            assert!(!n.ends_with(".sgk") && n != "pw", "{n}");
            let b = fs::read(&q).unwrap();
            assert!(
                !b.windows(18).any(|w| w == b"hunter2-passphrase"),
                "passphrase in {n}"
            );
        }
    }

    // the kit's own binary follows RECOVER.txt step 4a
    let bin = fs::read_dir(k.join("bin"))
        .unwrap()
        .flatten()
        .next()
        .unwrap()
        .path();
    run(
        &bin,
        &d,
        &["unseal", "note.sg1", "-o", "restored", "--pass-file", "pw"],
    );
    assert_eq!(fs::read(d.join("restored")).unwrap(), b"keep me\n");

    // an existing kit is kept unless --force
    let (c, o) = kit(&d, &["note.sg1"]);
    assert_eq!(c, 2, "{o}");
    assert!(o.contains("--force"), "{o}");
    let (c, o) = kit(&d, &["note.sg1", "--force"]);
    assert_eq!(c, 0, "{o}");
}

fn try_run(bin: &Path, d: &Path, a: &[&str]) -> (i32, String) {
    let o = Command::new(bin)
        .current_dir(d)
        .args(a)
        .output()
        .expect("run");
    (
        o.status.code().unwrap_or(-1),
        format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        ),
    )
}

/// `--check` refuses a damaged archive; the kit hashes a log folder; then RECOVER.txt steps 4b
/// (mend a torn copy), 4c (private log verify / mend / restore) and 4d (gather pieces) work with
/// the kit's own binary.
#[test]
fn check_archives_and_recover_steps_end_to_end() {
    let d = setup("kit-e2e");
    let s = Path::new(env!("CARGO_BIN_EXE_sigil"));
    run(s, &d, &["log", "init", "pv", "--pass-file", "pw"]);
    fs::create_dir_all(d.join("src/sub")).unwrap();
    fs::write(d.join("src/sub/a.txt"), "alpha\n").unwrap();
    fs::write(d.join("src/b.txt"), "beta\n").unwrap();
    run(s, &d, &["log", "add", "pv", "src", "--pass-file", "pw"]);
    let full = fs::read(d.join("note.sg1")).unwrap();
    fs::write(d.join("torn.sg1"), &full[..300.min(full.len())]).unwrap();

    let (c, o) = kit(&d, &["note.sg1", "torn.sg1", "--check"]);
    assert_eq!(c, 2, "{o}");
    assert!(o.contains("check failed for torn.sg1"), "{o}");
    assert!(!d.join("sigil-recovery").exists());

    let (c, o) = kit(&d, &["note.sg1", "pv.sigil", "--check"]);
    assert_eq!(c, 0, "{o}");
    assert!(
        o.contains("checked: note.sg1") && o.contains("checked: pv.sigil"),
        "{o}"
    );
    let k = d.join("sigil-recovery");
    let arch = fs::read_to_string(k.join("ARCHIVES.sha256")).unwrap();
    assert!(
        arch.contains("  note.sg1\n") && arch.contains("  pv.sigil/INDEX\n"),
        "{arch}"
    );
    assert!(arch.contains("pv.sigil/segments/"), "{arch}");
    if let Ok(o) = Command::new("sha256sum")
        .args(["-c", "sigil-recovery/ARCHIVES.sha256"])
        .current_dir(&d)
        .output()
    {
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stdout));
    }
    let rec = fs::read_to_string(k.join("RECOVER.txt")).unwrap();
    assert!(
        rec.contains("ARCHIVES.sha256") && rec.contains("pv.sigil/"),
        "{rec}"
    );
    let bin = fs::read_dir(k.join("bin"))
        .unwrap()
        .flatten()
        .next()
        .unwrap()
        .path();

    // 4b: zero some bytes in the middle (a repairable tear), mend a copy, open the copy
    let mut hurt = full.clone();
    let mid = hurt.len() / 2;
    for b in &mut hurt[mid..mid + 64] {
        *b = 0;
    }
    fs::write(d.join("hurt.sg1"), &hurt).unwrap();
    run(&bin, &d, &["mend", "hurt.sg1", "-o", "fixed.sg1"]);
    run(
        &bin,
        &d,
        &["unseal", "fixed.sg1", "-o", "r4b", "--pass-file", "pw"],
    );
    assert_eq!(fs::read(d.join("r4b")).unwrap(), b"keep me\n");

    // 4c: private log, as written in RECOVER.txt
    let (c, o) = try_run(
        &bin,
        &d,
        &["log", "verify", "pv.sigil", "--pass-file", "pw"],
    );
    assert_eq!(c, 0, "{o}");
    run(&bin, &d, &["log", "mend", "pv.sigil"]);
    run(
        &bin,
        &d,
        &[
            "log",
            "restore",
            "pv.sigil",
            ".",
            "-o",
            "r4c",
            "--pass-file",
            "pw",
        ],
    );
    assert_eq!(fs::read(d.join("r4c/sub/a.txt")).unwrap(), b"alpha\n");
    assert_eq!(fs::read(d.join("r4c/b.txt")).unwrap(), b"beta\n");

    // 4d: pieces spread out, a few lost, gathered back
    run(&bin, &d, &["scatter", "note.sg1", "-o", "pieces"]);
    for i in 0..3 {
        fs::remove_file(d.join(format!("pieces/piece-{i:03}.sgp"))).unwrap();
    }
    run(&bin, &d, &["gather", "pieces", "-o", "back.sg1"]);
    run(
        &bin,
        &d,
        &["unseal", "back.sg1", "-o", "r4d", "--pass-file", "pw"],
    );
    assert_eq!(fs::read(d.join("r4d")).unwrap(), b"keep me\n");
}
