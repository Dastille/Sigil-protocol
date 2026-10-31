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
    assert_eq!(sums.lines().count(), 3, "{sums}");
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
