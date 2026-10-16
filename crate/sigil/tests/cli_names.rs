//! Human-readable names: `sigil ls` and `sigil mount` show list names / `name@vN` for
//! container members instead of fingerprint paths; nothing on disk changes.
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sigil::container;

fn sigil_cmd(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .env_remove("SIGIL_SOFT_AUTHENTICATOR")
        .args(args)
        .output()
        .expect("run sigil")
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn ok(dir: &Path, args: &[&str]) -> String {
    let o = sigil_cmd(dir, args);
    assert!(o.status.success(), "{args:?}: {}", text(&o));
    text(&o)
}

fn fails(dir: &Path, args: &[&str]) -> String {
    let o = sigil_cmd(dir, args);
    assert!(
        !o.status.success(),
        "expected failure {args:?}: {}",
        text(&o)
    );
    text(&o)
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sigil-names-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn fingerprints(dir: &Path) -> BTreeSet<(String, String)> {
    fn walk(root: &Path, d: &Path, out: &mut BTreeSet<(String, String)>) {
        for e in fs::read_dir(d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() {
                walk(root, &p, out);
            } else {
                let rel = p.strip_prefix(root).unwrap().to_string_lossy().into_owned();
                out.insert((rel, hex::encode(sigil::sha256_path(&p).unwrap())));
            }
        }
    }
    let mut out = BTreeSet::new();
    walk(dir, dir, &mut out);
    out
}

fn sample(dir: &Path) -> PathBuf {
    fs::create_dir_all(dir.join("in/docs")).unwrap();
    fs::write(dir.join("in/b.txt"), b"beta beta").unwrap();
    fs::write(dir.join("in/docs/a.txt"), b"alpha alpha alpha").unwrap();
    fs::write(dir.join("in/docs/c.txt"), b"gamma").unwrap();
    ok(
        dir,
        &["constellation", "add", "Sky", "in", "--mode", "glyph"],
    );
    dir.join("Sky.sigil")
}

#[test]
fn ls_constellation_shows_names_not_hashes() {
    let dir = tmp("ls-sky");
    let c = sample(&dir);
    let before = fingerprints(&c);
    let o = ok(&dir, &["ls", "Sky"]);
    assert!(
        o.contains("3 name(s)")
            && o.contains("b.txt")
            && o.contains("docs/a.txt")
            && o.contains("docs/c.txt"),
        "{o}"
    );
    assert!(
        !o.contains("stars/") && !o.contains(".sg1"),
        "no fingerprint paths: {o}"
    );
    let o = ok(&dir, &["ls", "Sky.sigil", "docs/"]);
    assert!(
        o.contains("docs/a.txt") && o.contains("docs/c.txt") && !o.contains("b.txt  "),
        "{o}"
    );
    assert!(fails(&dir, &["ls", "Sky", "nope/"]).contains("nothing named"));
    // descend into a member by name
    let o = ok(&dir, &["ls", "Sky", "docs/a.txt"]);
    assert!(o.contains("trail  docs/a.txt") && o.contains("kind"), "{o}");
    // a raw fingerprint path gets its list name in the breadcrumb
    let star = container::star_path(&c, &sigil::sha256(b"beta beta"));
    let o = ok(&dir, &["ls", star.to_str().unwrap()]);
    assert!(
        o.contains("trail  b.txt") && !o.contains("trail  b6"),
        "{o}"
    );
    // missing star is flagged by name
    fs::remove_file(&star).unwrap();
    let o = ok(&dir, &["ls", "Sky"]);
    assert!(o.contains("b.txt") && o.contains("MISSING star"), "{o}");
    assert!(fails(&dir, &["ls", "Sky", "b.txt"]).contains("missing"));
    assert_ne!(
        before,
        fingerprints(&c),
        "(sanity: the file we deleted is gone)"
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn ls_never_changes_disk_and_works_on_flat_and_locked() {
    let dir = tmp("ls-keys");
    let c = sample(&dir);
    let before = fingerprints(&c);
    ok(&dir, &["ls", "Sky"]);
    ok(&dir, &["mount", "Sky", "m", "--export-dir", "x"]);
    assert_eq!(
        before,
        fingerprints(&c),
        "ls / mount never write into the container"
    );

    // old flat folder
    fs::create_dir_all(dir.join("Flat")).unwrap();
    fs::write(dir.join("Flat/readme"), b"x").unwrap();
    fs::write(dir.join("f.txt"), b"eff eff").unwrap();
    ok(&dir, &["constellation", "add", "Flat", "f.txt"]);
    let o = ok(&dir, &["ls", "Flat"]);
    assert!(o.contains("f.txt") && o.contains("1 name(s)"), "{o}");

    // warded card
    fs::write(dir.join("w.txt"), b"warded").unwrap();
    ok(
        &dir,
        &["constellation", "add", "W", "w.txt", "--pass", "pw"],
    );
    assert!(fails(&dir, &["ls", "W"]).contains("--pass"));
    assert!(ok(&dir, &["ls", "W", "--pass", "pw"]).contains("w.txt"));
    // fingerprint path of a warded star: no name without the key (falls back), name with it
    let star = container::star_path(&dir.join("W.sigil"), &sigil::sha256(b"warded"));
    let o = ok(&dir, &["ls", star.to_str().unwrap(), "--pass", "pw"]);
    assert!(o.contains("trail  w.txt"), "{o}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn ls_vault_versions_by_name() {
    let dir = tmp("ls-vault");
    fs::write(dir.join("n.txt"), b"one").unwrap();
    ok(&dir, &["vault", "track", "n.txt"]);
    fs::write(dir.join("n.txt"), b"two two").unwrap();
    ok(&dir, &["vault", "commit", "n.txt"]);
    let o = ok(&dir, &["ls", "n.txt.sigil"]);
    assert!(
        o.contains("n.txt@v1") && o.contains("n.txt@v2") && o.contains("(tip)"),
        "{o}"
    );
    assert!(!o.contains("versions/"), "{o}");
    let o = ok(&dir, &["ls", "n.txt.sigil", "v1"]);
    assert!(o.contains("trail  n.txt@v1"), "{o}");
    let o = ok(&dir, &["ls", "n.txt.sigil", "n.txt@v2"]);
    assert!(o.contains("trail  n.txt@v2"), "{o}");
    assert!(fails(&dir, &["ls", "n.txt.sigil", "v9"]).contains("no version v9"));
    assert!(fails(&dir, &["ls", "n.txt.sigil", "bogus"]).contains("not a version"));
    // raw seal path also gets the friendly label
    let o = ok(&dir, &["ls", "n.txt.sigil/versions/v2.sg1"]);
    assert!(o.contains("trail  n.txt@v2"), "{o}");
    // a live file that exists keeps the old behaviour (walks the file itself)
    let o = ok(&dir, &["ls", "n.txt"]);
    assert!(o.contains("trail  n.txt") && o.contains("leaf"), "{o}");
    // once the live file is gone, the vault listing answers
    fs::remove_file(dir.join("n.txt")).unwrap();
    assert!(ok(&dir, &["ls", "n.txt"]).contains("n.txt@v1"));
    // old .sgv layout lists the same way
    let c = dir.join("n.txt.sigil");
    let old = dir.join("n.txt.sgv");
    for e in fs::read_dir(c.join("versions")).unwrap().flatten() {
        fs::rename(e.path(), c.join(e.file_name())).unwrap();
    }
    fs::remove_dir(c.join("versions")).unwrap();
    fs::remove_file(c.join("CONTAINER")).unwrap();
    fs::rename(&c, &old).unwrap();
    assert!(ok(&dir, &["ls", "n.txt.sgv"]).contains("n.txt@v2"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn mount_constellation_export_uses_list_names() {
    let dir = tmp("mount-sky");
    let c = sample(&dir);
    let before = fingerprints(&c);
    let o = ok(&dir, &["mount", "Sky.sigil", "mnt", "--export-dir", "out"]);
    assert!(
        o.contains("exported 3 file(s)") && o.contains("seal intact"),
        "{o}"
    );
    assert_eq!(fs::read(dir.join("out/b.txt")).unwrap(), b"beta beta");
    assert_eq!(
        fs::read(dir.join("out/docs/a.txt")).unwrap(),
        b"alpha alpha alpha"
    );
    assert_eq!(fs::read(dir.join("out/docs/c.txt")).unwrap(), b"gamma");
    assert_eq!(before, fingerprints(&c));
    assert!(fails(
        &dir,
        &["mount", "Sky", "mnt", "--export-dir", "out2", "--writable"]
    )
    .contains("--writable"));

    // warded + encrypt-to constellations mount with the right key, refuse without
    fs::write(dir.join("w.txt"), b"warded").unwrap();
    ok(
        &dir,
        &["constellation", "add", "W", "w.txt", "--pass", "pw"],
    );
    assert!(fails(&dir, &["mount", "W", "mnt", "--export-dir", "wout"]).contains("--pass"));
    ok(
        &dir,
        &["mount", "W", "mnt", "--export-dir", "wout", "--pass", "pw"],
    );
    assert_eq!(fs::read(dir.join("wout/w.txt")).unwrap(), b"warded");
    ok(&dir, &["keygen", "-o", "alice.sgk"]);
    ok(
        &dir,
        &[
            "constellation",
            "add",
            "E",
            "w.txt",
            "--to",
            "alice.sgk.pub",
        ],
    );
    ok(
        &dir,
        &[
            "mount",
            "E",
            "mnt",
            "--export-dir",
            "eout",
            "--identity",
            "alice.sgk",
        ],
    );
    assert_eq!(fs::read(dir.join("eout/w.txt")).unwrap(), b"warded");

    // a missing star surfaces by name instead of a hash
    fs::remove_file(container::star_path(&c, &sigil::sha256(b"gamma"))).unwrap();
    let e = fails(&dir, &["mount", "Sky", "mnt", "--export-dir", "out3"]);
    assert!(e.contains("c.txt") && e.contains("missing"), "{e}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn mount_vault_container_still_names_the_payload() {
    let dir = tmp("mount-vault");
    fs::write(dir.join("n.txt"), b"vault bytes").unwrap();
    ok(&dir, &["vault", "track", "n.txt"]);
    ok(
        &dir,
        &[
            "mount",
            "n.txt.sigil",
            "mnt",
            "--export-dir",
            "out",
            "--vault",
        ],
    );
    assert_eq!(fs::read(dir.join("out/n.txt")).unwrap(), b"vault bytes");
    let _ = fs::remove_dir_all(&dir);
}
