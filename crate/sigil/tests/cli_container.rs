//! Tidy container (`name.sigil/`): new-layout round trips, `sigil tidy` migration of old
//! vaults / constellations (clear, passphrase, encrypt-to), and failed tidy leaves originals intact.
use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sigil::container::{self, TidyFault, TidyOpts};

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
    let d = std::env::temp_dir().join(format!("sigil-container-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// Every file under `dir` → sha256 (relative paths).
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

fn sg1_hashes(dir: &Path) -> BTreeSet<String> {
    fingerprints(dir)
        .into_iter()
        .filter(|(r, _)| r.ends_with(".sg1"))
        .map(|(_, h)| h)
        .collect()
}

/// Turn a container vault back into the old `<live>.sgv/` sidecar (exact old layout).
fn make_legacy_vault(live: &Path) {
    let c = container::with_suffix(live);
    let mut old = live.as_os_str().to_os_string();
    old.push(".sgv");
    let old = PathBuf::from(old);
    for e in fs::read_dir(c.join("versions")).unwrap().flatten() {
        fs::rename(e.path(), c.join(e.file_name())).unwrap();
    }
    fs::remove_dir(c.join("versions")).unwrap();
    fs::remove_file(c.join("CONTAINER")).unwrap();
    fs::rename(&c, &old).unwrap();
}

#[test]
fn container_vault_round_trip() {
    let dir = tmp("vault");
    fs::write(dir.join("notes.txt"), b"one").unwrap();
    ok(&dir, &["vault", "track", "notes.txt", "--mode", "glyph"]);
    let c = dir.join("notes.txt.sigil");
    assert!(c.join("CONTAINER").is_file() && c.join("CHART").is_file());
    assert!(c.join("versions/v1.sg1").is_file());
    assert!(!dir.join("notes.txt.sgv").exists());
    let m = fs::read_to_string(c.join("CONTAINER")).unwrap();
    assert!(
        m.starts_with("sigil-container=1\n")
            && m.contains("kind=vault")
            && m.contains("name=notes.txt"),
        "{m}"
    );

    fs::write(dir.join("notes.txt"), b"two").unwrap();
    ok(&dir, &["vault", "commit", "notes.txt", "--mode", "glyph"]);
    assert!(c.join("versions/v2.sg1").is_file());
    let s = ok(&dir, &["vault", "status", "notes.txt.sigil"]);
    assert!(s.contains("v2") || s.contains("tip"), "{s}");
    ok(
        &dir,
        &["vault", "restore", "notes.txt", "--version", "1", "--force"],
    );
    assert_eq!(fs::read(dir.join("notes.txt")).unwrap(), b"one");
    // Only the container sits next to the live file.
    let names: BTreeSet<_> = fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(
        names,
        ["notes.txt", "notes.txt.sigil"]
            .iter()
            .map(|s| s.to_string())
            .collect()
    );

    // Folder vault too.
    fs::create_dir_all(dir.join("photos/sub")).unwrap();
    fs::write(dir.join("photos/a.jpg"), b"aaa").unwrap();
    fs::write(dir.join("photos/sub/b.jpg"), b"bbb").unwrap();
    ok(&dir, &["vault", "track", "photos"]);
    assert!(dir.join("photos.sigil/versions/v1.sg1").is_file());
    fs::write(dir.join("photos/a.jpg"), b"AAA").unwrap();
    ok(&dir, &["vault", "commit", "photos"]);
    ok(
        &dir,
        &["vault", "restore", "photos", "--version", "1", "--force"],
    );
    assert_eq!(fs::read(dir.join("photos/a.jpg")).unwrap(), b"aaa");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn container_constellation_round_trip() {
    let dir = tmp("sky");
    fs::create_dir_all(dir.join("docs/sub")).unwrap();
    fs::write(dir.join("docs/a.txt"), b"alpha").unwrap();
    fs::write(dir.join("docs/sub/b.txt"), b"beta").unwrap();
    ok(
        &dir,
        &["constellation", "add", "Sky", "docs", "--mode", "glyph"],
    );
    let c = dir.join("Sky.sigil");
    assert!(
        c.join("CONTAINER").is_file() && c.join("Sky.sg1").is_file(),
        "card at root"
    );
    assert!(container::star_path(&c, &sigil::sha256(b"alpha")).is_file());
    assert!(container::star_path(&c, &sigil::sha256(b"beta")).is_file());
    assert!(!dir.join("Sky").exists());
    // Adding again via the short name lands in the same container.
    fs::write(dir.join("c.txt"), b"gamma").unwrap();
    ok(&dir, &["constellation", "add", "Sky", "c.txt"]);
    assert!(container::star_path(&c, &sigil::sha256(b"gamma")).is_file());
    let s = ok(&dir, &["constellation", "scry", "Sky"]);
    assert!(s.contains("stars=3") && !s.contains("MISSING"), "{s}");
    ok(&dir, &["de-scribe", "-o", "out", "Sky.sigil"]);
    assert_eq!(fs::read(dir.join("out/sub/b.txt")).unwrap(), b"beta");
    assert_eq!(fs::read(dir.join("out/c.txt")).unwrap(), b"gamma");
    ok(&dir, &["constellation", "atlas", "Sky"]);
    assert!(c.join("Sky.sga").is_file());
    ok(&dir, &["de-scribe", "-o", "bag-out", "Sky.sigil/Sky.sga"]);
    assert_eq!(fs::read(dir.join("bag-out/a.txt")).unwrap(), b"alpha");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn old_layouts_still_open_and_stay_old() {
    let dir = tmp("old");
    fs::write(dir.join("n.txt"), b"one").unwrap();
    ok(&dir, &["vault", "track", "n.txt"]);
    make_legacy_vault(&dir.join("n.txt"));
    fs::write(dir.join("n.txt"), b"two").unwrap();
    ok(&dir, &["vault", "commit", "n.txt"]);
    assert!(
        dir.join("n.txt.sgv/v2.sg1").is_file(),
        "commit on an old vault stays in .sgv"
    );
    assert!(!dir.join("n.txt.sigil").exists());
    ok(
        &dir,
        &["vault", "restore", "n.txt.sgv", "--version", "1", "--force"],
    );
    assert_eq!(fs::read(dir.join("n.txt")).unwrap(), b"one");

    // Existing non-empty folder: constellation stays flat.
    fs::create_dir_all(dir.join("Flat")).unwrap();
    fs::write(dir.join("Flat/readme"), b"x").unwrap();
    fs::write(dir.join("f.txt"), b"eff").unwrap();
    ok(&dir, &["constellation", "add", "Flat", "f.txt"]);
    assert!(dir.join("Flat/f.txt.sg1").is_file() && !dir.join("Flat/CONTAINER").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn tidy_old_vault_clear_pass_and_encrypt_to() {
    let dir = tmp("tidy-vault");
    ok(&dir, &["keygen", "-o", "alice.sgk"]);
    for (name, extra) in [
        ("clear.txt", vec![]),
        ("pass.txt", vec!["--pass", "hunter2"]),
        ("to.txt", vec!["--to", "alice.sgk.pub"]),
    ] {
        fs::write(dir.join(name), b"v1").unwrap();
        let mut a = vec!["vault", "track", name];
        a.extend(extra.iter());
        ok(&dir, &a);
        fs::write(dir.join(name), b"v2").unwrap();
        let mut a = vec!["vault", "commit", name];
        a.extend(extra.iter());
        ok(&dir, &a);
        make_legacy_vault(&dir.join(name));
        let old = dir.join(format!("{name}.sgv"));
        let before = sg1_hashes(&old);
        assert_eq!(before.len(), 2);

        let out = ok(&dir, &["tidy", name, "--dry-run"]);
        assert!(
            out.contains("would move") && out.contains("versions/v2.sg1"),
            "{out}"
        );
        assert!(old.join("CHART").is_file() && !dir.join(format!("{name}.sigil")).exists());

        let out = ok(&dir, &["tidy", name]);
        assert!(out.contains("fingerprints verified"), "{out}");
        let c = dir.join(format!("{name}.sigil"));
        assert!(!old.exists(), "old sidecar removed");
        assert!(c.join("CONTAINER").is_file() && c.join("versions/v1.sg1").is_file());
        assert_eq!(sg1_hashes(&c), before, "seal bytes never rewritten");
        // Second tidy is a no-op.
        assert!(ok(&dir, &["tidy", name]).contains("already tidy"));

        let mut a = vec!["vault", "restore", name, "--version", "1", "--force"];
        match name {
            "pass.txt" => a.extend(["--pass", "hunter2"]),
            "to.txt" => {
                fails(&dir, &a);
                a.extend(["--identity", "alice.sgk"]);
            }
            _ => {}
        }
        ok(&dir, &a);
        assert_eq!(fs::read(dir.join(name)).unwrap(), b"v1");
        // Keeps working: commit lands in the container.
        fs::write(dir.join(name), b"v3").unwrap();
        let mut a = vec!["vault", "commit", name];
        a.extend(extra.iter());
        ok(&dir, &a);
        assert!(c.join("versions/v3.sg1").is_file());
    }
    let _ = fs::remove_dir_all(&dir);
}

fn flat_sky(dir: &Path, name: &str, extra: &[&str]) -> PathBuf {
    let sky = dir.join(name);
    fs::create_dir_all(&sky).unwrap();
    fs::write(sky.join("keep.txt"), b"not sigil").unwrap(); // non-empty → old flat layout
    fs::create_dir_all(dir.join("docs/sub")).unwrap();
    fs::write(dir.join("docs/a.txt"), b"alpha").unwrap();
    fs::write(dir.join("docs/sub/b.txt"), b"beta").unwrap();
    let mut a = vec!["constellation", "add", name, "docs"];
    a.extend(extra);
    ok(dir, &a);
    assert!(sky.join("a.txt.sg1").is_file(), "flat star");
    sky
}

#[test]
fn tidy_old_constellations() {
    let dir = tmp("tidy-sky");
    ok(&dir, &["keygen", "-o", "alice.sgk"]);
    let cases: [(&str, Vec<&str>, Vec<&str>); 3] = [
        ("Clear", vec![], vec![]),
        ("Pass", vec!["--pass", "pw"], vec!["--pass", "pw"]),
        (
            "To",
            vec!["--to", "alice.sgk.pub"],
            vec!["--identity", "alice.sgk"],
        ),
    ];
    for (name, add, open) in cases {
        let sky = flat_sky(&dir, name, &add);
        ok(&dir, &{
            let mut a = vec!["constellation", "atlas", name];
            a.extend(open.iter());
            a
        });
        let before = sg1_hashes(&sky);
        let out = ok(&dir, &["tidy", name, "--dry-run"]);
        assert!(
            out.contains("would move") && out.contains("stars/"),
            "{out}"
        );
        assert_eq!(sg1_hashes(&sky), before);

        let mut a = vec!["tidy", name];
        a.extend(open.iter());
        let out = ok(&dir, &a);
        assert!(out.contains("list checked"), "{out}");
        assert!(
            out.contains("left alone") && out.contains("keep.txt"),
            "{out}"
        );
        let c = dir.join(format!("{name}.sigil"));
        assert_eq!(sg1_hashes(&c), before, "card + stars byte-identical");
        assert!(c.join(format!("{name}.sg1")).is_file() && c.join(format!("{name}.sga")).is_file());
        assert!(container::star_path(&c, &sigil::sha256(b"alpha")).is_file());
        assert!(!sky.join("a.txt.sg1").exists() && sky.join("keep.txt").is_file());

        let mut a = vec!["de-scribe", "-o"];
        let out_dir = format!("out-{name}");
        a.push(&out_dir);
        let cpath = format!("{name}.sigil");
        a.push(&cpath);
        a.extend(open.iter());
        ok(&dir, &a);
        assert_eq!(
            fs::read(dir.join(&out_dir).join("sub/b.txt")).unwrap(),
            b"beta"
        );
    }
    // Locked card tidied without keys: byte-level verification only, still opens after.
    let sky = flat_sky(&dir, "NoKey", &["--to", "alice.sgk.pub"]);
    let out = ok(&dir, &["tidy", "NoKey"]);
    assert!(
        out.contains("fingerprints verified") && !out.contains("list checked"),
        "{out}"
    );
    assert!(sky.join("keep.txt").is_file());
    let s = ok(
        &dir,
        &[
            "constellation",
            "scry",
            "NoKey.sigil",
            "--identity",
            "alice.sgk",
        ],
    );
    assert!(!s.contains("MISSING"), "{s}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn failed_tidy_leaves_original_intact() {
    let dir = tmp("tidy-fail");
    // Vault
    fs::write(dir.join("n.txt"), b"one").unwrap();
    ok(&dir, &["vault", "track", "n.txt"]);
    fs::write(dir.join("n.txt"), b"two").unwrap();
    ok(&dir, &["vault", "commit", "n.txt"]);
    make_legacy_vault(&dir.join("n.txt"));
    let old = dir.join("n.txt.sgv");
    let before = fingerprints(&old);
    // Sky
    let sky = flat_sky(&dir, "Sky", &[]);
    let sky_before = fingerprints(&sky);

    for fault in [TidyFault::FailAfterCopies(1), TidyFault::CorruptFirstStar] {
        for (target, snap, src) in [
            (dir.join("n.txt"), &before, &old),
            (sky.clone(), &sky_before, &sky),
        ] {
            let e = container::tidy(
                &target,
                &TidyOpts {
                    fault: Some(fault),
                    ..Default::default()
                },
            );
            let msg = e.err().expect("tidy must fail").to_string();
            if fault == TidyFault::CorruptFirstStar {
                assert!(msg.contains("fingerprint mismatch"), "{msg}");
            }
            assert_eq!(&fingerprints(src), snap, "original untouched");
            assert!(
                !container::with_suffix(&target).exists(),
                "no container after failure"
            );
            let leftovers: Vec<_> = fs::read_dir(&dir)
                .unwrap()
                .flatten()
                .filter(|e| e.file_name().to_string_lossy().starts_with(".tidy-"))
                .collect();
            assert!(leftovers.is_empty(), "staging cleaned");
        }
    }
    // Simulated crash: a stale staging folder is ignored by readers and replaced by the next tidy.
    fs::create_dir_all(dir.join(".tidy-n.txt.sigil/versions")).unwrap();
    fs::write(dir.join(".tidy-n.txt.sigil/versions/v1.sg1"), b"junk").unwrap();
    ok(&dir, &["vault", "status", "n.txt"]);
    ok(&dir, &["tidy", "n.txt"]);
    assert!(!dir.join(".tidy-n.txt.sigil").exists());
    ok(
        &dir,
        &["vault", "restore", "n.txt", "--version", "1", "--force"],
    );
    assert_eq!(fs::read(dir.join("n.txt")).unwrap(), b"one");

    // Refuses when the target exists.
    let sky2 = flat_sky(&dir, "Sky2", &[]);
    fs::create_dir_all(dir.join("Sky2.sigil")).unwrap();
    let e = fails(&dir, &["tidy", "Sky2"]);
    assert!(e.contains("already exists"), "{e}");
    assert!(sky2.join("a.txt.sg1").is_file());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn manifest_tolerates_unknown_keys_and_refuses_newer() {
    let m =
        container::Manifest::parse("sigil-container=1\nkind=vault\nname=x\nfuture=yes\n").unwrap();
    assert_eq!(m.extra.get("future").map(String::as_str), Some("yes"));
    assert!(m.render().contains("future=yes"));
    let e = container::Manifest::parse("sigil-container=2\nkind=vault\n")
        .unwrap_err()
        .to_string();
    assert!(e.contains("newer"), "{e}");
    assert!(container::Manifest::parse("kind=vault\n").is_err());
}
