//! Real remove + `sigil gc`: constellation `remove`, vault `remove`, report-only gc by
//! default, never deleting referenced members, cold kits untouched.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime};

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
    let d = std::env::temp_dir().join(format!("sigil-gc-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn age(p: &Path, secs: u64) {
    let f = fs::OpenOptions::new()
        .write(true)
        .open(p)
        .or_else(|_| fs::File::open(p))
        .unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(secs))
        .unwrap();
}

fn star(c: &Path, bytes: &[u8]) -> PathBuf {
    container::star_path(c, &sigil::sha256(bytes))
}

/// Sky.sigil with a.txt, b.txt, dir/c.txt, dir/d.txt (d has the same bytes as a).
fn sample_sky(dir: &Path) -> PathBuf {
    fs::create_dir_all(dir.join("in/dir")).unwrap();
    fs::write(dir.join("in/a.txt"), b"alpha").unwrap();
    fs::write(dir.join("in/b.txt"), b"beta").unwrap();
    fs::write(dir.join("in/dir/c.txt"), b"gamma").unwrap();
    fs::write(dir.join("in/dir/d.txt"), b"alpha").unwrap();
    ok(
        dir,
        &["constellation", "add", "Sky", "in", "--mode", "glyph"],
    );
    dir.join("Sky.sigil")
}

#[test]
fn constellation_remove_frees_star_but_keeps_shared_bytes() {
    let dir = tmp("sky-rm");
    let c = sample_sky(&dir);
    assert!(star(&c, b"beta").is_file());
    // dry run changes nothing
    let o = ok(
        &dir,
        &["constellation", "remove", "Sky", "b.txt", "--dry-run"],
    );
    assert!(
        o.contains("would remove b.txt") && o.contains("would delete"),
        "{o}"
    );
    assert!(star(&c, b"beta").is_file());
    // real remove
    let o = ok(&dir, &["constellation", "remove", "Sky", "b.txt"]);
    assert!(o.contains("1 star file(s) freed"), "{o}");
    assert!(
        !star(&c, b"beta").exists() && !star(&c, b"beta").parent().unwrap().exists(),
        "empty shard folder goes too"
    );
    let s = ok(&dir, &["constellation", "scry", "Sky"]);
    assert!(!s.contains("b.txt") && !s.contains("MISSING"), "{s}");
    // a.txt and dir/d.txt share bytes: removing one keeps the star
    let o = ok(&dir, &["constellation", "remove", "Sky", "a.txt"]);
    assert!(o.contains("0 star file(s) freed"), "{o}");
    assert!(star(&c, b"alpha").is_file());
    // folder prefix
    let o = ok(&dir, &["constellation", "rm", "Sky", "dir/d.txt"]);
    assert!(o.contains("1 star file(s) freed"), "{o}");
    assert!(!star(&c, b"alpha").exists());
    // everything still restores
    ok(&dir, &["de-scribe", "-o", "out", "Sky.sigil"]);
    assert_eq!(fs::read(dir.join("out/dir/c.txt")).unwrap(), b"gamma");
    // unknown name and last name refuse
    assert!(
        fails(&dir, &["constellation", "remove", "Sky", "nope.txt"]).contains("not on the list")
    );
    assert!(fails(&dir, &["constellation", "remove", "Sky", "dir/c.txt"]).contains("empty"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn constellation_remove_folder_prefix_and_keep_stars_then_gc() {
    let dir = tmp("sky-prefix");
    let c = sample_sky(&dir);
    let o = ok(
        &dir,
        &["constellation", "remove", "Sky", "dir/", "--keep-stars"],
    );
    assert!(
        o.contains("2 name(s) off the list") && o.contains("0 star file(s) freed"),
        "{o}"
    );
    assert!(star(&c, b"gamma").is_file(), "--keep-stars leaves the star");
    // alpha is still on the list via a.txt; gamma is now an orphan.
    let o = ok(&dir, &["gc", "Sky"]);
    assert!(
        o.contains("orphan star") && o.contains("dry run: nothing was changed"),
        "{o}"
    );
    assert!(star(&c, b"gamma").is_file());
    let o = ok(&dir, &["gc", "Sky.sigil", "--apply"]);
    assert!(o.contains("reclaimed"), "{o}");
    assert!(!star(&c, b"gamma").exists());
    assert!(star(&c, b"alpha").is_file() && star(&c, b"beta").is_file());
    assert!(ok(&dir, &["gc", "Sky"]).contains("nothing to reclaim"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn constellation_remove_passphrase_and_encrypt_to_cards() {
    let dir = tmp("sky-keys");
    fs::write(dir.join("a.txt"), b"alpha").unwrap();
    fs::write(dir.join("b.txt"), b"beta").unwrap();
    ok(
        &dir,
        &["constellation", "add", "W", "a.txt", "--pass", "pw"],
    );
    ok(
        &dir,
        &["constellation", "add", "W", "b.txt", "--pass", "pw"],
    );
    // locked card: gc refuses to guess, remove needs the passphrase
    assert!(fails(&dir, &["gc", "W", "--apply"]).contains("will not guess"));
    fails(&dir, &["constellation", "remove", "W", "b.txt"]);
    ok(
        &dir,
        &["constellation", "remove", "W", "b.txt", "--pass", "pw"],
    );
    assert!(!star(&dir.join("W.sigil"), b"beta").exists());
    assert!(ok(&dir, &["gc", "W", "--pass", "pw"]).contains("nothing to reclaim"));

    ok(&dir, &["keygen", "-o", "alice.sgk"]);
    ok(
        &dir,
        &[
            "constellation",
            "add",
            "E",
            "a.txt",
            "--to",
            "alice.sgk.pub",
        ],
    );
    ok(
        &dir,
        &[
            "constellation",
            "add",
            "E",
            "b.txt",
            "--to",
            "alice.sgk.pub",
            "--identity",
            "alice.sgk",
        ],
    );
    assert!(fails(
        &dir,
        &[
            "constellation",
            "remove",
            "E",
            "b.txt",
            "--identity",
            "alice.sgk"
        ]
    )
    .contains("encrypt-to"));
    ok(
        &dir,
        &[
            "constellation",
            "remove",
            "E",
            "b.txt",
            "--to",
            "alice.sgk.pub",
            "--identity",
            "alice.sgk",
        ],
    );
    assert!(!star(&dir.join("E.sigil"), b"beta").exists());
    assert!(star(&dir.join("E.sigil"), b"alpha").is_file());
    let o = ok(&dir, &["gc", "E", "--identity", "alice.sgk"]);
    assert!(o.contains("nothing to reclaim"), "{o}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn gc_constellation_temp_duplicates_cold_and_unknown_files() {
    let dir = tmp("sky-gc");
    let c = sample_sky(&dir);
    // a young temp file, an old one, an unknown file, cold kit, and a duplicate star by name
    fs::write(c.join("Sky.sg1.part"), b"half").unwrap();
    fs::write(c.join("stars/ab.part"), b"old").unwrap();
    age(&c.join("stars/ab.part"), 7200);
    fs::write(c.join("notes.md"), b"mine").unwrap();
    fs::create_dir_all(c.join("cold/v1")).unwrap();
    fs::write(c.join("cold/v1/keep.me"), b"cold").unwrap();
    fs::create_dir_all(c.join("stars/by-name")).unwrap();
    fs::copy(star(&c, b"beta"), c.join("stars/by-name/b.txt.sg1")).unwrap();
    // an orphan star: mint one for bytes not on the list
    fs::write(dir.join("zz.txt"), b"zeta").unwrap();
    ok(&dir, &["constellation", "add", "Other", "zz.txt"]);
    let oz = star(&dir.join("Other.sigil"), b"zeta");
    fs::create_dir_all(star(&c, b"zeta").parent().unwrap()).unwrap();
    fs::copy(&oz, star(&c, b"zeta")).unwrap();

    let before = ok(&dir, &["gc", "Sky"]);
    assert!(
        before.contains("orphan star")
            && before.contains("duplicate star")
            && before.contains("temp file"),
        "{before}"
    );
    assert!(before.contains("left alone: notes.md"), "{before}");
    assert!(before.contains("recent temp file kept"), "{before}");
    assert!(
        star(&c, b"zeta").is_file() && c.join("stars/ab.part").is_file(),
        "report-only changed nothing"
    );
    // explicit --dry-run behaves the same
    ok(&dir, &["gc", "Sky", "--dry-run"]);
    assert!(star(&c, b"zeta").is_file());
    fails(&dir, &["gc", "Sky", "--apply", "--dry-run"]);

    let o = ok(&dir, &["gc", "Sky", "--apply"]);
    assert!(o.contains("reclaimed"), "{o}");
    assert!(!star(&c, b"zeta").exists());
    assert!(!c.join("stars/ab.part").exists());
    assert!(!c.join("stars/by-name/b.txt.sg1").exists() && !c.join("stars/by-name").exists());
    assert!(c.join("Sky.sg1.part").is_file(), "young temp file kept");
    assert!(c.join("notes.md").is_file() && c.join("cold/v1/keep.me").is_file());
    for b in [&b"alpha"[..], b"beta", b"gamma"] {
        assert!(star(&c, b).is_file());
    }
    let s = ok(&dir, &["constellation", "scry", "Sky"]);
    assert!(!s.contains("MISSING"), "{s}");
    // --temp-age 0 takes the young one too
    ok(&dir, &["gc", "Sky", "--apply", "--temp-age", "0"]);
    assert!(!c.join("Sky.sg1.part").exists());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn gc_flat_folder_is_report_only_but_remove_works() {
    let dir = tmp("sky-flat");
    fs::create_dir_all(dir.join("Flat")).unwrap();
    fs::write(dir.join("Flat/readme"), b"x").unwrap();
    fs::write(dir.join("f.txt"), b"eff").unwrap();
    fs::write(dir.join("g.txt"), b"gee").unwrap();
    ok(&dir, &["constellation", "add", "Flat", "f.txt"]);
    ok(&dir, &["constellation", "add", "Flat", "g.txt"]);
    ok(
        &dir,
        &["constellation", "remove", "Flat", "g.txt", "--keep-stars"],
    );
    assert!(dir.join("Flat/g.txt.sg1").is_file());
    let o = ok(&dir, &["gc", "Flat", "--apply"]);
    assert!(o.contains("orphan star") && o.contains("tidy"), "{o}");
    assert!(
        dir.join("Flat/g.txt.sg1").is_file(),
        "old flat folders are never reclaimed"
    );
    // real remove on a flat folder deletes the star it freed
    fs::write(dir.join("h.txt"), b"aitch").unwrap();
    ok(&dir, &["constellation", "add", "Flat", "h.txt"]);
    ok(&dir, &["constellation", "remove", "Flat", "f.txt"]);
    assert!(!dir.join("Flat/f.txt.sg1").exists() && dir.join("Flat/h.txt.sg1").is_file());
    assert!(!ok(&dir, &["constellation", "scry", "Flat"]).contains("MISSING"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn vault_remove_policy_and_cold_here() {
    let dir = tmp("vault-rm");
    fs::write(dir.join("n.txt"), b"one").unwrap();
    ok(&dir, &["vault", "track", "n.txt"]);
    for v in ["two", "three", "four"] {
        fs::write(dir.join("n.txt"), v).unwrap();
        ok(&dir, &["vault", "commit", "n.txt"]);
    }
    let c = dir.join("n.txt.sigil");
    assert!(fails(&dir, &["vault", "remove", "n.txt", "--version", "4"]).contains("tip"));
    assert!(fails(&dir, &["vault", "remove", "n.txt", "--version", "9"]).contains("not in CHART"));
    // full retention: plain explicit remove is allowed
    let o = ok(
        &dir,
        &["vault", "remove", "n.txt", "--version", "2", "--dry-run"],
    );
    assert!(
        o.contains("dry run") && c.join("versions/v2.sg1").is_file(),
        "{o}"
    );
    ok(&dir, &["vault", "remove", "n.txt", "--version", "2"]);
    assert!(!c.join("versions/v2.sg1").exists());
    assert!(!ok(&dir, &["vault", "versions", "n.txt"]).contains("v2"));
    // light retention needs a cold kit or force-drop
    ok(
        &dir,
        &["vault", "retention", "n.txt", "--light", "--keep", "3"],
    );
    let e = fails(&dir, &["vault", "remove", "n.txt", "--version", "1"]);
    assert!(e.contains("--cold"), "{e}");
    assert!(c.join("versions/v1.sg1").is_file());
    ok(
        &dir,
        &["vault", "remove", "n.txt", "--version", "1", "--cold-here"],
    );
    assert!(!c.join("versions/v1.sg1").exists());
    assert!(
        c.join("cold/v1").is_dir(),
        "seal archived into the container's cold/"
    );
    // tip restores, gc leaves cold alone
    ok(&dir, &["vault", "restore", "n.txt", "--force"]);
    assert_eq!(fs::read(dir.join("n.txt")).unwrap(), b"four");
    let o = ok(&dir, &["gc", "n.txt", "--apply"]);
    assert!(
        o.contains("nothing to reclaim") && o.contains("cold/"),
        "{o}"
    );
    assert!(c.join("cold/v1").is_dir());
    // force-drop
    ok(
        &dir,
        &["vault", "remove", "n.txt", "--version", "3", "--force-drop"],
    );
    // only the tip remains: nothing more to remove
    assert!(fails(
        &dir,
        &["vault", "remove", "n.txt", "--version", "4", "--force-drop"]
    )
    .contains("tip"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn vault_prune_cold_here_and_old_layout_remove() {
    let dir = tmp("vault-prune");
    fs::write(dir.join("p.txt"), b"1").unwrap();
    ok(&dir, &["vault", "track", "p.txt"]);
    for v in ["2", "3"] {
        fs::write(dir.join("p.txt"), v).unwrap();
        ok(&dir, &["vault", "commit", "p.txt"]);
    }
    let c = dir.join("p.txt.sigil");
    ok(
        &dir,
        &["vault", "prune", "p.txt", "--keep", "2", "--cold-here"],
    );
    assert!(c.join("cold/v1").is_dir() && !c.join("versions/v1.sg1").exists());
    // old .sgv layout: remove works, --cold-here refuses
    fs::write(dir.join("q.txt"), b"1").unwrap();
    ok(&dir, &["vault", "track", "q.txt"]);
    fs::write(dir.join("q.txt"), b"2").unwrap();
    ok(&dir, &["vault", "commit", "q.txt"]);
    ok(&dir, &["tidy", "q.txt"]); // container ...
    assert!(
        fails(
            &dir,
            &[
                "vault",
                "remove",
                "q.txt",
                "--version",
                "1",
                "--cold",
                "x",
                "--cold-here"
            ]
        )
        .len()
            > 0
    );
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn gc_vault_orphans_temp_and_staging() {
    let dir = tmp("vault-gc");
    fs::write(dir.join("n.txt"), b"one").unwrap();
    ok(&dir, &["vault", "track", "n.txt"]);
    fs::write(dir.join("n.txt"), b"two").unwrap();
    ok(&dir, &["vault", "commit", "n.txt"]);
    let c = dir.join("n.txt.sigil");
    // a crashed commit left v9.sg1 (not in CHART), an old .part, and a stale tidy staging dir
    fs::copy(c.join("versions/v2.sg1"), c.join("versions/v9.sg1")).unwrap();
    fs::write(c.join("versions/v3.sg1.part"), b"torn").unwrap();
    age(&c.join("versions/v3.sg1.part"), 7200);
    fs::create_dir_all(dir.join(".tidy-n.txt.sigil")).unwrap();
    fs::write(dir.join(".tidy-n.txt.sigil/x"), b"x").unwrap();
    age(&dir.join(".tidy-n.txt.sigil"), 7200);
    fs::write(c.join("stray.bin"), b"mine").unwrap();

    let o = ok(&dir, &["gc", "n.txt"]);
    assert!(
        o.contains("orphan version")
            && o.contains("v9.sg1")
            && o.contains("temp file")
            && o.contains("stale staging"),
        "{o}"
    );
    assert!(
        o.contains("kept 2 referenced") && o.contains("left alone: stray.bin"),
        "{o}"
    );
    assert!(c.join("versions/v9.sg1").is_file());
    let o = ok(&dir, &["gc", "n.txt.sigil", "--apply"]);
    assert!(o.contains("reclaimed 3 of 3"), "{o}");
    assert!(!c.join("versions/v9.sg1").exists() && !c.join("versions/v3.sg1.part").exists());
    assert!(!dir.join(".tidy-n.txt.sigil").exists());
    assert!(
        c.join("versions/v1.sg1").is_file()
            && c.join("versions/v2.sg1").is_file()
            && c.join("stray.bin").is_file()
    );
    ok(
        &dir,
        &["vault", "restore", "n.txt", "--version", "1", "--force"],
    );
    assert_eq!(fs::read(dir.join("n.txt")).unwrap(), b"one");

    // gc on something that is neither
    fs::write(dir.join("plain.txt"), b"x").unwrap();
    assert!(fails(&dir, &["gc", "plain.txt"]).contains("nothing to gc"));
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn gc_old_sgv_layout_vault() {
    let dir = tmp("vault-sgv");
    fs::write(dir.join("o.txt"), b"one").unwrap();
    ok(&dir, &["vault", "track", "o.txt"]);
    let c = dir.join("o.txt.sigil");
    // fabricate the old layout
    let old = dir.join("o.txt.sgv");
    fs::create_dir_all(&old).unwrap();
    fs::copy(c.join("CHART"), old.join("CHART")).unwrap();
    fs::copy(c.join("versions/v1.sg1"), old.join("v1.sg1")).unwrap();
    fs::remove_dir_all(&c).unwrap();
    fs::copy(old.join("v1.sg1"), old.join("v5.sg1")).unwrap();
    let o = ok(&dir, &["gc", "o.txt.sgv", "--apply"]);
    assert!(
        o.contains("orphan version") && o.contains("old layout"),
        "{o}"
    );
    assert!(
        old.join("v1.sg1").is_file() && old.join("CHART").is_file() && !old.join("v5.sg1").exists()
    );
    let _ = fs::remove_dir_all(&dir);
}
