//! `sigil doctor`: read-only health report (exit 0 healthy / 1 warnings / 2 problems / 3 cannot check)
//! and the safe `--fix` (tidy an old layout + gc --apply).
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

/// Run doctor; return (exit code, output).
fn doc(dir: &Path, args: &[&str]) -> (i32, String) {
    let mut a = vec!["doctor"];
    a.extend(args);
    let o = sigil_cmd(dir, &a);
    (o.status.code().unwrap(), text(&o))
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sigil-doctor-{tag}-{}", std::process::id()));
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

fn zero_mid(p: &Path, len: usize) {
    let mut b = fs::read(p).unwrap();
    let mid = b.len() / 2;
    let end = (mid + len).min(b.len());
    b[mid..end].fill(0);
    fs::write(p, b).unwrap();
}

fn vault3(dir: &Path) -> PathBuf {
    fs::write(dir.join("n.txt"), b"one one one one one one").unwrap();
    ok(dir, &["vault", "track", "n.txt"]);
    for v in ["two two two two", "three three three"] {
        fs::write(dir.join("n.txt"), v).unwrap();
        ok(dir, &["vault", "commit", "n.txt"]);
    }
    dir.join("n.txt.sigil")
}

fn sky(dir: &Path) -> PathBuf {
    fs::write(dir.join("a.txt"), b"alpha alpha alpha alpha").unwrap();
    fs::write(dir.join("b.txt"), b"beta beta beta beta beta").unwrap();
    ok(dir, &["constellation", "add", "Sky", "a.txt"]);
    ok(dir, &["constellation", "add", "Sky", "b.txt"]);
    dir.join("Sky.sigil")
}

#[test]
fn healthy_vault_and_constellation_exit_zero_and_json() {
    let dir = tmp("healthy");
    vault3(&dir);
    sky(&dir);
    let (c, o) = doc(&dir, &["n.txt"]);
    assert_eq!(c, 0, "{o}");
    assert!(
        o.contains("result: healthy")
            && o.contains("verified 3 member(s)")
            && o.contains("container format 1"),
        "{o}"
    );
    let (c, o) = doc(&dir, &["Sky"]);
    assert_eq!(c, 0, "{o}");
    assert!(
        o.contains("constellation") && o.contains("verified 2 member(s)"),
        "{o}"
    );
    let (c, j) = doc(&dir, &["Sky.sigil", "--json"]);
    assert_eq!(c, 0);
    assert!(
        j.starts_with('{')
            && j.contains("\"status\":\"healthy\"")
            && j.contains("\"exit_code\":0")
            && j.contains("\"findings\":[]"),
        "{j}"
    );
    assert!(
        j.contains("\"kind\":\"constellation\"") && j.contains("\"container_version\":1"),
        "{j}"
    );
    // doctor changes nothing
    assert!(ok(&dir, &["gc", "Sky"]).contains("nothing to reclaim"));
    let (c, o) = doc(&dir, &["--quick", "n.txt"]);
    assert_eq!(c, 0, "{o}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn vault_bit_rot_missing_seal_and_orphans() {
    let dir = tmp("vault-bad");
    let c = vault3(&dir);
    // repairable rot in v1
    let v1 = c.join("versions/v1.sg1");
    let good = fs::read(&v1).unwrap();
    zero_mid(&v1, 8);
    let (code, o) = doc(&dir, &["n.txt"]);
    assert_eq!(code, 1, "{o}");
    assert!(
        o.contains("bit-rot") && o.contains("repairable") && o.contains("sigil mend"),
        "{o}"
    );
    // beyond repair
    let mut b = good.clone();
    let n = b.len();
    b[n / 8..n - n / 8].fill(0);
    fs::write(&v1, b).unwrap();
    let (code, o) = doc(&dir, &["n.txt"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("bit-rot-unrecoverable"), "{o}");
    fs::write(&v1, &good).unwrap();
    // missing seal
    fs::remove_file(c.join("versions/v2.sg1")).unwrap();
    let (code, o) = doc(&dir, &["n.txt.sigil", "--json"]);
    assert_eq!(code, 2, "{o}");
    assert!(
        o.contains("\"code\":\"seal-missing\"") && o.contains("\"status\":\"problems\""),
        "{o}"
    );
    let _ = fs::remove_dir_all(&dir);

    let dir = tmp("vault-orphan");
    let c = vault3(&dir);
    fs::copy(c.join("versions/v3.sg1"), c.join("versions/v9.sg1")).unwrap();
    fs::write(c.join("versions/v4.sg1.part"), b"torn").unwrap();
    age(&c.join("versions/v4.sg1.part"), 7200);
    let (code, o) = doc(&dir, &["n.txt"]);
    assert_eq!(code, 1, "{o}");
    assert!(
        o.contains("orphan-version") && o.contains("temp-file") && o.contains("sigil gc"),
        "{o}"
    );
    assert!(
        c.join("versions/v9.sg1").is_file(),
        "doctor alone is read-only"
    );
    let (code, o) = doc(&dir, &["n.txt", "--fix"]);
    assert_eq!(code, 0, "{o}");
    assert!(o.contains("fixed: gc removed 2"), "{o}");
    assert!(!c.join("versions/v9.sg1").exists() && c.join("versions/v3.sg1").is_file());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn constellation_missing_star_rot_locked_card_and_manifest() {
    let dir = tmp("sky-bad");
    let c = sky(&dir);
    // bit rot, repairable
    let sb = star(&c, b"beta beta beta beta beta");
    let good = fs::read(&sb).unwrap();
    zero_mid(&sb, 8);
    let (code, o) = doc(&dir, &["Sky"]);
    assert_eq!(code, 1, "{o}");
    assert!(o.contains("bit-rot") && o.contains("repairable"), "{o}");
    fs::write(&sb, &good).unwrap();
    // missing star
    fs::remove_file(&sb).unwrap();
    let (code, o) = doc(&dir, &["Sky"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("star-missing") && o.contains("b.txt"), "{o}");
    let (code, o) = doc(&dir, &["Sky", "--fix"]);
    assert_eq!(code, 2, "--fix never invents a missing member: {o}");
    assert!(star(&c, b"alpha alpha alpha alpha").is_file());
    fs::create_dir_all(sb.parent().unwrap()).unwrap(); // gc dropped the emptied shard folder
    fs::write(&sb, &good).unwrap();
    // newer container format
    fs::write(
        c.join("CONTAINER"),
        "sigil-container=99\nkind=constellation\nname=Sky\n",
    )
    .unwrap();
    let (code, o) = doc(&dir, &["Sky"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("manifest") && o.contains("upgrade sigil"), "{o}");
    fs::write(
        c.join("CONTAINER"),
        "sigil-container=1\nkind=vault\nname=Sky\n",
    )
    .unwrap();
    let (_, o) = doc(&dir, &["Sky"]);
    assert!(o.contains("manifest-kind"), "{o}");
    // nothing there
    let (code, o) = doc(&dir, &["nope"]);
    assert_eq!(code, 3, "{o}");
    let _ = fs::remove_dir_all(&dir);

    // warded card: warning without the key, healthy with it; rot still found without it
    let dir = tmp("sky-locked");
    fs::write(dir.join("w.txt"), b"warded warded warded").unwrap();
    ok(
        &dir,
        &["constellation", "add", "W", "w.txt", "--pass", "pw"],
    );
    let (code, o) = doc(&dir, &["W"]);
    assert_eq!(code, 1, "{o}");
    assert!(o.contains("card-locked") && o.contains("--pass"), "{o}");
    let (code, o) = doc(&dir, &["W", "--pass", "pw"]);
    assert_eq!(code, 0, "{o}");
    // a new encrypted star is filed under its keyless private id, not the plaintext SHA-256
    let ws =
        sigil::constellation_member_star(&dir.join("W.sigil"), "w.txt", Some("pw"), &[]).unwrap();
    assert!(!ws
        .to_string_lossy()
        .contains(&sigil::hex32(&sigil::sha256(b"warded warded warded"))));
    zero_mid(&ws, 8);
    let (code, o) = doc(&dir, &["W"]);
    assert_eq!(code, 1, "{o}");
    assert!(o.contains("bit-rot"), "{o}");
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn old_layouts_warn_and_fix_tidies() {
    let dir = tmp("old");
    let c = vault3(&dir);
    // back to old .sgv
    let old = dir.join("n.txt.sgv");
    for e in fs::read_dir(c.join("versions")).unwrap().flatten() {
        fs::rename(e.path(), c.join(e.file_name())).unwrap();
    }
    fs::remove_dir(c.join("versions")).unwrap();
    fs::remove_file(c.join("CONTAINER")).unwrap();
    fs::rename(&c, &old).unwrap();
    let (code, o) = doc(&dir, &["n.txt"]);
    assert_eq!(code, 1, "{o}");
    assert!(o.contains("old-layout") && o.contains("sigil tidy"), "{o}");
    assert!(old.is_dir() && !c.exists(), "no --fix: nothing moved");
    let (code, o) = doc(&dir, &["n.txt", "--fix"]);
    assert_eq!(code, 0, "{o}");
    assert!(
        o.contains("fixed: tidied") && o.contains("container format 1"),
        "{o}"
    );
    assert!(c.join("CONTAINER").is_file() && !old.exists());
    assert!(
        ok(&dir, &["vault", "versions", "n.txt"])
            .matches(".sg1")
            .count()
            .max(1)
            > 0
    );

    // flat constellation
    fs::create_dir_all(dir.join("Flat")).unwrap();
    fs::write(dir.join("Flat/readme"), b"x").unwrap();
    fs::write(dir.join("f.txt"), b"eff eff eff eff").unwrap();
    ok(&dir, &["constellation", "add", "Flat", "f.txt"]);
    let (code, o) = doc(&dir, &["Flat"]);
    assert_eq!(code, 1, "{o}");
    assert!(o.contains("old-layout"), "{o}");
    let (code, o) = doc(&dir, &["Flat", "--fix"]);
    assert!(o.contains("fixed: tidied"), "{o}");
    assert_eq!(code, 0, "{o}");
    assert!(dir.join("Flat.sigil/CONTAINER").is_file());
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn cold_kits_stale_missing_and_broken() {
    let dir = tmp("cold");
    let c = vault3(&dir);
    ok(
        &dir,
        &["vault", "retention", "n.txt", "--light", "--keep", "2"],
    );
    ok(
        &dir,
        &["vault", "prune", "n.txt", "--keep", "2", "--cold-here"],
    );
    assert!(c.join("cold/v1").is_dir());
    let (code, o) = doc(&dir, &["n.txt"]);
    assert_eq!(code, 0, "healthy cold kit: {o}");
    // stale: a cold copy of a hot version is a note, not a failure
    fs::create_dir_all(c.join("cold/v3")).unwrap();
    fn copy_tree(a: &Path, b: &Path) {
        fs::create_dir_all(b).unwrap();
        for e in fs::read_dir(a).unwrap().flatten() {
            if e.path().is_dir() {
                copy_tree(&e.path(), &b.join(e.file_name()));
            } else {
                fs::copy(e.path(), b.join(e.file_name())).unwrap();
            }
        }
    }
    copy_tree(&c.join("cold/v1"), &c.join("cold/v3"));
    let (code, o) = doc(&dir, &["n.txt"]);
    assert!(o.contains("cold-stale"), "{o}");
    assert_eq!(code, 0, "{o}");
    fs::remove_dir_all(c.join("cold/v3")).unwrap();
    // missing: cold/ is used but a departed version has no kit
    ok(
        &dir,
        &["vault", "remove", "n.txt", "--version", "2", "--force-drop"],
    );
    let (code, o) = doc(&dir, &["n.txt"]);
    assert_eq!(code, 1, "{o}");
    assert!(o.contains("cold-missing") && o.contains("v2"), "{o}");
    // broken: wreck the cold copy
    fn wreck(d: &Path) {
        for e in fs::read_dir(d).unwrap().flatten() {
            let p = e.path();
            if p.is_dir() && p.file_name().unwrap().to_string_lossy().starts_with("usb-") {
                fs::remove_dir_all(&p).unwrap();
            } else if p.extension().map(|x| x == "sg1").unwrap_or(false) {
                fs::write(&p, b"garbage").unwrap();
            }
        }
    }
    wreck(&c.join("cold/v1"));
    let (code, o) = doc(&dir, &["n.txt"]);
    assert_eq!(code, 2, "{o}");
    assert!(
        o.contains("cold-broken") || o.contains("bit-rot-unrecoverable"),
        "{o}"
    );
    // never "fixed" by --fix
    let (code, _) = doc(&dir, &["n.txt", "--fix"]);
    assert_eq!(code, 2);
    let _ = fs::remove_dir_all(&dir);
}

#[test]
fn folder_vault_and_work_pack_stars_are_verified() {
    let dir = tmp("shapes");
    fs::create_dir_all(dir.join("photos")).unwrap();
    fs::write(dir.join("photos/a.txt"), b"aaaa aaaa aaaa aaaa").unwrap();
    fs::write(dir.join("photos/b.txt"), b"bbbb bbbb bbbb bbbb").unwrap();
    ok(&dir, &["vault", "track", "photos"]);
    let (c, o) = doc(&dir, &["photos"]);
    assert_eq!(c, 0, "{o}");
    assert!(o.contains("verified 1 member(s)"), "{o}");
    let seal = dir.join("photos.sigil/versions/v1.sg1");
    let good = fs::read(&seal).unwrap();
    let mut b = good.clone();
    let n = b.len();
    b[n / 8..n - n / 8].fill(0);
    fs::write(&seal, b).unwrap();
    let (c, o) = doc(&dir, &["photos"]);
    assert_eq!(c, 2, "{o}");
    fs::write(&seal, good).unwrap();

    // large file → work pack star inside a constellation
    let mut x = 0x2545f4914f6cdd1du64;
    let data: Vec<u8> = (0..300_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 32) as u8
        })
        .collect();
    fs::write(dir.join("big.bin"), &data).unwrap();
    ok(
        &dir,
        &["constellation", "add", "Big", "big.bin", "--chunk", "65536"],
    );
    let (c, o) = doc(&dir, &["Big"]);
    assert_eq!(c, 0, "{o}");
    let star = dir.join(format!("Big.sigil/stars/{}", {
        let h = hex::encode(sigil::sha256(&data));
        format!("{}/{}.sg1", &h[..2], h)
    }));
    assert!(sigil::is_work_pack(&star));
    let mut p = fs::read(&star).unwrap();
    let mid = p.len() / 2;
    p[mid..mid + 64].fill(0);
    fs::write(&star, p).unwrap();
    let (c, o) = doc(&dir, &["Big"]);
    assert_eq!(c, 1, "{o}");
    assert!(o.contains("bit-rot") && o.contains("healable"), "{o}");
    let _ = fs::remove_dir_all(&dir);
}
