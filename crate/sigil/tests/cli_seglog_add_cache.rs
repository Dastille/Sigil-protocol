//! `sigil log add --cache`: skip re-hashing files whose size+mtime/ctime/inode stamp is unchanged.
mod common;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use std::time::Duration;

fn run(d: &Path, a: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(d)
        .env_remove("SIGIL_SOFT_AUTHENTICATOR")
        .args(a)
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
fn ok(d: &Path, a: &[&str]) -> String {
    let o = run(d, a);
    assert!(o.status.success(), "{a:?}: {}", text(&o));
    text(&o)
}
fn put(d: &Path, rel: &str, body: &str) {
    let p = d.join("photos").join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, body).unwrap();
}
/// Stamps younger than 2 s at cache-write time are not trusted; let them age.
fn age() {
    std::thread::sleep(Duration::from_millis(2300));
}

#[test]
fn cache_skips_unchanged_and_never_misses_a_change() {
    let d = common::scratch("add-cache");
    ok(&d, &["log", "init", "ev"]);
    put(&d, "a.txt", "aaaa\n");
    put(&d, "b/c.txt", "cccc\n");
    put(&d, "d.txt", "dddd\n");
    age();
    // without --cache: no sidecar
    ok(&d, &["log", "add", "ev", "photos"]);
    assert!(!d.join("ev.sigil/ADDCACHE").exists());
    let o = ok(&d, &["log", "add", "ev", "photos", "--cache"]);
    assert!(
        o.contains("unchanged 3") && !o.contains("not re-hashed"),
        "{o}"
    );
    assert!(d.join("ev.sigil/ADDCACHE").is_file());
    let o = ok(&d, &["log", "add", "ev", "photos", "--cache"]);
    assert!(
        o.contains("unchanged 3") && o.contains("3 not re-hashed"),
        "{o}"
    );
    // the sidecar is not a stray for verify / doctor
    ok(&d, &["log", "verify", "ev"]);

    // same size, mtime put back: ctime still moves, so the change is seen
    let p = d.join("photos/a.txt");
    let m = fs::metadata(&p).unwrap().modified().unwrap();
    fs::write(&p, "AAAA\n").unwrap();
    fs::File::options()
        .write(true)
        .open(&p)
        .unwrap()
        .set_modified(m)
        .unwrap();
    let o = ok(&d, &["log", "add", "ev", "photos", "--cache"]);
    assert!(o.contains("changed 1") && o.contains("unchanged 2"), "{o}");
    ok(&d, &["log", "restore", "ev", "a.txt", "-o", "a.out"]);
    assert_eq!(fs::read_to_string(d.join("a.out")).unwrap(), "AAAA\n");

    // a freshly sealed file is racy at first; after aging, cached again
    age();
    ok(&d, &["log", "add", "ev", "photos", "--cache"]);
    let o = ok(&d, &["log", "add", "ev", "photos", "--cache"]);
    assert!(o.contains("3 not re-hashed"), "{o}");

    // corrupt cache: ignored with a note, everything hashed
    fs::write(d.join("ev.sigil/ADDCACHE"), "garbage\n").unwrap();
    let o = ok(&d, &["log", "add", "ev", "photos", "--cache"]);
    assert!(
        o.contains("add cache ignored")
            && o.contains("unchanged 3")
            && !o.contains("not re-hashed"),
        "{o}"
    );

    // a size change is always re-hashed and sealed
    put(&d, "d.txt", "dddd and more\n");
    let o = ok(&d, &["log", "add", "ev", "photos", "--cache"]);
    assert!(o.contains("changed 1"), "{o}");
    // dry run uses the cache but writes nothing new
    let before = fs::read(d.join("ev.sigil/ADDCACHE")).unwrap();
    ok(&d, &["log", "add", "ev", "photos", "--cache", "--dry-run"]);
    assert_eq!(fs::read(d.join("ev.sigil/ADDCACHE")).unwrap(), before);
}

#[test]
fn cache_from_another_source_is_ignored_and_private_refused() {
    let d = common::scratch("add-cache-src");
    ok(&d, &["log", "init", "ev"]);
    put(&d, "a.txt", "a\n");
    fs::create_dir_all(d.join("other")).unwrap();
    fs::write(d.join("other/a.txt"), "a\n").unwrap();
    age();
    ok(&d, &["log", "add", "ev", "photos", "--cache"]);
    let o = ok(&d, &["log", "add", "ev", "other", "--cache"]);
    assert!(
        o.contains("another source folder") && !o.contains("not re-hashed"),
        "{o}"
    );

    fs::write(d.join("pw"), "pw\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join("pw"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    ok(
        &d,
        &["log", "init", "pv", "--private-index", "--pass-file", "pw"],
    );
    let o = run(
        &d,
        &["log", "add", "pv", "photos", "--cache", "--pass-file", "pw"],
    );
    assert!(
        !o.status.success() && text(&o).contains("private INDEX"),
        "{}",
        text(&o)
    );
    assert!(!d.join("pv.sigil/ADDCACHE").exists());
}
