//! `verify --read-data[-subset]` on constellations: each member's star is opened to its
//! original bytes. A locked card needs its key (key problem, exit 1, never "too damaged");
//! real damage still exits 2 as NOT recoverable; an atlas bag is refused.
mod common;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn sigil(d: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(d)
        .env_remove("SIGIL_SOFT_AUTHENTICATOR")
        .args(common::pass_via_file(args))
        .output()
        .expect("run sigil")
}

fn all(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn ok(d: &Path, args: &[&str]) -> String {
    let o = sigil(d, args);
    assert!(o.status.success(), "{args:?}: {}", all(&o));
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn noise(n: usize, mut x: u64) -> Vec<u8> {
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn tree(d: &Path, name: &str) -> Vec<u8> {
    fs::create_dir_all(d.join(name).join("sub")).unwrap();
    fs::write(d.join(name).join("a.txt"), b"alpha alpha alpha").unwrap();
    let big = noise(60_000, 7);
    fs::write(d.join(name).join("sub/c.bin"), &big).unwrap();
    big
}

#[test]
fn plain_constellation_deep_read() {
    let d = common::scratch("rd-sky-plain");
    tree(&d, "docs");
    ok(&d, &["constellation", "add", "Sky", "docs"]);
    let j = ok(&d, &["verify", "Sky", "--read-data", "--json"]);
    assert!(
        j.contains("\"read_data\":{\"kind\":\"constellation\""),
        "{j}"
    );
    assert!(j.contains("\"total_parts\":2,\"checked\":[0,1]"), "{j}");
    assert!(
        j.contains("\"bytes_read\":60017,\"failed\":[],\"skipped\":[]"),
        "{j}"
    );
    let j = ok(
        &d,
        &[
            "verify",
            "Sky",
            "--read-data-subset",
            "50%",
            "--subset-offset",
            "1",
            "--json",
        ],
    );
    assert!(j.contains("\"checked\":[1]"), "{j}");
}

#[test]
fn locked_card_needs_the_key_not_damage() {
    let d = common::scratch("rd-sky-locked");
    tree(&d, "docs");
    ok(&d, &["constellation", "add", "--pass", "pw", "Enc", "docs"]);
    let j = ok(
        &d,
        &["verify", "Enc", "--pass", "pw", "--read-data", "--json"],
    );
    assert!(j.contains("\"bytes_read\":60017,\"failed\":[]"), "{j}");
    for args in [
        &["verify", "Enc", "--read-data", "--json"][..],
        &["verify", "Enc", "--pass", "nope", "--read-data", "--json"][..],
    ] {
        let o = sigil(&d, args);
        assert_eq!(o.status.code(), Some(1), "{args:?}: {}", all(&o));
        let t = all(&o);
        assert!(
            !t.contains("too damaged") && t.contains("--identity"),
            "{t}"
        );
        assert!(!t.contains("\"bytes_read\":60017"), "{t}");
    }
}

#[test]
fn damaged_star_is_not_recoverable() {
    let d = common::scratch("rd-sky-dmg");
    let big = tree(&d, "docs");
    ok(&d, &["constellation", "add", "Sky", "docs"]);
    let star = sigil::container::star_path(&d.join("Sky.sigil"), &sigil::sha256(&big));
    let mut b = fs::read(&star).unwrap();
    let (a, z) = (b.len() * 20 / 100, b.len() * 95 / 100);
    b[a..z].fill(0);
    fs::write(&star, &b).unwrap();
    let o = sigil(&d, &["verify", "Sky", "--read-data", "--json"]);
    assert_eq!(o.status.code(), Some(2), "{}", all(&o));
    let t = all(&o);
    assert!(
        t.contains("NOT recoverable") && !t.contains("key problem"),
        "{t}"
    );
}

#[test]
fn atlas_bag_refused() {
    let d = common::scratch("rd-sky-atlas");
    tree(&d, "docs");
    ok(&d, &["constellation", "add", "Sky", "docs"]);
    ok(&d, &["constellation", "atlas", "Sky", "-o", "s.sga"]);
    let sga = d.join("s.sga");
    assert!(sga.exists(), "atlas written");
    let o = sigil(&d, &["verify", sga.to_str().unwrap(), "--read-data"]);
    assert!(!o.status.success());
    assert!(
        all(&o).contains("atlas bag is not supported yet"),
        "{}",
        all(&o)
    );
}
