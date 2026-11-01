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

/// An atlas bag is deep-read like its constellation (kind "atlas"); plain verify / scry
/// check every bag star too, so a damaged bag never reads healthy.
#[test]
fn atlas_bag_deep_read() {
    let d = common::scratch("rd-sky-atlas");
    tree(&d, "docs");
    ok(&d, &["constellation", "add", "Sky", "docs"]);
    ok(&d, &["constellation", "atlas", "Sky", "-o", "s.sga"]);
    let j = ok(&d, &["verify", "s.sga", "--read-data", "--json"]);
    assert!(j.contains("\"read_data\":{\"kind\":\"atlas\""), "{j}");
    assert!(
        j.contains("\"bytes_read\":60017,\"failed\":[],\"skipped\":[]"),
        "{j}"
    );

    let mut b = fs::read(d.join("s.sga")).unwrap();
    let (a, z) = (b.len() * 40 / 100, b.len() * 90 / 100);
    b[a..z].fill(0);
    fs::write(d.join("dmg.sga"), &b).unwrap();
    // Plain verify / scry check bag stars too: never a false healthy.
    for cmd in ["verify", "scry"] {
        let o = sigil(&d, &[cmd, "dmg.sga", "--json"]);
        assert_eq!(o.status.code(), Some(2), "{}", all(&o));
        let t = all(&o);
        assert!(t.contains("\"health\":\"not-recoverable\""), "{t}");
        assert!(t.contains("\"beyond_repair\":1"), "{t}");
        assert!(!t.contains("\"health\":\"healthy\""), "{t}");
        assert!(
            t.contains("NOT recoverable: 1 star(s) beyond repair"),
            "text agrees: {t}"
        );
    }
    let j = ok(&d, &["scry", "s.sga", "--json"]);
    assert!(
        j.contains("\"health\":\"healthy\"") && j.contains("\"present\":2,"),
        "{j}"
    );
    // One flipped byte in a star: repairable, and said so in text and JSON.
    let mut b = fs::read(d.join("s.sga")).unwrap();
    let k = b.len() * 60 / 100;
    b[k] ^= 0x40;
    fs::write(d.join("torn.sga"), &b).unwrap();
    let j = ok(&d, &["scry", "torn.sga", "--json"]);
    assert!(
        j.contains("\"health\":\"needs-repair\"") && j.contains("needs repair:"),
        "{j}"
    );
    let o = sigil(&d, &["verify", "dmg.sga", "--read-data", "--json"]);
    assert_eq!(o.status.code(), Some(2), "{}", all(&o));
    let t = all(&o);
    // The plain check now stops it first (as for folders and marks).
    assert!(t.contains("NOT recoverable"), "{t}");
    assert!(!t.contains("key problem"), "{t}");

    ok(&d, &["constellation", "add", "--pass", "pw", "Enc", "docs"]);
    ok(
        &d,
        &[
            "constellation",
            "atlas",
            "Enc",
            "--pass",
            "pw",
            "-o",
            "e.sga",
        ],
    );
    let j = ok(
        &d,
        &["verify", "e.sga", "--pass", "pw", "--read-data", "--json"],
    );
    assert!(
        j.contains("\"kind\":\"atlas\"") && j.contains("\"failed\":[]"),
        "{j}"
    );
    let o = sigil(&d, &["verify", "e.sga", "--read-data"]);
    assert_eq!(o.status.code(), Some(1), "{}", all(&o));
    assert!(!all(&o).contains("too damaged"), "{}", all(&o));
}

/// `sigil mend` on an atlas bag (what the needs-repair line tells people to run): a
/// repairable bag is healed into a new bag; a bag past repair is refused, nothing written.
#[test]
fn mend_atlas_bag() {
    let d = common::scratch("mend-atlas");
    let big = tree(&d, "docs");
    ok(&d, &["constellation", "add", "Sky", "docs"]);
    ok(&d, &["constellation", "atlas", "Sky", "-o", "s.sga"]);
    let good = fs::read(d.join("s.sga")).unwrap();

    let mut b = good.clone();
    let k = b.len() * 60 / 100;
    b[k] ^= 0x40;
    fs::write(d.join("torn.sga"), &b).unwrap();
    let t = ok(&d, &["scry", "torn.sga"]);
    assert!(
        t.contains("needs repair:") && t.contains("sigil mend"),
        "{t}"
    );
    let j = ok(&d, &["mend", "torn.sga", "-o", "fixed.sga", "--json"]);
    assert!(
        j.contains("\"kind\":\"atlas\"") && !j.contains("\"mended\":[]"),
        "{j}"
    );
    let j = ok(&d, &["scry", "fixed.sga", "--json"]);
    assert!(j.contains("\"health\":\"healthy\""), "{j}");
    ok(&d, &["unseal", "fixed.sga", "-o", "out"]);
    assert_eq!(fs::read(d.join("out/sub/c.bin")).unwrap(), big);

    let j = ok(&d, &["mend", "s.sga", "-o", "same.sga", "--json"]);
    assert!(j.contains("\"mended\":[]"), "{j}");

    let mut b = good;
    let (a, z) = (b.len() * 40 / 100, b.len() * 90 / 100);
    b[a..z].fill(0);
    fs::write(d.join("dmg.sga"), &b).unwrap();
    let o = sigil(&d, &["mend", "dmg.sga", "-o", "x.sga"]);
    assert_eq!(o.status.code(), Some(2), "{}", all(&o));
    assert!(all(&o).contains("beyond repair"), "{}", all(&o));
    assert!(!d.join("x.sga").exists() && !d.join("x.sga.mend-part").exists());

    ok(&d, &["constellation", "add", "--pass", "pw", "Enc", "docs"]);
    ok(
        &d,
        &[
            "constellation",
            "atlas",
            "Enc",
            "--pass",
            "pw",
            "-o",
            "e.sga",
        ],
    );
    let mut b = fs::read(d.join("e.sga")).unwrap();
    let k = b.len() * 60 / 100;
    b[k] ^= 0x40;
    fs::write(d.join("etorn.sga"), &b).unwrap();
    ok(&d, &["mend", "etorn.sga", "-o", "efixed.sga"]);
    let j = ok(
        &d,
        &[
            "verify",
            "efixed.sga",
            "--pass",
            "pw",
            "--read-data",
            "--json",
        ],
    );
    assert!(
        j.contains("\"health\":\"healthy\"") && j.contains("\"failed\":[]"),
        "{j}"
    );
}
