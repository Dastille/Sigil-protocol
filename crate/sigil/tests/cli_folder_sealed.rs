//! Encrypted folder packs hide member names and sizes by default (SGDR v2,
//! "sealed directory"). Round trip, keyless scry, --only, wrong key, tamper,
//! truncation, and the old v1 encrypted fixture still opening.
mod common;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn sigil(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(common::pass_via_file(args))
        .output()
        .expect("run sigil")
}

fn ok(o: &Output) -> String {
    assert!(
        o.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn scratch(tag: &str) -> common::Scratch {
    let d = common::scratch(&format!("cli-sealdir-{tag}"));
    std::fs::create_dir_all(d.join("album/private-sub")).unwrap();
    std::fs::write(d.join("album/visible-name-a.txt"), b"alpha alpha").unwrap();
    std::fs::write(
        d.join("album/private-sub/tax-return-2025.pdf"),
        b"pretend pdf bytes 0123456789",
    )
    .unwrap();
    d
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

fn fix(name: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("tests/fixtures/enc-v2")
        .join(name)
}

#[test]
fn encrypted_folder_hides_names_and_round_trips() {
    let d = scratch("rt");
    let out = ok(&sigil(
        &d,
        &["seal", "--pass", "pw-1", "-o", "e.sg1", "album"],
    ));
    assert!(out.contains("folder 2 files"), "{out}");
    let raw = std::fs::read(d.join("e.sg1")).unwrap();
    assert_eq!(&raw[0..5], b"SGDR\x02");
    for name in [
        &b"tax-return-2025"[..],
        b"visible-name-a",
        b"private-sub",
        b".pdf",
    ] {
        assert!(!contains(&raw, name), "name fragment leaked in the clear");
    }

    // Keyless scry: only the count.
    let s = ok(&sigil(&d, &["scry", "e.sg1"]));
    assert!(s.starts_with("folder  2 files (names hidden)"), "{s}");
    assert!(!s.contains("tax-return"), "{s}");
    assert!(s.contains("live=16/16"), "{s}");
    let v = ok(&sigil(&d, &["verify", "e.sg1"]));
    assert!(v.contains("names hidden"), "{v}");

    // With the key: listing as before.
    let s = ok(&sigil(&d, &["scry", "--pass", "pw-1", "e.sg1"]));
    assert!(s.contains("file  private-sub/tax-return-2025.pdf"), "{s}");
    assert!(s.contains("dir   private-sub/"), "{s}");

    // Full unseal and --only.
    ok(&sigil(
        &d,
        &["unseal", "--pass", "pw-1", "-o", "all", "e.sg1"],
    ));
    assert_eq!(
        std::fs::read(d.join("all/private-sub/tax-return-2025.pdf")).unwrap(),
        b"pretend pdf bytes 0123456789"
    );
    assert_eq!(
        std::fs::read(d.join("all/visible-name-a.txt")).unwrap(),
        b"alpha alpha"
    );
    ok(&sigil(
        &d,
        &[
            "unseal",
            "--pass",
            "pw-1",
            "--only",
            "private-sub/tax-return-2025.pdf",
            "-o",
            "one",
            "e.sg1",
        ],
    ));
    assert!(d.join("one/private-sub/tax-return-2025.pdf").is_file());
    assert!(!d.join("one/visible-name-a.txt").exists());

    // Keyless mend heals a torn body and keeps the names hidden.
    let mut torn = raw.clone();
    let at = 17 + (raw.len() - 17) / 2;
    for b in &mut torn[at..at + 64] {
        *b ^= 0xA5;
    }
    std::fs::write(d.join("torn.sg1"), &torn).unwrap();
    let s = ok(&sigil(&d, &["scry", "torn.sg1"]));
    assert!(!s.contains("live=16/16"), "damage visible keyless: {s}");
    let m = ok(&sigil(&d, &["mend", "torn.sg1", "-o", "m.sg1"]));
    assert!(m.contains("sealed folder pack"), "{m}");
    let healed = std::fs::read(d.join("m.sg1")).unwrap();
    assert_eq!(&healed[0..5], b"SGDR\x02");
    assert!(!contains(&healed, b"tax-return-2025"));
    let s = ok(&sigil(&d, &["scry", "m.sg1"]));
    assert!(s.contains("live=16/16"), "{s}");
    ok(&sigil(
        &d,
        &["unseal", "--pass", "pw-1", "-o", "mo", "m.sg1"],
    ));
    assert_eq!(
        std::fs::read(d.join("mo/private-sub/tax-return-2025.pdf")).unwrap(),
        b"pretend pdf bytes 0123456789"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn encrypt_to_folder_hides_names() {
    let d = scratch("to");
    ok(&sigil(&d, &["keygen", "-o", "me.sgk"]));
    let pubk = if d.join("me.sgk.pub").exists() {
        "me.sgk.pub"
    } else {
        "me.pub"
    };
    ok(&sigil(&d, &["seal", "--to", pubk, "-o", "t.sg1", "album"]));
    let raw = std::fs::read(d.join("t.sg1")).unwrap();
    assert_eq!(&raw[0..5], b"SGDR\x02");
    assert!(!contains(&raw, b"tax-return-2025"));
    let s = ok(&sigil(&d, &["scry", "--identity", "me.sgk", "t.sg1"]));
    assert!(s.contains("private-sub/tax-return-2025.pdf"), "{s}");
    ok(&sigil(
        &d,
        &["unseal", "--identity", "me.sgk", "-o", "o", "t.sg1"],
    ));
    assert!(d.join("o/private-sub/tax-return-2025.pdf").is_file());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn sealed_folder_fails_closed_on_wrong_key_tamper_and_truncation() {
    let d = scratch("tamper");
    ok(&sigil(
        &d,
        &["seal", "--pass", "pw-1", "-o", "e.sg1", "album"],
    ));
    let raw = std::fs::read(d.join("e.sg1")).unwrap();
    let expect = |o: &Output, what: &str, out: &str| {
        assert!(!o.status.success(), "{what}: must fail");
        assert!(!d.join(out).exists(), "{what}: left output behind");
    };

    // No key / wrong key.
    expect(
        &sigil(&d, &["unseal", "-o", "nokey", "e.sg1"]),
        "no key",
        "nokey",
    );
    expect(
        &sigil(&d, &["unseal", "--pass", "wrong", "-o", "wk", "e.sg1"]),
        "wrong key",
        "wk",
    );
    expect(
        &sigil(&d, &["scry", "--pass", "wrong", "e.sg1"]),
        "scry wrong key",
        "none",
    );

    // Outer member count edited: the inner pack no longer matches.
    let mut bad = raw.clone();
    bad[5] ^= 0x01;
    std::fs::write(d.join("count.sg1"), &bad).unwrap();
    expect(
        &sigil(&d, &["unseal", "--pass", "pw-1", "-o", "c", "count.sg1"]),
        "count flip",
        "c",
    );

    // Truncated body.
    std::fs::write(d.join("trunc.sg1"), &raw[..raw.len() - 7]).unwrap();
    expect(
        &sigil(&d, &["unseal", "--pass", "pw-1", "-o", "t", "trunc.sg1"]),
        "truncated",
        "t",
    );
    // Trailing junk after the body.
    let mut long = raw.clone();
    long.extend_from_slice(b"junk");
    std::fs::write(d.join("long.sg1"), &long).unwrap();
    expect(
        &sigil(&d, &["unseal", "--pass", "pw-1", "-o", "l", "long.sg1"]),
        "trailing bytes",
        "l",
    );

    // Body wrecked past repair (half of it zeroed).
    let mut wreck = raw.clone();
    let mid = 17 + (raw.len() - 17) / 4;
    for b in &mut wreck[mid..mid + (raw.len() - 17) / 2] {
        *b = 0;
    }
    std::fs::write(d.join("w.sg1"), &wreck).unwrap();
    expect(
        &sigil(&d, &["unseal", "--pass", "pw-1", "-o", "w", "w.sg1"]),
        "wrecked body",
        "w",
    );

    // Single bit flips anywhere in the body: either repaired byte-exact, or refused.
    for (i, at) in (17..raw.len()).step_by(97).enumerate() {
        let mut f = raw.clone();
        f[at] ^= 0x10;
        let name = format!("f{i}.sg1");
        let out = format!("fo{i}");
        std::fs::write(d.join(&name), &f).unwrap();
        let o = sigil(&d, &["unseal", "--pass", "pw-1", "-o", &out, &name]);
        if o.status.success() {
            assert_eq!(
                std::fs::read(d.join(&out).join("private-sub/tax-return-2025.pdf")).unwrap(),
                b"pretend pdf bytes 0123456789",
                "bit flip at {at} opened to different bytes"
            );
        } else {
            assert!(!d.join(&out).exists());
        }
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn plain_folder_pack_is_unchanged() {
    let d = scratch("plain");
    ok(&sigil(&d, &["seal", "-o", "p.sg1", "album"]));
    let raw = std::fs::read(d.join("p.sg1")).unwrap();
    assert_eq!(&raw[0..5], b"SGDR\x01");
    let s = ok(&sigil(&d, &["scry", "p.sg1"]));
    assert!(s.contains("file  private-sub/tax-return-2025.pdf"), "{s}");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn old_v1_encrypted_folder_fixture_still_opens_and_lists() {
    let d = scratch("fixture");
    let fx = fix("folder-pass-v2.sg1");
    let fx = fx.to_str().unwrap();
    // Written before sealed directories existed: names were in the clear, and still list keyless.
    let s = ok(&sigil(&d, &["scry", fx]));
    assert!(s.contains("file  a.txt"), "{s}");
    assert!(s.contains("file  sub/b.bin"), "{s}");
    ok(&sigil(
        &d,
        &[
            "unseal",
            "--pass",
            "fixture-pass",
            "--only",
            "sub/b.bin",
            "-o",
            "o",
            fx,
        ],
    ));
    assert_eq!(
        std::fs::read(d.join("o/sub/b.bin")).unwrap(),
        std::fs::read(fix("dir/sub/b.bin")).unwrap()
    );
    let o = sigil(&d, &["unseal", "--pass", "nope", "-o", "bad", fx]);
    assert!(!o.status.success());
    assert!(!d.join("bad").exists());
    let _ = std::fs::remove_dir_all(&d);
}
