//! CLI: encrypt-to constellations (`--to` / `--identity`) incl. atlas bags.
use std::path::Path;
use std::process::{Command, Output};

fn sigil(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .env_remove("SIGIL_SOFT_AUTHENTICATOR")
        .args(args)
        .output()
        .expect("run sigil")
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

fn ok(o: Output) -> String {
    assert!(o.status.success(), "{}", text(&o));
    text(&o)
}

fn fails(o: Output) -> String {
    assert!(!o.status.success(), "expected failure: {}", text(&o));
    text(&o)
}

#[test]
fn encrypt_to_constellation_cli() {
    let dir = std::env::temp_dir().join(format!("sigil-cli-sky-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(dir.join("docs/sub")).unwrap();
    std::fs::write(dir.join("docs/a.txt"), b"alpha").unwrap();
    let mut x = 0x9e3779b97f4a7c15u64;
    let big: Vec<u8> = (0..300_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    std::fs::write(dir.join("docs/sub/big.bin"), &big).unwrap();
    std::fs::write(dir.join("extra.txt"), b"extra").unwrap();

    ok(sigil(&dir, &["keygen", "-o", "alice.sgk", "--pub-out", "alice.pub"]));
    ok(sigil(&dir, &["keygen", "-o", "eve.sgk", "--pub-out", "eve.pub"]));

    let out = ok(sigil(
        &dir,
        &["constellation", "add", "Sky", "docs", "--to", "alice.pub", "--chunk", "131072"],
    ));
    assert!(out.contains("encrypt-to 1 recipient") && out.contains("stars=2"), "{out}");

    // Adding again needs the identity to read the card, and --to to keep it encrypt-to.
    let e = fails(sigil(&dir, &["constellation", "add", "Sky", "extra.txt", "--to", "alice.pub"]));
    assert!(e.contains("--identity"), "{e}");
    let e = fails(sigil(&dir, &["constellation", "add", "Sky", "extra.txt", "--identity", "alice.sgk"]));
    assert!(e.contains("encrypt-to") && e.contains("--to"), "{e}");
    ok(sigil(
        &dir,
        &["constellation", "add", "Sky", "extra.txt", "--to", "alice.pub", "--identity", "alice.sgk"],
    ));

    let e = fails(sigil(&dir, &["scry", "Sky"]));
    assert!(e.contains("--identity"), "{e}");
    let s = ok(sigil(&dir, &["constellation", "scry", "Sky", "--identity", "alice.sgk"]));
    assert!(s.contains("stars=3") && !s.contains("MISSING"), "{s}");

    fails(sigil(&dir, &["de-scribe", "-o", "nope", "Sky", "--identity", "eve.sgk"]));
    ok(sigil(&dir, &["de-scribe", "-o", "out", "Sky", "--identity", "alice.sgk"]));
    assert_eq!(std::fs::read(dir.join("out/a.txt")).unwrap(), b"alpha");
    assert_eq!(std::fs::read(dir.join("out/sub/big.bin")).unwrap(), big);
    assert_eq!(std::fs::read(dir.join("out/extra.txt")).unwrap(), b"extra");

    // Atlas bag: locked card needs the identity to bag; the bag opens with it.
    fails(sigil(&dir, &["constellation", "atlas", "Sky", "-o", "bag.sga"]));
    ok(sigil(&dir, &["constellation", "atlas", "Sky", "-o", "bag.sga", "--identity", "alice.sgk"]));
    fails(sigil(&dir, &["de-scribe", "-o", "bag-none", "bag.sga"]));
    ok(sigil(&dir, &["de-scribe", "-o", "bag-out", "bag.sga", "--identity", "alice.sgk"]));
    assert_eq!(std::fs::read(dir.join("bag-out/sub/big.bin")).unwrap(), big);

    // A named star gone: still refused.
    std::fs::remove_file(dir.join("Sky/extra.txt.sg1")).unwrap();
    let e = fails(sigil(&dir, &["de-scribe", "-o", "out2", "Sky", "--identity", "alice.sgk"]));
    assert!(e.contains("missing a star") && e.contains("extra.txt"), "{e}");
    let _ = std::fs::remove_dir_all(&dir);
}
