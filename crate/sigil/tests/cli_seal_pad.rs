//! CLI `--pad` on encrypted single-file seals: round-trip, default off, plain refuse.
mod common;
use std::path::Path;
use std::process::{Command, Output};

fn sigil(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(common::pass_via_file(args))
        .output()
        .expect("run sigil")
}

fn ok(o: Output) -> String {
    assert!(
        o.status.success(),
        "stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr)
}

fn fail(o: Output) -> String {
    assert!(
        !o.status.success(),
        "expected failure; stdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned() + &String::from_utf8_lossy(&o.stderr)
}

fn sample(tag: &str) -> (common::Scratch, Vec<u8>) {
    let dir = common::scratch(&format!("cli-pad-{tag}"));
    // Mix of compressible + noise so deflate runs; ~50 KiB so bucket padding is visible.
    let mut x = 0xcbf2_9ce4_8422_2325u64;
    let data: Vec<u8> = (0..50_000usize)
        .map(|i| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            if i % 5 == 0 {
                b'A' + (i % 26) as u8
            } else {
                (x >> 16) as u8
            }
        })
        .collect();
    std::fs::write(dir.join("note.txt"), &data).unwrap();
    (dir, data)
}

#[test]
fn pad_bucket_and_max_round_trip_and_grow() {
    let (dir, data) = sample("rt");
    ok(sigil(
        &dir,
        &["seal", "-o", "off.sg1", "note.txt", "--pass", "pw"],
    ));
    ok(sigil(
        &dir,
        &[
            "seal",
            "-o",
            "bucket.sg1",
            "note.txt",
            "--pass",
            "pw",
            "--pad",
            "bucket",
        ],
    ));
    ok(sigil(
        &dir,
        &[
            "seal", "-o", "max.sg1", "note.txt", "--pass", "pw", "--pad", "max",
        ],
    ));
    let off = std::fs::metadata(dir.join("off.sg1")).unwrap().len();
    let bucket = std::fs::metadata(dir.join("bucket.sg1")).unwrap().len();
    let max = std::fs::metadata(dir.join("max.sg1")).unwrap().len();
    assert!(bucket > off, "bucket {bucket} > off {off}");
    assert!(max >= bucket, "max {max} >= bucket {bucket}");

    ok(sigil(
        &dir,
        &["unseal", "-o", "b.out", "bucket.sg1", "--pass", "pw"],
    ));
    ok(sigil(
        &dir,
        &["unseal", "-o", "m.out", "max.sg1", "--pass", "pw"],
    ));
    assert_eq!(std::fs::read(dir.join("b.out")).unwrap(), data);
    assert_eq!(std::fs::read(dir.join("m.out")).unwrap(), data);
}

#[test]
fn pad_default_off_matches_explicit_off() {
    let (dir, _) = sample("default");
    ok(sigil(
        &dir,
        &["seal", "-o", "a.sg1", "note.txt", "--pass", "pw"],
    ));
    ok(sigil(
        &dir,
        &[
            "seal", "-o", "b.sg1", "note.txt", "--pass", "pw", "--pad", "off",
        ],
    ));
    // Same plaintext → same folded length (file bytes differ: salt/nonce/CEK).
    let (ha, _, _) = sigil::locate_header(&std::fs::read(dir.join("a.sg1")).unwrap()).unwrap();
    let (hb, _, _) = sigil::locate_header(&std::fs::read(dir.join("b.sg1")).unwrap()).unwrap();
    assert_eq!(ha.folded_len, hb.folded_len);
}

#[test]
fn plain_seal_with_pad_fails_closed() {
    let (dir, _) = sample("plain");
    let msg = fail(sigil(
        &dir,
        &["seal", "-o", "x.sg1", "note.txt", "--pad", "bucket"],
    ));
    assert!(
        msg.contains("--pad") && msg.to_lowercase().contains("encrypt"),
        "{msg}"
    );
    assert!(!dir.join("x.sg1").exists());
}

#[test]
fn padded_cli_seal_wrong_pass_fails_closed() {
    let (dir, _) = sample("wrong");
    ok(sigil(
        &dir,
        &[
            "seal", "-o", "p.sg1", "note.txt", "--pass", "pw", "--pad", "bucket",
        ],
    ));
    let msg = fail(sigil(
        &dir,
        &["unseal", "-o", "out", "p.sg1", "--pass", "nope"],
    ));
    assert!(!msg.is_empty());
    assert!(
        !dir.join("out").exists()
            || std::fs::read(dir.join("out")).unwrap()
                != std::fs::read(dir.join("note.txt")).unwrap()
    );
}
