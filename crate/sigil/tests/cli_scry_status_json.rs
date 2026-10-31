//! `scry --json` / `verify --json` / `constellation scry --json` carry a structured
//! `status` object (schema 1) next to the `report` text: healthy, needs-repair and
//! not-recoverable for a mark, a large-file pack, plain and encrypted folder packs and
//! a constellation.
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

fn ok(d: &Path, args: &[&str]) {
    let o = sigil(d, args);
    assert!(
        o.status.success(),
        "{args:?}: {}",
        String::from_utf8_lossy(&o.stderr)
    );
}

/// Runs with `--json`; checks the exit code and returns the single JSON line.
fn json(d: &Path, args: &[&str], code: i32) -> String {
    let mut a = args.to_vec();
    a.push("--json");
    let o = sigil(d, &a);
    let out = String::from_utf8_lossy(&o.stdout).into_owned();
    assert_eq!(o.status.code(), Some(code), "{a:?}: {out}");
    assert_eq!(out.lines().count(), 1, "{out}");
    assert!(out.contains("\"report\":\""), "report kept: {out}");
    assert!(out.contains("\"status\":{\"schema\":1,"), "{out}");
    out
}

fn health(j: &str) -> &str {
    let k = "\"health\":\"";
    let i = j.find(k).expect("health") + k.len();
    &j[i..i + j[i..].find('"').expect("end")]
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

fn wreck(p: &Path, from: f64, to: f64) {
    let mut b = fs::read(p).unwrap();
    let (a, z) = (
        (b.len() as f64 * from) as usize,
        (b.len() as f64 * to) as usize,
    );
    b[a..z].fill(0);
    fs::write(p, b).unwrap();
}

#[test]
fn mark_status_healthy_repair_dead() {
    let d = common::scratch("status-mark");
    fs::write(d.join("photo.jpg"), noise(300_000, 7)).unwrap();
    ok(&d, &["seal", "-o", "photo.sg1", "photo.jpg"]);
    for cmd in ["scry", "verify"] {
        let j = json(&d, &[cmd, "photo.sg1"], 0);
        assert_eq!(health(&j), "healthy", "{j}");
        assert!(
            j.contains("\"kind\":\"mark\"") && j.contains("\"reason\":null"),
            "{j}"
        );
        assert!(
            j.contains("\"merkle_closed\":true") && j.contains("\"orig_len\":300000"),
            "{j}"
        );
        assert!(
            j.contains("\"shards\":{\"live\":16,\"total\":16,\"need\":"),
            "{j}"
        );
    }
    fs::copy(d.join("photo.sg1"), d.join("torn.sg1")).unwrap();
    wreck(&d.join("torn.sg1"), 0.50, 0.55);
    let j = json(&d, &["scry", "torn.sg1"], 0);
    assert_eq!(health(&j), "needs-repair", "{j}");
    assert!(
        j.contains("\"merkle_closed\":false") && !j.contains("\"repair\":null"),
        "{j}"
    );
    assert!(!j.contains("\"live\":16,"), "{j}");

    fs::copy(d.join("photo.sg1"), d.join("dead.sg1")).unwrap();
    wreck(&d.join("dead.sg1"), 0.30, 0.90);
    for cmd in ["scry", "verify"] {
        let j = json(&d, &[cmd, "dead.sg1"], 2);
        assert!(j.starts_with("{\"ok\":false,"), "{j}");
        assert_eq!(health(&j), "not-recoverable", "{j}");
        assert!(j.contains("\"reason\":\"live="), "{j}");
    }

    ok(&d, &["seal", "--pass", "pw", "-o", "enc.sg1", "photo.jpg"]);
    let j = json(&d, &["scry", "enc.sg1"], 0);
    assert!(
        j.contains("\"encrypted\":true") && health(&j) == "healthy",
        "{j}"
    );
}

#[test]
fn work_pack_status() {
    let d = common::scratch("status-work");
    fs::write(d.join("big.bin"), noise(6_000_000, 9)).unwrap();
    ok(&d, &["seal", "-o", "big.sg1", "big.bin"]);
    let j = json(&d, &["scry", "big.sg1"], 0);
    assert!(
        j.contains("\"kind\":\"work-pack\"") && health(&j) == "healthy",
        "{j}"
    );
    assert!(
        j.contains("\"orig_len\":6000000") && j.contains("\"parts\":{\"total\":"),
        "{j}"
    );
    wreck(&d.join("big.sg1"), 0.10, 0.45);
    let j = json(&d, &["verify", "big.sg1"], 2);
    assert_eq!(health(&j), "not-recoverable", "{j}");
}

#[test]
fn folder_pack_status_plain_and_encrypted() {
    let d = common::scratch("status-dir");
    fs::create_dir_all(d.join("album/sub")).unwrap();
    fs::write(d.join("album/a.txt"), b"alpha").unwrap();
    fs::write(d.join("album/sub/b.bin"), noise(200_000, 3)).unwrap();
    ok(&d, &["seal", "-o", "p.sg1", "album"]);
    ok(&d, &["seal", "--pass", "pw", "-o", "e.sg1", "album"]);
    let j = json(&d, &["scry", "p.sg1"], 0);
    assert!(
        j.contains("\"kind\":\"folder-pack\"") && j.contains("\"members\":2"),
        "{j}"
    );
    assert!(
        j.contains("\"encrypted\":false") && health(&j) == "healthy",
        "{j}"
    );
    let j = json(&d, &["scry", "e.sg1"], 0);
    assert!(
        j.contains("\"members\":2,\"encrypted\":true") && health(&j) == "healthy",
        "{j}"
    );
    assert!(!j.contains("b.bin"), "names stay hidden without a key: {j}");
    for f in ["p.sg1", "e.sg1"] {
        wreck(&d.join(f), 0.20, 0.95);
        let j = json(&d, &["scry", f], 2);
        assert_eq!(health(&j), "not-recoverable", "{j}");
    }
}

#[test]
fn constellation_status() {
    let d = common::scratch("status-sky");
    fs::create_dir_all(d.join("docs/sub")).unwrap();
    fs::write(d.join("docs/a.txt"), b"alpha alpha alpha").unwrap();
    let big = noise(200_000, 0x9e37_79b9_7f4a_7c15);
    fs::write(d.join("docs/sub/big.bin"), &big).unwrap();
    ok(&d, &["constellation", "add", "Sky", "docs"]);
    let j = json(&d, &["constellation", "scry", "Sky"], 0);
    assert!(
        j.contains("\"kind\":\"constellation\"") && health(&j) == "healthy",
        "{j}"
    );
    assert!(j.contains("\"stars\":{\"members\":2,"), "{j}");
    assert!(
        j.contains("\"missing\":0,\"needs_repair\":0,\"beyond_repair\":0"),
        "{j}"
    );

    let star = sigil::container::star_path(&d.join("Sky.sigil"), &sigil::sha256(&big));
    let mut b = fs::read(&star).unwrap();
    let mid = b.len() / 2;
    b[mid] ^= 0x40;
    fs::write(&star, &b).unwrap();
    let j = json(&d, &["scry", "Sky"], 0);
    assert_eq!(health(&j), "needs-repair", "{j}");
    assert!(j.contains("\"needs_repair\":1"), "{j}");

    fs::remove_file(&star).unwrap();
    let j = json(&d, &["constellation", "scry", "Sky"], 2);
    assert_eq!(health(&j), "not-recoverable", "{j}");
    assert!(j.contains("\"missing\":1"), "{j}");
}
