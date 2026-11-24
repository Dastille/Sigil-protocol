//! CLI: `sigil mend --scan` (look only) and `sigil mend --max-secs` (scripts and
//! scheduled jobs: skip, exit 4, write nothing when the padded estimate is too long).
mod common;
use std::path::Path;
use std::process::{Command, Output};

fn sigil(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
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

fn data(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// Files in `dir` other than the ones the test made.
fn extra_files(dir: &Path, keep: &[&str]) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .expect("read dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| !keep.contains(&n.as_str()))
        .collect();
    v.sort();
    v
}

/// Seal `n` bytes as photo.sg1 and return its bytes.
fn seal(dir: &Path, n: usize) -> Vec<u8> {
    std::fs::write(dir.join("photo.bin"), data(n, 0x5eed)).expect("write");
    let o = sigil(dir, &["seal", "-o", "photo.sg1", "photo.bin"]);
    assert!(o.status.success(), "{}", text(&o));
    std::fs::read(dir.join("photo.sg1")).expect("read")
}

#[test]
fn scan_reports_and_writes_nothing() {
    let t = common::scratch("mend-scan");
    let d = t.path();
    let mut b = seal(d, 300_000);
    // Zero a stretch in the middle: one wiped region, quick repair.
    let mid = b.len() / 2;
    b[mid..mid + 4000].fill(0);
    std::fs::write(d.join("photo.sg1"), &b).expect("write");
    let o = sigil(d, &["mend", "--scan", "photo.sg1"]);
    let out = text(&o);
    assert_eq!(o.status.code(), Some(0), "{out}");
    assert!(out.contains("one damaged stretch"), "{out}");
    assert!(out.contains("quick repair"), "{out}");
    assert!(out.contains("Nothing was written"), "{out}");
    assert_eq!(
        extra_files(d, &["photo.bin", "photo.sg1"]),
        Vec::<String>::new()
    );
    assert_eq!(std::fs::read(d.join("photo.sg1")).expect("read"), b);

    let o = sigil(d, &["mend", "--scan", "--json", "photo.sg1"]);
    let j = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(j.contains("\"ok\":true"), "{j}");
    assert!(j.contains("\"kind\":\"one-region\""), "{j}");
    assert!(j.contains("\"path\":\"quick\""), "{j}");
    assert!(
        !j.contains("\"output\""),
        "scan must not name an output: {j}"
    );
}

#[test]
fn scan_clean_and_scattered() {
    let t = common::scratch("mend-scan");
    let d = t.path();
    let b = seal(d, 200_000);
    let o = sigil(d, &["mend", "--scan", "photo.sg1"]);
    assert!(text(&o).contains("no damage found"), "{}", text(&o));
    // One flipped bit every 1,000 bytes after the header.
    let mut f = b.clone();
    let mut i = 4096;
    while i < f.len() {
        f[i] ^= 0x04;
        i += 1000;
    }
    std::fs::write(d.join("rot.sg1"), &f).expect("write");
    let o = sigil(d, &["mend", "--scan", "--json", "rot.sg1"]);
    let j = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(j.contains("\"kind\":\"scattered\""), "{j}");
    assert!(j.contains("\"path\":\"deeper"), "{j}");
}

#[test]
fn max_secs_skips_with_exit_4_and_no_file() {
    let t = common::scratch("mend-scan");
    let d = t.path();
    let mut b = seal(d, 300_000);
    let mid = b.len() / 2;
    b[mid..mid + 4000].fill(0);
    std::fs::write(d.join("photo.sg1"), &b).expect("write");
    let o = sigil(d, &["mend", "--max-secs", "0", "photo.sg1"]);
    let out = text(&o);
    assert_eq!(o.status.code(), Some(4), "{out}");
    assert!(out.contains("repair skipped"), "{out}");
    assert_eq!(
        extra_files(d, &["photo.bin", "photo.sg1"]),
        Vec::<String>::new()
    );
    let o = sigil(d, &["mend", "--max-secs", "0", "--json", "photo.sg1"]);
    let j = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(
        j.contains("\"exit\":4") && j.contains("\"skipped\":true"),
        "{j}"
    );

    // A generous limit repairs as usual, and the copy opens to the original bytes.
    let o = sigil(
        d,
        &["mend", "--max-secs", "600", "-o", "fixed.sg1", "photo.sg1"],
    );
    assert!(o.status.success(), "{}", text(&o));
    let o = sigil(d, &["unseal", "fixed.sg1", "-o", "back.bin"]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(
        std::fs::read(d.join("back.bin")).expect("read"),
        data(300_000, 0x5eed)
    );
}

#[test]
fn scan_is_not_a_verdict_and_mend_still_fails_closed() {
    let t = common::scratch("mend-scan");
    let d = t.path();
    let mut b = seal(d, 200_000);
    // Wipe most of the file: far past what the parity can rebuild.
    let start = 2048.min(b.len());
    let end = b.len() * 3 / 4;
    b[start..end].fill(0);
    std::fs::write(d.join("photo.sg1"), &b).expect("write");
    let o = sigil(d, &["mend", "--scan", "photo.sg1"]);
    let out = text(&o);
    assert!(
        out.contains("too damaged") || out.contains("could not scan"),
        "{out}"
    );
    let o = sigil(d, &["mend", "-o", "x.sg1", "photo.sg1"]);
    assert!(!o.status.success(), "{}", text(&o));
    assert!(!d.join("x.sg1").exists());
}

#[test]
fn scan_refuses_several_copies_and_max_secs_on_copies() {
    let t = common::scratch("mend-scan");
    let d = t.path();
    let b = seal(d, 100_000);
    std::fs::write(d.join("b.sg1"), &b).expect("write");
    let o = sigil(d, &["mend", "--scan", "photo.sg1", "b.sg1"]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    let o = sigil(d, &["mend", "--max-secs", "5", "photo.sg1", "b.sg1"]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(text(&o).contains("--max-secs"), "{}", text(&o));
}
