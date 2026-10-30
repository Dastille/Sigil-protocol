//! CLI: opt-in `sigil unseal --repair` opens a bit-flipped mark exactly when
//! `mend --soft` + `unseal` would, writes no mended file, and fails closed otherwise.
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

fn rng(seed: u64) -> impl FnMut() -> u64 {
    let mut x = seed;
    move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    }
}

fn setup(tag: &str, extra: &[&str]) -> (common::Scratch, Vec<u8>, Vec<u8>) {
    let dir = common::scratch(&format!("unseal-repair-{tag}"));
    let mut next = rng(0x9e37_79b9_7f4a_7c15);
    let data: Vec<u8> = (0..200_000).map(|_| next() as u8).collect();
    std::fs::write(dir.join("in.bin"), &data).unwrap();
    let mut args = vec!["seal", "-o", "a.sg1"];
    args.extend_from_slice(extra);
    args.push("in.bin");
    let out = sigil(&dir, &args);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    let mark = std::fs::read(dir.join("a.sg1")).unwrap();
    (dir, data, mark)
}

/// For each bit-flip count: `unseal --repair` succeeds iff `mend --soft` + `unseal`
/// does, output matches the original, and a refusal leaves no output (or part) file.
#[test]
fn repair_matches_mend_soft_for_each_flip_count() {
    let (dir, data, mark) = setup("flips", &[]);
    let mut agree_ok = 0;
    let mut agree_refused = 0;
    for (i, &flips) in [0usize, 16, 64, 200, 1000, 4000, 60_000].iter().enumerate() {
        let mut next = rng(0xdead_beef ^ (i as u64 + 1));
        let mut m = mark.clone();
        for _ in 0..flips {
            let bit = (next() % (m.len() as u64 * 8)) as usize;
            m[bit / 8] ^= 1 << (bit % 8);
        }
        let t = format!("t{i}.sg1");
        std::fs::write(dir.join(&t), &m).unwrap();
        let mended = format!("m{i}.sg1");
        let via_mend = sigil(&dir, &["mend", "--soft", "-o", &mended, &t])
            .status
            .success()
            && sigil(&dir, &["unseal", "-o", &format!("v{i}.bin"), &mended])
                .status
                .success();
        let o = format!("r{i}.bin");
        let via_repair = sigil(&dir, &["unseal", "--repair", "-o", &o, &t])
            .status
            .success();
        assert_eq!(via_mend, via_repair, "flips={flips}");
        if via_repair {
            assert_eq!(std::fs::read(dir.join(&o)).unwrap(), data, "flips={flips}");
            agree_ok += 1;
        } else {
            assert!(!dir.join(&o).exists(), "flips={flips}: output on refusal");
            assert!(!dir.join(format!("{o}.unseal-part")).exists());
            agree_refused += 1;
        }
        // --repair never touches the damaged mark on disk.
        assert_eq!(std::fs::read(dir.join(&t)).unwrap(), m);
    }
    assert!(agree_ok >= 3, "expected the light-damage rows to open");
    assert!(agree_refused >= 1, "expected the flood row to refuse");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Default stays strict: without --repair a flipped mark is refused.
#[test]
fn repair_is_opt_in() {
    let (dir, _data, mut mark) = setup("optin", &[]);
    let mut next = rng(7);
    for _ in 0..200 {
        let bit = (next() % (mark.len() as u64 * 8)) as usize;
        mark[bit / 8] ^= 1 << (bit % 8);
    }
    std::fs::write(dir.join("t.sg1"), &mark).unwrap();
    assert!(!sigil(&dir, &["unseal", "-o", "o.bin", "t.sg1"])
        .status
        .success());
    assert!(!dir.join("o.bin").exists());
    let out = sigil(&dir, &["unseal", "--repair", "-o", "o.bin", "t.sg1"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(String::from_utf8_lossy(&out.stderr).contains("warning"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// A passphrase mark with flips: wrong pass is refused (no file), right pass opens.
#[test]
fn repair_wrong_pass_fails_closed() {
    let (dir, data, mut mark) = setup("pass", &["--pass", "correct horse battery staple 42"]);
    let mut next = rng(11);
    for _ in 0..100 {
        let bit = (next() % (mark.len() as u64 * 8)) as usize;
        mark[bit / 8] ^= 1 << (bit % 8);
    }
    std::fs::write(dir.join("t.sg1"), &mark).unwrap();
    let bad = sigil(
        &dir,
        &[
            "unseal",
            "--repair",
            "--pass",
            "wrong horse battery staple 42",
            "-o",
            "w.bin",
            "t.sg1",
        ],
    );
    assert!(!bad.status.success());
    assert!(!dir.join("w.bin").exists());
    let good = sigil(
        &dir,
        &[
            "unseal",
            "--repair",
            "--pass",
            "correct horse battery staple 42",
            "-o",
            "g.bin",
            "t.sg1",
        ],
    );
    assert!(
        good.status.success(),
        "{}",
        String::from_utf8_lossy(&good.stderr)
    );
    assert_eq!(std::fs::read(dir.join("g.bin")).unwrap(), data);
    let _ = std::fs::remove_dir_all(&dir);
}

/// A flooded body (half the mark overwritten) stays refused with no output.
#[test]
fn repair_flooded_fails_closed() {
    let (dir, _data, mut mark) = setup("flood", &[]);
    let half = mark.len() / 2;
    for b in &mut mark[64..64 + half] {
        *b = 0xA5;
    }
    std::fs::write(dir.join("t.sg1"), &mark).unwrap();
    assert!(
        !sigil(&dir, &["unseal", "--repair", "-o", "o.bin", "t.sg1"])
            .status
            .success()
    );
    assert!(!dir.join("o.bin").exists());
    let _ = std::fs::remove_dir_all(&dir);
}
