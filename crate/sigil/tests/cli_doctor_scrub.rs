//! CLI: `sigil doctor --scrub DIR` repairs bit-flipped marks in place (only when
//! Merkle + true name pass), leaves clean and uncorrectable marks byte-identical.
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

#[test]
fn scrub_repairs_flips_and_leaves_uncorrectable_identical() {
    let dir = common::scratch("cli-scrub");
    std::fs::create_dir_all(dir.join("vault/sub")).unwrap();
    let mut x = 0x9e37_79b9_7f4a_7c15u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut originals = Vec::new();
    for i in 0..10 {
        let data: Vec<u8> = (0..60_000).map(|_| next() as u8).collect();
        let src = format!("in{i}.bin");
        std::fs::write(dir.join(&src), &data).unwrap();
        let mark = format!("vault/sub/m{i}.sg1");
        assert!(sigil(&dir, &["seal", "-o", &mark, &src]).status.success());
        let mut m = std::fs::read(dir.join(&mark)).unwrap();
        for _ in 0..60 {
            let bit = (next() % (m.len() as u64 * 8)) as usize;
            m[bit / 8] ^= 1 << (bit % 8);
        }
        std::fs::write(dir.join(&mark), &m).unwrap();
        originals.push((mark, data));
    }
    // Unscrubbed: none open.
    for (i, (mark, _)) in originals.iter().enumerate() {
        assert!(
            !sigil(&dir, &["unseal", "-o", &format!("pre{i}.bin"), mark])
                .status
                .success()
        );
    }
    // A clean mark and a flooded one.
    std::fs::write(dir.join("c.bin"), b"clean clean clean").unwrap();
    assert!(sigil(&dir, &["seal", "-o", "vault/clean.sg1", "c.bin"])
        .status
        .success());
    let clean = std::fs::read(dir.join("vault/clean.sg1")).unwrap();
    let mut flood = std::fs::read(dir.join("vault/sub/m0.sg1")).unwrap();
    let half = flood.len() / 2;
    for b in &mut flood[64..64 + half] {
        *b = 0x5a;
    }
    std::fs::write(dir.join("vault/flood.sg1"), &flood).unwrap();

    let out = sigil(&dir, &["doctor", "--scrub", "vault"]);
    let text = String::from_utf8_lossy(&out.stdout).to_string();
    assert_eq!(out.status.code(), Some(2), "{text}");
    assert!(text.contains("UNCORRECTABLE"), "{text}");
    assert_eq!(std::fs::read(dir.join("vault/flood.sg1")).unwrap(), flood);
    assert_eq!(std::fs::read(dir.join("vault/clean.sg1")).unwrap(), clean);
    let mut opened = 0;
    for (i, (mark, data)) in originals.iter().enumerate() {
        let o = format!("post{i}.bin");
        if sigil(&dir, &["unseal", "-o", &o, mark]).status.success() {
            assert_eq!(&std::fs::read(dir.join(&o)).unwrap(), data);
            opened += 1;
        }
    }
    assert!(opened >= 9, "scrubbed {opened}/10");
    // No leftover temp files.
    let leftovers = std::fs::read_dir(dir.join("vault/sub"))
        .unwrap()
        .flatten()
        .filter(|e| e.file_name().to_string_lossy().ends_with(".scrub-part"))
        .count();
    assert_eq!(leftovers, 0);
    // Second run: nothing left to repair except the flood.
    std::fs::remove_file(dir.join("vault/flood.sg1")).unwrap();
    let again = sigil(&dir, &["doctor", "--scrub", "vault"]);
    assert_eq!(again.status.code(), Some(0));
    assert!(String::from_utf8_lossy(&again.stdout).contains("0 repaired"));
    let _ = std::fs::remove_dir_all(&dir);
}
