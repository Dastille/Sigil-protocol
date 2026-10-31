//! CLI: `sigil mend` heals a whole large-file work pack in one command.
mod common;
use std::process::Command;

fn sigil(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(common::pass_via_file(args))
        .output()
        .expect("run sigil")
}

/// Offsets of chunk stars in an SGWK pack (head: magic ver chunk orig nlen name stars [overture]).
fn spans(p: &[u8]) -> Vec<(usize, usize)> {
    let nlen = p[17] as usize;
    let mut off = 18 + nlen;
    let stars = u32::from_le_bytes(p[off..off + 4].try_into().unwrap());
    off += 4;
    if p[4] == 2 {
        off += 4;
    }
    (0..stars)
        .map(|_| {
            let len = u64::from_le_bytes(p[off..off + 8].try_into().unwrap()) as usize;
            off += 8;
            let s = (off, off + len);
            off += len;
            s
        })
        .collect()
}

#[test]
fn mend_work_pack_cli() {
    let dir = common::scratch("cli-mend");
    let mut x = 0x2545f4914f6cdd1du64;
    let data: Vec<u8> = (0..400_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 32) as u8
        })
        .collect();
    std::fs::write(dir.join("big.bin"), &data).unwrap();
    let o = sigil(
        &dir,
        &["inscribe", "--chunk", "131072", "-o", "big.sg1", "big.bin"],
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let mut pack = std::fs::read(dir.join("big.sg1")).unwrap();
    assert_eq!(&pack[0..4], b"SGWK");
    let sp = spans(&pack);
    // Wipe a 256-byte run in the middle of the body of every other chunk star.
    for (i, (a, b)) in sp.iter().enumerate() {
        if i % 2 == 0 {
            let mid = a + (b - a) / 2;
            pack[mid..mid + 256].fill(0);
        }
    }
    std::fs::write(dir.join("big.sg1"), &pack).unwrap();
    let o = sigil(&dir, &["mend", "big.sg1", "-o", "fixed.sg1"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(out.contains("healed") && out.contains("facets ok"), "{out}");
    let o = sigil(&dir, &["de-scribe", "-o", "back.bin", "fixed.sg1"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(std::fs::read(dir.join("back.bin")).unwrap(), data);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Scattered bit flips in every shard: plain unseal and plain mend refuse,
/// `mend --soft` repairs them column by column and the unseal is exact.
#[test]
fn mend_soft_cli_repairs_scattered_bit_flips() {
    let dir = common::scratch("cli-mend-flips");
    let mut x = 0x9e3779b97f4a7c15u64;
    let mut next = move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let data: Vec<u8> = (0..300_000).map(|_| next() as u8).collect();
    std::fs::write(dir.join("in.bin"), &data).unwrap();
    assert!(sigil(&dir, &["seal", "-o", "a.sg1", "in.bin"])
        .status
        .success());
    let mut mark = std::fs::read(dir.join("a.sg1")).unwrap();
    for _ in 0..200 {
        let bit = (next() % (mark.len() as u64 * 8)) as usize;
        mark[bit / 8] ^= 1 << (bit % 8);
    }
    std::fs::write(dir.join("t.sg1"), &mark).unwrap();
    assert!(!sigil(&dir, &["unseal", "-o", "o1.bin", "t.sg1"])
        .status
        .success());
    assert!(!dir.join("o1.bin").exists());
    assert!(!sigil(&dir, &["mend", "-o", "m0.sg1", "t.sg1"])
        .status
        .success());
    let out = sigil(&dir, &["mend", "--soft", "-o", "m.sg1", "t.sg1"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(sigil(&dir, &["unseal", "-o", "o.bin", "m.sg1"])
        .status
        .success());
    assert_eq!(std::fs::read(dir.join("o.bin")).unwrap(), data);
    let _ = std::fs::remove_dir_all(&dir);
}
