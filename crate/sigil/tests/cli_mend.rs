//! CLI: `sigil mend` heals a whole large-file work pack in one command.
use std::process::Command;

fn sigil(dir: &std::path::Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(args)
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
    let dir = std::env::temp_dir().join(format!("sigil-cli-mend-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
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
