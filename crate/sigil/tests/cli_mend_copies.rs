//! CLI: `sigil mend A.sg1 B.sg1 -o fixed.sg1` pools good shards from several damaged
//! copies of one Sigil, and refuses (writing nothing) when it cannot do so safely.
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

fn data(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 32) as u8
        })
        .collect()
}

/// Zero whole shard strides `range` (ember header + body + CRC) in a plain seal.
fn smash(bytes: &mut [u8], range: std::ops::Range<usize>) {
    let (h, prefix, _) = sigil::locate_header(bytes).unwrap();
    let lead = if h.ember() { sigil::HEADER_SIZE } else { 0 } + if h.vow() { 128 } else { 0 };
    let stride = lead + h.shard_len as usize + 4;
    for i in range {
        let off = prefix + i * stride;
        bytes[off..off + stride].fill(0);
    }
}

#[test]
fn mend_pools_two_copies_and_round_trips() {
    let dir = common::scratch("cli-mend-copies");
    let plain = data(120_000, 0x9e3779b97f4a7c15);
    std::fs::write(dir.join("in.bin"), &plain).unwrap();
    assert!(sigil(&dir, &["seal", "-o", "a.sg1", "in.bin"])
        .status
        .success());
    let good = std::fs::read(dir.join("a.sg1")).unwrap();
    let h = sigil::read_header(&good).unwrap();
    let (n, k) = (h.n as usize, h.k as usize);
    // Each copy loses one shard more than its repair budget (n - k), at opposite ends.
    let lost = n - k + 1;
    let mut a = good.clone();
    smash(&mut a, 0..lost);
    let mut b = good.clone();
    smash(&mut b, n - lost..n);
    std::fs::write(dir.join("copy1.sg1"), &a).unwrap();
    std::fs::write(dir.join("copy2.sg1"), &b).unwrap();

    // Each copy alone is past its repair budget.
    for c in ["copy1.sg1", "copy2.sg1"] {
        let o = sigil(&dir, &["mend", "-o", "solo.sg1", c]);
        assert!(!o.status.success());
        assert!(!dir.join("solo.sg1").exists());
    }

    let o = sigil(
        &dir,
        &[
            "mend",
            "--json",
            "copy1.sg1",
            "copy2.sg1",
            "-o",
            "fixed.sg1",
        ],
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let js = String::from_utf8_lossy(&o.stdout);
    assert!(js.contains("\"copies\":2"), "{js}");
    assert!(
        js.contains(&format!("\"live_per_copy\":[{},{}]", k - 1, k - 1)),
        "{js}"
    );
    assert!(js.contains("\"merkle\":true"), "{js}");
    assert_eq!(std::fs::read(dir.join("fixed.sg1")).unwrap(), good);
    assert!(sigil(&dir, &["unseal", "-o", "back.bin", "fixed.sg1"])
        .status
        .success());
    assert_eq!(std::fs::read(dir.join("back.bin")).unwrap(), plain);

    // Human output names each copy and the pooled count.
    let o = sigil(
        &dir,
        &["mend", "copy2.sg1", "copy1.sg1", "-o", "fixed2.sg1"],
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(
        out.contains("mended 2 copies") && out.contains("pooled"),
        "{out}"
    );
    assert_eq!(std::fs::read(dir.join("fixed2.sg1")).unwrap(), good);
}

#[test]
fn mend_copies_refuses_unsafe_mixes_and_writes_nothing() {
    let dir = common::scratch("cli-mend-copies-refuse");
    std::fs::write(dir.join("x.bin"), data(60_000, 1)).unwrap();
    std::fs::write(dir.join("y.bin"), data(60_000, 2)).unwrap();
    assert!(sigil(&dir, &["seal", "-o", "x.sg1", "x.bin"])
        .status
        .success());
    assert!(sigil(&dir, &["seal", "-o", "y.sg1", "y.bin"])
        .status
        .success());

    // Different Sigils.
    let o = sigil(&dir, &["mend", "x.sg1", "y.sg1", "-o", "out.sg1"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("not a copy of the same Sigil"));
    assert!(!dir.join("out.sg1").exists());

    // --soft is one copy at a time.
    let o = sigil(&dir, &["mend", "--soft", "x.sg1", "x.sg1", "-o", "out.sg1"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("--soft"));
    assert!(!dir.join("out.sg1").exists());

    // Same damage in both copies: not enough shards, nothing written.
    let good = std::fs::read(dir.join("x.sg1")).unwrap();
    let h = sigil::read_header(&good).unwrap();
    let mut t = good.clone();
    smash(&mut t, 0..(h.n - h.k) as usize + 1);
    std::fs::write(dir.join("t1.sg1"), &t).unwrap();
    std::fs::write(dir.join("t2.sg1"), &t).unwrap();
    let o = sigil(&dir, &["mend", "t1.sg1", "t2.sg1", "-o", "out.sg1"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("NOT recoverable"));
    assert!(!dir.join("out.sg1").exists());
    assert!(!dir.join("out.sg1.mend-part").exists());
}

#[test]
fn mend_copies_refuses_folder_packs() {
    let dir = common::scratch("cli-mend-copies-folder");
    std::fs::create_dir(dir.join("f")).unwrap();
    std::fs::write(dir.join("f/a.txt"), data(5_000, 3)).unwrap();
    assert!(sigil(&dir, &["seal", "f", "-o", "f.sg1"]).status.success());
    let o = sigil(&dir, &["mend", "f.sg1", "f.sg1", "-o", "out.sg1"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("one copy at a time"));
    assert!(!dir.join("out.sg1").exists());
}
