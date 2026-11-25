//! CLI: a large-file pack whose head is damaged is rebuilt from the facet list
//! and the stars' own headers (old packs included), and refused when it cannot be.
mod common;
use std::path::Path;
use std::process::Command;

fn sigil(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(common::pass_via_file(args))
        .output()
        .expect("run sigil")
}

fn text(o: &std::process::Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn plain() -> Vec<u8> {
    let mut x = 0x2545f4914f6cdd1du64;
    (0..200_000)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn setup(tag: &str) -> (common::Scratch, Vec<u8>) {
    let dir = common::scratch(&format!("cli-ph-{tag}"));
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pack-v0");
    let pack = std::fs::read(fx.join("pack-v2-reflection.sg1")).unwrap();
    (dir, pack)
}

#[test]
fn old_pack_with_wiped_magic_unseals_and_mends_back_byte_exact() {
    let (dir, pack) = setup("magic");
    let mut bad = pack.clone();
    bad[..4].fill(0);
    std::fs::write(dir.join("torn.sg1"), &bad).unwrap();

    let o = sigil(&dir, &["unseal", "torn.sg1", "-o", "out.bin"]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(std::fs::read(dir.join("out.bin")).unwrap(), plain());

    let o = sigil(&dir, &["mend", "torn.sg1", "-o", "fixed.sg1"]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("pack head rebuilt"), "{}", text(&o));
    assert_eq!(std::fs::read(dir.join("fixed.sg1")).unwrap(), pack);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn old_pack_with_wrong_total_in_head_mends_in_place() {
    let (dir, pack) = setup("total");
    let mut bad = pack.clone();
    bad[9] ^= 0x10; // low byte of the stored total size
    std::fs::write(dir.join("p.sg1"), &bad).unwrap();
    let o = sigil(&dir, &["mend", "p.sg1", "-o", "p.sg1"]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(std::fs::read(dir.join("p.sg1")).unwrap(), pack);
    assert!(!dir.join("p.sg1.mend-part").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn unrebuildable_head_still_fails_closed() {
    let (dir, pack) = setup("refuse");
    let mut bad = pack.clone();
    bad[..60].fill(0); // head and star 0's length framing gone
    std::fs::write(dir.join("torn.sg1"), &bad).unwrap();
    let o = sigil(&dir, &["unseal", "torn.sg1", "-o", "out.bin"]);
    assert!(!o.status.success());
    assert!(text(&o).contains("more than one seal"), "{}", text(&o));
    assert!(!dir.join("out.bin").exists());
    assert!(!dir.join("out.bin.sigil-part").exists());
    let o = sigil(&dir, &["mend", "torn.sg1", "-o", "m.sg1"]);
    assert!(!o.status.success());
    assert!(!dir.join("m.sg1").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn new_pack_with_head_and_facet_list_wiped_comes_back_byte_exact() {
    let (dir, _) = setup("guard");
    std::fs::write(dir.join("plain.bin"), plain()).unwrap();
    let o = sigil(
        &dir,
        &["seal", "--chunk", "65536", "-o", "new.sg1", "plain.bin"],
    );
    assert!(o.status.success(), "{}", text(&o));
    let pack = std::fs::read(dir.join("new.sg1")).unwrap();
    let mut bad = pack.clone();
    let n = bad.len();
    bad[..35].fill(0); // the whole head ("plain.bin": 26 + 9 bytes)
    bad[n - 32 * 4 - 8..].fill(0xaa); // facet list gone
    std::fs::write(dir.join("torn.sg1"), &bad).unwrap();

    let o = sigil(&dir, &["unseal", "torn.sg1", "-o", "out.bin"]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(std::fs::read(dir.join("out.bin")).unwrap(), plain());

    let o = sigil(&dir, &["mend", "torn.sg1", "-o", "fixed.sg1"]);
    assert!(o.status.success(), "{}", text(&o));
    let t = text(&o);
    assert!(
        t.contains("restored from a guard copy") && t.contains("facet list rebuilt"),
        "{t}"
    );
    assert_eq!(std::fs::read(dir.join("fixed.sg1")).unwrap(), pack);
    let _ = std::fs::remove_dir_all(&dir);
}

fn star_length_offsets(pack: &[u8]) -> Vec<usize> {
    // Walk from a live `sigil` layout by reading the on-disk prefixes after a
    // successful unseal of a clean pack is not needed: reuse the same tiling
    // the CLI just wrote (head then u64 lengths). We locate them via a tiny
    // helper binary-side test in packhead; here, parse with a conservative walk
    // of u64 prefixes after the head by asking `sigil scry`? Simpler: find
    // the four length prefixes by scanning for the known star count after
    // writing a 64 KiB-chunk pack (4 stars of a 200_000-byte payload).
    // The first length sits immediately after the head (variable length).
    // Use the work-pack magic and declared star count from the head.
    assert!(pack.starts_with(b"SGWK"), "not a work pack");
    let nlen = pack[17] as usize; // version-2 head: name length at this offset for a v2 pack
                                  // v2: magic 4, ver 1, chunk 4, total 8, nlen 1, name nlen, stars 4, overture 4
                                  // That's what inscribe writes for current packs. Offsets: 0-3 magic, 4 ver,
                                  // 5-8 chunk, 9-16 total, 17 nlen, 18..18+nlen name, then stars, overture.
    let head_end = 18 + nlen + 4 + 4;
    let mut off = head_end;
    let mut offs = Vec::new();
    let nstars = u32::from_le_bytes(pack[18 + nlen..18 + nlen + 4].try_into().unwrap());
    for _ in 0..nstars {
        offs.push(off);
        let len = u64::from_le_bytes(pack[off..off + 8].try_into().unwrap());
        off = off + 8 + len as usize;
    }
    offs
}

#[test]
fn new_pack_with_wiped_length_prefix_mends_and_prints_framing_rebuilt() {
    let dir = common::scratch("cli-ph-framing");
    std::fs::write(dir.join("plain.bin"), plain()).unwrap();
    let o = sigil(
        &dir,
        &["seal", "--chunk", "65536", "-o", "new.sg1", "plain.bin"],
    );
    assert!(o.status.success(), "{}", text(&o));
    let pack = std::fs::read(dir.join("new.sg1")).unwrap();
    let offs = star_length_offsets(&pack);
    assert!(offs.len() >= 2);
    let mut bad = pack.clone();
    let at = offs[1];
    bad[at..at + 8].fill(0);
    std::fs::write(dir.join("torn.sg1"), &bad).unwrap();

    let o = sigil(&dir, &["mend", "torn.sg1", "-o", "fixed.sg1"]);
    assert!(o.status.success(), "{}", text(&o));
    let t = text(&o);
    assert!(t.contains("length framing rebuilt"), "{t}");
    assert_eq!(std::fs::read(dir.join("fixed.sg1")).unwrap(), pack);

    let o = sigil(&dir, &["unseal", "fixed.sg1", "-o", "out.bin"]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(std::fs::read(dir.join("out.bin")).unwrap(), plain());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn truncated_pack_with_wiped_length_is_refused_and_names_the_part() {
    let dir = common::scratch("cli-ph-trunc");
    std::fs::write(dir.join("plain.bin"), plain()).unwrap();
    let o = sigil(
        &dir,
        &["seal", "--chunk", "65536", "-o", "new.sg1", "plain.bin"],
    );
    assert!(o.status.success(), "{}", text(&o));
    let pack = std::fs::read(dir.join("new.sg1")).unwrap();
    let offs = star_length_offsets(&pack);
    let mut bad = pack[..offs[2] + 8 + 200].to_vec();
    bad[offs[1]..offs[1] + 8].fill(0);
    std::fs::write(dir.join("torn.sg1"), &bad).unwrap();
    let o = sigil(&dir, &["mend", "torn.sg1", "-o", "m.sg1"]);
    assert!(!o.status.success(), "{}", text(&o));
    let t = text(&o);
    assert!(t.contains("framing") || t.contains("truncated"), "{t}");
    assert!(!dir.join("m.sg1").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn wrong_passphrase_on_encrypted_large_pack_stays_fail_closed_after_framing_mend() {
    let dir = common::scratch("cli-ph-wrongkey");
    std::fs::write(dir.join("plain.bin"), plain()).unwrap();
    let o = sigil(
        &dir,
        &[
            "seal",
            "--chunk",
            "65536",
            "--pass",
            "right-pass",
            "-o",
            "new.sg1",
            "plain.bin",
        ],
    );
    assert!(o.status.success(), "{}", text(&o));
    let pack = std::fs::read(dir.join("new.sg1")).unwrap();
    let offs = star_length_offsets(&pack);
    let mut bad = pack.clone();
    bad[offs[1]..offs[1] + 8].fill(0);
    std::fs::write(dir.join("torn.sg1"), &bad).unwrap();
    let o = sigil(&dir, &["mend", "torn.sg1", "-o", "fixed.sg1"]);
    assert!(o.status.success(), "{}", text(&o));
    assert!(text(&o).contains("length framing rebuilt"), "{}", text(&o));
    let o = sigil(
        &dir,
        &[
            "unseal",
            "fixed.sg1",
            "--pass",
            "wrong-pass",
            "-o",
            "out.bin",
        ],
    );
    assert!(!o.status.success(), "{}", text(&o));
    assert!(!dir.join("out.bin").exists());
    let o = sigil(
        &dir,
        &[
            "unseal",
            "fixed.sg1",
            "--pass",
            "right-pass",
            "-o",
            "out.bin",
        ],
    );
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(std::fs::read(dir.join("out.bin")).unwrap(), plain());
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn crafted_guard_flood_mend_and_unseal_fail_closed_with_hints() {
    let dir = common::scratch("cli-ph-guard-cap");
    std::fs::write(dir.join("plain.bin"), plain()).unwrap();
    let o = sigil(
        &dir,
        &["seal", "--chunk", "65536", "-o", "new.sg1", "plain.bin"],
    );
    assert!(o.status.success(), "{}", text(&o));
    let pack = std::fs::read(dir.join("new.sg1")).unwrap();
    let sgfc_at = pack.windows(4).rposition(|w| w == b"SGFC").expect("SGFC");
    // Wipe head & framing, fill 1 MiB with repeating `SGHG`, append trailer.
    let mut bad = vec![0u8; 64];
    for _ in 0..(1024 * 1024 / 4) {
        bad.extend_from_slice(b"SGHG");
    }
    bad.extend_from_slice(&pack[sgfc_at..]);
    std::fs::write(dir.join("hostile.sg1"), &bad).unwrap();

    let om = sigil(&dir, &["mend", "hostile.sg1", "-o", "m.sg1"]);
    assert_eq!(om.status.code(), Some(2), "{}", text(&om));
    let tm = text(&om);
    assert!(tm.contains("guard scan limit"), "{tm}");
    assert!(tm.contains("What you can try:"), "{tm}");
    assert!(!dir.join("m.sg1").exists());

    let ou = sigil(&dir, &["unseal", "hostile.sg1", "-o", "out.bin"]);
    assert_eq!(ou.status.code(), Some(2), "{}", text(&ou));
    let tu = text(&ou);
    assert!(tu.contains("guard scan limit"), "{tu}");
    assert!(tu.contains("What you can try:"), "{tu}");
    assert!(!dir.join("out.bin").exists());
    let _ = std::fs::remove_dir_all(&dir);
}
