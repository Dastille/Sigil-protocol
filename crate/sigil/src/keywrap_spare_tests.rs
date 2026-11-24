//! SGTO v3: the key wrap of a new encrypted Sigil is stored twice (front + `SGTS` tail spare).
//! Either copy alone opens the seal and lets `mend` rebuild the exact original; both gone,
//! a wrong key, a forged spare or a cut file fail closed. Older files open and mend unchanged.

use crate::mend_soft_tests::damage;
use crate::*;

const PASS: &str = "correct horse battery";

fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn seal_to(msg: &[u8], mode: Mode, pass: Option<&str>, to: &[keys::PublicIdentity]) -> Vec<u8> {
    seal_kn_to(
        msg,
        mode,
        pass,
        "k.bin",
        false,
        "",
        &[],
        None,
        DEFAULT_PIECE,
        to,
    )
    .unwrap()
}

fn open(f: &[u8], pass: Option<&str>, ids: &[keys::Identity]) -> Result<Vec<u8>> {
    unseal_ex_mds_keys(f, pass, &[], &*mds::default_backend(), ids)
}

/// (front SGTO range, SGTS spare range) of a healthy new seal.
fn spans(f: &[u8]) -> (std::ops::Range<usize>, std::ops::Range<usize>) {
    let (h, prefix, _) = locate_header(f).unwrap();
    let off = header::maps_len(&h);
    let len = keys::sgto_len_at(f, off);
    assert!(len > 0, "front SGTO");
    let body_end = prefix + h.n as usize * header::shard_stride(&h);
    let spare = header::sgto_spare_len_at(f, body_end);
    assert_eq!(
        spare,
        header::SGTO_SPARE_HEAD + len,
        "spare right after the shards"
    );
    (off..off + len, body_end..body_end + spare)
}

#[test]
fn new_seals_write_sgto_v3_twice_and_round_trip() {
    let id = keys::Identity::generate().unwrap();
    let msg = noise(30_000, 1);
    for mode in [Mode::Reflection, Mode::Seal, Mode::Glyph] {
        for (pass, to) in [
            (Some(PASS), vec![]),
            (None, vec![id.public()]),
            (Some(PASS), vec![id.public()]),
        ] {
            let f = seal_to(&msg, mode, pass, &to);
            let (front, spare) = spans(&f);
            assert_eq!(f[front.start + 4], keys::SGTO_VERSION_SPARED);
            assert_eq!(&f[spare.start..spare.start + 4], b"SGTS");
            assert_eq!(
                &f[spare.start + header::SGTO_SPARE_HEAD..spare.end],
                &f[front.clone()]
            );
            // The Keystone trailer stays last, right after the spare.
            assert_eq!(spare.end + KEYSTONE_TRAILER_SIZE, f.len());
            let ids = std::slice::from_ref(&id);
            assert_eq!(
                open(&f, pass, if to.is_empty() { &[] } else { ids }).unwrap(),
                msg
            );
            // Healthy: mend writes the same bytes, doctor calls it OK.
            assert_eq!(pieces::mend_bytes_ex(&f, true).unwrap().0, f, "{mode:?}");
            assert!(
                matches!(doctor::health_bytes(&f), doctor::Health::Ok),
                "{mode:?}"
            );
        }
    }
}

/// The repair cost of the fix: one copy of the wrap plus an 8-byte `SGTS` head.
#[test]
fn spare_costs_wrap_length_plus_eight_bytes() {
    let id = keys::Identity::generate().unwrap();
    let f = seal_to(&noise(5000, 2), Mode::Reflection, Some(PASS), &[]);
    let (front, spare) = spans(&f);
    assert_eq!(front.len(), 101, "passphrase-only wrap");
    assert_eq!(spare.len(), 109);
    let f = seal_to(&noise(5000, 2), Mode::Reflection, None, &[id.public()]);
    let (front, spare) = spans(&f);
    assert_eq!((front.len(), spare.len()), (113, 121), "one recipient");
}

#[test]
fn either_copy_alone_opens_and_mend_restores_the_exact_original() {
    let id = keys::Identity::generate().unwrap();
    let ids = std::slice::from_ref(&id);
    let msg = noise(60_000, 3);
    for (pass, to, keys_) in [
        (Some(PASS), vec![], &[][..]),
        (None, vec![id.public()], ids),
    ] {
        let f = seal_to(&msg, Mode::Reflection, pass, &to);
        let (front, spare) = spans(&f);
        let mut a = f.clone(); // copy A (front) hit: one flipped bit
        a[front.start + 40] ^= 1;
        let mut a2 = f.clone(); // copy A wiped whole
        a2[front.clone()].fill(0);
        let mut b = f.clone(); // copy B (spare) hit
        b[spare.start + 30] ^= 0x80;
        let mut b2 = f.clone();
        b2[spare.clone()].fill(0);
        for (what, t) in [
            ("A flip", a),
            ("A wiped", a2),
            ("B flip", b),
            ("B wiped", b2),
        ] {
            assert_eq!(open(&t, pass, keys_).unwrap(), msg, "{what}");
            let (m, _) = pieces::mend_bytes_ex(&t, false).unwrap();
            assert_eq!(m, f, "{what}: quick mend is byte-identical");
            let (m, _) = pieces::mend_bytes_ex(&t, true).unwrap();
            assert_eq!(m, f, "{what}: default mend is byte-identical");
            assert!(
                !matches!(doctor::health_bytes(&t), doctor::Health::Ok),
                "{what}"
            );
        }
    }
}

/// Both copies hit, in different bytes: the two are merged byte by byte (each disagreement
/// tried both ways until the block CRC passes), so the seal still opens and mends exactly.
#[test]
fn both_copies_hit_in_different_bytes_are_merged() {
    let id = keys::Identity::generate().unwrap();
    let msg = noise(20_000, 4);
    for (pass, to) in [(Some(PASS), vec![]), (None, vec![id.public()])] {
        let ids: &[keys::Identity] = if to.is_empty() {
            &[]
        } else {
            std::slice::from_ref(&id)
        };
        let f = seal_to(&msg, Mode::Seal, pass, &to);
        let (front, spare) = spans(&f);
        let inner = spare.start + header::SGTO_SPARE_HEAD;
        let mut t = f.clone();
        // Front: count/kind area and a record byte; spare: its SGTS head and other bytes.
        for o in [5usize, 8, 40, 77] {
            t[front.start + o] ^= 0x21;
        }
        t[spare.start] ^= 0xff;
        for o in [9usize, 60, 99] {
            t[inner + o] ^= 0x08;
        }
        assert_eq!(open(&t, pass, ids).unwrap(), msg);
        let (m, _) = pieces::mend_bytes_ex(&t, true).unwrap();
        assert_eq!(m, f, "mend restores both copies");
        // The same merge when the Keystone trailer is gone as well.
        let cut = &t[..t.len() - KEYSTONE_TRAILER_SIZE];
        assert_eq!(open(cut, pass, ids).unwrap(), msg);
    }
}

/// Both copies hit in the same bytes, wiped, or too far apart to merge: refused, cleanly.
#[test]
fn both_copies_damaged_fails_closed() {
    let msg = noise(20_000, 4);
    let f = seal_to(&msg, Mode::Seal, Some(PASS), &[]);
    let (front, spare) = spans(&f);
    let inner = spare.start + header::SGTO_SPARE_HEAD;
    let mut same = f.clone();
    same[front.start + 20] ^= 4;
    same[inner + 20] ^= 4;
    let mut wiped = f.clone();
    wiped[front.clone()].fill(0);
    wiped[spare.clone()].fill(0);
    let mut many = f.clone();
    for o in 0..front.len() {
        if o % 2 == 0 {
            many[front.start + o] ^= 1;
        } else {
            many[inner + o] ^= 1;
        }
    }
    for (what, t) in [
        ("same bytes", same),
        ("both wiped", wiped),
        ("too many", many),
    ] {
        let e = open(&t, Some(PASS), &[]).unwrap_err().to_string();
        assert!(e.contains("no key wrap"), "{what}: {e}");
        let e = pieces::mend_bytes_ex(&t, true).unwrap_err().to_string();
        assert!(e.contains("key wrap (SGTO)"), "{what}: {e}");
    }
}

#[test]
fn wrong_key_fails_closed_with_either_copy() {
    let id = keys::Identity::generate().unwrap();
    let other = keys::Identity::generate().unwrap();
    let msg = noise(20_000, 5);
    let f = seal_to(&msg, Mode::Reflection, Some(PASS), &[id.public()]);
    let (front, _) = spans(&f);
    let mut a = f.clone();
    a[front].fill(0xAA);
    for t in [&f, &a] {
        assert!(open(t, Some("wrong horse"), &[]).is_err());
        assert!(open(t, None, std::slice::from_ref(&other)).is_err());
        assert!(open(t, None, &[]).is_err());
        assert_eq!(open(t, Some(PASS), &[]).unwrap(), msg);
    }
}

/// A spare that parses but wraps a different key (an attacker's, or another seal's) never
/// yields plaintext: the body's AES-GCM tag and the inner SHA-256 still decide.
#[test]
fn forged_spare_with_front_damaged_fails_closed() {
    let id = keys::Identity::generate().unwrap();
    let msg = noise(20_000, 6);
    let f = seal_to(&msg, Mode::Reflection, None, &[id.public()]);
    let (front, spare) = spans(&f);
    let (h, _, _) = locate_header(&f).unwrap();
    let forged =
        keys::mark_spared(&keys::build_sgto(&[7u8; 32], &[id.public()], None, &h.salt).unwrap())
            .unwrap();
    assert_eq!(forged.len(), front.len());
    let mut t = f.clone();
    t[front].fill(0);
    t[spare.start + header::SGTO_SPARE_HEAD..spare.end].copy_from_slice(&forged);
    assert!(open(&t, None, std::slice::from_ref(&id)).is_err());
    // Another seal's genuine wrap for the same recipient: also refused.
    let g = seal_to(&msg, Mode::Reflection, None, &[id.public()]);
    let (gf, _) = spans(&g);
    let mut t2 = f.clone();
    t2[spans(&f).0].fill(0);
    t2[spare.start + header::SGTO_SPARE_HEAD..spare.end].copy_from_slice(&g[gf]);
    assert!(open(&t2, None, std::slice::from_ref(&id)).is_err());
}

/// Every cut point: either the exact plaintext or an error, never other bytes.
#[test]
fn truncation_never_returns_wrong_plaintext() {
    let msg = noise(9_000, 7);
    let f = seal_to(&msg, Mode::Reflection, Some(PASS), &[]);
    let (front, spare) = spans(&f);
    for cut in (0..f.len())
        .step_by(97)
        .chain([spare.start, spare.end, f.len() - 1])
    {
        for base in [f.clone(), {
            let mut a = f.clone();
            a[front.clone()].fill(0);
            a
        }] {
            if let Ok(p) = open(&base[..cut], Some(PASS), &[]) {
                assert_eq!(p, msg, "cut at {cut}");
            }
            if let Ok((m, _)) = pieces::mend_bytes_ex(&base[..cut], true) {
                assert_eq!(open(&m, Some(PASS), &[]).unwrap(), msg, "cut at {cut}");
            }
        }
    }
    // Losing the spare and the trailer (cut right after the shards) still opens via the front.
    assert_eq!(open(&f[..spare.start], Some(PASS), &[]).unwrap(), msg);
}

/// The refusal case from the 17 November 2026 mend change: key wrap hit AND data damaged. Now mend rebuilds it exactly.
#[test]
fn mend_with_keywrap_and_data_damage_is_byte_identical() {
    let msg = noise(48_000, 8);
    let f = seal_to(&msg, Mode::Reflection, Some(PASS), &[]);
    let (front, _) = spans(&f);
    let mut t = damage(&f, &[2, 9], 1e-4, 3);
    t[front.start + 50] ^= 0x10;
    assert!(open(&t, Some(PASS), &[]).is_err(), "needs soft repair");
    let (m, soft) = pieces::mend_bytes_ex(&t, true).unwrap();
    assert!(soft);
    assert_eq!(m, f);
    assert_eq!(open(&m, Some(PASS), &[]).unwrap(), msg);
}

/// Files written before SGTO v3 (one key-wrap copy) open and mend exactly as before: no
/// spare is added to them. `keywrap-v0` was written by `main` as of 17 November 2026.
#[test]
fn old_single_copy_files_open_and_mend_unchanged() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let rd = |p: &str| std::fs::read(dir.join(p)).unwrap();
    let plain = rd("kdf-v2/plain.txt");
    let id = keys::Identity::load(&dir.join("enc-v2/id.sgk")).unwrap();
    for (name, pass, with_id) in [
        ("keywrap-v0/pass-reflection.sg1", Some(PASS), false),
        ("keywrap-v0/to-seal.sg1", None, true),
        ("kdf-v2/pass-reflection.sg1", Some(PASS), false),
        ("kdf-v2/pass-and-to.sg1", Some(PASS), false),
    ] {
        let f = rd(name);
        let ids = if with_id {
            std::slice::from_ref(&id)
        } else {
            &[]
        };
        assert_eq!(open(&f, pass, ids).unwrap(), plain, "{name}");
        let (h, prefix, _) = locate_header(&f).unwrap();
        let off = header::maps_len(&h);
        assert_ne!(f[off + 4], keys::SGTO_VERSION_SPARED, "{name}");
        assert!(!f.windows(4).any(|w| w == b"SGTS"), "{name}");
        // One wiped shard: mend rebuilds the same layout (single wrap, no spare).
        let healthy = pieces::mend_bytes_ex(&f, true).unwrap().0;
        let stride = header::shard_stride(&h);
        let mut t = f.clone();
        t[prefix + stride..prefix + 2 * stride].fill(0);
        let (m, _) = pieces::mend_bytes_ex(&t, true).unwrap();
        assert_eq!(m, healthy, "{name}");
        assert!(!m.windows(4).any(|w| w == b"SGTS"), "{name}");
        if name.starts_with("keywrap-v0") {
            assert_eq!(m, f, "{name}: byte-identical");
        }
        // The old weakness is still there for old files (re-seal to fix).
        let mut k = f.clone();
        k[off + 30] ^= 1;
        assert!(open(&k, pass, ids).is_err(), "{name}");
    }
}

/// Readers refuse an SGTO version they do not know; this build knows 1..=3.
#[test]
fn unknown_sgto_version_is_refused() {
    let f = seal_to(&noise(4000, 9), Mode::Reflection, Some(PASS), &[]);
    let (front, spare) = spans(&f);
    let mut t = f.clone();
    for at in [front.start, spare.start + header::SGTO_SPARE_HEAD] {
        t[at + 4] = 4;
        let end = if at == front.start {
            front.end
        } else {
            spare.end
        };
        let crc = crc32fast::hash(&t[at..end - 4]);
        t[end - 4..end].copy_from_slice(&crc.to_le_bytes());
    }
    assert!(open(&t, Some(PASS), &[]).is_err());
}

/// Large files are work packs of chunk-sized stars; every encrypted star gets its own spare,
/// and the pack opens.
#[test]
fn work_pack_stars_carry_spares() {
    let d = crate::staging::TempDir::create("kw-pack").unwrap();
    let big = d.path().join("big.bin");
    let msg = noise(300_000, 10);
    std::fs::write(&big, &msg).unwrap();
    let pack = d.path().join("big.sg1");
    let (_, stars, _) = work::inscribe_path(
        &big,
        &pack,
        Mode::Seal,
        Some(PASS),
        "",
        &[],
        65_536,
        None,
        DEFAULT_PIECE,
        0,
        None,
    )
    .unwrap();
    let p = std::fs::read(&pack).unwrap();
    let spares = p.windows(4).filter(|w| *w == b"SGTS").count();
    assert!(
        stars >= 4 && spares as u32 >= stars,
        "stars {stars} spares {spares}"
    );
    let out = d.path().join("big.out");
    work::unseal_path(&pack, &out, Some(PASS), &[]).unwrap();
    assert_eq!(std::fs::read(&out).unwrap(), msg);
}

/// The committed new-layout fixture (also read by the web lab) keeps opening, and mends back
/// to itself byte for byte after its front key wrap is wiped.
#[test]
fn keywrap_v1_fixture_opens_and_mends_after_front_wipe() {
    let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures");
    let f = std::fs::read(dir.join("keywrap-v1/pass-reflection.sg1")).unwrap();
    let plain = std::fs::read(dir.join("kdf-v2/plain.txt")).unwrap();
    let (front, _) = spans(&f);
    assert_eq!(open(&f, Some(PASS), &[]).unwrap(), plain);
    let mut t = f.clone();
    t[front].fill(0);
    assert_eq!(open(&t, Some(PASS), &[]).unwrap(), plain);
    assert_eq!(pieces::mend_bytes_ex(&t, true).unwrap().0, f);
}
