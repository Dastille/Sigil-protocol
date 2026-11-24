//! `mend --soft` speed and equivalence: the easy-first column repair against the
//! pre-ratchet search (kept as `pieces::mend_soft_legacy`, test only).

use crate::pieces::{mend_bytes_stats, mend_bytes_stats_threads, mend_soft_legacy, SoftMendStats};
use crate::*;

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

/// Deterministic damage on shard bodies only: wipe the whole stride (Ember, body, CRC) of
/// each shard in `lost`, then flip `ber × body bits` random bits in the other bodies.
pub(crate) fn damage(bytes: &[u8], lost: &[usize], ber: f64, seed: u64) -> Vec<u8> {
    damage_ex(bytes, lost, ber, seed, false)
}

/// [`damage`], optionally with every flip in a different byte column (so no column has
/// more than one flipped symbol besides the wiped shards).
pub(crate) fn damage_ex(
    bytes: &[u8],
    lost: &[usize],
    ber: f64,
    seed: u64,
    distinct_columns: bool,
) -> Vec<u8> {
    let h = read_header(bytes).unwrap();
    let prefix = header::body_prefix_file(&h, bytes);
    let stride = header::shard_stride(&h);
    let lead = if h.ember() { HEADER_SIZE } else { 0 } + if h.vow() { header::VOW_SIZE } else { 0 };
    let sl = h.shard_len as usize;
    let mut out = bytes.to_vec();
    for &i in lost {
        let off = (prefix + i * stride).min(out.len());
        let end = (off + stride).min(out.len());
        out[off..end].fill(0);
    }
    let mut x = seed | 1;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let flips = ((sl * 8 * h.n as usize) as f64 * ber) as usize;
    let mut done = 0;
    let mut used = std::collections::HashSet::new();
    while done < flips {
        let i = (next() % h.n as u64) as usize;
        if lost.contains(&i) {
            continue;
        }
        let bit = (next() % (sl as u64 * 8)) as usize;
        if distinct_columns && !used.insert(bit / 8) {
            continue;
        }
        if let Some(b) = out.get_mut(prefix + i * stride + lead + bit / 8) {
            *b ^= 1 << (bit % 8);
        }
        done += 1;
    }
    out
}

fn new_path(torn: &[u8]) -> (Result<Vec<u8>>, SoftMendStats) {
    let mut st = SoftMendStats::default();
    let r = mend_bytes_stats(torn, true, &mut st).map(|(b, _)| b);
    (r, st)
}

fn new_path_threads(torn: &[u8], threads: usize) -> (Result<Vec<u8>>, SoftMendStats) {
    let mut st = SoftMendStats::default();
    let r = mend_bytes_stats_threads(torn, true, &mut st, threads).map(|(b, _)| b);
    (r, st)
}

/// The R1 repro: 2 wiped shards + scattered flips on Reflection 12/16. Column repair alone
/// gets stuck (a wiped shard counts as an error in every column), so the old search walked
/// every (shard pair × 4 KiB stripe), each with a full re-encode + Merkle + true-name check.
#[test]
fn mend_soft_old_search_rehashes_per_candidate_new_checks_once() {
    let msg = noise(64 * 1024, 0xbe7c);
    let bytes = seal(&msg, Mode::Reflection, None, "r1.bin", false).unwrap();
    let h = read_header(&bytes).unwrap();
    assert_eq!((h.k, h.n), (12, 16));
    let torn = damage_ex(&bytes, &[0, 1], 1e-4, 7, true);
    let (old, old_gates) = mend_soft_legacy(&torn);
    let (new, st) = new_path(&torn);
    // Old: one full-file check per candidate — C(14,2) pairs × stripes, and more.
    assert!(old_gates > 150, "old gate calls {old_gates}");
    // New: one full-file check (plus at most 2(n−k)+1 fallback checks when it fails).
    assert_eq!(st.gate_calls, 1, "{st:?}");
    let rep = st.ratchet.clone().unwrap();
    assert!(
        rep.crc_columns + rep.erasure_columns + rep.bw_columns > 0,
        "{rep:?}"
    );
    assert_eq!(new.as_ref().unwrap(), &bytes, "{rep:?}");
    if let Ok(o) = old {
        assert_eq!(o, bytes);
    }
}

/// Same input, same bytes: wherever the old search finishes with a result, the new path
/// returns the identical mark; it never fails where the old one succeeded; and it never
/// spends more than 2(n−k)+2 full-file checks. Any success is the exact original.
#[test]
fn mend_soft_matches_old_path_on_damage_corpus() {
    let mut old_ok = 0;
    let mut new_ok = 0;
    let mut col_ok = 0;
    let mut cases = 0;
    for (mode, size) in [(Mode::Reflection, 20_000usize), (Mode::Seal, 24_000)] {
        let msg = noise(size, size as u64);
        crate::set_test_random_seed(Some(0xc0_1124 + size as u64));
        let bytes = seal(&msg, mode, None, "c.bin", false);
        crate::set_test_random_seed(None);
        let bytes = bytes.unwrap();
        let h = read_header(&bytes).unwrap();
        let cap = 2 * (h.n - h.k) as usize + 2;
        let damages: &[(&[usize], f64)] = &[
            (&[], 2e-4),
            (&[], 1e-3),
            (&[], 4e-3),
            (&[], 2e-2),
            (&[3], 1e-3),
            (&[0, 5], 5e-4),
            (&[0, 5], 2e-3),
            (&[1, 2, 3], 3e-4),
            (&[1, 2, 3, 4], 1e-4),
            (&[0, 1, 2, 3, 4, 5], 1e-4),
        ];
        for (d, &(lost, ber)) in damages.iter().enumerate() {
            for seed in 1..=3u64 {
                cases += 1;
                let torn = damage(&bytes, lost, ber, seed * 101 + d as u64);
                let (old, _) = mend_soft_legacy(&torn);
                let (new, st) = new_path(&torn);
                assert!(st.gate_calls <= cap, "{mode:?} {lost:?} {ber}: {st:?}");
                // The per-column ratchet without the (g) neighbour steps, as a baseline.
                let (col_only, _) = mend_with_joint(&torn, false, 8);
                if let Ok(b) = &col_only {
                    assert_eq!(b, &bytes);
                    col_ok += 1;
                    assert!(
                        new.is_ok(),
                        "{mode:?} {lost:?} {ber} seed {seed}: (g) lost a case"
                    );
                }
                // Racing regions and candidates: same bytes (or same refusal) on 1, 3 or
                // 8 threads.
                for t in [1usize, 3] {
                    let (other, _) = new_path_threads(&torn, t);
                    assert_eq!(
                        other.as_ref().ok(),
                        new.as_ref().ok(),
                        "{mode:?} {lost:?} {ber} seed {seed}: {t} thread(s) differ from 8"
                    );
                }
                if let Ok(n) = &new {
                    assert_eq!(n, &bytes, "{mode:?} {lost:?} {ber}");
                    new_ok += 1;
                }
                if let Ok(o) = &old {
                    old_ok += 1;
                    assert_eq!(o, &bytes);
                    assert_eq!(
                        new.as_ref().ok(),
                        Some(o),
                        "{mode:?} lost {lost:?} ber {ber} seed {seed}: old repaired, new did not ({st:?})"
                    );
                }
            }
        }
    }
    assert!(new_ok >= old_ok, "new {new_ok} old {old_ok} of {cases}");
    eprintln!(
        "corpus: old repaired {old_ok}, per-column {col_ok}, new repaired {new_ok}, of {cases}"
    );
    // Quoted in docs/SOFT-RS.md (fixed salt and damage seeds).
    assert_eq!(
        (old_ok, col_ok, new_ok, cases),
        CORPUS_COUNTS,
        "update the docs if this changes"
    );
}

/// Bigger stars, where column blocks really are split across threads: 1, 2 and 8 threads
/// return the same bytes (or all refuse), and any success is the exact original.
#[test]
fn mend_soft_same_bytes_any_thread_count() {
    for (mode, lost, ber, distinct) in [
        (Mode::Reflection, vec![0usize, 1], 1e-4, true),
        (Mode::Reflection, vec![0, 1], 1e-3, false),
        (Mode::Seal, vec![0, 1, 2, 3], 5e-4, false),
        (Mode::Reflection, vec![], 3e-3, false),
    ] {
        let msg = noise(300_000, 0x7e5);
        let bytes = seal(&msg, mode, None, "m.bin", false).unwrap();
        let torn = damage_ex(&bytes, &lost, ber, 13, distinct);
        let (one, _) = new_path_threads(&torn, 1);
        if let Ok(b) = &one {
            assert_eq!(b, &bytes, "{mode:?} {lost:?} {ber}");
        }
        for t in [2usize, 8] {
            let (many, _) = new_path_threads(&torn, t);
            assert_eq!(
                many.as_ref().ok(),
                one.as_ref().ok(),
                "{mode:?} {lost:?} {ber} {t}"
            );
        }
    }
}

/// Encrypted: the new path mends without the key (Merkle-gated), the wrong key still fails.
#[test]
fn mend_soft_new_path_encrypted_stuck_columns_and_wrong_key() {
    let msg = noise(48_000, 0xe1);
    let bytes = seal(&msg, Mode::Reflection, Some("deep space"), "e.bin", false).unwrap();
    let torn = damage_ex(&bytes, &[2, 9], 1e-4, 3, true);
    assert!(unseal(&torn, Some("deep space")).is_err());
    let (healed, st) = new_path(&torn);
    let healed = healed.unwrap_or_else(|e| panic!("{e} {st:?}"));
    assert_eq!(st.gate_calls, 1, "{st:?}");
    assert_eq!(healed, bytes);
    assert_eq!(unseal(&healed, Some("deep space")).unwrap(), msg);
    assert!(unseal(&healed, Some("wrong")).is_err());
}

/// Fail closed, fast: beyond repair means an error after a bounded number of checks.
#[test]
fn mend_soft_new_path_fails_closed_and_bounded() {
    let msg = noise(40_000, 0xdead);
    let bytes = seal(&msg, Mode::Reflection, None, "f.bin", false).unwrap();
    let h = read_header(&bytes).unwrap();
    // 4 lost (no spare symbol) + flips: no column can be checked, so no repair.
    let torn = damage(&bytes, &[0, 1, 2, 3], 2e-3, 11);
    let (r, st) = new_path(&torn);
    assert!(r.is_err());
    assert!(st.gate_calls <= 2 * (h.n - h.k) as usize + 2, "{st:?}");
    // Truncated mid-body: either the exact original or an error.
    let cut = damage(&bytes[..bytes.len() * 11 / 16], &[], 1e-3, 5);
    if let Ok(b) = new_path(&cut).0 {
        assert_eq!(b, bytes);
    }
    // Flooded with flips.
    let flood = damage(&bytes, &[], 5e-2, 6);
    if let Ok(b) = new_path(&flood).0 {
        assert_eq!(b, bytes);
    }
}

/// Timing on a bigger star (not run in CI): `cargo test --release -p sigil --lib
/// mend_soft_timing -- --ignored --nocapture`, size via `SIGIL_BENCH_BYTES`
/// (default 1 MiB), `SIGIL_BENCH_OLD=0` to skip the old search, `SIGIL_BENCH_THREADS`
/// (default 8) for the thread cap.
#[test]
#[ignore]
fn mend_soft_timing() {
    let size: usize = std::env::var("SIGIL_BENCH_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1 << 20);
    let threads: usize = std::env::var("SIGIL_BENCH_THREADS")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(crate::race::MAX_THREADS);
    let run_old = std::env::var("SIGIL_BENCH_OLD")
        .map(|v| v != "0")
        .unwrap_or(true);
    for (mode, lost, ber, distinct) in [
        (Mode::Reflection, vec![], 1e-4, false),
        (Mode::Reflection, vec![0usize, 1], 1e-5, true),
        (Mode::Seal, vec![0, 1, 2, 3], 1e-5, true),
        (Mode::Reflection, vec![0, 1], 1e-3, false),
        (Mode::Reflection, vec![], 1e-3, false),
        (Mode::Seal, vec![0, 1, 2, 3], 1e-3, false),
    ] {
        let msg = noise(size, 0xbe7c);
        let bytes = seal(&msg, mode, None, "t.bin", false).unwrap();
        let h = read_header(&bytes).unwrap();
        let torn = damage_ex(&bytes, &lost, ber, 7, distinct);
        let t = std::time::Instant::now();
        let (new, st) = new_path_threads(&torn, threads);
        let new_t = t.elapsed();
        eprintln!(
            "{size} B {mode:?} k={} n={} lost={lost:?} ber={ber} distinct={distinct} threads={threads}: new ok={} exact={} {:.3}s gates={} {:?}",
            h.k,
            h.n,
            new.is_ok(),
            new.as_ref().map(|b| b == &bytes).unwrap_or(false),
            new_t.as_secs_f64(),
            st.gate_calls,
            st.ratchet
        );
        if run_old {
            let t = std::time::Instant::now();
            let (old, gates) = mend_soft_legacy(&torn);
            eprintln!(
                "    old ok={} exact={} {:.3}s gates={gates}",
                old.is_ok(),
                old.as_ref().map(|b| b == &bytes).unwrap_or(false),
                t.elapsed().as_secs_f64()
            );
        }
    }
}

/// Bad-sector damage as failing disks and flash produce it: `count` distinct `sector`-byte
/// blocks, aligned to the file's own sector grid, anywhere in the file (header, Embers,
/// bodies and CRC trailers alike), filled with zeros (an unreadable sector after a
/// ddrescue-style copy) or random bytes (a garbage page).
pub(crate) fn damage_sectors(
    bytes: &[u8],
    sector: usize,
    count: usize,
    zero: bool,
    seed: u64,
) -> Vec<u8> {
    let mut out = bytes.to_vec();
    let slots = bytes.len().div_ceil(sector).max(1);
    let mut x = seed | 1;
    let mut next = || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    };
    let mut hit = std::collections::HashSet::new();
    while hit.len() < count.min(slots) {
        let s = (next() % slots as u64) as usize;
        if !hit.insert(s) {
            continue;
        }
        let end = ((s + 1) * sector).min(out.len());
        for b in &mut out[s * sector..end] {
            *b = if zero { 0 } else { next() as u8 };
        }
    }
    out
}

fn sha(b: &[u8]) -> [u8; 32] {
    use sha2::Digest;
    sha2::Sha256::digest(b).into()
}

/// `(old search, per-column alone, with (g), cases)` for
/// `mend_soft_matches_old_path_on_damage_corpus`.
const CORPUS_COUNTS: (usize, usize, usize, usize) = (18, 36, 39, 60);

/// `(per-column alone, with (g), cases)` for
/// `mend_joint_windows_repair_scattered_sectors_main_loses`.
const SECTOR_COUNTS: (usize, usize, usize) = (23, 41, 54);

/// Mend `torn` with the per-column ratchet alone (`false`) or with the (g) neighbour steps.
fn mend_with_joint(torn: &[u8], joint: bool, threads: usize) -> (Result<Vec<u8>>, SoftMendStats) {
    crate::soft_ratchet::set_joint_for_tests(joint);
    let r = new_path_threads(torn, threads);
    crate::soft_ratchet::set_joint_for_tests(true);
    r
}

/// (g) regression: scattered bad sectors (zero-filled and garbage, 512 B and 4 KiB) on
/// Reflection and Seal. With the neighbour steps on, repair (1) never loses a case the
/// per-column ratchet repairs, (2) repairs strictly more of them, and (3) every success is
/// the exact original Sigil (same SHA-256 fingerprint) that unseals to the exact original
/// file. Same bytes on 1 and 8 threads.
#[test]
fn mend_joint_windows_repair_scattered_sectors_main_loses() {
    let mut base_ok = 0;
    let mut joint_ok = 0;
    let mut cases = 0;
    for (mode, size, levels) in [
        (Mode::Reflection, 600_000usize, [8usize, 10, 12]),
        (Mode::Seal, 300_000, [24, 30, 36]),
    ] {
        let msg = noise(size, 0x6_1124 + size as u64);
        // Fixed salt, so the counts below are the same on every run.
        crate::set_test_random_seed(Some(0x5a17_1124 + size as u64));
        let bytes = seal(&msg, mode, None, "g.bin", false);
        crate::set_test_random_seed(None);
        let bytes = bytes.unwrap();
        let want = sha(&bytes);
        let want_msg = sha(&msg);
        for (li, &count) in levels.iter().enumerate() {
            for (sector, zero) in [(4096usize, true), (4096, false), (512, true)] {
                let count = if sector == 512 { count * 4 } else { count };
                for seed in 1..=3u64 {
                    cases += 1;
                    let s = 1124 + seed * 7919 + li as u64 * 31 + sector as u64 + zero as u64;
                    let torn = damage_sectors(&bytes, sector, count, zero, s);
                    let (base, _) = mend_with_joint(&torn, false, 8);
                    let (got, st) = mend_with_joint(&torn, true, 8);
                    let what = format!("{mode:?} {sector} B x{count} zero={zero} seed {seed}");
                    if let Ok(b) = &base {
                        assert_eq!(
                            sha(b),
                            want,
                            "{what}: per-column output is not the original"
                        );
                        base_ok += 1;
                        assert!(
                            got.is_ok(),
                            "{what}: (g) lost a case the ratchet repairs: {st:?}"
                        );
                    }
                    if let Ok(b) = &got {
                        assert_eq!(sha(b), want, "{what}: (g) output is not the original");
                        assert_eq!(sha(&unseal(b, None).unwrap()), want_msg, "{what}");
                        joint_ok += 1;
                        let (one, _) = mend_with_joint(&torn, true, 1);
                        assert_eq!(one.as_ref().ok(), Some(b), "{what}: 1 thread differs");
                    }
                }
            }
        }
    }
    eprintln!("sectors: per-column repaired {base_ok}, with (g) {joint_ok}, of {cases}");
    assert!(
        joint_ok > base_ok,
        "(g) gained nothing: {joint_ok} vs {base_ok} of {cases}"
    );
    // The counts quoted in docs/SOFT-RS.md and README.md (fixed salt and damage seeds).
    assert_eq!(
        (base_ok, joint_ok, cases),
        SECTOR_COUNTS,
        "update the docs if this changes"
    );
}

/// (g) on an encrypted Sigil: mend needs no key and repairs bad-sector damage the
/// per-column ratchet cannot; the output is the exact original, opens with the right key
/// and not with a wrong one.
#[test]
fn mend_joint_windows_encrypted_sectors_and_wrong_key() {
    let msg = noise(600_000, 0xe_1124);
    let bytes = seal(&msg, Mode::Reflection, Some("deep space"), "e.bin", false).unwrap();
    let mut found = false;
    for seed in 1..=40u64 {
        let torn = damage_sectors(&bytes, 4096, 12, true, 0xe5 + seed);
        let (base, _) = mend_with_joint(&torn, false, 8);
        let (got, st) = mend_with_joint(&torn, true, 8);
        if let Ok(b) = &got {
            assert_eq!(sha(b), sha(&bytes), "seed {seed}");
        }
        if base.is_err() {
            if let Ok(b) = got {
                let rep = st.ratchet.unwrap_or_default();
                assert!(rep.joint_columns + rep.hunt_columns > 0, "{rep:?}");
                assert_eq!(unseal(&b, Some("deep space")).unwrap(), msg);
                assert!(unseal(&b, Some("wrong")).is_err());
                found = true;
                break;
            }
        }
    }
    assert!(
        found,
        "no seed where (g) repaired what the per-column ratchet could not"
    );
}

/// Fail closed with (g) on: damage past any repair, sectors plus bit flips, cut-off tails
/// and a Sigil whose stored Merkle binding was altered never give back anything but the
/// exact original (or an error after a bounded number of whole-file checks).
#[test]
fn mend_joint_windows_fail_closed() {
    let msg = noise(300_000, 0xfa11);
    let bytes = seal(&msg, Mode::Reflection, None, "f.bin", false).unwrap();
    let h = read_header(&bytes).unwrap();
    let cap = 2 * (h.n - h.k) as usize + 2;
    let want = sha(&bytes);
    for seed in 1..=4u64 {
        // Far past the limit: an error, bounded.
        let torn = damage_sectors(&bytes, 4096, 40, false, seed);
        let (r, st) = mend_with_joint(&torn, true, 8);
        assert!(
            r.is_err(),
            "seed {seed}: repaired 40 of ~74 sectors? {st:?}"
        );
        assert!(st.gate_calls <= cap, "{st:?}");
        // Sectors plus a few stray bit flips (class H) and plus a cut tail (class E).
        let mut mixed = damage_sectors(&bytes, 4096, 10, true, 50 + seed);
        mixed = damage(&mixed, &[], 2e-6, 60 + seed);
        let cut = &mixed[..mixed.len() - 3000 * seed as usize];
        for t in [&mixed[..], cut] {
            let (r, st) = mend_with_joint(t, true, 8);
            if let Ok(b) = r {
                assert_eq!(sha(&b), want, "seed {seed}");
            }
            assert!(st.gate_calls <= cap, "{st:?}");
        }
    }
    // Tampered binding: every header copy claims a different Merkle root. Repair can only
    // fail (or rebuild the true header from elsewhere), never return other bytes.
    let root = merkle_root_offset(&bytes);
    let mut forged = damage_sectors(&bytes, 4096, 8, true, 77);
    for off in root {
        forged[off] ^= 0x40;
    }
    let (r, _) = mend_with_joint(&forged, true, 8);
    if let Ok(b) = r {
        assert_eq!(sha(&b), want);
    }
}

/// Byte offsets of the Merkle root in every copy of the 160-byte header in the file
/// (front copy and Keystone copies; located by matching the front copy's root bytes).
fn merkle_root_offset(bytes: &[u8]) -> Vec<usize> {
    let h = read_header(bytes).unwrap();
    let root = h.merkle;
    let mut out = Vec::new();
    let mut i = 0;
    while i + root.len() <= bytes.len() {
        if bytes[i..i + root.len()] == root {
            out.push(i);
        }
        i += 1;
    }
    assert!(!out.is_empty());
    out
}

/// Size the (g) edge on bigger stars (not run in CI): `cargo test --release -p sigil --lib
/// mend_joint_sector_sweep -- --ignored --nocapture`.
#[test]
#[ignore]
fn mend_joint_sector_sweep() {
    for (mode, size, levels) in [
        (
            Mode::Reflection,
            600_000usize,
            vec![6usize, 8, 10, 12, 14, 16],
        ),
        (Mode::Seal, 300_000, vec![12, 18, 24, 30, 36, 42]),
    ] {
        let msg = noise(size, 0x6_1124 + size as u64);
        let bytes = seal(&msg, mode, None, "g.bin", false).unwrap();
        for count in levels {
            let (mut b0, mut b1, mut n) = (0, 0, 0);
            for seed in 1..=10u64 {
                let torn =
                    damage_sectors(&bytes, 4096, count, seed % 2 == 0, seed * 13 + count as u64);
                let (base, _) = mend_with_joint(&torn, false, 8);
                let (got, _) = mend_with_joint(&torn, true, 8);
                n += 1;
                b0 += base.map(|b| (b == bytes) as usize).unwrap_or(0);
                b1 += got.map(|b| (b == bytes) as usize).unwrap_or(0);
            }
            eprintln!("{mode:?} {size} B, {count} x 4 KiB: per-column {b0}/{n}, (g) {b1}/{n}");
        }
    }
}
