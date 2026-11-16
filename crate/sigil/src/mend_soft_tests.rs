//! `mend --soft` speed and equivalence: the easy-first column repair against the
//! pre-ratchet search (kept as `pieces::mend_soft_legacy`, test only).

use crate::pieces::{mend_bytes_stats, mend_soft_legacy, SoftMendStats};
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
    let mut cases = 0;
    for (mode, size) in [(Mode::Reflection, 20_000usize), (Mode::Seal, 24_000)] {
        let msg = noise(size, size as u64);
        let bytes = seal(&msg, mode, None, "c.bin", false).unwrap();
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
    eprintln!("corpus: old repaired {old_ok}, new repaired {new_ok}, of {cases}");
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
/// (default 1 MiB), `SIGIL_BENCH_OLD=0` to skip the old search.
#[test]
#[ignore]
fn mend_soft_timing() {
    let size: usize = std::env::var("SIGIL_BENCH_BYTES")
        .ok()
        .and_then(|s| s.parse().ok())
        .unwrap_or(1 << 20);
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
        let (new, st) = new_path(&torn);
        let new_t = t.elapsed();
        eprintln!(
            "{size} B {mode:?} k={} n={} lost={lost:?} ber={ber} distinct={distinct}: new ok={} exact={} {:.3}s gates={} {:?}",
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
