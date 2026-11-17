//! Key-wrap (SGTO) damage measurement: how often an encrypted Sigil is lost ONLY because its
//! key wrap was hit while the data itself was still repairable. Not run in CI:
//! `cargo test --release -p sigil --lib keywrap_loss_table -- --ignored --nocapture`.
//! `SIGIL_KW_SIZES` (comma list of bytes) and `SIGIL_KW_TRIALS` override the defaults.

use crate::*;

fn xorshift(seed: u64) -> impl FnMut() -> u64 {
    let mut x = seed | 1;
    move || {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        x
    }
}

fn noise(len: usize, seed: u64) -> Vec<u8> {
    let mut r = xorshift(seed);
    (0..len).map(|_| r() as u8).collect()
}

/// Byte ranges that hold a key wrap: the front SGTO block, and any `SGTS` spare (new layout).
fn keywrap_ranges(f: &[u8]) -> Vec<std::ops::Range<usize>> {
    let (h, _, _) = locate_header(f).unwrap();
    let off = header::maps_len(&h);
    let len = keys::sgto_len_at(f, off);
    let mut out: Vec<std::ops::Range<usize>> = std::iter::once(off..off + len).collect();
    let mut i = f.len().saturating_sub(64 * 1024).max(off + len);
    while i + 8 <= f.len() {
        if &f[i..i + 4] == b"SGTS" {
            let l = keys::sgto_len_at(f, i + 8);
            if l > 0 {
                out.push(i..i + 8 + l);
                break;
            }
        }
        i += 1;
    }
    out
}

#[derive(Clone, Copy)]
enum Dmg {
    /// Flip round(len·8·ber) random bits anywhere in the file (at least one).
    Ber(f64),
    /// Zero `n` bytes starting at a uniform random offset.
    Burst(usize),
    /// Zero a fraction of the file starting at a uniform random offset.
    BurstFrac(f64),
}

fn apply(f: &[u8], d: Dmg, seed: u64) -> Vec<u8> {
    let mut r = xorshift(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) ^ 0x5bd1);
    let mut t = f.to_vec();
    let burst = |t: &mut Vec<u8>, n: usize, r: &mut dyn FnMut() -> u64| {
        let n = n.min(t.len());
        let s = (r() as usize) % (t.len() - n + 1);
        t[s..s + n].fill(0);
    };
    match d {
        Dmg::Ber(ber) => {
            let flips = ((f.len() as f64 * 8.0 * ber).round() as usize).max(1);
            for _ in 0..flips {
                let bit = (r() as usize) % (f.len() * 8);
                t[bit / 8] ^= 1 << (bit % 8);
            }
        }
        Dmg::Burst(n) => burst(&mut t, n, &mut r),
        Dmg::BurstFrac(x) => burst(&mut t, (f.len() as f64 * x) as usize, &mut r),
    }
    t
}

/// What `sigil unseal`, then `sigil mend` (quick, then soft) + unseal, get back.
fn open(t: &[u8], id: &keys::Identity, msg: &[u8]) -> Result<bool> {
    let ids = std::slice::from_ref(id);
    let be = mds::default_backend();
    let got = match unseal_ex_mds_keys(t, None, &[], &*be, ids) {
        Ok(p) => p,
        Err(_) => {
            let (m, _) = pieces::mend_bytes_ex(t, true)?;
            unseal_ex_mds_keys(&m, None, &[], &*be, ids)?
        }
    };
    Ok(got == msg)
}

#[derive(Default, Clone, Copy)]
struct Tally {
    exact: usize,
    refused: usize,
    wrong: usize,
    key_only: usize,
    key_hit: usize,
}

#[test]
#[ignore]
fn keywrap_loss_table() {
    let sizes: Vec<usize> = std::env::var("SIGIL_KW_SIZES")
        .ok()
        .map(|s| s.split(',').filter_map(|x| x.trim().parse().ok()).collect())
        .unwrap_or_else(|| vec![4 * 1024, 1024 * 1024, 10 * 1024 * 1024]);
    let trials_env: Option<usize> = std::env::var("SIGIL_KW_TRIALS")
        .ok()
        .and_then(|s| s.parse().ok());
    let id = keys::Identity::generate().unwrap();
    let cases = [
        ("bits BER 1e-5", Dmg::Ber(1e-5)),
        ("bits BER 1e-4", Dmg::Ber(1e-4)),
        ("bits BER 1e-3", Dmg::Ber(1e-3)),
        ("512 B burst", Dmg::Burst(512)),
        ("4 KiB burst", Dmg::Burst(4096)),
        ("10% burst", Dmg::BurstFrac(0.10)),
    ];
    println!("size,mode,file_bytes,keywrap_bytes,case,trials,exact,refused,WRONG,keywrap_hit,lost_only_keywrap");
    for &size in &sizes {
        let trials = trials_env.unwrap_or(match size {
            s if s <= 64 * 1024 => 400,
            s if s <= 2 * 1024 * 1024 => 100,
            _ => 100,
        });
        let msg = noise(size, size as u64);
        for mode in [Mode::Reflection, Mode::Seal] {
            let f = seal_kn_to(
                &msg,
                mode,
                None,
                "kw.bin",
                false,
                "",
                &[],
                None,
                DEFAULT_PIECE,
                &[id.public()],
            )
            .unwrap();
            assert!(open(&f, &id, &msg).unwrap());
            let ranges = keywrap_ranges(&f);
            let kw: usize = ranges.iter().map(|r| r.len()).sum();
            for (label, d) in cases {
                let threads = std::thread::available_parallelism().map_or(4, |n| n.get());
                let per: Vec<Tally> = std::thread::scope(|sc| {
                    let hs: Vec<_> = (0..threads)
                        .map(|w| {
                            let (f, msg, id, ranges) = (&f, &msg, &id, &ranges);
                            sc.spawn(move || {
                                let mut t = Tally::default();
                                for s in (w..trials).step_by(threads) {
                                    let torn = apply(f, d, s as u64 + 1);
                                    let hit =
                                        ranges.iter().any(|r| torn[r.clone()] != f[r.clone()]);
                                    t.key_hit += hit as usize;
                                    match open(&torn, id, msg) {
                                        Ok(true) => t.exact += 1,
                                        Ok(false) => t.wrong += 1,
                                        Err(_) => {
                                            t.refused += 1;
                                            if hit {
                                                let mut fixed = torn.clone();
                                                for r in ranges {
                                                    fixed[r.clone()].copy_from_slice(&f[r.clone()]);
                                                }
                                                if matches!(open(&fixed, id, msg), Ok(true)) {
                                                    t.key_only += 1;
                                                }
                                            }
                                        }
                                    }
                                }
                                t
                            })
                        })
                        .collect();
                    hs.into_iter().map(|h| h.join().unwrap()).collect()
                });
                let t = per.iter().fold(Tally::default(), |a, b| Tally {
                    exact: a.exact + b.exact,
                    refused: a.refused + b.refused,
                    wrong: a.wrong + b.wrong,
                    key_only: a.key_only + b.key_only,
                    key_hit: a.key_hit + b.key_hit,
                });
                println!(
                    "{size},{mode:?},{},{kw},{label},{trials},{},{},{},{},{}",
                    f.len(),
                    t.exact,
                    t.refused,
                    t.wrong,
                    t.key_hit,
                    t.key_only
                );
                assert_eq!(t.wrong, 0, "wrong plaintext returned");
            }
        }
    }
}

/// Reproduction: one flipped bit, and one wiped 16-byte range, inside the front key wrap of a
/// healthy encrypted Sigil. Prints what unseal and mend do and how many data shards are intact.
#[test]
#[ignore]
fn keywrap_single_hit_repro() {
    let id = keys::Identity::generate().unwrap();
    let msg = noise(200_000, 7);
    for pass in [None, Some("deep space nine")] {
        let recips = if pass.is_none() {
            vec![id.public()]
        } else {
            vec![]
        };
        let f = seal_kn_to(
            &msg,
            Mode::Reflection,
            pass,
            "r.bin",
            false,
            "",
            &[],
            None,
            DEFAULT_PIECE,
            &recips,
        )
        .unwrap();
        let ranges = keywrap_ranges(&f);
        let r0 = ranges[0].clone();
        for (what, torn) in [
            ("one flipped bit", {
                let mut t = f.clone();
                t[r0.start + 40] ^= 0x01;
                t
            }),
            ("16 bytes zeroed", {
                let mut t = f.clone();
                t[r0.start + 30..r0.start + 46].fill(0);
                t
            }),
        ] {
            let (h, prefix, _) = locate_header(&torn).unwrap();
            let live = header::gather_live_shards(&torn, &h, prefix)
                .iter()
                .filter(|s| s.is_some())
                .count();
            let ids = std::slice::from_ref(&id);
            let be = mds::default_backend();
            let un = unseal_ex_mds_keys(&torn, pass, &[], &*be, ids).map(|p| p == msg);
            let me = pieces::mend_bytes_ex(&torn, true)
                .map(|(m, _)| unseal_ex_mds_keys(&m, pass, &[], &*be, ids).map(|p| p == msg));
            println!(
                "wrap={} file={} B keywrap ranges={:?} damage={what}: intact data shards {live}/{} (need {}); unseal={:?}; mend+unseal={:?}",
                if pass.is_some() { "passphrase" } else { "encrypt-to" },
                f.len(),
                ranges,
                h.n,
                h.k,
                un.map_err(|e| e.to_string()),
                me.map_err(|e| e.to_string()).map(|r| r.map_err(|e| e.to_string())),
            );
        }
    }
}
