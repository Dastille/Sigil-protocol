//! `deluge --fountain --loss P`: how many extra RaptorQ packets to send so the far
//! side can rebuild without asking again, given an expected packet loss fraction.
//!
//! ## Model and formula
//!
//! One source block has `K` source symbols. The sender writes `N = K + E` packets
//! for it (`E` = extra repair packets). Assumptions:
//!
//! 1. **Independent losses.** Each packet is lost with the same probability `P`,
//!    independently of every other packet (no bursts, no outages). The number of
//!    packets that arrive is then `S ~ Binomial(N, 1 - P)`.
//! 2. **Arrived means intact.** A damaged packet is detected (per-packet SHA-256)
//!    and counts as lost.
//! 3. **RFC 6330 section 5.8 decoder bound.** Given `K'` symbols with ESIs chosen
//!    independently and uniformly at random, a compliant decoder fails at most
//!    1 in 100 times on average; with `K'+1` at most 1 in 10 000; with `K'+2` at
//!    most 1 in 1 000 000. Here `K'` is the padded block size; the `K' - K` padding
//!    symbols are known to the decoder, so `K + j` received packets stand for
//!    `K' + j` symbols. More symbols never hurt (a decoder may ignore extras), so
//!    `j >= 2` is bounded by 1e-6 as well, and `j < 0` (fewer than `K`) always fails.
//!    Sigil's default random ESIs match the bound's setting. With `--sequential`
//!    the ESIs are not random, so the bound is not claimed there; it is only measured.
//!
//! The chance that the block cannot be rebuilt from what arrives is then at most
//!
//! ```text
//! F(K, E, P) = P[S < K] + 1e-2 * P[S = K] + 1e-4 * P[S = K+1] + 1e-6 * P[S >= K+2]
//! ```
//!
//! computed from the exact binomial terms ([`block_failure_bound`]). `F` never
//! increases as `E` grows, so the smallest `E` with `F <= target` is found by binary
//! search ([`extra_for_loss`]). A file with `Z` source blocks uses the union bound:
//! each block gets `target / Z`, and the same `E` (the largest any block needs) is
//! sent for every block ([`loss_plan`]).
//!
//! The Chernoff bound `P[S <= m] <= exp(-N * D(m/N || 1-P))` ([`chernoff_lower_tail`],
//! `D` = binary relative entropy) gives a closed-form check: the exact count is never
//! larger than the count that bound would pick (tested).
//!
//! What this does **not** cover: bursty or correlated loss (a whole contact pass
//! missed), a loss rate higher than the one given, or a decoder that is not
//! RFC 6330 compliant. When fewer packets arrive than needed, `gather` refuses and
//! says how many more are needed; it never writes wrong bytes.

use crate::fountain::{block_sizes, MAX_ESI, MTU};
use crate::Result;
use raptorq::ObjectTransmissionInformation;

/// RFC 6330 section 5.8: decode-failure bounds with `K'`, `K'+1`, `K'+2` symbols.
pub const RFC6330_FAILURE: [f64; 3] = [1e-2, 1e-4, 1e-6];

/// Default target for `--loss`: the chance that the far side cannot rebuild the
/// whole file without a resend is at most 1 in 10 000.
pub const LOSS_TARGET_FAILURE: f64 = 1e-4;

fn err(m: impl Into<String>) -> crate::Error {
    crate::Error::Msg(m.into())
}

/// Parse a `--loss` value: a fraction `0 <= P < 1` (`0.1`) or a percentage below
/// 100 (`10%`). Refuses NaN, infinities, negatives, 1 / 100% and above, and empty
/// or trailing junk. A bare number >= 1 is refused with a hint, since `--loss 10`
/// most likely meant 10%.
pub fn parse_loss(s: &str) -> Result<f64> {
    let t = s.trim();
    let (num, pct) = match t.strip_suffix('%') {
        Some(n) => (n.trim(), true),
        None => (t, false),
    };
    let v: f64 = num.parse().map_err(|_| {
        err(format!(
            "--loss {s:?}: not a number (use a fraction like 0.1 or a percentage like 10%)"
        ))
    })?;
    if !v.is_finite() {
        return Err(err(format!("--loss {s:?}: must be a finite number")));
    }
    let p = if pct { v / 100.0 } else { v };
    if p < 0.0 {
        return Err(err(format!(
            "--loss {s:?}: a loss fraction cannot be negative"
        )));
    }
    if p >= 1.0 {
        return Err(err(if pct || v == 1.0 {
            format!("--loss {s:?}: must be below 100% (if every packet is lost, no amount of extra packets helps)")
        } else {
            format!("--loss {s:?}: must be a fraction below 1 (did you mean {v}%? write --loss {v}% or --loss {})", v / 100.0)
        }));
    }
    Ok(p)
}

/// Upper bound on the chance that one source block of `k` source symbols cannot
/// be rebuilt when `k + extra` packets are sent and each is lost independently with
/// probability `loss` (the formula `F` in the module docs). Returns 1.0 for
/// arguments outside the model (`k == 0`, `loss` not in `[0, 1)`).
pub fn block_failure_bound(k: u32, extra: u32, loss: f64) -> f64 {
    if k == 0 || !(0.0..1.0).contains(&loss) {
        return 1.0;
    }
    let weight = |s: u64| -> f64 {
        let k = u64::from(k);
        if s < k {
            1.0
        } else {
            match s - k {
                0 => RFC6330_FAILURE[0],
                1 => RFC6330_FAILURE[1],
                _ => RFC6330_FAILURE[2],
            }
        }
    };
    let n = u64::from(k) + u64::from(extra);
    if loss == 0.0 {
        return weight(n);
    }
    // Binomial terms for S = 0 ..= min(k+1, n), in log space:
    // ln pmf(0) = n ln(loss); pmf(s+1)/pmf(s) = (n-s)/(s+1) * (1-loss)/loss.
    let odds = ((1.0 - loss) / loss).ln();
    let top = (u64::from(k) + 1).min(n);
    // Compensated (Kahan) running sum of the log ratios keeps the error of
    // ln pmf small even for K in the tens of thousands.
    let mut ln_pmf = n as f64 * loss.ln();
    let mut carry = 0.0f64;
    let (mut sum, mut low) = (0.0f64, 0.0f64);
    for s in 0..=top {
        let pmf = ln_pmf.exp();
        sum += pmf * weight(s);
        low += pmf;
        let step = ((n - s) as f64 / (s + 1) as f64).ln() + odds - carry;
        let next = ln_pmf + step;
        carry = (next - ln_pmf) - step;
        ln_pmf = next;
    }
    let tail = (1.0 - low).max(0.0);
    (sum + RFC6330_FAILURE[2] * tail).clamp(0.0, 1.0)
}

/// Chernoff bound on `P[S <= m]` for `S ~ Binomial(n, 1 - loss)`:
/// `exp(-n * D(m/n || 1-loss))` when `m/n < 1 - loss`, else 1. A closed-form
/// cross-check for [`block_failure_bound`]; not used to pick the count.
pub fn chernoff_lower_tail(n: u64, m: u64, loss: f64) -> f64 {
    let q = 1.0 - loss;
    if n == 0 || !(0.0..1.0).contains(&loss) {
        return 1.0;
    }
    let a = m as f64 / n as f64;
    if a >= q {
        return 1.0;
    }
    if loss == 0.0 {
        return 0.0;
    }
    let term = |x: f64, y: f64| if x == 0.0 { 0.0 } else { x * (x / y).ln() };
    let d = term(a, q) + term(1.0 - a, loss);
    (-(n as f64) * d).exp()
}

/// Smallest number of extra packets `E` for a block of `k` source symbols with
/// `block_failure_bound(k, E, loss) <= target`. Refuses when no `E` within the
/// 24-bit ESI space reaches the target (the 1e-6 floor of RFC 6330 section 5.8
/// means `target` must be above 1e-6).
pub fn extra_for_loss(k: u32, loss: f64, target: f64) -> Result<u32> {
    if k == 0 || k > MAX_ESI {
        return Err(err("source block size out of range"));
    }
    if !(0.0..1.0).contains(&loss) {
        return Err(err("loss must be a fraction 0 <= P < 1"));
    }
    if !(target > 0.0 && target < 1.0) {
        return Err(err("target failure probability must be between 0 and 1"));
    }
    // Every packet of a block needs its own ESI: at most 2^24 per block.
    let hi_max = MAX_ESI - (k - 1);
    if block_failure_bound(k, hi_max, loss) > target {
        return Err(err(format!(
            "no number of extra packets reaches a failure chance of {target:e} at {:.4}% loss",
            loss * 100.0
        )));
    }
    let (mut lo, mut hi) = (0u32, hi_max);
    while lo < hi {
        let mid = lo + (hi - lo) / 2;
        if block_failure_bound(k, mid, loss) <= target {
            hi = mid;
        } else {
            lo = mid + 1;
        }
    }
    Ok(lo)
}

/// What `--loss` decided for one file.
#[derive(Debug, Clone, PartialEq)]
pub struct LossPlan {
    /// The loss fraction the plan was made for.
    pub loss: f64,
    /// Target: chance the whole file cannot be rebuilt without a resend.
    pub target: f64,
    /// Source symbols per source block (K of each block).
    pub blocks: Vec<u32>,
    /// Extra packets per block (the same for every block).
    pub extra: u32,
    /// Union bound over the blocks of [`block_failure_bound`] with this `extra`;
    /// never above `target`.
    pub failure_bound: f64,
}

impl LossPlan {
    /// Packets of this file the folder will hold: sum over blocks of `K + extra`.
    pub fn packets(&self) -> u64 {
        self.blocks
            .iter()
            .map(|k| u64::from(*k) + u64::from(self.extra))
            .sum()
    }
}

/// Plan `deluge --fountain --loss` for a file of `len` bytes: the source blocks
/// the encoder will use (same parameters as `deluge --fountain`), and the extra
/// packets per block so the chance any block fails is at most `target` (union
/// bound: `target / Z` per block for `Z` blocks).
pub fn loss_plan(len: u64, loss: f64, target: f64) -> Result<LossPlan> {
    if len == 0 {
        return Err(err("nothing to rain: the file is empty"));
    }
    let oti = ObjectTransmissionInformation::with_defaults(len, MTU);
    let blocks = block_sizes(&oti).ok_or_else(|| err("file too large for one fountain object"))?;
    let per_block = target / blocks.len() as f64;
    let mut extra = 0u32;
    let mut sizes: Vec<u32> = blocks.clone();
    sizes.sort_unstable();
    sizes.dedup();
    for k in sizes {
        extra = extra.max(extra_for_loss(k, loss, per_block)?);
    }
    let failure_bound: f64 = blocks
        .iter()
        .map(|k| block_failure_bound(*k, extra, loss))
        .sum();
    Ok(LossPlan {
        loss,
        target,
        blocks,
        extra,
        failure_bound,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::fs;
    use std::path::{Path, PathBuf};

    /// Values from an independent exact-rational evaluation of `F` (Python
    /// `fractions.Fraction`, `math.comb`), smallest `E` with `F <= 1e-4`.
    const KNOWN: &[(u32, f64, u32)] = &[
        (1, 0.0, 1),
        (1, 0.01, 2),
        (1, 0.05, 3),
        (1, 0.1, 4),
        (1, 0.25, 6),
        (1, 0.5, 13),
        (2, 0.25, 8),
        (2, 0.5, 16),
        (10, 0.01, 3),
        (10, 0.05, 5),
        (10, 0.1, 8),
        (10, 0.25, 15),
        (10, 0.5, 33),
        (82, 0.0, 1),
        (82, 0.01, 6),
        (82, 0.05, 14),
        (82, 0.1, 23),
        (82, 0.25, 53),
        (82, 0.5, 136),
    ];

    fn close(a: f64, b: f64) -> bool {
        (a - b).abs() <= 1e-9 * b.abs().max(1e-300)
    }

    #[test]
    fn bound_matches_exact_values() {
        // F(K, E, P) from the exact-rational reference, at the chosen E and E-1.
        let cases: &[(u32, u32, f64, f64)] = &[
            (1, 4, 0.1, 1.630144e-05),
            (1, 3, 0.1, 0.0001418077),
            (10, 8, 0.1, 2.350707015889836e-05),
            (10, 7, 0.1, 0.0001138111596937614),
            (82, 23, 0.1, 9.366623491971105e-05),
            (82, 22, 0.1, 0.00021717329313169616),
            (82, 53, 0.25, 9.202971639620474e-05),
            (82, 136, 0.5, 9.22720627549417e-05),
            (82, 135, 0.5, 0.00011676953279319513),
        ];
        for &(k, e, p, want) in cases {
            let got = block_failure_bound(k, e, p);
            assert!(close(got, want), "F({k},{e},{p}) = {got:e}, want {want:e}");
        }
        // No loss: exactly the RFC 6330 section 5.8 numbers, then the 1e-6 floor.
        assert_eq!(block_failure_bound(82, 0, 0.0), 1e-2);
        assert_eq!(block_failure_bound(82, 1, 0.0), 1e-4);
        assert_eq!(block_failure_bound(82, 2, 0.0), 1e-6);
        assert_eq!(block_failure_bound(82, 50, 0.0), 1e-6);
        // Outside the model.
        assert_eq!(block_failure_bound(0, 5, 0.1), 1.0);
        assert_eq!(block_failure_bound(5, 5, 1.0), 1.0);
        assert_eq!(block_failure_bound(5, 5, -0.1), 1.0);
        assert_eq!(block_failure_bound(5, 5, f64::NAN), 1.0);
    }

    #[test]
    fn extra_matches_known_values_and_is_the_smallest() {
        for &(k, p, want) in KNOWN {
            let e = extra_for_loss(k, p, LOSS_TARGET_FAILURE).unwrap();
            assert_eq!(e, want, "K={k} P={p}");
            assert!(block_failure_bound(k, e, p) <= LOSS_TARGET_FAILURE);
            if e > 0 {
                assert!(block_failure_bound(k, e - 1, p) > LOSS_TARGET_FAILURE);
            }
        }
    }

    #[test]
    fn bound_never_increases_with_more_extra() {
        for &k in &[1u32, 7, 82, 1000] {
            for &p in &[0.0, 0.01, 0.1, 0.3, 0.7] {
                let mut prev = 1.0f64;
                for e in 0..400 {
                    let f = block_failure_bound(k, e, p);
                    assert!(
                        f <= prev * (1.0 + 1e-12),
                        "K={k} P={p} E={e}: {f:e} > {prev:e}"
                    );
                    prev = f;
                }
            }
        }
    }

    #[test]
    fn exact_count_never_exceeds_the_chernoff_count() {
        let floor = RFC6330_FAILURE[2];
        for &k in &[1u32, 10, 82, 1000, 20_000] {
            for &p in &[0.01, 0.05, 0.1, 0.25, 0.5, 0.9] {
                let exact = extra_for_loss(k, p, LOSS_TARGET_FAILURE).unwrap();
                // F <= P[S <= K+1] + 1e-6, so Chernoff on P[S <= K+1] <= target - 1e-6
                // is enough; the smallest such E can only be >= the exact one.
                let mut e = 0u32;
                while chernoff_lower_tail(u64::from(k + e), u64::from(k) + 1, p)
                    > LOSS_TARGET_FAILURE - floor
                {
                    e += 1;
                }
                assert!(exact <= e, "K={k} P={p}: exact {exact} > chernoff {e}");
                // And the exact count is a real saving, not a different formula
                // that happens to agree: within the Chernoff count but above the
                // bare mean K/(1-P) - K.
                let mean = f64::from(k) / (1.0 - p) - f64::from(k);
                assert!(f64::from(exact) >= mean.floor(), "K={k} P={p}");
            }
        }
        assert_eq!(chernoff_lower_tail(10, 3, 0.0), 0.0);
        assert_eq!(chernoff_lower_tail(10, 9, 0.5), 1.0);
    }

    #[test]
    fn unreachable_targets_and_bad_arguments_are_refused() {
        // RFC 6330's 1e-6 floor: a target at or below it cannot be promised.
        assert!(extra_for_loss(82, 0.1, 1e-7).is_err());
        assert!(extra_for_loss(0, 0.1, 1e-4).is_err());
        assert!(extra_for_loss(82, 1.0, 1e-4).is_err());
        assert!(extra_for_loss(82, -0.5, 1e-4).is_err());
        assert!(extra_for_loss(82, f64::NAN, 1e-4).is_err());
        assert!(extra_for_loss(82, 0.1, 0.0).is_err());
        assert!(extra_for_loss(82, 0.1, 1.0).is_err());
        // So much loss that 2^24 packets per block are not enough.
        assert!(extra_for_loss(56_403, 0.999_999, 1e-4).is_err());
    }

    #[test]
    fn parse_loss_accepts_fractions_and_percentages_and_refuses_nonsense() {
        for (s, want) in [
            ("0", 0.0),
            ("0.1", 0.1),
            (" 0.25 ", 0.25),
            ("10%", 0.1),
            ("2.5%", 0.025),
            ("99.9%", 0.999),
            ("0.999", 0.999),
        ] {
            let got = parse_loss(s).unwrap();
            assert!((got - want).abs() < 1e-12, "{s}: {got}");
        }
        for s in [
            "", "abc", "1", "1.0", "100%", "150%", "10", "-0.1", "-1%", "nan", "NaN", "inf",
            "-inf", "0.1x", "%", "1e400",
        ] {
            assert!(parse_loss(s).is_err(), "{s:?} should be refused");
        }
        let msg = parse_loss("10").unwrap_err().to_string();
        assert!(msg.contains("10%"), "{msg}");
    }

    #[test]
    fn plan_uses_the_encoders_blocks_and_the_union_bound() {
        // 82 symbols of 16 KiB: the 1 336 608-byte Reflection mark of the bench.
        let p = loss_plan(1_336_608, 0.1, LOSS_TARGET_FAILURE).unwrap();
        assert_eq!(p.blocks, vec![82]);
        assert_eq!(p.extra, 23);
        assert_eq!(p.packets(), 105);
        assert!(p.failure_bound <= LOSS_TARGET_FAILURE);
        // A file big enough for several source blocks: each block gets target / Z.
        let big = loss_plan(3 << 30, 0.1, LOSS_TARGET_FAILURE).unwrap();
        assert!(big.blocks.len() > 1, "{:?}", big.blocks.len());
        let z = big.blocks.len() as f64;
        let kmax = *big.blocks.iter().max().unwrap();
        assert_eq!(
            big.extra,
            extra_for_loss(kmax, 0.1, LOSS_TARGET_FAILURE / z)
                .unwrap()
                .max(
                    extra_for_loss(
                        *big.blocks.iter().min().unwrap(),
                        0.1,
                        LOSS_TARGET_FAILURE / z
                    )
                    .unwrap()
                )
        );
        assert!(big.failure_bound <= LOSS_TARGET_FAILURE);
        assert!(loss_plan(0, 0.1, LOSS_TARGET_FAILURE).is_err());
    }

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sigil-loss-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    /// xorshift64: seeded, so every trial is the same on every run.
    fn rng(seed: u64) -> impl FnMut() -> u64 {
        let mut x = seed.wrapping_mul(0x9e37_79b9_7f4a_7c15) | 1;
        move || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        }
    }

    fn rq_files(d: &Path) -> Vec<PathBuf> {
        let mut v: Vec<_> = fs::read_dir(d)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("rq"))
            .collect();
        v.sort();
        v
    }

    /// Rain with `--loss P` (seeded ESIs), drop each packet independently with
    /// probability `drop` (seeded), gather. Returns (rebuilt exact, refused).
    fn trials(data: &[u8], loss: f64, drop: f64, sequential: bool, n: u64) -> (u32, u32) {
        let plan = loss_plan(data.len() as u64, loss, LOSS_TARGET_FAILURE).unwrap();
        let src = scratch(&format!("src-{loss}-{drop}-{sequential}"));
        let mut esi = rng(7);
        let rep =
            crate::fountain::deluge_fountain_with(data, &src, plan.extra, sequential, &mut || {
                Ok(esi() as u32)
            })
            .unwrap();
        assert_eq!(u64::from(rep.total()), plan.packets());
        let files = rq_files(&src);
        let (mut ok, mut refused) = (0, 0);
        for t in 0..n {
            let dst = scratch(&format!("dst-{loss}-{drop}-{sequential}"));
            let mut r = rng(1000 + t);
            for f in &files {
                // Keep with probability 1 - drop.
                if (r() >> 11) as f64 / (1u64 << 53) as f64 >= drop {
                    fs::copy(f, dst.join(f.file_name().unwrap())).unwrap();
                }
            }
            match crate::fountain::gather_fountain(&dst) {
                Ok(back) => {
                    assert_eq!(back, data, "gather returned different bytes");
                    ok += 1;
                }
                Err(_) => refused += 1,
            }
            let _ = fs::remove_dir_all(&dst);
        }
        let _ = fs::remove_dir_all(&src);
        (ok, refused)
    }

    fn data(k: usize) -> Vec<u8> {
        let mut r = rng(42);
        (0..k * usize::from(MTU)).map(|_| r() as u8).collect()
    }

    #[test]
    fn seeded_random_drop_at_the_stated_loss_rebuilds_every_trial() {
        let d = data(40);
        for p in [0.05, 0.10, 0.25, 0.5] {
            let (ok, refused) = trials(&d, p, p, false, 100);
            assert_eq!((ok, refused), (100, 0), "loss {p}");
        }
        // --sequential uses the same count; measured, not covered by the RFC bound.
        let (ok, refused) = trials(&d, 0.25, 0.25, true, 100);
        assert_eq!((ok, refused), (100, 0), "sequential");
    }

    #[test]
    fn loss_worse_than_stated_fails_closed() {
        // Planned for 5% but 50% are lost: gather refuses, never wrong bytes
        // (`trials` asserts exactness on every success).
        let d = data(40);
        let (ok, refused) = trials(&d, 0.05, 0.5, false, 5);
        assert_eq!((ok, refused), (0, 5));
    }
}
