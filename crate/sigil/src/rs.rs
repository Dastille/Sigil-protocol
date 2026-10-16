//! v1: polynomial coefficients = data (evaluation code).
//! v2: first k shards ARE the data (systematic); parity is extra evaluations.

use crate::gf;
use crate::Error;

// Every operation here is a fixed linear map over GF(256) applied to each byte
// column. The map depends only on (k, n, which shards are used), so we build
// its matrix once and then run whole shard slices through `gf::matrix_apply`
// (table/SIMD multiply-accumulate). Field arithmetic is exact, so the bytes are
// identical to the old per-column solve, which lives on in `rs_ref` as an oracle.

/// Evaluation point for shard `index` (wraps exactly like the original code).
fn x_of(index: usize) -> u8 {
    (index + 1) as u8
}

/// Row-major `rows × k` power matrix: E[i][j] = x_i^j (so E·coeffs = evaluations).
fn power_matrix(xs: &[u8], k: usize) -> Vec<u8> {
    let mut m = vec![0u8; xs.len() * k];
    for (i, &x) in xs.iter().enumerate() {
        let mut p = 1u8;
        for j in 0..k {
            m[i * k + j] = p;
            p = gf::mul(p, x);
        }
    }
    m
}

/// Inverse of the k×k Vandermonde matrix at `xs` (maps evaluations → coefficients).
/// Panics on a singular system, exactly like `gf::solve_vandermonde` did.
fn vandermonde_inverse(xs: &[u8]) -> Vec<u8> {
    let k = xs.len();
    gf::invert_matrix(k, &power_matrix(xs, k)).expect("singular")
}

/// Matrix mapping k data shards → shard `rows` evaluations.
/// systematic: E(rows) · V(1..k)^-1 ; v1: E(rows).
fn encode_matrix(k: usize, rows: &[usize], systematic: bool) -> Vec<u8> {
    let xr: Vec<u8> = rows.iter().map(|&i| x_of(i)).collect();
    let e = power_matrix(&xr, k);
    if systematic {
        let xs: Vec<u8> = (0..k).map(x_of).collect();
        gf::matmul(&e, &vandermonde_inverse(&xs), rows.len(), k, k)
    } else {
        e
    }
}

/// Matrix mapping k received symbols at `xs` → k data symbols.
fn decode_matrix(xs: &[u8], systematic: bool) -> Vec<u8> {
    let k = xs.len();
    let vinv = vandermonde_inverse(xs);
    if systematic {
        let data_xs: Vec<u8> = (0..k).map(x_of).collect();
        gf::matmul(&power_matrix(&data_xs, k), &vinv, k, k, k)
    } else {
        vinv
    }
}

#[allow(dead_code)]
pub fn encode_column(data: &[u8], n: usize) -> Vec<u8> {
    (0..n).map(|i| gf::eval_poly(data, (i + 1) as u8)).collect()
}

#[allow(dead_code)]
pub fn decode_column(codeword: &[u8], k: usize, erased: &[bool]) -> Result<Vec<u8>, Error> {
    let mut xs = Vec::with_capacity(k);
    let mut ys = Vec::with_capacity(k);
    for (i, &sym) in codeword.iter().enumerate() {
        if xs.len() == k {
            break;
        }
        if erased[i] {
            continue;
        }
        xs.push((i + 1) as u8);
        ys.push(sym);
    }
    if xs.len() < k {
        return Err(Error::Msg(format!("need {k} live shards")));
    }
    Ok(gf::solve_vandermonde(&xs, &ys))
}

pub fn encode_shards(payload: &[u8], k: usize, n: usize) -> Vec<Vec<u8>> {
    encode_shards_ex(payload, k, n, true)
}

/// v1 evaluation code (coefficients = data). Kept so old files still De-scribe.
pub fn encode_shards_v1(payload: &[u8], k: usize, n: usize) -> Vec<Vec<u8>> {
    encode_shards_ex(payload, k, n, false)
}

fn split_padded(payload: &[u8], k: usize) -> (usize, Vec<Vec<u8>>) {
    let shard_len = (payload.len().div_ceil(k)).max(1);
    let data = (0..k)
        .map(|i| {
            let mut v = vec![0u8; shard_len];
            let a = (i * shard_len).min(payload.len());
            let b = ((i + 1) * shard_len).min(payload.len());
            v[..b - a].copy_from_slice(&payload[a..b]);
            v
        })
        .collect();
    (shard_len, data)
}

fn encode_shards_ex(payload: &[u8], k: usize, n: usize, systematic: bool) -> Vec<Vec<u8>> {
    let (shard_len, data) = split_padded(payload, k);
    let rows: Vec<usize> = if systematic {
        (k..n).collect()
    } else {
        (0..n).collect()
    };
    let m = encode_matrix(k, &rows, systematic);
    let ins: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
    let mut computed = vec![vec![0u8; shard_len]; rows.len()];
    {
        let mut outs: Vec<&mut [u8]> = computed.iter_mut().map(|v| v.as_mut_slice()).collect();
        gf::matrix_apply(&m, &ins, &mut outs);
    }
    if systematic {
        let mut shards = data;
        shards.truncate(n.min(k));
        shards.extend(computed);
        shards
    } else {
        computed
    }
}

pub fn decode_shards(
    shards: &[Option<Vec<u8>>],
    k: usize,
    payload_len: usize,
    systematic: bool,
) -> Result<Vec<u8>, Error> {
    let parts: Vec<(usize, Vec<u8>)> = shards
        .iter()
        .enumerate()
        .filter_map(|(i, s)| s.as_ref().map(|b| (i, b.clone())))
        .collect();
    decode_indexed(&parts, k, payload_len, systematic)
}

pub fn encode_shard_index(payload: &[u8], k: usize, index: usize, systematic: bool) -> Vec<u8> {
    let (shard_len, data) = split_padded(payload, k);
    if systematic && index < k {
        return data[index].clone();
    }
    let m = encode_matrix(k, &[index], systematic);
    let ins: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
    let mut shard = vec![0u8; shard_len];
    gf::matrix_apply(&m, &ins, &mut [shard.as_mut_slice()]);
    shard
}

/// First k distinct usable evaluation points, as (x, position in `idx`).
fn pick_live(idx: impl Iterator<Item = usize>, k: usize) -> (Vec<u8>, Vec<usize>) {
    let mut xs = Vec::with_capacity(k);
    let mut pos = Vec::with_capacity(k);
    for (j, index) in idx.enumerate() {
        if xs.len() == k {
            break;
        }
        if index > 254 {
            continue;
        }
        let x = x_of(index);
        if xs.contains(&x) {
            continue;
        }
        xs.push(x);
        pos.push(j);
    }
    (xs, pos)
}

/// Recover payload from any k shards, each tagged with its index (eval at index+1).
pub fn decode_indexed(
    parts: &[(usize, Vec<u8>)],
    k: usize,
    payload_len: usize,
    systematic: bool,
) -> Result<Vec<u8>, Error> {
    if parts.len() < k {
        return Err(Error::Msg(format!("need {k} pieces, have {}", parts.len())));
    }
    let shard_len = parts[0].1.len();
    if systematic {
        let mut data_ok = vec![None; k];
        for (index, body) in parts {
            if *index < k && data_ok[*index].is_none() {
                data_ok[*index] = Some(body);
            }
        }
        if data_ok.iter().all(|s| s.is_some()) {
            let mut padded = vec![0u8; shard_len * k];
            for i in 0..k {
                let s = data_ok[i].unwrap();
                let n = s.len().min(shard_len);
                padded[i * shard_len..i * shard_len + n].copy_from_slice(&s[..n]);
            }
            padded.truncate(payload_len);
            return Ok(padded);
        }
    }
    let (xs, live_idx) = pick_live(parts.iter().map(|p| p.0), k);
    if xs.len() < k {
        return Err(Error::Msg(format!("need {k} distinct pieces")));
    }
    let m = decode_matrix(&xs, systematic);
    // Inputs longer than shard_len are cut; shorter ones read as zero (as before).
    let ins: Vec<&[u8]> = live_idx
        .iter()
        .map(|&j| {
            let b = &parts[j].1;
            &b[..b.len().min(shard_len)]
        })
        .collect();
    let mut padded = vec![0u8; shard_len * k];
    {
        let mut outs: Vec<&mut [u8]> = padded.chunks_mut(shard_len.max(1)).take(k).collect();
        gf::matrix_apply(&m, &ins, &mut outs);
    }
    padded.truncate(payload_len);
    Ok(padded)
}

pub fn stripe(payload: &[u8], n: usize) -> Vec<Vec<u8>> {
    let shard_len = (payload.len().div_ceil(n)).max(1);
    let mut padded = vec![0u8; shard_len * n];
    padded[..payload.len()].copy_from_slice(payload);
    (0..n)
        .map(|i| padded[i * shard_len..(i + 1) * shard_len].to_vec())
        .collect()
}

pub fn unstripe(shards: &[Option<Vec<u8>>], payload_len: usize) -> Result<Vec<u8>, Error> {
    if shards.iter().any(|s| s.is_none()) {
        return Err(Error::Msg("glyph: missing shard".into()));
    }
    let mut out = Vec::new();
    for s in shards {
        out.extend_from_slice(s.as_ref().unwrap());
    }
    out.truncate(payload_len);
    Ok(out)
}

/// Soft-RS stripe width within a shard payload (v0).
pub const SOFT_STRIPE: usize = 4096;

/// One present shard for soft decode: `hard` means whole-shard CRC passed.
#[derive(Clone, Debug)]
pub struct SoftPart {
    pub index: usize,
    pub body: Vec<u8>,
    pub hard: bool,
}

fn shard_len_of(parts: &[SoftPart]) -> usize {
    parts.iter().map(|p| p.body.len()).max().unwrap_or(0)
}

/// Stripe-aware graded decode: hard symbols preferred; soft fill gaps.
/// `erased_soft_stripes` lists (shard_index, stripe_idx) forced to erasure.
///
/// The set of symbols chosen is the same for every byte of a stripe, so each
/// stripe is one matrix × slices pass (matrices cached per chosen-index set).
fn decode_graded_with_mask(
    parts: &[SoftPart],
    k: usize,
    payload_len: usize,
    systematic: bool,
    erased_soft_stripes: &[(usize, usize)],
) -> Result<Vec<u8>, Error> {
    let shard_len = shard_len_of(parts);
    if shard_len == 0 {
        return Err(Error::Msg("empty shards".into()));
    }
    // Fast path: enough hard shards and no stripe erasures → classic indexed decode.
    if erased_soft_stripes.is_empty() {
        let hard: Vec<(usize, Vec<u8>)> = parts
            .iter()
            .filter(|p| p.hard)
            .map(|p| (p.index, p.body.clone()))
            .collect();
        if hard.len() >= k {
            return decode_indexed(&hard, k, payload_len, systematic);
        }
    }

    let mut cache: std::collections::HashMap<Vec<u8>, Vec<u8>> = Default::default();
    let mut padded = vec![0u8; shard_len * k];
    let mut out_rows = vec![vec![0u8; SOFT_STRIPE.min(shard_len)]; k];
    let mut st = 0;
    while st * SOFT_STRIPE < shard_len {
        let a = st * SOFT_STRIPE;
        let b = (a + SOFT_STRIPE).min(shard_len);
        // Same selection rule as the per-column code: hard first, then soft.
        let mut hard_sel: Vec<&SoftPart> = Vec::new();
        let mut soft_sel: Vec<&SoftPart> = Vec::new();
        for p in parts {
            let erased = !p.hard
                && erased_soft_stripes
                    .iter()
                    .any(|&(si, s2)| si == p.index && s2 == st);
            if erased {
                continue;
            }
            if p.hard {
                hard_sel.push(p);
            } else {
                soft_sel.push(p);
            }
        }
        let mut chosen = hard_sel;
        if chosen.len() < k {
            for sp in soft_sel {
                if chosen.len() >= k {
                    break;
                }
                if chosen.iter().any(|c| c.index == sp.index) {
                    continue;
                }
                chosen.push(sp);
            }
        }
        if chosen.len() < k {
            return Err(Error::Msg(format!("need {k} live symbols")));
        }
        let (xs, pos) = pick_live(chosen.iter().map(|c| c.index), k);
        if xs.len() < k {
            return Err(Error::Msg(format!("need {k} distinct symbols")));
        }
        let m = cache
            .entry(xs.clone())
            .or_insert_with(|| decode_matrix(&xs, systematic));
        let ins: Vec<&[u8]> = pos
            .iter()
            .map(|&j| {
                let body = &chosen[j].body;
                &body[a.min(body.len())..b.min(body.len())]
            })
            .collect();
        {
            let mut outs: Vec<&mut [u8]> = out_rows.iter_mut().map(|r| &mut r[..b - a]).collect();
            gf::matrix_apply(m, &ins, &mut outs);
        }
        for (i, row) in out_rows.iter().enumerate() {
            padded[i * shard_len + a..i * shard_len + b].copy_from_slice(&row[..b - a]);
        }
        st += 1;
    }
    padded.truncate(payload_len);
    Ok(padded)
}

fn soft_stripe_count(parts: &[SoftPart]) -> usize {
    let sl = shard_len_of(parts);
    if sl == 0 {
        0
    } else {
        sl.div_ceil(SOFT_STRIPE)
    }
}

/// Soft-decision RS (GMD-lite): prefer CRC-hard shards; salvage Soft bodies with
/// stripe-level erasures. Caller must gate acceptance (Merkle / true-name).
///
/// Attempts:
/// 1. Hard-only erasure decode
/// 2. Include soft shards; if accept fails, flip ≤ (n−k) lowest-reliability soft
///    shards (by index) to full erasure and retry
/// 3. Stripe GMD: flip ≤ (n−k) lowest-reliability soft stripes to erasure and retry
pub fn decode_soft<F>(
    parts: &[SoftPart],
    k: usize,
    n: usize,
    payload_len: usize,
    systematic: bool,
    mut accept: F,
) -> Result<Vec<u8>, Error>
where
    F: FnMut(&[u8]) -> bool,
{
    let hard_n = parts.iter().filter(|p| p.hard).count();
    let soft_n = parts.iter().filter(|p| !p.hard).count();
    let present = parts.len();
    if present < k {
        return Err(Error::Msg(format!(
            "need {k} present shards for soft mend, have {present}"
        )));
    }

    // 1) Hard-only
    if hard_n >= k {
        let hard: Vec<(usize, Vec<u8>)> = parts
            .iter()
            .filter(|p| p.hard)
            .map(|p| (p.index, p.body.clone()))
            .collect();
        if let Ok(payload) = decode_indexed(&hard, k, payload_len, systematic) {
            if accept(&payload) {
                return Ok(payload);
            }
        }
    }

    if hard_n + soft_n < k {
        return Err(Error::Msg(format!(
            "soft mend: need {k} shards with some data, have {}",
            hard_n + soft_n
        )));
    }

    let parity = n.saturating_sub(k);
    let mut soft_idx: Vec<usize> = parts.iter().filter(|p| !p.hard).map(|p| p.index).collect();
    soft_idx.sort_unstable();

    // 2) GMD shard-level: erase tau lowest-index soft shards, use the rest
    let max_tau = parity.min(soft_idx.len());
    for tau in 0..=max_tau {
        let erased: std::collections::BTreeSet<usize> =
            soft_idx.iter().take(tau).copied().collect();
        let use_parts: Vec<SoftPart> = parts
            .iter()
            .filter(|p| p.hard || !erased.contains(&p.index))
            .cloned()
            .collect();
        if use_parts.len() < k {
            continue;
        }
        if let Ok(payload) = decode_graded_with_mask(&use_parts, k, payload_len, systematic, &[]) {
            if accept(&payload) {
                return Ok(payload);
            }
        }
    }

    // 3) Stripe GMD-lite: flip ≤ parity lowest-reliability soft stripes
    let n_stripes = soft_stripe_count(parts);
    if n_stripes == 0 || soft_idx.is_empty() || parity == 0 {
        return Err(Error::Msg(
            "soft mend could not reconstruct a true-name match".into(),
        ));
    }
    let mut soft_stripes: Vec<(usize, usize)> = Vec::new();
    for &si in &soft_idx {
        for st in 0..n_stripes {
            soft_stripes.push((si, st));
        }
    }
    // Lowest reliability first: already ordered by shard index then stripe.
    let max_flip = parity.min(soft_stripes.len());
    for flip in 1..=max_flip {
        // Erase the `flip` lowest-reliability soft stripes.
        let mask = &soft_stripes[..flip];
        // Also try alongside excluding no whole extra shards (mask only).
        if let Ok(payload) = decode_graded_with_mask(parts, k, payload_len, systematic, mask) {
            if accept(&payload) {
                return Ok(payload);
            }
        }
    }

    // Bounded combo: erase one soft shard entirely + one extra stripe from another
    if soft_idx.len() >= 2 && parity >= 2 {
        for (a_i, &a) in soft_idx.iter().enumerate() {
            for &b in soft_idx.iter().skip(a_i + 1) {
                for st in 0..n_stripes {
                    let use_parts: Vec<SoftPart> =
                        parts.iter().filter(|p| p.index != a).cloned().collect();
                    if use_parts.len() < k {
                        continue;
                    }
                    let mask = [(b, st)];
                    if let Ok(payload) =
                        decode_graded_with_mask(&use_parts, k, payload_len, systematic, &mask)
                    {
                        if accept(&payload) {
                            return Ok(payload);
                        }
                    }
                }
            }
        }
    }

    Err(Error::Msg(
        "soft mend could not reconstruct a true-name match".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn invert_once_matches_column() {
        let payload: Vec<u8> = (0..200).map(|i| (i * 7) as u8).collect();
        let shards = encode_shards(&payload, 8, 16);
        assert_eq!(shards[0], {
            let sl = shards[0].len();
            let mut padded = vec![0u8; sl * 8];
            padded[..payload.len()].copy_from_slice(&payload);
            padded[..sl].to_vec()
        });
        let mut opt: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        for i in 0..8 {
            opt[i] = None;
        }
        let out = decode_shards(&opt, 8, payload.len(), true).unwrap();
        assert_eq!(out, payload);
        let v1 = encode_shards_v1(&payload, 8, 16);
        let mut o1: Vec<Option<Vec<u8>>> = v1.into_iter().map(Some).collect();
        for i in 0..8 {
            o1[i] = None;
        }
        assert_eq!(
            decode_shards(&o1, 8, payload.len(), false).unwrap(),
            payload
        );
    }

    #[test]
    fn soft_recovers_crc_trailer_corruption() {
        let payload: Vec<u8> = (0..5000).map(|i| (i * 13) as u8).collect();
        let shards = encode_shards(&payload, 8, 16);
        let parts: Vec<SoftPart> = shards
            .iter()
            .enumerate()
            .map(|(i, b)| SoftPart {
                index: i,
                body: b.clone(),
                hard: true,
            })
            .collect();
        // 8 missing, 7 hard + 1 soft (intact body) → soft salvage
        let parts: Vec<SoftPart> = parts
            .into_iter()
            .enumerate()
            .filter_map(|(i, mut p)| {
                if i < 8 {
                    None
                } else if i == 8 {
                    p.hard = false;
                    Some(p)
                } else {
                    Some(p)
                }
            })
            .collect();
        assert_eq!(parts.iter().filter(|p| p.hard).count(), 7);
        assert_eq!(parts.iter().filter(|p| !p.hard).count(), 1);
        let expect = payload.clone();
        let out = decode_soft(&parts, 8, 16, payload.len(), true, |got| got == expect).unwrap();
        assert_eq!(out, payload);
    }

    #[test]
    fn soft_gmd_drops_bad_soft_shard() {
        let payload: Vec<u8> = (0..3000).map(|i| (i * 3) as u8).collect();
        let shards = encode_shards(&payload, 8, 16);
        let mut parts: Vec<SoftPart> = Vec::new();
        for i in 0..7 {
            parts.push(SoftPart {
                index: i,
                body: shards[i].clone(),
                hard: true,
            });
        }
        parts.push(SoftPart {
            index: 7,
            body: shards[7].clone(),
            hard: false,
        });
        let mut bad = shards[8].clone();
        bad[0] ^= 0xff;
        bad[100] ^= 0x55;
        parts.push(SoftPart {
            index: 8,
            body: bad,
            hard: false,
        });
        let expect = payload.clone();
        let out = decode_soft(&parts, 8, 16, payload.len(), true, |got| got == expect).unwrap();
        assert_eq!(out, payload);
    }

    // ---- Property tests: fast matrix/SIMD path vs. frozen per-column oracle ----

    use crate::rs_ref;

    struct Rng(u64);
    impl Rng {
        fn next(&mut self) -> u64 {
            self.0 ^= self.0 << 13;
            self.0 ^= self.0 >> 7;
            self.0 ^= self.0 << 17;
            self.0
        }
        fn below(&mut self, n: usize) -> usize {
            (self.next() % n as u64) as usize
        }
        fn bytes(&mut self, n: usize) -> Vec<u8> {
            (0..n).map(|_| self.next() as u8).collect()
        }
    }

    fn random_shape(r: &mut Rng) -> (usize, usize, usize) {
        let k = 1 + r.below(40);
        let n = k + r.below(41.min(256 - k));
        let len = match r.below(4) {
            0 => r.below(8),
            1 => r.below(200),
            _ => r.below(20_000),
        };
        (k, n, len)
    }

    #[test]
    fn prop_encode_matches_oracle() {
        let mut r = Rng(0x0005_1611);
        for _ in 0..300 {
            let (k, n, len) = random_shape(&mut r);
            let p = r.bytes(len);
            assert_eq!(
                encode_shards(&p, k, n),
                rs_ref::encode_shards(&p, k, n),
                "v2 k={k} n={n} len={len}"
            );
            assert_eq!(
                encode_shards_v1(&p, k, n),
                rs_ref::encode_shards_v1(&p, k, n),
                "v1 k={k} n={n} len={len}"
            );
            let idx = r.below(n);
            for sys in [true, false] {
                assert_eq!(
                    encode_shard_index(&p, k, idx, sys),
                    rs_ref::encode_shard_index(&p, k, idx, sys)
                );
            }
        }
    }

    #[test]
    fn prop_encode_matches_oracle_large_k() {
        let mut r = Rng(77);
        for &(k, n) in &[
            (127usize, 254usize),
            (189, 252),
            (200, 255),
            (12, 16),
            (15, 20),
        ] {
            let extra = r.below(k);
            let p = r.bytes(k * 37 + extra);
            assert_eq!(
                encode_shards(&p, k, n),
                rs_ref::encode_shards(&p, k, n),
                "k={k} n={n}"
            );
        }
    }

    #[test]
    fn prop_decode_matches_oracle_random_erasures() {
        let mut r = Rng(0xdec0de);
        for _ in 0..300 {
            let (k, n, len) = random_shape(&mut r);
            let p = r.bytes(len);
            for sys in [true, false] {
                let shards = if sys {
                    encode_shards(&p, k, n)
                } else {
                    encode_shards_v1(&p, k, n)
                };
                // random subset, random order, sometimes duplicates or extras
                let mut idx: Vec<usize> = (0..n).collect();
                for i in (1..idx.len()).rev() {
                    idx.swap(i, r.below(i + 1));
                }
                let keep = k + r.below(n - k + 1);
                let mut parts: Vec<(usize, Vec<u8>)> = idx[..keep]
                    .iter()
                    .map(|&i| (i, shards[i].clone()))
                    .collect();
                if r.below(4) == 0 && !parts.is_empty() {
                    let d = parts[0].clone();
                    parts.insert(r.below(parts.len()), d);
                }
                let fast = decode_indexed(&parts, k, len, sys).unwrap();
                let slow = rs_ref::decode_indexed(&parts, k, len, sys).unwrap();
                assert_eq!(fast, slow, "k={k} n={n} len={len} sys={sys}");
                assert_eq!(fast, p);
            }
        }
    }

    #[test]
    fn prop_decode_garbage_matches_oracle() {
        // Corrupt / short / long bodies: the fast path must compute the same
        // (wrong) bytes as before so higher layers (Merkle, true-name) still reject.
        let mut r = Rng(0xbad);
        for _ in 0..200 {
            let (k, n, len) = random_shape(&mut r);
            let p = r.bytes(len);
            let shards = encode_shards(&p, k, n);
            let mut parts: Vec<(usize, Vec<u8>)> = (0..n)
                .rev()
                .take(k)
                .map(|i| (i, shards[i].clone()))
                .collect();
            let j = r.below(parts.len());
            match r.below(3) {
                0 if !parts[j].1.is_empty() => {
                    let b = r.below(parts[j].1.len());
                    parts[j].1[b] ^= 1 << r.below(8);
                }
                1 => {
                    let l = parts[j].1.len();
                    parts[j].1.truncate(r.below(l + 1));
                }
                _ => parts[j].1.extend(r.bytes(5)),
            }
            assert_eq!(
                decode_indexed(&parts, k, len, true).unwrap(),
                rs_ref::decode_indexed(&parts, k, len, true).unwrap(),
                "k={k} n={n} len={len}"
            );
        }
    }

    #[test]
    #[allow(clippy::needless_range_loop)]
    fn prop_graded_matches_oracle() {
        let mut r = Rng(0x50f7);
        for _ in 0..60 {
            let k = 1 + r.below(12);
            let n = k + 1 + r.below(8);
            let len = r.below(3 * SOFT_STRIPE * k);
            let p = r.bytes(len);
            let shards = encode_shards(&p, k, n);
            let mut parts: Vec<SoftPart> = Vec::new();
            for i in 0..n {
                if r.below(5) == 0 {
                    continue;
                }
                let mut body = shards[i].clone();
                let hard = r.below(2) == 0;
                if !hard && !body.is_empty() && r.below(2) == 0 {
                    let b = r.below(body.len());
                    body[b] ^= 0x41;
                }
                parts.push(SoftPart {
                    index: i,
                    body,
                    hard,
                });
            }
            let stripes = shard_len_of(&parts).div_ceil(SOFT_STRIPE).max(1);
            let mut mask = Vec::new();
            for p in &parts {
                if !p.hard && r.below(2) == 0 {
                    mask.push((p.index, r.below(stripes)));
                }
            }
            for sys in [true, false] {
                let fast = decode_graded_with_mask(&parts, k, len, sys, &mask);
                let slow = rs_ref::decode_graded_with_mask(&parts, k, len, sys, &mask);
                match (fast, slow) {
                    (Ok(a), Ok(b)) => assert_eq!(a, b, "k={k} n={n} len={len}"),
                    (Err(_), Err(_)) => {}
                    (a, b) => panic!("divergence: fast={:?} slow={:?}", a.is_ok(), b.is_ok()),
                }
            }
        }
    }

    #[test]
    fn decode_too_few_fails() {
        let p = vec![9u8; 1000];
        let shards = encode_shards(&p, 8, 12);
        let parts: Vec<(usize, Vec<u8>)> = (0..7).map(|i| (i + 5, shards[i + 5].clone())).collect();
        assert!(decode_indexed(&parts, 8, 1000, true).is_err());
        let dup: Vec<(usize, Vec<u8>)> = (0..8).map(|_| (9, shards[9].clone())).collect();
        assert!(decode_indexed(&dup, 8, 1000, true).is_err());
    }
}
