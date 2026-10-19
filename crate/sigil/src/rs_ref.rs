//! FROZEN reference implementation of `rs` (the pre-speedup scalar code, per-column
//! Vandermonde solve). Kept verbatim as a test oracle and benchmark baseline:
//! the fast `rs` must produce byte-identical output. Do not optimise this file.
#![allow(dead_code, clippy::needless_range_loop)]

use crate::gf;
use crate::Error;

fn vandermonde_inverse(xs: &[u8]) -> Result<Vec<Vec<u8>>, Error> {
    let k = xs.len();
    let mut m = vec![vec![0u8; k]; k];
    for col in 0..k {
        let mut e = vec![0u8; k];
        e[col] = 1;
        let c = gf::solve_vandermonde(xs, &e);
        for row in 0..k {
            m[row][col] = c[row];
        }
    }
    Ok(m)
}

fn apply_inv(inv: &[Vec<u8>], ys: &[u8]) -> Vec<u8> {
    let k = inv.len();
    let mut out = vec![0u8; k];
    for row in 0..k {
        let mut acc = 0u8;
        for col in 0..k {
            acc ^= gf::mul(inv[row][col], ys[col]);
        }
        out[row] = acc;
    }
    out
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

pub fn encode_shards_ex(payload: &[u8], k: usize, n: usize, systematic: bool) -> Vec<Vec<u8>> {
    let shard_len = (payload.len().div_ceil(k)).max(1);
    let mut padded = vec![0u8; shard_len * k];
    padded[..payload.len()].copy_from_slice(payload);
    let mut shards = vec![vec![0u8; shard_len]; n];
    let mut col = vec![0u8; k];
    for s in 0..shard_len {
        for i in 0..k {
            col[i] = padded[i * shard_len + s];
        }
        if systematic {
            let xs: Vec<u8> = (0..k).map(|i| (i + 1) as u8).collect();
            let coeffs = gf::solve_vandermonde(&xs, &col);
            for i in 0..k {
                shards[i][s] = col[i];
            }
            for i in k..n {
                shards[i][s] = gf::eval_poly(&coeffs, (i + 1) as u8);
            }
        } else {
            for i in 0..n {
                shards[i][s] = gf::eval_poly(&col, (i + 1) as u8);
            }
        }
    }
    shards
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
    encode_shard_index_ex(payload, k, index, systematic)
}

fn encode_shard_index_ex(payload: &[u8], k: usize, index: usize, systematic: bool) -> Vec<u8> {
    let shard_len = (payload.len().div_ceil(k)).max(1);
    let mut padded = vec![0u8; shard_len * k];
    padded[..payload.len()].copy_from_slice(payload);
    if systematic && index < k {
        return padded[index * shard_len..(index + 1) * shard_len].to_vec();
    }
    let x = (index + 1) as u8;
    let mut shard = vec![0u8; shard_len];
    let mut col = vec![0u8; k];
    let xs: Vec<u8> = (0..k).map(|i| (i + 1) as u8).collect();
    for s in 0..shard_len {
        for i in 0..k {
            col[i] = padded[i * shard_len + s];
        }
        if systematic {
            let coeffs = gf::solve_vandermonde(&xs, &col);
            shard[s] = gf::eval_poly(&coeffs, x);
        } else {
            shard[s] = gf::eval_poly(&col, x);
        }
    }
    shard
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
                data_ok[*index] = Some(body.clone());
            }
        }
        if let Some(data) = data_ok
            .iter()
            .map(|s| s.as_ref())
            .collect::<Option<Vec<_>>>()
        {
            let mut padded = vec![0u8; shard_len * k];
            for (i, s) in data.into_iter().enumerate() {
                let n = s.len().min(shard_len);
                padded[i * shard_len..i * shard_len + n].copy_from_slice(&s[..n]);
            }
            padded.truncate(payload_len);
            return Ok(padded);
        }
    }
    let mut xs = Vec::with_capacity(k);
    let mut live_idx = Vec::with_capacity(k);
    for (j, (index, _)) in parts.iter().enumerate() {
        if xs.len() == k {
            break;
        }
        if *index > 254 {
            continue;
        }
        let x = (*index + 1) as u8;
        if xs.contains(&x) {
            continue;
        }
        xs.push(x);
        live_idx.push(j);
    }
    if xs.len() < k {
        return Err(Error::Msg(format!("need {k} distinct pieces")));
    }
    let inv = vandermonde_inverse(&xs)?;
    let mut padded = vec![0u8; shard_len * k];
    let mut ys = vec![0u8; k];
    for s in 0..shard_len {
        for (j, &pj) in live_idx.iter().enumerate() {
            ys[j] = parts[pj].1.get(s).copied().unwrap_or(0);
        }
        let coeffs = apply_inv(&inv, &ys);
        if systematic {
            for i in 0..k {
                padded[i * shard_len + s] = gf::eval_poly(&coeffs, (i + 1) as u8);
            }
        } else {
            for i in 0..k {
                padded[i * shard_len + s] = coeffs[i];
            }
        }
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
    let mut out = Vec::new();
    for s in shards {
        let Some(s) = s else {
            return Err(Error::Msg("glyph: missing shard".into()));
        };
        out.extend_from_slice(s);
    }
    out.truncate(payload_len);
    Ok(out)
}

/// Soft-RS stripe width within a shard payload (v0).
pub const SOFT_STRIPE: usize = 4096;

pub use crate::rs::SoftPart;

fn shard_len_of(parts: &[SoftPart]) -> usize {
    parts.iter().map(|p| p.body.len()).max().unwrap_or(0)
}

/// Decode one column from selected parts (erasure-only).
fn decode_column_parts(
    parts: &[(usize, u8)],
    k: usize,
    systematic: bool,
) -> Result<Vec<u8>, Error> {
    if parts.len() < k {
        return Err(Error::Msg(format!("need {k} live symbols")));
    }
    let mut xs = Vec::with_capacity(k);
    let mut ys = Vec::with_capacity(k);
    for &(index, sym) in parts {
        if xs.len() == k {
            break;
        }
        if index > 254 {
            continue;
        }
        let x = (index + 1) as u8;
        if xs.contains(&x) {
            continue;
        }
        xs.push(x);
        ys.push(sym);
    }
    if xs.len() < k {
        return Err(Error::Msg(format!("need {k} distinct symbols")));
    }
    let coeffs = gf::solve_vandermonde(&xs, &ys);
    if systematic {
        Ok((0..k)
            .map(|i| gf::eval_poly(&coeffs, (i + 1) as u8))
            .collect())
    } else {
        Ok(coeffs)
    }
}

/// Stripe-aware graded decode: hard symbols preferred; soft fill gaps.
/// `erased_soft_stripes` lists (shard_index, stripe_idx) forced to erasure.
pub fn decode_graded_with_mask(
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

    let mut padded = vec![0u8; shard_len * k];
    for s in 0..shard_len {
        let stripe = s / SOFT_STRIPE;
        let mut hard_syms: Vec<(usize, u8)> = Vec::new();
        let mut soft_syms: Vec<(usize, u8)> = Vec::new();
        for p in parts {
            let erased = !p.hard
                && erased_soft_stripes
                    .iter()
                    .any(|&(si, st)| si == p.index && st == stripe);
            if erased {
                continue;
            }
            let sym = p.body.get(s).copied().unwrap_or(0);
            if p.hard {
                hard_syms.push((p.index, sym));
            } else {
                soft_syms.push((p.index, sym));
            }
        }
        let mut chosen = hard_syms;
        if chosen.len() < k {
            for sym in soft_syms {
                if chosen.len() >= k {
                    break;
                }
                if chosen.iter().any(|(i, _)| *i == sym.0) {
                    continue;
                }
                chosen.push(sym);
            }
        }
        let col = decode_column_parts(&chosen, k, systematic)?;
        for i in 0..k {
            padded[i * shard_len + s] = col[i];
        }
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
