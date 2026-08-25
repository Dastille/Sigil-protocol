//! v1: polynomial coefficients = data (evaluation code).
//! v2: first k shards ARE the data (systematic); parity is extra evaluations.

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

fn encode_shards_ex(payload: &[u8], k: usize, n: usize, systematic: bool) -> Vec<Vec<u8>> {
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
        if data_ok.iter().all(|s| s.is_some()) {
            let mut padded = vec![0u8; shard_len * k];
            for i in 0..k {
                let s = data_ok[i].as_ref().unwrap();
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
        assert_eq!(decode_shards(&o1, 8, payload.len(), false).unwrap(), payload);
    }
}
