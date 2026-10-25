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
///
/// A Vandermonde matrix over GF(256) is invertible iff its points are pairwise distinct.
/// Decoders pass points from `pick_live`, which dedups and drops indexes > 254; encoders
/// pass `x_of(0..k)`, distinct for k <= 255. Repeated points (or k > 255, where `x_of`
/// wraps) are refused with an error instead of a panic.
fn vandermonde_inverse(xs: &[u8]) -> Result<Vec<u8>, Error> {
    let k = xs.len();
    gf::invert_matrix(k, &power_matrix(xs, k)).ok_or_else(|| {
        Error::Msg(format!(
            "Reed-Solomon: evaluation points are not distinct (k = {k}); refusing a singular matrix"
        ))
    })
}

/// Matrix mapping k data shards → shard `rows` evaluations.
/// systematic: E(rows) · V(1..k)^-1 ; v1: E(rows).
fn encode_matrix(k: usize, rows: &[usize], systematic: bool) -> Result<Vec<u8>, Error> {
    let xr: Vec<u8> = rows.iter().map(|&i| x_of(i)).collect();
    let e = power_matrix(&xr, k);
    if systematic {
        let xs: Vec<u8> = (0..k).map(x_of).collect();
        Ok(gf::matmul(&e, &vandermonde_inverse(&xs)?, rows.len(), k, k))
    } else {
        Ok(e)
    }
}

/// Matrix mapping k received symbols at `xs` → k data symbols.
fn decode_matrix(xs: &[u8], systematic: bool) -> Result<Vec<u8>, Error> {
    let k = xs.len();
    let vinv = vandermonde_inverse(xs)?;
    if systematic {
        let data_xs: Vec<u8> = (0..k).map(x_of).collect();
        Ok(gf::matmul(&power_matrix(&data_xs, k), &vinv, k, k, k))
    } else {
        Ok(vinv)
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

pub fn encode_shards(payload: &[u8], k: usize, n: usize) -> Result<Vec<Vec<u8>>, Error> {
    encode_shards_ex(payload, k, n, true)
}

/// v1 evaluation code (coefficients = data). Old files are decoded by the
/// shared decoder; this encoder is only needed to produce v1 fixtures in tests.
#[cfg(test)]
pub fn encode_shards_v1(payload: &[u8], k: usize, n: usize) -> Result<Vec<Vec<u8>>, Error> {
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

fn encode_shards_ex(
    payload: &[u8],
    k: usize,
    n: usize,
    systematic: bool,
) -> Result<Vec<Vec<u8>>, Error> {
    let (shard_len, data) = split_padded(payload, k);
    let rows: Vec<usize> = if systematic {
        (k..n).collect()
    } else {
        (0..n).collect()
    };
    let m = encode_matrix(k, &rows, systematic)?;
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
        Ok(shards)
    } else {
        Ok(computed)
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

pub fn encode_shard_index(
    payload: &[u8],
    k: usize,
    index: usize,
    systematic: bool,
) -> Result<Vec<u8>, Error> {
    let (shard_len, data) = split_padded(payload, k);
    if systematic && index < k {
        return Ok(data[index].clone());
    }
    let m = encode_matrix(k, &[index], systematic)?;
    let ins: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
    let mut shard = vec![0u8; shard_len];
    gf::matrix_apply(&m, &ins, &mut [shard.as_mut_slice()]);
    Ok(shard)
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
        if let Some(data) = data_ok.iter().copied().collect::<Option<Vec<_>>>() {
            let mut padded = vec![0u8; shard_len * k];
            for (i, s) in data.into_iter().enumerate() {
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
    let m = decode_matrix(&xs, systematic)?;
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
    for s in shards.iter().flatten() {
        out.extend_from_slice(s);
    }
    out.truncate(payload_len);
    Ok(out)
}

// ---------------------------------------------------------------------------
// Column error correction (errors-and-erasures), decoder side only.
//
// Every byte column j (byte j of each shard) is one Reed–Solomon codeword:
// the evaluations at x = index + 1 of a polynomial of degree < k (v1 and v2
// differ only in how the payload maps to that polynomial). Classic decode treats
// a shard as either intact or erased. Here each column is decoded on its own,
// so one flipped bit damages one symbol of one column instead of a whole shard.
// With p shards present a column can absorb up to (p - k) / 2 unknown symbol
// errors; missing shards are erasures. Nothing on disk changes.

/// What [`decode_column_errors`] had to fix.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub struct ColumnRepair {
    /// Byte columns whose symbols were not one consistent codeword.
    pub dirty_columns: usize,
    /// Shard bytes changed to make every column a codeword again.
    pub corrected_symbols: usize,
    /// Most unknown errors each column could absorb: (present - k) / 2.
    pub per_column_budget: usize,
}

/// Solve `a · v = rhs` over GF(256) (`a` is `rows × cols`, row-major). Free
/// variables are set to 0. `None` if the system is inconsistent.
fn solve_any(rows: usize, cols: usize, a: &mut [u8], rhs: &mut [u8]) -> Option<Vec<u8>> {
    let mut pivots: Vec<usize> = Vec::with_capacity(cols);
    let mut r = 0usize;
    for c in 0..cols {
        if r == rows {
            break;
        }
        let Some(p) = (r..rows).find(|&i| a[i * cols + c] != 0) else {
            continue;
        };
        if p != r {
            for t in 0..cols {
                a.swap(r * cols + t, p * cols + t);
            }
            rhs.swap(r, p);
        }
        let invp = gf::inv(a[r * cols + c]);
        for t in 0..cols {
            a[r * cols + t] = gf::mul(a[r * cols + t], invp);
        }
        rhs[r] = gf::mul(rhs[r], invp);
        for i in 0..rows {
            let f = a[i * cols + c];
            if i == r || f == 0 {
                continue;
            }
            for t in 0..cols {
                a[i * cols + t] ^= gf::mul(f, a[r * cols + t]);
            }
            rhs[i] ^= gf::mul(f, rhs[r]);
        }
        pivots.push(c);
        r += 1;
    }
    if rhs[r..rows].iter().any(|&v| v != 0) {
        return None;
    }
    let mut v = vec![0u8; cols];
    for (row, &c) in pivots.iter().enumerate() {
        v[c] = rhs[row];
    }
    Some(v)
}

/// Berlekamp–Welch for one column: the polynomial of degree < k (coefficients,
/// low first) within `e` symbol errors of `(xs, ys)`, if one exists.
/// Needs `xs.len() >= k + 2e` and distinct non-zero points.
fn berlekamp_welch(xs: &[u8], ys: &[u8], k: usize, e: usize) -> Option<Vec<u8>> {
    let p = xs.len();
    if k == 0 || p < k + 2 * e {
        return None;
    }
    let qn = k + e; // Q has degree < k + e
    let cols = qn + e; // plus E's e low coefficients (E is monic of degree e)
    let mut a = vec![0u8; p * cols];
    let mut rhs = vec![0u8; p];
    for i in 0..p {
        let (x, y) = (xs[i], ys[i]);
        // Q(x) + y·(E_low(x)) = y·x^e  (characteristic 2: minus is plus)
        let mut pw = 1u8;
        for j in 0..qn {
            a[i * cols + j] = pw;
            if j < e {
                a[i * cols + qn + j] = gf::mul(y, pw);
            }
            if j == e {
                rhs[i] = gf::mul(y, pw);
            }
            pw = gf::mul(pw, x);
        }
    }
    let v = solve_any(p, cols, &mut a, &mut rhs)?;
    // Long division Q / E, E = x^e + sum e_l x^l.
    let mut q = v[..qn].to_vec();
    let mut el = v[qn..].to_vec();
    el.push(1);
    let mut quot = vec![0u8; k];
    for d in (e..qn).rev() {
        let c = q[d];
        if c == 0 {
            continue;
        }
        quot[d - e] = c;
        for (l, &ec) in el.iter().enumerate() {
            q[d - e + l] ^= gf::mul(c, ec);
        }
    }
    if q[..e].iter().any(|&r| r != 0) {
        return None;
    }
    Some(quot)
}

/// Errors-and-erasures decode, one byte column at a time.
///
/// `parts` are the shard bodies that are present (CRC-good or not), tagged with
/// their index. Bodies of the wrong length, indexes above 254 and repeated
/// indexes are ignored (treated as erasures). Columns that are already a
/// codeword cost one matrix pass; each other column is decoded with
/// Berlekamp–Welch and corrected only if at most `(present - k) / 2` of its
/// symbols disagree with the decoded polynomial. Any column beyond that budget
/// makes the whole call fail: there is no partial result.
///
/// The returned payload is **not** verified here. A column with more errors
/// than the budget can decode to a different codeword, so callers must accept
/// it only after the Merkle binding (and true name, when not encrypted) match,
/// exactly like [`decode_soft`].
pub fn decode_column_errors(
    parts: &[(usize, Vec<u8>)],
    k: usize,
    shard_len: usize,
    payload_len: usize,
    systematic: bool,
) -> Result<(Vec<u8>, ColumnRepair), Error> {
    if k == 0 || shard_len == 0 {
        return Err(Error::Msg("column repair: empty geometry".into()));
    }
    let mut seen = [false; 255];
    let mut live: Vec<(usize, Vec<u8>)> = Vec::new();
    for (i, b) in parts {
        if *i > 254 || b.len() != shard_len || seen[*i] {
            continue;
        }
        seen[*i] = true;
        live.push((*i, b.clone()));
    }
    live.sort_by_key(|p| p.0);
    let p = live.len();
    if p < k {
        return Err(Error::Msg(format!(
            "column repair needs {k} shards with data, have {p}"
        )));
    }
    let budget = (p - k) / 2;
    let xs: Vec<u8> = live.iter().map(|(i, _)| x_of(*i)).collect();
    let mut rep = ColumnRepair {
        per_column_budget: budget,
        ..ColumnRepair::default()
    };
    if p > k {
        // Predict the other p - k shards from the first k; a column is clean
        // when every prediction matches what was read.
        let others: Vec<u8> = xs[k..].to_vec();
        let m = gf::matmul(
            &power_matrix(&others, k),
            &vandermonde_inverse(&xs[..k])?,
            others.len(),
            k,
            k,
        );
        let ins: Vec<&[u8]> = live[..k].iter().map(|(_, b)| b.as_slice()).collect();
        let mut pred = vec![vec![0u8; shard_len]; p - k];
        {
            let mut outs: Vec<&mut [u8]> = pred.iter_mut().map(|v| v.as_mut_slice()).collect();
            gf::matrix_apply(&m, &ins, &mut outs);
        }
        let dirty: Vec<usize> = (0..shard_len)
            .filter(|&j| (0..p - k).any(|o| pred[o][j] != live[k + o].1[j]))
            .collect();
        drop(pred);
        rep.dirty_columns = dirty.len();
        if !dirty.is_empty() && budget == 0 {
            return Err(Error::Msg(format!(
                "column repair: {} damaged columns but only {p} of the shards (need {}) are present to locate errors",
                dirty.len(),
                k + 2
            )));
        }
        let mut ys = vec![0u8; p];
        for &j in &dirty {
            for (t, (_, b)) in live.iter().enumerate() {
                ys[t] = b[j];
            }
            let poly = berlekamp_welch(&xs, &ys, k, budget).ok_or_else(|| {
                Error::Msg(format!(
                    "column repair: byte column {j} has more than {budget} damaged symbols"
                ))
            })?;
            let fixed: Vec<u8> = xs.iter().map(|&x| gf::eval_poly(&poly, x)).collect();
            let wrong = fixed.iter().zip(&ys).filter(|(a, b)| a != b).count();
            if wrong > budget {
                return Err(Error::Msg(format!(
                    "column repair: byte column {j} has more than {budget} damaged symbols"
                )));
            }
            for (t, v) in fixed.into_iter().enumerate() {
                live[t].1[j] = v;
            }
            rep.corrected_symbols += wrong;
        }
    }
    let payload = decode_indexed(&live, k, payload_len, systematic)?;
    Ok((payload, rep))
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
        let m = match cache.entry(xs.clone()) {
            std::collections::hash_map::Entry::Occupied(e) => e.into_mut(),
            std::collections::hash_map::Entry::Vacant(e) => {
                e.insert(decode_matrix(&xs, systematic)?)
            }
        };
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
        let shards = encode_shards(&payload, 8, 16).unwrap();
        assert_eq!(shards[0], {
            let sl = shards[0].len();
            let mut padded = vec![0u8; sl * 8];
            padded[..payload.len()].copy_from_slice(&payload);
            padded[..sl].to_vec()
        });
        let mut opt: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
        for slot in opt.iter_mut().take(8) {
            *slot = None;
        }
        let out = decode_shards(&opt, 8, payload.len(), true).unwrap();
        assert_eq!(out, payload);
        let v1 = encode_shards_v1(&payload, 8, 16).unwrap();
        let mut o1: Vec<Option<Vec<u8>>> = v1.into_iter().map(Some).collect();
        for slot in o1.iter_mut().take(8) {
            *slot = None;
        }
        assert_eq!(
            decode_shards(&o1, 8, payload.len(), false).unwrap(),
            payload
        );
    }

    #[test]
    fn soft_recovers_crc_trailer_corruption() {
        let payload: Vec<u8> = (0..5000).map(|i| (i * 13) as u8).collect();
        let shards = encode_shards(&payload, 8, 16).unwrap();
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
        let shards = encode_shards(&payload, 8, 16).unwrap();
        let mut parts: Vec<SoftPart> = Vec::new();
        for (i, shard) in shards.iter().enumerate().take(7) {
            parts.push(SoftPart {
                index: i,
                body: shard.clone(),
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
                encode_shards(&p, k, n).unwrap(),
                rs_ref::encode_shards(&p, k, n),
                "v2 k={k} n={n} len={len}"
            );
            assert_eq!(
                encode_shards_v1(&p, k, n).unwrap(),
                rs_ref::encode_shards_v1(&p, k, n),
                "v1 k={k} n={n} len={len}"
            );
            let idx = r.below(n);
            for sys in [true, false] {
                assert_eq!(
                    encode_shard_index(&p, k, idx, sys).unwrap(),
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
                encode_shards(&p, k, n).unwrap(),
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
                    encode_shards(&p, k, n).unwrap()
                } else {
                    encode_shards_v1(&p, k, n).unwrap()
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
            let shards = encode_shards(&p, k, n).unwrap();
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
            let shards = encode_shards(&p, k, n).unwrap();
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
        let shards = encode_shards(&p, 8, 12).unwrap();
        let parts: Vec<(usize, Vec<u8>)> = (0..7).map(|i| (i + 5, shards[i + 5].clone())).collect();
        assert!(decode_indexed(&parts, 8, 1000, true).is_err());
        let dup: Vec<(usize, Vec<u8>)> = (0..8).map(|_| (9, shards[9].clone())).collect();
        assert!(decode_indexed(&dup, 8, 1000, true).is_err());
    }

    /// Repeated evaluation points make the Vandermonde matrix singular. This used to be an
    /// `expect("singular")` panic; it must now be a clean error on every path that reaches it.
    #[test]
    fn singular_points_are_an_error_not_a_panic() {
        assert!(vandermonde_inverse(&[3, 3]).is_err());
        assert!(decode_matrix(&[7, 9, 7], true).is_err());
        // k = 257 makes `x_of` wrap (index 256 → 1 again), so the data points repeat.
        let payload = vec![0x5au8; 1024];
        assert!(encode_shards(&payload, 257, 260).is_err());
        assert!(encode_shard_index(&payload, 257, 258, true).is_err());
        // Distinct points still invert, and k = 255 (the header maximum) still encodes.
        assert!(vandermonde_inverse(&[1, 2, 3]).is_ok());
        assert_eq!(encode_shards(&payload, 255, 256).unwrap().len(), 256);
    }

    // ---- Column error correction (errors-and-erasures) ----

    #[test]
    fn column_errors_fix_scattered_symbols_and_erasures() {
        let mut r = Rng(0x0dee_95ac);
        for &(k, n) in &[(12usize, 16usize), (8, 16), (3, 7), (20, 30), (1, 5)] {
            for sys in [true, false] {
                for _ in 0..6 {
                    let len = 1 + r.below(30_000);
                    let p = r.bytes(len);
                    let shards = if sys {
                        encode_shards(&p, k, n).unwrap()
                    } else {
                        encode_shards_v1(&p, k, n).unwrap()
                    };
                    let sl = shards[0].len();
                    // f whole shards missing, then up to (n - f - k) / 2 bad symbols per column.
                    let f = r.below(n - k + 1);
                    let mut parts: Vec<(usize, Vec<u8>)> =
                        shards.iter().cloned().enumerate().skip(f).collect();
                    let budget = (parts.len() - k) / 2;
                    let mut flipped = 0usize;
                    if budget > 0 {
                        let mut used = std::collections::BTreeSet::new();
                        for _ in 0..1 + r.below(200) {
                            let j = r.below(sl);
                            if !used.insert(j) {
                                continue; // one damage pattern per column
                            }
                            let mut rows: Vec<usize> = (0..parts.len()).collect();
                            for i in (1..rows.len()).rev() {
                                rows.swap(i, r.below(i + 1));
                            }
                            for &t in rows.iter().take(1 + r.below(budget)) {
                                if parts[t].1[j] == shards[parts[t].0][j] {
                                    flipped += 1;
                                }
                                parts[t].1[j] = shards[parts[t].0][j] ^ (1 + r.below(255) as u8);
                            }
                        }
                    }
                    let (got, rep) = decode_column_errors(&parts, k, sl, len, sys).unwrap();
                    assert_eq!(got, p, "k={k} n={n} f={f} sys={sys}");
                    assert_eq!(rep.corrected_symbols, flipped);
                    assert_eq!(rep.per_column_budget, budget);
                }
            }
        }
    }

    #[test]
    fn column_errors_clean_input_matches_erasure_decode() {
        let mut r = Rng(0xc1ea);
        let p = r.bytes(10_000);
        let shards = encode_shards(&p, 12, 16).unwrap();
        let parts: Vec<(usize, Vec<u8>)> = shards.iter().cloned().enumerate().collect();
        let (got, rep) = decode_column_errors(&parts, 12, shards[0].len(), p.len(), true).unwrap();
        assert_eq!(got, p);
        assert_eq!(rep.dirty_columns, 0);
        assert_eq!(rep.corrected_symbols, 0);
    }

    #[test]
    fn column_errors_beyond_budget_never_return_the_original_unchecked() {
        // 3 bad symbols in one column of a (12,16) code: budget is 2. The call
        // must either refuse or return bytes the caller's Merkle check rejects;
        // it must never claim a repair that equals the original by luck of the
        // test (it cannot: the original is 3 symbols away).
        let mut r = Rng(0xbeef);
        let mut refused = 0;
        for _ in 0..50 {
            let p = r.bytes(5_000);
            let shards = encode_shards(&p, 12, 16).unwrap();
            let sl = shards[0].len();
            let mut parts: Vec<(usize, Vec<u8>)> = shards.iter().cloned().enumerate().collect();
            let j = r.below(sl);
            for t in [1usize, 6, 14] {
                parts[t].1[j] ^= 1 + r.below(255) as u8;
            }
            match decode_column_errors(&parts, 12, sl, p.len(), true) {
                Err(_) => refused += 1,
                Ok((got, _)) => assert_ne!(got, p),
            }
        }
        assert!(refused > 0);
    }

    #[test]
    fn column_errors_without_spare_shards_refuse() {
        let p = vec![7u8; 4_000];
        let shards = encode_shards(&p, 12, 16).unwrap();
        let sl = shards[0].len();
        // 13 present (budget 0) and one flipped byte: detectable, not locatable.
        let mut parts: Vec<(usize, Vec<u8>)> =
            shards.iter().cloned().enumerate().take(13).collect();
        parts[3].1[10] ^= 1;
        assert!(decode_column_errors(&parts, 12, sl, p.len(), true).is_err());
        // Fewer than k, wrong-length bodies, empty geometry and k = 0 are refused, not panics.
        assert!(decode_column_errors(&parts[..11], 12, sl, p.len(), true).is_err());
        let short: Vec<(usize, Vec<u8>)> =
            parts.iter().map(|(i, b)| (*i, b[1..].to_vec())).collect();
        assert!(decode_column_errors(&short, 12, sl, p.len(), true).is_err());
        assert!(decode_column_errors(&parts, 12, 0, p.len(), true).is_err());
        assert!(decode_column_errors(&parts, 0, sl, p.len(), true).is_err());
        // Repeated and out-of-range indexes are ignored rather than trusted.
        let mut dup: Vec<(usize, Vec<u8>)> = shards.iter().cloned().enumerate().collect();
        dup.push((3, vec![0u8; sl]));
        dup.push((300, vec![0u8; sl]));
        assert_eq!(
            decode_column_errors(&dup, 12, sl, p.len(), true).unwrap().0,
            p
        );
    }
}
