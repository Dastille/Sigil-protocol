//! Seal geometry RS(16, 8) over GF(256), systematic, evaluation points x = index + 1,
//! matching `crate/sigil/src/rs.rs` (`encode_shards`). Cross-checked in tests.

use crate::gf;
use std::ops::Range;

/// Seal's k (synthetic runs).
pub const SEAL_K: usize = 8;
/// All geometries measured here have n = 16.
pub const N: usize = 16;

pub fn x_of(i: usize) -> u8 {
    (i + 1) as u8
}

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

/// Precomputed maps "values at any K positions -> all N values".
pub struct Code {
    /// Data shards (8 = Seal, 12 = Reflection).
    pub k: usize,
    /// N×K systematic generator.
    g: Vec<u8>,
    /// mask -> index into `predict` (u32::MAX if popcount != K).
    idx: Vec<u32>,
    /// For every K-subset S (by index): N×K matrix G·(G_S)^-1.
    predict: Vec<u8>,
}

impl Code {
    pub fn new(k: usize) -> Option<Self> {
        if k == 0 || k >= N {
            return None;
        }
        let xs: Vec<u8> = (0..k).map(x_of).collect();
        let vinv = gf::invert(k, &power_matrix(&xs, k))?;
        let all: Vec<u8> = (0..N).map(x_of).collect();
        let g = gf::matmul(&power_matrix(&all, k), &vinv, N, k, k);
        let mut idx = vec![u32::MAX; 1 << N];
        let mut predict = Vec::new();
        let mut count = 0u32;
        for mask in 0u32..(1 << N) {
            if mask.count_ones() as usize != k {
                continue;
            }
            let rows: Vec<usize> = (0..N).filter(|&i| mask & (1 << i) != 0).collect();
            let mut gs = vec![0u8; k * k];
            for (r, &i) in rows.iter().enumerate() {
                gs[r * k..(r + 1) * k].copy_from_slice(&g[i * k..(i + 1) * k]);
            }
            let gsi = gf::invert(k, &gs)?;
            predict.extend(gf::matmul(&g, &gsi, N, k, k));
            idx[mask as usize] = count;
            count += 1;
        }
        Some(Code { k, g, idx, predict })
    }

    /// N×self.k matrix for the self.k positions in `mask` (sorted ascending order of inputs).
    pub fn pmat(&self, mask: u16) -> Option<&[u8]> {
        let i = *self.idx.get(mask as usize)?;
        if i == u32::MAX {
            return None;
        }
        let s = i as usize * N * self.k;
        self.predict.get(s..s + N * self.k)
    }

    /// Systematic encode of self.k equal-length data shards to N shards.
    pub fn encode(&self, data: &[Vec<u8>]) -> Vec<Vec<u8>> {
        let len = data.first().map_or(0, |d| d.len());
        let mut out: Vec<Vec<u8>> = data.to_vec();
        for r in self.k..N {
            let mut v = vec![0u8; len];
            for (c, d) in data.iter().enumerate() {
                gf::mul_acc(self.g[r * self.k + c], d, &mut v);
            }
            out.push(v);
        }
        out
    }

    /// From the self.k shards in `base` (ascending), predict rows `rows` over `range`.
    pub fn predict_rows(
        &self,
        rx: &[Option<Vec<u8>>],
        base: &[usize],
        rows: &[usize],
        range: Range<usize>,
    ) -> Option<Vec<Vec<u8>>> {
        let mask = base.iter().fold(0u16, |m, &i| m | (1 << i));
        let p = self.pmat(mask)?;
        let len = range.len();
        let mut outs = Vec::with_capacity(rows.len());
        for &r in rows {
            let mut v = vec![0u8; len];
            for (c, &b) in base.iter().enumerate() {
                let src = rx.get(b)?.as_ref()?.get(range.clone())?;
                gf::mul_acc(p[r * self.k + c], src, &mut v);
            }
            outs.push(v);
        }
        Some(outs)
    }
}

/// Solve a·v = rhs (rows×cols). Free variables 0. None if inconsistent.
/// Port of `solve_any` in `crate/sigil/src/rs.rs`.
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

/// Berlekamp–Welch, port of `berlekamp_welch` in `crate/sigil/src/rs.rs`.
fn berlekamp_welch(xs: &[u8], ys: &[u8], k: usize, e: usize) -> Option<Vec<u8>> {
    let p = xs.len();
    if k == 0 || p < k + 2 * e {
        return None;
    }
    let qn = k + e;
    let cols = qn + e;
    let mut a = vec![0u8; p * cols];
    let mut rhs = vec![0u8; p];
    for i in 0..p {
        let (x, y) = (xs[i], ys[i]);
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

/// Unique decode of one column from symbols at `pos` (ascending shard indexes):
/// full N-symbol codeword if at most `(pos.len()-K)/2` disagree.
pub fn bw_column(k: usize, pos: &[usize], ys: &[u8]) -> Option<[u8; N]> {
    if pos.len() < k {
        return None;
    }
    let budget = (pos.len() - k) / 2;
    let xs: Vec<u8> = pos.iter().map(|&i| x_of(i)).collect();
    let poly = berlekamp_welch(&xs, ys, k, budget)?;
    let mut cw = [0u8; N];
    for (i, c) in cw.iter_mut().enumerate() {
        *c = gf::eval_poly(&poly, x_of(i));
    }
    let wrong = pos.iter().zip(ys).filter(|(&i, &y)| cw[i] != y).count();
    if wrong > budget {
        return None;
    }
    Some(cw)
}

/// Column repair over `range` with shards `live` (ascending), like
/// `rs::decode_column_errors`: returns all N rows for the range plus the list of
/// columns (absolute) that could not be fixed within the unique-decoding budget.
pub fn column_repair(
    code: &Code,
    rx: &[Option<Vec<u8>>],
    live: &[usize],
    range: Range<usize>,
) -> Option<(Vec<Vec<u8>>, Vec<usize>)> {
    let k = code.k;
    if live.len() < k {
        return None;
    }
    let all: Vec<usize> = (0..N).collect();
    let mut full = code.predict_rows(rx, &live[..k], &all, range.clone())?;
    let mut failed = Vec::new();
    let start = range.start;
    let mut ys = vec![0u8; live.len()];
    for x in 0..range.len() {
        let abs = start + x;
        let dirty = live[k..]
            .iter()
            .any(|&r| rx[r].as_ref().is_none_or(|s| s[abs] != full[r][x]));
        if !dirty {
            continue;
        }
        for (t, &i) in live.iter().enumerate() {
            ys[t] = rx[i].as_ref().map_or(0, |s| s[abs]);
        }
        match bw_column(k, live, &ys) {
            Some(cw) => {
                for (r, row) in full.iter_mut().enumerate() {
                    row[x] = cw[r];
                }
            }
            None => failed.push(abs),
        }
    }
    Some((full, failed))
}
