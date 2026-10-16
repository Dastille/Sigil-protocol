//! MDS backends for systematic Reed–Solomon over GF(256).
//!
//! Vandermonde is the production default (wire-compatible with existing .sg1).
//! Cauchy is an opt-in bake-off: same k/n systematic layout, different parity
//! matrix — true-name (plaintext SHA-256) matches after repair; shards do not.

use crate::gf;
use crate::rs;
use crate::Error;

/// Pluggable systematic MDS encode/decode.
pub trait MdsBackend: Send + Sync {
    fn name(&self) -> &'static str;
    fn encode(&self, payload: &[u8], k: usize, n: usize) -> Vec<Vec<u8>>;
    fn decode(
        &self,
        shards: &[Option<Vec<u8>>],
        k: usize,
        payload_len: usize,
    ) -> Result<Vec<u8>, Error>;
}

/// Production Vandermonde RS (existing `rs::encode_shards` / `decode_shards`).
#[derive(Clone, Copy, Debug, Default)]
pub struct VandermondeRs;

impl MdsBackend for VandermondeRs {
    fn name(&self) -> &'static str {
        "vandermonde"
    }
    fn encode(&self, payload: &[u8], k: usize, n: usize) -> Vec<Vec<u8>> {
        rs::encode_shards(payload, k, n)
    }
    fn decode(
        &self,
        shards: &[Option<Vec<u8>>],
        k: usize,
        payload_len: usize,
    ) -> Result<Vec<u8>, Error> {
        rs::decode_shards(shards, k, payload_len, true)
    }
}

/// Systematic Cauchy Reed–Solomon (Plank-style coding matrix over GF(256)).
///
/// Data shards 0..k-1 are the payload stripe; coding rows use
/// `C[i][j] = 1 / (x_j ⊕ y_i)` with `x_j = j+1`, `y_i = k+1+i`.
#[derive(Debug)]
pub struct CauchyRs {
    /// Cached (k, n, coding matrix m×k) for repeated encode of same shape.
    cache: std::sync::Mutex<Option<CauchyCache>>,
}

#[derive(Clone, Debug)]
struct CauchyCache {
    k: usize,
    n: usize,
    /// m × k coding matrix, row-major flattened (m = n−k).
    c: Vec<u8>,
}

impl Default for CauchyRs {
    fn default() -> Self {
        Self {
            cache: std::sync::Mutex::new(None),
        }
    }
}

impl CauchyRs {
    pub fn new() -> Self {
        Self::default()
    }

    fn coding_matrix(k: usize, n: usize) -> Result<Vec<u8>, Error> {
        if k == 0 || n < k || n > 255 {
            return Err(Error::Msg(format!("bad Cauchy shape k={k} n={n}")));
        }
        let m = n - k;
        let mut c = vec![0u8; m * k];
        for i in 0..m {
            let y = (k + 1 + i) as u8;
            for j in 0..k {
                let x = (j + 1) as u8;
                let d = x ^ y;
                if d == 0 {
                    return Err(Error::Msg("Cauchy singular: x==y".into()));
                }
                c[i * k + j] = gf::inv(d);
            }
        }
        Ok(c)
    }

    fn matrix(&self, k: usize, n: usize) -> Result<Vec<u8>, Error> {
        {
            let guard = self
                .cache
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let Some(ref cached) = *guard {
                if cached.k == k && cached.n == n {
                    return Ok(cached.c.clone());
                }
            }
        }
        let c = Self::coding_matrix(k, n)?;
        *self
            .cache
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) =
            Some(CauchyCache { k, n, c: c.clone() });
        Ok(c)
    }
}

impl MdsBackend for CauchyRs {
    fn name(&self) -> &'static str {
        "cauchy"
    }

    fn encode(&self, payload: &[u8], k: usize, n: usize) -> Vec<Vec<u8>> {
        // `MdsBackend::encode` is infallible by signature and is only driven by the opt-in
        // bake-off with caller-chosen (k, n); `decode` (untrusted input) returns errors instead.
        let c = self.matrix(k, n).expect("Cauchy matrix");
        let m = n - k;
        let shard_len = (payload.len().div_ceil(k)).max(1);
        let mut padded = vec![0u8; shard_len * k];
        padded[..payload.len()].copy_from_slice(payload);
        let mut shards = vec![vec![0u8; shard_len]; n];
        for i in 0..k {
            shards[i].copy_from_slice(&padded[i * shard_len..(i + 1) * shard_len]);
        }
        {
            let (data, parity) = shards.split_at_mut(k);
            let ins: Vec<&[u8]> = data.iter().map(|v| v.as_slice()).collect();
            let mut outs: Vec<&mut [u8]> =
                parity[..m].iter_mut().map(|v| v.as_mut_slice()).collect();
            gf::matrix_apply(&c, &ins, &mut outs);
        }
        shards
    }

    fn decode(
        &self,
        shards: &[Option<Vec<u8>>],
        k: usize,
        payload_len: usize,
    ) -> Result<Vec<u8>, Error> {
        let n = shards.len();
        if n < k {
            return Err(Error::Msg(format!("need {k} shards, have {n}")));
        }
        let c = self.matrix(k, n)?;
        let parts: Vec<(usize, &Vec<u8>)> = shards
            .iter()
            .enumerate()
            .filter_map(|(i, s)| s.as_ref().map(|b| (i, b)))
            .collect();
        if parts.len() < k {
            return Err(Error::Msg(format!(
                "need {k} live shards, have {}",
                parts.len()
            )));
        }
        let shard_len = parts[0].1.len();

        // Fast path: all data shards present.
        let mut data_ok = vec![None; k];
        for &(index, body) in &parts {
            if index < k && data_ok[index].is_none() {
                data_ok[index] = Some(body);
            }
        }
        if let Some(data) = data_ok.iter().copied().collect::<Option<Vec<_>>>() {
            let mut padded = vec![0u8; shard_len * k];
            for (i, s) in data.into_iter().enumerate() {
                let ncopy = s.len().min(shard_len);
                padded[i * shard_len..i * shard_len + ncopy].copy_from_slice(&s[..ncopy]);
            }
            padded.truncate(payload_len);
            return Ok(padded);
        }

        // Pick first k distinct live indices; build decoding matrix A (k×k).
        let mut live: Vec<(usize, &Vec<u8>)> = Vec::with_capacity(k);
        for &(index, body) in &parts {
            if live.len() == k {
                break;
            }
            if live.iter().any(|(i, _)| *i == index) {
                continue;
            }
            live.push((index, body));
        }
        if live.len() < k {
            return Err(Error::Msg(format!("need {k} distinct live shards")));
        }

        // A[row][col]: if live index < k → unit row; else coding row C[index-k].
        let mut a = vec![0u8; k * k];
        for (row, &(index, _)) in live.iter().enumerate() {
            if index < k {
                a[row * k + index] = 1;
            } else {
                let ci = index - k;
                let base = ci * k;
                for col in 0..k {
                    a[row * k + col] = c[base + col];
                }
            }
        }
        let inv = invert_gf_matrix(k, &a)?;

        let ins: Vec<&[u8]> = live
            .iter()
            .map(|&(_, body)| &body[..body.len().min(shard_len)])
            .collect();
        let mut padded = vec![0u8; shard_len * k];
        {
            let mut outs: Vec<&mut [u8]> = padded.chunks_mut(shard_len.max(1)).take(k).collect();
            gf::matrix_apply(&inv, &ins, &mut outs);
        }
        padded.truncate(payload_len);
        Ok(padded)
    }
}

/// Invert k×k matrix over GF(256); returns row-major inverse.
fn invert_gf_matrix(k: usize, a_in: &[u8]) -> Result<Vec<u8>, Error> {
    // Augment [A | I]
    let mut m = vec![0u8; k * (2 * k)];
    for r in 0..k {
        for c in 0..k {
            m[r * 2 * k + c] = a_in[r * k + c];
        }
        m[r * 2 * k + k + r] = 1;
    }
    for col in 0..k {
        let mut pivot = col;
        while pivot < k && m[pivot * 2 * k + col] == 0 {
            pivot += 1;
        }
        if pivot == k {
            return Err(Error::Msg("Cauchy decode: singular matrix".into()));
        }
        if pivot != col {
            for c in 0..2 * k {
                m.swap(col * 2 * k + c, pivot * 2 * k + c);
            }
        }
        let invp = gf::inv(m[col * 2 * k + col]);
        for c in 0..2 * k {
            m[col * 2 * k + c] = gf::mul(m[col * 2 * k + c], invp);
        }
        for row in 0..k {
            if row == col {
                continue;
            }
            let f = m[row * 2 * k + col];
            if f == 0 {
                continue;
            }
            for c in 0..2 * k {
                m[row * 2 * k + c] ^= gf::mul(f, m[col * 2 * k + c]);
            }
        }
    }
    let mut inv = vec![0u8; k * k];
    for r in 0..k {
        for c in 0..k {
            inv[r * k + c] = m[r * 2 * k + k + c];
        }
    }
    Ok(inv)
}

/// Default backend (always Vandermonde unless feature enables Cauchy default — never wired).
pub fn default_backend() -> Box<dyn MdsBackend> {
    Box::new(VandermondeRs)
}

pub fn backend_by_name(name: &str) -> Result<Box<dyn MdsBackend>, Error> {
    match name.to_ascii_lowercase().as_str() {
        "vandermonde" | "v" | "default" => Ok(Box::new(VandermondeRs)),
        "cauchy" | "c" => Ok(Box::new(CauchyRs::new())),
        other => Err(Error::Msg(format!("unknown MDS backend: {other}"))),
    }
}

/// One bake-off sample: MB/s encode + multi-erasure decode for both backends.
#[derive(Clone, Debug)]
pub struct MdsBenchRow {
    pub backend: String,
    pub k: usize,
    pub n: usize,
    pub size: usize,
    pub encode_mibs: f64,
    pub decode_mibs: f64,
    pub erasures: usize,
}

/// Run Seal/Reflection bake-off sizes. `iters` ≥ 1.
pub fn run_bakeoff(iters: usize) -> Vec<MdsBenchRow> {
    let iters = iters.max(1);
    let sizes = [1usize << 20, 4usize << 20, 8usize << 20];
    let shapes = [(8usize, 16usize), (12usize, 16usize)];
    let backends: Vec<Box<dyn MdsBackend>> =
        vec![Box::new(VandermondeRs), Box::new(CauchyRs::new())];
    let mut rows = Vec::new();
    for &(k, n) in &shapes {
        let erasures = n - k; // multi-erasure: wipe all parity budget on data side
        for &size in &sizes {
            let payload: Vec<u8> = (0..size).map(|i| (i * 17 + 3) as u8).collect();
            for be in &backends {
                // Warmup
                let shards = be.encode(&payload, k, n);
                let mut opt: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
                for slot in opt.iter_mut().take(erasures) {
                    *slot = None;
                }
                let _ = be.decode(&opt, k, size).expect("warmup decode");

                let t0 = std::time::Instant::now();
                let mut last = Vec::new();
                for _ in 0..iters {
                    last = be.encode(&payload, k, n);
                }
                let enc_s = t0.elapsed().as_secs_f64() / iters as f64;
                let encode_mibs = (size as f64 / (1024.0 * 1024.0)) / enc_s;

                let t1 = std::time::Instant::now();
                let mut recovered = Vec::new();
                for _ in 0..iters {
                    let mut opt: Vec<Option<Vec<u8>>> = last.iter().cloned().map(Some).collect();
                    for slot in opt.iter_mut().take(erasures) {
                        *slot = None;
                    }
                    recovered = be.decode(&opt, k, size).expect("bench decode");
                }
                let dec_s = t1.elapsed().as_secs_f64() / iters as f64;
                let decode_mibs = (size as f64 / (1024.0 * 1024.0)) / dec_s;
                assert_eq!(recovered, payload, "{} true-name mismatch", be.name());

                rows.push(MdsBenchRow {
                    backend: be.name().to_string(),
                    k,
                    n,
                    size,
                    encode_mibs,
                    decode_mibs,
                    erasures,
                });
            }
        }
    }
    rows
}

/// Format bake-off table + keep/drop recommendation (≥15% win on encode OR decode).
pub fn format_bakeoff_report(rows: &[MdsBenchRow]) -> (String, bool) {
    let mut out = String::new();
    out.push_str("MDS bake-off (GF(256) systematic; SIMD: none / scalar tables)\n");
    out.push_str("backend       k/n     size    encode MiB/s   decode MiB/s  erasures\n");
    out.push_str("--------------------------------------------------------------------\n");
    let mut best_enc_gain = 0.0_f64;
    let mut best_dec_gain = 0.0_f64;
    // Pair by (k,n,size)
    let mut i = 0;
    while i + 1 < rows.len() {
        let a = &rows[i];
        let b = &rows[i + 1];
        if a.k == b.k && a.n == b.n && a.size == b.size {
            let (v, c) = if a.backend == "vandermonde" {
                (a, b)
            } else {
                (b, a)
            };
            for r in [v, c] {
                out.push_str(&format!(
                    "{:<12}  {:>2}/{:<2}  {:>4} MiB   {:>10.1}    {:>10.1}     {}\n",
                    r.backend,
                    r.k,
                    r.n,
                    r.size / (1024 * 1024),
                    r.encode_mibs,
                    r.decode_mibs,
                    r.erasures
                ));
            }
            if v.encode_mibs > 0.0 {
                best_enc_gain = best_enc_gain.max(c.encode_mibs / v.encode_mibs - 1.0);
            }
            if v.decode_mibs > 0.0 {
                best_dec_gain = best_dec_gain.max(c.decode_mibs / v.decode_mibs - 1.0);
            }
            i += 2;
        } else {
            i += 1;
        }
    }
    let keep = best_enc_gain >= 0.15 || best_dec_gain >= 0.15;
    out.push('\n');
    out.push_str(&format!(
        "Best Cauchy vs Vandermonde: encode {:+.0}%, multi-erasure decode {:+.0}%\n",
        best_enc_gain * 100.0,
        best_dec_gain * 100.0
    ));
    if keep {
        out.push_str(
            "Recommendation: KEEP Cauchy behind feature `mds-cauchy` / --mds cauchy (≥15% win).\n",
        );
    } else {
        out.push_str(
            "Recommendation: NO WIN — Vandermonde remains default; Cauchy not wired as default.\n",
        );
        out.push_str(
            "Cauchy stays available for benches (`sigil bench-mds`) and feature `mds-cauchy` (off).\n",
        );
    }
    (out, keep)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::sha256;

    fn erase_first(shards: &[Vec<u8>], n_erase: usize) -> Vec<Option<Vec<u8>>> {
        shards
            .iter()
            .enumerate()
            .map(|(i, s)| if i < n_erase { None } else { Some(s.clone()) })
            .collect()
    }

    #[test]
    fn cauchy_roundtrip_seal_erasures() {
        let be = CauchyRs::new();
        let payload: Vec<u8> = (0..4096).map(|i| (i * 9) as u8).collect();
        let shards = be.encode(&payload, 8, 16);
        assert_eq!(shards.len(), 16);
        // systematic: first k are data stripes
        let sl = shards[0].len();
        let mut padded = vec![0u8; sl * 8];
        padded[..payload.len()].copy_from_slice(&payload);
        assert_eq!(shards[0], padded[..sl]);
        let opt = erase_first(&shards, 8);
        let out = be.decode(&opt, 8, payload.len()).unwrap();
        assert_eq!(out, payload);
        assert_eq!(sha256(&out), sha256(&payload));
    }

    #[test]
    fn cauchy_roundtrip_reflection_erasures() {
        let be = CauchyRs::new();
        let payload: Vec<u8> = (0..3000).map(|i| (i * 3) as u8).collect();
        let shards = be.encode(&payload, 12, 16);
        let opt = erase_first(&shards, 4);
        assert_eq!(be.decode(&opt, 12, payload.len()).unwrap(), payload);
    }

    #[test]
    fn both_backends_same_true_name_after_erasures() {
        let payload: Vec<u8> = (0..8192).map(|i| ((i * 13) ^ 0x5a) as u8).collect();
        let true_name = sha256(&payload);
        for (k, n, erase) in [(8, 16, 8), (12, 16, 4)] {
            for be in [
                Box::new(VandermondeRs) as Box<dyn MdsBackend>,
                Box::new(CauchyRs::new()),
            ] {
                let shards = be.encode(&payload, k, n);
                let opt = erase_first(&shards, erase);
                let out = be.decode(&opt, k, payload.len()).unwrap();
                assert_eq!(sha256(&out), true_name, "{} k={k}", be.name());
            }
        }
    }

    #[test]
    fn cauchy_parity_differs_from_vandermonde() {
        let payload: Vec<u8> = (0..512).map(|i| i as u8).collect();
        let v = VandermondeRs.encode(&payload, 8, 16);
        let c = CauchyRs::new().encode(&payload, 8, 16);
        // systematic data matches; parity generally differs
        assert_eq!(v[0], c[0]);
        assert_ne!(v[8], c[8], "expected different Cauchy parity");
    }

    #[test]
    fn backend_by_name_resolves() {
        assert_eq!(backend_by_name("cauchy").unwrap().name(), "cauchy");
        assert_eq!(
            backend_by_name("vandermonde").unwrap().name(),
            "vandermonde"
        );
    }

    #[test]
    #[ignore = "slow MDS bake-off; run: cargo test --release ignored_full_bakeoff -- --ignored --nocapture"]
    fn ignored_full_bakeoff() {
        let rows = run_bakeoff(2);
        let (report, keep) = format_bakeoff_report(&rows);
        println!("{report}");
        // Always succeeds — recommendation is printed for humans.
        let _ = keep;
        assert!(!rows.is_empty());
    }

    /// Cauchy fast path vs. the original per-byte scalar formula.
    #[test]
    #[allow(clippy::needless_range_loop)]
    fn cauchy_slices_match_scalar_oracle() {
        let be = CauchyRs::new();
        let mut seed = 12345u64;
        for &(k, n, len) in &[
            (1usize, 2usize, 7usize),
            (8, 16, 5000),
            (12, 16, 33333),
            (15, 20, 1),
            (40, 60, 9001),
        ] {
            let payload: Vec<u8> = (0..len)
                .map(|_| {
                    seed ^= seed << 13;
                    seed ^= seed >> 7;
                    seed ^= seed << 17;
                    seed as u8
                })
                .collect();
            let shards = be.encode(&payload, k, n);
            let c = CauchyRs::coding_matrix(k, n).unwrap();
            let sl = shards[0].len();
            for row in 0..n - k {
                for s in 0..sl {
                    let mut acc = 0u8;
                    for j in 0..k {
                        acc ^= gf::mul(c[row * k + j], shards[j][s]);
                    }
                    assert_eq!(shards[k + row][s], acc, "k={k} n={n} row={row} s={s}");
                }
            }
            let mut opt: Vec<Option<Vec<u8>>> = shards.into_iter().map(Some).collect();
            for i in 0..(n - k).min(k) {
                opt[i] = None;
            }
            assert_eq!(be.decode(&opt, k, len).unwrap(), payload);
        }
    }
}
