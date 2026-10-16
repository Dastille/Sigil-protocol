const EXP: [u8; 512] = {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x11d;
        }
        i += 1;
    }
    let mut i = 255;
    while i < 512 {
        exp[i] = exp[i - 255];
        i += 1;
    }
    let _ = log;
    exp
};

const LOG: [u8; 256] = {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    let mut i = 0;
    while i < 255 {
        exp[i] = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x11d;
        }
        i += 1;
    }
    log
};

pub fn mul(a: u8, b: u8) -> u8 {
    if a == 0 || b == 0 {
        0
    } else {
        EXP[LOG[a as usize] as usize + LOG[b as usize] as usize]
    }
}

pub fn inv(a: u8) -> u8 {
    assert!(a != 0);
    EXP[255 - LOG[a as usize] as usize]
}

pub fn eval_poly(coeff: &[u8], x: u8) -> u8 {
    let mut y = 0u8;
    for &c in coeff.iter().rev() {
        y = mul(y, x) ^ c;
    }
    y
}

pub fn solve_vandermonde(xs: &[u8], ys: &[u8]) -> Vec<u8> {
    let k = xs.len();
    let mut a = vec![vec![0u8; k + 1]; k];
    for i in 0..k {
        let mut p = 1u8;
        for j in 0..k {
            a[i][j] = p;
            p = mul(p, xs[i]);
        }
        a[i][k] = ys[i];
    }
    for col in 0..k {
        let mut pivot = col;
        while pivot < k && a[pivot][col] == 0 {
            pivot += 1;
        }
        if pivot == k {
            panic!("singular");
        }
        a.swap(col, pivot);
        let invp = inv(a[col][col]);
        for j in col..=k {
            a[col][j] = mul(a[col][j], invp);
        }
        for row in 0..k {
            if row == col {
                continue;
            }
            let f = a[row][col];
            if f == 0 {
                continue;
            }
            for j in col..=k {
                a[row][j] ^= mul(f, a[col][j]);
            }
        }
    }
    (0..k).map(|i| a[i][k]).collect()
}

// ---------------------------------------------------------------------------
// Bulk (slice) arithmetic. Same field (poly 0x11d) and same values as `mul`;
// only the evaluation order changes, so results are bit-identical.
// ---------------------------------------------------------------------------

/// Full 256×256 product table, built at compile time from `mul`.
static MUL_TABLE: [[u8; 256]; 256] = {
    let mut t = [[0u8; 256]; 256];
    let mut a = 1;
    while a < 256 {
        let mut b = 1;
        while b < 256 {
            t[a][b] = EXP[LOG[a] as usize + LOG[b] as usize];
            b += 1;
        }
        a += 1;
    }
    t
};

/// Which kernel `mul_acc` uses on this machine (for diagnostics/benchmarks).
pub fn kernel_name() -> &'static str {
    #[cfg(target_arch = "x86_64")]
    {
        if std::arch::is_x86_feature_detected!("avx2") {
            return "avx2";
        }
        if std::arch::is_x86_feature_detected!("ssse3") {
            return "ssse3";
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if std::arch::is_aarch64_feature_detected!("neon") {
            return "neon";
        }
    }
    "scalar"
}

/// `dst[i] ^= c * src[i]` for `i < min(len)`. Runtime-dispatched SIMD.
pub fn mul_acc(c: u8, src: &[u8], dst: &mut [u8]) {
    let n = src.len().min(dst.len());
    let (src, dst) = (&src[..n], &mut dst[..n]);
    if c == 0 || n == 0 {
        return;
    }
    if c == 1 {
        for (d, s) in dst.iter_mut().zip(src) {
            *d ^= *s;
        }
        return;
    }
    #[cfg(target_arch = "x86_64")]
    {
        if n >= 32 && std::arch::is_x86_feature_detected!("avx2") {
            // SAFETY: AVX2 availability checked at runtime just above.
            unsafe { simd_x86::mul_acc_avx2(c, src, dst) };
            return;
        }
        if n >= 16 && std::arch::is_x86_feature_detected!("ssse3") {
            // SAFETY: SSSE3 availability checked at runtime just above.
            unsafe { simd_x86::mul_acc_ssse3(c, src, dst) };
            return;
        }
    }
    #[cfg(target_arch = "aarch64")]
    {
        if n >= 16 && std::arch::is_aarch64_feature_detected!("neon") {
            // SAFETY: NEON availability checked at runtime just above.
            unsafe { simd_arm::mul_acc_neon(c, src, dst) };
            return;
        }
    }
    mul_acc_scalar(c, src, dst);
}

/// Portable fallback (and SIMD tail handler): one table row lookup per byte.
pub fn mul_acc_scalar(c: u8, src: &[u8], dst: &mut [u8]) {
    let row = &MUL_TABLE[c as usize];
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= row[*s as usize];
    }
}

/// Split-nibble tables for SIMD shuffles: lo[i] = c*i, hi[i] = c*(i<<4).
#[allow(dead_code)]
fn nibble_tables(c: u8) -> ([u8; 16], [u8; 16]) {
    let mut lo = [0u8; 16];
    let mut hi = [0u8; 16];
    for i in 0..16u8 {
        lo[i as usize] = mul(c, i);
        hi[i as usize] = mul(c, i << 4);
    }
    (lo, hi)
}

#[cfg(target_arch = "x86_64")]
mod simd_x86 {
    use std::arch::x86_64::*;

    #[target_feature(enable = "avx2")]
    pub unsafe fn mul_acc_avx2(c: u8, src: &[u8], dst: &mut [u8]) {
        let (lo, hi) = super::nibble_tables(c);
        let n = src.len();
        let lo128 = _mm_loadu_si128(lo.as_ptr() as *const __m128i);
        let hi128 = _mm_loadu_si128(hi.as_ptr() as *const __m128i);
        let tlo = _mm256_broadcastsi128_si256(lo128);
        let thi = _mm256_broadcastsi128_si256(hi128);
        let mask = _mm256_set1_epi8(0x0f);
        let mut i = 0;
        while i + 32 <= n {
            let s = _mm256_loadu_si256(src.as_ptr().add(i) as *const __m256i);
            let d = _mm256_loadu_si256(dst.as_ptr().add(i) as *const __m256i);
            let l = _mm256_and_si256(s, mask);
            let h = _mm256_and_si256(_mm256_srli_epi64(s, 4), mask);
            let p = _mm256_xor_si256(_mm256_shuffle_epi8(tlo, l), _mm256_shuffle_epi8(thi, h));
            _mm256_storeu_si256(
                dst.as_mut_ptr().add(i) as *mut __m256i,
                _mm256_xor_si256(d, p),
            );
            i += 32;
        }
        super::mul_acc_scalar(c, &src[i..], &mut dst[i..]);
    }

    #[target_feature(enable = "ssse3")]
    pub unsafe fn mul_acc_ssse3(c: u8, src: &[u8], dst: &mut [u8]) {
        let (lo, hi) = super::nibble_tables(c);
        let n = src.len();
        let tlo = _mm_loadu_si128(lo.as_ptr() as *const __m128i);
        let thi = _mm_loadu_si128(hi.as_ptr() as *const __m128i);
        let mask = _mm_set1_epi8(0x0f);
        let mut i = 0;
        while i + 16 <= n {
            let s = _mm_loadu_si128(src.as_ptr().add(i) as *const __m128i);
            let d = _mm_loadu_si128(dst.as_ptr().add(i) as *const __m128i);
            let l = _mm_and_si128(s, mask);
            let h = _mm_and_si128(_mm_srli_epi64(s, 4), mask);
            let p = _mm_xor_si128(_mm_shuffle_epi8(tlo, l), _mm_shuffle_epi8(thi, h));
            _mm_storeu_si128(dst.as_mut_ptr().add(i) as *mut __m128i, _mm_xor_si128(d, p));
            i += 16;
        }
        super::mul_acc_scalar(c, &src[i..], &mut dst[i..]);
    }
}

#[cfg(target_arch = "aarch64")]
mod simd_arm {
    use std::arch::aarch64::*;

    #[target_feature(enable = "neon")]
    pub unsafe fn mul_acc_neon(c: u8, src: &[u8], dst: &mut [u8]) {
        let (lo, hi) = super::nibble_tables(c);
        let n = src.len();
        let tlo = vld1q_u8(lo.as_ptr());
        let thi = vld1q_u8(hi.as_ptr());
        let mask = vdupq_n_u8(0x0f);
        let mut i = 0;
        while i + 16 <= n {
            let s = vld1q_u8(src.as_ptr().add(i));
            let d = vld1q_u8(dst.as_ptr().add(i));
            let l = vandq_u8(s, mask);
            let h = vshrq_n_u8::<4>(s);
            let p = veorq_u8(vqtbl1q_u8(tlo, l), vqtbl1q_u8(thi, h));
            vst1q_u8(dst.as_mut_ptr().add(i), veorq_u8(d, p));
            i += 16;
        }
        super::mul_acc_scalar(c, &src[i..], &mut dst[i..]);
    }
}

/// Cache block for matrix × shard-slices (bytes per row per pass).
const BLOCK: usize = 16 * 1024;

/// `outs[r] = Σ_c m[r][c] · ins[c]` over whole slices (all the same length as
/// `outs[r]`; shorter inputs read as zero-padded). `m` is row-major, `rows × ins.len()`.
pub fn matrix_apply(m: &[u8], ins: &[&[u8]], outs: &mut [&mut [u8]]) {
    let cols = ins.len();
    debug_assert!(m.len() >= outs.len() * cols);
    let len = outs.iter().map(|o| o.len()).max().unwrap_or(0);
    for o in outs.iter_mut() {
        o.fill(0);
    }
    let mut start = 0;
    while start < len {
        let end = (start + BLOCK).min(len);
        for (r, out) in outs.iter_mut().enumerate() {
            let row = &m[r * cols..(r + 1) * cols];
            let oe = end.min(out.len());
            if start >= oe {
                continue;
            }
            for (c, inp) in ins.iter().enumerate() {
                let ie = oe.min(inp.len());
                if start < ie {
                    mul_acc(row[c], &inp[start..ie], &mut out[start..ie]);
                }
            }
        }
        start = end;
    }
}

/// Invert a k×k row-major matrix by Gauss–Jordan. `None` if singular.
/// (A matrix inverse is unique, so any correct method yields the same bytes.)
pub fn invert_matrix(k: usize, a: &[u8]) -> Option<Vec<u8>> {
    let w = 2 * k;
    let mut m = vec![0u8; k * w];
    for r in 0..k {
        m[r * w..r * w + k].copy_from_slice(&a[r * k..(r + 1) * k]);
        m[r * w + k + r] = 1;
    }
    for col in 0..k {
        let pivot = (col..k).find(|&p| m[p * w + col] != 0)?;
        if pivot != col {
            for c in 0..w {
                m.swap(col * w + c, pivot * w + c);
            }
        }
        let invp = inv(m[col * w + col]);
        for c in 0..w {
            m[col * w + c] = mul(m[col * w + c], invp);
        }
        for row in 0..k {
            if row == col {
                continue;
            }
            let f = m[row * w + col];
            if f == 0 {
                continue;
            }
            for c in 0..w {
                let v = mul(f, m[col * w + c]);
                m[row * w + c] ^= v;
            }
        }
    }
    let mut out = vec![0u8; k * k];
    for r in 0..k {
        out[r * k..(r + 1) * k].copy_from_slice(&m[r * w + k..(r + 1) * w]);
    }
    Some(out)
}

/// Row-major product `a (r×n) · b (n×c)`.
pub fn matmul(a: &[u8], b: &[u8], r: usize, n: usize, c: usize) -> Vec<u8> {
    let mut out = vec![0u8; r * c];
    for i in 0..r {
        for t in 0..n {
            let f = a[i * n + t];
            if f == 0 {
                continue;
            }
            for j in 0..c {
                out[i * c + j] ^= mul(f, b[t * c + j]);
            }
        }
    }
    out
}

#[cfg(test)]
mod bulk_tests {
    use super::*;

    #[test]
    fn mul_table_matches_mul() {
        for a in 0..=255u8 {
            for b in 0..=255u8 {
                assert_eq!(MUL_TABLE[a as usize][b as usize], mul(a, b));
            }
        }
    }

    #[test]
    fn simd_kernel_matches_scalar_all_coeffs_and_lengths() {
        let src: Vec<u8> = (0..1000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
            .collect();
        for c in 0..=255u8 {
            for &len in &[0usize, 1, 15, 16, 17, 31, 32, 33, 63, 64, 100, 1000] {
                let base: Vec<u8> = (0..len).map(|i| (i * 31 + c as usize) as u8).collect();
                let mut a = base.clone();
                let mut b = base.clone();
                mul_acc(c, &src[..len], &mut a);
                for i in 0..len {
                    b[i] ^= mul(c, src[i]);
                }
                assert_eq!(a, b, "c={c} len={len} kernel={}", kernel_name());
            }
        }
    }

    /// Exercise every kernel this CPU has, not just the one dispatch picks.
    #[test]
    fn each_available_kernel_matches_scalar() {
        let src: Vec<u8> = (0..517u32).map(|i| (i * 97 + 5) as u8).collect();
        let base: Vec<u8> = (0..517u32).map(|i| (i * 13) as u8).collect();
        for c in 0..=255u8 {
            let mut want = base.clone();
            mul_acc_scalar(c, &src, &mut want);
            #[cfg(target_arch = "x86_64")]
            {
                if std::arch::is_x86_feature_detected!("ssse3") {
                    let mut got = base.clone();
                    unsafe { simd_x86::mul_acc_ssse3(c, &src, &mut got) };
                    assert_eq!(got, want, "ssse3 c={c}");
                }
                if std::arch::is_x86_feature_detected!("avx2") {
                    let mut got = base.clone();
                    unsafe { simd_x86::mul_acc_avx2(c, &src, &mut got) };
                    assert_eq!(got, want, "avx2 c={c}");
                }
            }
            #[cfg(target_arch = "aarch64")]
            {
                let mut got = base.clone();
                unsafe { simd_arm::mul_acc_neon(c, &src, &mut got) };
                assert_eq!(got, want, "neon c={c}");
            }
        }
    }

    #[test]
    fn invert_matches_solve_vandermonde() {
        let xs: Vec<u8> = (1..=20).collect();
        let k = xs.len();
        let mut v = vec![0u8; k * k];
        for i in 0..k {
            let mut p = 1;
            for j in 0..k {
                v[i * k + j] = p;
                p = mul(p, xs[i]);
            }
        }
        let inv = invert_matrix(k, &v).unwrap();
        for col in 0..k {
            let mut e = vec![0u8; k];
            e[col] = 1;
            let c = solve_vandermonde(&xs, &e);
            for row in 0..k {
                assert_eq!(inv[row * k + col], c[row]);
            }
        }
        assert!(invert_matrix(2, &[1, 1, 1, 1]).is_none());
    }
}
