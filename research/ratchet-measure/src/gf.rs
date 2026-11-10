//! GF(256) with the same field polynomial as `crate/sigil/src/gf.rs` (0x11d).

use std::sync::OnceLock;

pub struct Tables {
    mul: Vec<u8>,
    inv: [u8; 256],
}

fn build() -> Tables {
    let mut exp = [0u8; 512];
    let mut log = [0u8; 256];
    let mut x: u16 = 1;
    for (i, e) in exp.iter_mut().enumerate().take(255) {
        *e = x as u8;
        log[x as usize] = i as u8;
        x <<= 1;
        if x & 0x100 != 0 {
            x ^= 0x11d;
        }
    }
    for i in 255..512 {
        exp[i] = exp[i - 255];
    }
    let mut mul = vec![0u8; 65536];
    for a in 1..256usize {
        for b in 1..256usize {
            mul[(a << 8) | b] = exp[log[a] as usize + log[b] as usize];
        }
    }
    let mut inv = [0u8; 256];
    for (a, slot) in inv.iter_mut().enumerate().skip(1) {
        *slot = exp[255 - log[a] as usize];
    }
    Tables { mul, inv }
}

fn t() -> &'static Tables {
    static T: OnceLock<Tables> = OnceLock::new();
    T.get_or_init(build)
}

#[inline]
pub fn mul(a: u8, b: u8) -> u8 {
    t().mul[((a as usize) << 8) | b as usize]
}

/// Inverse; 0 maps to 0 (callers never divide by 0).
#[inline]
pub fn inv(a: u8) -> u8 {
    t().inv[a as usize]
}

#[inline]
pub fn row(c: u8) -> &'static [u8] {
    let s = (c as usize) << 8;
    &t().mul[s..s + 256]
}

/// dst ^= c · src
pub fn mul_acc(c: u8, src: &[u8], dst: &mut [u8]) {
    if c == 0 {
        return;
    }
    let r = row(c);
    for (d, s) in dst.iter_mut().zip(src) {
        *d ^= r[*s as usize];
    }
}

pub fn eval_poly(coeff: &[u8], x: u8) -> u8 {
    let mut y = 0u8;
    for &c in coeff.iter().rev() {
        y = mul(y, x) ^ c;
    }
    y
}

/// Invert a k×k row-major matrix; None if singular.
pub fn invert(k: usize, a: &[u8]) -> Option<Vec<u8>> {
    let mut m = a.to_vec();
    let mut r = vec![0u8; k * k];
    for i in 0..k {
        r[i * k + i] = 1;
    }
    for c in 0..k {
        let p = (c..k).find(|&i| m[i * k + c] != 0)?;
        if p != c {
            for t in 0..k {
                m.swap(c * k + t, p * k + t);
                r.swap(c * k + t, p * k + t);
            }
        }
        let iv = inv(m[c * k + c]);
        for t in 0..k {
            m[c * k + t] = mul(m[c * k + t], iv);
            r[c * k + t] = mul(r[c * k + t], iv);
        }
        for i in 0..k {
            let f = m[i * k + c];
            if i == c || f == 0 {
                continue;
            }
            for t in 0..k {
                m[i * k + t] ^= mul(f, m[c * k + t]);
                r[i * k + t] ^= mul(f, r[c * k + t]);
            }
        }
    }
    Some(r)
}

/// (r×n)·(n×c)
pub fn matmul(a: &[u8], b: &[u8], r: usize, n: usize, c: usize) -> Vec<u8> {
    let mut out = vec![0u8; r * c];
    for i in 0..r {
        for j in 0..c {
            let mut acc = 0u8;
            for t in 0..n {
                acc ^= mul(a[i * n + t], b[t * c + j]);
            }
            out[i * c + j] = acc;
        }
    }
    out
}
