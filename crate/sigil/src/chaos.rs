use crate::gf;

const LOGISTIC_R: f64 = 3.99;
const PI_SEED: u32 = 3141592653;
const PHI_SEED: u32 = 1618033988;
const E_SEED: u32 = 2718281828;
const PRIMES: [u8; 3] = [0xfb, 0xf1, 0xef];

fn mix32(a: u32, b: u32) -> u32 {
    let mut x = a ^ b;
    x = (x ^ (x >> 16)).wrapping_mul(0x7feb352d);
    x = (x ^ (x >> 15)).wrapping_mul(0x846ca68b);
    x ^ (x >> 16)
}

fn logistic_mask(seed: u32, size: usize) -> Vec<u8> {
    let mut x = (seed as f64) / 4_294_967_296.0;
    if x < 1e-9 {
        x = 0.3141592653589793;
    }
    if x > 1.0 - 1e-9 {
        x = 0.2718281828459045;
    }
    let mut out = vec![0u8; size];
    for (i, slot) in out.iter_mut().enumerate() {
        x = LOGISTIC_R * x * (1.0 - x);
        if !(x > 0.0 && x < 1.0) {
            x = 0.5 + (i % 97) as f64 / 200.0;
        }
        *slot = ((x * 256.0).floor() as u32 & 0xff) as u8;
    }
    out
}

fn masks(salt: &[u8; 16], size: usize) -> (Vec<u8>, Vec<u8>, Vec<u8>, u8) {
    let s0 = u32::from_be_bytes([salt[0], salt[1], salt[2], salt[3]]);
    let s1 = u32::from_be_bytes([salt[4], salt[5], salt[6], salt[7]]);
    let s2 = u32::from_be_bytes([salt[8], salt[9], salt[10], salt[11]]);
    let pi = logistic_mask(mix32(PI_SEED, s0), size);
    let phi = logistic_mask(mix32(PHI_SEED, s1), size);
    let log = logistic_mask(mix32(E_SEED, s2), size);
    let prime = PRIMES[salt[12] as usize % PRIMES.len()];
    (pi, phi, log, prime)
}

pub fn fold(data: &[u8], salt: &[u8; 16]) -> Vec<u8> {
    let (pi, phi, log, prime) = masks(salt, data.len());
    let mut out = vec![0u8; data.len()];
    for i in 0..data.len() {
        let mut b = data[i] ^ pi[i];
        b = gf::mul(b, prime);
        b ^= phi[i];
        out[i] = b;
    }
    if out.len() >= 2 {
        let mut i = 0;
        while i + 1 < out.len() {
            out.swap(i, i + 1);
            i += 2;
        }
    }
    for i in 0..out.len() {
        out[i] ^= log[i];
    }
    out
}

pub fn unfold(data: &[u8], salt: &[u8; 16]) -> Vec<u8> {
    let (pi, phi, log, prime) = masks(salt, data.len());
    let mut out = data.to_vec();
    for i in 0..out.len() {
        out[i] ^= log[i];
    }
    if out.len() >= 2 {
        let mut i = 0;
        while i + 1 < out.len() {
            out.swap(i, i + 1);
            i += 2;
        }
    }
    for i in 0..out.len() {
        let mut b = out[i] ^ phi[i];
        b = if b == 0 {
            0
        } else {
            gf::mul(b, gf::inv(prime))
        };
        out[i] = b ^ pi[i];
    }
    out
}
