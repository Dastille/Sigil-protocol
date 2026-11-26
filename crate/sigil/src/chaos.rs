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

/// The logistic-map byte stream of [`logistic_mask`], one byte at a time (same bytes, no
/// buffer of the whole length).
struct Logistic {
    x: f64,
    i: usize,
}

impl Logistic {
    fn new(seed: u32) -> Self {
        let mut x = (seed as f64) / 4_294_967_296.0;
        if x < 1e-9 {
            x = 0.3141592653589793;
        }
        if x > 1.0 - 1e-9 {
            x = 0.2718281828459045;
        }
        Logistic { x, i: 0 }
    }

    fn next_byte(&mut self) -> u8 {
        let mut x = LOGISTIC_R * self.x * (1.0 - self.x);
        if !(x > 0.0 && x < 1.0) {
            x = 0.5 + (self.i % 97) as f64 / 200.0;
        }
        self.x = x;
        self.i += 1;
        ((x * 256.0).floor() as u32 & 0xff) as u8
    }
}

/// [`unfold`] a piece at a time, for checking a big payload without holding it (or its three
/// masks) in memory. Feed consecutive pieces of even length (only the last may be odd); the
/// concatenated output equals `unfold(whole, salt)`.
pub struct Unfolder {
    pi: Logistic,
    phi: Logistic,
    log: Logistic,
    inv_prime: u8,
}

impl Unfolder {
    /// Start unfolding a payload sealed with `salt`.
    pub fn new(salt: &[u8; 16]) -> Self {
        let s0 = u32::from_be_bytes([salt[0], salt[1], salt[2], salt[3]]);
        let s1 = u32::from_be_bytes([salt[4], salt[5], salt[6], salt[7]]);
        let s2 = u32::from_be_bytes([salt[8], salt[9], salt[10], salt[11]]);
        let prime = PRIMES[salt[12] as usize % PRIMES.len()];
        Unfolder {
            pi: Logistic::new(mix32(PI_SEED, s0)),
            phi: Logistic::new(mix32(PHI_SEED, s1)),
            log: Logistic::new(mix32(E_SEED, s2)),
            inv_prime: gf::inv(prime),
        }
    }

    /// Unfold the next piece into `out` (cleared first).
    pub fn feed(&mut self, data: &[u8], out: &mut Vec<u8>) {
        out.clear();
        out.extend(data.iter().map(|b| b ^ self.log.next_byte()));
        let mut i = 0;
        while i + 1 < out.len() {
            out.swap(i, i + 1);
            i += 2;
        }
        for b in out.iter_mut() {
            let v = *b ^ self.phi.next_byte();
            let v = if v == 0 {
                0
            } else {
                gf::mul(v, self.inv_prime)
            };
            *b = v ^ self.pi.next_byte();
        }
    }
}

/// [`fold`] a piece at a time, for sealing a big payload without holding it (or its three
/// masks) in memory. Feed consecutive pieces of even length (only the last may be odd); the
/// concatenated output equals `fold(whole, salt)`.
pub struct Folder {
    pi: Logistic,
    phi: Logistic,
    log: Logistic,
    prime: u8,
}

impl Folder {
    /// Start folding a payload sealed with `salt`.
    pub fn new(salt: &[u8; 16]) -> Self {
        let s0 = u32::from_be_bytes([salt[0], salt[1], salt[2], salt[3]]);
        let s1 = u32::from_be_bytes([salt[4], salt[5], salt[6], salt[7]]);
        let s2 = u32::from_be_bytes([salt[8], salt[9], salt[10], salt[11]]);
        Folder {
            pi: Logistic::new(mix32(PI_SEED, s0)),
            phi: Logistic::new(mix32(PHI_SEED, s1)),
            log: Logistic::new(mix32(E_SEED, s2)),
            prime: PRIMES[salt[12] as usize % PRIMES.len()],
        }
    }

    /// Fold `data` in place (the next piece of the payload).
    pub fn fold_in_place(&mut self, data: &mut [u8]) {
        for b in data.iter_mut() {
            let v = gf::mul(*b ^ self.pi.next_byte(), self.prime);
            *b = v ^ self.phi.next_byte();
        }
        let mut i = 0;
        while i + 1 < data.len() {
            data.swap(i, i + 1);
            i += 2;
        }
        for b in data.iter_mut() {
            *b ^= self.log.next_byte();
        }
    }
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

#[cfg(test)]
mod unfolder_tests {
    use super::*;

    #[test]
    fn chunked_unfold_matches_whole() {
        let salts: [[u8; 16]; 3] = [[0u8; 16], [0xff; 16], *b"0123456789abcdef"];
        for salt in salts {
            for len in [0usize, 1, 2, 3, 97, 1000, 4097] {
                let data: Vec<u8> = (0..len).map(|i| (i * 31 + 7) as u8).collect();
                let whole = unfold(&data, &salt);
                for chunk in [2usize, 6, 64, 4096] {
                    let mut u = Unfolder::new(&salt);
                    let mut got = Vec::new();
                    let mut buf = Vec::new();
                    for piece in data.chunks(chunk) {
                        u.feed(piece, &mut buf);
                        got.extend_from_slice(&buf);
                    }
                    assert_eq!(got, whole, "len {len} chunk {chunk}");
                }
                assert_eq!(unfold(&fold(&data, &salt), &salt), data);
                let folded = fold(&data, &salt);
                for chunk in [2usize, 6, 64, 4096] {
                    let mut f = Folder::new(&salt);
                    let mut got = data.clone();
                    for piece in got.chunks_mut(chunk) {
                        f.fold_in_place(piece);
                    }
                    assert_eq!(got, folded, "fold len {len} chunk {chunk}");
                }
            }
        }
    }
}
