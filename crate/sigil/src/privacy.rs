//! Private label for new encrypted seals (header version 3).
//!
//! A v1/v2 encrypted seal carried the original file's name, SHA-256, exact
//! size, compressed size and entropy score in the clear on its outer label
//! (header, keystone copies and every ember). A **v3** seal moves all of them
//! inside the AES-256-GCM ciphertext as an *inner block* and leaves the outer
//! label with only what repair needs (geometry, ciphertext length, salt, nonce,
//! tag, Merkle root of the ciphertext shards).
//!
//! * The outer label is fed to AES-256-GCM as associated data ([`label_aad`]),
//!   so editing any field fails closed when the seal is opened. The three
//!   fields that are computed after encryption (tag, Merkle root, CRC) are
//!   bound separately: the tag by GCM itself, the Merkle root by re-encoding
//!   the decrypted-to ciphertext and comparing (see `lib.rs`).
//! * The outer `digest` slot holds a **keyed fingerprint** ([`keyed_fingerprint`]):
//!   HMAC-SHA-256 (RFC 2104) of the original bytes under a key derived with
//!   HKDF-SHA-256 (RFC 5869) from the file key (per file, the default) or from
//!   a caller-supplied dedupe secret (opt-in, vault-wide). Without the key it
//!   cannot be tested against a guessed file.
//! * Repair and mend never needed the plaintext hash for encrypted seals: they
//!   gate on the Merkle root of the ciphertext shards, which stays outside.
//!
//! No new cryptography: AES-256-GCM, SHA-256, HMAC-SHA-256 and HKDF-SHA-256
//! are the primitives the crate already used.

use crate::{Error, Result};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;

/// Header version for new encrypted seals with the private label.
pub const PRIVATE_VERSION: u8 = 3;
const INNER_MAGIC: [u8; 4] = *b"SGIN";
const INNER_VERSION: u8 = 1;
/// Fixed part of the inner block (before the name bytes).
pub const INNER_FIXED: usize = 72;
const FP_INFO: &[u8] = b"sigil v3 keyed fingerprint";
const DEDUPE_SALT: &[u8] = b"sigil v3 shared dedupe";
const AAD_DOMAIN: &[u8] = b"sigil v3 label\0";

const IF_COMPRESSED: u8 = 1;
const IF_SHARED_FP: u8 = 2;

/// Which key the keyed fingerprint is made with.
#[derive(Clone, Default)]
pub enum FingerprintKey {
    /// Derived from this file's own content key: unlinkable across files (default).
    #[default]
    PerFile,
    /// Derived from a shared secret (e.g. one vault): equal files under the same
    /// secret get equal fingerprints, so they can be deduplicated, and so a
    /// stranger can also see that two such files are equal. Opt-in only.
    Shared([u8; 32]),
}

/// Opt-in size hiding (see `docs` / `public/sigil-v1.txt`). Never on by default.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum Pad {
    /// No padding (default): ciphertext length ≈ compressed size + inner block.
    #[default]
    Off,
    /// Round up to a bucket: next multiple of 1/16 of the power of two below
    /// the size (≤ ~6.25 % extra), 4 KiB floor.
    Bucket,
    /// Round up to the next power of two (≤ 100 % extra), 4 KiB floor.
    Pow2,
}

impl Pad {
    pub fn parse(s: &str) -> Result<Pad> {
        match s {
            "off" | "none" => Ok(Pad::Off),
            "bucket" | "buckets" => Ok(Pad::Bucket),
            "max" | "pow2" => Ok(Pad::Pow2),
            _ => Err(Error::Msg(format!(
                "unknown --pad {s:?} (off | bucket | max)"
            ))),
        }
    }
}

/// Floor for padded sizes.
pub const PAD_FLOOR: u64 = 4096;

/// Padded length for `len` bytes under `pad` (never smaller than `len`).
pub fn padded_len(len: u64, pad: Pad) -> u64 {
    match pad {
        Pad::Off => len,
        _ if len <= PAD_FLOOR => PAD_FLOOR,
        Pad::Pow2 => len.checked_next_power_of_two().unwrap_or(len),
        Pad::Bucket => {
            // Largest power of two <= len, then steps of 1/16 of it.
            let below = 1u64 << (63 - len.leading_zeros());
            let step = (below / 16).max(1);
            len.div_ceil(step).saturating_mul(step)
        }
    }
}

/// Seal-time options for the private label (v3 encrypted seals).
#[derive(Clone, Default)]
pub struct SealOpts {
    pub fingerprint: FingerprintKey,
    pub pad: Pad,
    /// Large-file packs: total original size of the whole pack, recorded inside
    /// the first chunk's ciphertext (0 = not a pack's first chunk).
    pub group_total: u64,
}

/// What the private label says, available only after unlock.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealMeta {
    pub name: String,
    pub orig_len: u64,
    /// SHA-256 of the original bytes.
    pub digest: [u8; 32],
    /// Length of the (maybe deflated) body before folding and padding.
    pub body_len: u64,
    pub entropy_milli: u32,
    pub compressed: bool,
    /// Whole-pack size for a pack's first chunk (0 otherwise).
    pub group_total: u64,
    /// Keyed fingerprint was made with a shared (dedupe) secret.
    pub shared_fingerprint: bool,
    /// Padding bytes after the body.
    pub pad_len: u64,
}

/// HKDF-SHA-256 (RFC 5869) key for the keyed fingerprint.
pub fn fingerprint_key(
    cek: &[u8; 32],
    salt: &[u8; 16],
    which: &FingerprintKey,
) -> Result<[u8; 32]> {
    let hk = match which {
        FingerprintKey::PerFile => Hkdf::<Sha256>::new(Some(salt), cek),
        FingerprintKey::Shared(secret) => Hkdf::<Sha256>::new(Some(DEDUPE_SALT), secret),
    };
    let mut okm = [0u8; 32];
    hk.expand(FP_INFO, &mut okm)
        .map_err(|_| Error::Msg("HKDF expand failed".into()))?;
    Ok(okm)
}

/// HMAC-SHA-256 (RFC 2104) of `data` under a [`fingerprint_key`].
pub fn keyed_fingerprint(key: &[u8; 32], data: &[u8]) -> Result<[u8; 32]> {
    let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key)
        .map_err(|_| Error::Msg("HMAC key rejected".into()))?;
    mac.update(data);
    Ok(mac.finalize().into_bytes().into())
}

/// Keyed fingerprint a shared dedupe secret gives `data` (vault dedupe checks).
pub fn shared_fingerprint(secret: &[u8; 32], data: &[u8]) -> Result<[u8; 32]> {
    let k = fingerprint_key(&[0u8; 32], &[0u8; 16], &FingerprintKey::Shared(*secret))?;
    keyed_fingerprint(&k, data)
}

/// Associated data for a v3 label: the 160-byte header with the post-encryption
/// fields (tag 84..100, shard length 100..104, ember index/entropy + CRC 104..112,
/// Merkle 128..160) zeroed. Shard length is a function of the ciphertext length
/// and `k`; the Merkle check on open binds it with the rest.
pub fn label_aad(header: &[u8]) -> Result<Vec<u8>> {
    let h = header
        .get(..crate::header::HEADER_SIZE)
        .ok_or_else(|| Error::Msg("truncated header".into()))?;
    let mut aad = Vec::with_capacity(AAD_DOMAIN.len() + h.len());
    aad.extend_from_slice(AAD_DOMAIN);
    aad.extend_from_slice(h);
    let base = AAD_DOMAIN.len();
    aad[base..base + 4].copy_from_slice(b"SGIL");
    aad[base + 84..base + 112].fill(0);
    aad[base + 128..base + 160].fill(0);
    Ok(aad)
}

/// Serialise the inner block that leads the plaintext under AES-256-GCM.
pub fn write_inner(m: &SealMeta) -> Vec<u8> {
    let nb = m.name.as_bytes();
    let nlen = nb.len().min(u16::MAX as usize);
    let mut b = Vec::with_capacity(INNER_FIXED + nlen);
    b.extend_from_slice(&INNER_MAGIC);
    b.push(INNER_VERSION);
    let mut fl = 0u8;
    if m.compressed {
        fl |= IF_COMPRESSED;
    }
    if m.shared_fingerprint {
        fl |= IF_SHARED_FP;
    }
    b.push(fl);
    b.extend_from_slice(&(nlen as u16).to_le_bytes());
    b.extend_from_slice(&m.orig_len.to_le_bytes());
    b.extend_from_slice(&m.body_len.to_le_bytes());
    b.extend_from_slice(&m.digest);
    b.extend_from_slice(&m.entropy_milli.to_le_bytes());
    b.extend_from_slice(&m.group_total.to_le_bytes());
    b.extend_from_slice(&[0u8; 4]);
    b.extend_from_slice(&nb[..nlen]);
    b
}

fn u64_at(b: &[u8], at: usize) -> Result<u64> {
    b.get(at..at + 8)
        .and_then(|w| <[u8; 8]>::try_from(w).ok())
        .map(u64::from_le_bytes)
        .ok_or_else(|| Error::Msg("truncated inner block".into()))
}

/// Parse the inner block at the start of decrypted bytes. Returns the metadata and
/// the offset of the body. Padding after the body must be zero.
pub fn read_inner(plain: &[u8]) -> Result<(SealMeta, usize)> {
    let bad = |s: &str| Error::Msg(format!("private label: {s}"));
    if plain.len() < INNER_FIXED || plain[0..4] != INNER_MAGIC {
        return Err(bad("inner block missing"));
    }
    if plain[4] != INNER_VERSION {
        return Err(bad("unknown inner block version"));
    }
    let fl = plain[5];
    let nlen = u16::from_le_bytes([plain[6], plain[7]]) as usize;
    let orig_len = u64_at(plain, 8)?;
    let body_len = u64_at(plain, 16)?;
    let mut digest = [0u8; 32];
    digest.copy_from_slice(&plain[24..56]);
    let entropy_milli = u32::from_le_bytes([plain[56], plain[57], plain[58], plain[59]]);
    let group_total = u64_at(plain, 60)?;
    let body_off = INNER_FIXED
        .checked_add(nlen)
        .filter(|&o| o <= plain.len())
        .ok_or_else(|| bad("name runs past the end"))?;
    let name = String::from_utf8(plain[INNER_FIXED..body_off].to_vec())
        .map_err(|_| bad("name is not UTF-8"))?;
    let body_end = usize::try_from(body_len)
        .ok()
        .and_then(|l| body_off.checked_add(l))
        .filter(|&e| e <= plain.len())
        .ok_or_else(|| bad("body runs past the end"))?;
    if plain[body_end..].iter().any(|&b| b != 0) {
        return Err(bad("padding is not zero"));
    }
    Ok((
        SealMeta {
            name,
            orig_len,
            digest,
            body_len,
            entropy_milli,
            compressed: fl & IF_COMPRESSED != 0,
            group_total,
            shared_fingerprint: fl & IF_SHARED_FP != 0,
            pad_len: (plain.len() - body_end) as u64,
        },
        body_off,
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn pad_rules() {
        assert_eq!(padded_len(10, Pad::Off), 10);
        assert_eq!(padded_len(10, Pad::Bucket), 4096);
        assert_eq!(padded_len(4097, Pad::Pow2), 8192);
        // 9 MiB + 1 → next 0.5 MiB step above 9 MiB.
        let m = 1u64 << 20;
        assert_eq!(padded_len(9 * m + 1, Pad::Bucket), 9 * m + m / 2);
        for len in [4097u64, 5000, 65_537, 3 * m + 7, 1 << 33] {
            let b = padded_len(len, Pad::Bucket);
            assert!(
                b >= len && (b - len) * 16 <= len,
                "bucket ≤ 1/16 extra for {len}"
            );
            let p = padded_len(len, Pad::Pow2);
            assert!(p >= len && p.is_power_of_two());
        }
    }

    #[test]
    fn inner_round_trip_and_rejects() {
        let m = SealMeta {
            name: "secret-name.pdf".into(),
            orig_len: 1234,
            digest: [7u8; 32],
            body_len: 3,
            entropy_milli: 4000,
            compressed: true,
            group_total: 99,
            shared_fingerprint: false,
            pad_len: 0,
        };
        let mut b = write_inner(&m);
        b.extend_from_slice(b"abc");
        let (got, off) = read_inner(&b).unwrap();
        assert_eq!(got, m);
        assert_eq!(&b[off..], b"abc");
        let mut padded = b.clone();
        padded.extend_from_slice(&[0, 0]);
        assert_eq!(read_inner(&padded).unwrap().0.pad_len, 2);
        padded.push(1);
        assert!(read_inner(&padded).is_err(), "non-zero padding");
        assert!(read_inner(&b[..b.len() - 1]).is_err(), "short body");
        assert!(read_inner(&b[..10]).is_err());
    }

    #[test]
    fn keyed_fingerprints_differ_by_key() {
        let a = fingerprint_key(&[1u8; 32], &[2u8; 16], &FingerprintKey::PerFile).unwrap();
        let b = fingerprint_key(&[1u8; 32], &[3u8; 16], &FingerprintKey::PerFile).unwrap();
        assert_ne!(
            keyed_fingerprint(&a, b"x").unwrap(),
            keyed_fingerprint(&b, b"x").unwrap()
        );
        let s1 = shared_fingerprint(&[9u8; 32], b"x").unwrap();
        let k =
            fingerprint_key(&[5u8; 32], &[6u8; 16], &FingerprintKey::Shared([9u8; 32])).unwrap();
        assert_eq!(
            s1,
            keyed_fingerprint(&k, b"x").unwrap(),
            "shared ignores file key"
        );
        assert_ne!(s1, crate::sha256(b"x"));
    }
}
