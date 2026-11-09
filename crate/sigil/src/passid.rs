//! Passphrase-protected identity key file (`SGKP` v1).
//!
//! `sigil keygen --pass -` (or `--pass-file F`) writes the secret identity locked under a
//! passphrase instead of in plain bytes. Like the passkey wrapper (`SGKW`), this is an
//! **additive key-file wrapper** around the exact bytes of a plain `.sgk` (v1 native or v2
//! imported): `.sg1` files, SGTO blocks and plain `.sgk` files are unchanged, and builds that
//! predate it refuse an `SGKP` file as "not a Sigil identity" without reading further.
//!
//! Construction (standard primitives only):
//!
//! * Key: Argon2id, version 0x13 (RFC 9106), over the passphrase with a random 16-byte salt.
//!   New files use the OWASP minimum (m = 19 MiB, t = 2, p = 1; [`crate::keys::ARGON2_M_KIB`]);
//!   the parameters are stored in the header and checked against Sigil's reader caps
//!   ([`crate::keys::ARGON2_MAX_M_KIB`] …) **before** any work, so a crafted file cannot make
//!   the reader spend unbounded memory or time.
//! * Seal: AES-256-GCM (NIST SP 800-38D) with a random 96-bit nonce. The whole clear header
//!   (magic, version, KDF id, parameters, salt, public keys, nonce, length) is the associated
//!   data, so changing any header byte makes the unlock fail.
//! * After unlock the inner identity's public keys must equal the clear header copy.
//!
//! Layout (all integers little-endian):
//!
//! ```text
//!   0  4  "SGKP"
//!   4  1  version = 1
//!   5  1  KDF id  = 1 (Argon2id v0x13)
//!   6  2  reserved, must be 0
//!   8  4  Argon2id memory, KiB
//!  12  4  Argon2id passes (t)
//!  16  4  Argon2id lanes (p)
//!  20 16  salt
//!  36 32  X25519 public key
//!  68 32  Ed25519 public key
//! 100 12  AES-GCM nonce
//! 112  4  sealed length N (inner .sgk length + 16-byte tag)
//! 116  N  AES-256-GCM(inner .sgk) || tag      (file length must be exactly 116 + N)
//! ```
//!
//! A wrong passphrase and a damaged file give the same answer (the AEAD tag cannot tell them
//! apart); either way no key is returned.

use crate::keys::{
    argon2_params_ok, argon2id_key, parse_identity, Identity, PublicIdentity, ARGON2_M_KIB,
    ARGON2_P, ARGON2_T, ID_MAGIC,
};
use crate::{Error, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use zeroize::Zeroizing;

/// File magic of a passphrase-protected identity.
pub const SGKP_MAGIC: [u8; 4] = *b"SGKP";
/// The only `SGKP` version this build writes and reads.
pub const SGKP_VERSION: u8 = 1;
/// KDF id for Argon2id v0x13 (RFC 9106).
pub const KDF_ARGON2ID: u8 = 1;
/// Length of the clear header (everything before the sealed identity), which is also the AAD.
pub const SGKP_HEADER_LEN: usize = 116;

const TAG_LEN: usize = 16;
/// Largest inner plain `.sgk` accepted (v1 is 40 bytes, v2 is 92).
const MAX_INNER: usize = 256;

/// Message used for every unlock failure after the header checks pass.
const UNLOCK_FAILED: &str = "wrong passphrase, or the identity file was changed or damaged \
(SGKP check failed); nothing was unlocked";

/// Refused: an empty or all-blank passphrase protects nothing.
const EMPTY: &str =
    "an empty passphrase (or only spaces) is refused: it would not protect anything";

/// True when `b` starts with the `SGKP` magic (it may still be damaged).
pub fn is_pass_protected(b: &[u8]) -> bool {
    b.len() >= 4 && b[0..4] == SGKP_MAGIC
}

/// Argon2id parameters stored in an `SGKP` header.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct KdfParams {
    /// Memory in KiB.
    pub m_kib: u32,
    /// Passes.
    pub t: u32,
    /// Lanes.
    pub p: u32,
}

impl KdfParams {
    /// Defaults for new files (OWASP Argon2id minimum: 19 MiB, 2 passes, 1 lane).
    pub const DEFAULT: KdfParams = KdfParams {
        m_kib: ARGON2_M_KIB,
        t: ARGON2_T,
        p: ARGON2_P,
    };
}

/// What can be read from an `SGKP` file without the passphrase.
#[derive(Clone, Debug)]
pub struct PassInfo {
    /// Public keys (clear copy; authenticated on unlock).
    pub public: PublicIdentity,
    /// Stored Argon2id parameters (already checked against the reader caps).
    pub kdf: KdfParams,
}

fn blank(pass: &[u8]) -> bool {
    pass.iter().all(|b| b.is_ascii_whitespace())
}

fn rand<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|e| Error::Msg(e.to_string()))?;
    Ok(b)
}

fn u32_at(b: &[u8], at: usize) -> Result<u32> {
    Ok(u32::from_le_bytes(
        b.get(at..at + 4)
            .ok_or_else(|| Error::Msg("damaged passphrase identity (SGKP)".into()))?
            .try_into()
            .map_err(crate::short_field)?,
    ))
}

/// Check the clear header and length (no key derivation). Returns the header info and the
/// sealed length. Every refusal here happens before any Argon2id work.
fn check_header(b: &[u8]) -> Result<(PassInfo, usize)> {
    if !is_pass_protected(b) {
        return Err(Error::Msg(
            "not a passphrase-protected identity (SGKP)".into(),
        ));
    }
    if b.len() < 5 {
        return Err(Error::Msg(
            "damaged passphrase identity (SGKP): the file is cut short".into(),
        ));
    }
    if b[4] != SGKP_VERSION {
        return Err(Error::Msg(format!(
            "unsupported passphrase identity version {} (upgrade sigil)",
            b[4]
        )));
    }
    if b.len() < SGKP_HEADER_LEN {
        return Err(Error::Msg(
            "damaged passphrase identity (SGKP): the file is cut short".into(),
        ));
    }
    if b[5] != KDF_ARGON2ID {
        return Err(Error::Msg(format!(
            "passphrase identity uses key-derivation method {} that this sigil does not know \
(upgrade sigil)",
            b[5]
        )));
    }
    if b[6] != 0 || b[7] != 0 {
        return Err(Error::Msg(
            "damaged passphrase identity (SGKP): reserved header bytes are not zero".into(),
        ));
    }
    let kdf = KdfParams {
        m_kib: u32_at(b, 8)?,
        t: u32_at(b, 12)?,
        p: u32_at(b, 16)?,
    };
    argon2_params_ok(kdf.m_kib, kdf.t, kdf.p)?;
    let n = u32_at(b, 112)? as usize;
    if !(TAG_LEN + 4..=TAG_LEN + MAX_INNER).contains(&n) {
        return Err(Error::Msg(
            "damaged passphrase identity (SGKP): sealed length is out of range".into(),
        ));
    }
    if b.len() != SGKP_HEADER_LEN + n {
        return Err(Error::Msg(
            "damaged passphrase identity (SGKP): file length does not match its header \
(cut short, or extra bytes)"
                .into(),
        ));
    }
    let public = PublicIdentity {
        x25519_pk: b[36..68].try_into().map_err(crate::short_field)?,
        ed25519_pk: b[68..100].try_into().map_err(crate::short_field)?,
    };
    Ok((PassInfo { public, kdf }, n))
}

/// Read the public keys and parameters of an `SGKP` file without the passphrase.
pub fn inspect(b: &[u8]) -> Result<PassInfo> {
    Ok(check_header(b)?.0)
}

/// Lock `id` under `pass` with the default Argon2id parameters; returns the `SGKP` bytes.
/// Refuses an empty or all-blank passphrase.
pub fn protect(id: &Identity, pass: &[u8]) -> Result<Vec<u8>> {
    protect_with_params(id, pass, KdfParams::DEFAULT)
}

/// [`protect`] with explicit Argon2id parameters (must pass the same caps readers enforce).
pub fn protect_with_params(id: &Identity, pass: &[u8], kdf: KdfParams) -> Result<Vec<u8>> {
    if blank(pass) {
        return Err(Error::Msg(EMPTY.into()));
    }
    argon2_params_ok(kdf.m_kib, kdf.t, kdf.p)?;
    let inner = Zeroizing::new(id.to_bytes());
    if inner.len() > MAX_INNER {
        return Err(Error::Msg("identity too large for SGKP".into()));
    }
    let salt: [u8; 16] = rand()?;
    let nonce: [u8; 12] = rand()?;
    let public = id.public();
    let mut out = Vec::with_capacity(SGKP_HEADER_LEN + inner.len() + TAG_LEN);
    out.extend_from_slice(&SGKP_MAGIC);
    out.push(SGKP_VERSION);
    out.push(KDF_ARGON2ID);
    out.extend_from_slice(&[0, 0]);
    out.extend_from_slice(&kdf.m_kib.to_le_bytes());
    out.extend_from_slice(&kdf.t.to_le_bytes());
    out.extend_from_slice(&kdf.p.to_le_bytes());
    out.extend_from_slice(&salt);
    out.extend_from_slice(&public.x25519_pk);
    out.extend_from_slice(&public.ed25519_pk);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&((inner.len() + TAG_LEN) as u32).to_le_bytes());
    debug_assert_eq!(out.len(), SGKP_HEADER_LEN);
    let key = argon2id_key(pass, &salt, kdf.m_kib, kdf.t, kdf.p)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|e| Error::Msg(e.to_string()))?;
    let sealed = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &inner,
                aad: &out,
            },
        )
        .map_err(|_| Error::Msg("AES-GCM seal failed".into()))?;
    // Prove it opens (same key, no second Argon2id run) before anyone writes it to disk.
    let back = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &sealed,
                aad: &out,
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Msg("SGKP self-check failed".into()))?;
    if back.as_slice() != inner.as_slice() {
        return Err(Error::Msg("SGKP self-check failed".into()));
    }
    out.extend_from_slice(&sealed);
    Ok(out)
}

/// Unlock `SGKP` bytes with `pass`. Header, length and Argon2id parameter checks run first;
/// a wrong passphrase or any changed byte fails closed and returns no key.
pub fn unlock(b: &[u8], pass: &[u8]) -> Result<Identity> {
    let (info, n) = check_header(b)?;
    if blank(pass) {
        return Err(Error::Msg(EMPTY.into()));
    }
    let salt: [u8; 16] = b[20..36].try_into().map_err(crate::short_field)?;
    let nonce: [u8; 12] = b[100..112].try_into().map_err(crate::short_field)?;
    let key = argon2id_key(pass, &salt, info.kdf.m_kib, info.kdf.t, info.kdf.p)?;
    let cipher = Aes256Gcm::new_from_slice(key.as_ref()).map_err(|e| Error::Msg(e.to_string()))?;
    let inner = cipher
        .decrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &b[SGKP_HEADER_LEN..SGKP_HEADER_LEN + n],
                aad: &b[..SGKP_HEADER_LEN],
            },
        )
        .map(Zeroizing::new)
        .map_err(|_| Error::Msg(UNLOCK_FAILED.into()))?;
    if inner.len() < 4 || inner[0..4] != ID_MAGIC {
        return Err(Error::Msg(
            "passphrase identity holds no plain .sgk inside".into(),
        ));
    }
    let id = parse_identity(&inner)?;
    let p = id.public();
    if p.x25519_pk != info.public.x25519_pk || p.ed25519_pk != info.public.ed25519_pk {
        return Err(Error::Msg(
            "passphrase identity public keys do not match its contents".into(),
        ));
    }
    Ok(id)
}

/// Ask for the passphrase of `shown` on the terminal (hidden), or fail closed when there is
/// no terminal to ask on.
pub(crate) fn prompt_unlock(b: &[u8], shown: &str) -> Result<Identity> {
    use std::io::IsTerminal;
    // Header problems are reported before asking for anything.
    check_header(b)?;
    if !(std::io::stdin().is_terminal() && std::io::stderr().is_terminal()) {
        return Err(Error::Msg(
            "this identity is passphrase-protected and there is no terminal here to ask for the \
passphrase (input is piped or redirected); give --identity-pass-file PATH (a file only you can \
read). Nothing was unlocked"
                .into(),
        ));
    }
    let pass = Zeroizing::new(
        rpassword::prompt_password(format!("Passphrase for {shown}: ")).map_err(|e| {
            Error::Msg(format!(
                "could not read a passphrase from the terminal ({e})"
            ))
        })?,
    );
    unlock(b, pass.as_bytes())
}

#[cfg(test)]
mod tests {
    use super::*;

    const FAST: KdfParams = KdfParams {
        m_kib: 64,
        t: 1,
        p: 1,
    };

    fn native() -> Identity {
        Identity::generate().unwrap()
    }

    #[test]
    fn round_trip_default_params_native_and_raw() {
        let id = native();
        let b = protect(&id, b"correct horse").unwrap();
        assert_eq!(&b[0..4], b"SGKP");
        assert_eq!(b.len(), SGKP_HEADER_LEN + 40 + 16);
        let info = inspect(&b).unwrap();
        assert_eq!(info.kdf, KdfParams::DEFAULT);
        assert_eq!(info.public.x25519_pk, id.public().x25519_pk);
        let back = unlock(&b, b"correct horse").unwrap();
        assert_eq!(back.master, id.master);
        assert_eq!(back.ed25519_seed, id.ed25519_seed);

        let raw = Identity::from_raw([7u8; 32], [9u8; 32], Some([3u8; 20]));
        let b = protect_with_params(&raw, b"pw", FAST).unwrap();
        let back = unlock(&b, b"pw").unwrap();
        assert_eq!(back.x25519_sk, raw.x25519_sk);
        assert_eq!(back.pgp_fpr, Some([3u8; 20]));
    }

    #[test]
    fn two_protects_differ_salt_and_nonce() {
        let id = native();
        let a = protect_with_params(&id, b"pw", FAST).unwrap();
        let b = protect_with_params(&id, b"pw", FAST).unwrap();
        assert_ne!(a[20..36], b[20..36]);
        assert_ne!(a[100..112], b[100..112]);
        assert_ne!(a[SGKP_HEADER_LEN..], b[SGKP_HEADER_LEN..]);
    }

    #[test]
    fn wrong_and_empty_passphrase_refused() {
        let id = native();
        let b = protect_with_params(&id, b"right", FAST).unwrap();
        let e = unlock(&b, b"wrong").err().unwrap().to_string();
        assert!(e.contains("wrong passphrase"), "{e}");
        for empty in [&b""[..], b"   ", b"\t\n"] {
            let e = unlock(&b, empty).err().unwrap().to_string();
            assert!(e.contains("empty passphrase"), "{e}");
            let e = protect(&id, empty).err().unwrap().to_string();
            assert!(e.contains("empty passphrase"), "{e}");
        }
    }

    #[test]
    fn truncation_and_extension_refused() {
        let id = native();
        let b = protect_with_params(&id, b"pw", FAST).unwrap();
        for cut in [0, 3, 4, 5, 6, 20, 64, 111, 115, 116, 117, 140, b.len() - 1] {
            assert!(unlock(&b[..cut], b"pw").is_err(), "cut at {cut}");
        }
        let mut longer = b.clone();
        longer.push(0);
        let e = unlock(&longer, b"pw").err().unwrap().to_string();
        assert!(e.contains("length does not match"), "{e}");
    }

    #[test]
    fn every_bit_flip_fails_closed() {
        let id = native();
        let b = protect_with_params(&id, b"pw", FAST).unwrap();
        for i in 0..b.len() {
            for bit in [0u8, 3, 7] {
                let mut t = b.clone();
                t[i] ^= 1 << bit;
                assert!(unlock(&t, b"pw").is_err(), "flip byte {i} bit {bit} opened");
            }
        }
    }

    #[test]
    fn region_errors_are_clear() {
        let id = native();
        let b = protect_with_params(&id, b"pw", FAST).unwrap();
        let err = |f: &dyn Fn(&mut Vec<u8>)| {
            let mut t = b.clone();
            f(&mut t);
            unlock(&t, b"pw").err().unwrap().to_string()
        };
        assert!(err(&|t| t[4] = 2).contains("unsupported passphrase identity version 2"));
        assert!(err(&|t| t[5] = 9).contains("key-derivation method 9"));
        assert!(err(&|t| t[6] = 1).contains("reserved header bytes"));
        // salt, public keys, nonce, sealed body, tag: AEAD refuses.
        for i in [20, 40, 80, 105, 120, b.len() - 1] {
            assert!(
                err(&|t| t[i] ^= 0x10).contains("wrong passphrase"),
                "byte {i}"
            );
        }
        // Lowering t keeps parameters in bounds but changes the key: AEAD refuses.
        assert!(err(&|t| t[12] = 2).contains("wrong passphrase"));
        assert!(err(&|t| t[112] ^= 1).contains("length"));
    }

    #[test]
    fn huge_argon2_params_refused_before_work() {
        let id = native();
        let b = protect_with_params(&id, b"pw", FAST).unwrap();
        let set = |at: usize, v: u32| {
            let mut t = b.clone();
            t[at..at + 4].copy_from_slice(&v.to_le_bytes());
            t
        };
        let start = std::time::Instant::now();
        for t in [
            set(8, u32::MAX),      // memory
            set(8, (1 << 20) + 1), // just over 1 GiB
            set(12, u32::MAX),     // passes
            set(16, 9),            // lanes
            set(16, u32::MAX),     // lanes: 8p must not overflow
            set(12, 0),            // below RFC 9106 minimum
            set(16, 0),
            set(8, 4), // m < 8p
        ] {
            let e = unlock(&t, b"pw").err().unwrap().to_string();
            assert!(e.contains("Argon2id wrap parameters rejected"), "{e}");
            assert!(inspect(&t).is_err());
        }
        // Work budget: 256 MiB x 17 passes is over 2^22 KiB-passes (and over the pass cap).
        let mut t = set(8, 1 << 18);
        t[12..16].copy_from_slice(&17u32.to_le_bytes());
        assert!(unlock(&t, b"pw").is_err());
        let mut t = set(8, 1 << 20);
        t[12..16].copy_from_slice(&5u32.to_le_bytes());
        let e = unlock(&t, b"pw").err().unwrap().to_string();
        assert!(e.contains("work budget"), "{e}");
        assert!(start.elapsed() < std::time::Duration::from_secs(5));
        assert!(protect_with_params(
            &id,
            b"pw",
            KdfParams {
                m_kib: u32::MAX,
                t: 1,
                p: 1
            }
        )
        .is_err());
    }

    #[test]
    fn swapped_inner_refused() {
        // A header from one identity with the body of another fails (AAD covers the keys).
        let a = protect_with_params(&native(), b"pw", FAST).unwrap();
        let b = protect_with_params(&native(), b"pw", FAST).unwrap();
        let mut mix = a[..SGKP_HEADER_LEN].to_vec();
        mix.extend_from_slice(&b[SGKP_HEADER_LEN..]);
        assert!(unlock(&mix, b"pw").is_err());
    }
}
