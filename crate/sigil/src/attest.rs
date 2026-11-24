//! Attest: Ed25519 signature beside a mark (`.sg1.sig`). Not a Ward.

use crate::{sha256, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::path::Path;

pub const SIG_MAGIC: [u8; 4] = *b"SGAT";

pub fn keygen(path: &Path) -> Result<[u8; 32]> {
    let mut seed = zeroize::Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut seed[..]).map_err(|e| crate::Error::Msg(e.to_string()))?;
    // The seed is a secret signing key: owner-only (0600 on Unix), never umask-dependent.
    crate::keys::write_secret_file(path, &seed[..])?;
    Ok(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
}

fn load_seed(path: &Path, pass: Option<&[u8]>) -> Result<[u8; 32]> {
    let b = std::fs::read(path).map_err(|e| crate::Error::Msg(e.to_string()))?;
    // Modern .sgk identity: attest with the Ed25519 half.
    if b.len() >= 8
        && (b[0..4] == *b"SGIK"
            || b[0..4] == crate::passkey::SGKW_MAGIC
            || b[0..4] == crate::passid::SGKP_MAGIC)
    {
        let id = crate::keys::Identity::load_unlocking(path, pass)?;
        return Ok(id.ed25519_seed);
    }
    if b.len() < 32 {
        return Err(crate::Error::Msg(
            "key file too short (need 32 bytes)".into(),
        ));
    }
    let mut s = [0u8; 32];
    s.copy_from_slice(&b[..32]);
    Ok(s)
}

/// Sign `mark` with `key` (raw 32-byte seed or any `.sgk`); writes `<mark>.sig`.
pub fn attest(mark: &Path, key: &Path) -> Result<std::path::PathBuf> {
    attest_unlocking(mark, key, None)
}

/// [`attest`], unlocking a passphrase-protected `key` (`SGKP`) with `pass` when given.
pub fn attest_unlocking(
    mark: &Path,
    key: &Path,
    pass: Option<&[u8]>,
) -> Result<std::path::PathBuf> {
    let seed = zeroize::Zeroizing::new(load_seed(key, pass)?);
    let sk = SigningKey::from_bytes(&seed);
    let hash = sha256(&std::fs::read(mark).map_err(|e| crate::Error::Msg(e.to_string()))?);
    let sig = sk.sign(&hash);
    let mut out = Vec::with_capacity(4 + 32 + 64);
    out.extend_from_slice(&SIG_MAGIC);
    out.extend_from_slice(&sk.verifying_key().to_bytes());
    out.extend_from_slice(&sig.to_bytes());
    let dest = {
        let mut p = mark.as_os_str().to_os_string();
        p.push(".sig");
        std::path::PathBuf::from(p)
    };
    std::fs::write(&dest, out).map_err(|e| crate::Error::Msg(e.to_string()))?;
    Ok(dest)
}

pub fn verify_attestation(mark: &Path) -> Result<String> {
    let mut p = mark.as_os_str().to_os_string();
    p.push(".sig");
    let sigp = std::path::PathBuf::from(p);
    if !sigp.exists() {
        return Ok("attestation: none (no .sig beside this file)".into());
    }
    let b = std::fs::read(&sigp).map_err(|e| crate::Error::Msg(e.to_string()))?;
    if b.len() < 4 + 32 + 64 || b[0..4] != SIG_MAGIC {
        return Ok("attestation: FAILED — not a Sigil .sig".into());
    }
    let pk: [u8; 32] = b[4..36].try_into().map_err(crate::short_field)?;
    let sg: [u8; 64] = b[36..100].try_into().map_err(crate::short_field)?;
    let vk = match VerifyingKey::from_bytes(&pk) {
        Ok(v) => v,
        Err(_) => return Ok("attestation: FAILED — bad public key in .sig".into()),
    };
    let hash = sha256(&std::fs::read(mark).map_err(|e| crate::Error::Msg(e.to_string()))?);
    match vk.verify(&hash, &Signature::from_bytes(&sg)) {
        Ok(()) => Ok(format!("attestation: good  pubkey={}", hex::encode(pk))),
        Err(_) => Ok("attestation: FAILED — file or .sig was changed".into()),
    }
}

/// Any file as a Talisman: 32-byte secret used as the Ward passphrase (hex of sha256).
pub fn talisman_pass(path: &Path) -> Result<String> {
    let b = std::fs::read(path).map_err(|e| crate::Error::Msg(e.to_string()))?;
    if b.is_empty() {
        return Err(crate::Error::Msg("empty talisman".into()));
    }
    Ok(hex::encode(sha256(&b)))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A fresh unique directory under the OS temp dir (created with mode 0700 on Unix,
    /// refusing to reuse an existing path).
    fn fresh_dir(tag: &str) -> std::path::PathBuf {
        let mut r = [0u8; 8];
        getrandom::getrandom(&mut r).unwrap();
        let dir = std::env::temp_dir().join(format!("sigil-attest-{tag}-{}", hex::encode(r)));
        let mut b = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(0o700);
        }
        b.create(&dir).unwrap();
        dir
    }

    /// The raw attest seed is a secret signing key: it must never be group/world readable,
    /// whatever the umask, and re-running keygen over an old 0644 file must tighten it.
    #[cfg(unix)]
    #[test]
    fn legacy_seed_file_is_owner_only_even_over_old_world_readable_file() {
        use std::os::unix::fs::PermissionsExt;
        let dir = fresh_dir("perm");
        let fresh = dir.join("fresh.key");
        keygen(&fresh).unwrap();
        let mode = std::fs::metadata(&fresh).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600, "new seed file must be 0600");

        let old = dir.join("old.key");
        std::fs::write(&old, b"x").unwrap();
        std::fs::set_permissions(&old, std::fs::Permissions::from_mode(0o644)).unwrap();
        keygen(&old).unwrap();
        let mode = std::fs::metadata(&old).unwrap().permissions().mode() & 0o777;
        assert_eq!(
            mode, 0o600,
            "overwritten seed file must be tightened to 0600"
        );
        assert_eq!(std::fs::read(&old).unwrap().len(), 32);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Sign then verify an arbitrary (non-.sg1) report file; any change to it fails.
    #[test]
    fn signed_report_roundtrip_and_tamper_fails() {
        let dir = fresh_dir("rep");
        let key = dir.join("box.key");
        let pk = keygen(&key).unwrap();
        let rep = dir.join("report.txt");
        std::fs::write(
            &rep,
            b"scrub: 1 Sigil(s), 0 repaired, 0 uncorrectable, 1 clean\n",
        )
        .unwrap();
        attest(&rep, &key).unwrap();
        let ok = verify_attestation(&rep).unwrap();
        assert_eq!(ok, format!("attestation: good  pubkey={}", hex::encode(pk)));
        std::fs::write(
            &rep,
            b"scrub: 1 Sigil(s), 0 repaired, 0 uncorrectable, 9 clean\n",
        )
        .unwrap();
        let bad = verify_attestation(&rep).unwrap();
        assert!(bad.starts_with("attestation: FAILED"), "{bad}");
        let _ = std::fs::remove_dir_all(&dir);
    }
}
