//! Attest: Ed25519 signature beside a mark (`.sg1.sig`). Not a Ward.

use crate::{sha256, Result};
use ed25519_dalek::{Signature, Signer, SigningKey, Verifier, VerifyingKey};
use std::path::Path;

pub const SIG_MAGIC: [u8; 4] = *b"SGAT";

pub fn keygen(path: &Path) -> Result<[u8; 32]> {
    let mut seed = [0u8; 32];
    getrandom::getrandom(&mut seed).map_err(|e| crate::Error::Msg(e.to_string()))?;
    std::fs::write(path, seed).map_err(|e| crate::Error::Msg(e.to_string()))?;
    Ok(SigningKey::from_bytes(&seed).verifying_key().to_bytes())
}

fn load_seed(path: &Path) -> Result<[u8; 32]> {
    let b = std::fs::read(path).map_err(|e| crate::Error::Msg(e.to_string()))?;
    // Modern .sgk identity: attest with the Ed25519 half.
    if b.len() >= 8 && (b[0..4] == *b"SGIK" || b[0..4] == crate::passkey::SGKW_MAGIC) {
        let id = crate::keys::Identity::load(path)?;
        return Ok(id.ed25519_seed);
    }
    if b.len() < 32 {
        return Err(crate::Error::Msg("key file too short (need 32 bytes)".into()));
    }
    let mut s = [0u8; 32];
    s.copy_from_slice(&b[..32]);
    Ok(s)
}

pub fn attest(mark: &Path, key: &Path) -> Result<std::path::PathBuf> {
    let seed = load_seed(key)?;
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
    let pk: [u8; 32] = b[4..36].try_into().unwrap();
    let sg: [u8; 64] = b[36..100].try_into().unwrap();
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
