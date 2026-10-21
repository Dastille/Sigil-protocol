//! `sigil log rotate-signer`: hand a signed log over to a new Ed25519 signer. See "Signer
//! rotation" in `docs/SEGMENT-LOG.md`.
//!
//! The outgoing signer appends one chain-covered `op=signer` entry naming the new key, with its own
//! signature over a handover statement (log-id, the entry's seq, both keys), and signs the HEAD that
//! covers it. Every later HEAD must be signed by the new key. `CONTAINER`'s `signer=` stays the key
//! pinned at `init` (the root of the chain); `verify`, `prove` and `check-proof` follow the
//! handovers from it. Additive: the manifest goes to `log=4` only when the first handover is
//! written; a log that is never rotated is untouched.

use super::*;

#[derive(Clone, Debug)]
pub struct RotateReport {
    /// Seq of the handover entry.
    pub entry: u64,
    pub from: [u8; 32],
    pub to: [u8; 32],
    /// Root of the new HEAD (covers the handover; signed by `from`).
    pub root: [u8; 32],
    /// Handover entries in the log now (this one included).
    pub handovers: usize,
    pub notes: Vec<String>,
}

/// Hand the signed log at `path` over from `identity` (its current signer) to the Ed25519 public
/// key `new`. Needs only the new signer's public key.
pub fn rotate_signer(path: &Path, identity: &Identity, new: [u8; 32]) -> Result<RotateReport> {
    let mut log = Log::open(path)?;
    if log.signer.is_none() {
        return Err(err(
            "this log was created unsigned (no --identity at init): there is no signer to hand over \
             (adding a signer to an unsigned log is not supported; start a signed log with `sigil log init --identity`)",
        ));
    }
    // a real, canonically encoded key that is not of small order (no one could sign for it otherwise)
    match VerifyingKey::from_bytes(&new) {
        Ok(vk) if vk.to_edwards().compress().to_bytes() == new && !vk.is_weak() => {}
        _ => return Err(err("--new is not a valid Ed25519 public key")),
    }
    signer_gate(&log, Some(identity))?;
    let _guard = lock(&log)?;
    let (idx, notes) = prepare_write(&log)?;
    signer_gate_at(&log, &idx.entries, Some(identity))?;
    let sk = SigningKey::from_bytes(&identity.ed25519_seed);
    let from = sk.verifying_key().to_bytes();
    if new == from {
        return Err(err("--new is already this log's signer"));
    }
    let seq = idx.entries.len() as u64 + 1;
    let sig = sk
        .sign(&handover_message(&log.id, seq, &from, &new))
        .to_bytes();
    let body = format!(
        "seq={seq} t={} op=signer from={} to={} sig={}",
        now(),
        hex32(&from),
        hex32(&new),
        hex::encode(sig)
    );
    // The manifest goes first: an older sigil must refuse this log before it can see the line.
    raise_format(&mut log, 4)?;
    let (entries, head) = commit(&log, idx, &[body], Some(identity))?;
    let handovers = entries.iter().filter(|e| e.is_handover()).count();
    Ok(RotateReport {
        entry: seq,
        from,
        to: new,
        root: head.root,
        handovers,
        notes,
    })
}
