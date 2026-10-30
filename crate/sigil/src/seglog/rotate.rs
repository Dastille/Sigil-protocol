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

#[derive(Clone, Debug)]
pub struct AddSignerReport {
    /// The newly pinned Ed25519 signer.
    pub signer: [u8; 32],
    /// Entries already in the log when the signer was added (written unsigned); the new signed
    /// HEAD covers exactly these.
    pub covered: u64,
    /// Root of the new HEAD (signed by the new key).
    pub root: [u8; 32],
    pub notes: Vec<String>,
}

/// Pin a first Ed25519 signer on a log that was created unsigned (`sigil log add-signer`).
///
/// The new key signs the HEAD covering every entry already in the log (its attestation of the
/// state at that point), then the manifest pins it (`signer=`, plus `signer-added=<n>` recording
/// how many entries predate it). From then on the log behaves exactly like one signed at `init`.
/// No INDEX line and no new crypto: HEAD signing is the existing `make_head` / Ed25519 path.
///
/// Crash order: signed HEAD first (harmless in an unsigned log), then the manifest (the commit
/// point). A crash before the manifest leaves the log unsigned; run it again.
pub fn add_signer(path: &Path, identity: &Identity) -> Result<AddSignerReport> {
    let mut log = Log::open(path)?;
    if log.signer.is_some() {
        return Err(err(
            "this log is already signed: to move it to another key use `sigil log rotate-signer --identity CURRENT.sgk --new NEW.pub`",
        ));
    }
    let _guard = lock(&log)?;
    // Re-read the manifest under the lock: another writer may have pinned a signer meanwhile.
    let mut m = container::read_manifest(&log.dir)?;
    if m.extra.contains_key("signer") {
        return Err(err(
            "this log is already signed: to move it to another key use `sigil log rotate-signer`",
        ));
    }
    let (idx, notes) = prepare_write(&log)?;
    if idx.entries.iter().any(|e| e.is_handover()) {
        return Err(err(
            "INDEX holds a signer handover but the log is unsigned; refusing (run `sigil log verify`)",
        ));
    }
    let sk = SigningKey::from_bytes(&identity.ed25519_seed);
    let pk = sk.verifying_key().to_bytes();
    let head = commit_head(&log, &idx.entries, Some(identity))?;
    m.extra.insert("signer".into(), hex32(&pk));
    m.extra
        .insert("signer-added".into(), idx.entries.len().to_string());
    container::write_manifest(&log.dir, &m)?;
    log.signer = Some(pk);
    Ok(AddSignerReport {
        signer: pk,
        covered: idx.entries.len() as u64,
        root: head.root,
        notes,
    })
}
