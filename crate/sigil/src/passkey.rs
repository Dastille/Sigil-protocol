//! Passkey unlock for `.sgk` identities (FIDO2 `hmac-secret` / WebAuthn PRF).
//!
//! A passkey-protected identity is an **additive key-file wrapper** (`SGKW`) around the
//! exact bytes of a plain `.sgk` (v1 native or v2 imported). `.sg1` marks, SGTO blocks and
//! plain `.sgk` files are untouched; old builds simply refuse an `SGKW` file as "not a
//! Sigil identity".
//!
//! Construction (standard primitives only):
//!
//! * A random 32-byte data key (DEK) seals the inner `.sgk` with AES-256-GCM
//!   (AAD = the clear wrapper header, which carries the public keys).
//! * Each passkey slot evaluates the authenticator PRF: CTAP2 `hmac-secret` with
//!   `salt = SHA-256("WebAuthn PRF" || 0x00 || prf_input)` — byte-for-byte what a browser's
//!   WebAuthn `prf` extension sends for `eval.first = prf_input`.
//! * `KEK = HKDF-SHA256(salt = prf_input, ikm = prf_output, info = "sigil-sgkw-kek-v1")`,
//!   and the DEK is AES-256-GCM-wrapped under the KEK (AAD = header || slot metadata).
//! * Several slots (primary + backup key) can wrap the same DEK.
//!
//! After unwrap the inner identity's public keys must equal the clear header, so a
//! swapped header or inner blob is refused.
//!
//! The authenticator sits behind [`Authenticator`]. Real USB/NFC-HID security keys use the
//! CTAP backend (cargo feature `passkey`); tests use [`SoftAuthenticator`], which follows
//! the CTAP2 hmac-secret definition (`HMAC-SHA-256(CredRandom, salt)`, separate CredRandom
//! with / without user verification) but keeps its secrets in a file — **test only**.

use crate::keys::{parse_identity, write_secret_file, Identity, PublicIdentity, ID_MAGIC};
use crate::{sha256, Error, Result};
use aes_gcm::{
    aead::{Aead, KeyInit, Payload},
    Aes256Gcm, Nonce,
};
use hkdf::Hkdf;
use hmac::{Hmac, Mac};
use sha2::Sha256;
use std::path::{Path, PathBuf};
use zeroize::Zeroizing;

pub const SGKW_MAGIC: [u8; 4] = *b"SGKW";
pub const SGKW_VERSION: u8 = 1;
/// Default relying-party id for Sigil credentials (CTAP accepts any string; WebAuthn
/// would need a domain you control — pass `--rp-id` for that).
pub const DEFAULT_RP_ID: &str = "sigil.sg1";
/// Env var naming a software-authenticator state file. **Testing only.**
pub const SOFT_ENV: &str = "SIGIL_SOFT_AUTHENTICATOR";
/// Env var with the authenticator PIN (else Sigil prompts on the terminal).
pub const PIN_ENV: &str = "SIGIL_PASSKEY_PIN";

const HEADER_LEN: usize = 8 + 32 + 32;
const SLOT_FIDO2_PRF: u8 = 1;
const SLOT_FLAG_UV: u8 = 1;
const KEK_INFO: &[u8] = b"sigil-sgkw-kek-v1";
const PRF_LABEL: &[u8] = b"WebAuthn PRF";

/// CTAP2 hmac-secret salt for a WebAuthn PRF input (WebAuthn L3 §10.1.4).
pub fn prf_salt(prf_input: &[u8; 32]) -> [u8; 32] {
    let mut m = Vec::with_capacity(PRF_LABEL.len() + 1 + 32);
    m.extend_from_slice(PRF_LABEL);
    m.push(0);
    m.extend_from_slice(prf_input);
    sha256(&m)
}

/// Result of one hmac-secret evaluation.
pub struct PrfEval {
    pub output: Zeroizing<[u8; 32]>,
    /// Whether the authenticator reported user verification (it selects CredRandom).
    pub uv: bool,
}

/// A FIDO2 authenticator that supports `hmac-secret`.
pub trait Authenticator {
    fn describe(&self) -> String;
    /// Create a non-discoverable credential with hmac-secret enabled; returns its id.
    fn make_credential(&mut self, rp_id: &str, uv: bool) -> Result<Vec<u8>>;
    /// Evaluate hmac-secret for `cred_id` with the 32-byte CTAP `salt`.
    fn hmac_secret(
        &mut self,
        rp_id: &str,
        cred_id: &[u8],
        salt: &[u8; 32],
        uv: bool,
    ) -> Result<PrfEval>;
}

// ---------------------------------------------------------------------------
// Wrapper format
// ---------------------------------------------------------------------------

/// One passkey slot (clear metadata + wrapped DEK).
#[derive(Clone, Debug)]
pub struct Slot {
    pub uv: bool,
    pub rp_id: String,
    pub cred_id: Vec<u8>,
    pub prf_input: [u8; 32],
    nonce: [u8; 12],
    wrapped_dek: Vec<u8>, // 32 + 16 tag
}

/// Parsed `SGKW` file. Public keys are readable without the authenticator.
#[derive(Clone, Debug)]
pub struct Wrapped {
    pub public: PublicIdentity,
    body_nonce: [u8; 12],
    body_ct: Vec<u8>,
    pub slots: Vec<Slot>,
    /// Slots of kinds this build doesn't know (kept verbatim on rewrite).
    unknown_slots: Vec<(u8, Vec<u8>)>,
}

pub fn is_wrapped(b: &[u8]) -> bool {
    b.len() >= 5 && b[0..4] == SGKW_MAGIC
}

fn header_bytes(public: &PublicIdentity) -> [u8; HEADER_LEN] {
    let mut h = [0u8; HEADER_LEN];
    h[0..4].copy_from_slice(&SGKW_MAGIC);
    h[4] = SGKW_VERSION;
    h[8..40].copy_from_slice(&public.x25519_pk);
    h[40..72].copy_from_slice(&public.ed25519_pk);
    h
}

fn slot_meta(header: &[u8; HEADER_LEN], s: &Slot) -> Vec<u8> {
    let mut m = Vec::with_capacity(HEADER_LEN + 4 + s.rp_id.len() + s.cred_id.len() + 32);
    m.extend_from_slice(header);
    m.push(SLOT_FIDO2_PRF);
    m.push(if s.uv { SLOT_FLAG_UV } else { 0 });
    m.push(s.rp_id.len() as u8);
    m.extend_from_slice(s.rp_id.as_bytes());
    m.extend_from_slice(&(s.cred_id.len() as u16).to_le_bytes());
    m.extend_from_slice(&s.cred_id);
    m.extend_from_slice(&s.prf_input);
    m
}

fn kek(prf_input: &[u8; 32], prf_output: &[u8; 32]) -> Result<Zeroizing<[u8; 32]>> {
    let hk = Hkdf::<Sha256>::new(Some(prf_input), prf_output);
    let mut k = Zeroizing::new([0u8; 32]);
    hk.expand(KEK_INFO, k.as_mut())
        .map_err(|_| Error::Msg("HKDF expand failed".into()))?;
    Ok(k)
}

fn rand<const N: usize>() -> Result<[u8; N]> {
    let mut b = [0u8; N];
    getrandom::getrandom(&mut b).map_err(|e| Error::Msg(e.to_string()))?;
    Ok(b)
}

fn gcm_seal(key: &[u8; 32], nonce: &[u8; 12], pt: &[u8], aad: &[u8]) -> Result<Vec<u8>> {
    let c = Aes256Gcm::new_from_slice(key).map_err(|e| Error::Msg(e.to_string()))?;
    c.encrypt(Nonce::from_slice(nonce), Payload { msg: pt, aad })
        .map_err(|_| Error::Msg("AES-GCM seal failed".into()))
}

fn gcm_open(key: &[u8; 32], nonce: &[u8; 12], ct: &[u8], aad: &[u8]) -> Option<Zeroizing<Vec<u8>>> {
    let c = Aes256Gcm::new_from_slice(key).ok()?;
    c.decrypt(Nonce::from_slice(nonce), Payload { msg: ct, aad })
        .ok()
        .map(Zeroizing::new)
}

impl Wrapped {
    pub fn to_bytes(&self) -> Vec<u8> {
        let header = header_bytes(&self.public);
        let mut out = Vec::new();
        out.extend_from_slice(&header);
        out[6] = (self.slots.len() + self.unknown_slots.len()) as u8;
        out.extend_from_slice(&self.body_nonce);
        out.extend_from_slice(&(self.body_ct.len() as u32).to_le_bytes());
        out.extend_from_slice(&self.body_ct);
        for s in &self.slots {
            let mut body = Vec::new();
            body.push(if s.uv { SLOT_FLAG_UV } else { 0 });
            body.push(s.rp_id.len() as u8);
            body.extend_from_slice(s.rp_id.as_bytes());
            body.extend_from_slice(&(s.cred_id.len() as u16).to_le_bytes());
            body.extend_from_slice(&s.cred_id);
            body.extend_from_slice(&s.prf_input);
            body.extend_from_slice(&s.nonce);
            body.extend_from_slice(&s.wrapped_dek);
            out.push(SLOT_FIDO2_PRF);
            out.extend_from_slice(&(body.len() as u16).to_le_bytes());
            out.extend_from_slice(&body);
        }
        for (kind, body) in &self.unknown_slots {
            out.push(*kind);
            out.extend_from_slice(&(body.len() as u16).to_le_bytes());
            out.extend_from_slice(body);
        }
        let crc = crc32fast::hash(&out);
        out.extend_from_slice(&crc.to_le_bytes());
        out
    }

    pub fn parse(b: &[u8]) -> Result<Self> {
        let bad = || Error::Msg("damaged passkey identity (SGKW)".into());
        if !is_wrapped(b) {
            return Err(Error::Msg("not a passkey-protected identity".into()));
        }
        if b[4] != SGKW_VERSION {
            return Err(Error::Msg(format!(
                "unsupported passkey identity version {} (upgrade sigil)",
                b[4]
            )));
        }
        if b.len() < HEADER_LEN + 12 + 4 + 4 {
            return Err(bad());
        }
        let (body, crc) = b.split_at(b.len() - 4);
        if crc32fast::hash(body).to_le_bytes() != crc {
            return Err(bad());
        }
        let nslots = b[6] as usize;
        let public = PublicIdentity {
            x25519_pk: b[8..40].try_into().unwrap(),
            ed25519_pk: b[40..72].try_into().unwrap(),
        };
        let mut i = HEADER_LEN;
        let body_nonce: [u8; 12] = body.get(i..i + 12).ok_or_else(bad)?.try_into().unwrap();
        i += 12;
        let ct_len =
            u32::from_le_bytes(body.get(i..i + 4).ok_or_else(bad)?.try_into().unwrap()) as usize;
        i += 4;
        let body_ct = body
            .get(i..i.checked_add(ct_len).ok_or_else(bad)?)
            .ok_or_else(bad)?
            .to_vec();
        i += ct_len;
        let mut slots = Vec::new();
        let mut unknown_slots = Vec::new();
        for _ in 0..nslots {
            let kind = *body.get(i).ok_or_else(bad)?;
            let len =
                u16::from_le_bytes(body.get(i + 1..i + 3).ok_or_else(bad)?.try_into().unwrap())
                    as usize;
            let s = body.get(i + 3..i + 3 + len).ok_or_else(bad)?;
            i += 3 + len;
            if kind != SLOT_FIDO2_PRF {
                unknown_slots.push((kind, s.to_vec()));
                continue;
            }
            let mut j = 0usize;
            let flags = *s.get(j).ok_or_else(bad)?;
            let rp_len = *s.get(j + 1).ok_or_else(bad)? as usize;
            j += 2;
            let rp_id = String::from_utf8(s.get(j..j + rp_len).ok_or_else(bad)?.to_vec())
                .map_err(|_| bad())?;
            j += rp_len;
            let cl =
                u16::from_le_bytes(s.get(j..j + 2).ok_or_else(bad)?.try_into().unwrap()) as usize;
            j += 2;
            let cred_id = s.get(j..j + cl).ok_or_else(bad)?.to_vec();
            j += cl;
            let prf_input: [u8; 32] = s.get(j..j + 32).ok_or_else(bad)?.try_into().unwrap();
            j += 32;
            let nonce: [u8; 12] = s.get(j..j + 12).ok_or_else(bad)?.try_into().unwrap();
            j += 12;
            let wrapped_dek = s.get(j..j + 48).ok_or_else(bad)?.to_vec();
            j += 48;
            if j != s.len() {
                return Err(bad());
            }
            slots.push(Slot {
                uv: flags & SLOT_FLAG_UV != 0,
                rp_id,
                cred_id,
                prf_input,
                nonce,
                wrapped_dek,
            });
        }
        if i != body.len() {
            return Err(bad());
        }
        Ok(Self {
            public,
            body_nonce,
            body_ct,
            slots,
            unknown_slots,
        })
    }

    fn new_slot(
        header: &[u8; HEADER_LEN],
        dek: &[u8; 32],
        auth: &mut dyn Authenticator,
        rp_id: &str,
        uv: bool,
    ) -> Result<Slot> {
        if rp_id.is_empty() || rp_id.len() > 255 {
            return Err(Error::Msg("--rp-id must be 1..255 bytes".into()));
        }
        eprintln!("passkey: registering a new credential — touch your authenticator");
        let cred_id = auth.make_credential(rp_id, uv)?;
        if cred_id.is_empty() || cred_id.len() > u16::MAX as usize {
            return Err(Error::Msg(
                "authenticator returned an unusable credential id".into(),
            ));
        }
        let prf_input = rand::<32>()?;
        eprintln!("passkey: deriving the unlock key — touch your authenticator again");
        let ev = auth.hmac_secret(rp_id, &cred_id, &prf_salt(&prf_input), uv)?;
        if uv && !ev.uv {
            return Err(Error::Msg(
                "authenticator did not perform user verification (PIN); use --no-uv for touch-only"
                    .into(),
            ));
        }
        let mut slot = Slot {
            uv: ev.uv,
            rp_id: rp_id.to_string(),
            cred_id,
            prf_input,
            nonce: rand::<12>()?,
            wrapped_dek: Vec::new(),
        };
        let k = kek(&slot.prf_input, &ev.output)?;
        slot.wrapped_dek = gcm_seal(&k, &slot.nonce, dek, &slot_meta(header, &slot))?;
        Ok(slot)
    }

    /// Wrap a plain identity under a fresh passkey credential.
    pub fn protect(
        id: &Identity,
        auth: &mut dyn Authenticator,
        rp_id: &str,
        uv: bool,
    ) -> Result<Self> {
        let public = id.public();
        let header = header_bytes(&public);
        let inner = Zeroizing::new(id.to_bytes());
        let dek = Zeroizing::new(rand::<32>()?);
        let body_nonce = rand::<12>()?;
        let body_ct = gcm_seal(&dek, &body_nonce, &inner, &header)?;
        let slot = Self::new_slot(&header, &dek, auth, rp_id, uv)?;
        Ok(Self {
            public,
            body_nonce,
            body_ct,
            slots: vec![slot],
            unknown_slots: Vec::new(),
        })
    }

    fn unlock_dek(&self, auth: &mut dyn Authenticator) -> Result<Zeroizing<[u8; 32]>> {
        let header = header_bytes(&self.public);
        let mut last_err = None;
        for s in &self.slots {
            let ev = match auth.hmac_secret(&s.rp_id, &s.cred_id, &prf_salt(&s.prf_input), s.uv) {
                Ok(ev) => ev,
                Err(e) => {
                    last_err = Some(e);
                    continue;
                }
            };
            let k = kek(&s.prf_input, &ev.output)?;
            if let Some(d) = gcm_open(&k, &s.nonce, &s.wrapped_dek, &slot_meta(&header, s)) {
                if d.len() == 32 {
                    let mut dek = Zeroizing::new([0u8; 32]);
                    dek.copy_from_slice(&d);
                    return Ok(dek);
                }
            }
            last_err = Some(Error::Msg(if s.uv && !ev.uv {
                "passkey answered without user verification; this slot needs your PIN".into()
            } else {
                "passkey answered but the unlock key did not match (wrong credential or tampered file)"
                    .into()
            }));
        }
        Err(last_err.unwrap_or_else(|| Error::Msg("no passkey slots in this identity".into())))
    }

    /// Unlock with any matching slot; returns the plain identity.
    pub fn unlock(&self, auth: &mut dyn Authenticator) -> Result<Identity> {
        let dek = self.unlock_dek(auth)?;
        let header = header_bytes(&self.public);
        let inner = gcm_open(&dek, &self.body_nonce, &self.body_ct, &header)
            .ok_or_else(|| Error::Msg("passkey identity body failed authentication".into()))?;
        if inner.len() < 4 || inner[0..4] != ID_MAGIC {
            return Err(Error::Msg("passkey identity holds no .sgk".into()));
        }
        let id = parse_identity(&inner)?;
        let p = id.public();
        if p.x25519_pk != self.public.x25519_pk || p.ed25519_pk != self.public.ed25519_pk {
            return Err(Error::Msg(
                "passkey identity public keys do not match its contents".into(),
            ));
        }
        Ok(id)
    }

    /// Add another passkey (e.g. a backup key). Unlocks with an existing slot first.
    pub fn add_slot(
        &mut self,
        unlock_with: &mut dyn Authenticator,
        new_auth: &mut dyn Authenticator,
        rp_id: &str,
        uv: bool,
    ) -> Result<()> {
        let dek = self.unlock_dek(unlock_with)?;
        let header = header_bytes(&self.public);
        if self.slots.len() + self.unknown_slots.len() >= 255 {
            return Err(Error::Msg("too many passkey slots".into()));
        }
        let slot = Self::new_slot(&header, &dek, new_auth, rp_id, uv)?;
        self.slots.push(slot);
        Ok(())
    }

    /// Drop slot `idx` (0-based). Refuses to remove the last one.
    pub fn remove_slot(&mut self, idx: usize) -> Result<()> {
        if idx >= self.slots.len() {
            return Err(Error::Msg(format!("no passkey slot #{idx}")));
        }
        if self.slots.len() + self.unknown_slots.len() == 1 {
            return Err(Error::Msg(
                "refusing to remove the only passkey slot; use `identity unprotect` instead".into(),
            ));
        }
        self.slots.remove(idx);
        Ok(())
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        write_secret_file(path, &self.to_bytes())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let b = std::fs::read(path).map_err(|e| Error::Msg(e.to_string()))?;
        Self::parse(&b)
    }

    /// Human summary (no secrets, no authenticator needed).
    pub fn describe(&self) -> String {
        let mut s = format!(
            "passkey-protected identity (SGKW v{SGKW_VERSION})\n  x25519 {}\n  ed25519 {}\n",
            hex::encode(self.public.x25519_pk),
            hex::encode(self.public.ed25519_pk)
        );
        for (n, sl) in self.slots.iter().enumerate() {
            let cid = hex::encode(&sl.cred_id);
            s.push_str(&format!(
                "  slot #{n}: FIDO2 hmac-secret/PRF  rp {}  cred {}…  {}\n",
                sl.rp_id,
                &cid[..cid.len().min(16)],
                if sl.uv {
                    "PIN/UV required"
                } else {
                    "touch only"
                }
            ));
        }
        for (kind, _) in &self.unknown_slots {
            s.push_str(&format!("  slot (unknown kind {kind}, kept)\n"));
        }
        s
    }
}

// ---------------------------------------------------------------------------
// Software authenticator (tests / CI only)
// ---------------------------------------------------------------------------

#[derive(Clone)]
struct SoftCred {
    id: [u8; 32],
    rp_hash: [u8; 32],
    cred_random_uv: [u8; 32],
    cred_random_no_uv: [u8; 32],
}

/// In-process FIDO2 hmac-secret model. **Not a security device**: its secrets live in RAM
/// or in a plain file. For tests, CI and dry runs only.
pub struct SoftAuthenticator {
    creds: Vec<SoftCred>,
    path: Option<PathBuf>,
}

const SOFT_MAGIC: &[u8; 4] = b"SGSA";

impl SoftAuthenticator {
    pub fn new() -> Self {
        Self {
            creds: Vec::new(),
            path: None,
        }
    }

    /// Load (or start) a state file that persists credentials across processes.
    pub fn open(path: &Path) -> Result<Self> {
        let mut a = Self {
            creds: Vec::new(),
            path: Some(path.to_path_buf()),
        };
        if let Ok(b) = std::fs::read(path) {
            if b.len() < 4 || &b[0..4] != SOFT_MAGIC || (b.len() - 4) % 128 != 0 {
                return Err(Error::Msg("bad soft authenticator state file".into()));
            }
            for c in b[4..].chunks(128) {
                a.creds.push(SoftCred {
                    id: c[0..32].try_into().unwrap(),
                    rp_hash: c[32..64].try_into().unwrap(),
                    cred_random_uv: c[64..96].try_into().unwrap(),
                    cred_random_no_uv: c[96..128].try_into().unwrap(),
                });
            }
        }
        Ok(a)
    }

    fn save(&self) -> Result<()> {
        if let Some(p) = &self.path {
            let mut b = SOFT_MAGIC.to_vec();
            for c in &self.creds {
                b.extend_from_slice(&c.id);
                b.extend_from_slice(&c.rp_hash);
                b.extend_from_slice(&c.cred_random_uv);
                b.extend_from_slice(&c.cred_random_no_uv);
            }
            write_secret_file(p, &b)?;
        }
        Ok(())
    }
}

impl Default for SoftAuthenticator {
    fn default() -> Self {
        Self::new()
    }
}

impl Authenticator for SoftAuthenticator {
    fn describe(&self) -> String {
        "software test authenticator (NOT secure)".into()
    }

    fn make_credential(&mut self, rp_id: &str, _uv: bool) -> Result<Vec<u8>> {
        let c = SoftCred {
            id: rand::<32>()?,
            rp_hash: sha256(rp_id.as_bytes()),
            cred_random_uv: rand::<32>()?,
            cred_random_no_uv: rand::<32>()?,
        };
        let id = c.id.to_vec();
        self.creds.push(c);
        self.save()?;
        Ok(id)
    }

    fn hmac_secret(
        &mut self,
        rp_id: &str,
        cred_id: &[u8],
        salt: &[u8; 32],
        uv: bool,
    ) -> Result<PrfEval> {
        let rp_hash = sha256(rp_id.as_bytes());
        let c = self
            .creds
            .iter()
            .find(|c| c.id[..] == *cred_id && c.rp_hash == rp_hash)
            .ok_or_else(|| Error::Msg("no matching credential on this authenticator".into()))?;
        let key = if uv {
            &c.cred_random_uv
        } else {
            &c.cred_random_no_uv
        };
        let mut mac = <Hmac<Sha256> as Mac>::new_from_slice(key).expect("hmac key");
        mac.update(salt);
        let mut out = Zeroizing::new([0u8; 32]);
        out.copy_from_slice(&mac.finalize().into_bytes());
        Ok(PrfEval { output: out, uv })
    }
}

// ---------------------------------------------------------------------------
// Real CTAP2 HID backend (feature "passkey")
// ---------------------------------------------------------------------------

#[cfg(feature = "passkey")]
pub mod ctap {
    use super::{Authenticator, PrfEval, PIN_ENV};
    use crate::{Error, Result};
    use ctap_hid_fido2::fidokey::get_assertion::{Extension as Gext, GetAssertionArgsBuilder};
    use ctap_hid_fido2::fidokey::make_credential::{Extension as Mext, MakeCredentialArgsBuilder};
    use ctap_hid_fido2::{FidoKeyHid, FidoKeyHidFactory, LibCfg};
    use zeroize::Zeroizing;

    /// First connected FIDO2 HID authenticator (USB, or NFC via a HID bridge).
    pub struct CtapAuthenticator {
        pin: Option<Zeroizing<String>>,
    }

    impl CtapAuthenticator {
        pub fn new() -> Self {
            Self { pin: None }
        }

        fn device(&self) -> Result<FidoKeyHid> {
            let mut cfg = LibCfg::init().with_keep_alive_msg_to_stderr(true);
            cfg.keep_alive_msg = "passkey: touch your security key…".into();
            FidoKeyHidFactory::create(&cfg).map_err(|e| {
                Error::Msg(format!(
                    "no usable FIDO2 security key ({e}); plug in exactly one key \
                     (Linux: install your distro's FIDO udev rules / libfido2 package)"
                ))
            })
        }

        fn pin(&mut self) -> Result<Zeroizing<String>> {
            if let Some(p) = &self.pin {
                return Ok(p.clone());
            }
            let p = match std::env::var(PIN_ENV) {
                Ok(v) if !v.is_empty() => Zeroizing::new(v),
                _ => Zeroizing::new(
                    rpassword::prompt_password("Security key PIN: ")
                        .map_err(|e| Error::Msg(format!("PIN prompt failed: {e}")))?,
                ),
            };
            self.pin = Some(p.clone());
            Ok(p)
        }
    }

    impl Default for CtapAuthenticator {
        fn default() -> Self {
            Self::new()
        }
    }

    fn challenge() -> Result<[u8; 32]> {
        super::rand::<32>()
    }

    impl Authenticator for CtapAuthenticator {
        fn describe(&self) -> String {
            "FIDO2 security key (CTAP2 HID)".into()
        }

        fn make_credential(&mut self, rp_id: &str, uv: bool) -> Result<Vec<u8>> {
            let dev = self.device()?;
            let ch = challenge()?;
            let pin = if uv { Some(self.pin()?) } else { None };
            let ext = [Mext::HmacSecret(Some(true))];
            let mut b = MakeCredentialArgsBuilder::new(rp_id, &ch).extensions(&ext);
            b = match pin.as_ref() {
                Some(p) => b.pin(p.as_str()),
                None => b.without_pin_and_uv(),
            };
            let att = dev
                .make_credential_with_args(&b.build())
                .map_err(|e| Error::Msg(format!("security key refused registration: {e}")))?;
            let hmac_on = att
                .extensions
                .iter()
                .any(|e| matches!(e, Mext::HmacSecret(Some(true))));
            if !hmac_on {
                return Err(Error::Msg(
                    "this security key does not support the FIDO2 hmac-secret extension".into(),
                ));
            }
            Ok(att.credential_descriptor.id.clone())
        }

        fn hmac_secret(
            &mut self,
            rp_id: &str,
            cred_id: &[u8],
            salt: &[u8; 32],
            uv: bool,
        ) -> Result<PrfEval> {
            let dev = self.device()?;
            let ch = challenge()?;
            let pin = if uv { Some(self.pin()?) } else { None };
            let ext = [Gext::HmacSecret(Some(*salt))];
            let mut b = GetAssertionArgsBuilder::new(rp_id, &ch)
                .credential_id(cred_id)
                .extensions(&ext);
            b = match pin.as_ref() {
                Some(p) => b.pin(p.as_str()),
                None => b.without_pin_and_uv(),
            };
            let asss = dev
                .get_assertion_with_args(&b.build())
                .map_err(|e| Error::Msg(format!("security key assertion failed: {e}")))?;
            let a = asss
                .first()
                .ok_or_else(|| Error::Msg("security key returned no assertion".into()))?;
            for e in &a.extensions {
                if let Gext::HmacSecret(Some(out)) = e {
                    return Ok(PrfEval {
                        output: Zeroizing::new(*out),
                        uv: a.flags.user_verified_result,
                    });
                }
            }
            Err(Error::Msg(
                "security key returned no hmac-secret output".into(),
            ))
        }
    }
}

/// The authenticator `--identity` / `--passkey` use: the soft one if `SIGIL_SOFT_AUTHENTICATOR`
/// is set (tests), else a real security key when built with `--features passkey`.
pub fn default_authenticator() -> Result<Box<dyn Authenticator>> {
    if let Some(p) = std::env::var_os(SOFT_ENV).filter(|v| !v.is_empty()) {
        eprintln!("passkey: using the SOFTWARE TEST authenticator from ${SOFT_ENV} (not secure)");
        return Ok(Box::new(SoftAuthenticator::open(Path::new(&p))?));
    }
    #[cfg(feature = "passkey")]
    {
        Ok(Box::new(ctap::CtapAuthenticator::new()))
    }
    #[cfg(not(feature = "passkey"))]
    {
        Err(Error::Msg(
            "this sigil was built without security-key support; rebuild with \
             `cargo build --release --features passkey` (see docs/PASSKEY.md)"
                .into(),
        ))
    }
}

/// Unlock wrapped identity bytes with the default authenticator.
pub fn unlock_bytes(b: &[u8]) -> Result<Identity> {
    let w = Wrapped::parse(b)?;
    let mut a = default_authenticator()?;
    w.unlock(a.as_mut())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn prf_salt_matches_webauthn_definition() {
        // SHA-256("WebAuthn PRF" || 0x00 || input), computed independently.
        let input = [0u8; 32];
        let mut m = b"WebAuthn PRF".to_vec();
        m.push(0);
        m.extend_from_slice(&input);
        assert_eq!(prf_salt(&input), sha256(&m));
        assert_ne!(prf_salt(&input), prf_salt(&[1u8; 32]));
    }

    #[test]
    fn protect_unlock_roundtrip_native_and_raw() {
        let mut auth = SoftAuthenticator::new();
        let id = Identity::generate().unwrap();
        let w = Wrapped::protect(&id, &mut auth, DEFAULT_RP_ID, true).unwrap();
        let bytes = w.to_bytes();
        let back = Wrapped::parse(&bytes).unwrap();
        assert_eq!(back.public.x25519_pk, id.public().x25519_pk);
        let got = back.unlock(&mut auth).unwrap();
        assert_eq!(got.master, id.master);
        assert_eq!(got.x25519_sk, id.x25519_sk);

        let base = Identity::generate().unwrap();
        let raw = Identity::from_raw(base.x25519_sk, base.ed25519_seed, Some([3u8; 20]));
        let w2 = Wrapped::protect(&raw, &mut auth, "example.org", false).unwrap();
        let got2 = Wrapped::parse(&w2.to_bytes())
            .unwrap()
            .unlock(&mut auth)
            .unwrap();
        assert_eq!(got2.pgp_fpr, Some([3u8; 20]));
        assert_eq!(got2.ed25519_seed, base.ed25519_seed);
    }

    #[test]
    fn wrong_authenticator_or_tamper_refused() {
        let mut auth = SoftAuthenticator::new();
        let mut other = SoftAuthenticator::new();
        let id = Identity::generate().unwrap();
        let w = Wrapped::protect(&id, &mut auth, DEFAULT_RP_ID, false).unwrap();
        assert!(w.unlock(&mut other).is_err());

        // Flip the stored public key (and fix the CRC): must be refused after unwrap.
        let mut b = w.to_bytes();
        b[9] ^= 1;
        let n = b.len() - 4;
        let crc = crc32fast::hash(&b[..n]).to_le_bytes();
        b[n..].copy_from_slice(&crc);
        let t = Wrapped::parse(&b).unwrap();
        assert!(t.unlock(&mut auth).is_err());

        // CRC catches casual damage.
        let mut d = w.to_bytes();
        d[80] ^= 0x40;
        assert!(Wrapped::parse(&d).is_err());

        // UV mismatch: slot made with UV can't be opened touch-only.
        let wuv = Wrapped::protect(&id, &mut auth, DEFAULT_RP_ID, true).unwrap();
        let mut s = wuv.clone();
        s.slots[0].uv = false; // attacker edits the flag → AAD mismatch
        assert!(s.unlock(&mut auth).is_err());
    }

    #[test]
    fn backup_slot_add_and_remove() {
        let mut primary = SoftAuthenticator::new();
        let mut backup = SoftAuthenticator::new();
        let id = Identity::generate().unwrap();
        let mut w = Wrapped::protect(&id, &mut primary, DEFAULT_RP_ID, true).unwrap();
        w.add_slot(&mut primary, &mut backup, DEFAULT_RP_ID, false)
            .unwrap();
        let w = Wrapped::parse(&w.to_bytes()).unwrap();
        assert_eq!(w.slots.len(), 2);
        assert_eq!(w.unlock(&mut backup).unwrap().master, id.master);
        assert_eq!(w.unlock(&mut primary).unwrap().master, id.master);
        let mut w2 = w.clone();
        w2.remove_slot(0).unwrap();
        assert!(w2.unlock(&mut primary).is_err());
        assert!(w2.unlock(&mut backup).is_ok());
        assert!(w2.remove_slot(0).is_err());
    }

    #[test]
    fn wrapped_file_opens_sgto_and_exposes_public_without_touch() {
        let dir = std::env::temp_dir().join(format!("sigil-sgkw-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("me.sgk");
        let mut auth = SoftAuthenticator::new();
        let id = Identity::generate().unwrap();
        Wrapped::protect(&id, &mut auth, DEFAULT_RP_ID, true)
            .unwrap()
            .write(&path)
            .unwrap();
        // --to me.sgk works from the clear header.
        let pk = PublicIdentity::load(&path).unwrap();
        assert_eq!(pk.x25519_pk, id.public().x25519_pk);
        // Encrypt-to and unlock through the authenticator.
        let cek = [5u8; 32];
        let salt = [1u8; 16];
        let sgto = crate::keys::build_sgto(&cek, &[pk], None, &salt).unwrap();
        let loaded = Identity::load_with(&path, &mut auth).unwrap();
        assert_eq!(
            crate::keys::unwrap_cek(&sgto, &[loaded], None, &salt).unwrap(),
            cek
        );
        // Plain v1 files still load the old way, untouched by the wrapper code.
        let plain = dir.join("plain.sgk");
        id.write(&plain).unwrap();
        assert_eq!(std::fs::read(&plain).unwrap()[4], 1);
        assert_eq!(Identity::load(&plain).unwrap().master, id.master);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn soft_state_persists_across_instances() {
        let dir = std::env::temp_dir().join(format!("sigil-soft-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let st = dir.join("auth.bin");
        let id = Identity::generate().unwrap();
        let w = {
            let mut a = SoftAuthenticator::open(&st).unwrap();
            Wrapped::protect(&id, &mut a, DEFAULT_RP_ID, true).unwrap()
        };
        let mut a2 = SoftAuthenticator::open(&st).unwrap();
        assert_eq!(w.unlock(&mut a2).unwrap().master, id.master);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
