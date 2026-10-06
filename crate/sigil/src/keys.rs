//! ECC identity (.sgk / .pub) and SGTO encrypt-to recipient envelopes.
//!
//! Passphrase Ward (--pass / --talisman) stays unchanged for seals without SGTO.
//! With --to, body is AES-GCM'd under a random CEK; each recipient gets an X25519
//! ECDH + HKDF wrap of that CEK in an SGTO companion block (no header flag bit).
//! If both --pass and --to: either the passphrase OR any matching identity opens.

use crate::{sha256, Error, Result, PBKDF2_ITERS};
use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use ed25519_dalek::SigningKey;
use hkdf::Hkdf;
use pbkdf2::pbkdf2_hmac;
use sha2::Sha256;
use std::path::Path;
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

pub const ID_MAGIC: [u8; 4] = *b"SGIK";
pub const PUB_MAGIC: [u8; 4] = *b"SGIP";
pub const SGTO_MAGIC: [u8; 4] = *b"SGTO";
pub const ID_VERSION: u8 = 1;
/// .sgk v2: raw keys (no HKDF master), e.g. imported from OpenPGP. Old builds refuse it cleanly.
pub const ID_VERSION_RAW: u8 = 2;
const ID_FLAG_PGP: u8 = 1;
const ID_SIZE_RAW: usize = ID_HEADER + 32 + 32 + 20; // x25519 sk + ed25519 seed + pgp fpr
pub const SGTO_VERSION: u8 = 1;

const ID_HEADER: usize = 8; // magic + ver + flags + pad
const PUB_SIZE: usize = ID_HEADER + 32 + 32;
const ID_SIZE: usize = ID_HEADER + 32; // master seed; keys derived via HKDF
const RECIPIENT_REC: usize = 8 + 32 + 12 + 16 + 32; // hint + eph_pk + nonce + tag + ct
const SGTO_HEADER: usize = 8; // magic + ver + count + flags + pad
const KIND_X25519: u8 = 1;
const KIND_PASS: u8 = 2;
const FLAG_HAS_PASS_WRAP: u8 = 1;

/// Secret identity: X25519 decrypt + Ed25519 attest seed (HKDF-split from master).
#[derive(Clone)]
pub struct Identity {
    /// HKDF master for native identities; all-zero for raw (imported) ones.
    pub master: [u8; 32],
    pub x25519_sk: [u8; 32],
    pub ed25519_seed: [u8; 32],
    /// Set for identities imported from OpenPGP (v4 primary fingerprint). Written as .sgk v2.
    pub pgp_fpr: Option<[u8; 20]>,
}

/// Public half for --to.
#[derive(Clone, Debug)]
pub struct PublicIdentity {
    pub x25519_pk: [u8; 32],
    pub ed25519_pk: [u8; 32],
}

impl Identity {
    pub fn generate() -> Result<Self> {
        let mut master = [0u8; 32];
        getrandom::getrandom(&mut master).map_err(|e| Error::Msg(e.to_string()))?;
        Self::from_master(master)
    }

    pub fn from_master(master: [u8; 32]) -> Result<Self> {
        let (x_sk, ed_seed) = split_master(&master)?;
        Ok(Self {
            master,
            x25519_sk: x_sk,
            ed25519_seed: ed_seed,
            pgp_fpr: None,
        })
    }

    /// Raw key pair (no master), e.g. from `sigil import-pgp`.
    pub fn from_raw(x25519_sk: [u8; 32], ed25519_seed: [u8; 32], pgp_fpr: Option<[u8; 20]>) -> Self {
        Self {
            master: [0u8; 32],
            x25519_sk,
            ed25519_seed,
            pgp_fpr,
        }
    }

    pub fn public(&self) -> PublicIdentity {
        let sk = StaticSecret::from(self.x25519_sk);
        let x_pk = XPublic::from(&sk);
        let ed = SigningKey::from_bytes(&self.ed25519_seed);
        PublicIdentity {
            x25519_pk: *x_pk.as_bytes(),
            ed25519_pk: ed.verifying_key().to_bytes(),
        }
    }

    pub fn write(&self, path: &Path) -> Result<()> {
        let mut buf = Vec::with_capacity(ID_SIZE_RAW);
        buf.extend_from_slice(&ID_MAGIC);
        if let Some(fpr) = self.pgp_fpr {
            buf.push(ID_VERSION_RAW);
            buf.push(ID_FLAG_PGP);
            buf.push(0);
            buf.push(0);
            buf.extend_from_slice(&self.x25519_sk);
            buf.extend_from_slice(&self.ed25519_seed);
            buf.extend_from_slice(&fpr);
        } else {
            buf.push(ID_VERSION);
            buf.push(0); // flags
            buf.push(0);
            buf.push(0);
            buf.extend_from_slice(&self.master);
        }
        write_secret_file(path, &buf)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let b = std::fs::read(path).map_err(|e| Error::Msg(e.to_string()))?;
        parse_identity(&b)
    }
}

impl PublicIdentity {
    pub fn write(&self, path: &Path) -> Result<()> {
        let mut buf = Vec::with_capacity(PUB_SIZE);
        buf.extend_from_slice(&PUB_MAGIC);
        buf.push(ID_VERSION);
        buf.push(0);
        buf.push(0);
        buf.push(0);
        buf.extend_from_slice(&self.x25519_pk);
        buf.extend_from_slice(&self.ed25519_pk);
        std::fs::write(path, &buf).map_err(|e| Error::Msg(e.to_string()))?;
        Ok(())
    }

    pub fn load(path: &Path) -> Result<Self> {
        let b = std::fs::read(path).map_err(|e| Error::Msg(e.to_string()))?;
        parse_public(&b)
    }

    pub fn hint(&self) -> [u8; 8] {
        let h = sha256(&self.x25519_pk);
        let mut out = [0u8; 8];
        out.copy_from_slice(&h[..8]);
        out
    }
}

fn split_master(master: &[u8; 32]) -> Result<([u8; 32], [u8; 32])> {
    let hk = Hkdf::<Sha256>::new(None, master);
    let mut x = [0u8; 32];
    let mut e = [0u8; 32];
    hk.expand(b"sigil-id-x25519-v1", &mut x)
        .map_err(|_| Error::Msg("HKDF expand failed".into()))?;
    hk.expand(b"sigil-id-ed25519-v1", &mut e)
        .map_err(|_| Error::Msg("HKDF expand failed".into()))?;
    Ok((x, e))
}

/// Secret key files are created owner-only (0600) on unix.
fn write_secret_file(path: &Path, buf: &[u8]) -> Result<()> {
    use std::io::Write;
    let mut opts = std::fs::OpenOptions::new();
    opts.write(true).create(true).truncate(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        opts.mode(0o600);
    }
    let mut f = opts.open(path).map_err(|e| Error::Msg(e.to_string()))?;
    f.write_all(buf).map_err(|e| Error::Msg(e.to_string()))?;
    Ok(())
}

fn parse_identity(b: &[u8]) -> Result<Identity> {
    if b.len() >= ID_SIZE_RAW && b[0..4] == ID_MAGIC && b[4] == ID_VERSION_RAW {
        let mut x = [0u8; 32];
        let mut e = [0u8; 32];
        let mut fpr = [0u8; 20];
        x.copy_from_slice(&b[ID_HEADER..ID_HEADER + 32]);
        e.copy_from_slice(&b[ID_HEADER + 32..ID_HEADER + 64]);
        fpr.copy_from_slice(&b[ID_HEADER + 64..ID_HEADER + 84]);
        let pgp = if b[5] & ID_FLAG_PGP != 0 { Some(fpr) } else { None };
        return Ok(Identity::from_raw(x, e, pgp));
    }
    if b.len() >= ID_SIZE && b[0..4] == ID_MAGIC {
        if b[4] != ID_VERSION {
            return Err(Error::Msg(format!("unsupported .sgk version {}", b[4])));
        }
        let mut master = [0u8; 32];
        master.copy_from_slice(&b[ID_HEADER..ID_HEADER + 32]);
        return Identity::from_master(master);
    }
    // Allow raw 64-byte (x25519_sk || ed_seed) experimental, or reject.
    Err(Error::Msg(
        "not a Sigil identity (.sgk); use `sigil keygen` or --legacy for attest-only".into(),
    ))
}

fn parse_public(b: &[u8]) -> Result<PublicIdentity> {
    if b.len() >= PUB_SIZE && b[0..4] == PUB_MAGIC {
        if b[4] != ID_VERSION {
            return Err(Error::Msg(format!("unsupported .pub version {}", b[4])));
        }
        let mut x = [0u8; 32];
        let mut e = [0u8; 32];
        x.copy_from_slice(&b[ID_HEADER..ID_HEADER + 32]);
        e.copy_from_slice(&b[ID_HEADER + 32..ID_HEADER + 64]);
        return Ok(PublicIdentity {
            x25519_pk: x,
            ed25519_pk: e,
        });
    }
    // Raw 32-byte X25519 public key
    if b.len() == 32 {
        let mut x = [0u8; 32];
        x.copy_from_slice(b);
        return Ok(PublicIdentity {
            x25519_pk: x,
            ed25519_pk: [0u8; 32],
        });
    }
    // Hex-encoded 32-byte pk (64 hex chars, optional whitespace)
    let hex: String = b
        .iter()
        .copied()
        .filter(|c| !c.is_ascii_whitespace())
        .map(|c| c as char)
        .collect();
    if hex.len() == 64 && hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        let raw = hex::decode(&hex).map_err(|e| Error::Msg(e.to_string()))?;
        let mut x = [0u8; 32];
        x.copy_from_slice(&raw);
        return Ok(PublicIdentity {
            x25519_pk: x,
            ed25519_pk: [0u8; 32],
        });
    }
    // .sgk secret → derive public
    if b.len() >= ID_SIZE && b[0..4] == ID_MAGIC {
        return Ok(parse_identity(b)?.public());
    }
    // OpenPGP Curve25519 public key (armored or binary): use its cv25519 subkey.
    if crate::pgp::looks_like_pgp(b) {
        return Ok(crate::pgp::import(b)?.public);
    }
    Err(Error::Msg(
        "not a recipient public key (.pub / .sgk / OpenPGP cv25519 / 32-byte / hex)".into(),
    ))
}

/// Resolve --to argument: path to .pub/.sgk, or hex X25519 pk.
pub fn resolve_recipient(spec: &str) -> Result<PublicIdentity> {
    let p = Path::new(spec);
    if p.exists() {
        let b = std::fs::read(p).map_err(|e| Error::Msg(e.to_string()))?;
        return parse_public(&b);
    }
    // hex pk
    let hex: String = spec.chars().filter(|c| !c.is_whitespace()).collect();
    if hex.len() == 64 && hex.bytes().all(|c| c.is_ascii_hexdigit()) {
        let raw = hex::decode(&hex).map_err(|e| Error::Msg(e.to_string()))?;
        let mut x = [0u8; 32];
        x.copy_from_slice(&raw);
        return Ok(PublicIdentity {
            x25519_pk: x,
            ed25519_pk: [0u8; 32],
        });
    }
    Err(Error::Msg(format!(
        "--to needs .pub / .sgk / hex pk, got {spec}"
    )))
}

/// Write modern identity; optionally also write .pub beside it.
pub fn keygen_ecc(path: &Path, pub_out: Option<&Path>) -> Result<PublicIdentity> {
    let id = Identity::generate()?;
    id.write(path)?;
    let pk = id.public();
    if let Some(p) = pub_out {
        pk.write(p)?;
    } else {
        // default: path.pub
        let mut dest = path.as_os_str().to_os_string();
        dest.push(".pub");
        pk.write(Path::new(&dest))?;
    }
    Ok(pk)
}

/// Legacy: raw 32-byte Ed25519 attest seed (also Talisman).
pub fn keygen_legacy(path: &Path) -> Result<[u8; 32]> {
    crate::attest::keygen(path)
}

fn wrap_key_from_shared(shared: &[u8], eph_pk: &[u8; 32], recip_pk: &[u8; 32]) -> Result<[u8; 32]> {
    let mut salt = [0u8; 64];
    salt[..32].copy_from_slice(eph_pk);
    salt[32..].copy_from_slice(recip_pk);
    let hk = Hkdf::<Sha256>::new(Some(&salt), shared);
    let mut okm = [0u8; 32];
    hk.expand(b"sigil-sgto-cek-v1", &mut okm)
        .map_err(|_| Error::Msg("HKDF expand failed".into()))?;
    Ok(okm)
}

fn aes_wrap(key: &[u8; 32], plaintext: &[u8]) -> Result<([u8; 12], [u8; 16], Vec<u8>)> {
    let mut nonce = [0u8; 12];
    getrandom::getrandom(&mut nonce).map_err(|e| Error::Msg(e.to_string()))?;
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| Error::Msg(e.to_string()))?;
    let packed = cipher
        .encrypt(Nonce::from_slice(&nonce), plaintext)
        .map_err(|_| Error::Msg("CEK wrap failed".into()))?;
    let t = packed.len() - 16;
    let mut tag = [0u8; 16];
    tag.copy_from_slice(&packed[t..]);
    Ok((nonce, tag, packed[..t].to_vec()))
}

fn aes_unwrap(key: &[u8; 32], nonce: &[u8; 12], tag: &[u8; 16], ct: &[u8]) -> Result<Vec<u8>> {
    let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| Error::Msg(e.to_string()))?;
    let mut packed = ct.to_vec();
    packed.extend_from_slice(tag);
    cipher
        .decrypt(Nonce::from_slice(nonce), packed.as_ref())
        .map_err(|_| Error::Msg("CEK unwrap failed".into()))
}

fn encode_recipient_x25519(recip: &PublicIdentity, cek: &[u8; 32]) -> Result<Vec<u8>> {
    let mut eph_seed = [0u8; 32];
    getrandom::getrandom(&mut eph_seed).map_err(|e| Error::Msg(e.to_string()))?;
    let eph_sk = StaticSecret::from(eph_seed);
    let eph_pk = XPublic::from(&eph_sk);
    let their = XPublic::from(recip.x25519_pk);
    let shared = eph_sk.diffie_hellman(&their);
    let wrap_key = wrap_key_from_shared(shared.as_bytes(), eph_pk.as_bytes(), &recip.x25519_pk)?;
    let (nonce, tag, ct) = aes_wrap(&wrap_key, cek)?;
    if ct.len() != 32 {
        return Err(Error::Msg("unexpected CEK ciphertext length".into()));
    }
    let mut rec = Vec::with_capacity(1 + RECIPIENT_REC);
    rec.push(KIND_X25519);
    rec.extend_from_slice(&recip.hint());
    rec.extend_from_slice(eph_pk.as_bytes());
    rec.extend_from_slice(&nonce);
    rec.extend_from_slice(&tag);
    rec.extend_from_slice(&ct);
    Ok(rec)
}

fn encode_recipient_pass(pass: &str, salt: &[u8; 16], cek: &[u8; 32]) -> Result<Vec<u8>> {
    let mut key = [0u8; 32];
    pbkdf2_hmac::<Sha256>(pass.as_bytes(), salt, PBKDF2_ITERS, &mut key);
    let (nonce, tag, ct) = aes_wrap(&key, cek)?;
    if ct.len() != 32 {
        return Err(Error::Msg("unexpected CEK ciphertext length".into()));
    }
    let mut rec = Vec::with_capacity(1 + 12 + 16 + 32);
    rec.push(KIND_PASS);
    rec.extend_from_slice(&nonce);
    rec.extend_from_slice(&tag);
    rec.extend_from_slice(&ct);
    Ok(rec)
}

/// Build SGTO block: wraps of `cek` for each recipient (+ optional passphrase wrap).
pub fn build_sgto(
    cek: &[u8; 32],
    recipients: &[PublicIdentity],
    pass: Option<&str>,
    salt: &[u8; 16],
) -> Result<Vec<u8>> {
    if recipients.is_empty() && pass.map(|p| p.is_empty()).unwrap_or(true) {
        return Err(Error::Msg("SGTO needs at least one --to or passphrase wrap".into()));
    }
    let mut body = Vec::new();
    let mut count = 0u8;
    let mut flags = 0u8;
    for r in recipients {
        body.extend_from_slice(&encode_recipient_x25519(r, cek)?);
        count = count.saturating_add(1);
    }
    if let Some(p) = pass.filter(|s| !s.is_empty()) {
        body.extend_from_slice(&encode_recipient_pass(p, salt, cek)?);
        count = count.saturating_add(1);
        flags |= FLAG_HAS_PASS_WRAP;
    }
    let mut out = Vec::with_capacity(SGTO_HEADER + 4 + body.len());
    out.extend_from_slice(&SGTO_MAGIC);
    out.push(SGTO_VERSION);
    out.push(count);
    out.push(flags);
    out.push(0); // pad
    out.extend_from_slice(&body);
    let crc = crc32fast::hash(&out);
    out.extend_from_slice(&crc.to_le_bytes());
    Ok(out)
}

/// Peek SGTO at `off`; returns (block_bytes including CRC, inner payload after header).
pub fn read_sgto_at(file: &[u8], off: usize) -> Option<&[u8]> {
    if off + SGTO_HEADER > file.len() {
        return None;
    }
    if file[off..off + 4] != SGTO_MAGIC {
        return None;
    }
    if file[off + 4] != SGTO_VERSION {
        return None;
    }
    let count = file[off + 5] as usize;
    // Walk records to find length
    let mut i = off + SGTO_HEADER;
    for _ in 0..count {
        if i >= file.len() {
            return None;
        }
        let kind = file[i];
        i += 1;
        match kind {
            KIND_X25519 => {
                if i + RECIPIENT_REC > file.len() {
                    return None;
                }
                i += RECIPIENT_REC;
            }
            KIND_PASS => {
                if i + 12 + 16 + 32 > file.len() {
                    return None;
                }
                i += 12 + 16 + 32;
            }
            _ => return None,
        }
    }
    if i + 4 > file.len() {
        return None;
    }
    let crc_got = u32::from_le_bytes(file[i..i + 4].try_into().ok()?);
    let crc_expect = crc32fast::hash(&file[off..i]);
    if crc_got != crc_expect {
        return None;
    }
    Some(&file[off..i + 4])
}

pub fn sgto_len_at(file: &[u8], off: usize) -> usize {
    read_sgto_at(file, off).map(|b| b.len()).unwrap_or(0)
}

/// Try unwrap CEK from SGTO using identities and/or passphrase.
pub fn unwrap_cek(
    sgto: &[u8],
    identities: &[Identity],
    pass: Option<&str>,
    salt: &[u8; 16],
) -> Result<[u8; 32]> {
    if sgto.len() < SGTO_HEADER + 4 || sgto[0..4] != SGTO_MAGIC {
        return Err(Error::Msg("missing SGTO".into()));
    }
    let count = sgto[5] as usize;
    let mut i = SGTO_HEADER;
    let end = sgto.len() - 4;
    for _ in 0..count {
        if i >= end {
            break;
        }
        let kind = sgto[i];
        i += 1;
        match kind {
            KIND_X25519 => {
                if i + RECIPIENT_REC > end {
                    break;
                }
                let hint = &sgto[i..i + 8];
                let eph_pk: [u8; 32] = sgto[i + 8..i + 40].try_into().unwrap();
                let nonce: [u8; 12] = sgto[i + 40..i + 52].try_into().unwrap();
                let tag: [u8; 16] = sgto[i + 52..i + 68].try_into().unwrap();
                let ct = &sgto[i + 68..i + 100];
                i += RECIPIENT_REC;
                for id in identities {
                    let pk = id.public();
                    if hint != pk.hint() {
                        // still try — hint collision rare; wrong hint → skip fast
                        continue;
                    }
                    let sk = StaticSecret::from(id.x25519_sk);
                    let eph = XPublic::from(eph_pk);
                    let shared = sk.diffie_hellman(&eph);
                    let wrap_key =
                        wrap_key_from_shared(shared.as_bytes(), &eph_pk, &pk.x25519_pk)?;
                    if let Ok(cek) = aes_unwrap(&wrap_key, &nonce, &tag, ct) {
                        if cek.len() == 32 {
                            let mut out = [0u8; 32];
                            out.copy_from_slice(&cek);
                            return Ok(out);
                        }
                    }
                }
                // Also try all identities ignoring hint (in case of older/no hint match)
                for id in identities {
                    let pk = id.public();
                    if hint == pk.hint() {
                        continue; // already tried
                    }
                    let sk = StaticSecret::from(id.x25519_sk);
                    let eph = XPublic::from(eph_pk);
                    let shared = sk.diffie_hellman(&eph);
                    let wrap_key =
                        wrap_key_from_shared(shared.as_bytes(), &eph_pk, &pk.x25519_pk)?;
                    if let Ok(cek) = aes_unwrap(&wrap_key, &nonce, &tag, ct) {
                        if cek.len() == 32 {
                            let mut out = [0u8; 32];
                            out.copy_from_slice(&cek);
                            return Ok(out);
                        }
                    }
                }
            }
            KIND_PASS => {
                if i + 12 + 16 + 32 > end {
                    break;
                }
                let nonce: [u8; 12] = sgto[i..i + 12].try_into().unwrap();
                let tag: [u8; 16] = sgto[i + 12..i + 28].try_into().unwrap();
                let ct = &sgto[i + 28..i + 60];
                i += 12 + 16 + 32;
                if let Some(p) = pass.filter(|s| !s.is_empty()) {
                    let mut key = [0u8; 32];
                    pbkdf2_hmac::<Sha256>(p.as_bytes(), salt, PBKDF2_ITERS, &mut key);
                    if let Ok(cek) = aes_unwrap(&key, &nonce, &tag, ct) {
                        if cek.len() == 32 {
                            let mut out = [0u8; 32];
                            out.copy_from_slice(&cek);
                            return Ok(out);
                        }
                    }
                }
            }
            _ => break,
        }
    }
    Err(Error::Msg(
        "could not unwrap CEK — need matching --identity or passphrase".into(),
    ))
}

/// Offset of SGTO in a mark (right after keystone / single header).

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn identity_roundtrip_file() {
        let dir = std::env::temp_dir().join(format!("sigil-id-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("me.sgk");
        let pub_path = dir.join("me.pub");
        let pk = keygen_ecc(&path, Some(&pub_path)).unwrap();
        let id = Identity::load(&path).unwrap();
        assert_eq!(id.public().x25519_pk, pk.x25519_pk);
        let loaded = PublicIdentity::load(&pub_path).unwrap();
        assert_eq!(loaded.x25519_pk, pk.x25519_pk);
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn raw_identity_v2_roundtrip_owner_only() {
        let dir = std::env::temp_dir().join(format!("sigil-id2-{}", std::process::id()));
        let _ = std::fs::create_dir_all(&dir);
        let path = dir.join("pgp.sgk");
        let base = Identity::generate().unwrap();
        let id = Identity::from_raw(base.x25519_sk, base.ed25519_seed, Some([7u8; 20]));
        id.write(&path).unwrap();
        let b = std::fs::read(&path).unwrap();
        assert_eq!(b[4], ID_VERSION_RAW);
        let back = Identity::load(&path).unwrap();
        assert_eq!(back.pgp_fpr, Some([7u8; 20]));
        assert_eq!(back.public().x25519_pk, base.public().x25519_pk);
        assert_eq!(back.public().ed25519_pk, base.public().ed25519_pk);
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = std::fs::metadata(&path).unwrap().permissions().mode() & 0o777;
            assert_eq!(mode, 0o600);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn sgto_wrap_unwrap() {
        let alice = Identity::generate().unwrap();
        let bob = Identity::generate().unwrap();
        let mut cek = [0u8; 32];
        getrandom::getrandom(&mut cek).unwrap();
        let salt = [9u8; 16];
        let sgto = build_sgto(&cek, &[alice.public()], Some("hunter2"), &salt).unwrap();
        assert!(read_sgto_at(&sgto, 0).is_some());
        let got = unwrap_cek(&sgto, &[alice], None, &salt).unwrap();
        assert_eq!(got, cek);
        let got2 = unwrap_cek(&sgto, &[], Some("hunter2"), &salt).unwrap();
        assert_eq!(got2, cek);
        assert!(unwrap_cek(&sgto, &[bob], None, &salt).is_err());
        assert!(unwrap_cek(&sgto, &[], Some("wrong"), &salt).is_err());
    }
}
