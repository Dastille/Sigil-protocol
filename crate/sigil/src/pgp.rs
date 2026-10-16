//! Minimal OpenPGP import: v4 / v6 Curve25519 keys → Sigil identity (.sgk) / public (.pub).
//!
//! Scope is deliberately narrow. Accepted: a v4 key whose primary is Ed25519
//! (legacy EdDSA algo 22, or RFC 9580 algo 27) with at least one Curve25519
//! encryption subkey (legacy ECDH cv25519 algo 18, or RFC 9580 X25519 algo 25),
//! or an RFC 9580 v6 key (Ed25519 algo 27 + X25519 algo 25, SHA-256 fingerprints,
//! salted v6 self-signatures). The Ed25519 primary becomes the attest half; the
//! newest valid encryption subkey becomes the SGTO encrypt-to half. RSA/DSA/NIST
//! keys are refused.
//!
//! Every subkey we pick must carry a binding signature (0x18) that verifies
//! against the primary; verified revocations (0x20 primary, 0x28 subkey) and
//! expired keys are refused. Secret import takes an unprotected secret key
//! (S2K usage 0) or a passphrase-protected one:
//! - usage 254 / legacy 255: string-to-key (simple / salted / iterated+salted over
//!   SHA-1/SHA-2) → AES-128/192/256 in OpenPGP CFB (RFC 4880 §5.5.3 / RFC 9580
//!   §5.5.3), SHA-1 (254) or 16-bit (255) check;
//! - usage 253 (RFC 9580 AEAD): Argon2id (capped, see [`ARGON2_MAX_ENCODED_M`]) or
//!   iterated S2K → HKDF-SHA256 KEK → AES-OCB / GCM / EAX with the packet type and
//!   public key packet as associated data; the tag check fails closed.
//!
//! Recovered scalars are always checked against the public points.
//!
//! This touches key files only. Seal (.sg1) bytes and SGTO are unchanged.

use crate::keys::{Identity, PublicIdentity};
use crate::{Error, Result};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};
use zeroize::Zeroizing;

const OID_ED25519: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0xDA, 0x47, 0x0F, 0x01];
const OID_CV25519: &[u8] = &[0x2B, 0x06, 0x01, 0x04, 0x01, 0x97, 0x55, 0x01, 0x05, 0x01];

const TAG_SIG: u8 = 2;
const TAG_SECRET_KEY: u8 = 5;
const TAG_PUBLIC_KEY: u8 = 6;
const TAG_SECRET_SUBKEY: u8 = 7;
const TAG_USER_ID: u8 = 13;
const TAG_PUBLIC_SUBKEY: u8 = 14;

const ALGO_ECDH: u8 = 18;
const ALGO_EDDSA_LEGACY: u8 = 22;
const ALGO_X25519: u8 = 25;
const ALGO_ED25519: u8 = 27;

const SIG_SUBKEY_BINDING: u8 = 0x18;
const SIG_DIRECT_KEY: u8 = 0x1F;
const SIG_KEY_REVOCATION: u8 = 0x20;
const SIG_SUBKEY_REVOCATION: u8 = 0x28;

const KEYFLAG_ENCRYPT: u8 = 0x04 | 0x08;

fn err(s: impl Into<String>) -> Error {
    Error::Msg(format!("pgp import: {}", s.into()))
}

/// Result of importing an OpenPGP key.
pub struct PgpImport {
    pub public: PublicIdentity,
    /// Present only when the input held unprotected secret material for both halves.
    pub secret: Option<Identity>,
    /// Primary key fingerprint: 20 bytes (v4, SHA-1) or 32 bytes (v6, SHA-256).
    pub primary_fpr: Vec<u8>,
    pub subkey_fpr: Vec<u8>,
    /// OpenPGP key version of the primary (4 or 6).
    pub key_version: u8,
    pub user_id: Option<String>,
    /// True if the input held secret packets (even if we did not use them).
    pub had_secret_packets: bool,
}

/// Cheap sniff: does this look like an OpenPGP key (armored or binary)?
pub fn looks_like_pgp(b: &[u8]) -> bool {
    let head = &b[..b.len().min(64)];
    if head.windows(14).any(|w| w == b"-----BEGIN PGP") {
        return true;
    }
    match b.first() {
        Some(&c) if c & 0x80 != 0 => {
            let tag = if c & 0x40 != 0 {
                c & 0x3f
            } else {
                (c >> 2) & 0x0f
            };
            tag == TAG_PUBLIC_KEY || tag == TAG_SECRET_KEY
        }
        _ => false,
    }
}

pub fn import(input: &[u8]) -> Result<PgpImport> {
    import_with_passphrase(input, None)
}

/// Like [`import`], decrypting passphrase-protected secret keys with `passphrase`.
/// A wrong passphrase is an error (never a silent public-only import).
pub fn import_with_passphrase(input: &[u8], passphrase: Option<&[u8]>) -> Result<PgpImport> {
    let data = Zeroizing::new(dearmor(input)?);
    let pkts = packets(&data)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    select(&pkts, now, passphrase)
}

/// True when the file holds secret key packets protected by a passphrase.
pub fn secret_is_protected(input: &[u8]) -> bool {
    let Ok(data) = dearmor(input) else {
        return false;
    };
    let Ok(pkts) = packets(&data) else {
        return false;
    };
    pkts.iter().any(|p| {
        (p.tag == TAG_SECRET_KEY || p.tag == TAG_SECRET_SUBKEY)
            && parse_key(p.tag, p.body, None).map_or(false, |k| k.protected)
    })
}

// ---------------------------------------------------------------- armor

fn dearmor(input: &[u8]) -> Result<Vec<u8>> {
    if input.first().map_or(false, |c| c & 0x80 != 0) {
        return Ok(input.to_vec());
    }
    let text = std::str::from_utf8(input).map_err(|_| err("not armored text or binary OpenPGP"))?;
    let mut lines = text.lines().map(|l| l.trim_end_matches('\r'));
    let begin = lines
        .by_ref()
        .find(|l| l.starts_with("-----BEGIN PGP"))
        .ok_or_else(|| err("no -----BEGIN PGP armor line"))?;
    if !(begin.contains("PUBLIC KEY BLOCK") || begin.contains("PRIVATE KEY BLOCK")) {
        return Err(err(format!("armor is not a key block: {begin}")));
    }
    // Armor headers run until the first blank line.
    for l in lines.by_ref() {
        if l.trim().is_empty() {
            break;
        }
    }
    let mut b64 = String::new();
    let mut crc: Option<String> = None;
    let mut ended = false;
    for l in lines {
        let l = l.trim();
        if l.starts_with("-----END PGP") {
            ended = true;
            break;
        }
        if let Some(c) = l.strip_prefix('=') {
            if l.len() == 5 {
                crc = Some(c.to_string());
                continue;
            }
        }
        b64.push_str(l);
    }
    if !ended {
        return Err(err("armor has no END line"));
    }
    let raw = b64_decode(&b64)?;
    if let Some(c) = crc {
        let want = b64_decode(&c)?;
        let got = crc24(&raw);
        if want.len() != 3 || want != got.to_be_bytes()[1..] {
            return Err(err("armor CRC24 mismatch (file damaged?)"));
        }
    }
    Ok(raw)
}

fn b64_decode(s: &str) -> Result<Vec<u8>> {
    fn val(c: u8) -> Option<u32> {
        Some(match c {
            b'A'..=b'Z' => (c - b'A') as u32,
            b'a'..=b'z' => (c - b'a' + 26) as u32,
            b'0'..=b'9' => (c - b'0' + 52) as u32,
            b'+' => 62,
            b'/' => 63,
            _ => return None,
        })
    }
    let clean: Vec<u8> = s.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    let body: Vec<u8> = clean.iter().copied().take_while(|&c| c != b'=').collect();
    if clean[body.len()..].iter().any(|&c| c != b'=') {
        return Err(err("bad base64 padding"));
    }
    let mut out = Vec::with_capacity(body.len() * 3 / 4);
    let mut acc = 0u32;
    let mut bits = 0u32;
    for &c in &body {
        let v = val(c).ok_or_else(|| err("bad base64 character"))?;
        acc = (acc << 6) | v;
        bits += 6;
        if bits >= 8 {
            bits -= 8;
            out.push((acc >> bits) as u8);
            acc &= (1 << bits) - 1;
        }
    }
    Ok(out)
}

fn crc24(data: &[u8]) -> u32 {
    let mut crc: u32 = 0xB704CE;
    for &b in data {
        crc ^= (b as u32) << 16;
        for _ in 0..8 {
            crc <<= 1;
            if crc & 0x1000000 != 0 {
                crc ^= 0x1864CFB;
            }
        }
    }
    crc & 0xFFFFFF
}

// ---------------------------------------------------------------- packets

struct Packet<'a> {
    tag: u8,
    body: &'a [u8],
}

fn packets(data: &[u8]) -> Result<Vec<Packet<'_>>> {
    let mut out = Vec::new();
    let mut p = 0usize;
    let need = |p: usize, n: usize| -> Result<()> {
        if p + n > data.len() {
            Err(err("truncated packet"))
        } else {
            Ok(())
        }
    };
    while p < data.len() {
        let c = data[p];
        p += 1;
        if c & 0x80 == 0 {
            return Err(err("bad packet header"));
        }
        let (tag, len) = if c & 0x40 != 0 {
            let tag = c & 0x3f;
            need(p, 1)?;
            let o1 = data[p] as usize;
            p += 1;
            let len = if o1 < 192 {
                o1
            } else if o1 < 224 {
                need(p, 1)?;
                let l = ((o1 - 192) << 8) + data[p] as usize + 192;
                p += 1;
                l
            } else if o1 == 255 {
                need(p, 4)?;
                let l = u32::from_be_bytes(data[p..p + 4].try_into().unwrap()) as usize;
                p += 4;
                l
            } else {
                return Err(err("partial-length packets are not valid in a key"));
            };
            (tag, len)
        } else {
            let tag = (c >> 2) & 0x0f;
            let len = match c & 3 {
                0 => {
                    need(p, 1)?;
                    p += 1;
                    data[p - 1] as usize
                }
                1 => {
                    need(p, 2)?;
                    p += 2;
                    u16::from_be_bytes([data[p - 2], data[p - 1]]) as usize
                }
                2 => {
                    need(p, 4)?;
                    p += 4;
                    u32::from_be_bytes(data[p - 4..p].try_into().unwrap()) as usize
                }
                _ => data.len() - p,
            };
            (tag, len)
        };
        need(p, len)?;
        out.push(Packet {
            tag,
            body: &data[p..p + len],
        });
        p += len;
    }
    Ok(out)
}

struct Reader<'a> {
    b: &'a [u8],
    p: usize,
}

impl<'a> Reader<'a> {
    fn take(&mut self, n: usize) -> Result<&'a [u8]> {
        if self.p + n > self.b.len() {
            return Err(err("truncated key material"));
        }
        let s = &self.b[self.p..self.p + n];
        self.p += n;
        Ok(s)
    }
    fn u8(&mut self) -> Result<u8> {
        Ok(self.take(1)?[0])
    }
    fn u16(&mut self) -> Result<u16> {
        let s = self.take(2)?;
        Ok(u16::from_be_bytes([s[0], s[1]]))
    }
    fn u32(&mut self) -> Result<u32> {
        Ok(u32::from_be_bytes(self.take(4)?.try_into().unwrap()))
    }
    fn mpi(&mut self) -> Result<&'a [u8]> {
        let bits = self.u16()? as usize;
        self.take(bits.div_ceil(8))
    }
    fn oid(&mut self) -> Result<&'a [u8]> {
        let n = self.u8()? as usize;
        self.take(n)
    }
}

fn left_pad32(b: &[u8]) -> Result<[u8; 32]> {
    if b.len() > 32 {
        return Err(err("scalar longer than 32 bytes"));
    }
    let mut out = [0u8; 32];
    out[32 - b.len()..].copy_from_slice(b);
    Ok(out)
}

#[derive(Clone, Copy, PartialEq, Debug)]
enum Kind {
    Ed25519,
    X25519,
    Other,
}

struct Key {
    /// Key packet version: 4 or 6 (RFC 9580).
    version: u8,
    algo: u8,
    kind: Kind,
    created: u32,
    /// Public packet body (version .. end of public material) — fingerprint/hash input.
    pub_body: Vec<u8>,
    public: [u8; 32],
    secret: Option<[u8; 32]>,
    protected: bool,
}

impl Key {
    /// Key as hashed into signatures and fingerprints: 0x99 || u16 len (v4),
    /// 0x9B || u32 len (v6), then the public packet body.
    fn hash_prefix(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(5 + self.pub_body.len());
        if self.version == 6 {
            v.push(0x9B);
            v.extend_from_slice(&(self.pub_body.len() as u32).to_be_bytes());
        } else {
            v.push(0x99);
            v.extend_from_slice(&(self.pub_body.len() as u16).to_be_bytes());
        }
        v.extend_from_slice(&self.pub_body);
        v
    }
    /// v4: SHA-1 (20 bytes). v6: SHA-256 (32 bytes), RFC 9580 §5.5.4.
    fn fingerprint(&self) -> Vec<u8> {
        if self.version == 6 {
            Sha256::digest(self.hash_prefix()).to_vec()
        } else {
            Sha1::digest(self.hash_prefix()).to_vec()
        }
    }
}

fn parse_key(tag: u8, body: &[u8], passphrase: Option<&[u8]>) -> Result<Key> {
    let mut r = Reader { b: body, p: 0 };
    let ver = r.u8()?;
    if ver != 4 && ver != 6 {
        return Err(err(format!(
            "OpenPGP v{ver} key packets are not supported (v4 and v6 only)"
        )));
    }
    let created = r.u32()?;
    let algo = r.u8()?;
    // v6 counts the public key material (RFC 9580 §5.5.2.3).
    let material_len = if ver == 6 {
        Some(r.u32()? as usize)
    } else {
        None
    };
    let material_start = r.p;
    let is_secret_packet = tag == TAG_SECRET_KEY || tag == TAG_SECRET_SUBKEY;
    let mut kind = Kind::Other;
    let mut public = [0u8; 32];
    match algo {
        ALGO_EDDSA_LEGACY | ALGO_ECDH if ver == 6 => {
            return Err(err(
                "v6 key uses legacy EdDSA/ECDH (algo 22/18), which RFC 9580 forbids for v6 keys",
            ));
        }
        ALGO_EDDSA_LEGACY | ALGO_ECDH => {
            let oid = r.oid()?;
            let point = r.mpi()?;
            if algo == ALGO_ECDH {
                let kdf_len = r.u8()? as usize;
                r.take(kdf_len)?;
            }
            let want_oid = if algo == ALGO_ECDH {
                OID_CV25519
            } else {
                OID_ED25519
            };
            if oid == want_oid && point.len() == 33 && point[0] == 0x40 {
                public.copy_from_slice(&point[1..]);
                kind = if algo == ALGO_ECDH {
                    Kind::X25519
                } else {
                    Kind::Ed25519
                };
            }
        }
        ALGO_X25519 | ALGO_ED25519 => {
            public.copy_from_slice(r.take(32)?);
            kind = if algo == ALGO_X25519 {
                Kind::X25519
            } else {
                Kind::Ed25519
            };
        }
        _ => {
            // Unsupported algorithm: we only need to know it is not ours.
            let pub_body = match material_len {
                Some(n) => r
                    .take(n)
                    .map(|_| body[..r.p].to_vec())
                    .unwrap_or_else(|_| body.to_vec()),
                None => body.to_vec(),
            };
            return Ok(Key {
                version: ver,
                algo,
                kind,
                created,
                pub_body,
                public,
                secret: None,
                protected: false,
            });
        }
    }
    if let Some(n) = material_len {
        if r.p - material_start != n {
            return Err(err(
                "v6 public key material length does not match its count",
            ));
        }
    }
    let pub_end = r.p;
    let mut secret = None;
    let mut protected = false;
    if is_secret_packet && kind != Kind::Other {
        let usage = r.u8()?;
        // v6: one octet counting every S2K parameter field that follows (§5.5.3).
        let params_len = if ver == 6 && usage != 0 {
            Some(r.u8()? as usize)
        } else {
            None
        };
        if usage == 255 && ver == 6 {
            return Err(err(
                "v6 secret key uses MalleableCFB (usage 255), which RFC 9580 forbids",
            ));
        }
        if usage == 253 || usage == 254 || usage == 255 {
            match passphrase {
                None => protected = true,
                Some(pass) => {
                    let ctx = KeyCtx {
                        tag,
                        version: ver,
                        kind,
                        algo,
                        public: &public,
                        pub_body: &body[..pub_end],
                    };
                    secret = decrypt_secret(usage, params_len, &mut r, body, pass, &ctx)?;
                }
            }
        } else if usage != 0 {
            protected = true;
            if passphrase.is_some() {
                return Err(err(
                    "pre-RFC 2440 secret key protection isn't supported; re-export with a current GnuPG",
                ));
            }
        } else {
            let start = r.p;
            let raw: [u8; 32] = match algo {
                ALGO_X25519 | ALGO_ED25519 => r.take(32)?.try_into().unwrap(),
                _ => left_pad32(r.mpi()?)?,
            };
            if ver == 4 {
                let material = &body[start..r.p];
                let want = r.u16()?;
                let sum = material.iter().fold(0u16, |a, &b| a.wrapping_add(b as u16));
                if sum != want {
                    return Err(err("secret key checksum mismatch (damaged export?)"));
                }
            } else if r.p != body.len() {
                // v6 has no checksum: the cleartext must end exactly at the secret.
                return Err(err("unexpected bytes after v6 secret key material"));
            }
            secret = Some(recover_secret(kind, algo, raw, &public)?);
        }
    }
    Ok(Key {
        version: ver,
        algo,
        kind,
        created,
        pub_body: body[..pub_end].to_vec(),
        public,
        secret,
        protected,
    })
}

/// What decryption needs to know about the enclosing key packet.
struct KeyCtx<'a> {
    tag: u8,
    version: u8,
    kind: Kind,
    algo: u8,
    public: &'a [u8; 32],
    /// Public key packet fields from the version octet on (AEAD associated data).
    pub_body: &'a [u8],
}

// ---------------------------------------------------------------- S2K / CFB / AEAD

const HASH_SHA1: u8 = 2;
const HASH_SHA256: u8 = 8;
const HASH_SHA384: u8 = 9;
const HASH_SHA512: u8 = 10;
const HASH_SHA224: u8 = 11;

const AEAD_EAX: u8 = 1;
const AEAD_OCB: u8 = 2;
const AEAD_GCM: u8 = 3;

/// Argon2 memory cap: 2^22 KiB = 4 GiB. RFC 9580 allows up to 2^31 KiB (2 TiB);
/// a hostile key file must not be able to make `import-pgp` allocate that.
/// RFC 9106's first recommended setting (m = 2^21, 2 GiB) stays inside.
pub const ARGON2_MAX_ENCODED_M: u8 = 22;
/// Argon2 pass cap, and a combined passes × memory budget (2^26 KiB-passes,
/// e.g. 16 passes at 4 GiB or 1024 passes at 64 MiB) so CPU time stays bounded too.
pub const ARGON2_MAX_PASSES: u8 = 64;
const ARGON2_MAX_WORK_LOG2: u32 = 26;

enum S2k {
    Simple {
        hash: u8,
    },
    Salted {
        hash: u8,
        salt: [u8; 8],
    },
    Iterated {
        hash: u8,
        salt: [u8; 8],
        count: usize,
    },
    /// RFC 9580 §3.7.1.4 (type 4); only valid with AEAD protection.
    Argon2 {
        salt: [u8; 16],
        t: u8,
        p: u8,
        m: u8,
    },
    /// GnuPG extension 101: no secret here (stub / smartcard).
    GnuStub,
}

fn parse_s2k(r: &mut Reader<'_>) -> Result<S2k> {
    let t = r.u8()?;
    match t {
        0 => Ok(S2k::Simple { hash: r.u8()? }),
        1 => {
            let hash = r.u8()?;
            Ok(S2k::Salted {
                hash,
                salt: r.take(8)?.try_into().unwrap(),
            })
        }
        3 => {
            let hash = r.u8()?;
            let salt = r.take(8)?.try_into().unwrap();
            let c = r.u8()? as usize;
            let count = (16 + (c & 15)) << ((c >> 4) + 6);
            Ok(S2k::Iterated { hash, salt, count })
        }
        4 => {
            let salt = r.take(16)?.try_into().unwrap();
            let (t, p, m) = (r.u8()?, r.u8()?, r.u8()?);
            Ok(S2k::Argon2 { salt, t, p, m })
        }
        101 => {
            let _hash = r.u8()?;
            if r.take(3)? != b"GNU" {
                return Err(err("unknown GnuPG S2K extension"));
            }
            Ok(S2k::GnuStub)
        }
        t => Err(err(format!("unsupported S2K type {t}"))),
    }
}

/// Check Argon2 parameters against RFC 9580 and Sigil's resource caps
/// before anything is allocated.
fn argon2_check(t: u8, p: u8, m: u8) -> Result<()> {
    if t == 0 || p == 0 {
        return Err(err(
            "Argon2 S2K with zero passes or parallelism (malformed key)",
        ));
    }
    // m must be in 3 + ceil(log2 p) ..= 31, i.e. at least 8*p KiB.
    let min_m = 3 + (p as u32).next_power_of_two().trailing_zeros();
    if (m as u32) < min_m || m > 31 {
        return Err(err(format!(
            "Argon2 S2K memory exponent {m} is out of range for parallelism {p} (malformed key)"
        )));
    }
    if m > ARGON2_MAX_ENCODED_M {
        return Err(err(format!(
            "Argon2 S2K wants 2^{m} KiB of memory; Sigil caps import at 2^{ARGON2_MAX_ENCODED_M} KiB \
             (4 GiB) so a hostile key can't exhaust RAM. Re-protect the key with less memory \
             (e.g. sq key password) and try again"
        )));
    }
    let work_log2 = m as u32 + (t as u32).next_power_of_two().trailing_zeros();
    if t > ARGON2_MAX_PASSES || work_log2 > ARGON2_MAX_WORK_LOG2 {
        return Err(err(format!(
            "Argon2 S2K wants {t} passes over 2^{m} KiB; Sigil caps import at {ARGON2_MAX_PASSES} \
             passes and 2^{ARGON2_MAX_WORK_LOG2} KiB-passes in total"
        )));
    }
    Ok(())
}

fn argon2_derive(
    pass: &[u8],
    salt: &[u8; 16],
    t: u8,
    p: u8,
    m: u8,
    key_len: usize,
) -> Result<Zeroizing<Vec<u8>>> {
    use argon2::{Algorithm, Argon2, Block, Params, Version};
    use zeroize::Zeroize;
    argon2_check(t, p, m)?;
    let params = Params::new(1u32 << m, t as u32, p as u32, Some(key_len))
        .map_err(|e| err(format!("Argon2 parameters rejected: {e}")))?;
    let blocks_n = params.block_count();
    let mut blocks: Vec<Block> = Vec::new();
    blocks.try_reserve_exact(blocks_n).map_err(|_| {
        err(format!(
            "not enough memory for Argon2 S2K (needs 2^{m} KiB)"
        ))
    })?;
    blocks.resize(blocks_n, Block::default());
    let mut out = Zeroizing::new(vec![0u8; key_len]);
    let res = Argon2::new(Algorithm::Argon2id, Version::V0x13, params)
        .hash_password_into_with_memory(pass, salt, &mut out, &mut blocks);
    blocks.iter_mut().for_each(|b| b.zeroize());
    res.map_err(|e| err(format!("Argon2 S2K failed: {e}")))?;
    Ok(out)
}

fn hasher(algo: u8) -> Result<Box<dyn sha2::digest::DynDigest>> {
    Ok(match algo {
        HASH_SHA1 => Box::new(Sha1::new()),
        HASH_SHA224 => Box::new(Sha224::new()),
        HASH_SHA256 => Box::new(Sha256::new()),
        HASH_SHA384 => Box::new(Sha384::new()),
        HASH_SHA512 => Box::new(Sha512::new()),
        a => {
            return Err(err(format!(
                "S2K hash algorithm {a} not supported (SHA-1/SHA-2 only)"
            )))
        }
    })
}

/// OpenPGP string-to-key (RFC 4880 §3.7.1 / RFC 9580 §3.7.1). When the key is longer
/// than one digest, context `i` is preloaded with `i` zero octets. Argon2 (§3.7.1.4)
/// produces the whole key in one Argon2id call.
fn s2k_derive(s2k: &S2k, pass: &[u8], key_len: usize) -> Result<Zeroizing<Vec<u8>>> {
    if let S2k::Argon2 { salt, t, p, m } = s2k {
        return argon2_derive(pass, salt, *t, *p, *m, key_len);
    }
    let mut out = Zeroizing::new(Vec::with_capacity(key_len + 64));
    let mut i = 0usize;
    while out.len() < key_len {
        let (hash, salt, count) = match s2k {
            S2k::Simple { hash } => (*hash, None, None),
            S2k::Salted { hash, salt } => (*hash, Some(salt), None),
            S2k::Iterated { hash, salt, count } => (*hash, Some(salt), Some(*count)),
            S2k::Argon2 { .. } => unreachable!(),
            S2k::GnuStub => return Err(err("no secret material (GnuPG stub)")),
        };
        let mut h = hasher(hash)?;
        h.update(&vec![0u8; i]);
        let mut sp = Zeroizing::new(Vec::with_capacity(8 + pass.len()));
        if let Some(salt) = salt {
            sp.extend_from_slice(salt);
        }
        sp.extend_from_slice(pass);
        match count {
            None => h.update(&sp),
            Some(count) => {
                // Hash `count` octets of the repeating salt||pass stream (at least one copy).
                let total = count.max(sp.len());
                if sp.is_empty() {
                    return Err(err("empty S2K input"));
                }
                let reps = (65536 / sp.len()).max(1);
                let mut block = Zeroizing::new(Vec::with_capacity(reps * sp.len()));
                for _ in 0..reps {
                    block.extend_from_slice(&sp);
                }
                let mut left = total;
                while left >= block.len() {
                    h.update(&block);
                    left -= block.len();
                }
                h.update(&block[..left]);
            }
        }
        let d = Zeroizing::new(h.finalize().into_vec());
        out.extend_from_slice(&d);
        i += 1;
    }
    out.truncate(key_len);
    Ok(out)
}

fn cfb_decrypt(sym: u8, key: &[u8], iv: &[u8], buf: &mut [u8]) -> Result<()> {
    use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
    let bad = |_| err("bad AES key/IV length");
    match sym {
        7 => cfb_mode::Decryptor::<aes::Aes128>::new_from_slices(key, iv)
            .map_err(bad)?
            .decrypt(buf),
        8 => cfb_mode::Decryptor::<aes::Aes192>::new_from_slices(key, iv)
            .map_err(bad)?
            .decrypt(buf),
        9 => cfb_mode::Decryptor::<aes::Aes256>::new_from_slices(key, iv)
            .map_err(bad)?
            .decrypt(buf),
        _ => unreachable!(),
    }
    Ok(())
}

/// Nonce length per AEAD mode (RFC 9580 §5.13.2).
fn aead_nonce_len(aead: u8) -> Result<usize> {
    match aead {
        AEAD_EAX => Ok(16),
        AEAD_OCB => Ok(15),
        AEAD_GCM => Ok(12),
        a => Err(err(format!(
            "AEAD algorithm {a} not supported for secret keys (EAX, OCB and GCM are)"
        ))),
    }
}

/// One-shot AEAD open (ciphertext || 16-byte tag). `None` on authentication failure.
fn aead_open(
    sym: u8,
    aead: u8,
    key: &[u8],
    nonce: &[u8],
    ct: &[u8],
    ad: &[u8],
) -> Option<Zeroizing<Vec<u8>>> {
    use aes_gcm::aead::{consts::U12, consts::U15, Aead, KeyInit, Payload};
    fn open<A: KeyInit + Aead>(
        key: &[u8],
        nonce: &[u8],
        ct: &[u8],
        ad: &[u8],
    ) -> Option<Zeroizing<Vec<u8>>> {
        let c = A::new_from_slice(key).ok()?;
        if nonce.len() != <A as aes_gcm::aead::AeadCore>::NonceSize::to_usize() {
            return None;
        }
        let n = aes_gcm::aead::Nonce::<A>::from_slice(nonce);
        c.decrypt(n, Payload { msg: ct, aad: ad })
            .ok()
            .map(Zeroizing::new)
    }
    use aes::{Aes128, Aes192, Aes256};
    use aes_gcm::aead::generic_array::typenum::Unsigned;
    match (aead, sym) {
        (AEAD_EAX, 7) => open::<eax::Eax<Aes128>>(key, nonce, ct, ad),
        (AEAD_EAX, 8) => open::<eax::Eax<Aes192>>(key, nonce, ct, ad),
        (AEAD_EAX, 9) => open::<eax::Eax<Aes256>>(key, nonce, ct, ad),
        (AEAD_OCB, 7) => open::<ocb3::Ocb3<Aes128, U15>>(key, nonce, ct, ad),
        (AEAD_OCB, 8) => open::<ocb3::Ocb3<Aes192, U15>>(key, nonce, ct, ad),
        (AEAD_OCB, 9) => open::<ocb3::Ocb3<Aes256, U15>>(key, nonce, ct, ad),
        (AEAD_GCM, 7) => open::<aes_gcm::AesGcm<Aes128, U12>>(key, nonce, ct, ad),
        (AEAD_GCM, 8) => open::<aes_gcm::AesGcm<Aes192, U12>>(key, nonce, ct, ad),
        (AEAD_GCM, 9) => open::<aes_gcm::AesGcm<Aes256, U12>>(key, nonce, ct, ad),
        _ => None,
    }
}

/// Decrypt S2K usage 253 (AEAD) / 254 (CFB+SHA-1) / 255 (CFB+checksum) secret
/// material and return the recovered scalar. `r` sits just after the usage octet
/// (and, for v6, after the parameter-count octet `params_len`).
fn decrypt_secret(
    usage: u8,
    params_len: Option<usize>,
    r: &mut Reader<'_>,
    body: &[u8],
    pass: &[u8],
    k: &KeyCtx<'_>,
) -> Result<Option<[u8; 32]>> {
    let params_start = r.p;
    let sym = r.u8()?;
    let aead = if usage == 253 { Some(r.u8()?) } else { None };
    let s2k = if k.version == 6 {
        // v6: the S2K specifier is length-prefixed.
        let n = r.u8()? as usize;
        let spec = r.take(n)?;
        let mut sr = Reader { b: spec, p: 0 };
        let s = parse_s2k(&mut sr)?;
        if sr.p != n {
            return Err(err(
                "S2K specifier length does not match its count (malformed key)",
            ));
        }
        s
    } else {
        parse_s2k(r)?
    };
    if matches!(s2k, S2k::GnuStub) {
        return Ok(None); // secret lives elsewhere (smartcard / --export-secret-subkeys stub)
    }
    if matches!(s2k, S2k::Argon2 { .. }) && usage != 253 {
        return Err(err(
            "Argon2 S2K is only valid with AEAD protection (usage 253); refusing malformed key",
        ));
    }
    let key_len = match sym {
        7 => 16,
        8 => 24,
        9 => 32,
        a => {
            return Err(err(format!(
                "secret key cipher {a} not supported (AES only); re-export with a current GnuPG"
            )))
        }
    };
    let iv_len = match aead {
        Some(a) => aead_nonce_len(a)?,
        None => 16,
    };
    let iv = r.take(iv_len)?;
    if let Some(n) = params_len {
        if r.p - params_start != n {
            return Err(err(
                "S2K parameter count does not match the fields (malformed key)",
            ));
        }
    }
    let rest = &body[r.p..];
    r.p = body.len();
    let key = s2k_derive(&s2k, pass, key_len)?;
    let wrong = || err("wrong passphrase (or damaged secret key)");
    let material: Zeroizing<Vec<u8>> = match aead {
        Some(a) => {
            // RFC 9580 §5.5.3: KEK = HKDF-SHA256(ikm = S2K key, no salt,
            // info = packet type (OpenPGP format) || version || cipher || AEAD mode);
            // AD = packet type || public key packet fields; one tag, no chunks.
            let ptag = 0xC0 | k.tag;
            let info = [ptag, k.version, sym, a];
            let mut kek = Zeroizing::new(vec![0u8; key_len]);
            hkdf::Hkdf::<Sha256>::new(None, &key)
                .expand(&info, &mut kek)
                .map_err(|_| err("HKDF expand failed"))?;
            let mut ad = Vec::with_capacity(1 + k.pub_body.len());
            ad.push(ptag);
            ad.extend_from_slice(k.pub_body);
            aead_open(sym, a, &kek, iv, rest, &ad).ok_or_else(|| {
                err("wrong passphrase (or damaged secret key): AEAD authentication failed")
            })?
        }
        None => {
            let mut pt = Zeroizing::new(rest.to_vec());
            cfb_decrypt(sym, &key, iv, &mut pt)?;
            let check_len = if usage == 254 { 20 } else { 2 };
            if pt.len() < check_len {
                return Err(wrong());
            }
            let (material, check) = pt.split_at(pt.len() - check_len);
            let ok = if usage == 254 {
                let d: [u8; 20] = Sha1::digest(material).into();
                d[..] == *check
            } else {
                let sum = material.iter().fold(0u16, |a, &b| a.wrapping_add(b as u16));
                sum.to_be_bytes()[..] == *check
            };
            if !ok {
                return Err(wrong());
            }
            Zeroizing::new(material.to_vec())
        }
    };
    let mut m = Reader { b: &material, p: 0 };
    let raw: Zeroizing<[u8; 32]> = Zeroizing::new(match k.algo {
        ALGO_X25519 | ALGO_ED25519 => m.take(32).map_err(|_| wrong())?.try_into().unwrap(),
        _ => left_pad32(m.mpi().map_err(|_| wrong())?)?,
    });
    if m.p != material.len() {
        return Err(wrong());
    }
    recover_secret(k.kind, k.algo, *raw, k.public).map(Some)
}

/// Turn the stored secret into Sigil's native form and prove it matches the public point.
fn recover_secret(kind: Kind, algo: u8, raw: [u8; 32], public: &[u8; 32]) -> Result<[u8; 32]> {
    match kind {
        Kind::Ed25519 => {
            if SigningKey::from_bytes(&raw).verifying_key().to_bytes() == *public {
                Ok(raw)
            } else {
                Err(err("Ed25519 secret does not match its public key"))
            }
        }
        Kind::X25519 => {
            // RFC 9580 X25519 stores the native (little-endian) scalar. Legacy
            // cv25519 stores it as a big-endian MPI, i.e. byte-reversed.
            let mut candidates = vec![raw];
            if algo == ALGO_ECDH {
                let mut rev = raw;
                rev.reverse();
                candidates.insert(0, rev);
            }
            for c in candidates {
                let pk = XPublic::from(&StaticSecret::from(c));
                if pk.as_bytes() == public {
                    return Ok(c);
                }
            }
            Err(err("X25519 secret does not match its public key"))
        }
        Kind::Other => Err(err("unsupported key algorithm")),
    }
}

// ---------------------------------------------------------------- signatures

struct Sig {
    /// Signature packet version (4 or 6).
    version: u8,
    sigtype: u8,
    hash_algo: u8,
    /// version .. end of hashed subpackets (hashed as the sig trailer).
    hashed_part: Vec<u8>,
    hashed_subs: Vec<u8>,
    left16: [u8; 2],
    /// v6 only: per-signature salt, hashed first (RFC 9580 §5.2.4).
    salt: Vec<u8>,
    sig: Option<[u8; 64]>,
}

fn parse_sig(body: &[u8]) -> Option<Sig> {
    let mut r = Reader { b: body, p: 0 };
    let version = r.u8().ok()?;
    if version != 4 && version != 6 {
        return None;
    }
    let v6 = version == 6;
    let sigtype = r.u8().ok()?;
    let pub_algo = r.u8().ok()?;
    let hash_algo = r.u8().ok()?;
    let hlen = if v6 {
        r.u32().ok()? as usize
    } else {
        r.u16().ok()? as usize
    };
    let hashed_subs = r.take(hlen).ok()?.to_vec();
    let hashed_part = body[..r.p].to_vec();
    let ulen = if v6 {
        r.u32().ok()? as usize
    } else {
        r.u16().ok()? as usize
    };
    r.take(ulen).ok()?;
    let left16: [u8; 2] = r.take(2).ok()?.try_into().ok()?;
    let salt = if v6 {
        let n = r.u8().ok()? as usize;
        r.take(n).ok()?.to_vec()
    } else {
        Vec::new()
    };
    let sig = match pub_algo {
        ALGO_EDDSA_LEGACY if !v6 => {
            let rr = left_pad32(r.mpi().ok()?).ok()?;
            let ss = left_pad32(r.mpi().ok()?).ok()?;
            let mut s = [0u8; 64];
            s[..32].copy_from_slice(&rr);
            s[32..].copy_from_slice(&ss);
            Some(s)
        }
        ALGO_ED25519 => Some(r.take(64).ok()?.try_into().ok()?),
        _ => None,
    };
    Some(Sig {
        version,
        sigtype,
        hash_algo,
        hashed_part,
        hashed_subs,
        left16,
        salt,
        sig,
    })
}

fn digest(algo: u8, data: &[u8]) -> Option<Vec<u8>> {
    Some(match algo {
        8 => Sha256::digest(data).to_vec(),
        9 => Sha384::digest(data).to_vec(),
        10 => Sha512::digest(data).to_vec(),
        11 => Sha224::digest(data).to_vec(),
        _ => return None, // MD5/SHA-1/RIPEMD refused for self-signatures.
    })
}

/// RFC 9580 Table 23: v6 signature salt size per hash.
fn v6_salt_len(hash: u8) -> Option<usize> {
    match hash {
        HASH_SHA256 | HASH_SHA224 => Some(16),
        HASH_SHA384 => Some(24),
        HASH_SHA512 => Some(32),
        _ => None,
    }
}

/// Verify `sig` made by Ed25519 `primary` (a v`key_version` key) over `prefix`
/// (key/uid material). v4 keys take v4 signatures, v6 keys v6 (salted) ones.
fn verify_sig(sig: &Sig, primary: &[u8; 32], key_version: u8, prefix: &[u8]) -> bool {
    let Some(raw) = sig.sig else { return false };
    if sig.version != key_version {
        return false;
    }
    let mut data = Vec::with_capacity(sig.salt.len() + prefix.len() + sig.hashed_part.len() + 6);
    if sig.version == 6 {
        if v6_salt_len(sig.hash_algo) != Some(sig.salt.len()) {
            return false;
        }
        data.extend_from_slice(&sig.salt);
    }
    data.extend_from_slice(prefix);
    data.extend_from_slice(&sig.hashed_part);
    data.push(sig.version);
    data.push(0xFF);
    data.extend_from_slice(&(sig.hashed_part.len() as u32).to_be_bytes());
    let Some(d) = digest(sig.hash_algo, &data) else {
        return false;
    };
    if d[..2] != sig.left16 {
        return false;
    }
    let Ok(vk) = VerifyingKey::from_bytes(primary) else {
        return false;
    };
    vk.verify_strict(&d, &Signature::from_bytes(&raw)).is_ok()
}

/// Hashed subpackets of interest: (key flags, key expiration seconds, sig creation).
fn subpackets(hashed: &[u8]) -> (Option<u8>, Option<u32>, u32) {
    let (mut flags, mut kexp, mut created) = (None, None, 0u32);
    let mut p = 0usize;
    while p < hashed.len() {
        let o = hashed[p] as usize;
        p += 1;
        let len = if o < 192 {
            o
        } else if o < 255 {
            if p >= hashed.len() {
                break;
            }
            let l = ((o - 192) << 8) + hashed[p] as usize + 192;
            p += 1;
            l
        } else {
            if p + 4 > hashed.len() {
                break;
            }
            let l = u32::from_be_bytes(hashed[p..p + 4].try_into().unwrap()) as usize;
            p += 4;
            l
        };
        if len == 0 || p + len > hashed.len() {
            break;
        }
        let ty = hashed[p] & 0x7f;
        let data = &hashed[p + 1..p + len];
        match ty {
            2 if data.len() == 4 => created = u32::from_be_bytes(data.try_into().unwrap()),
            9 if data.len() == 4 => kexp = Some(u32::from_be_bytes(data.try_into().unwrap())),
            27 if !data.is_empty() => flags = Some(data[0]),
            _ => {}
        }
        p += len;
    }
    (flags, kexp, created)
}

fn expired(key_created: u32, kexp: Option<u32>, now: u64) -> bool {
    match kexp {
        Some(0) | None => false,
        Some(s) => (key_created as u64 + s as u64) <= now,
    }
}

// ---------------------------------------------------------------- selection

fn select(pkts: &[Packet<'_>], now: u64, passphrase: Option<&[u8]>) -> Result<PgpImport> {
    let first = pkts.first().ok_or_else(|| err("empty key file"))?;
    if first.tag != TAG_PUBLIC_KEY && first.tag != TAG_SECRET_KEY {
        return Err(err("file does not start with a primary key packet"));
    }
    let primary = parse_key(first.tag, first.body, passphrase)?;
    if primary.kind != Kind::Ed25519 {
        return Err(err(format!(
            "primary key algorithm {} is not Ed25519; Sigil imports Curve25519 keys only \
             (gpg --quick-gen-key '<you>' ed25519 sign && gpg --quick-add-key <FPR> cv25519 encr)",
            primary.algo
        )));
    }
    let had_secret_packets = pkts
        .iter()
        .any(|p| p.tag == TAG_SECRET_KEY || p.tag == TAG_SECRET_SUBKEY);

    let primary_prefix = primary.hash_prefix();
    let mut user_id: Option<String> = None;
    let mut primary_exp: Option<u32> = None;
    let mut primary_revoked = false;
    let mut best_uid_sig_time = 0u32;
    // v6 keys carry primary-key metadata (expiry) on the direct-key self-signature.
    let mut direct_exp: Option<(u32, Option<u32>)> = None;

    // Walk the rest: direct sigs, then (uid, sigs)*, then (subkey, sigs)*.
    enum Ctx {
        Primary,
        Uid(Vec<u8>, String),
        Sub(usize),
        Skip,
    }
    let mut ctx = Ctx::Primary;
    let mut subs: Vec<(Key, bool, bool, Option<u8>, Option<u32>)> = Vec::new(); // key, bound, revoked, flags, exp
    for pkt in &pkts[1..] {
        match pkt.tag {
            TAG_USER_ID => {
                let mut pre = vec![0xB4];
                pre.extend_from_slice(&(pkt.body.len() as u32).to_be_bytes());
                pre.extend_from_slice(pkt.body);
                ctx = Ctx::Uid(pre, String::from_utf8_lossy(pkt.body).into_owned());
            }
            TAG_PUBLIC_SUBKEY | TAG_SECRET_SUBKEY => {
                let k = parse_key(pkt.tag, pkt.body, passphrase)?;
                subs.push((k, false, false, None, None));
                ctx = Ctx::Sub(subs.len() - 1);
            }
            TAG_PUBLIC_KEY | TAG_SECRET_KEY => break, // next key in a keyring: stop at the first
            TAG_SIG => {
                let Some(sig) = parse_sig(pkt.body) else {
                    continue;
                };
                match &ctx {
                    Ctx::Primary => {
                        if sig.sigtype == SIG_KEY_REVOCATION
                            && verify_sig(&sig, &primary.public, primary.version, &primary_prefix)
                        {
                            primary_revoked = true;
                        } else if sig.sigtype == SIG_DIRECT_KEY
                            && primary.version == 6
                            && verify_sig(&sig, &primary.public, primary.version, &primary_prefix)
                        {
                            let (_, kexp, t) = subpackets(&sig.hashed_subs);
                            if direct_exp.is_none_or(|(bt, _)| t >= bt) {
                                direct_exp = Some((t, kexp));
                            }
                        }
                    }
                    Ctx::Uid(pre, name) => {
                        if (0x10..=0x13).contains(&sig.sigtype) {
                            let mut data = primary_prefix.clone();
                            data.extend_from_slice(pre);
                            if verify_sig(&sig, &primary.public, primary.version, &data) {
                                let (_, kexp, t) = subpackets(&sig.hashed_subs);
                                if t >= best_uid_sig_time {
                                    best_uid_sig_time = t;
                                    primary_exp = kexp;
                                    user_id = Some(name.clone());
                                }
                            }
                        }
                    }
                    Ctx::Sub(i) => {
                        let i = *i;
                        let mut data = primary_prefix.clone();
                        data.extend_from_slice(&subs[i].0.hash_prefix());
                        if !matches!(sig.sigtype, SIG_SUBKEY_BINDING | SIG_SUBKEY_REVOCATION)
                            || subs[i].0.kind == Kind::Other
                            || !verify_sig(&sig, &primary.public, primary.version, &data)
                        {
                            continue;
                        }
                        if sig.sigtype == SIG_SUBKEY_REVOCATION {
                            subs[i].2 = true;
                        } else {
                            let (flags, kexp, _) = subpackets(&sig.hashed_subs);
                            subs[i].1 = true;
                            subs[i].3 = flags;
                            subs[i].4 = kexp;
                        }
                    }
                    Ctx::Skip => {}
                }
            }
            12 => {} // trust packet (keyring files): keep context
            _ => {
                ctx = Ctx::Skip; // user attribute etc.: ignore its signatures
            }
        }
    }
    if primary_revoked {
        return Err(err("primary key is revoked"));
    }
    if let Some((_, Some(kexp))) = direct_exp {
        if expired(primary.created, Some(kexp), now) {
            return Err(err("primary key has expired"));
        }
    }
    if expired(primary.created, primary_exp, now) {
        return Err(err("primary key has expired"));
    }
    let mut candidates: Vec<&(Key, bool, bool, Option<u8>, Option<u32>)> = subs
        .iter()
        .filter(|(k, bound, revoked, flags, kexp)| {
            k.kind == Kind::X25519
                && k.version == primary.version
                && *bound
                && !*revoked
                && flags.map_or(true, |f| f & KEYFLAG_ENCRYPT != 0)
                && !expired(k.created, *kexp, now)
        })
        .collect();
    candidates.sort_by_key(|(k, ..)| k.created);
    let Some((sub, ..)) = candidates.last() else {
        let unbound = subs
            .iter()
            .any(|(k, bound, ..)| k.kind == Kind::X25519 && !*bound);
        return Err(err(if unbound {
            "cv25519 subkey found but its binding signature does not verify — refusing"
        } else {
            "no usable cv25519/X25519 encryption subkey (add one: gpg --quick-add-key <FPR> cv25519 encr)"
        }));
    };

    let public = PublicIdentity {
        x25519_pk: sub.public,
        ed25519_pk: primary.public,
    };
    let primary_fpr = primary.fingerprint();
    // .sgk v2 has a 20-byte fingerprint slot. A v4 fingerprint fills it; RFC 9580
    // §14.1 forbids squeezing part of a v6 fingerprint into such a field, so v6
    // imports leave it all-zero (no SHA-1 fingerprint is all-zero) and the full
    // 32-byte v6 fingerprint is printed at import / recomputed from the key.
    let sgk_fpr: [u8; 20] = primary_fpr.as_slice().try_into().unwrap_or([0u8; 20]);
    let secret = match (primary.secret, sub.secret) {
        (Some(ed), Some(x)) => Some(Identity::from_raw(x, ed, Some(sgk_fpr))),
        _ => None,
    };
    Ok(PgpImport {
        public,
        secret,
        primary_fpr,
        subkey_fpr: sub.fingerprint(),
        key_version: primary.version,
        user_id,
        had_secret_packets,
    })
}

/// Why secret import is not possible, for CLI messages.
pub fn secret_unavailable_reason(input: &[u8]) -> String {
    let Ok(data) = dearmor(input) else {
        return "unreadable key".into();
    };
    let Ok(pkts) = packets(&data) else {
        return "unreadable key".into();
    };
    let mut any_secret = false;
    for p in &pkts {
        if p.tag == TAG_SECRET_KEY || p.tag == TAG_SECRET_SUBKEY {
            any_secret = true;
            if let Ok(k) = parse_key(p.tag, p.body, None) {
                if k.protected {
                    return "secret key is passphrase-protected; give its passphrase \
                            (prompt, --passphrase-file, or SIGIL_PGP_PASSPHRASE)"
                        .into();
                }
            }
        }
    }
    if any_secret {
        "secret export lacks the primary or the chosen subkey secret (gpg stub?)".into()
    } else {
        "file holds only a public key".into()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    const PUB_ASC: &[u8] = include_bytes!("../tests/fixtures/pgp/test-pub.asc");
    const PUB_GPG: &[u8] = include_bytes!("../tests/fixtures/pgp/test-pub.gpg");
    const SEC_ASC: &[u8] = include_bytes!("../tests/fixtures/pgp/test-sec.asc");
    const LOCKED: &[u8] = include_bytes!("../tests/fixtures/pgp/locked-sec.asc");
    const RSA: &[u8] = include_bytes!("../tests/fixtures/pgp/rsa-pub.asc");
    const FPR: &str = "5c3732680d936481b3b5d0315675d9f5af137892";
    const SUB_FPR: &str = "a0b0c8a26b6c03352f215ca1f59a387e09a9ed21";

    #[test]
    fn public_armored_and_binary_agree() {
        let a = import(PUB_ASC).unwrap();
        let b = import(PUB_GPG).unwrap();
        assert_eq!(hex::encode(&a.primary_fpr), FPR);
        assert_eq!(hex::encode(&a.subkey_fpr), SUB_FPR);
        assert_eq!(a.public.x25519_pk, b.public.x25519_pk);
        assert_eq!(a.public.ed25519_pk, b.public.ed25519_pk);
        assert!(a.secret.is_none());
        assert_eq!(
            a.user_id.as_deref(),
            Some("Sigil Test <test@sigil.invalid>")
        );
        assert!(looks_like_pgp(PUB_ASC) && looks_like_pgp(PUB_GPG));
    }

    #[test]
    fn secret_matches_public_and_roundtrips_sgto() {
        let s = import(SEC_ASC).unwrap();
        let p = import(PUB_ASC).unwrap();
        let id = s.secret.expect("unprotected secret");
        assert_eq!(id.public().x25519_pk, p.public.x25519_pk);
        assert_eq!(id.public().ed25519_pk, p.public.ed25519_pk);
        let mut cek = [0u8; 32];
        getrandom::getrandom(&mut cek).unwrap();
        let salt = [3u8; 16];
        let sgto = crate::keys::build_sgto(&cek, &[p.public.clone()], None, &salt).unwrap();
        let got = crate::keys::unwrap_cek(&sgto, &[id], None, &salt).unwrap();
        assert_eq!(got, cek);
    }

    #[test]
    fn locked_secret_gives_public_only_with_reason() {
        let l = import(LOCKED).unwrap();
        assert!(l.secret.is_none() && l.had_secret_packets);
        assert!(secret_unavailable_reason(LOCKED).contains("passphrase-protected"));
        assert!(secret_unavailable_reason(LOCKED).contains("--passphrase-file"));
    }

    #[test]
    fn rsa_refused() {
        let e = import(RSA).err().unwrap().to_string();
        assert!(e.contains("not Ed25519"), "{e}");
    }

    #[test]
    fn tampered_subkey_binding_refused() {
        let mut bin = dearmor(PUB_ASC).unwrap();
        let pkts = packets(&bin).unwrap();
        let sub = pkts.iter().find(|p| p.tag == TAG_PUBLIC_SUBKEY).unwrap();
        let off = sub.body.as_ptr() as usize - bin.as_ptr() as usize;
        // Flip a byte of the subkey creation time: binding sig must stop verifying.
        bin[off + 2] ^= 0x01;
        let e = import(&bin).err().unwrap().to_string();
        assert!(e.contains("binding signature"), "{e}");
    }

    #[test]
    fn armor_crc_detects_damage() {
        let s = std::str::from_utf8(PUB_ASC).unwrap();
        let mut lines: Vec<String> = s.lines().map(String::from).collect();
        let i = lines.iter().position(|l| l.starts_with("mDME")).unwrap();
        let mut b = lines[i].clone().into_bytes();
        b[10] = if b[10] == b'A' { b'B' } else { b'A' };
        lines[i] = String::from_utf8(b).unwrap();
        let e = import(lines.join("\n").as_bytes())
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("CRC24") || e.contains("pgp import"), "{e}");
    }

    #[test]
    fn revoked_newest_subkey_skipped() {
        let r = import(include_bytes!("../tests/fixtures/pgp/rotated-pub.asc")).unwrap();
        assert_eq!(
            hex::encode(r.subkey_fpr),
            "717bf0015bcd36d83809d4f21603472aaf6d6f38"
        );
    }

    #[test]
    fn expiry_math() {
        assert!(!expired(100, None, 10_000));
        assert!(!expired(100, Some(0), 10_000));
        assert!(expired(100, Some(50), 10_000));
        assert!(!expired(100, Some(50_000), 10_000));
    }

    const PGPY256: &[u8] = include_bytes!("../tests/fixtures/pgp/pgpy256-sec.asc");

    #[test]
    fn gpg_protected_secret_decrypts_with_passphrase() {
        // GnuPG 2.4 export: iterated+salted SHA-1, AES-128 CFB, SHA-1 check (usage 254).
        let p = import(LOCKED).unwrap();
        assert!(secret_is_protected(LOCKED) && !secret_is_protected(SEC_ASC));
        let s = import_with_passphrase(LOCKED, Some(b"hunter2")).unwrap();
        assert_eq!(
            hex::encode_upper(s.primary_fpr),
            "D72741DA96202F19169094EE7E85B88D75D629D3"
        );
        let id = s.secret.expect("decrypted secret");
        assert_eq!(id.public().x25519_pk, p.public.x25519_pk);
        assert_eq!(id.public().ed25519_pk, p.public.ed25519_pk);
        let cek = [9u8; 32];
        let salt = [4u8; 16];
        let sgto = crate::keys::build_sgto(&cek, &[p.public.clone()], None, &salt).unwrap();
        assert_eq!(
            crate::keys::unwrap_cek(&sgto, &[id], None, &salt).unwrap(),
            cek
        );
    }

    #[test]
    fn independent_aes256_sha512_secret_decrypts() {
        // Made by PGPy (AES-256, iterated+salted SHA-512), cross-checked by importing into gpg.
        let s = import_with_passphrase(PGPY256, Some(b"pgpy pass 256")).unwrap();
        assert_eq!(
            hex::encode_upper(s.primary_fpr),
            "5834A3244168C7852AF2388EE03B0A4A27E9BCDA"
        );
        assert_eq!(
            hex::encode_upper(s.subkey_fpr),
            "2E0ED3C7E41E94D70AF6D249982C8A39D81E44E6"
        );
        let id = s.secret.expect("decrypted secret");
        assert_eq!(id.public().x25519_pk, s.public.x25519_pk);
    }

    #[test]
    fn wrong_passphrase_and_damage_refused() {
        let e = import_with_passphrase(LOCKED, Some(b"hunter3"))
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("wrong passphrase"), "{e}");
        let e = import_with_passphrase(PGPY256, Some(b""))
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("wrong passphrase"), "{e}");
        // Flip the last encrypted byte of the primary secret packet: SHA-1 check fails.
        let mut bin = dearmor(LOCKED).unwrap();
        let end = {
            let pkts = packets(&bin).unwrap();
            let k = pkts.iter().find(|p| p.tag == TAG_SECRET_KEY).unwrap();
            k.body.as_ptr() as usize - bin.as_ptr() as usize + k.body.len()
        };
        bin[end - 1] ^= 0x01;
        let e = import_with_passphrase(&bin, Some(b"hunter2"))
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("wrong passphrase"), "{e}");
    }

    #[test]
    fn s2k_count_and_checks_254_255() {
        // RFC 4880 §3.7.1.3 coded count.
        let mut r = Reader {
            b: &[3, HASH_SHA256, 1, 2, 3, 4, 5, 6, 7, 8, 255],
            p: 0,
        };
        assert!(matches!(
            parse_s2k(&mut r).unwrap(),
            S2k::Iterated {
                count: 65011712,
                ..
            }
        ));
        let mut r = Reader {
            b: &[3, HASH_SHA256, 1, 2, 3, 4, 5, 6, 7, 8, 96],
            p: 0,
        };
        assert!(matches!(
            parse_s2k(&mut r).unwrap(),
            S2k::Iterated { count: 65536, .. }
        ));

        use cfb_mode::cipher::{AsyncStreamCipher, KeyIvInit};
        let seed = [0x42u8; 32];
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let salt = [7u8; 8];
        let spec = [3u8, HASH_SHA256, 7, 7, 7, 7, 7, 7, 7, 7, 96];
        let s2k = S2k::Iterated {
            hash: HASH_SHA256,
            salt,
            count: 65536,
        };
        let key = s2k_derive(&s2k, b"pw", 32).unwrap();
        let iv = [5u8; 16];
        for usage in [254u8, 255] {
            let mut pt = seed.to_vec();
            if usage == 254 {
                pt.extend_from_slice(&Sha1::digest(seed));
            } else {
                let sum = seed.iter().fold(0u16, |a, &b| a.wrapping_add(b as u16));
                pt.extend_from_slice(&sum.to_be_bytes());
            }
            cfb_mode::Encryptor::<aes::Aes256>::new_from_slices(&key, &iv)
                .unwrap()
                .encrypt(&mut pt);
            let mut body = vec![9u8];
            body.extend_from_slice(&spec);
            body.extend_from_slice(&iv);
            body.extend_from_slice(&pt);
            let ctx = KeyCtx {
                tag: TAG_SECRET_KEY,
                version: 4,
                kind: Kind::Ed25519,
                algo: ALGO_ED25519,
                public: &public,
                pub_body: &[],
            };
            let mut r = Reader { b: &body, p: 0 };
            let got = decrypt_secret(usage, None, &mut r, &body, b"pw", &ctx).unwrap();
            assert_eq!(got, Some(seed));
            let mut r = Reader { b: &body, p: 0 };
            assert!(decrypt_secret(usage, None, &mut r, &body, b"px", &ctx).is_err());
        }
    }

    // ------------------------------------------------ RFC 9580: Argon2, AEAD, v6

    const RFC_PUB: &[u8] = include_bytes!("../tests/fixtures/pgp/rfc9580-a3-pub.asc");
    const RFC_SEC: &[u8] = include_bytes!("../tests/fixtures/pgp/rfc9580-a4-sec.asc");
    const RFC_LOCKED: &[u8] = include_bytes!("../tests/fixtures/pgp/rfc9580-a5-locked-sec.asc");
    const RFC_PASS: &[u8] = b"correct horse battery staple";
    const RFC_FPR: &str = "CB186C4F0609A697E4D52DFA6C722B0C1F1E27C18A56708F6525EC27BAD9ACC9";
    const RFC_SUB_FPR: &str = "12C83F1E706F6308FE151A417743A1F033790E93E9978488D1DB378DA9930885";
    const SQ_V6: &[u8] = include_bytes!("../tests/fixtures/pgp/sq-v6-sec.asc");
    const OPJS: [(&[u8], &[u8], &str, &str); 4] = [
        // (file, passphrase, primary fpr, encrypt subkey fpr) as printed by OpenPGP.js.
        (
            include_bytes!("../tests/fixtures/pgp/opjs-ocb-sec.asc"),
            b"ocb pass",
            "a06012db9b2e0eb7e366d5cae6a184a73dd71bad",
            "1231d454484b491a4bfb78b27bd3a05e69bd08a8",
        ),
        (
            include_bytes!("../tests/fixtures/pgp/opjs-gcm-sec.asc"),
            b"gcm pass",
            "95caae6b3cce171dfc890247b666e23cf612fbaf",
            "a7abf823e08d5ef0f51b169960f1b22928ea805e",
        ),
        (
            include_bytes!("../tests/fixtures/pgp/opjs-eax-sec.asc"),
            b"eax pass",
            "8b50f97490734436b394374b5cd58b3cd5c8fe96",
            "f3c0ac73c1e9d23c1347b78edc770da0ebf6a0ba",
        ),
        (
            include_bytes!("../tests/fixtures/pgp/opjs-ocb-iter-sec.asc"),
            b"iter pass",
            "1831ee33b09b86ce12391bb5bbc535be71edba3a",
            "755845035af541328fef9521c7bed2e8a8264715",
        ),
    ];

    /// Byte offset of the first packet with `tag` inside the dearmored buffer, and its body length.
    fn packet_at(bin: &[u8], tag: u8) -> (usize, usize) {
        let pkts = packets(bin).unwrap();
        let k = pkts.iter().find(|p| p.tag == tag).unwrap();
        (
            k.body.as_ptr() as usize - bin.as_ptr() as usize,
            k.body.len(),
        )
    }

    #[test]
    fn rfc9580_v6_certificate_and_unlocked_secret() {
        let p = import(RFC_PUB).unwrap();
        assert_eq!(p.key_version, 6);
        assert_eq!(hex::encode_upper(&p.primary_fpr), RFC_FPR);
        assert_eq!(hex::encode_upper(&p.subkey_fpr), RFC_SUB_FPR);
        assert!(p.secret.is_none() && p.user_id.is_none());
        let s = import(RFC_SEC).unwrap();
        let id = s.secret.expect("unprotected v6 secret");
        assert_eq!(id.public().x25519_pk, p.public.x25519_pk);
        assert_eq!(id.public().ed25519_pk, p.public.ed25519_pk);
        // RFC 9580 §14.1: no truncated v6 fingerprint in the 20-byte .sgk slot.
        assert_eq!(id.pgp_fpr, Some([0u8; 20]));
        let back = crate::keys::parse_identity(&id.to_bytes()).unwrap();
        assert_eq!(back.x25519_sk, id.x25519_sk);
        assert_eq!(back.ed25519_seed, id.ed25519_seed);
        let cek = [5u8; 32];
        let salt = [6u8; 16];
        let sgto =
            crate::keys::build_sgto(&cek, std::slice::from_ref(&p.public), None, &salt).unwrap();
        assert_eq!(
            crate::keys::unwrap_cek(&sgto, &[id], None, &salt).unwrap(),
            cek
        );
    }

    /// The A.5 key uses Argon2id with m = 2^21 KiB (2 GiB); keep those runs few and serial.
    static BIG_ARGON2: std::sync::Mutex<()> = std::sync::Mutex::new(());

    #[test]
    fn rfc9580_locked_v6_argon2_ocb_decrypts() {
        assert!(secret_is_protected(RFC_LOCKED));
        let l = import(RFC_LOCKED).unwrap();
        assert!(l.secret.is_none() && l.had_secret_packets);
        assert!(secret_unavailable_reason(RFC_LOCKED).contains("passphrase-protected"));
        let _g = BIG_ARGON2.lock().unwrap_or_else(|e| e.into_inner());
        let s = import_with_passphrase(RFC_LOCKED, Some(RFC_PASS)).unwrap();
        assert_eq!(hex::encode_upper(&s.primary_fpr), RFC_FPR);
        let got = s.secret.expect("decrypted v6 secret");
        let want = import(RFC_SEC).unwrap().secret.unwrap();
        assert_eq!(got.x25519_sk, want.x25519_sk);
        assert_eq!(got.ed25519_seed, want.ed25519_seed);
        // Wrong passphrase: Argon2 runs, the OCB tag check fails closed.
        let e = import_with_passphrase(RFC_LOCKED, Some(b"correct horse battery stapler"))
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("wrong passphrase") && e.contains("AEAD"), "{e}");
    }

    /// Parse the A.5 secret packet's protection fields: (s2k, nonce, ciphertext||tag).
    fn a5_fields(body: &[u8]) -> (S2k, Vec<u8>, Vec<u8>) {
        let mut r = Reader { b: body, p: 42 }; // v6 Ed25519/X25519 public part is 42 bytes
        assert_eq!(r.u8().unwrap(), 253);
        let params_len = r.u8().unwrap() as usize;
        let start = r.p;
        assert_eq!((r.u8().unwrap(), r.u8().unwrap()), (9, AEAD_OCB));
        let n = r.u8().unwrap() as usize;
        let mut sr = Reader {
            b: r.take(n).unwrap(),
            p: 0,
        };
        let s2k = parse_s2k(&mut sr).unwrap();
        let nonce = r.take(15).unwrap().to_vec();
        assert_eq!(r.p - start, params_len);
        (s2k, nonce, body[r.p..].to_vec())
    }

    #[test]
    fn rfc9580_a5_intermediate_values_and_tamper() {
        // A.5.1 / A.5.2: HKDF KEK from the published S2K output, AEAD associated data,
        // then OCB opens with that KEK and fails closed on tag / ciphertext / AD damage.
        let bin = dearmor(RFC_LOCKED).unwrap();
        let want = import(RFC_SEC).unwrap().secret.unwrap();
        let cases = [
            (
                TAG_SECRET_KEY,
                "832bd2662a5c2b251ee3fc82aec349a766ca539015880133002e5a21960b3bcf",
                "9e37cb26787f37e18db172795c4c297550d39ac82511d9af4c8706db6a77fd51",
                "c50663877fe31b00000020f94da7bb48d60a61e567706a6587d0331999bb9d891a08242ead84543df895a3",
            ),
            (
                TAG_SECRET_SUBKEY,
                "f74a6ce873a089ef13a3da9ac059777bb22340d15eaa6c9dc0f8ef09035c67cd",
                "3c60cb63285f62f4c3de49835786f011cf6f4c069f61232cd7013ff5fd31e603",
                "c70663877fe319000000208693248367f9e5015db922f8f48095dda784987f2d5985b12fbad16caf5e4435",
            ),
        ];
        for (tag, s2k_hex, kek_hex, ad_hex) in cases {
            let (off, len) = packet_at(&bin, tag);
            let body = &bin[off..off + len];
            let (s2k, nonce, ct) = a5_fields(body);
            assert!(matches!(
                s2k,
                S2k::Argon2 {
                    t: 1,
                    p: 4,
                    m: 21,
                    ..
                }
            ));
            let ikm = hex::decode(s2k_hex).unwrap();
            let mut kek = [0u8; 32];
            hkdf::Hkdf::<Sha256>::new(None, &ikm)
                .expand(&[0xC0 | tag, 6, 9, AEAD_OCB], &mut kek)
                .unwrap();
            assert_eq!(hex::encode(kek), kek_hex);
            let mut ad = vec![0xC0 | tag];
            ad.extend_from_slice(&body[..42]);
            assert_eq!(hex::encode(&ad), ad_hex);
            let pt = aead_open(9, AEAD_OCB, &kek, &nonce, &ct, &ad).expect("OCB opens");
            let expect = if tag == TAG_SECRET_KEY {
                want.ed25519_seed
            } else {
                want.x25519_sk
            };
            assert_eq!(pt[..], expect[..]);
            let mut t = ct.clone();
            *t.last_mut().unwrap() ^= 0x80; // tag
            assert!(aead_open(9, AEAD_OCB, &kek, &nonce, &t, &ad).is_none());
            let mut t = ct.clone();
            t[0] ^= 0x01; // ciphertext
            assert!(aead_open(9, AEAD_OCB, &kek, &nonce, &t, &ad).is_none());
            let mut a2 = ad.clone();
            a2[3] ^= 0x01; // creation time is associated data
            assert!(aead_open(9, AEAD_OCB, &kek, &nonce, &ct, &a2).is_none());
            let mut a2 = ad.clone();
            a2[0] = 0xC0
                | if tag == TAG_SECRET_KEY {
                    TAG_SECRET_SUBKEY
                } else {
                    TAG_SECRET_KEY
                };
            assert!(aead_open(9, AEAD_OCB, &kek, &nonce, &ct, &a2).is_none());
        }
    }

    #[test]
    fn argon2_memory_and_work_caps() {
        assert!(argon2_check(1, 4, 15).is_ok());
        assert!(argon2_check(1, 4, 21).is_ok()); // RFC 9106 first recommendation (2 GiB)
        assert!(argon2_check(16, 4, 22).is_ok());
        let e = argon2_check(1, 4, 23).err().unwrap().to_string();
        assert!(e.contains("4 GiB"), "{e}");
        assert!(argon2_check(1, 4, 31).is_err());
        assert!(argon2_check(1, 4, 32).is_err());
        assert!(argon2_check(17, 4, 22).is_err());
        assert!(argon2_check(65, 1, 10).is_err());
        assert!(argon2_check(0, 4, 15).is_err());
        assert!(argon2_check(1, 0, 15).is_err());
        assert!(argon2_check(1, 4, 4).is_err()); // m < 8*p KiB
        assert!(argon2_check(1, 1, 3).is_ok());
        // A hostile file asking for 2^30 KiB (1 TiB) is refused before allocating.
        let mut bin = dearmor(RFC_LOCKED).unwrap();
        let (off, _) = packet_at(&bin, TAG_SECRET_KEY);
        let m_at = off + 42 + 5 + 1 + 16 + 2; // usage,count,sym,aead,s2klen | type | salt | t,p | m
        assert_eq!(bin[m_at], 21);
        bin[m_at] = 30;
        let e = import_with_passphrase(&bin, Some(RFC_PASS))
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("caps import") && e.contains("4 GiB"), "{e}");
    }

    #[test]
    fn openpgp_js_v4_aead_fixtures_decrypt() {
        // Independent generator (OpenPGP.js 6): v4 keys, Argon2id (t=1, p=4, m=2^15) with
        // AES-256-OCB, -GCM, -EAX, and iterated SHA-256 + OCB. Sequoia `sq` 1.3 unlocks them too.
        for (file, pass, fpr, sub) in OPJS {
            assert!(secret_is_protected(file));
            let s = import_with_passphrase(file, Some(pass)).unwrap();
            assert_eq!(s.key_version, 4);
            assert_eq!(hex::encode(&s.primary_fpr), fpr);
            assert_eq!(hex::encode(&s.subkey_fpr), sub);
            let id = s.secret.expect("decrypted secret");
            assert_eq!(id.public().x25519_pk, s.public.x25519_pk);
            assert_eq!(id.public().ed25519_pk, s.public.ed25519_pk);
            assert_eq!(id.pgp_fpr.map(hex::encode).as_deref(), Some(fpr));
            let e = import_with_passphrase(file, Some(b"nope"))
                .err()
                .unwrap()
                .to_string();
            assert!(e.contains("wrong passphrase"), "{e}");
            let mut bin = dearmor(file).unwrap();
            let (off, len) = packet_at(&bin, TAG_SECRET_SUBKEY);
            bin[off + len - 3] ^= 0x10; // inside the tag
            let e = import_with_passphrase(&bin, Some(pass))
                .err()
                .unwrap()
                .to_string();
            assert!(e.contains("wrong passphrase"), "{e}");
        }
    }

    #[test]
    fn sequoia_v6_cfb_secret_decrypts() {
        // sq 1.3.1 --profile rfc9580: v6 Ed25519 + X25519, usage 254 (CFB, iterated SHA-256).
        let s = import_with_passphrase(SQ_V6, Some(b"sq v6 pass")).unwrap();
        assert_eq!(s.key_version, 6);
        assert_eq!(
            hex::encode_upper(&s.primary_fpr),
            "EC9E746153F62ADFF10E2CF04B347A727FA7442A5E0C2C6D2D58203647F01C37"
        );
        assert_eq!(
            hex::encode_upper(&s.subkey_fpr),
            "4393CBC13D93539E8B975F4654EDC60452DE724CA5FE32A5EFC2DCD5674945B8"
        );
        assert_eq!(s.user_id.as_deref(), Some("Sigil v6 <v6@sigil.invalid>"));
        let id = s.secret.expect("decrypted secret");
        assert_eq!(id.public().x25519_pk, s.public.x25519_pk);
        let e = import_with_passphrase(SQ_V6, Some(b"sq v6 pas"))
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("wrong passphrase"), "{e}");
    }

    /// Own encoder: v4 usage-253 secret params + AEAD-sealed Ed25519 seed (algo 27).
    fn seal_v4_aead(
        tag: u8,
        sym: u8,
        aead: u8,
        s2k_spec: &[u8],
        pass: &[u8],
        pub_body: &[u8],
        seed: &[u8; 32],
    ) -> Vec<u8> {
        use aes_gcm::aead::{consts::U12, consts::U15, Aead, KeyInit, Payload};
        let key_len = match sym {
            7 => 16,
            8 => 24,
            _ => 32,
        };
        let mut sr = Reader { b: s2k_spec, p: 0 };
        let s2k = parse_s2k(&mut sr).unwrap();
        let ikm = s2k_derive(&s2k, pass, key_len).unwrap();
        let mut kek = vec![0u8; key_len];
        hkdf::Hkdf::<Sha256>::new(None, &ikm)
            .expand(&[0xC0 | tag, 4, sym, aead], &mut kek)
            .unwrap();
        let nonce = vec![0x5Au8; aead_nonce_len(aead).unwrap()];
        let mut ad = vec![0xC0 | tag];
        ad.extend_from_slice(pub_body);
        let pl = Payload {
            msg: &seed[..],
            aad: &ad,
        };
        macro_rules! seal {
            ($t:ty) => {
                <$t>::new_from_slice(&kek)
                    .unwrap()
                    .encrypt(aes_gcm::aead::Nonce::<$t>::from_slice(&nonce), pl)
                    .unwrap()
            };
        }
        use aes::{Aes128, Aes192, Aes256};
        let ct = match (aead, sym) {
            (AEAD_EAX, 7) => seal!(eax::Eax<Aes128>),
            (AEAD_EAX, 8) => seal!(eax::Eax<Aes192>),
            (AEAD_EAX, 9) => seal!(eax::Eax<Aes256>),
            (AEAD_OCB, 7) => seal!(ocb3::Ocb3<Aes128, U15>),
            (AEAD_OCB, 8) => seal!(ocb3::Ocb3<Aes192, U15>),
            (AEAD_OCB, 9) => seal!(ocb3::Ocb3<Aes256, U15>),
            (AEAD_GCM, 7) => seal!(aes_gcm::AesGcm<Aes128, U12>),
            (AEAD_GCM, 8) => seal!(aes_gcm::AesGcm<Aes192, U12>),
            _ => seal!(aes_gcm::AesGcm<Aes256, U12>),
        };
        let mut v = vec![sym, aead];
        v.extend_from_slice(s2k_spec);
        v.extend_from_slice(&nonce);
        v.extend_from_slice(&ct);
        v
    }

    #[test]
    fn aead_all_modes_and_key_sizes_roundtrip() {
        let seed = [0x24u8; 32];
        let public = SigningKey::from_bytes(&seed).verifying_key().to_bytes();
        let mut pub_body = vec![4u8, 0x66, 0, 0, 0, ALGO_ED25519];
        pub_body.extend_from_slice(&public);
        let mut argon = vec![4u8];
        argon.extend_from_slice(&[0x11; 16]);
        argon.extend_from_slice(&[1, 1, 3]); // tiny Argon2id: 8 KiB
        let iter = [3u8, HASH_SHA256, 1, 2, 3, 4, 5, 6, 7, 8, 96];
        let ctx = KeyCtx {
            tag: TAG_SECRET_KEY,
            version: 4,
            kind: Kind::Ed25519,
            algo: ALGO_ED25519,
            public: &public,
            pub_body: &pub_body,
        };
        for aead in [AEAD_EAX, AEAD_OCB, AEAD_GCM] {
            for sym in [7u8, 8, 9] {
                for spec in [&argon[..], &iter[..]] {
                    let body =
                        seal_v4_aead(TAG_SECRET_KEY, sym, aead, spec, b"pw", &pub_body, &seed);
                    let mut r = Reader { b: &body, p: 0 };
                    let got = decrypt_secret(253, None, &mut r, &body, b"pw", &ctx).unwrap();
                    assert_eq!(got, Some(seed), "aead {aead} sym {sym}");
                    let mut r = Reader { b: &body, p: 0 };
                    assert!(decrypt_secret(253, None, &mut r, &body, b"px", &ctx).is_err());
                    let mut bad = body.clone();
                    *bad.last_mut().unwrap() ^= 1;
                    let mut r = Reader { b: &bad, p: 0 };
                    let e = decrypt_secret(253, None, &mut r, &bad, b"pw", &ctx)
                        .err()
                        .unwrap()
                        .to_string();
                    assert!(e.contains("wrong passphrase"), "{e}");
                    // Sealed as a primary, opened as a subkey: packet tag is bound via HKDF info + AD.
                    let sub_ctx = KeyCtx {
                        tag: TAG_SECRET_SUBKEY,
                        ..ctx
                    };
                    let mut r = Reader { b: &body, p: 0 };
                    assert!(decrypt_secret(253, None, &mut r, &body, b"pw", &sub_ctx).is_err());
                }
            }
        }
    }

    #[test]
    fn malformed_protection_refused() {
        let public = [0u8; 32];
        let ctx = KeyCtx {
            tag: TAG_SECRET_KEY,
            version: 4,
            kind: Kind::Ed25519,
            algo: ALGO_ED25519,
            public: &public,
            pub_body: &[],
        };
        // Argon2 S2K under CFB (usage 254) is malformed per RFC 9580 §3.7.2.
        let mut body = vec![9u8, 4];
        body.extend_from_slice(&[0; 16]);
        body.extend_from_slice(&[1, 1, 3]);
        body.extend_from_slice(&[0; 16 + 52]);
        let mut r = Reader { b: &body, p: 0 };
        let e = decrypt_secret(254, None, &mut r, &body, b"pw", &ctx)
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("only valid with AEAD"), "{e}");
        // Unknown AEAD mode.
        let mut body = vec![9u8, 7, 3, HASH_SHA256, 1, 2, 3, 4, 5, 6, 7, 8, 96];
        body.extend_from_slice(&[0; 64]);
        let mut r = Reader { b: &body, p: 0 };
        let e = decrypt_secret(253, None, &mut r, &body, b"pw", &ctx)
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("AEAD algorithm 7"), "{e}");
        // v6 key with a legacy algorithm id.
        let mut v6 = vec![6u8, 0, 0, 0, 1, ALGO_EDDSA_LEGACY, 0, 0, 0, 10];
        v6.extend_from_slice(&[0; 10]);
        let e = parse_key(TAG_PUBLIC_KEY, &v6, None)
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("forbids"), "{e}");
        // v6 secret with MalleableCFB (255).
        let mut v6 = vec![6u8, 0, 0, 0, 1, ALGO_ED25519, 0, 0, 0, 32];
        v6.extend_from_slice(&[0; 32]);
        v6.extend_from_slice(&[255, 0]);
        let e = parse_key(TAG_SECRET_KEY, &v6, Some(b"x"))
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("MalleableCFB"), "{e}");
    }
}
