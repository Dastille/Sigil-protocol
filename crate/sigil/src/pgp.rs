//! Minimal OpenPGP import: v4 Curve25519 keys → Sigil identity (.sgk) / public (.pub).
//!
//! Scope is deliberately narrow. Accepted: a v4 key whose primary is Ed25519
//! (legacy EdDSA algo 22, or RFC 9580 algo 27) with at least one Curve25519
//! encryption subkey (legacy ECDH cv25519 algo 18, or RFC 9580 X25519 algo 25).
//! The Ed25519 primary becomes the attest half; the newest valid encryption
//! subkey becomes the SGTO encrypt-to half. RSA/DSA/NIST/v6 keys are refused.
//!
//! Every subkey we pick must carry a binding signature (0x18) that verifies
//! against the primary; verified revocations (0x20 primary, 0x28 subkey) and
//! expired keys are refused. Secret import needs an unprotected secret key
//! (S2K usage 0); the recovered scalars are checked against the public points.
//!
//! This touches key files only. Seal (.sg1) bytes and SGTO are unchanged.

use crate::keys::{Identity, PublicIdentity};
use crate::{Error, Result};
use ed25519_dalek::{Signature, SigningKey, VerifyingKey};
use sha1::Sha1;
use sha2::{Digest, Sha224, Sha256, Sha384, Sha512};
use x25519_dalek::{PublicKey as XPublic, StaticSecret};

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
    pub primary_fpr: [u8; 20],
    pub subkey_fpr: [u8; 20],
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
            let tag = if c & 0x40 != 0 { c & 0x3f } else { (c >> 2) & 0x0f };
            tag == TAG_PUBLIC_KEY || tag == TAG_SECRET_KEY
        }
        _ => false,
    }
}

pub fn import(input: &[u8]) -> Result<PgpImport> {
    let data = dearmor(input)?;
    let pkts = packets(&data)?;
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    select(&pkts, now)
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
    fn hash_prefix(&self) -> Vec<u8> {
        let mut v = Vec::with_capacity(3 + self.pub_body.len());
        v.push(0x99);
        v.extend_from_slice(&(self.pub_body.len() as u16).to_be_bytes());
        v.extend_from_slice(&self.pub_body);
        v
    }
    fn fingerprint(&self) -> [u8; 20] {
        let mut h = Sha1::new();
        h.update(self.hash_prefix());
        h.finalize().into()
    }
}

fn parse_key(tag: u8, body: &[u8]) -> Result<Key> {
    let mut r = Reader { b: body, p: 0 };
    let ver = r.u8()?;
    if ver != 4 {
        return Err(err(format!(
            "OpenPGP v{ver} key packets are not supported (v4 only for now)"
        )));
    }
    let created = r.u32()?;
    let algo = r.u8()?;
    let is_secret_packet = tag == TAG_SECRET_KEY || tag == TAG_SECRET_SUBKEY;
    let mut kind = Kind::Other;
    let mut public = [0u8; 32];
    match algo {
        ALGO_EDDSA_LEGACY | ALGO_ECDH => {
            let oid = r.oid()?;
            let point = r.mpi()?;
            if algo == ALGO_ECDH {
                let kdf_len = r.u8()? as usize;
                r.take(kdf_len)?;
            }
            let want_oid = if algo == ALGO_ECDH { OID_CV25519 } else { OID_ED25519 };
            if oid == want_oid && point.len() == 33 && point[0] == 0x40 {
                public.copy_from_slice(&point[1..]);
                kind = if algo == ALGO_ECDH { Kind::X25519 } else { Kind::Ed25519 };
            }
        }
        ALGO_X25519 | ALGO_ED25519 => {
            public.copy_from_slice(r.take(32)?);
            kind = if algo == ALGO_X25519 { Kind::X25519 } else { Kind::Ed25519 };
        }
        _ => {
            // Unsupported algorithm: we only need to know it is not ours.
            return Ok(Key {
                algo,
                kind,
                created,
                pub_body: body.to_vec(),
                public,
                secret: None,
                protected: false,
            });
        }
    }
    let pub_end = r.p;
    let mut secret = None;
    let mut protected = false;
    if is_secret_packet && kind != Kind::Other {
        let usage = r.u8()?;
        if usage != 0 {
            protected = true;
        } else {
            let start = r.p;
            let raw: [u8; 32] = match algo {
                ALGO_X25519 | ALGO_ED25519 => r.take(32)?.try_into().unwrap(),
                _ => left_pad32(r.mpi()?)?,
            };
            let material = &body[start..r.p];
            let want = r.u16()?;
            let sum = material.iter().fold(0u16, |a, &b| a.wrapping_add(b as u16));
            if sum != want {
                return Err(err("secret key checksum mismatch (damaged export?)"));
            }
            secret = Some(recover_secret(kind, algo, raw, &public)?);
        }
    }
    Ok(Key {
        algo,
        kind,
        created,
        pub_body: body[..pub_end].to_vec(),
        public,
        secret,
        protected,
    })
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
    sigtype: u8,
    hash_algo: u8,
    /// version .. end of hashed subpackets (hashed as the sig trailer).
    hashed_part: Vec<u8>,
    hashed_subs: Vec<u8>,
    left16: [u8; 2],
    sig: Option<[u8; 64]>,
}

fn parse_sig(body: &[u8]) -> Option<Sig> {
    let mut r = Reader { b: body, p: 0 };
    if r.u8().ok()? != 4 {
        return None;
    }
    let sigtype = r.u8().ok()?;
    let pub_algo = r.u8().ok()?;
    let hash_algo = r.u8().ok()?;
    let hlen = r.u16().ok()? as usize;
    let hashed_subs = r.take(hlen).ok()?.to_vec();
    let hashed_part = body[..r.p].to_vec();
    let ulen = r.u16().ok()? as usize;
    r.take(ulen).ok()?;
    let left16: [u8; 2] = r.take(2).ok()?.try_into().ok()?;
    let sig = match pub_algo {
        ALGO_EDDSA_LEGACY => {
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
        sigtype,
        hash_algo,
        hashed_part,
        hashed_subs,
        left16,
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

/// Verify `sig` made by Ed25519 `primary` over `prefix` (key/uid material).
fn verify_sig(sig: &Sig, primary: &[u8; 32], prefix: &[u8]) -> bool {
    let Some(raw) = sig.sig else { return false };
    let mut data = prefix.to_vec();
    data.extend_from_slice(&sig.hashed_part);
    data.push(0x04);
    data.push(0xFF);
    data.extend_from_slice(&(sig.hashed_part.len() as u32).to_be_bytes());
    let Some(d) = digest(sig.hash_algo, &data) else { return false };
    if d[..2] != sig.left16 {
        return false;
    }
    let Ok(vk) = VerifyingKey::from_bytes(primary) else { return false };
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

fn select(pkts: &[Packet<'_>], now: u64) -> Result<PgpImport> {
    let first = pkts.first().ok_or_else(|| err("empty key file"))?;
    if first.tag != TAG_PUBLIC_KEY && first.tag != TAG_SECRET_KEY {
        return Err(err("file does not start with a primary key packet"));
    }
    let primary = parse_key(first.tag, first.body)?;
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
                let k = parse_key(pkt.tag, pkt.body)?;
                subs.push((k, false, false, None, None));
                ctx = Ctx::Sub(subs.len() - 1);
            }
            TAG_PUBLIC_KEY | TAG_SECRET_KEY => break, // next key in a keyring: stop at the first
            TAG_SIG => {
                let Some(sig) = parse_sig(pkt.body) else { continue };
                match &ctx {
                    Ctx::Primary => {
                        if sig.sigtype == SIG_KEY_REVOCATION
                            && verify_sig(&sig, &primary.public, &primary_prefix)
                        {
                            primary_revoked = true;
                        }
                    }
                    Ctx::Uid(pre, name) => {
                        if (0x10..=0x13).contains(&sig.sigtype) {
                            let mut data = primary_prefix.clone();
                            data.extend_from_slice(pre);
                            if verify_sig(&sig, &primary.public, &data) {
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
                            || !verify_sig(&sig, &primary.public, &data)
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
    if expired(primary.created, primary_exp, now) {
        return Err(err("primary key has expired"));
    }
    let mut candidates: Vec<&(Key, bool, bool, Option<u8>, Option<u32>)> = subs
        .iter()
        .filter(|(k, bound, revoked, flags, kexp)| {
            k.kind == Kind::X25519
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
    let secret = match (primary.secret, sub.secret) {
        (Some(ed), Some(x)) => Some(Identity::from_raw(x, ed, Some(primary_fpr))),
        _ => None,
    };
    Ok(PgpImport {
        public,
        secret,
        primary_fpr,
        subkey_fpr: sub.fingerprint(),
        user_id,
        had_secret_packets,
    })
}

/// Why secret import is not possible, for CLI messages.
pub fn secret_unavailable_reason(input: &[u8]) -> String {
    let Ok(data) = dearmor(input) else { return "unreadable key".into() };
    let Ok(pkts) = packets(&data) else { return "unreadable key".into() };
    let mut any_secret = false;
    for p in &pkts {
        if p.tag == TAG_SECRET_KEY || p.tag == TAG_SECRET_SUBKEY {
            any_secret = true;
            if let Ok(k) = parse_key(p.tag, p.body) {
                if k.protected {
                    return "secret key is passphrase-protected; export an unprotected copy \
                            to a private temp dir (or clear the passphrase on a throwaway copy) \
                            and import that"
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
        assert_eq!(hex::encode(a.primary_fpr), FPR);
        assert_eq!(hex::encode(a.subkey_fpr), SUB_FPR);
        assert_eq!(a.public.x25519_pk, b.public.x25519_pk);
        assert_eq!(a.public.ed25519_pk, b.public.ed25519_pk);
        assert!(a.secret.is_none());
        assert_eq!(a.user_id.as_deref(), Some("Sigil Test <test@sigil.invalid>"));
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
        let e = import(lines.join("\n").as_bytes()).err().unwrap().to_string();
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
}
