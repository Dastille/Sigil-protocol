//! Private INDEX (`sigil log init --private-index`, `log=5`, manifest `privindex=1`).
//!
//! In an ordinary log every segment line shows the batch's plain size, its plain SHA-256 and (for
//! `log add`) its file name. In a private log those three live inside a small **box** on the line:
//!
//! ```text
//! seq=7 t=1760000000 size=0 sha=<star> star=<star> box=<hex> chain=<hex>
//! ```
//!
//! * `size=0 sha=<star> star=<star>` is exactly the shape of a key-less ("label only") entry, so
//!   every keyless operation (`verify`, `mend`, `gc`, `doctor`, `shred`, `tombstone`) works as
//!   before: it binds the segment file to the line through the star's **keyed fingerprint** (the v3
//!   private label), which reveals nothing about the plain bytes.
//! * `box` = `01 ‖ commit(32) ‖ nonce(12) ‖ AES-256-GCM(size, sha, path)`. The line's visible part
//!   (everything before ` box=`), the log id and the seq are the GCM associated data, and the box is
//!   itself covered by the hash chain like every other field.
//!
//! Keys, all with HKDF-SHA-256 (RFC 5869) and AES-256-GCM (NIST SP 800-38D), the primitives the
//! crate already uses:
//!
//! * the **index key**: 32 random bytes made at `init`, wrapped with the existing SGTO machinery to
//!   the `--to` recipients and/or `--pass` given at `init`, kept in `IXKEY.sg1` (an unencrypted
//!   ECC star like the key ring shards: only the wrap is inside, so it heals with `mend`);
//! * the **entry key** of entry `seq`: HKDF(salt = "sigil-log-box-v1\0" ‖ log-id, ikm = index key,
//!   info = "sigil log box v1 entry" ‖ seq as 8 big-endian bytes). It opens exactly one box, so a
//!   receipt can carry it (`entry-key=`) without exposing any other entry;
//! * from the entry key: the AES-256-GCM key (info "… aead key") and a 32-byte **key commitment**
//!   (info "… key commitment") stored in the clear at the front of the box. AES-GCM alone is not
//!   key-committing (one ciphertext can be made to open under two keys, see Albertini et al., "How
//!   to Abuse and Fix Authenticated Encryption Without Key Commitment", USENIX Security 2022); the
//!   commitment check makes a receipt's `entry-key=` the only key that opens its box.
//!
//! The plaintext is a short text record padded with zero bytes to a multiple of 64, so the box
//! length does not reveal the exact length of a file name. Fresh random 96-bit nonce per box.

use aes_gcm::aead::{Aead, KeyInit, Payload};
use aes_gcm::{Aes256Gcm, Nonce};
use hkdf::Hkdf;
use sha2::Sha256;
use zeroize::Zeroizing;

use super::*;
use crate::keys;

/// The wrapped index key of a private log (a small unencrypted ECC star holding only the wrap).
pub const IXKEY_FILE: &str = "IXKEY.sg1";
const IXKEY_MAGIC: &str = "sigil-log-ixkey=1";
const BOX_VERSION: u8 = 1;
const COMMIT_LEN: usize = 32;
const NONCE_LEN: usize = 12;
const TAG_LEN: usize = 16;
/// Box plaintexts are zero-padded to a multiple of this many bytes.
const PAD_TO: usize = 64;
const PLAIN_MAGIC: &str = "sigil-log-box=1";
const ENTRY_SALT: &[u8] = b"sigil-log-box-v1\0";
const INFO_ENTRY: &[u8] = b"sigil log box v1 entry";
const INFO_AEAD: &[u8] = b"sigil log box v1 aead key";
const INFO_COMMIT: &[u8] = b"sigil log box v1 key commitment";
const AAD_DOMAIN: &[u8] = b"sigil-log-box-v1\0";

/// Message for an operation that needs the sealed sizes / names but has no index key.
pub const LOCKED_MSG: &str = "this log keeps its INDEX private: give the --pass and/or an --identity (or --unlock KEY.sgk) its index key was wrapped to at init";

/// The log's index key, only ever held in memory after unlocking `IXKEY.sg1`.
#[derive(Clone)]
pub struct IndexKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for IndexKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("IndexKey(<redacted>)")
    }
}

/// The key of one entry's box (derived from the index key; opens that box only).
#[derive(Clone)]
pub struct EntryKey(Zeroizing<[u8; 32]>);

impl std::fmt::Debug for EntryKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str("EntryKey(<redacted>)")
    }
}

impl EntryKey {
    /// An entry key received in a receipt (`entry-key=` hex).
    pub fn from_hex(s: &str) -> Option<EntryKey> {
        parse_hex32(s).map(|k| EntryKey(Zeroizing::new(k)))
    }

    /// Hex form for a receipt.
    pub fn to_hex(&self) -> String {
        hex::encode(&self.0[..])
    }
}

/// What a box holds: the values an ordinary line shows in the clear.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Hidden {
    /// Plain size in bytes.
    pub size: u64,
    /// SHA-256 of the plain bytes.
    pub sha: [u8; 32],
    /// `log add` file path relative to the added folder (raw bytes), if any.
    pub path: Option<Vec<u8>>,
    /// Tombstone / shred reason (`log=6`; only in a tombstone's box).
    pub reason: Option<String>,
}

/// Entry key of entry `seq` of log `log_id` (HKDF-SHA-256, RFC 5869).
pub fn entry_key(key: &IndexKey, log_id: &str, seq: u64) -> Result<EntryKey> {
    let mut salt = ENTRY_SALT.to_vec();
    salt.extend_from_slice(log_id.as_bytes());
    let hk = Hkdf::<Sha256>::new(Some(&salt), &key.0[..]);
    let mut info = INFO_ENTRY.to_vec();
    info.extend_from_slice(&seq.to_be_bytes());
    let mut okm = Zeroizing::new([0u8; 32]);
    hk.expand(&info, &mut okm[..])
        .map_err(|_| err("internal: HKDF expand failed"))?;
    Ok(EntryKey(okm))
}

/// (AES-256-GCM key, key commitment) of an entry key.
fn split(ek: &EntryKey) -> Result<(Zeroizing<[u8; 32]>, [u8; COMMIT_LEN])> {
    let hk = Hkdf::<Sha256>::new(None, &ek.0[..]);
    let mut k = Zeroizing::new([0u8; 32]);
    let mut c = [0u8; COMMIT_LEN];
    hk.expand(INFO_AEAD, &mut k[..])
        .and_then(|_| hk.expand(INFO_COMMIT, &mut c))
        .map_err(|_| err("internal: HKDF expand failed"))?;
    Ok((k, c))
}

fn aad(log_id: &str, seq: u64, visible: &str) -> Vec<u8> {
    let mut a = AAD_DOMAIN.to_vec();
    a.extend_from_slice(log_id.as_bytes());
    a.push(0);
    a.extend_from_slice(&seq.to_be_bytes());
    a.extend_from_slice(visible.as_bytes());
    a
}

/// Encrypt `h` for the line whose visible part (everything before ` box=`) is `visible`.
pub fn seal_box(
    ek: &EntryKey,
    log_id: &str,
    seq: u64,
    visible: &str,
    h: &Hidden,
) -> Result<String> {
    let mut text = format!("{PLAIN_MAGIC}\nsize={}\nsha={}\n", h.size, hex32(&h.sha));
    if let Some(p) = &h.path {
        text.push_str(&format!("path={}\n", enc_bytes(p)));
    }
    if let Some(r) = &h.reason {
        text.push_str(&format!("reason={}\n", enc_reason(r)));
    }
    let mut pt = Zeroizing::new(text.into_bytes());
    let padded = pt.len().div_ceil(PAD_TO) * PAD_TO;
    pt.resize(padded, 0);
    let (k, commit) = split(ek)?;
    let mut nonce = [0u8; NONCE_LEN];
    getrandom::getrandom(&mut nonce).map_err(|e| err(e.to_string()))?;
    let cipher = Aes256Gcm::new_from_slice(&k[..]).map_err(|e| err(e.to_string()))?;
    let ct = cipher
        .encrypt(
            Nonce::from_slice(&nonce),
            Payload {
                msg: &pt,
                aad: &aad(log_id, seq, visible),
            },
        )
        .map_err(|_| err("internal: AES-GCM encryption failed"))?;
    let mut out = Vec::with_capacity(1 + COMMIT_LEN + NONCE_LEN + ct.len());
    out.push(BOX_VERSION);
    out.extend_from_slice(&commit);
    out.extend_from_slice(&nonce);
    out.extend_from_slice(&ct);
    Ok(hex::encode(out))
}

/// Open a box. Fails closed on any alteration, a wrong key, or a record this sigil does not know.
pub fn open_box(
    ek: &EntryKey,
    log_id: &str,
    seq: u64,
    visible: &str,
    box_hex: &str,
) -> std::result::Result<Hidden, String> {
    let raw = hex::decode(box_hex).map_err(|_| "box= is not hex".to_string())?;
    if raw.len() < 1 + COMMIT_LEN + NONCE_LEN + TAG_LEN {
        return Err("box= is too short (truncated)".into());
    }
    if raw[0] != BOX_VERSION {
        return Err(format!(
            "box version {} is not known to this sigil; upgrade sigil",
            raw[0]
        ));
    }
    let (k, commit) = split(ek).map_err(|e| e.to_string())?;
    if raw[1..1 + COMMIT_LEN] != commit {
        return Err(
            "the key does not match this box (wrong index key, or the box was altered)".into(),
        );
    }
    let nonce = &raw[1 + COMMIT_LEN..1 + COMMIT_LEN + NONCE_LEN];
    let cipher = Aes256Gcm::new_from_slice(&k[..]).map_err(|e| e.to_string())?;
    let pt = Zeroizing::new(
        cipher
            .decrypt(
                Nonce::from_slice(nonce),
                Payload {
                    msg: &raw[1 + COMMIT_LEN + NONCE_LEN..],
                    aad: &aad(log_id, seq, visible),
                },
            )
            .map_err(|_| {
                "box does not authenticate (altered, moved to another line, or wrong key)"
                    .to_string()
            })?,
    );
    parse_plain(&pt)
}

fn parse_plain(pt: &[u8]) -> std::result::Result<Hidden, String> {
    let end = pt.iter().rposition(|b| *b != 0).map(|i| i + 1).unwrap_or(0);
    let text = std::str::from_utf8(&pt[..end]).map_err(|_| "box record is not text".to_string())?;
    let mut lines = text.lines();
    if lines.next() != Some(PLAIN_MAGIC) {
        return Err("box record has no sigil-log-box=1 header".into());
    }
    let (mut size, mut sha, mut path, mut reason) = (None, None, None, None);
    for l in lines {
        match l.split_once('=') {
            Some(("size", v)) if size.is_none() => size = v.parse::<u64>().ok(),
            Some(("sha", v)) if sha.is_none() => sha = parse_hex32(v),
            Some(("path", v)) if path.is_none() => {
                path = Some(dec_bytes(v).ok_or_else(|| "box record has a bad path=".to_string())?)
            }
            Some(("reason", v)) if reason.is_none() => {
                reason =
                    Some(dec_reason(v).ok_or_else(|| "box record has a bad reason=".to_string())?)
            }
            _ => {
                return Err(format!(
                    "box record has an unknown or repeated field {l:?}; upgrade sigil"
                ))
            }
        }
    }
    match (size, sha) {
        (Some(size), Some(sha)) => Ok(Hidden {
            size,
            sha,
            path,
            reason,
        }),
        _ => Err("box record lacks size= / sha=".into()),
    }
}

/// The visible part of a body that ends in ` box=<hex>`, and the box hex.
pub(super) fn split_body(body: &str) -> Option<(&str, &str)> {
    let (visible, b) = body.rsplit_once(" box=")?;
    (!b.is_empty() && !b.contains(char::is_whitespace)).then_some((visible, b))
}

/// Open entry `e` in place with the log's index key (no-op for an unsealed entry).
pub(super) fn open_entry(
    key: &IndexKey,
    log_id: &str,
    e: &mut Entry,
) -> std::result::Result<(), String> {
    let Some((visible, b)) = split_body(&e.body) else {
        return Ok(());
    };
    let ek = entry_key(key, log_id, e.seq).map_err(|x| x.to_string())?;
    let h = open_box(&ek, log_id, e.seq, visible, b).map_err(|m| format!("seq {}: {m}", e.seq))?;
    e.size = h.size;
    e.sha = h.sha;
    e.hidden_path = h.path;
    if let Op::Tomb { reason, .. } = &mut e.op {
        *reason = h.reason;
    } else if h.reason.is_some() {
        return Err(format!(
            "seq {}: a reason in a box that is not a tombstone's",
            e.seq
        ));
    }
    e.opened = true;
    Ok(())
}

/// Open entry `e` with a receipt's entry key (`check-proof`).
pub(super) fn open_with_entry_key(
    ek: &EntryKey,
    log_id: &str,
    e: &mut Entry,
) -> std::result::Result<(), String> {
    let Some((visible, b)) = split_body(&e.body) else {
        return Ok(());
    };
    let h = open_box(ek, log_id, e.seq, visible, b)?;
    e.size = h.size;
    e.sha = h.sha;
    e.hidden_path = h.path;
    if let Op::Tomb { reason, .. } = &mut e.op {
        *reason = h.reason;
    } else if h.reason.is_some() {
        return Err(format!(
            "seq {}: a reason in a box that is not a tombstone's",
            e.seq
        ));
    }
    e.opened = true;
    Ok(())
}

/// The INDEX line body for a new segment / compaction entry of a private log: `size=0`, `sha` and
/// `star` = the segment star's keyed fingerprint, then the box. `op_part` is `""` for a segment or
/// ` op=compact of=…`. Refuses a segment that is not an encrypted (v3 private label) star: its
/// header would show the plain SHA-256 and size the box is hiding.
pub(super) fn sealed_body(
    log: &Log,
    seq: u64,
    t: u64,
    op_part: &str,
    sealed: &[u8],
    h: &Hidden,
) -> Result<String> {
    let key = log.ixkey.as_ref().ok_or_else(|| err(LOCKED_MSG))?;
    let star = match crate::locate_header(sealed) {
        Ok((hd, _, _)) if hd.private_label() => hd.digest,
        _ => {
            return Err(err(
                "this log keeps its INDEX private, so every segment must be encrypted: give --pass and/or --to (an unencrypted star would show the size and SHA-256 the INDEX hides)",
            ))
        }
    };
    let s = hex32(&star);
    let visible = format!("seq={seq} t={t} size=0 sha={s}{op_part} star={s}");
    let ek = entry_key(key, &log.id, seq)?;
    let b = seal_box(&ek, &log.id, seq, &visible, h)?;
    Ok(format!("{visible} box={b}"))
}

/// Make the index key of a new private log and store it, wrapped, in `dir/IXKEY.sg1`.
pub(super) fn create_key(
    dir: &Path,
    pass: Option<&str>,
    recipients: &[PublicIdentity],
) -> Result<IndexKey> {
    let pass = pass.filter(|p| !p.is_empty());
    if pass.is_none() && recipients.is_empty() {
        return Err(err(
            "--private-index needs --to and/or --pass: the index key must be wrapped to someone who can open it later",
        ));
    }
    let mut k = Zeroizing::new([0u8; 32]);
    getrandom::getrandom(&mut k[..]).map_err(|e| err(e.to_string()))?;
    let mut salt = [0u8; 16];
    getrandom::getrandom(&mut salt).map_err(|e| err(e.to_string()))?;
    let wrap = keys::build_sgto(&k, recipients, pass, &salt)?;
    store_ixkey(dir, &salt, &wrap)?;
    Ok(IndexKey(k))
}

/// Write `IXKEY.sg1` (a Seal-mode ECC star, not encrypted: its record is already wrapped).
pub(super) fn store_ixkey(dir: &Path, salt: &[u8; 16], wrap: &[u8]) -> Result<()> {
    let text = format!(
        "{IXKEY_MAGIC}\nsalt={} wrap={}\n",
        hex::encode(salt),
        hex::encode(wrap)
    );
    let sealed = crate::seal_kn_to(
        text.as_bytes(),
        Mode::Seal,
        None,
        "ixkey",
        false,
        "",
        &[],
        None,
        crate::DEFAULT_PIECE,
        &[],
    )?;
    write_atomic(&dir.join(IXKEY_FILE), &sealed)
}

/// Unwrap the index key of the log in `dir` with a passphrase and/or identities.
pub(super) fn unlock_key(dir: &Path, pass: Option<&str>, ids: &[Identity]) -> Result<IndexKey> {
    let pass = pass.filter(|p| !p.is_empty());
    if pass.is_none() && ids.is_empty() {
        return Err(err(LOCKED_MSG));
    }
    let (salt, wrap) = read_ixkey(dir)?;
    let k = keys::unwrap_cek(&wrap, ids, pass, &salt).map_err(|_| {
        err("the given --pass / --identity does not open this log's index key (it was wrapped at init to other keys)")
    })?;
    Ok(IndexKey(Zeroizing::new(k)))
}

/// The wrapped index key record of `IXKEY.sg1`: `(salt, SGTO block)`.
pub(super) fn read_ixkey(dir: &Path) -> Result<([u8; 16], Vec<u8>)> {
    let file = fs::read(dir.join(IXKEY_FILE)).map_err(|e| {
        err(format!(
            "{IXKEY_FILE} unreadable ({e}): the private INDEX cannot be opened; restore {IXKEY_FILE} from a copy of the log (the segments themselves still open with their own keys)"
        ))
    })?;
    let plain = crate::unseal_ex_keys(&file, None, &[], &[]).map_err(|e| {
        err(format!(
            "{IXKEY_FILE} is damaged ({e}); `sigil log mend` heals what ECC can, else restore it from a copy"
        ))
    })?;
    let text = String::from_utf8_lossy(&plain);
    let mut lines = text.lines();
    if lines.next().map(str::trim) != Some(IXKEY_MAGIC) {
        return Err(err(format!("{IXKEY_FILE} is not a sigil index key file")));
    }
    let rec = lines.next().unwrap_or_default();
    let mut salt = None;
    let mut wrap = None;
    for t in rec.split_whitespace() {
        match t.split_once('=') {
            Some(("salt", v)) => {
                salt = hex::decode(v)
                    .ok()
                    .and_then(|b| <[u8; 16]>::try_from(b).ok())
            }
            Some(("wrap", v)) => {
                wrap = hex::decode(v)
                    .ok()
                    .filter(|w| keys::sgto_len_at(w, 0) == w.len())
            }
            _ => {}
        }
    }
    let (Some(salt), Some(wrap)) = (salt, wrap) else {
        return Err(err(format!("{IXKEY_FILE} has a bad record")));
    };
    Ok((salt, wrap))
}

/// After parsing: enforce the private-INDEX rules and, with the key, open every box. The first
/// violation truncates the entries there and becomes the INDEX error, like the format checks.
pub(super) fn apply(log: &Log, idx: &mut ParsedIndex) {
    let mut bad: Option<(usize, &'static str, String)> = None;
    let mut opened_any = false;
    for (i, e) in idx.entries.iter_mut().enumerate() {
        let sealed = e.is_sealed();
        if sealed && !log.privindex {
            bad = Some((i, "log-format", format!("INDEX has a private entry (box=) at seq {} but this log has no private index (privindex=1 is missing)", e.seq)));
            break;
        }
        if log.privindex && e.has_file() && !sealed {
            bad = Some((i, "index-private", format!("seq {}: entry shows its size and SHA-256 in the clear, but this log keeps its INDEX private", e.seq)));
            break;
        }
        if let (true, Some(k)) = (sealed, log.ixkey.as_ref()) {
            if let Err(m) = open_entry(k, &log.id, e) {
                bad = Some((i, "index-box", m));
                break;
            }
            opened_any = true;
        }
    }
    if bad.is_none() && opened_any {
        // fold again with the real sizes (re-checks that compaction sizes add up)
        let mut st = State::default();
        for (i, e) in idx.entries.iter().enumerate() {
            if let Err((code, m)) = st.apply(e) {
                bad = Some((i, code, m));
                break;
            }
        }
        if bad.is_none() {
            idx.state = st;
        }
    }
    if let Some((i, code, msg)) = bad {
        idx.entries.truncate(i);
        idx.state = State::build(&idx.entries);
        if idx.error.is_none() {
            idx.error = Some((i + 2, code, msg));
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn key(b: u8) -> IndexKey {
        IndexKey(Zeroizing::new([b; 32]))
    }

    fn h() -> Hidden {
        Hidden {
            size: 1234,
            sha: [7u8; 32],
            path: Some(b"2024/trip/beach \xff.jpg".to_vec()),
            reason: None,
        }
    }

    const VIS: &str = "seq=3 t=5 size=0 sha=aa star=aa";

    #[test]
    fn box_round_trips_and_pads() {
        let ek = entry_key(&key(1), "logid", 3).unwrap();
        let b = seal_box(&ek, "logid", 3, VIS, &h()).unwrap();
        assert_eq!(open_box(&ek, "logid", 3, VIS, &b).unwrap(), h());
        // 1 + 32 + 12 + padded plaintext + 16; plaintext is a multiple of 64
        let raw = hex::decode(&b).unwrap();
        assert_eq!((raw.len() - 1 - 32 - 12 - 16) % 64, 0);
        // no path, fresh nonce: two seals differ
        let h2 = Hidden { path: None, ..h() };
        let b1 = seal_box(&ek, "logid", 3, VIS, &h2).unwrap();
        let b2 = seal_box(&ek, "logid", 3, VIS, &h2).unwrap();
        assert_ne!(b1, b2);
        assert_eq!(open_box(&ek, "logid", 3, VIS, &b1).unwrap(), h2);
        // the plaintext name does not appear in the box
        assert!(!b.contains(&hex::encode(b"beach")));
    }

    #[test]
    fn box_fails_closed() {
        let ek = entry_key(&key(1), "logid", 3).unwrap();
        let b = seal_box(&ek, "logid", 3, VIS, &h()).unwrap();
        let raw = hex::decode(&b).unwrap();
        // every single bit flip anywhere is refused
        for i in 0..raw.len() {
            for bit in [0x01u8, 0x80] {
                let mut r = raw.clone();
                r[i] ^= bit;
                assert!(
                    open_box(&ek, "logid", 3, VIS, &hex::encode(&r)).is_err(),
                    "byte {i}"
                );
            }
        }
        // truncation (any length) is refused
        for n in 0..raw.len() {
            assert!(open_box(&ek, "logid", 3, VIS, &hex::encode(&raw[..n])).is_err());
        }
        // wrong index key, wrong seq, wrong log, other visible fields
        let wrong = entry_key(&key(2), "logid", 3).unwrap();
        assert!(open_box(&wrong, "logid", 3, VIS, &b)
            .unwrap_err()
            .contains("does not match"));
        let other_seq = entry_key(&key(1), "logid", 4).unwrap();
        assert!(open_box(&other_seq, "logid", 4, VIS, &b).is_err());
        assert!(open_box(&ek, "logid", 4, VIS, &b).is_err());
        assert!(open_box(&ek, "other", 3, VIS, &b).is_err());
        assert!(open_box(&ek, "logid", 3, "seq=3 t=6 size=0 sha=aa star=aa", &b).is_err());
        assert!(open_box(&ek, "logid", 3, VIS, "zz").is_err());
    }

    #[test]
    fn entry_keys_are_separate() {
        let k = key(9);
        let a = entry_key(&k, "id", 1).unwrap();
        let b = entry_key(&k, "id", 2).unwrap();
        let c = entry_key(&k, "id2", 1).unwrap();
        assert_ne!(a.to_hex(), b.to_hex());
        assert_ne!(a.to_hex(), c.to_hex());
        assert_eq!(
            EntryKey::from_hex(&a.to_hex()).unwrap().to_hex(),
            a.to_hex()
        );
        assert_eq!(
            format!("{a:?} {k:?}"),
            "EntryKey(<redacted>) IndexKey(<redacted>)"
        );
    }

    #[test]
    fn plain_record_is_strict() {
        assert!(parse_plain(b"nope\nsize=1\n").is_err());
        let sha = hex::encode([1u8; 32]);
        assert!(parse_plain(format!("{PLAIN_MAGIC}\nsize=1\nsha={sha}\n").as_bytes()).is_ok());
        assert!(parse_plain(format!("{PLAIN_MAGIC}\nsize=1\n").as_bytes()).is_err());
        assert!(
            parse_plain(format!("{PLAIN_MAGIC}\nsize=1\nsha={sha}\nnew=1\n").as_bytes()).is_err()
        );
        assert!(
            parse_plain(format!("{PLAIN_MAGIC}\nsize=1\nsize=2\nsha={sha}\n").as_bytes()).is_err()
        );
    }

    #[test]
    fn key_file_unlocks_only_for_its_keys() {
        let dir = std::env::temp_dir().join(format!("sigil-ixkey-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        let me = Identity::generate().unwrap();
        let other = Identity::generate().unwrap();
        assert!(create_key(&dir, None, &[]).is_err());
        assert!(create_key(&dir, Some(""), &[]).is_err());
        let k = create_key(&dir, Some("pw"), &[me.public()]).unwrap();
        let by_id = unlock_key(&dir, None, std::slice::from_ref(&me)).unwrap();
        let by_pw = unlock_key(&dir, Some("pw"), &[]).unwrap();
        assert_eq!((*by_id.0, *by_pw.0), (*k.0, *k.0));
        assert!(unlock_key(&dir, Some("wrong"), &[]).is_err());
        assert!(unlock_key(&dir, None, std::slice::from_ref(&other)).is_err());
        assert!(unlock_key(&dir, None, &[]).is_err());
        let _ = fs::remove_dir_all(&dir);
    }
}
