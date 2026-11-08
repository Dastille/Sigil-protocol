use crate::{Error, Mode, Result};

/// Little-endian `u32` at `at`, or `None` when `b` is too short (never panics).
fn le_u32_at(b: &[u8], at: usize) -> Option<u32> {
    let end = at.checked_add(4)?;
    b.get(at..end)
        .and_then(|w| <[u8; 4]>::try_from(w).ok())
        .map(u32::from_le_bytes)
}

pub const HEADER_SIZE: usize = 160;
pub const KEYSTONE_COPIES: usize = 3;
pub const KEYSTONE_SPAN: usize = HEADER_SIZE * (1 + KEYSTONE_COPIES);
/// Trailing Keystone spare: magic + version + one full header copy after the seal body.
pub const KEYSTONE_TRAILER_VERSION: u8 = 1;
pub const KEYSTONE_TRAILER_SIZE: usize = 4 + 1 + HEADER_SIZE;
/// Version written for plain (unencrypted) seals; unchanged since v2.
pub const VERSION: u8 = 2;
pub const VERSION_MIN: u8 = 1;
/// Highest version this reader opens: v3 is the private label for new encrypted
/// seals (see `privacy.rs`).
pub const VERSION_MAX: u8 = crate::privacy::PRIVATE_VERSION;
const MAGIC: [u8; 4] = *b"SGIL";
const MAGIC_EMBER: [u8; 4] = *b"SGEM";
const MAGIC_KEYSTONE_TRAILER: [u8; 4] = *b"SGKT";
pub const FLAG_KEYSTONE: u8 = 1 << 5;
pub const FLAG_EMBER: u8 = 1 << 6;
pub const FLAG_VOW: u8 = 1 << 7;
pub const VOW_SIZE: usize = 128;

#[derive(Clone, Debug)]
pub struct Header {
    pub version: u8,
    pub flags: u8,
    pub k: u8,
    pub n: u8,
    pub orig_len: u64,
    pub folded_len: u64,
    pub digest: [u8; 32],
    pub salt: [u8; 16],
    pub nonce: [u8; 12],
    pub tag: [u8; 16],
    pub shard_len: u32,
    pub entropy_milli: u32,
    pub name: String,
    pub merkle: [u8; 32],
}

impl Header {
    pub fn encrypted(&self) -> bool {
        self.flags & 2 != 0
    }
    pub fn compressed(&self) -> bool {
        self.flags & 1 != 0
    }
    pub fn graph(&self) -> bool {
        self.flags & (1 << 4) != 0
    }
    pub fn keystone(&self) -> bool {
        self.flags & FLAG_KEYSTONE != 0
    }
    pub fn ember(&self) -> bool {
        self.flags & FLAG_EMBER != 0
    }
    pub fn vow(&self) -> bool {
        self.flags & FLAG_VOW != 0
    }
    /// v3 private label: name, size, plaintext hash and entropy are inside the
    /// ciphertext; `digest` is a keyed fingerprint and `orig_len` is 0.
    pub fn private_label(&self) -> bool {
        self.version >= crate::privacy::PRIVATE_VERSION
    }
    pub fn mode(&self) -> Mode {
        match (self.flags >> 2) & 3 {
            1 => Mode::Reflection,
            2 => Mode::Seal,
            _ => Mode::Glyph,
        }
    }
}

pub fn write_header(h: &Header) -> Vec<u8> {
    let mut buf = vec![0u8; HEADER_SIZE];
    buf[0..4].copy_from_slice(&MAGIC);
    buf[4] = if h.version == 0 { VERSION } else { h.version };
    buf[5] = h.flags;
    buf[6] = h.k;
    buf[7] = h.n;
    buf[8..16].copy_from_slice(&h.orig_len.to_le_bytes());
    buf[16..24].copy_from_slice(&h.folded_len.to_le_bytes());
    buf[24..56].copy_from_slice(&h.digest);
    buf[56..72].copy_from_slice(&h.salt);
    buf[72..84].copy_from_slice(&h.nonce);
    buf[84..100].copy_from_slice(&h.tag);
    buf[100..104].copy_from_slice(&h.shard_len.to_le_bytes());
    buf[104..108].copy_from_slice(&h.entropy_milli.to_le_bytes());
    let nb = h.name.as_bytes();
    let nlen = nb.len().min(16);
    buf[112..112 + nlen].copy_from_slice(&nb[..nlen]);
    buf[128..160].copy_from_slice(&h.merkle);
    let crc = crc32fast::hash(&buf);
    buf[108..112].copy_from_slice(&crc.to_le_bytes());
    buf
}

pub fn read_header(buf: &[u8]) -> Result<Header> {
    parse_header(buf, &MAGIC)
}

fn parse_header(buf: &[u8], magic: &[u8; 4]) -> Result<Header> {
    if buf.len() < HEADER_SIZE {
        return Err(Error::Msg("truncated header".into()));
    }
    if buf[0..4] != magic[..] {
        return Err(Error::Msg("missing magic".into()));
    }
    if buf[4] < VERSION_MIN || buf[4] > VERSION_MAX {
        return Err(Error::Msg(format!(
            "unsupported Sigil version {} (this tool reads v{VERSION_MIN}–v{VERSION_MAX})",
            buf[4]
        )));
    }
    let mut probe = buf[..HEADER_SIZE].to_vec();
    probe[108..112].fill(0);
    let expect = crc32fast::hash(&probe);
    let got = u32::from_le_bytes(buf[108..112].try_into().map_err(crate::short_field)?);
    if expect != got {
        return Err(Error::Msg("header CRC mismatch".into()));
    }
    // The CRC is not authentication: reject geometry no encoder produces, so a crafted
    // header cannot drive the decoders into a zero divisor or an empty-input index.
    if buf[6] == 0 || buf[6] > buf[7] {
        return Err(Error::Msg(format!(
            "invalid header geometry k={} n={}",
            buf[6], buf[7]
        )));
    }
    let name_end = buf[112..128]
        .iter()
        .rposition(|&b| b != 0)
        .map(|i| i + 1)
        .unwrap_or(0);
    Ok(Header {
        version: buf[4],
        flags: buf[5],
        k: buf[6],
        n: buf[7],
        orig_len: u64::from_le_bytes(buf[8..16].try_into().map_err(crate::short_field)?),
        folded_len: u64::from_le_bytes(buf[16..24].try_into().map_err(crate::short_field)?),
        digest: buf[24..56].try_into().map_err(crate::short_field)?,
        salt: buf[56..72].try_into().map_err(crate::short_field)?,
        nonce: buf[72..84].try_into().map_err(crate::short_field)?,
        tag: buf[84..100].try_into().map_err(crate::short_field)?,
        shard_len: u32::from_le_bytes(buf[100..104].try_into().map_err(crate::short_field)?),
        entropy_milli: u32::from_le_bytes(buf[104..108].try_into().map_err(crate::short_field)?),
        name: String::from_utf8_lossy(&buf[112..112 + name_end]).into_owned(),
        merkle: buf[128..160].try_into().map_err(crate::short_field)?,
    })
}

pub fn write_ember(header: &[u8], index: u8) -> Vec<u8> {
    let mut buf = header[..HEADER_SIZE].to_vec();
    buf[0..4].copy_from_slice(&MAGIC_EMBER);
    buf[107] = index; // entropy MSB is 0 for real entropy; piece index lives here
    buf[108..112].fill(0);
    let crc = crc32fast::hash(&buf);
    buf[108..112].copy_from_slice(&crc.to_le_bytes());
    buf
}

pub fn shard_stride(h: &Header) -> usize {
    let lead = if h.ember() { HEADER_SIZE } else { 0 } + if h.vow() { VOW_SIZE } else { 0 };
    lead + h.shard_len as usize + 4
}

/// Soft-RS grading: CRC-good (Hard), present-but-CRC-fail (Soft), or absent.
#[derive(Clone, Debug)]
pub enum GradedShard {
    Hard(Vec<u8>),
    Soft(Vec<u8>),
    Missing,
}

impl GradedShard {
    /// The shard bytes as read (CRC-good or not); `None` when the shard is missing.
    pub fn body(&self) -> Option<&[u8]> {
        match self {
            GradedShard::Hard(b) | GradedShard::Soft(b) => Some(b),
            GradedShard::Missing => None,
        }
    }
    #[allow(dead_code)]
    pub fn is_hard(&self) -> bool {
        matches!(self, GradedShard::Hard(_))
    }
    pub fn is_present(&self) -> bool {
        !matches!(self, GradedShard::Missing)
    }
}

fn grade_shard(shard: Vec<u8>, crc: u32) -> GradedShard {
    if crc32fast::hash(&shard) == crc {
        GradedShard::Hard(shard)
    } else {
        GradedShard::Soft(shard)
    }
}

/// Like [`gather_live_shards`], but keeps CRC-failed shard bodies as Soft for soft-RS salvage.
pub fn gather_graded_shards(file: &[u8], h: &Header, prefix: usize) -> Vec<GradedShard> {
    let n = h.n as usize;
    let sl = h.shard_len as usize;
    let lead = if h.ember() { HEADER_SIZE } else { 0 } + if h.vow() { VOW_SIZE } else { 0 };
    let stride = shard_stride(h);
    let mut live = vec![GradedShard::Missing; n];
    if h.ember() {
        struct Hit {
            slot: usize,
            grade: GradedShard,
        }
        let mut hits: Vec<Hit> = Vec::new();
        let mut i = 0usize;
        while i + HEADER_SIZE <= file.len() {
            if file[i..i + 4] != MAGIC_EMBER {
                i += 1;
                continue;
            }
            match parse_header(&file[i..], &MAGIC_EMBER) {
                Ok(eh) if eh.merkle == h.merkle && eh.shard_len == h.shard_len => {
                    let slot = (eh.entropy_milli >> 24) as usize;
                    let off = i + lead;
                    // `get` + `try_from` is the bounds check: no CRC word, no shard.
                    if let Some(crc) = le_u32_at(file, off + sl) {
                        let shard = file[off..off + sl].to_vec();
                        hits.push(Hit {
                            slot,
                            grade: grade_shard(shard, crc),
                        });
                    }
                    i += HEADER_SIZE;
                }
                _ => i += 1,
            }
        }
        let unique: std::collections::BTreeSet<usize> =
            hits.iter().map(|h| h.slot).filter(|s| *s < n).collect();
        let use_order = unique.len() < 2;
        for (order, hit) in hits.into_iter().enumerate() {
            let slot = if use_order { order } else { hit.slot };
            if slot < n && matches!(live[slot], GradedShard::Missing) {
                live[slot] = hit.grade;
            }
        }
    }
    let body = if prefix <= file.len() {
        &file[prefix..]
    } else {
        file
    };
    for (i, slot) in live.iter_mut().enumerate().take(n) {
        if !matches!(slot, GradedShard::Missing) {
            continue;
        }
        let off = i * stride + lead;
        if off + sl + 4 > body.len() {
            continue;
        }
        let shard = body[off..off + sl].to_vec();
        let Some(crc) = le_u32_at(body, off + sl) else {
            continue;
        };
        *slot = grade_shard(shard, crc);
    }
    live
}

/// Walk the file for Ember maps. A deleted byte only kills that piece; later pieces stay findable.
pub fn gather_live_shards(file: &[u8], h: &Header, prefix: usize) -> Vec<Option<Vec<u8>>> {
    let n = h.n as usize;
    let sl = h.shard_len as usize;
    let lead = if h.ember() { HEADER_SIZE } else { 0 } + if h.vow() { VOW_SIZE } else { 0 };
    let stride = shard_stride(h);
    let mut live = vec![None; n];
    if h.ember() {
        struct Hit {
            slot: usize,
            shard: Vec<u8>,
        }
        let mut hits: Vec<Hit> = Vec::new();
        let mut i = 0usize;
        while i + HEADER_SIZE <= file.len() {
            if file[i..i + 4] != MAGIC_EMBER {
                i += 1;
                continue;
            }
            match parse_header(&file[i..], &MAGIC_EMBER) {
                Ok(eh) if eh.merkle == h.merkle && eh.shard_len == h.shard_len => {
                    let slot = (eh.entropy_milli >> 24) as usize;
                    let off = i + lead;
                    // `get` + `try_from` is the bounds check: no CRC word, no shard.
                    if let Some(crc) = le_u32_at(file, off + sl) {
                        let shard = file[off..off + sl].to_vec();
                        if crc32fast::hash(&shard) == crc {
                            hits.push(Hit { slot, shard });
                        }
                    }
                    i += HEADER_SIZE;
                }
                _ => i += 1,
            }
        }
        let unique: std::collections::BTreeSet<usize> =
            hits.iter().map(|h| h.slot).filter(|s| *s < n).collect();
        let use_order = unique.len() < 2;
        for (order, hit) in hits.into_iter().enumerate() {
            let slot = if use_order { order } else { hit.slot };
            if slot < n && live[slot].is_none() {
                live[slot] = Some(hit.shard);
            }
        }
    }
    let body = if prefix <= file.len() {
        &file[prefix..]
    } else {
        file
    };
    for (i, slot) in live.iter_mut().enumerate().take(n) {
        if slot.is_some() {
            continue;
        }
        let off = i * stride + lead;
        if off + sl + 4 > body.len() {
            continue;
        }
        let shard = body[off..off + sl].to_vec();
        let Some(crc) = le_u32_at(body, off + sl) else {
            continue;
        };
        if crc32fast::hash(&shard) == crc {
            *slot = Some(shard);
        }
    }
    live
}

pub fn maps_len(h: &Header) -> usize {
    if h.keystone() {
        KEYSTONE_SPAN
    } else {
        HEADER_SIZE
    }
}

/// Body prefix without peeking for SGTO (legacy / when file bytes unavailable).
#[allow(dead_code)]
pub fn body_prefix(h: &Header) -> usize {
    maps_len(h) + if h.vow() { VOW_SIZE } else { 0 }
}

/// Body prefix including an optional SGTO companion block (magic `SGTO` after keystone).
pub fn body_prefix_file(h: &Header, file: &[u8]) -> usize {
    let maps = maps_len(h);
    let sgto = crate::keys::sgto_len_at(file, maps);
    maps + sgto + if h.vow() { VOW_SIZE } else { 0 }
}

/// Slice of SGTO bytes after the keystone maps, if present.
pub fn sgto_slice<'a>(h: &Header, file: &'a [u8]) -> Option<&'a [u8]> {
    crate::keys::read_sgto_at(file, maps_len(h))
}

pub fn write_vow(covenant: &str, geas: &[[u8; 32]]) -> Vec<u8> {
    let mut buf = vec![0u8; VOW_SIZE];
    let cov = covenant.as_bytes();
    let n = cov.len().min(48);
    buf[0] = n as u8;
    let g = geas.len().min(2);
    buf[1] = g as u8;
    buf[2..2 + n].copy_from_slice(&cov[..n]);
    for (i, h) in geas.iter().take(2).enumerate() {
        buf[50 + i * 32..50 + (i + 1) * 32].copy_from_slice(h);
    }
    let crc = crc32fast::hash(&buf[..124]);
    buf[124..128].copy_from_slice(&crc.to_le_bytes());
    buf
}

pub fn read_vow(buf: &[u8]) -> Option<(String, Vec<[u8; 32]>)> {
    if buf.len() < VOW_SIZE {
        return None;
    }
    let crc = crc32fast::hash(&buf[..124]);
    let got = u32::from_le_bytes(buf[124..128].try_into().ok()?);
    if crc != got {
        return None;
    }
    let n = (buf[0] as usize).min(48);
    let g = (buf[1] as usize).min(2);
    let cov = String::from_utf8_lossy(&buf[2..2 + n]).into_owned();
    let mut geas = Vec::new();
    for i in 0..g {
        let mut h = [0u8; 32];
        h.copy_from_slice(&buf[50 + i * 32..50 + (i + 1) * 32]);
        geas.push(h);
    }
    Some((cov, geas))
}

/// Rank a candidate body offset for a header found only through an Ember.
///
/// Primary key: shards whose CRC32 matches at that offset. Tie-break (only
/// matters when bit rot left few or no CRC-good shards): Ember copies sitting
/// exactly where this offset puts them (1 point for the `SGEM` magic, 1 more
/// when that Ember parses and carries the same binding). The CRC count always
/// dominates, so offsets that won before still win.
fn score_prefix(file: &[u8], h: &Header, prefix: usize) -> i32 {
    if prefix > file.len() {
        return -1;
    }
    let stride = shard_stride(h);
    let body = &file[prefix..];
    let mut live = 0i32;
    let mut embers = 0i32;
    for i in 0..h.n as usize {
        let lead = if h.ember() { HEADER_SIZE } else { 0 } + if h.vow() { VOW_SIZE } else { 0 };
        let start = i * stride;
        if h.ember() && body.get(start..start + 4) == Some(&MAGIC_EMBER[..]) {
            embers += 1;
            if let Ok(eh) = parse_header(&body[start..], &MAGIC_EMBER) {
                if eh.merkle == h.merkle {
                    embers += 1;
                }
            }
        }
        let off = start + lead;
        if off + h.shard_len as usize + 4 > body.len() {
            continue;
        }
        let shard = &body[off..off + h.shard_len as usize];
        let Some(crc) = le_u32_at(body, off + h.shard_len as usize) else {
            continue;
        };
        if crc32fast::hash(shard) == crc {
            live += 1;
        }
    }
    // n <= 255, so 2 * n Ember points < 1024 never outweigh one CRC-good shard.
    live * 1024 + embers
}

fn locate_from_ember(file: &[u8]) -> Option<(Header, usize)> {
    let mut best: Option<(Header, usize, i32)> = None;
    let mut i = 0usize;
    while i + HEADER_SIZE <= file.len() {
        if file[i..i + 4] != MAGIC_EMBER {
            i += 1;
            continue;
        }
        if let Ok(mut h) = parse_header(&file[i..], &MAGIC_EMBER) {
            // An Ember keeps its slot in the top byte of the entropy word; the
            // front header always has 0 there (entropy is at most 8000 milli-bits),
            // so clear it to get the front header's exact bytes back.
            h.entropy_milli &= 0x00ff_ffff;
            if h.ember() {
                let stride = shard_stride(&h);
                if stride > 0 {
                    let mut prefixes = vec![0usize, KEYSTONE_SPAN, KEYSTONE_SPAN + VOW_SIZE];
                    // SGTO (variable) may sit after keystone — probe common offsets + magic scan.
                    if let Some(block) = crate::keys::read_sgto_at(file, KEYSTONE_SPAN) {
                        let s = block.len();
                        prefixes.push(KEYSTONE_SPAN + s);
                        prefixes.push(KEYSTONE_SPAN + s + VOW_SIZE);
                    }
                    for k in 0..h.n as usize {
                        if i >= k * stride {
                            prefixes.push(i - k * stride);
                        }
                    }
                    for p in prefixes {
                        let score = score_prefix(file, &h, p);
                        let better = best.as_ref().map(|b| score > b.2).unwrap_or(true);
                        if better {
                            best = Some((h.clone(), p, score));
                        }
                    }
                }
            }
        }
        i += 1;
    }
    best.filter(|b| b.2 >= 0).map(|b| (b.0, b.1))
}

pub fn wrap_keystone(header: &[u8]) -> Vec<u8> {
    let mut out = vec![0u8; KEYSTONE_SPAN];
    for i in 0..=KEYSTONE_COPIES {
        out[i * HEADER_SIZE..i * HEADER_SIZE + HEADER_SIZE].copy_from_slice(&header[..HEADER_SIZE]);
    }
    out
}

/// End-of-file Keystone spare: `SGKT` | version | one header copy.
///
/// Written after the seal body so a wiped front Keystone span can still locate
/// the header when Embers are also gone. Does not move SGTO: body prefix stays
/// keyed off the recovered header's Keystone flag from file start.
///
/// The copy stores the primary header with its `SGIL` magic overwritten as
/// four zero bytes so a byte scan (including older readers that look for a
/// second `SGIL`) does not treat the spare as another seal. Parsers restore
/// `SGIL` before checking the header CRC.
pub fn write_keystone_trailer(header: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(KEYSTONE_TRAILER_SIZE);
    out.extend_from_slice(&MAGIC_KEYSTONE_TRAILER);
    out.push(KEYSTONE_TRAILER_VERSION);
    let n = header.len().min(HEADER_SIZE);
    out.extend_from_slice(&header[..n]);
    if n < HEADER_SIZE {
        out.resize(KEYSTONE_TRAILER_SIZE, 0);
    }
    // Elide SGIL so older ensure_single_seal / hunt ignore this spare.
    if out.len() >= 9 {
        out[5..9].copy_from_slice(&[0, 0, 0, 0]);
    }
    out
}

/// How many trailing bytes at `off` are a Keystone trailer (`SGKT` magic).
/// Returns [`KEYSTONE_TRAILER_SIZE`] when the magic matches (header may be
/// damaged); otherwise 0. Used when measuring a seal that may still carry a
/// trailer in front of a pack guard.
pub fn keystone_trailer_len_at(file: &[u8], off: usize) -> usize {
    match file.get(off..off.saturating_add(4)) {
        Some(m) if m == MAGIC_KEYSTONE_TRAILER => KEYSTONE_TRAILER_SIZE,
        _ => 0,
    }
}

/// Parse a Keystone trailer at `off`. Garbage or non-keystone headers yield `None`
/// (fail closed, never panic).
fn try_parse_keystone_trailer_at(file: &[u8], off: usize) -> Option<Header> {
    let end = off.checked_add(KEYSTONE_TRAILER_SIZE)?;
    let block = file.get(off..end)?;
    if block[0..4] != MAGIC_KEYSTONE_TRAILER {
        return None;
    }
    if block[4] != KEYSTONE_TRAILER_VERSION {
        return None;
    }
    let mut hdr = block[5..].to_vec();
    if hdr.len() < HEADER_SIZE {
        return None;
    }
    // Magic was stored as zeros; restore SGIL so the header CRC matches.
    hdr[0..4].copy_from_slice(&MAGIC);
    let h = read_header(&hdr).ok()?;
    if !h.keystone() {
        return None;
    }
    Some(h)
}

/// True when `off` points at an SGIL that is the payload of a Keystone trailer
/// (`SGKT` | version immediately before it). Hunt must skip these so a small
/// file's trailing spare is not mistaken for a mid-file header.
fn sgil_is_keystone_trailer_payload(file: &[u8], off: usize) -> bool {
    off.checked_sub(5)
        .is_some_and(|t| try_parse_keystone_trailer_at(file, t).is_some())
}

/// Scan a bounded tail window for a Keystone trailer. Body prefix matches a
/// front Keystone spare: SGTO still sits at `KEYSTONE_SPAN` from file start.
fn locate_from_trailer(file: &[u8]) -> Option<(Header, usize)> {
    if file.len() < KEYSTONE_TRAILER_SIZE {
        return None;
    }
    // Trailer sits after the seal body; allow a little trailing junk/padding.
    const TAIL_SLACK: usize = 1024;
    let window = KEYSTONE_TRAILER_SIZE.saturating_add(TAIL_SLACK);
    let start = file.len().saturating_sub(window);
    let mut i = start;
    while i + KEYSTONE_TRAILER_SIZE <= file.len() {
        if let Some(h) = try_parse_keystone_trailer_at(file, i) {
            let prefix = body_prefix_file(&h, file);
            return Some((h, prefix));
        }
        i += 1;
    }
    None
}

/// Fail closed when `file` holds more than the one seal its header describes.
///
/// A large-file pack (SGWK) is many complete seals back to back. If the pack's
/// front is damaged, `locate_header` still finds the *first* chunk's seal a few
/// bytes in, and that seal opens and checks out on its own, so opening "the
/// file" would silently return only the first chunk. Any second Sigil header or
/// pack trailer after the end of the located seal means "this is not one seal".
///
/// It also refuses a seal that still has pack framing in front of it: a
/// little-endian u64 right before the seal's header that equals the seal's own
/// length (plus at most [`PACK_STAR_EXTRA`] bytes). That is one chunk star of a
/// pack whose head is damaged and whose other stars are missing; returning it
/// would hand back one 4 MiB chunk as if it were the whole file.
pub fn ensure_single_seal(file: &[u8], h: &Header, prefix: usize) -> Result<()> {
    let end = prefix.saturating_add((h.n as usize).saturating_mul(shard_stride(h)));
    let lone_star = || {
        if framed_as_pack_star(file, end) {
            return Err(Error::Msg(
                "this file holds one part of a large-file pack whose front (pack head) is \
                 damaged and whose other parts are missing. Refusing to return only that \
                 part; restore the pack from another copy."
                    .into(),
            ));
        }
        Ok(())
    };
    if file.len() <= end {
        return lone_star();
    }
    let tail = &file[end..];
    let mut i = 0;
    while i + 4 <= tail.len() {
        // New seals append an SGKT Keystone trailer after the shards. Skip a
        // recognized trailer so header-field bytes that happen to look like
        // SGIL/SGEM are not treated as a second seal. The copy's SGIL magic is
        // stored as zeros, so older readers that scan for SGIL ignore it too.
        if try_parse_keystone_trailer_at(file, end + i).is_some() {
            i += KEYSTONE_TRAILER_SIZE;
            continue;
        }
        let w = &tail[i..i + 4];
        // A middle-byte deletion can shift the SGKT trailer so its embedded SGIL
        // sits in the tail without a recognizable SGKT prefix. Same merkle as the
        // located header means it is our own spare, not a second seal.
        if w == MAGIC {
            if let Ok(th) = read_header(&tail[i..]) {
                if th.keystone() && th.merkle == h.merkle {
                    i += HEADER_SIZE;
                    continue;
                }
            }
        }
        let hit = (w == MAGIC && read_header(&tail[i..]).is_ok())
            || (w == MAGIC_EMBER && parse_header(&tail[i..], &MAGIC_EMBER).is_ok())
            || (w == b"SGFC"
                && tail.len() >= i + 8
                && (tail.len() - i - 8).is_multiple_of(32)
                && u32::from_le_bytes(tail[i + 4..i + 8].try_into().map_err(crate::short_field)?)
                    as usize
                    == (tail.len() - i - 8) / 32);
        if hit {
            return Err(Error::Msg(
                "this file holds more than one seal: it looks like a large-file pack whose \
                 front (pack head) is damaged. Refusing to return only the first part. \
                 `sigil mend` rebuilds the head when the facet list and the stars \
                 survive; otherwise restore it from another copy."
                    .into(),
            ));
        }
        i += 1;
    }
    lone_star()
}

/// Bytes a pack star may carry after its seal and still count as framed (room
/// for optional per-star records such as a pack-head guard).
pub const PACK_STAR_EXTRA: usize = 1024;

/// Longest SGWK pack head plus the star's 8-byte length: how far in a framed
/// first star's header can sit.
const PACK_FRAME_REACH: usize = 281 + 8;

/// True when some header within the first [`PACK_FRAME_REACH`] bytes is preceded
/// by an 8-byte length that matches the seal ending at `end`.
fn framed_as_pack_star(file: &[u8], end: usize) -> bool {
    let reach = file.len().min(PACK_FRAME_REACH + 1);
    (8..reach).any(|s| {
        if file.get(s..s + 4) != Some(&MAGIC[..]) || read_header(&file[s..]).is_err() {
            return false;
        }
        let mut lb = [0u8; 8];
        lb.copy_from_slice(&file[s - 8..s]);
        let framed = u64::from_le_bytes(lb);
        let Some(seal_len) = end.checked_sub(s) else {
            return false;
        };
        framed >= seal_len as u64 && framed <= (seal_len + PACK_STAR_EXTRA) as u64
    })
}

/// Returns (header, body prefix, recovered from a spare copy).
pub fn locate_header(file: &[u8]) -> Result<(Header, usize, bool)> {
    if let Ok(h) = read_header(file) {
        let prefix = body_prefix_file(&h, file);
        return Ok((h, prefix, false));
    }
    for slot in 1..=KEYSTONE_COPIES {
        let off = slot * HEADER_SIZE;
        if off + HEADER_SIZE > file.len() {
            continue;
        }
        if let Ok(h) = read_header(&file[off..]) {
            if h.keystone() {
                // Keystone spare: SGTO still sits after the full keystone span from file start.
                let prefix = body_prefix_file(&h, file);
                return Ok((h, prefix, true));
            }
        }
    }
    // Leading junk (e.g. a UTF-8 BOM) — search a little way in for SGIL.
    // Skip an SGIL that is the payload of an end-of-file Keystone trailer so a
    // small seal's trailing spare is not treated as a mid-file header.
    let hunt = file.len().min(8192);
    for i in 1..hunt {
        if i + HEADER_SIZE > file.len() {
            break;
        }
        if file[i..i + 4] != MAGIC {
            continue;
        }
        if sgil_is_keystone_trailer_payload(file, i) {
            continue;
        }
        if let Ok(h) = read_header(&file[i..]) {
            let prefix = i + body_prefix_file(&h, &file[i..]);
            return Ok((h, prefix, true));
        }
    }
    // Trailing Keystone spare before Ember: cheaper bounded scan, and covers
    // the case where every Ember marker is also gone.
    if let Some((h, prefix)) = locate_from_trailer(file) {
        return Ok((h, prefix, true));
    }
    if let Some((h, prefix)) = locate_from_ember(file) {
        return Ok((h, prefix, true));
    }
    Err(Error::Msg(
        "header damaged and no Keystone, trailer, or Ember survived".into(),
    ))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn with_geometry(k: u8, n: u8) -> Vec<u8> {
        let sealed = crate::seal(b"geometry probe", crate::Mode::Reflection, None, "g", false)
            .expect("seal");
        let mut h = sealed[..HEADER_SIZE].to_vec();
        h[6] = k;
        h[7] = n;
        h[108..112].fill(0);
        let crc = crc32fast::hash(&h);
        h[108..112].copy_from_slice(&crc.to_le_bytes());
        h
    }

    #[test]
    fn crafted_geometry_is_an_error_not_a_panic() {
        assert!(read_header(&with_geometry(0, 8)).is_err(), "k = 0");
        assert!(read_header(&with_geometry(9, 8)).is_err(), "k > n");
        assert!(read_header(&with_geometry(4, 8)).is_ok(), "valid k <= n");
    }

    #[test]
    fn le_u32_at_is_total() {
        let b = [1u8, 0, 0, 0, 2];
        assert_eq!(le_u32_at(&b, 0), Some(1));
        assert_eq!(le_u32_at(&b, 1), Some(0x0200_0000));
        assert_eq!(le_u32_at(&b, 2), None, "3 bytes left");
        assert_eq!(le_u32_at(&b, 99), None, "past the end");
        assert_eq!(le_u32_at(&b, usize::MAX), None, "offset overflow");
    }

    /// The best-effort shard scanners must never panic on a truncated file: every prefix of a
    /// real mark either parses or is refused.
    #[test]
    fn scanners_survive_every_truncation() {
        let mark = crate::seal(&[0x42u8; 3000], Mode::Seal, None, "t", false).unwrap();
        for cut in (0..mark.len()).step_by(37) {
            let f = &mark[..cut];
            if let Ok((h, prefix, _)) = locate_header(f) {
                let _ = gather_live_shards(f, &h, prefix);
                let _ = gather_graded_shards(f, &h, prefix);
            }
        }
    }

    #[test]
    fn keystone_trailer_roundtrip_extends_file() {
        let msg = b"trailer roundtrip payload -- long enough for seal shards xx";
        let bytes = crate::seal(msg, Mode::Seal, None, "tr.bin", false).unwrap();
        assert!(bytes.len() >= KEYSTONE_TRAILER_SIZE);
        let t = &bytes[bytes.len() - KEYSTONE_TRAILER_SIZE..];
        assert_eq!(&t[0..4], b"SGKT");
        assert_eq!(t[4], KEYSTONE_TRAILER_VERSION);
        assert_eq!(
            &t[5..9],
            &[0, 0, 0, 0],
            "SGIL elided so older readers do not see a second seal"
        );
        assert_eq!(&t[9..], &bytes[4..HEADER_SIZE]);
        assert_eq!(crate::unseal(&bytes, None).unwrap(), msg);
        let h = read_header(&bytes).unwrap();
        let prefix = body_prefix_file(&h, &bytes);
        ensure_single_seal(&bytes, &h, prefix).expect("healthy seal with SGKT trailer");
    }

    #[test]
    fn keystone_trailer_recovers_wiped_front_and_embers() {
        let msg = b"front and embers gone; trailer must still open this seal xx";
        let bytes = crate::seal(msg, Mode::Seal, None, "wipe.bin", false).unwrap();
        let h = read_header(&bytes).unwrap();
        let prefix = body_prefix_file(&h, &bytes);
        let stride = shard_stride(&h);
        let mut torn = bytes.clone();
        torn[..KEYSTONE_SPAN].fill(0);
        torn[0] = 0x58;
        for i in 0..h.n as usize {
            let off = prefix + i * stride;
            if off + 4 <= torn.len() {
                torn[off..off + 4].fill(0);
            }
        }
        let (rh, rprefix, recovered) = locate_header(&torn).expect("trailer locate");
        assert!(recovered);
        assert_eq!(rh.merkle, h.merkle);
        assert_eq!(rprefix, prefix);
        assert_eq!(crate::unseal(&torn, None).unwrap(), msg);
        let healed = crate::pieces::mend_bytes(&torn).unwrap();
        assert_eq!(crate::unseal(&healed, None).unwrap(), msg);
        assert_eq!(healed, bytes);
    }

    /// Zero the primary header, every front Keystone copy and the end-of-file
    /// SGKT trailer. Ember copies inside the body are left alone.
    fn wipe_both_ends(bytes: &[u8]) -> Vec<u8> {
        let mut torn = bytes.to_vec();
        torn[..KEYSTONE_SPAN].fill(0);
        torn[0] = 0x58;
        let t0 = torn.len() - KEYSTONE_TRAILER_SIZE;
        torn[t0..].fill(0);
        torn
    }

    #[test]
    fn both_ends_wiped_recovers_from_middle_ember() {
        let msg: Vec<u8> = (0..40_000u32).map(|i| (i * 31 % 251) as u8).collect();
        for pass in [None, Some("both ends pass")] {
            let bytes = crate::seal(&msg, Mode::Seal, pass, "ends.bin", false).unwrap();
            let h = read_header(&bytes).unwrap();
            assert!(h.ember(), "new seals carry Embers");
            let prefix = body_prefix_file(&h, &bytes);
            let mut torn = wipe_both_ends(&bytes);
            // Also kill shard 0's Ember so the header must come from a later one.
            torn[prefix..prefix + 4].fill(0);
            assert!(read_header(&torn).is_err(), "primary header gone");
            for slot in 1..=KEYSTONE_COPIES {
                assert!(
                    read_header(&torn[slot * HEADER_SIZE..]).is_err(),
                    "Keystone {slot} gone"
                );
            }
            assert!(locate_from_trailer(&torn).is_none(), "trailer gone");
            let (eh, eprefix) = locate_from_ember(&torn).expect("a middle Ember survives");
            assert_eq!(eh.merkle, h.merkle);
            assert_eq!(eprefix, prefix);
            let (rh, rprefix, recovered) = locate_header(&torn).expect("locate via Ember");
            assert!(recovered);
            assert_eq!(rh.merkle, h.merkle);
            assert_eq!(rprefix, prefix);
            assert_eq!(crate::unseal(&torn, pass).unwrap(), msg, "pass={pass:?}");
            let healed = crate::pieces::mend_bytes(&torn).unwrap();
            assert_eq!(
                healed, bytes,
                "mend restores front, Keystones and trailer; pass={pass:?}"
            );
            assert_eq!(crate::unseal(&healed, pass).unwrap(), msg);
        }
    }

    #[test]
    fn every_header_copy_gone_fails_closed() {
        let msg: Vec<u8> = (0..40_000u32).map(|i| (i * 17 % 253) as u8).collect();
        let bytes = crate::seal(&msg, Mode::Seal, None, "none.bin", false).unwrap();
        let h = read_header(&bytes).unwrap();
        let prefix = body_prefix_file(&h, &bytes);
        let stride = shard_stride(&h);
        let mut torn = wipe_both_ends(&bytes);
        for i in 0..h.n as usize {
            let off = prefix + i * stride;
            torn[off..off + 4].fill(0);
        }
        assert!(locate_header(&torn).is_err());
        assert!(crate::unseal(&torn, None).is_err());
        assert!(crate::pieces::mend_bytes(&torn).is_err());
    }

    #[test]
    fn keystone_trailer_absent_old_style_still_opens() {
        let msg = b"old style without trailer still opens via front header xx";
        let bytes = crate::seal(msg, Mode::Seal, None, "old.bin", false).unwrap();
        assert!(bytes.len() > KEYSTONE_TRAILER_SIZE);
        let stripped = bytes[..bytes.len() - KEYSTONE_TRAILER_SIZE].to_vec();
        let t = &bytes[bytes.len() - KEYSTONE_TRAILER_SIZE..];
        assert_eq!(&t[0..4], b"SGKT");
        assert_eq!(crate::unseal(&stripped, None).unwrap(), msg);
        let (h, prefix, recovered) = locate_header(&stripped).unwrap();
        assert!(!recovered);
        assert!(h.keystone());
        ensure_single_seal(&stripped, &h, prefix).expect("old-style single seal");
    }

    #[test]
    fn keystone_trailer_bitflip_alone_does_not_break_healthy_file() {
        let msg = b"bitflip only in trailer; front header still wins xx";
        let bytes = crate::seal(msg, Mode::Seal, None, "flip.bin", false).unwrap();
        let mut torn = bytes.clone();
        let i = torn.len() - 20;
        torn[i] ^= 0xff;
        assert_ne!(torn, bytes);
        assert_eq!(crate::unseal(&torn, None).unwrap(), msg);
        let (_, _, recovered) = locate_header(&torn).unwrap();
        assert!(!recovered, "front header must still win");
    }

    #[test]
    fn keystone_trailer_garbage_sgkt_is_ignored() {
        let mut junk = vec![0u8; 200];
        junk[0..4].copy_from_slice(b"SGKT");
        junk[4] = KEYSTONE_TRAILER_VERSION;
        // No valid header follows — must not panic or claim a locate.
        assert!(try_parse_keystone_trailer_at(&junk, 0).is_none());
        assert!(locate_from_trailer(&junk).is_none());
    }

    #[test]
    fn keystone_start_bitflips_still_open_or_mend() {
        let msg = b"bitflips near the start must still open or mend xx";
        let bytes = crate::seal(msg, Mode::Seal, None, "flipstart.bin", false).unwrap();
        // Primary header only: remaining Keystone copies should carry us.
        let mut torn = bytes.clone();
        for b in &mut torn[..HEADER_SIZE] {
            *b ^= 0xff;
        }
        assert_eq!(crate::unseal(&torn, None).unwrap(), msg);
        let healed = crate::pieces::mend_bytes(&torn).unwrap();
        assert_eq!(crate::unseal(&healed, None).unwrap(), msg);

        // Entire front Keystone span: trailer (or Ember) must still open.
        let mut torn = bytes.clone();
        for b in &mut torn[..KEYSTONE_SPAN] {
            *b ^= 0xff;
        }
        assert_eq!(crate::unseal(&torn, None).unwrap(), msg);
        let healed = crate::pieces::mend_bytes(&torn).unwrap();
        assert_eq!(crate::unseal(&healed, None).unwrap(), msg);
        assert_eq!(healed, bytes);
    }

    #[test]
    fn keystone_start_truncation_fails_closed_or_correct() {
        let msg = b"truncation near start must not return different bytes xx";
        let bytes = crate::seal(msg, Mode::Seal, None, "cutstart.bin", false).unwrap();
        // File cut down from the end, leaving only a prefix: fail closed or
        // (if enough survived) return the real payload — never different bytes.
        for cut in [
            0usize,
            16,
            80,
            HEADER_SIZE,
            KEYSTONE_SPAN,
            KEYSTONE_SPAN + 8,
        ] {
            let f = &bytes[..cut.min(bytes.len())];
            if let Ok(got) = crate::unseal(f, None) {
                assert_eq!(got, msg, "truncation at {cut} returned different bytes");
            }
        }
        // Leading bytes removed: never return the wrong payload.
        for drop in [1usize, 8, 80, HEADER_SIZE, KEYSTONE_SPAN] {
            if drop >= bytes.len() {
                continue;
            }
            let f = &bytes[drop..];
            if let Ok(got) = crate::unseal(f, None) {
                assert_eq!(got, msg, "leading drop {drop} returned different bytes");
            }
        }
    }
}
