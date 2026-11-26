//! The classic single seal (`.sg1`: one AES-256-GCM message over one deflate stream,
//! folded, then split into Reed–Solomon parts), sealed, opened, checked and mended a
//! bounded window at a time instead of in memory.
//!
//! Nothing about the file changes: every function here writes the same bytes as the
//! in-memory code in `lib.rs` / `pieces.rs`, and reads the files that code reads.
//!
//! * **Layout.** [`probe`] accepts only a file whose framing is exactly where its front
//!   header puts it (front header, key wrap, Vow, every Ember, the key-wrap spare and the
//!   trailer). Anything else (a shifted or damaged frame, an old v1 seal, a pack) returns
//!   `None` and the caller uses the in-memory path, which has the full salvage logic.
//!   Damage inside part bodies is fine here: a part whose CRC fails is an erasure.
//! * **Opening.** The parts are checked one window at a time. If a data part is missing it
//!   is rebuilt into a private (0600) scratch file beside the output; for an encrypted seal
//!   that file holds ciphertext only. The GCM tag is computed over the whole ciphertext
//!   (GHASH, pass 1) and compared before a single byte is decrypted (pass 2), so no
//!   unauthenticated plaintext is ever released.
//! * **Sealing.** The input is read once (SHA-256, entropy, keyed fingerprint, deflate).
//!   The deflate output goes to a scratch file encrypted with a throwaway key that lives
//!   only in memory, so no plaintext-derived bytes reach the disk. Ciphertext is written
//!   straight into the data parts of the output, parity is computed a column window at a
//!   time, and the headers (which carry the tag and Merkle root) are written last.
//!
//! Peak memory is a few column windows (about [`RS_BUDGET`]) plus 1 MiB buffers, whatever
//! the file size. Every loop over file data calls [`crate::repair_ctl::check`] once per
//! window, so Ctrl-C and time limits stop it; every read is bounded by the file size.

use crate::header::{self, Header, HEADER_SIZE, KEYSTONE_SPAN, VOW_SIZE};
use crate::packhead::{FileSrc, Src};
use crate::{chaos, gf, keys, mds, merkle, privacy, rs, Error, Mode, Result};
use aes::cipher::{
    generic_array::GenericArray, BlockEncrypt, KeyInit, KeyIvInit, StreamCipher, StreamCipherSeek,
};
use ghash::universal_hash::UniversalHash;
use hmac::{Hmac, Mac};
use sha2::{Digest, Sha256};
use std::fs::File;
use std::io::{Read, Seek, SeekFrom, Write};
use std::path::{Path, PathBuf};

/// Plain sequential I/O window (even, so folding byte pairs never straddle two pieces).
const IO_WINDOW: usize = 1 << 20;
/// Bytes of Reed–Solomon column windows held at once, over all parts.
const RS_BUDGET: usize = 32 << 20;
/// How much of the file front is read to find the header, key wrap and Vow (the largest
/// key wrap is about 26 KB).
const HEAD_READ: u64 = 64 * 1024;
/// Longest AES-GCM message the in-memory path accepts (`aes_gcm::P_MAX` / `C_MAX`).
const GCM_P_MAX: u64 = 1 << 36;
const GCM_C_MAX: u64 = (1 << 36) + 16;

type Ctr = ctr::Ctr32BE<aes::Aes256>;
type HmacSha256 = Hmac<Sha256>;

fn msg(s: impl Into<String>) -> Error {
    Error::Msg(s.into())
}

fn io(e: std::io::Error) -> Error {
    Error::Msg(e.to_string())
}

fn col_window(n: usize, sl: u64) -> usize {
    let w = (RS_BUDGET / n.max(1)).clamp(64 * 1024, IO_WINDOW);
    (w as u64).min(sl.max(1)) as usize
}

// ---------------------------------------------------------------------------------------
// Layout
// ---------------------------------------------------------------------------------------

/// Where everything sits in a classic seal whose framing is intact.
pub(crate) struct Layout {
    pub h: Header,
    /// `write_header(h)`: the canonical header bytes (Embers and trailer copy these).
    pub hdr: Vec<u8>,
    /// The front of the file is the canonical Keystone (all copies intact).
    pub front_canonical: bool,
    pub prefix: u64,
    pub lead: u64,
    pub stride: u64,
    pub sl: u64,
    pub n: usize,
    pub k: usize,
    pub sgto: Option<Vec<u8>>,
    pub vow: Option<Vec<u8>>,
    pub file_len: u64,
}

impl Layout {
    fn shard_off(&self, i: usize) -> u64 {
        self.prefix + i as u64 * self.stride + self.lead
    }
    fn data_parts(&self) -> usize {
        self.k
    }
}

/// The layout of a classic seal whose framing is exactly where its front header puts it,
/// or `None` (use the in-memory path). Errors are I/O errors only.
pub(crate) fn probe(src: &mut FileSrc) -> Result<Option<Layout>> {
    let len = src.size();
    let mut head = vec![0u8; len.min(HEAD_READ) as usize];
    src.read_at(0, &mut head)?;
    if head.starts_with(b"SGWK") {
        return Ok(None);
    }
    let Ok(h) = header::read_header(&head) else {
        return Ok(None);
    };
    let n = h.n as usize;
    let k = h.k as usize;
    let glyph = h.mode() == Mode::Glyph;
    // v1 seals (non-systematic) and odd Glyph shapes stay on the in-memory path.
    if k == 0 || k > n || (glyph && k != n) || (!glyph && h.version < 2) {
        return Ok(None);
    }
    let sl = u64::from(h.shard_len);
    if sl == 0 || h.folded_len.div_ceil(k as u64).max(1) != sl {
        return Ok(None);
    }
    let maps = header::maps_len(&h);
    let sgto_len = keys::sgto_len_at(&head, maps);
    let sgto = (sgto_len > 0).then(|| head[maps..maps + sgto_len].to_vec());
    if sgto.is_none() && h.encrypted() && h.private_label() {
        return Ok(None);
    }
    let vow_len = if h.vow() { VOW_SIZE } else { 0 };
    let prefix = maps + sgto_len + vow_len;
    let vow = if h.vow() {
        match head.get(prefix - VOW_SIZE..prefix) {
            Some(v) if header::read_vow(v).is_some() => Some(v.to_vec()),
            _ => return Ok(None),
        }
    } else {
        None
    };
    let hdr = header::write_header(&h);
    let lead_bytes = if h.keystone() {
        header::wrap_keystone(&hdr)
    } else {
        hdr.clone()
    };
    if head.get(..HEADER_SIZE) != Some(&hdr[..]) {
        // The front header parses but is not in canonical form: leave it to the
        // in-memory path.
        return Ok(None);
    }
    let front_canonical = head.get(..lead_bytes.len()) == Some(&lead_bytes[..]);
    let lead = (if h.ember() { HEADER_SIZE } else { 0 } + vow_len) as u64;
    let stride = header::shard_stride(&h) as u64;
    let Some(body_end) = (n as u64)
        .checked_mul(stride)
        .and_then(|b| b.checked_add(prefix as u64))
    else {
        return Ok(None);
    };
    let spare = header::write_sgto_spare(sgto.as_deref()).unwrap_or_default();
    let trailer = if h.keystone() {
        header::write_keystone_trailer(&hdr)
    } else {
        Vec::new()
    };
    let tail_len = len.checked_sub(body_end);
    let full = (spare.len() + trailer.len()) as u64;
    let trailer_missing = match tail_len {
        Some(t) if t == full => false,
        Some(t) if h.keystone() && t == spare.len() as u64 => true,
        _ => return Ok(None),
    };
    let mut tail = vec![0u8; tail_len.unwrap_or(0) as usize];
    src.read_at(body_end, &mut tail)?;
    let mut want = spare;
    if !trailer_missing {
        want.extend_from_slice(&trailer);
    }
    if tail != want {
        return Ok(None);
    }
    // `ensure_single_seal` would refuse a lone pack star; leave that to the in-memory path.
    let end = body_end + want.len() as u64
        - if trailer_missing {
            0
        } else {
            trailer.len() as u64
        };
    if header::framed_as_pack_star(&head, end as usize) {
        return Ok(None);
    }
    let l = Layout {
        h,
        hdr,
        front_canonical,
        prefix: prefix as u64,
        lead,
        stride,
        sl,
        n,
        k,
        sgto,
        vow,
        file_len: len,
    };
    // Every Ember (and the Vow after it) must be exactly where the header puts it.
    let mut buf = vec![0u8; l.lead as usize];
    for i in 0..n {
        crate::repair_ctl::check()?;
        src.read_at(l.prefix + i as u64 * stride, &mut buf)?;
        let mut pos = 0;
        if l.h.ember() {
            if buf[..HEADER_SIZE] != header::write_ember(&l.hdr, i as u8)[..] {
                return Ok(None);
            }
            pos = HEADER_SIZE;
        }
        if let Some(v) = &l.vow {
            if buf[pos..pos + VOW_SIZE] != v[..] {
                return Ok(None);
            }
        }
    }
    Ok(Some(l))
}

/// Is `input` a classic seal whose framing [`probe`] accepts?
pub(crate) fn is_clean(input: &Path) -> Result<bool> {
    let mut src = FileSrc::open(input)?;
    Ok(probe(&mut src)?.is_some())
}

/// CRC result and SHA-256 of every part as it sits in the file.
pub(crate) struct Parts {
    pub crc_ok: Vec<bool>,
    pub sha: Vec<[u8; 32]>,
}

impl Parts {
    pub fn live(&self) -> usize {
        self.crc_ok.iter().filter(|&&b| b).count()
    }
}

/// Check every part's CRC (and hash it), one window at a time.
pub(crate) fn scan_parts(src: &mut FileSrc, l: &Layout) -> Result<Parts> {
    let mut buf = vec![0u8; (l.sl.min(IO_WINDOW as u64)) as usize];
    let mut crc_ok = Vec::with_capacity(l.n);
    let mut sha = Vec::with_capacity(l.n);
    for i in 0..l.n {
        let off = l.shard_off(i);
        let mut crc = crc32fast::Hasher::new();
        let mut hs = Sha256::new();
        let mut done = 0u64;
        while done < l.sl {
            crate::repair_ctl::check()?;
            let t = (l.sl - done).min(buf.len() as u64) as usize;
            src.read_at(off + done, &mut buf[..t])?;
            crc.update(&buf[..t]);
            hs.update(&buf[..t]);
            done += t as u64;
        }
        let mut stored = [0u8; 4];
        src.read_at(off + l.sl, &mut stored)?;
        crc_ok.push(crc.finalize() == u32::from_le_bytes(stored));
        sha.push(hs.finalize().into());
    }
    Ok(Parts { crc_ok, sha })
}

/// Longest run of one repeated byte in part `i` (the "wiped" hint of the repair scan).
fn longest_run(src: &mut FileSrc, l: &Layout, i: usize) -> Result<usize> {
    let mut buf = vec![0u8; (l.sl.min(IO_WINDOW as u64)) as usize];
    let (mut best, mut cur, mut prev) = (0usize, 0usize, None::<u8>);
    let mut done = 0u64;
    while done < l.sl {
        crate::repair_ctl::check()?;
        let t = (l.sl - done).min(buf.len() as u64) as usize;
        src.read_at(l.shard_off(i) + done, &mut buf[..t])?;
        for &x in &buf[..t] {
            if Some(x) == prev {
                cur += 1;
            } else {
                cur = 1;
                prev = Some(x);
            }
            best = best.max(cur);
        }
        done += t as u64;
    }
    Ok(best)
}

// ---------------------------------------------------------------------------------------
// The payload (folded / encrypted bytes), in place or rebuilt into a scratch file
// ---------------------------------------------------------------------------------------

/// The seal's payload (`folded_len` bytes: the data parts in order), read a window at a time.
pub(crate) enum Payload {
    /// Every data part passed its CRC: read straight from the seal.
    InPlace,
    /// Rebuilt from parity into a private scratch file (removed when dropped).
    Spool {
        /// Keeps the scratch file until the payload is dropped.
        _file: SpoolFile,
        src: FileSrc,
    },
}

/// A private scratch file beside the output, or in the temp folder when that folder cannot
/// take one (a read-only input folder, for example). Removed when dropped.
pub(crate) enum SpoolFile {
    Beside(crate::folder::Scratch),
    Temp(crate::staging::TempFile),
}

impl SpoolFile {
    fn create(beside: &Path, tag: &str) -> Result<(Self, File)> {
        let path = crate::folder::scratch_beside(beside, tag);
        match crate::staging::create_private(&path) {
            Ok(f) => Ok((SpoolFile::Beside(crate::folder::Scratch(path)), f)),
            Err(_) => {
                let t = crate::staging::TempFile::reserve(tag)?;
                let f = std::fs::OpenOptions::new()
                    .write(true)
                    .open(t.path())
                    .map_err(io)?;
                Ok((SpoolFile::Temp(t), f))
            }
        }
    }
    fn path(&self) -> &Path {
        match self {
            SpoolFile::Beside(s) => &s.0,
            SpoolFile::Temp(t) => t.path(),
        }
    }
}

impl Payload {
    fn read_at(&mut self, src: &mut FileSrc, l: &Layout, off: u64, buf: &mut [u8]) -> Result<()> {
        match self {
            Payload::Spool { src: f, .. } => f.read_at(off, buf),
            Payload::InPlace => {
                if off
                    .checked_add(buf.len() as u64)
                    .is_none_or(|e| e > l.h.folded_len)
                {
                    return Err(msg("read past the end of the payload"));
                }
                let mut done = 0usize;
                while done < buf.len() {
                    let o = off + done as u64;
                    let part = (o / l.sl) as usize;
                    let within = o % l.sl;
                    let t = ((l.sl - within) as usize).min(buf.len() - done);
                    src.read_at(l.shard_off(part) + within, &mut buf[done..done + t])?;
                    done += t;
                }
                Ok(())
            }
        }
    }

    /// Bytes `[off, off + buf.len())` of data part `d` as the encoder sees it: the payload,
    /// zero past `folded_len`.
    fn read_data_window(
        &mut self,
        src: &mut FileSrc,
        l: &Layout,
        d: usize,
        col: u64,
        buf: &mut [u8],
    ) -> Result<()> {
        let start = d as u64 * l.sl + col;
        let have = l.h.folded_len.saturating_sub(start).min(buf.len() as u64) as usize;
        buf[have..].fill(0);
        if have > 0 {
            self.read_at(src, l, start, &mut buf[..have])?;
        }
        Ok(())
    }
}

/// The payload from the parts that passed their CRC. `beside` names where a rebuilt payload
/// is spooled (a hidden 0600 file next to it). Errors match the in-memory decoders.
pub(crate) fn payload(
    src: &mut FileSrc,
    l: &Layout,
    parts: &Parts,
    beside: &Path,
) -> Result<Payload> {
    let k = l.data_parts();
    if parts.crc_ok[..k].iter().all(|&b| b) {
        return Ok(Payload::InPlace);
    }
    if l.h.mode() == Mode::Glyph {
        return Err(msg("glyph: missing shard"));
    }
    let live: Vec<usize> = (0..l.n).filter(|&i| parts.crc_ok[i]).collect();
    if live.len() < k {
        return Err(msg(format!("need {k} pieces, have {}", live.len())));
    }
    // The in-memory decoder uses the first k distinct parts (n <= 255, so all distinct).
    let rows: Vec<usize> = live[..k].to_vec();
    let xs: Vec<u8> = rows.iter().map(|&i| rs::x_of(i)).collect();
    let m = rs::decode_matrix(&xs, true)?;
    let (scratch, mut f) = SpoolFile::create(beside, "classic-spool")?;
    let w = col_window(2 * k, l.sl);
    let mut ins = vec![vec![0u8; w]; k];
    let mut outs = vec![vec![0u8; w]; k];
    let folded = l.h.folded_len;
    let mut col = 0u64;
    while col < l.sl {
        crate::repair_ctl::check()?;
        let t = (l.sl - col).min(w as u64) as usize;
        for (j, &r) in rows.iter().enumerate() {
            src.read_at(l.shard_off(r) + col, &mut ins[j][..t])?;
        }
        {
            let inr: Vec<&[u8]> = ins.iter().map(|v| &v[..t]).collect();
            let mut outr: Vec<&mut [u8]> = outs.iter_mut().map(|v| &mut v[..t]).collect();
            gf::matrix_apply(&m, &inr, &mut outr);
        }
        for (d, out) in outs.iter().enumerate() {
            let start = d as u64 * l.sl + col;
            let have = folded.saturating_sub(start).min(t as u64) as usize;
            if have > 0 {
                f.seek(SeekFrom::Start(start)).map_err(io)?;
                f.write_all(&out[..have]).map_err(io)?;
            }
        }
        col += t as u64;
    }
    f.set_len(folded).map_err(io)?;
    f.sync_data().map_err(io)?;
    drop(f);
    let fs = FileSrc::open(scratch.path())?;
    Ok(Payload::Spool {
        _file: scratch,
        src: fs,
    })
}

/// Re-encode every part from the payload, a column window at a time, and return each
/// part's SHA-256. `each(part, column, bytes)` sees every window of every part in column
/// order (used to write a mended copy). Same bytes as `MdsBackend::encode` / `rs::stripe`.
fn reencode(
    src: &mut FileSrc,
    l: &Layout,
    p: &mut Payload,
    parity: &[u8],
    mut each: impl FnMut(usize, u64, &[u8]) -> Result<()>,
) -> Result<Vec<[u8; 32]>> {
    let k = l.data_parts();
    let m = l.n - k;
    let w = col_window(l.n, l.sl);
    let mut ins = vec![vec![0u8; w]; k];
    let mut outs = vec![vec![0u8; w]; m];
    let mut hs: Vec<Sha256> = (0..l.n).map(|_| Sha256::new()).collect();
    let mut col = 0u64;
    while col < l.sl {
        crate::repair_ctl::check()?;
        let t = (l.sl - col).min(w as u64) as usize;
        for (d, buf) in ins.iter_mut().enumerate() {
            p.read_data_window(src, l, d, col, &mut buf[..t])?;
        }
        if m > 0 {
            let inr: Vec<&[u8]> = ins.iter().map(|v| &v[..t]).collect();
            let mut outr: Vec<&mut [u8]> = outs.iter_mut().map(|v| &mut v[..t]).collect();
            gf::matrix_apply(parity, &inr, &mut outr);
        }
        for (i, h) in hs.iter_mut().enumerate() {
            let b = if i < k {
                &ins[i][..t]
            } else {
                &outs[i - k][..t]
            };
            h.update(b);
            each(i, col, b)?;
        }
        col += t as u64;
    }
    Ok(hs.into_iter().map(|h| h.finalize().into()).collect())
}

fn parity_for(l: &Layout, mds_be: &dyn mds::MdsBackend) -> Result<Vec<u8>> {
    if l.h.mode() == Mode::Glyph {
        Ok(Vec::new())
    } else {
        mds_be.parity_matrix(l.k, l.n)
    }
}

// ---------------------------------------------------------------------------------------
// AES-256-GCM in two passes
// ---------------------------------------------------------------------------------------

struct Gcm {
    key: zeroize::Zeroizing<[u8; 32]>,
    nonce: [u8; 12],
}

impl Gcm {
    fn block(&self, b: &mut [u8; 16]) {
        let c = aes::Aes256::new(GenericArray::from_slice(&self.key[..]));
        c.encrypt_block(GenericArray::from_mut_slice(&mut b[..]));
    }
    fn ghash(&self, aad: &[u8]) -> Ghash {
        let mut h = [0u8; 16];
        self.block(&mut h);
        let mut g = ghash::GHash::new(GenericArray::from_slice(&h));
        g.update_padded(aad);
        Ghash {
            g,
            carry: [0u8; 16],
            have: 0,
            aad_len: aad.len() as u64,
            len: 0,
        }
    }
    /// The tag mask E(K, J0).
    fn mask(&self) -> [u8; 16] {
        let mut j0 = [0u8; 16];
        j0[..12].copy_from_slice(&self.nonce);
        j0[15] = 1;
        self.block(&mut j0);
        j0
    }
    /// The payload keystream (counter J0 + 1 onward), positioned at byte `at`.
    fn ctr(&self, at: u64) -> Result<Ctr> {
        let mut iv = [0u8; 16];
        iv[..12].copy_from_slice(&self.nonce);
        iv[15] = 2;
        let mut c = Ctr::new(
            GenericArray::from_slice(&self.key[..]),
            GenericArray::from_slice(&iv),
        );
        c.try_seek(at)
            .map_err(|_| msg("AES-GCM: message too long"))?;
        Ok(c)
    }
}

struct Ghash {
    g: ghash::GHash,
    carry: [u8; 16],
    have: usize,
    aad_len: u64,
    len: u64,
}

impl Ghash {
    fn update(&mut self, mut d: &[u8]) {
        self.len += d.len() as u64;
        if self.have > 0 {
            let t = (16 - self.have).min(d.len());
            self.carry[self.have..self.have + t].copy_from_slice(&d[..t]);
            self.have += t;
            d = &d[t..];
            if self.have < 16 {
                return;
            }
            self.g.update_padded(&self.carry);
            self.have = 0;
        }
        let full = d.len() - d.len() % 16;
        if full > 0 {
            self.g.update_padded(&d[..full]);
        }
        let rest = &d[full..];
        self.carry[..rest.len()].copy_from_slice(rest);
        self.have = rest.len();
    }
    fn tag(mut self, mask: &[u8; 16]) -> [u8; 16] {
        if self.have > 0 {
            self.g.update_padded(&self.carry[..self.have]);
        }
        let mut b = [0u8; 16];
        b[..8].copy_from_slice(&(self.aad_len * 8).to_be_bytes());
        b[8..].copy_from_slice(&(self.len * 8).to_be_bytes());
        self.g.update_padded(&b);
        let t = self.g.finalize();
        let mut out = [0u8; 16];
        for (o, (a, m)) in out.iter_mut().zip(t.iter().zip(mask)) {
            *o = a ^ m;
        }
        out
    }
}

fn ct_eq16(a: &[u8; 16], b: &[u8; 16]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

// ---------------------------------------------------------------------------------------
// Opening
// ---------------------------------------------------------------------------------------

/// What a streamed open found.
pub(crate) struct Opened {
    /// Plain bytes written.
    pub len: u64,
}

/// The decrypted (when encrypted) and unfolded bytes of payload range `[pos, end)`.
struct BodyReader<'a> {
    src: &'a mut FileSrc,
    l: &'a Layout,
    p: &'a mut Payload,
    pos: u64,
    end: u64,
    ctr: Option<Ctr>,
    unfold: chaos::Unfolder,
    raw: zeroize::Zeroizing<Vec<u8>>,
    buf: zeroize::Zeroizing<Vec<u8>>,
    at: usize,
}

impl Read for BodyReader<'_> {
    fn read(&mut self, out: &mut [u8]) -> std::io::Result<usize> {
        if self.at == self.buf.len() {
            if self.pos >= self.end {
                return Ok(0);
            }
            crate::repair_ctl::check().map_err(std::io::Error::other)?;
            let t = (self.end - self.pos).min(IO_WINDOW as u64) as usize;
            self.raw.resize(t, 0);
            self.p
                .read_at(self.src, self.l, self.pos, &mut self.raw[..t])
                .map_err(std::io::Error::other)?;
            if let Some(c) = &mut self.ctr {
                c.try_apply_keystream(&mut self.raw[..t])
                    .map_err(|_| std::io::Error::other("AES-GCM: message too long"))?;
            }
            self.unfold.feed(&self.raw[..t], &mut self.buf);
            self.pos += t as u64;
            self.at = 0;
        }
        let m = (self.buf.len() - self.at).min(out.len());
        out[..m].copy_from_slice(&self.buf[self.at..self.at + m]);
        self.at += m;
        Ok(m)
    }
}

/// Plain bytes on their way out: hashed, counted, capped.
struct Sink<'w, W: Write> {
    w: &'w mut W,
    sha: Sha256,
    mac: Option<HmacSha256>,
    n: u64,
}

impl<W: Write> Sink<'_, W> {
    fn put(&mut self, b: &[u8]) -> Result<()> {
        self.sha.update(b);
        if let Some(m) = &mut self.mac {
            m.update(b);
        }
        self.n += b.len() as u64;
        self.w.write_all(b).map_err(io)
    }
}

/// Copy the plain bytes (inflating if `compressed`) to `sink`, refusing more than `want`
/// bytes the same way the in-memory `inflate` does ("length mismatch").
fn pump<W: Write>(
    body: BodyReader<'_>,
    compressed: bool,
    want: u64,
    sink: &mut Sink<'_, W>,
) -> Result<()> {
    let mut chunk = zeroize::Zeroizing::new(vec![0u8; 64 * 1024]);
    let mut rd: Box<dyn Read + '_> = if compressed {
        Box::new(flate2::read::DeflateDecoder::new(body).take(want.saturating_add(1)))
    } else {
        Box::new(body)
    };
    loop {
        let r = rd.read(&mut chunk[..]).map_err(io)?;
        if r == 0 {
            break;
        }
        if sink.n + r as u64 > want {
            return Err(msg("length mismatch"));
        }
        sink.put(&chunk[..r])?;
    }
    if sink.n != want {
        return Err(msg("length mismatch"));
    }
    Ok(())
}

/// Open the classic seal at `input` into `out` without holding it in memory, with the same
/// checks and errors as `unseal_meta`. `Ok(None)`: not a clean classic layout (or an MDS
/// backend without a column matrix); the caller uses the in-memory path. When
/// `verify_first`, the whole plaintext is checked (into a sink) before any byte reaches
/// `out` (for outputs that cannot be taken back, like stdout).
// Justification: the same independent options `unseal_meta` takes, plus the two stream ones.
#[allow(clippy::too_many_arguments)]
pub(crate) fn open<W: Write>(
    input: &Path,
    out: &mut W,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    mds_be: &dyn mds::MdsBackend,
    identities: &[keys::Identity],
    beside: &Path,
    verify_first: bool,
) -> Result<Option<Opened>> {
    crate::refuse_empty_open_pass(pass)?;
    let mut src = FileSrc::open(input)?;
    let Some(l) = probe(&mut src)? else {
        return Ok(None);
    };
    if mds_be.name() != "vandermonde" {
        return Ok(None);
    }
    let h = &l.h;
    if let Some(v) = &l.vow {
        if let Some((_, need)) = header::read_vow(v) {
            let have: Vec<[u8; 32]> = companions.iter().map(|c| crate::sha256(c)).collect();
            for n in &need {
                if !have.iter().any(|hsh| hsh == n) {
                    return Err(msg("Geas not met — companion missing or changed."));
                }
            }
        }
    }
    if h.private_label() && !h.encrypted() {
        return Err(msg("v3 label on an unencrypted seal; refusing"));
    }
    if h.private_label() && h.entropy_milli & 0x00FF_FFFF != 0 {
        return Err(msg("v3 label carries an outer entropy score; refusing"));
    }
    let parts = scan_parts(&mut src, &l)?;
    let mut p = payload(&mut src, &l, &parts, beside)?;
    let pz = pass.unwrap_or("").trim();
    let mut gcm: Option<Gcm> = None;
    if h.encrypted() {
        let key: zeroize::Zeroizing<[u8; 32]> = if let Some(block) = &l.sgto {
            match keys::unwrap_cek(block, identities, pass.filter(|s| !s.is_empty()), &h.salt) {
                Ok(cek) => zeroize::Zeroizing::new(cek),
                Err(e) => {
                    if identities.is_empty() && pz.is_empty() {
                        return Err(msg(format!(
                            "{} — this Sigil Archive is Warded",
                            crate::KEY_REQUIRED
                        )));
                    }
                    return Err(e);
                }
            }
        } else if h.private_label() {
            return Err(msg("v3 seal has no key wrap (SGTO) left (front copy and any tail spare are damaged); past repair"));
        } else {
            if pz.is_empty() {
                if !identities.is_empty() {
                    return Err(msg(crate::NO_RECIPIENTS));
                }
                return Err(msg(format!(
                    "{} — this Sigil Archive is Warded",
                    crate::KEY_REQUIRED
                )));
            }
            zeroize::Zeroizing::new(crate::derive_key(pz, &h.salt))
        };
        if h.private_label() {
            // The Merkle root is computed after encryption, so GCM cannot cover it:
            // re-encode the ciphertext and require the label's root.
            let parity = parity_for(&l, mds_be)?;
            let leaves = reencode(&mut src, &l, &mut p, &parity, |_, _, _| Ok(()))?;
            if merkle::merkle_root(&leaves) != h.merkle {
                return Err(msg(
                    "label does not match the parts (Merkle root); refusing",
                ));
            }
        }
        let g = Gcm {
            key,
            nonce: h.nonce,
        };
        let aad = if h.private_label() {
            privacy::label_aad(&header::write_header(h))?
        } else {
            Vec::new()
        };
        if h.folded_len > GCM_C_MAX {
            return Err(msg(crate::LEGACY_OPEN_FAILED));
        }
        // Pass 1: the tag over the whole ciphertext, before anything is decrypted.
        let mut gh = g.ghash(&aad);
        let mut buf = vec![0u8; IO_WINDOW];
        let mut pos = 0u64;
        while pos < h.folded_len {
            crate::repair_ctl::check()?;
            let t = (h.folded_len - pos).min(IO_WINDOW as u64) as usize;
            p.read_at(&mut src, &l, pos, &mut buf[..t])?;
            gh.update(&buf[..t]);
            pos += t as u64;
        }
        if !ct_eq16(&gh.tag(&g.mask()), &h.tag) {
            return Err(msg(crate::LEGACY_OPEN_FAILED));
        }
        gcm = Some(g);
    } else if !pz.is_empty() {
        return Err(msg("seal was not encrypted"));
    }
    // Pass 2 (and 3 when `verify_first`): decrypt, unfold, inflate, check.
    if verify_first {
        plain_pass(&mut src, &l, &mut p, gcm.as_ref(), &mut std::io::sink())?;
    }
    plain_pass(&mut src, &l, &mut p, gcm.as_ref(), out).map(Some)
}

fn plain_pass<W: Write>(
    src: &mut FileSrc,
    l: &Layout,
    p: &mut Payload,
    gcm: Option<&Gcm>,
    out: &mut W,
) -> Result<Opened> {
    let h = &l.h;
    let total = h.folded_len;
    if h.private_label() {
        let g = gcm.ok_or_else(|| msg("no key"))?;
        // The inner block: at most INNER_FIXED + 65535 bytes.
        let head_len = total.min((privacy::INNER_FIXED + 65535) as u64) as usize;
        let mut head = zeroize::Zeroizing::new(vec![0u8; head_len]);
        p.read_at(src, l, 0, &mut head[..])?;
        g.ctr(0)?
            .try_apply_keystream(&mut head[..])
            .map_err(|_| msg("AES-GCM: message too long"))?;
        let (meta, body_off) = privacy::read_inner_head(&head, total)?;
        drop(head);
        let body_end = body_off as u64 + meta.body_len;
        // Padding must be zero (checked before the body, as `read_inner` does).
        let mut c = g.ctr(body_end)?;
        let mut buf = zeroize::Zeroizing::new(vec![0u8; IO_WINDOW]);
        let mut pos = body_end;
        while pos < total {
            crate::repair_ctl::check()?;
            let t = (total - pos).min(IO_WINDOW as u64) as usize;
            p.read_at(src, l, pos, &mut buf[..t])?;
            c.try_apply_keystream(&mut buf[..t])
                .map_err(|_| msg("AES-GCM: message too long"))?;
            if buf[..t].iter().any(|&b| b != 0) {
                return Err(msg(format!("private label: {}", privacy::PADDING_NOT_ZERO)));
            }
            pos += t as u64;
        }
        drop(buf);
        if !meta.compressed && meta.body_len != meta.orig_len {
            return Err(msg("length mismatch"));
        }
        let mac = if meta.shared_fingerprint {
            None
        } else {
            let fk = privacy::fingerprint_key(&g.key, &h.salt, &privacy::FingerprintKey::PerFile)?;
            Some(<HmacSha256 as Mac>::new_from_slice(&fk).map_err(|_| msg("HMAC key rejected"))?)
        };
        let mut sink = Sink {
            w: out,
            sha: Sha256::new(),
            mac,
            n: 0,
        };
        let ctr = Some(g.ctr(body_off as u64)?);
        let unfold = chaos::Unfolder::new(&h.salt);
        let body = BodyReader {
            src,
            l,
            p,
            pos: body_off as u64,
            end: body_end,
            ctr,
            unfold,
            raw: zeroize::Zeroizing::new(Vec::new()),
            buf: zeroize::Zeroizing::new(Vec::new()),
            at: 0,
        };
        pump(body, meta.compressed, meta.orig_len, &mut sink)?;
        let digest: [u8; 32] = sink.sha.finalize().into();
        if digest != meta.digest {
            return Err(msg("SHA-256 mismatch"));
        }
        if let Some(m) = sink.mac {
            let fp: [u8; 32] = m.finalize().into_bytes().into();
            if fp != h.digest {
                return Err(msg("keyed fingerprint mismatch"));
            }
        }
        sink.w.flush().map_err(io)?;
        return Ok(Opened { len: sink.n });
    }
    if !h.compressed() && total != h.orig_len {
        return Err(msg("length mismatch"));
    }
    let mut sink = Sink {
        w: out,
        sha: Sha256::new(),
        mac: None,
        n: 0,
    };
    let ctr = gcm.map(|g| g.ctr(0)).transpose()?;
    let unfold = chaos::Unfolder::new(&h.salt);
    let body = BodyReader {
        src,
        l,
        p,
        pos: 0,
        end: total,
        ctr,
        unfold,
        raw: zeroize::Zeroizing::new(Vec::new()),
        buf: zeroize::Zeroizing::new(Vec::new()),
        at: 0,
    };
    pump(body, h.compressed(), h.orig_len, &mut sink)?;
    let digest: [u8; 32] = sink.sha.finalize().into();
    if digest != h.digest {
        return Err(msg("SHA-256 mismatch"));
    }
    sink.w.flush().map_err(io)?;
    Ok(Opened { len: sink.n })
}

// ---------------------------------------------------------------------------------------
// Writing parts into an output file
// ---------------------------------------------------------------------------------------

fn write_at(f: &mut File, off: u64, b: &[u8]) -> Result<()> {
    f.seek(SeekFrom::Start(off)).map_err(io)?;
    f.write_all(b).map_err(io)
}

fn read_at(f: &mut File, off: u64, b: &mut [u8]) -> Result<()> {
    f.seek(SeekFrom::Start(off)).map_err(io)?;
    f.read_exact(b).map_err(io)
}

/// Where the parts of a seal being written go, and their running CRC-32 / SHA-256.
struct PartWriter {
    prefix: u64,
    lead: u64,
    stride: u64,
    sl: u64,
    crc: Vec<crc32fast::Hasher>,
    sha: Vec<Sha256>,
    /// Data bytes written so far (sequential writes into the data parts).
    pos: u64,
}

impl PartWriter {
    fn new(prefix: u64, lead: u64, sl: u64, n: usize) -> Self {
        PartWriter {
            prefix,
            lead,
            stride: lead + sl + 4,
            sl,
            crc: (0..n).map(|_| crc32fast::Hasher::new()).collect(),
            sha: (0..n).map(|_| Sha256::new()).collect(),
            pos: 0,
        }
    }
    fn shard_off(&self, i: usize) -> u64 {
        self.prefix + i as u64 * self.stride + self.lead
    }
    /// Append to the data parts, in order.
    fn put(&mut self, f: &mut File, mut b: &[u8]) -> Result<()> {
        while !b.is_empty() {
            let part = (self.pos / self.sl) as usize;
            let within = self.pos % self.sl;
            let t = ((self.sl - within) as usize).min(b.len());
            let (crc, sha) = match (self.crc.get_mut(part), self.sha.get_mut(part)) {
                (Some(c), Some(s)) => (c, s),
                _ => return Err(msg("internal: payload runs past the data parts")),
            };
            crc.update(&b[..t]);
            sha.update(&b[..t]);
            write_at(f, self.shard_off(part) + within, &b[..t])?;
            self.pos += t as u64;
            b = &b[t..];
        }
        Ok(())
    }
    /// Write window `col` of part `i` (parity, or a mended part), column order per part.
    fn put_window(&mut self, f: &mut File, i: usize, col: u64, b: &[u8]) -> Result<()> {
        if let (Some(c), Some(s)) = (self.crc.get_mut(i), self.sha.get_mut(i)) {
            c.update(b);
            s.update(b);
        }
        write_at(f, self.shard_off(i) + col, b)
    }
    /// Finish: each part's CRC-32 and SHA-256 (Merkle leaves).
    fn finish(&mut self) -> (Vec<u32>, Vec<[u8; 32]>) {
        (
            std::mem::take(&mut self.crc)
                .into_iter()
                .map(|c| c.finalize())
                .collect(),
            std::mem::take(&mut self.sha)
                .into_iter()
                .map(|s| s.finalize().into())
                .collect(),
        )
    }
}

/// Write the framing around parts already in place: Keystone (or header), key wrap, Vow,
/// every Ember + Vow + CRC, the key-wrap spare and (when `trailer`) the Keystone trailer.
/// Same bytes as `assemble` / `assemble_mark`. Returns the file length.
// Justification: each argument is one independent piece of the frame.
#[allow(clippy::too_many_arguments)]
fn write_frame(
    f: &mut File,
    hdr: &[u8],
    keystone: bool,
    ember: bool,
    sgto: Option<&[u8]>,
    vow: Option<&[u8]>,
    pw: &PartWriter,
    crcs: &[u32],
) -> Result<u64> {
    let front = if keystone {
        header::wrap_keystone(hdr)
    } else {
        hdr.to_vec()
    };
    let mut pos = 0u64;
    write_at(f, pos, &front)?;
    pos += front.len() as u64;
    if let Some(s) = sgto {
        write_at(f, pos, s)?;
        pos += s.len() as u64;
    }
    if let Some(v) = vow {
        write_at(f, pos, v)?;
    }
    for (i, c) in crcs.iter().enumerate() {
        crate::repair_ctl::check()?;
        let mut at = pw.prefix + i as u64 * pw.stride;
        if ember {
            write_at(f, at, &header::write_ember(hdr, i as u8))?;
            at += HEADER_SIZE as u64;
        }
        if let Some(v) = vow {
            write_at(f, at, v)?;
        }
        write_at(f, pw.shard_off(i) + pw.sl, &c.to_le_bytes())?;
    }
    let mut end = pw.prefix + crcs.len() as u64 * pw.stride;
    if let Some(spare) = header::write_sgto_spare(sgto) {
        write_at(f, end, &spare)?;
        end += spare.len() as u64;
    }
    if keystone {
        let t = header::write_keystone_trailer(hdr);
        write_at(f, end, &t)?;
        end += t.len() as u64;
    }
    f.set_len(end).map_err(io)?;
    Ok(end)
}

/// Removes a part file unless it was kept.
struct PartFile {
    path: PathBuf,
    keep: bool,
}

impl Drop for PartFile {
    fn drop(&mut self) {
        if !self.keep {
            let _ = std::fs::remove_file(&self.path);
        }
    }
}

// ---------------------------------------------------------------------------------------
// Sealing
// ---------------------------------------------------------------------------------------

/// A throwaway-key AES-CTR stream: scratch bytes are never plaintext on disk.
fn scratch_cipher() -> Result<(Ctr128, zeroize::Zeroizing<[u8; 48]>)> {
    let mut k = zeroize::Zeroizing::new([0u8; 48]);
    getrandom::getrandom(&mut k[..]).map_err(|e| msg(format!("random key: {e}")))?;
    let c = Ctr128::new(
        GenericArray::from_slice(&k[..32]),
        GenericArray::from_slice(&k[32..]),
    );
    Ok((c, k))
}

type Ctr128 = ctr::Ctr128BE<aes::Aes256>;

/// Deflate output, encrypted with a throwaway key, counted.
struct SpoolWriter {
    f: std::io::BufWriter<File>,
    c: Ctr128,
    n: u64,
    buf: Vec<u8>,
}

impl Write for SpoolWriter {
    fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
        self.buf.clear();
        self.buf.extend_from_slice(b);
        self.c.apply_keystream(&mut self.buf);
        self.f.write_all(&self.buf)?;
        self.n += b.len() as u64;
        Ok(b.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        self.f.flush()
    }
}

/// What one read of the input gave.
struct InputPass {
    digest: [u8; 32],
    counts: [u64; 256],
    len: u64,
    keyed: Option<[u8; 32]>,
    /// The deflated body (scratch file, its throwaway key, its length), when deflate made
    /// it smaller; `None`: the body is the input itself.
    deflated: Option<(SpoolFile, zeroize::Zeroizing<[u8; 48]>, u64)>,
}

/// Read the input once: SHA-256, byte counts, keyed fingerprint and (from 24 bytes up, as
/// `maybe_deflate`) the deflate stream into a scratch file beside `output`.
fn read_input(input: &Path, fp_key: Option<&[u8; 32]>, output: &Path) -> Result<InputPass> {
    let mut f = File::open(input).map_err(io)?;
    let len = f.metadata().map_err(io)?.len();
    let mut sha = Sha256::new();
    let mut counts = [0u64; 256];
    let mut mac = match fp_key {
        Some(k) => {
            Some(<HmacSha256 as Mac>::new_from_slice(k).map_err(|_| msg("HMAC key rejected"))?)
        }
        None => None,
    };
    let mut enc = None;
    let mut spool = None;
    let mut key = None;
    if len >= 24 {
        let (sc, file) = SpoolFile::create(output, "classic-deflate")?;
        let (c, k) = scratch_cipher()?;
        enc = Some(flate2::write::DeflateEncoder::new(
            SpoolWriter {
                f: std::io::BufWriter::new(file),
                c,
                n: 0,
                buf: Vec::new(),
            },
            flate2::Compression::default(),
        ));
        spool = Some(sc);
        key = Some(k);
    }
    let mut buf = zeroize::Zeroizing::new(vec![0u8; IO_WINDOW]);
    let mut total = 0u64;
    loop {
        crate::repair_ctl::check()?;
        let r = match f.read(&mut buf[..]) {
            Ok(0) => break,
            Ok(r) => r,
            Err(e) if e.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(e) => return Err(io(e)),
        };
        let b = &buf[..r];
        total += r as u64;
        if total > len {
            break;
        }
        sha.update(b);
        for &x in b {
            counts[x as usize] += 1;
        }
        if let Some(m) = &mut mac {
            m.update(b);
        }
        if let Some(e) = &mut enc {
            e.write_all(b).map_err(io)?;
            // Already no smaller than the input: deflate will not be used.
            if e.get_ref().n >= len {
                enc = None;
                spool = None;
            }
        }
    }
    if total != len {
        return Err(msg(
            "the input changed size while it was being sealed; nothing was written",
        ));
    }
    let mut deflated = None;
    if let (Some(e), Some(sc), Some(k)) = (enc, spool, key) {
        let mut w = e.finish().map_err(io)?;
        w.flush().map_err(io)?;
        if w.n < len {
            deflated = Some((sc, k, w.n));
        }
    }
    Ok(InputPass {
        digest: sha.finalize().into(),
        counts,
        len,
        keyed: mac.map(|m| m.finalize().into_bytes().into()),
        deflated,
    })
}

/// The body (deflated or not) of a sealed input, read back in order. A raw body is re-read
/// from the input and its SHA-256 compared at the end, so a file that changed between the
/// two reads is refused instead of sealed wrong.
enum BodySource {
    Deflated(Box<(std::io::BufReader<File>, Ctr128)>),
    Raw(File, Sha256),
}

impl BodySource {
    fn open(input: &Path, ip: &InputPass) -> Result<Self> {
        match &ip.deflated {
            Some((sc, k, _)) => {
                let c = Ctr128::new(
                    GenericArray::from_slice(&k[..32]),
                    GenericArray::from_slice(&k[32..]),
                );
                Ok(BodySource::Deflated(Box::new((
                    std::io::BufReader::new(File::open(sc.path()).map_err(io)?),
                    c,
                ))))
            }
            None => Ok(BodySource::Raw(
                File::open(input).map_err(io)?,
                Sha256::new(),
            )),
        }
    }
    fn fill(&mut self, b: &mut [u8]) -> Result<()> {
        match self {
            BodySource::Deflated(rc) => {
                let (r, c) = &mut **rc;
                r.read_exact(b).map_err(io)?;
                c.apply_keystream(b);
            }
            BodySource::Raw(f, h) => {
                f.read_exact(b).map_err(|_| {
                    msg("the input changed while it was being sealed; nothing was written")
                })?;
                h.update(&*b);
            }
        }
        Ok(())
    }
    fn finish(self, ip: &InputPass) -> Result<()> {
        if let BodySource::Raw(_, h) = self {
            let d: [u8; 32] = h.finalize().into();
            if d != ip.digest {
                return Err(msg(
                    "the input changed while it was being sealed; nothing was written",
                ));
            }
        }
        Ok(())
    }
}

/// Seal `input` into `output` as one classic seal without holding it in memory: the same
/// bytes `seal_kn_mds_to_opts` writes for the same random draws. `Ok(None)`: this MDS
/// backend has no column matrix; use the in-memory path. Returns the input length.
// Justification: the same independent seal options `seal_kn_mds_to_opts` takes.
#[allow(clippy::too_many_arguments)]
pub(crate) fn seal(
    input: &Path,
    output: &Path,
    mode: Mode,
    pass: Option<&str>,
    name: &str,
    graph: bool,
    covenant: &str,
    geas: &[[u8; 32]],
    shards: Option<u8>,
    piece_bytes: u32,
    mds_be: &dyn mds::MdsBackend,
    recipients: &[keys::PublicIdentity],
    opts: &privacy::SealOpts,
) -> Result<Option<u64>> {
    if mds_be.parity_matrix(8, 16).is_err() {
        return Ok(None);
    }
    crate::refuse_empty_seal_pass(pass)?;
    let pass_nonempty = pass.filter(|s| !s.is_empty());
    let use_to = !recipients.is_empty() || pass_nonempty.is_some();
    if opts.pad != privacy::Pad::Off && !use_to {
        return Err(msg(
            "padding needs an encrypted seal (passphrase or encrypt-to recipients)",
        ));
    }
    let has_vow = !covenant.is_empty() || !geas.is_empty();
    let vow = has_vow.then(|| header::write_vow(covenant, geas));
    // Random draws in the in-memory order: salt, nonce, then (encrypted) the content key
    // and the key wrap. Deflate and hashing draw nothing, so they can come after.
    let mut salt = [0u8; 16];
    let mut nonce = [0u8; 12];
    if !use_to {
        let len = std::fs::metadata(input).map_err(io)?.len();
        let (k, n) = crate::choose_kn(mode, len, piece_bytes, shards);
        crate::getrandom(&mut salt);
        crate::getrandom(&mut nonce);
        let ip = read_input(input, None, output)?;
        if ip.len != len {
            return Err(msg(
                "the input changed size while it was being sealed; nothing was written",
            ));
        }
        let body_len = ip.deflated.as_ref().map_or(ip.len, |d| d.2);
        let mut flags = mode.flag();
        if ip.deflated.is_some() {
            flags |= 1;
        }
        if graph {
            flags |= 1 << 4;
        }
        flags |= header::FLAG_KEYSTONE | header::FLAG_EMBER;
        if has_vow {
            flags |= header::FLAG_VOW;
        }
        let h = Header {
            version: header::VERSION,
            flags,
            k: k as u8,
            n: n as u8,
            orig_len: ip.len,
            folded_len: body_len,
            digest: ip.digest,
            salt,
            nonce,
            tag: [0u8; 16],
            shard_len: 0,
            entropy_milli: (crate::shannon_counts(&ip.counts, ip.len) * 1000.0).round() as u32,
            name: name.to_string(),
            merkle: [0u8; 32],
        };
        write_seal(
            input,
            output,
            h,
            &ip,
            None,
            None,
            vow.as_deref(),
            mode,
            mds_be,
        )?;
        return Ok(Some(ip.len));
    }
    crate::getrandom(&mut salt);
    crate::getrandom(&mut nonce);
    let mut cek = zeroize::Zeroizing::new([0u8; 32]);
    crate::getrandom(&mut cek[..]);
    let sgto_block = keys::mark_spared(&keys::build_sgto(&cek, recipients, pass_nonempty, &salt)?)?;
    let fp_key = privacy::fingerprint_key(&cek, &salt, &opts.fingerprint)?;
    let ip = read_input(input, Some(&fp_key), output)?;
    let body_len = ip.deflated.as_ref().map_or(ip.len, |d| d.2);
    let mut meta = privacy::SealMeta {
        name: name.to_string(),
        orig_len: ip.len,
        digest: ip.digest,
        body_len,
        entropy_milli: (crate::shannon_counts(&ip.counts, ip.len) * 1000.0).round() as u32,
        compressed: ip.deflated.is_some(),
        group_total: opts.group_total,
        shared_fingerprint: matches!(opts.fingerprint, privacy::FingerprintKey::Shared(_)),
        pad_len: 0,
    };
    let inner_len = privacy::write_inner(&meta).len() as u64;
    let unpadded = inner_len + body_len;
    meta.pad_len = privacy::padded_len(unpadded, opts.pad) - unpadded;
    let inner = privacy::write_inner(&meta);
    let total = inner.len() as u64 + body_len + meta.pad_len;
    usize::try_from(meta.pad_len).map_err(|_| msg("padding too large"))?;
    let (k, n) = crate::choose_kn(mode, total, piece_bytes, shards);
    let mut flags = mode.flag() | 2;
    if graph {
        flags |= 1 << 4;
    }
    flags |= header::FLAG_KEYSTONE | header::FLAG_EMBER;
    if has_vow {
        flags |= header::FLAG_VOW;
    }
    let h = Header {
        version: privacy::PRIVATE_VERSION,
        flags,
        k: k as u8,
        n: n as u8,
        orig_len: 0,
        folded_len: total,
        digest: ip
            .keyed
            .ok_or_else(|| msg("internal: no keyed fingerprint"))?,
        salt,
        nonce,
        tag: [0u8; 16],
        shard_len: 0,
        entropy_milli: 0,
        name: String::new(),
        merkle: [0u8; 32],
    };
    let enc = Enc {
        gcm: Gcm { key: cek, nonce },
        inner,
        pad: meta.pad_len,
        sgto: sgto_block,
    };
    write_seal(
        input,
        output,
        h,
        &ip,
        Some(&enc),
        Some(&enc.sgto),
        vow.as_deref(),
        mode,
        mds_be,
    )?;
    Ok(Some(ip.len))
}

/// The encryption side of a seal being written.
struct Enc {
    gcm: Gcm,
    inner: Vec<u8>,
    pad: u64,
    sgto: Vec<u8>,
}

/// Write the payload (`[inner] | fold(body) | [zero pad]`, encrypted when `enc`), parity,
/// and framing of a classic seal into `output` (through a part file renamed at the end).
// Justification: the header, the input pass and the frame pieces are independent.
#[allow(clippy::too_many_arguments)]
fn write_seal(
    input: &Path,
    output: &Path,
    mut h: Header,
    ip: &InputPass,
    enc: Option<&Enc>,
    sgto: Option<&[u8]>,
    vow: Option<&[u8]>,
    mode: Mode,
    mds_be: &dyn mds::MdsBackend,
) -> Result<()> {
    let total = h.folded_len;
    let k = h.k as usize;
    let n = h.n as usize;
    let glyph = mode == Mode::Glyph;
    let data_parts = if glyph { n } else { k };
    if data_parts == 0 {
        return Err(msg("internal: no data parts"));
    }
    if enc.is_some() && total > GCM_P_MAX {
        return Err(msg("encrypt failed"));
    }
    let sl = total.div_ceil(data_parts as u64).max(1);
    h.shard_len = u32::try_from(sl).map_err(|_| msg("file too large for one classic seal (part length over 4 GiB); use the default large-file pack"))?;
    let parity = if glyph {
        Vec::new()
    } else {
        mds_be.parity_matrix(k, n)?
    };
    let vow_len = vow.map_or(0, <[u8]>::len) as u64;
    let prefix = KEYSTONE_SPAN as u64 + sgto.map_or(0, <[u8]>::len) as u64 + vow_len;
    let lead = HEADER_SIZE as u64 + vow_len;
    let mut pw = PartWriter::new(prefix, lead, sl, n);

    let mut part = output.as_os_str().to_os_string();
    part.push(".sigil-part");
    let mut guard = PartFile {
        path: PathBuf::from(part),
        keep: false,
    };
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(&guard.path)
        .map_err(io)?;

    // Payload: data parts, in order.
    let aad = if enc.is_some() {
        privacy::label_aad(&header::write_header(&h))?
    } else {
        Vec::new()
    };
    let mut gh = enc.map(|e| e.gcm.ghash(&aad));
    let mut ctr = enc.map(|e| e.gcm.ctr(0)).transpose()?;
    let mut emit = |pw: &mut PartWriter, f: &mut File, b: &mut [u8]| -> Result<()> {
        if let Some(c) = &mut ctr {
            c.try_apply_keystream(b)
                .map_err(|_| msg("encrypt failed"))?;
        }
        if let Some(g) = &mut gh {
            g.update(b);
        }
        pw.put(f, b)
    };
    if let Some(e) = enc {
        let mut b = e.inner.clone();
        emit(&mut pw, &mut f, &mut b)?;
    }
    let body_len = ip.deflated.as_ref().map_or(ip.len, |d| d.2);
    let mut body = BodySource::open(input, ip)?;
    let mut folder = chaos::Folder::new(&h.salt);
    let mut buf = zeroize::Zeroizing::new(vec![0u8; IO_WINDOW]);
    let mut done = 0u64;
    while done < body_len {
        crate::repair_ctl::check()?;
        let t = (body_len - done).min(IO_WINDOW as u64) as usize;
        body.fill(&mut buf[..t])?;
        folder.fold_in_place(&mut buf[..t]);
        emit(&mut pw, &mut f, &mut buf[..t])?;
        done += t as u64;
    }
    body.finish(ip)?;
    let mut pad = enc.map_or(0, |e| e.pad);
    while pad > 0 {
        crate::repair_ctl::check()?;
        let t = pad.min(IO_WINDOW as u64) as usize;
        buf[..t].fill(0);
        emit(&mut pw, &mut f, &mut buf[..t])?;
        pad -= t as u64;
    }
    drop(emit);
    // Zero padding of the last data part(s): part of the parts, not of the message.
    let mut rest = data_parts as u64 * sl - total;
    while rest > 0 {
        let t = rest.min(IO_WINDOW as u64) as usize;
        buf[..t].fill(0);
        pw.put(&mut f, &buf[..t])?;
        rest -= t as u64;
    }
    drop(buf);
    if let (Some(e), Some(g)) = (enc, gh) {
        h.tag = g.tag(&e.gcm.mask());
    }

    // Parity, a column window at a time, from the data parts just written.
    let m = n - data_parts;
    if m > 0 {
        let w = col_window(n, sl);
        let mut ins = vec![vec![0u8; w]; data_parts];
        let mut outs = vec![vec![0u8; w]; m];
        let mut col = 0u64;
        while col < sl {
            crate::repair_ctl::check()?;
            let t = (sl - col).min(w as u64) as usize;
            for (d, b) in ins.iter_mut().enumerate() {
                read_at(&mut f, pw.shard_off(d) + col, &mut b[..t])?;
            }
            {
                let inr: Vec<&[u8]> = ins.iter().map(|v| &v[..t]).collect();
                let mut outr: Vec<&mut [u8]> = outs.iter_mut().map(|v| &mut v[..t]).collect();
                gf::matrix_apply(&parity, &inr, &mut outr);
            }
            for (j, o) in outs.iter().enumerate() {
                pw.put_window(&mut f, data_parts + j, col, &o[..t])?;
            }
            col += t as u64;
        }
    }
    let (crcs, leaves) = pw.finish();
    h.merkle = merkle::merkle_root(&leaves);
    let hdr = header::write_header(&h);
    write_frame(&mut f, &hdr, true, true, sgto, vow, &pw, &crcs)?;
    f.sync_all().map_err(io)?;
    drop(f);
    std::fs::rename(&guard.path, output).map_err(io)?;
    guard.keep = true;
    Ok(())
}

// ---------------------------------------------------------------------------------------
// Mending
// ---------------------------------------------------------------------------------------

/// A classic seal laid out well enough to mend a window at a time.
pub struct MendPlan {
    src: FileSrc,
    l: Layout,
    parts: Parts,
    beside: PathBuf,
}

/// What a streamed mend wrote (the values `verify` reports on the mended copy).
pub struct MendDone {
    pub header: Header,
    pub merkle_ok: bool,
    pub live: usize,
    pub k: usize,
}

/// Look at `input` for a streamed mend: `Ok(None)` when it is not a classic seal with
/// intact framing (use the in-memory mend). Also returns the repair scan, graded exactly as
/// `repair_scan::scan_bytes` grades it.
pub fn mend_plan(
    input: &Path,
    beside: &Path,
) -> Result<Option<(MendPlan, crate::repair_scan::RepairScan)>> {
    let mut src = FileSrc::open(input)?;
    let Some(l) = probe(&mut src)? else {
        return Ok(None);
    };
    let parts = scan_parts(&mut src, &l)?;
    let mut grades = Vec::with_capacity(l.n);
    for (i, &ok) in parts.crc_ok.iter().enumerate() {
        grades.push(if ok {
            crate::repair_scan::Grade::Clean
        } else {
            let run = longest_run(&mut src, &l, i)?;
            crate::repair_scan::Grade::Damaged {
                wiped: run >= crate::repair_scan::WIPE_RUN.min(l.sl.max(1) as usize),
            }
        });
    }
    let scan = crate::repair_scan::grade_states(&l.h, &grades);
    let rep = crate::repair_scan::summarize_one(l.file_len, scan);
    Ok(Some((
        MendPlan {
            src,
            l,
            parts,
            beside: beside.to_path_buf(),
        },
        rep,
    )))
}

/// Mend the planned seal into `out` (created or truncated), with the checks and errors of
/// the quick path of `pieces::mend_bytes_ex`. `Ok(None)`: the quick repair is not enough
/// and `soft` asks for the deeper one, which runs in memory; nothing useful was written.
pub fn mend_run(plan: MendPlan, out: &Path, soft: bool) -> Result<Option<MendDone>> {
    let MendPlan {
        mut src,
        l,
        parts,
        beside,
    } = plan;
    let h = &l.h;
    let n = l.n;
    let k = l.k;
    let live = parts.live();
    let glyph = h.mode() == Mode::Glyph;
    if glyph && live < n {
        return Err(msg(format!("Glyph needs all {n} shards, have {live}")));
    }
    if !glyph && live < k {
        if soft {
            return Ok(None);
        }
        return Err(msg(format!("need {k} live shards to mend, have {live}")));
    }
    let mut f = File::create(out).map_err(io)?;
    let mut pw = PartWriter::new(l.prefix, l.lead, l.sl, n);
    let mut merkle_ok = true;
    if glyph {
        // Every part is whole: copied as is (the in-memory mend runs no check here).
        let mut buf = vec![0u8; (l.sl.min(IO_WINDOW as u64)) as usize];
        for i in 0..n {
            let mut col = 0u64;
            while col < l.sl {
                crate::repair_ctl::check()?;
                let t = (l.sl - col).min(buf.len() as u64) as usize;
                src.read_at(l.shard_off(i) + col, &mut buf[..t])?;
                pw.put_window(&mut f, i, col, &buf[..t])?;
                col += t as u64;
            }
        }
    } else {
        let mut p = payload(&mut src, &l, &parts, &beside)?;
        let parity = rs::parity_matrix(k, n)?;
        let leaves = reencode(&mut src, &l, &mut p, &parity, |i, col, b| {
            pw.put_window(&mut f, i, col, b)
        })?;
        let mut ok = merkle::merkle_root(&leaves) == h.merkle;
        if ok && !h.encrypted() {
            ok = plain_pass(&mut src, &l, &mut p, None, &mut std::io::sink()).is_ok();
        }
        if !ok {
            drop(f);
            let _ = std::fs::remove_file(out);
            if soft {
                return Ok(None);
            }
            return Err(msg("quick repair failed the true-name/Merkle check"));
        }
    }
    let (crcs, leaves) = pw.finish();
    if glyph {
        merkle_ok = merkle::merkle_root(&leaves) == h.merkle;
    }
    write_frame(
        &mut f,
        &l.hdr,
        h.keystone(),
        h.ember(),
        l.sgto.as_deref(),
        l.vow.as_deref(),
        &pw,
        &crcs,
    )?;
    f.sync_all().map_err(io)?;
    Ok(Some(MendDone {
        header: l.h.clone(),
        merkle_ok,
        live: n,
        k,
    }))
}

// ---------------------------------------------------------------------------------------
// Checking (scry)
// ---------------------------------------------------------------------------------------

/// What `crate::verify` returns: `(header, merkle_ok, live, k, recovered)`.
pub(crate) type Verified = (Header, bool, usize, usize, bool);

/// `crate::verify` for a classic seal on disk: `(header, merkle_ok, live, k, recovered)`,
/// or `Ok(None)` when the framing is not intact (use the in-memory check).
pub(crate) fn verify_path(input: &Path) -> Result<Option<Verified>> {
    let mut src = FileSrc::open(input)?;
    let Some(l) = probe(&mut src)? else {
        return Ok(None);
    };
    let parts = scan_parts(&mut src, &l)?;
    let live = parts.live();
    let merkle_ok = live == l.n && merkle::merkle_root(&parts.sha) == l.h.merkle;
    Ok(Some((l.h, merkle_ok, live, l.k, false)))
}

/// `recovery::assess_seal` for a classic seal on disk whose framing is intact and which
/// opens as is; `Ok(None)` for anything else (the in-memory assessment, with its repair
/// probe, decides).
pub(crate) fn assess_path(input: &Path) -> Result<Option<crate::recovery::Condition>> {
    use crate::recovery::Condition;
    let mut src = FileSrc::open(input)?;
    let Some(l) = probe(&mut src)? else {
        return Ok(None);
    };
    let parts = scan_parts(&mut src, &l)?;
    let (n, k) = (l.n, l.k);
    let live = parts.live();
    let merkle_ok = live == n && merkle::merkle_root(&parts.sha) == l.h.merkle;
    if live < k || !(merkle_ok || live < n) {
        return Ok(None);
    }
    if live < n || !merkle_ok {
        return Ok(Some(Condition::Torn(format!(
            "{live}/{n} shards intact (need {k})"
        ))));
    }
    // `pieces::canonical_check`: the parts are exactly a re-encode of their own payload,
    // and (plain seals) the payload names the header's plain bytes.
    if let Err(e) = reencodes_exactly(&mut src, &l) {
        return Ok(Some(Condition::Unrecoverable(format!(
            "repair check failed: {e}"
        ))));
    }
    Ok(Some(if l.front_canonical {
        Condition::Healthy
    } else {
        Condition::Torn(
            "redundant copies (shard or key-wrap spares) are damaged (data still intact)".into(),
        )
    }))
}

fn reencodes_exactly(src: &mut FileSrc, l: &Layout) -> Result<()> {
    let hard_fail = || msg("hard mend failed true-name/Merkle check (try --soft)");
    let k = l.k;
    let folded = l.h.folded_len;
    let mut buf = vec![0u8; (l.sl.min(IO_WINDOW as u64)) as usize];
    // data parts hold the payload, zero-padded past `folded`
    for i in 0..k {
        let start = (i as u64 * l.sl).min(folded);
        let used = folded.saturating_sub(start).min(l.sl);
        let mut col = used;
        while col < l.sl {
            crate::repair_ctl::check()?;
            let t = (l.sl - col).min(buf.len() as u64) as usize;
            src.read_at(l.shard_off(i) + col, &mut buf[..t])?;
            if buf[..t].iter().any(|&b| b != 0) {
                return Err(hard_fail());
            }
            col += t as u64;
        }
    }
    let mut p = Payload::InPlace;
    if l.h.mode() != Mode::Glyph {
        let parity = rs::parity_matrix(k, l.n)?;
        let mut disk = vec![0u8; col_window(l.n, l.sl)];
        let mut same = true;
        let mut f2 = src.try_clone()?;
        reencode(src, l, &mut p, &parity, |i, col, b| {
            if i >= k && same {
                f2.read_at(l.shard_off(i) + col, &mut disk[..b.len()])?;
                same = disk[..b.len()] == *b;
            }
            Ok(())
        })?;
        if !same {
            return Err(hard_fail());
        }
    }
    if !l.h.encrypted() {
        plain_pass(src, l, &mut p, None, &mut std::io::sink()).map_err(|_| hard_fail())?;
    }
    Ok(())
}
