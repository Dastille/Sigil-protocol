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
    /// The front of the file is the canonical Keystone and every Ember / Vow copy beside
    /// a part is byte-exact (nothing for a mend to rewrite but the parts themselves).
    pub front_canonical: bool,
    /// Per part: its Ember sits where the header puts it, byte-exact (the in-memory scan
    /// finds that part by its Ember; a damaged Ember leaves it to the CRC at its slot).
    pub ember_ok: Vec<bool>,
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
    /// The in-memory scan places Ember-found parts by their order, not their slot, when
    /// fewer than two distinct slots were found that way; with exactly one such part
    /// away from slot 0 it reads the seal differently from here. Leave that rare case
    /// (all but one Ember or part lost) to the in-memory path.
    fn placed_by_order(&self, parts: &Parts) -> bool {
        if !self.h.ember() {
            return false;
        }
        let mut found = (0..self.n).filter(|&i| self.ember_ok[i] && parts.crc_ok[i]);
        matches!((found.next(), found.next()), (Some(i), None) if i != 0)
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
    let mut l = Layout {
        h,
        hdr,
        front_canonical,
        ember_ok: vec![true; n],
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
    // Note which Embers (and Vows after them) are exactly where the header puts them. A
    // damaged copy does not move any part (each part sits at its slot); a mend rewrites it.
    let mut buf = vec![0u8; l.lead as usize];
    for i in 0..n {
        crate::repair_ctl::check()?;
        src.read_at(l.prefix + i as u64 * stride, &mut buf)?;
        let mut pos = 0;
        if l.h.ember() {
            if buf[..HEADER_SIZE] != header::write_ember(&l.hdr, i as u8)[..] {
                l.ember_ok[i] = false;
                l.front_canonical = false;
            }
            pos = HEADER_SIZE;
        }
        if let Some(v) = &l.vow {
            if buf[pos..pos + VOW_SIZE] != v[..] {
                l.front_canonical = false;
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
#[derive(Debug)]
pub(crate) struct Opened {
    /// Plain bytes written.
    pub len: u64,
}

/// The decrypted (when encrypted) and unfolded bytes of payload range `[pos, end)`.
/// SHA-256 of each [`IO_WINDOW`]-aligned window of the payload, taken in the pass that
/// authenticated those bytes (the GCM tag pass, or a hashing pass before a plain seal goes
/// to stdout). Later passes read whole windows and re-check each one before using a byte,
/// so a file changed between passes cannot slip other bytes into the output.
pub(crate) struct Pinned {
    sums: Vec<[u8; 32]>,
    idx: Option<u64>,
    win: zeroize::Zeroizing<Vec<u8>>,
}

/// Message when a pinned window no longer matches (the file changed under us).
const CHANGED: &str = "the archive changed while it was being opened; nothing was kept";

impl Pinned {
    fn new() -> Self {
        Pinned {
            sums: Vec::new(),
            idx: None,
            win: zeroize::Zeroizing::new(Vec::new()),
        }
    }
    /// Record the next window (windows arrive in order from offset 0).
    fn record(&mut self, b: &[u8]) {
        self.sums.push(Sha256::digest(b).into());
    }
    fn read_at(
        &mut self,
        p: &mut Payload,
        src: &mut FileSrc,
        l: &Layout,
        off: u64,
        buf: &mut [u8],
    ) -> Result<()> {
        let w = IO_WINDOW as u64;
        let mut done = 0usize;
        while done < buf.len() {
            let at = off + done as u64;
            let i = at / w;
            if self.idx != Some(i) {
                let start = i * w;
                let len = l.h.folded_len.saturating_sub(start).min(w) as usize;
                let want = self.sums.get(i as usize).ok_or_else(|| msg(CHANGED))?;
                self.idx = None;
                self.win.resize(len, 0);
                p.read_at(src, l, start, &mut self.win[..])?;
                let got: [u8; 32] = Sha256::digest(&self.win[..]).into();
                if !ct_eq32(&got, want) {
                    return Err(msg(CHANGED));
                }
                self.idx = Some(i);
            }
            let within = (at - i * w) as usize;
            let t = (self.win.len().saturating_sub(within)).min(buf.len() - done);
            if t == 0 {
                return Err(msg("read past the end of the payload"));
            }
            buf[done..done + t].copy_from_slice(&self.win[within..within + t]);
            done += t;
        }
        Ok(())
    }
}

fn ct_eq32(a: &[u8; 32], b: &[u8; 32]) -> bool {
    a.iter().zip(b).fold(0u8, |acc, (x, y)| acc | (x ^ y)) == 0
}

/// Read payload bytes, through `pin` when the pass must see exactly the bytes an earlier
/// pass authenticated.
fn pread(
    p: &mut Payload,
    pin: &mut Option<&mut Pinned>,
    src: &mut FileSrc,
    l: &Layout,
    off: u64,
    buf: &mut [u8],
) -> Result<()> {
    match pin {
        Some(pn) => pn.read_at(p, src, l, off, buf),
        None => p.read_at(src, l, off, buf),
    }
}

struct BodyReader<'a> {
    src: &'a mut FileSrc,
    l: &'a Layout,
    p: &'a mut Payload,
    pin: Option<&'a mut Pinned>,
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
            pread(
                self.p,
                &mut self.pin,
                self.src,
                self.l,
                self.pos,
                &mut self.raw[..t],
            )
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
    if l.placed_by_order(&parts) {
        return Ok(None);
    }
    let mut p = payload(&mut src, &l, &parts, beside)?;
    let pz = pass.unwrap_or("").trim();
    let mut gcm: Option<Gcm> = None;
    let mut pin = Pinned::new();
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
        // Pass 1: the tag over the whole ciphertext, before anything is decrypted. Each
        // window is pinned so later passes decrypt exactly these bytes.
        let mut gh = g.ghash(&aad);
        let mut buf = vec![0u8; IO_WINDOW];
        let mut pos = 0u64;
        while pos < h.folded_len {
            crate::repair_ctl::check()?;
            let t = (h.folded_len - pos).min(IO_WINDOW as u64) as usize;
            p.read_at(&mut src, &l, pos, &mut buf[..t])?;
            gh.update(&buf[..t]);
            pin.record(&buf[..t]);
            pos += t as u64;
        }
        if !ct_eq16(&gh.tag(&g.mask()), &h.tag) {
            return Err(msg(crate::LEGACY_OPEN_FAILED));
        }
        gcm = Some(g);
    } else if !pz.is_empty() {
        return Err(msg("seal was not encrypted"));
    }
    // Pass 2 (and 3 when `verify_first`): decrypt, unfold, inflate, check. An encrypted
    // seal's passes read only the windows pass 1 pinned. A plain seal written to a file
    // needs no pin (the part file is renamed only after the SHA-256 check); before a plain
    // seal goes to stdout its windows are pinned first, so the bytes released are the
    // bytes the check passed.
    if gcm.is_none() && verify_first {
        let mut buf = vec![0u8; IO_WINDOW];
        let mut pos = 0u64;
        while pos < h.folded_len {
            crate::repair_ctl::check()?;
            let t = (h.folded_len - pos).min(IO_WINDOW as u64) as usize;
            p.read_at(&mut src, &l, pos, &mut buf[..t])?;
            pin.record(&buf[..t]);
            pos += t as u64;
        }
    }
    let pinned = gcm.is_some() || verify_first;
    if verify_first {
        plain_pass(
            &mut src,
            &l,
            &mut p,
            gcm.as_ref(),
            Some(&mut pin),
            &mut std::io::sink(),
        )?;
    }
    let pin = if pinned { Some(&mut pin) } else { None };
    plain_pass(&mut src, &l, &mut p, gcm.as_ref(), pin, out).map(Some)
}

fn plain_pass<W: Write>(
    src: &mut FileSrc,
    l: &Layout,
    p: &mut Payload,
    gcm: Option<&Gcm>,
    mut pin: Option<&mut Pinned>,
    out: &mut W,
) -> Result<Opened> {
    let h = &l.h;
    let total = h.folded_len;
    if h.private_label() {
        let g = gcm.ok_or_else(|| msg("no key"))?;
        // The inner block: at most INNER_FIXED + 65535 bytes.
        let head_len = total.min((privacy::INNER_FIXED + 65535) as u64) as usize;
        let mut head = zeroize::Zeroizing::new(vec![0u8; head_len]);
        pread(p, &mut pin, src, l, 0, &mut head[..])?;
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
            pread(p, &mut pin, src, l, pos, &mut buf[..t])?;
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
            pin,
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
        pin,
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
        crate::getrandom(&mut salt)?;
        crate::getrandom(&mut nonce)?;
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
    crate::getrandom(&mut salt)?;
    crate::getrandom(&mut nonce)?;
    let mut cek = zeroize::Zeroizing::new([0u8; 32]);
    crate::getrandom(&mut cek[..])?;
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
#[derive(Debug)]
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
    if l.placed_by_order(&parts) {
        return Ok(None);
    }
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
    // Any error (a stop, a failed check, I/O) removes the partial output.
    let mut guard = PartFile {
        path: out.to_path_buf(),
        keep: false,
    };
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
            ok = plain_pass(&mut src, &l, &mut p, None, None, &mut std::io::sink()).is_ok();
        }
        if !ok {
            drop(f);
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
    guard.keep = true;
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
    if l.placed_by_order(&parts) {
        return Ok(None);
    }
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
    if l.placed_by_order(&parts) {
        return Ok(None);
    }
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

/// `doctor::health_bytes` for a classic seal on disk whose framing is intact; `Ok(None)`
/// for anything else, or when the repair check fails (the in-memory check words that).
pub(crate) fn health_path(input: &Path) -> Result<Option<crate::doctor::Health>> {
    use crate::doctor::Health;
    let mut src = FileSrc::open(input)?;
    let Some(l) = probe(&mut src)? else {
        return Ok(None);
    };
    let parts = scan_parts(&mut src, &l)?;
    if l.placed_by_order(&parts) {
        return Ok(None);
    }
    let (n, k) = (l.n, l.k);
    let live = parts.live();
    if live < k {
        return Ok(Some(Health::Damaged(format!(
            "only {live}/{n} shards intact, need {k}"
        ))));
    }
    if live < n {
        return Ok(Some(Health::Mendable(format!(
            "{live}/{n} shards intact (need {k})"
        ))));
    }
    if merkle::merkle_root(&parts.sha) != l.h.merkle {
        return Ok(Some(Health::Damaged(
            "all shards present but Merkle root differs (corrupt shard data)".into(),
        )));
    }
    if reencodes_exactly(&mut src, &l).is_err() {
        return Ok(None);
    }
    Ok(Some(if l.front_canonical {
        Health::Ok
    } else {
        Health::Mendable(
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
        plain_pass(src, l, &mut p, None, None, &mut std::io::sink()).map_err(|_| hard_fail())?;
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::header::KEYSTONE_TRAILER_SIZE;
    use crate::privacy::{Pad, SealOpts};

    fn dir(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "sigil-classic-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn noise(len: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..len)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    fn text(len: usize) -> Vec<u8> {
        b"the quick brown fox jumps over the lazy dog 0123456789\n"
            .iter()
            .cycle()
            .take(len)
            .copied()
            .collect()
    }

    const PIECE: u32 = 64 * 1024;

    struct Case<'a> {
        data: &'a [u8],
        mode: Mode,
        pass: Option<&'a str>,
        cov: &'a str,
        geas: &'a [[u8; 32]],
        shards: Option<u8>,
        opts: SealOpts,
        mds: &'a str,
    }

    impl<'a> Case<'a> {
        fn new(data: &'a [u8], mode: Mode) -> Self {
            Case {
                data,
                mode,
                pass: None,
                cov: "",
                geas: &[],
                shards: None,
                opts: SealOpts::default(),
                mds: "vandermonde",
            }
        }
        /// (in-memory seal, streamed seal), same random draws.
        fn seal_both(&self, seed: u64) -> (Vec<u8>, Vec<u8>) {
            let be = mds::backend_by_name(self.mds).unwrap();
            crate::set_test_random_seed(Some(seed));
            let mem = crate::seal_kn_mds_to_opts(
                self.data,
                self.mode,
                self.pass,
                "f.bin",
                false,
                self.cov,
                self.geas,
                self.shards,
                PIECE,
                &*be,
                &[],
                &self.opts,
            )
            .unwrap();
            let d = dir("seal");
            let input = d.join("f.bin");
            std::fs::write(&input, self.data).unwrap();
            let out = d.join("f.sg1");
            crate::set_test_random_seed(Some(seed));
            let n = seal(
                &input,
                &out,
                self.mode,
                self.pass,
                "f.bin",
                false,
                self.cov,
                self.geas,
                self.shards,
                PIECE,
                &*be,
                &[],
                &self.opts,
            )
            .unwrap()
            .unwrap();
            crate::set_test_random_seed(None);
            assert_eq!(n, self.data.len() as u64);
            let streamed = std::fs::read(&out).unwrap();
            // no scratch or part files left behind
            assert_eq!(std::fs::read_dir(&d).unwrap().count(), 2);
            std::fs::remove_dir_all(&d).unwrap();
            (mem, streamed)
        }
    }

    /// The key wrap (and its spare) is drawn from the OS, so two encrypted seals of the same
    /// draws differ only there: copy `from`'s key-wrap bytes into `to`.
    fn same_key_wrap(to: &mut [u8], from: &[u8]) {
        let len = keys::sgto_len_at(from, KEYSTONE_SPAN);
        assert!(len > 0);
        assert_eq!(keys::sgto_len_at(to, KEYSTONE_SPAN), len);
        to[KEYSTONE_SPAN..KEYSTONE_SPAN + len]
            .copy_from_slice(&from[KEYSTONE_SPAN..KEYSTONE_SPAN + len]);
        let end = from.len() - KEYSTONE_TRAILER_SIZE;
        let sp = header::SGTO_SPARE_HEAD + len;
        to[end - sp..end].copy_from_slice(&from[end - sp..end]);
    }

    fn open_stream(file: &[u8], pass: Option<&str>, companions: &[Vec<u8>]) -> Result<Vec<u8>> {
        let d = dir("open");
        let p = d.join("x.sg1");
        std::fs::write(&p, file).unwrap();
        let mut out = Vec::new();
        let r = open(
            &p,
            &mut out,
            pass,
            companions,
            &*mds::default_backend(),
            &[],
            &d.join("out.bin"),
            false,
        );
        // the spool (if any) is gone
        assert_eq!(std::fs::read_dir(&d).unwrap().count(), 1);
        std::fs::remove_dir_all(&d).unwrap();
        match r? {
            Some(o) => {
                assert_eq!(o.len, out.len() as u64);
                Ok(out)
            }
            None => Err(msg("not a clean layout")),
        }
    }

    fn with_file<T>(file: &[u8], f: impl FnOnce(&Path) -> T) -> T {
        let d = dir("file");
        let p = d.join("x.sg1");
        std::fs::write(&p, file).unwrap();
        let r = f(&p);
        std::fs::remove_dir_all(&d).unwrap();
        r
    }

    fn layout_of(file: &[u8]) -> Layout {
        with_file(file, |p| {
            probe(&mut FileSrc::open(p).unwrap()).unwrap().unwrap()
        })
    }

    /// Damage part `i` (CRC now fails).
    fn hit_part(file: &mut [u8], l: &Layout, i: usize) {
        let off = l.shard_off(i) as usize + (l.sl as usize / 2);
        file[off] ^= 0x5a;
    }

    /// Rewrite every header copy (front Keystone, Embers, trailer) after `edit`.
    fn patch_header(file: &mut [u8], edit: impl FnOnce(&mut Header)) {
        let l = layout_of(file);
        let mut h = l.h.clone();
        edit(&mut h);
        let hdr = header::write_header(&h);
        let ks = header::wrap_keystone(&hdr);
        file[..ks.len()].copy_from_slice(&ks);
        for i in 0..l.n {
            let at = (l.prefix + i as u64 * l.stride) as usize;
            file[at..at + HEADER_SIZE].copy_from_slice(&header::write_ember(&hdr, i as u8));
        }
        let t = header::write_keystone_trailer(&hdr);
        let n = file.len();
        file[n - t.len()..].copy_from_slice(&t);
    }

    #[test]
    fn plain_seals_are_byte_identical() {
        let h1 = crate::sha256(b"companion");
        let datas = [
            Vec::new(),
            vec![7u8],
            text(23),
            text(24),
            noise(24, 3),
            text(1000),
            noise(70_001, 5),
            text(300_003),
            noise(1_200_000, 9),
        ];
        let mut n = 0;
        for data in &datas {
            for mode in [Mode::Seal, Mode::Reflection, Mode::Glyph] {
                let mut c = Case::new(data, mode);
                let (a, b) = c.seal_both(0x1126 + n);
                assert_eq!(a, b, "plain {} bytes {mode:?}", data.len());
                c.cov = "keep";
                c.geas = std::slice::from_ref(&h1);
                c.shards = Some(40);
                let (a, b) = c.seal_both(0x2126 + n);
                assert_eq!(a, b, "vow {} bytes {mode:?}", data.len());
                c.mds = "cauchy";
                if mode != Mode::Glyph {
                    let (a, b) = c.seal_both(0x3126 + n);
                    assert_eq!(a, b, "cauchy {} bytes {mode:?}", data.len());
                }
                n += 1;
            }
        }
    }

    #[test]
    fn warded_seals_match_and_cross_open() {
        let datas = [text(24), noise(5000, 4), text(300_003), noise(900_001, 8)];
        let mut n = 0;
        for data in &datas {
            for mode in [Mode::Seal, Mode::Glyph] {
                for pad in [Pad::Off, Pad::Bucket] {
                    let mut c = Case::new(data, mode);
                    c.pass = Some("pw 1126");
                    c.opts.pad = pad;
                    let (a, mut b) = c.seal_both(0x4126 + n);
                    n += 1;
                    // each opens in the other's reader
                    assert_eq!(crate::unseal(&b, c.pass).unwrap(), *data);
                    assert_eq!(open_stream(&a, c.pass, &[]).unwrap(), *data);
                    assert_eq!(open_stream(&b, c.pass, &[]).unwrap(), *data);
                    same_key_wrap(&mut b, &a);
                    assert_eq!(a, b, "warded {} bytes {mode:?} {pad:?}", data.len());
                }
            }
        }
    }

    #[test]
    fn streamed_open_matches_in_memory_with_damaged_parts() {
        for pass in [None, Some("pw")] {
            for (data, mode) in [
                (noise(400_000, 11), Mode::Seal),
                (text(400_000), Mode::Reflection),
                (noise(200_000, 12), Mode::Glyph),
            ] {
                crate::set_test_random_seed(Some(77));
                let file = crate::seal_kn(&data, mode, pass, "d", false, "", &[], Some(20), PIECE)
                    .unwrap();
                crate::set_test_random_seed(None);
                assert_eq!(open_stream(&file, pass, &[]).unwrap(), data);
                let l = layout_of(&file);
                let mut torn = file.clone();
                let hits: Vec<usize> = if mode == Mode::Glyph {
                    vec![2]
                } else {
                    // two data parts and one parity part
                    vec![0, 3, l.k + 1]
                };
                for &i in &hits {
                    hit_part(&mut torn, &l, i);
                }
                if l.h.ember() {
                    // damaged Ember copies beside an intact part and a damaged one
                    for i in [1, hits[0]] {
                        torn[(l.prefix + i as u64 * l.stride) as usize + 20] ^= 0x33;
                    }
                }
                let mem = crate::unseal(&torn, pass).map_err(|e| e.to_string());
                let st = open_stream(&torn, pass, &[]).map_err(|e| e.to_string());
                assert_eq!(st, mem, "{mode:?} {pass:?}");
                if mode != Mode::Glyph {
                    assert_eq!(st.unwrap(), data);
                    // past repair: too few parts
                    let mut gone = torn.clone();
                    for i in 0..l.n - l.k + 1 {
                        if !hits.contains(&i) {
                            hit_part(&mut gone, &l, i);
                        }
                    }
                    let mem = crate::unseal(&gone, pass).map_err(|e| e.to_string());
                    let st = open_stream(&gone, pass, &[]).map_err(|e| e.to_string());
                    assert!(mem.is_err());
                    assert_eq!(st, mem);
                }
            }
        }
    }

    #[test]
    fn a_window_changed_after_it_was_pinned_is_refused() {
        let data = noise(3_000_000, 61);
        let file = crate::seal(&data, Mode::Seal, Some("pw"), "p", false).unwrap();
        let d = dir("pin");
        let path = d.join("x.sg1");
        std::fs::write(&path, &file).unwrap();
        let mut src = FileSrc::open(&path).unwrap();
        let l = probe(&mut src).unwrap().unwrap();
        let mut p = Payload::InPlace;
        let mut pin = Pinned::new();
        let mut pos = 0u64;
        while pos < l.h.folded_len {
            let t = (l.h.folded_len - pos).min(IO_WINDOW as u64) as usize;
            let mut b = vec![0u8; t];
            p.read_at(&mut src, &l, pos, &mut b).unwrap();
            pin.record(&b);
            pos += t as u64;
        }
        // unchanged: pinned reads give the same bytes, across a window edge too
        let at = IO_WINDOW as u64 - 100;
        let (mut a, mut b) = (vec![0u8; 300], vec![0u8; 300]);
        pin.read_at(&mut p, &mut src, &l, at, &mut a).unwrap();
        p.read_at(&mut src, &l, at, &mut b).unwrap();
        assert_eq!(a, b);
        // one byte of window 2 changes on disk after pinning: refused, nothing handed on
        let mut f = file.clone();
        let off = {
            let o = 2 * IO_WINDOW as u64 + 7;
            let part = o / l.sl;
            (l.shard_off(part as usize) + o % l.sl) as usize
        };
        f[off] ^= 1;
        std::fs::write(&path, &f).unwrap();
        let mut src = FileSrc::open(&path).unwrap();
        let mut out = vec![0u8; 64];
        let e = pin
            .read_at(&mut p, &mut src, &l, 2 * IO_WINDOW as u64, &mut out)
            .unwrap_err();
        assert!(e.to_string().contains("changed"), "{e}");
        assert!(out.iter().all(|&x| x == 0));
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn tamper_wrong_key_and_geas_fail_closed() {
        let data = noise(300_000, 21);
        let geas = [crate::sha256(b"comp")];
        crate::set_test_random_seed(Some(5));
        let file =
            crate::seal_ex(&data, Mode::Seal, Some("right"), "t", false, "c", &geas).unwrap();
        crate::set_test_random_seed(None);
        let comp = vec![b"comp".to_vec()];
        assert_eq!(open_stream(&file, Some("right"), &comp).unwrap(), data);
        for (pass, comp) in [
            (Some("wrong"), comp.clone()),
            (None, comp.clone()),
            (Some("right"), Vec::new()),
        ] {
            let mem = crate::unseal_ex(&file, pass, &comp).map_err(|e| e.to_string());
            let st = open_stream(&file, pass, &comp).map_err(|e| e.to_string());
            assert!(mem.is_err());
            assert_eq!(st, mem);
        }
        // A changed ciphertext byte with a matching CRC and Merkle root: the Merkle check
        // passes, so only the GCM tag catches it, and nothing is written.
        let l = layout_of(&file);
        let mut t = file.clone();
        let off = l.shard_off(1) as usize + 10;
        t[off] ^= 1;
        let body = &t[l.shard_off(1) as usize..(l.shard_off(1) + l.sl) as usize];
        let crc = crc32fast::hash(body).to_le_bytes();
        let at = (l.shard_off(1) + l.sl) as usize;
        t[at..at + 4].copy_from_slice(&crc);
        let lt = layout_of(&t);
        let mut parts = Vec::new();
        with_file(&t, |p| {
            let mut s = FileSrc::open(p).unwrap();
            parts = scan_parts(&mut s, &lt).unwrap().sha;
        });
        // parity no longer matches the data, so re-encoding gives a different root:
        // refused before decrypting
        let mem = crate::unseal_ex(&t, Some("right"), &comp).map_err(|e| e.to_string());
        let st = open_stream(&t, Some("right"), &comp).map_err(|e| e.to_string());
        assert!(mem.is_err());
        assert_eq!(st, mem);
        // drop every parity part's evidence by making the label agree with a re-encode of
        // the tampered ciphertext: then the GCM tag is the only check left
        let d = dir("tamper");
        let p = d.join("t.sg1");
        std::fs::write(&p, &t).unwrap();
        let mut src = FileSrc::open(&p).unwrap();
        let mut pl = Payload::InPlace;
        let parity = rs::parity_matrix(lt.k, lt.n).unwrap();
        let leaves = reencode(&mut src, &lt, &mut pl, &parity, |_, _, _| Ok(())).unwrap();
        drop(src);
        std::fs::remove_dir_all(&d).unwrap();
        let root = merkle::merkle_root(&leaves);
        patch_header(&mut t, |h| h.merkle = root);
        // parity parts still hold the old values: rebuild them so every part is consistent
        let lt = layout_of(&t);
        let d = dir("tamper2");
        let p = d.join("t.sg1");
        std::fs::write(&p, &t).unwrap();
        let mut src = FileSrc::open(&p).unwrap();
        let mut pl = Payload::InPlace;
        let mut f = std::fs::OpenOptions::new().write(true).open(&p).unwrap();
        let mut pw = PartWriter::new(lt.prefix, lt.lead, lt.sl, lt.n);
        reencode(&mut src, &lt, &mut pl, &parity, |i, col, b| {
            if i >= lt.k {
                pw.put_window(&mut f, i, col, b)
            } else {
                Ok(())
            }
        })
        .unwrap();
        let (crcs, _) = pw.finish();
        for (i, c) in crcs.iter().enumerate().skip(lt.k) {
            write_at(&mut f, lt.shard_off(i) + lt.sl, &c.to_le_bytes()).unwrap();
        }
        drop(f);
        let t = std::fs::read(&p).unwrap();
        std::fs::remove_dir_all(&d).unwrap();
        let _ = parts;
        let mem = crate::unseal_ex(&t, Some("right"), &comp).map_err(|e| e.to_string());
        assert_eq!(mem, Err(crate::LEGACY_OPEN_FAILED.to_string()));
        let d = dir("tamper3");
        let p = d.join("t.sg1");
        std::fs::write(&p, &t).unwrap();
        let mut out = Vec::new();
        let r = open(
            &p,
            &mut out,
            Some("right"),
            &comp,
            &*mds::default_backend(),
            &[],
            &d.join("o"),
            false,
        );
        std::fs::remove_dir_all(&d).unwrap();
        assert_eq!(
            r.map(|o| o.map(|o| o.len)).map_err(|e| e.to_string()),
            Err(crate::LEGACY_OPEN_FAILED.to_string())
        );
        assert!(
            out.is_empty(),
            "no plaintext released before the tag checks"
        );
    }

    #[test]
    fn deflate_bomb_is_refused_at_the_stated_length() {
        // 8 MiB of zeros deflates to a few KiB; the label then claims 1000 bytes.
        let data = vec![0u8; 8 << 20];
        let mut file = crate::seal(&data, Mode::Seal, None, "z", false).unwrap();
        patch_header(&mut file, |h| h.orig_len = 1000);
        let mem = crate::unseal(&file, None).map_err(|e| e.to_string());
        assert_eq!(mem, Err("length mismatch".to_string()));
        let d = dir("bomb");
        let p = d.join("z.sg1");
        std::fs::write(&p, &file).unwrap();
        struct Count(u64);
        impl Write for Count {
            fn write(&mut self, b: &[u8]) -> std::io::Result<usize> {
                self.0 += b.len() as u64;
                Ok(b.len())
            }
            fn flush(&mut self) -> std::io::Result<()> {
                Ok(())
            }
        }
        let mut c = Count(0);
        let r = open(
            &p,
            &mut c,
            None,
            &[],
            &*mds::default_backend(),
            &[],
            &d.join("o"),
            false,
        );
        std::fs::remove_dir_all(&d).unwrap();
        assert_eq!(
            r.map(|o| o.map(|o| o.len)).map_err(|e| e.to_string()),
            Err("length mismatch".to_string())
        );
        assert!(c.0 <= 1000, "wrote {} bytes past the stated length", c.0);
    }

    #[test]
    fn a_stop_or_time_limit_ends_every_stream_with_nothing_kept() {
        let data = noise(600_000, 31);
        let d = dir("stop");
        let input = d.join("in.bin");
        std::fs::write(&input, &data).unwrap();
        let out = d.join("out.sg1");
        let be = mds::default_backend();
        {
            let _s = crate::repair_ctl::DeadlineScope::enter(Some(std::time::Instant::now()));
            let e = seal(
                &input,
                &out,
                Mode::Seal,
                Some("p"),
                "in.bin",
                false,
                "",
                &[],
                None,
                PIECE,
                &*be,
                &[],
                &SealOpts::default(),
            );
            assert!(e
                .unwrap_err()
                .to_string()
                .contains(crate::repair_ctl::TIME_LIMIT));
        }
        assert_eq!(
            std::fs::read_dir(&d).unwrap().count(),
            1,
            "nothing left behind"
        );
        seal(
            &input,
            &out,
            Mode::Seal,
            Some("p"),
            "in.bin",
            false,
            "",
            &[],
            None,
            PIECE,
            &*be,
            &[],
            &SealOpts::default(),
        )
        .unwrap()
        .unwrap();
        {
            let _s = crate::repair_ctl::DeadlineScope::enter(Some(std::time::Instant::now()));
            let mut v = Vec::new();
            let e = open(&out, &mut v, Some("p"), &[], &*be, &[], &out, false);
            assert!(e
                .unwrap_err()
                .to_string()
                .contains(crate::repair_ctl::TIME_LIMIT));
            assert!(v.is_empty());
            let (plan, _) = match mend_plan(&out, &out) {
                Err(e) => {
                    assert!(e.to_string().contains(crate::repair_ctl::TIME_LIMIT));
                    (None, ())
                }
                Ok(p) => (p.map(|p| p.0), ()),
            };
            assert!(plan.is_none());
        }
        std::fs::remove_dir_all(&d).unwrap();
    }

    #[test]
    fn mend_scan_verify_and_assess_match_in_memory() {
        for pass in [None, Some("pw")] {
            for (data, mode) in [
                (noise(500_000, 41), Mode::Seal),
                (text(500_000), Mode::Reflection),
                (noise(100_000, 42), Mode::Glyph),
            ] {
                crate::set_test_random_seed(Some(9));
                let file = crate::seal_kn(&data, mode, pass, "m", false, "", &[], Some(24), PIECE)
                    .unwrap();
                crate::set_test_random_seed(None);
                let l = layout_of(&file);
                let mut cases = vec![file.clone()];
                let mut one = file.clone();
                hit_part(&mut one, &l, 1);
                cases.push(one.clone());
                if mode != Mode::Glyph {
                    let mut many = one.clone();
                    for i in [0, 4, l.k, l.n - 1] {
                        hit_part(&mut many, &l, i);
                    }
                    cases.push(many.clone());
                    let mut gone = file.clone();
                    for i in 0..=(l.n - l.k) {
                        hit_part(&mut gone, &l, i);
                    }
                    cases.push(gone);
                }
                // a damaged spare Keystone copy (data intact)
                let mut ks = file.clone();
                ks[HEADER_SIZE + 9] ^= 0xff;
                cases.push(ks);
                let ember_at = |i: usize| (l.prefix + i as u64 * l.stride) as usize;
                if l.h.ember() {
                    // damaged Embers: beside an intact part 1, and beside a damaged part 2
                    let mut em = file.clone();
                    em[ember_at(1) + 20] ^= 0x33;
                    em[ember_at(2) + 3] ^= 0x01;
                    hit_part(&mut em, &l, 2);
                    cases.push(em);
                    // 4 KiB wiped across the boundary of parts 2 and 3 (CRC word, Ember)
                    let mut st = file.clone();
                    let (b, w) = (ember_at(3), (l.stride as usize / 2).min(2048));
                    st[b - w..b + w].fill(0xa5);
                    cases.push(st);
                    // only part 1 is still found by its Ember: the in-memory scan places
                    // it by order, so the streamed paths step aside
                    let mut ord = file.clone();
                    for i in (0..l.n).filter(|&i| i != 1) {
                        ord[ember_at(i) + 20] ^= 0x33;
                    }
                    with_file(&ord, |p| {
                        assert!(verify_path(p).unwrap().is_none(), "{mode:?} order");
                        assert!(assess_path(p).unwrap().is_none(), "{mode:?} order");
                        assert!(health_path(p).unwrap().is_none(), "{mode:?} order");
                        assert!(mend_plan(p, p).unwrap().is_none(), "{mode:?} order");
                        let mut sink = Vec::new();
                        let be = crate::mds::VandermondeRs;
                        let o = open(p, &mut sink, pass, &[], &be, &[], p, true).unwrap();
                        assert!(o.is_none() && sink.is_empty(), "{mode:?} order");
                    });
                }
                for (ci, f) in cases.iter().enumerate() {
                    let what = format!("{mode:?} {pass:?} case {ci}");
                    with_file(f, |p| {
                        assert!(verify_path(p).unwrap().is_some(), "streams {what}");
                        assert_eq!(
                            verify_path(p).unwrap().map(|v| (v.1, v.2, v.3, v.4)),
                            crate::verify(f).ok().map(|v| (v.1, v.2, v.3, v.4)),
                            "verify {what}"
                        );
                        if let Some(h) = health_path(p).unwrap() {
                            assert_eq!(
                                format!("{h:?}"),
                                format!("{:?}", crate::doctor::health_bytes(f)),
                                "health {what}"
                            );
                        }
                        let mut budget = crate::recovery::ProbeBudget::with_secs(30);
                        if let Some(c) = assess_path(p).unwrap() {
                            assert_eq!(
                                c,
                                crate::recovery::assess_seal(
                                    f,
                                    crate::recovery::MendMode::Deep,
                                    &mut budget
                                ),
                                "assess {what}"
                            );
                        }
                        let mem = crate::pieces::mend_bytes_ex(f, false);
                        let (plan, rep) = mend_plan(p, p).unwrap().unwrap();
                        assert_eq!(
                            Some(rep),
                            crate::repair_scan::scan_bytes(f).ok(),
                            "scan {what}"
                        );
                        let out = p.with_extension("mended");
                        let st = mend_run(plan, &out, false);
                        match (mem, st) {
                            (Ok((m, _)), Ok(Some(done))) => {
                                assert_eq!(std::fs::read(&out).unwrap(), m, "mend {what}");
                                let v = crate::verify(&m).unwrap();
                                assert_eq!((v.1, v.2, v.3), (done.merkle_ok, done.live, done.k));
                            }
                            (Err(a), Err(b)) => assert_eq!(a.to_string(), b.to_string(), "{what}"),
                            (a, b) => panic!(
                                "{what}: in memory {:?}, streamed {:?}",
                                a.map(|_| ()),
                                b.map(|o| o.is_some())
                            ),
                        }
                    });
                }
            }
        }
    }

    #[test]
    fn shifted_or_extended_framing_is_left_to_the_in_memory_path() {
        let data = noise(200_000, 51);
        let file = crate::seal(&data, Mode::Seal, None, "s", false).unwrap();
        let mut ins = file.clone();
        ins.insert(file.len() / 2, 0);
        let mut cut = file.clone();
        cut.truncate(file.len() - 1000);
        let mut extra = file.clone();
        extra.extend_from_slice(b"SGIL trailing junk");
        let mut ember = file.clone();
        let l = layout_of(&file);
        ember[(l.prefix + 3 * l.stride) as usize + 20] ^= 1;
        for f in [&ins, &cut, &extra] {
            with_file(f, |p| assert!(!is_clean(p).unwrap()));
        }
        // a damaged Ember copy moves nothing: still streamed, and not canonical
        with_file(&ember, |p| {
            let l = probe(&mut FileSrc::open(p).unwrap()).unwrap().unwrap();
            assert!(!l.front_canonical && !l.ember_ok[3] && l.ember_ok[2]);
        });
        with_file(&file, |p| assert!(is_clean(p).unwrap()));
    }
}
