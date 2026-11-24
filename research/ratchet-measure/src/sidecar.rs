//! Prototype stripe-check sidecar (`NAME.sg1.stripes`), research only.
//!
//! Lives next to a Sigil; never inside `.sg1`. A missing, unparsable or
//! mis-bound sidecar means "no hints" (today's behaviour). Plain checks catch
//! faults (threat line F) only: anyone who can rewrite a shard can rewrite its
//! check too (threat line A needs a keyed or signed table).
//!
//! Layout (little endian):
//!   "SGRS" | ver=1 u8 | mode u8 (0 independent, 1 chained) | check u8 (1 CRC32, 2 SHA-256/64)
//!   | 0 u8 | cell u32 | n u16 | k u16 | shard_len u32 | merkle_root[32] | true_name[32]
//!   | crc32(header)
//!   then entries (w = 4 or 8 bytes each), in groups of 256 entries, each group followed by
//!   crc32(group bytes). Entry order: shard-major, block-minor.

use sha2::{Digest, Sha256};

pub const MAGIC: &[u8; 4] = b"SGRS";
pub const GROUP: usize = 256;
const HEADER_LEN: usize = 4 + 4 + 4 + 2 + 2 + 4 + 32 + 32;

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Check {
    Crc32,
    Sha64,
}

impl Check {
    pub fn width(self) -> usize {
        match self {
            Check::Crc32 => 4,
            Check::Sha64 => 8,
        }
    }
    fn code(self) -> u8 {
        match self {
            Check::Crc32 => 1,
            Check::Sha64 => 2,
        }
    }
    pub fn name(self) -> &'static str {
        match self {
            Check::Crc32 => "crc32",
            Check::Sha64 => "sha256/64",
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum Mode {
    Independent,
    Chained,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub struct Spec {
    pub cell: usize,
    pub check: Check,
    pub mode: Mode,
}

/// Bytes hashed before the cell: domain, shard, block, and (chained) previous check.
pub fn prefix(spec: &Spec, i: usize, j: u32, prev: Option<u64>) -> Vec<u8> {
    let mut p = Vec::with_capacity(16);
    p.push(match spec.mode {
        Mode::Independent => 0x49,
        Mode::Chained => 0x43,
    });
    p.extend_from_slice(&(i as u16).to_le_bytes());
    p.extend_from_slice(&j.to_le_bytes());
    if let Some(v) = prev {
        p.extend_from_slice(&v.to_le_bytes()[..spec.check.width()]);
    }
    p
}

pub fn prefix_len(spec: &Spec) -> usize {
    7 + match spec.mode {
        Mode::Independent => 0,
        Mode::Chained => spec.check.width(),
    }
}

pub fn hash(check: Check, prefix: &[u8], cell: &[u8]) -> u64 {
    match check {
        Check::Crc32 => {
            let mut h = crc32fast::Hasher::new();
            h.update(prefix);
            h.update(cell);
            h.finalize() as u64
        }
        Check::Sha64 => {
            let mut h = Sha256::new();
            h.update(b"SGRS-cell");
            h.update(prefix);
            h.update(cell);
            let d = h.finalize();
            let mut b = [0u8; 8];
            b.copy_from_slice(&d[..8]);
            u64::from_le_bytes(b)
        }
    }
}

/// Chain start value for shard i.
pub fn chain_init(spec: &Spec, i: usize, root: &[u8; 32]) -> u64 {
    hash(spec.check, &prefix(spec, i, u32::MAX, None), root)
}

pub struct Sidecar {
    pub spec: Spec,
    pub n: usize,
    pub k: usize,
    pub shard_len: usize,
    pub blocks: usize,
    pub root: [u8; 32],
    pub name: [u8; 32],
    /// None = entry lost (its group CRC failed).
    pub entries: Vec<Option<u64>>,
}

impl Sidecar {
    pub fn build(
        spec: Spec,
        k: usize,
        shards: &[Vec<u8>],
        root: [u8; 32],
        name: [u8; 32],
    ) -> Option<Self> {
        let shard_len = shards.first()?.len();
        if spec.cell == 0 || shard_len == 0 {
            return None;
        }
        // last cell may be short
        let blocks = shard_len.div_ceil(spec.cell);
        let mut entries = Vec::with_capacity(shards.len() * blocks);
        for (i, s) in shards.iter().enumerate() {
            let mut prev = chain_init(&spec, i, &root);
            for j in 0..blocks {
                let cell = &s[j * spec.cell..((j + 1) * spec.cell).min(shard_len)];
                let p = match spec.mode {
                    Mode::Independent => prefix(&spec, i, j as u32, None),
                    Mode::Chained => prefix(&spec, i, j as u32, Some(prev)),
                };
                let v = hash(spec.check, &p, cell);
                prev = v;
                entries.push(Some(v));
            }
        }
        Some(Sidecar {
            spec,
            n: shards.len(),
            k,
            shard_len,
            blocks,
            root,
            name,
            entries,
        })
    }

    pub fn entry(&self, i: usize, j: usize) -> Option<u64> {
        if j >= self.blocks {
            return None;
        }
        self.entries.get(i * self.blocks + j).copied().flatten()
    }

    pub fn to_bytes(&self) -> Vec<u8> {
        let w = self.spec.check.width();
        let mut out = Vec::with_capacity(HEADER_LEN + 4 + self.entries.len() * w + 64);
        out.extend_from_slice(MAGIC);
        out.push(1);
        out.push(match self.spec.mode {
            Mode::Independent => 0,
            Mode::Chained => 1,
        });
        out.push(self.spec.check.code());
        out.push(0);
        out.extend_from_slice(&(self.spec.cell as u32).to_le_bytes());
        out.extend_from_slice(&(self.n as u16).to_le_bytes());
        out.extend_from_slice(&(self.k as u16).to_le_bytes());
        out.extend_from_slice(&(self.shard_len as u32).to_le_bytes());
        out.extend_from_slice(&self.root);
        out.extend_from_slice(&self.name);
        let hc = crc32fast::hash(&out);
        out.extend_from_slice(&hc.to_le_bytes());
        for g in self.entries.chunks(GROUP) {
            let start = out.len();
            for e in g {
                out.extend_from_slice(&e.unwrap_or(0).to_le_bytes()[..w]);
            }
            let c = crc32fast::hash(&out[start..]);
            out.extend_from_slice(&c.to_le_bytes());
        }
        out
    }

    /// Hostile-input parse. `expect_root`/`expect_name` come from the Sigil header;
    /// a sidecar bound to anything else is refused.
    pub fn parse(b: &[u8], expect_root: &[u8; 32], expect_name: &[u8; 32]) -> Result<Self, String> {
        let hdr = b.get(..HEADER_LEN).ok_or("short header")?;
        let hc = b
            .get(HEADER_LEN..HEADER_LEN + 4)
            .ok_or("short header crc")?;
        if crc32fast::hash(hdr).to_le_bytes() != hc {
            return Err("header crc".into());
        }
        if &hdr[..4] != MAGIC || hdr[4] != 1 {
            return Err("magic/version".into());
        }
        let mode = match hdr[5] {
            0 => Mode::Independent,
            1 => Mode::Chained,
            _ => return Err("mode".into()),
        };
        let check = match hdr[6] {
            1 => Check::Crc32,
            2 => Check::Sha64,
            _ => return Err("check".into()),
        };
        let u32_at = |o: usize| u32::from_le_bytes([hdr[o], hdr[o + 1], hdr[o + 2], hdr[o + 3]]);
        let cell = u32_at(8) as usize;
        let n = u16::from_le_bytes([hdr[12], hdr[13]]) as usize;
        let k = u16::from_le_bytes([hdr[14], hdr[15]]) as usize;
        let shard_len = u32_at(16) as usize;
        if !(16..=1 << 20).contains(&cell) || !cell.is_power_of_two() {
            return Err("cell size".into());
        }
        if n != crate::rs::N || k == 0 || k >= n || shard_len == 0 {
            return Err("geometry".into());
        }
        let mut root = [0u8; 32];
        root.copy_from_slice(&hdr[20..52]);
        let mut name = [0u8; 32];
        name.copy_from_slice(&hdr[52..84]);
        if &root != expect_root || &name != expect_name {
            return Err("bound to a different Sigil".into());
        }
        let blocks = shard_len.div_ceil(cell);
        let total = n.checked_mul(blocks).ok_or("overflow")?;
        let w = check.width();
        let groups = total.div_ceil(GROUP);
        let need = HEADER_LEN + 4 + total * w + groups * 4;
        if b.len() != need {
            return Err(format!("length {} != {}", b.len(), need));
        }
        let mut entries = Vec::with_capacity(total);
        let mut off = HEADER_LEN + 4;
        let mut left = total;
        while left > 0 {
            let cnt = left.min(GROUP);
            let body = &b[off..off + cnt * w];
            let c = &b[off + cnt * w..off + cnt * w + 4];
            let ok = crc32fast::hash(body).to_le_bytes() == c;
            for e in body.chunks(w) {
                if ok {
                    let mut v = [0u8; 8];
                    v[..w].copy_from_slice(e);
                    entries.push(Some(u64::from_le_bytes(v)));
                } else {
                    entries.push(None);
                }
            }
            off += cnt * w + 4;
            left -= cnt;
        }
        Ok(Sidecar {
            spec: Spec { cell, check, mode },
            n,
            k,
            shard_len,
            blocks,
            root,
            name,
            entries,
        })
    }
}

/// CRC32 bit-flip deltas: crc(m ^ e_p) = crc(m) ^ delta[p] for messages of
/// `plen + cell` bytes (CRC is affine over GF(2)). Bit p = byte p/8, bit p%8.
pub fn crc_deltas(plen: usize, cell: usize) -> Vec<u32> {
    let len = plen + cell;
    let zero = vec![0u8; len];
    let c0 = crc32fast::hash(&zero);
    let mut buf = zero;
    let mut out = Vec::with_capacity(cell * 8);
    for p in 0..cell * 8 {
        let byte = plen + p / 8;
        buf[byte] ^= 1 << (p % 8);
        out.push(crc32fast::hash(&buf) ^ c0);
        buf[byte] ^= 1 << (p % 8);
    }
    out
}
