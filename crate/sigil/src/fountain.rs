//! RaptorQ rain (RFC 6330). Extra packets are not limited to 255 RS indices.
//!
//! ## Packet numbering
//!
//! RFC 6330 section 3.2 (FEC Payload ID) gives every encoding symbol an 8-bit
//! Source Block Number and a **24-bit Encoding Symbol ID** (ESI), so ESIs run
//! from 0 to 2^24 - 1 = 16 777 215 ([`MAX_ESI`]). ESIs 0..K-1 of a block are its
//! source symbols and K.. are repair symbols (RFC 6330 section 4.4.2); a decoder
//! rebuilds the block from any K (usually) or K+1 / K+2 distinct symbols.
//!
//! By default `deluge --fountain` gives every packet a **random ESI drawn from
//! the whole 24-bit space**, so people raining the same file without talking to
//! each other almost never send the same packet, and partial shares pooled from
//! several senders add up. `--sequential` keeps the old order (source symbols
//! 0..K-1, then K..K+extra-1 per block).
//!
//! `--extra N` is a target: rerunning into the same folder tops each block up to
//! K + N valid packets of this file and writes nothing once it is there
//! ([`DelugeReport`]).
//!
//! ## Packet file
//!
//! - v1 (old, still read): `"SGFT" | 1 | OTI (12) | payload id (4) | symbol`.
//! - v2 (written now): `"SGFT" | 2 | OTI (12) | object SHA-256 (32) | payload id (4)
//!   | symbol | SHA-256 of every byte before it (32)`.
//!
//! Gather checks each v2 packet's SHA-256 (skips damaged files), groups packets by
//! object (skips strays from another file), dedupes ESIs, and after decoding checks
//! the result against the object SHA-256, so a forged packet fails closed instead
//! of yielding different bytes.

use crate::Result;
use raptorq::{
    partition, Decoder, Encoder, EncodingPacket, ObjectTransmissionInformation, PayloadId,
};
use sha2::{Digest, Sha256};
use std::collections::{BTreeMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};

pub const FT_MAGIC: [u8; 4] = *b"SGFT";
/// Largest packet symbol (bytes); also what `deluge --fountain` asks the encoder for.
pub(crate) const MTU: u16 = 16 * 1024;
/// Largest Encoding Symbol ID: RFC 6330 section 3.2, the ESI is a 24-bit field.
pub const MAX_ESI: u32 = (1 << 24) - 1;
/// Largest source block RFC 6330 supports (K'max, section 5.1.2 / Table 2).
const MAX_K: u32 = 56_403;
/// Refuse to allocate a decoder for more than this (a hostile OTI could ask for TBs).
const MAX_TRANSFER: u64 = 1 << 40;

fn err(m: impl Into<String>) -> crate::Error {
    crate::Error::Msg(m.into())
}

/// Encode one v2 packet file.
fn packet_v2(cfg: &[u8; 12], object: &[u8; 32], pkt: &EncodingPacket) -> Vec<u8> {
    let ser = pkt.serialize();
    let mut out = Vec::with_capacity(4 + 1 + 12 + 32 + ser.len() + 32);
    out.extend_from_slice(&FT_MAGIC);
    out.push(2);
    out.extend_from_slice(cfg);
    out.extend_from_slice(object);
    out.extend_from_slice(&ser);
    let h: [u8; 32] = Sha256::digest(&out).into();
    out.extend_from_slice(&h);
    out
}

/// One parsed packet file.
struct Parsed {
    cfg: [u8; 12],
    /// Object SHA-256 (v2 only).
    object: Option<[u8; 32]>,
    pkt: EncodingPacket,
}

/// Number of source symbols in each source block (RFC 6330 section 4.4.1.2:
/// Kt = ceil(F/T), Partition[Kt, Z]). `None` when the OTI is not one we will decode.
pub(crate) fn block_sizes(oti: &ObjectTransmissionInformation) -> Option<Vec<u32>> {
    let (f, t, z) = (
        oti.transfer_length(),
        u64::from(oti.symbol_size()),
        u32::from(oti.source_blocks()),
    );
    if f == 0 || f > MAX_TRANSFER || t == 0 || z == 0 || oti.sub_blocks() == 0 {
        return None;
    }
    let kt = u32::try_from(f.div_ceil(t)).ok()?;
    if kt < z {
        return None;
    }
    let (kl, ks, zl, _zs) = partition(kt, z);
    if kl > MAX_K {
        return None;
    }
    Some((0..z).map(|i| if i < zl { kl } else { ks }).collect())
}

fn parse_packet(b: &[u8]) -> std::result::Result<Parsed, String> {
    if b.len() < 5 || b[0..4] != FT_MAGIC {
        return Err("not a fountain packet".into());
    }
    let (cfg_at, body_at, end, object) = match b[4] {
        1 => (5usize, 17usize, b.len(), None),
        2 => {
            if b.len() < 4 + 1 + 12 + 32 + 4 + 32 {
                return Err("cut off".into());
            }
            let end = b.len() - 32;
            let want: [u8; 32] = Sha256::digest(&b[..end]).into();
            if b[end..] != want {
                return Err("checksum mismatch (damaged)".into());
            }
            let mut o = [0u8; 32];
            o.copy_from_slice(&b[17..49]);
            (5, 49, end, Some(o))
        }
        v => return Err(format!("unknown packet version {v}")),
    };
    if end < body_at + 4 {
        return Err("cut off".into());
    }
    let mut cfg = [0u8; 12];
    cfg.copy_from_slice(&b[cfg_at..cfg_at + 12]);
    let oti = ObjectTransmissionInformation::deserialize(&cfg);
    let sizes = block_sizes(&oti).ok_or("unusable transmission parameters")?;
    let body = &b[body_at..end];
    if body.len() != 4 + usize::from(oti.symbol_size()) {
        return Err("wrong symbol size (damaged or cut off)".into());
    }
    let pkt = EncodingPacket::deserialize(body);
    if usize::from(pkt.payload_id().source_block_number()) >= sizes.len() {
        return Err("source block number out of range".into());
    }
    Ok(Parsed { cfg, object, pkt })
}

/// What `deluge --fountain` found and wrote in the output folder.
///
/// `--extra N` is a target, not an increment: each source block ends up with
/// K + N valid packets of this file (K = its source-symbol count). Packets already
/// in the folder count toward it only if they are byte-for-byte the packet this
/// file produces for their symbol ID; nothing that is already there is overwritten.
#[derive(Debug, Default, Clone)]
pub struct DelugeReport {
    /// Valid packets of this file wanted in the folder: sum over blocks of K + extra.
    pub target: u32,
    /// Valid packets of this file that were already there and were kept (counted
    /// toward the target; may exceed it when an earlier run used a bigger `--extra`).
    pub kept: u32,
    /// New packet files written by this run.
    pub written: u32,
    /// `.rq` files not counted: unreadable, damaged, or claiming to be this file
    /// but not matching it. Left in place.
    pub bad: Vec<(PathBuf, String)>,
    /// `.rq` files of another file. Left in place, not counted.
    pub stray: Vec<PathBuf>,
    /// Extra copies of a packet already counted (same block and symbol ID).
    pub duplicates: usize,
}

impl DelugeReport {
    /// Valid packets of this file in the folder after the run.
    pub fn total(&self) -> u32 {
        self.kept.saturating_add(self.written)
    }
}

/// Write source packets plus `repair` extra RaptorQ packets of the whole .sg1,
/// with random ESIs (the default; see the module docs). Returns how many valid
/// packets of this file the folder holds afterwards.
pub fn deluge_fountain(file: &[u8], dir: &Path, repair: u32) -> Result<u32> {
    deluge_fountain_opts(file, dir, repair, false)
}

/// Like [`deluge_fountain`]; `sequential` writes ESIs 0..K+repair-1 per block
/// (the order used before random numbering). See [`deluge_fountain_report`].
pub fn deluge_fountain_opts(file: &[u8], dir: &Path, repair: u32, sequential: bool) -> Result<u32> {
    deluge_fountain_report(file, dir, repair, sequential).map(|r| r.total())
}

/// The packet this file's encoder produces for `esi` in one source block.
fn expected_packet(
    block: &raptorq::SourceBlockEncoder,
    source: &[EncodingPacket],
    esi: u32,
) -> Result<EncodingPacket> {
    let k = source.len() as u32;
    if esi < k {
        source
            .get(esi as usize)
            .cloned()
            .ok_or_else(|| err("internal: source symbol out of range"))
    } else {
        block
            .repair_packets(esi - k, 1)
            .into_iter()
            .next()
            .ok_or_else(|| err("internal: no repair packet"))
    }
}

/// Top the folder up to `repair` spare packets per source block beyond K (see
/// [`DelugeReport`]). Random mode (default) counts the valid packets of this file
/// already in `dir` (any name, v1 or v2) and writes only the missing number, with
/// fresh random ESIs that collide with none already there; at or above the target
/// it writes nothing. `sequential` fills in the missing `rain-NNNNN.rq` files of
/// ESIs 0..K+repair-1; an existing one that does not match is reported, not replaced.
pub fn deluge_fountain_report(
    file: &[u8],
    dir: &Path,
    repair: u32,
    sequential: bool,
) -> Result<DelugeReport> {
    deluge_fountain_with(file, dir, repair, sequential, &mut random_esi)
}

/// Consecutive already-taken random ESIs tolerated before a top-up gives up.
const ESI_MISS_LIMIT: u32 = 100_000;

/// A fresh ESI from the OS random source, masked to the 24-bit ESI space.
fn random_esi() -> Result<u32> {
    let mut r = [0u8; 4];
    getrandom::getrandom(&mut r).map_err(|e| err(format!("random ESI: {e}")))?;
    Ok(u32::from_le_bytes(r) & MAX_ESI)
}

/// [`deluge_fountain_report`] with the source of random ESIs passed in, so tests
/// can make a whole transfer repeatable with a seeded generator. Values above
/// [`MAX_ESI`] are masked into range.
pub(crate) fn deluge_fountain_with(
    file: &[u8],
    dir: &Path,
    repair: u32,
    sequential: bool,
    next_esi: &mut dyn FnMut() -> Result<u32>,
) -> Result<DelugeReport> {
    if file.len() >= 4 && file.starts_with(&crate::work::WORK_MAGIC) {
        return Err(err(
            "work pack: fountain each star, or Scatter the pack first.",
        ));
    }
    if file.is_empty() {
        return Err(err("nothing to rain: the file is empty"));
    }
    fs::create_dir_all(dir).map_err(|e| err(e.to_string()))?;
    let enc = Encoder::with_defaults(file, MTU);
    let cfg = enc.get_config().serialize();
    let object: [u8; 32] = Sha256::digest(file).into();
    let blocks = enc.get_block_encoders();
    let sources: Vec<Vec<EncodingPacket>> = blocks.iter().map(|b| b.source_packets()).collect();
    let mut rep = DelugeReport::default();
    if sequential {
        for (i, pkt) in enc.get_encoded_packets(repair).iter().enumerate() {
            rep.target = rep.target.saturating_add(1);
            let path = dir.join(format!("rain-{i:05}.rq"));
            let want = packet_v2(&cfg, &object, pkt);
            if path.exists() {
                if fs::read(&path).ok().as_deref() == Some(want.as_slice()) {
                    rep.kept += 1;
                } else {
                    rep.bad.push((
                        path,
                        "does not match this file's packet; left in place".into(),
                    ));
                }
            } else {
                write_new(&path, &want)?;
                rep.written += 1;
            }
        }
        return Ok(rep);
    }
    // Per block: ESIs of valid packets of this file, and every ESI any packet of
    // this file claims (valid or not), so new ones never collide.
    let mut valid: Vec<HashSet<u32>> = vec![HashSet::new(); blocks.len()];
    let mut taken: Vec<HashSet<u32>> = vec![HashSet::new(); blocks.len()];
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| err(e.to_string()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("rq"))
        .collect();
    files.sort();
    for p in files {
        let x = match fs::read(&p) {
            Ok(b) => match parse_packet(&b) {
                Ok(x) => x,
                Err(why) => {
                    rep.bad.push((p, why));
                    continue;
                }
            },
            Err(e) => {
                rep.bad.push((p, e.to_string()));
                continue;
            }
        };
        if x.cfg != cfg || x.object.is_some_and(|o| o != object) {
            rep.stray.push(p);
            continue;
        }
        let id = x.pkt.payload_id();
        let (sbn, esi) = (
            usize::from(id.source_block_number()),
            id.encoding_symbol_id(),
        );
        let (Some(block), Some(source)) = (blocks.get(sbn), sources.get(sbn)) else {
            rep.bad.push((p, "source block number out of range".into()));
            continue;
        };
        let want = expected_packet(block, source, esi)?;
        if want.serialize() != x.pkt.serialize() {
            if x.object.is_some() {
                taken[sbn].insert(esi);
                rep.bad.push((
                    p,
                    "symbol does not match this file (damaged or forged)".into(),
                ));
            } else {
                // v1 carries no object id: same parameters, but another file.
                rep.stray.push(p);
            }
            continue;
        }
        taken[sbn].insert(esi);
        if valid[sbn].insert(esi) {
            rep.kept += 1;
        } else {
            rep.duplicates += 1;
        }
    }
    for (sbn, (block, source)) in blocks.iter().zip(&sources).enumerate() {
        let k = source.len() as u32;
        let sbn_u8 = u8::try_from(sbn).map_err(|_| err("internal: too many source blocks"))?;
        let want = k.saturating_add(repair);
        rep.target = rep.target.saturating_add(want);
        let mut missing = want.saturating_sub(valid[sbn].len() as u32);
        // Fail closed instead of spinning forever if the ESI source keeps repeating
        // taken IDs (a stuck generator, or a block whose ESI space is used up).
        let mut misses = 0u32;
        while missing > 0 {
            let esi = next_esi()? & MAX_ESI;
            let path = dir.join(format!("rain-{sbn_u8:03}-{esi:08}.rq"));
            if taken[sbn].contains(&esi) || path.exists() {
                misses += 1;
                if misses >= ESI_MISS_LIMIT {
                    return Err(err(format!(
                        "could not find a fresh symbol ID for block {sbn} after {misses} tries; \
                         wrote {} new packet(s), {missing} still short",
                        rep.written
                    )));
                }
                continue;
            }
            misses = 0;
            let pkt = expected_packet(block, source, esi)?;
            debug_assert_eq!(pkt.payload_id(), &PayloadId::new(sbn_u8, esi));
            write_new(&path, &packet_v2(&cfg, &object, &pkt))?;
            taken[sbn].insert(esi);
            rep.written += 1;
            missing -= 1;
        }
    }
    Ok(rep)
}

/// Write a packet file whole (temp + rename), so a reader never sees half of one.
fn write_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut part = path.as_os_str().to_os_string();
    part.push(".part");
    let part = PathBuf::from(part);
    fs::write(&part, bytes).map_err(|e| err(e.to_string()))?;
    fs::rename(&part, path).map_err(|e| err(e.to_string()))
}

/// What gather did with the packet files in a folder.
#[derive(Debug, Default, Clone)]
pub struct FountainReport {
    /// Distinct packets used for the chosen object.
    pub packets: usize,
    /// Source symbols needed in total (sum of K over the source blocks).
    pub needed: u32,
    /// `.rq` files skipped as damaged / unreadable, with the reason.
    pub bad: Vec<(PathBuf, String)>,
    /// `.rq` files skipped because they belong to another file (stray).
    pub stray: Vec<PathBuf>,
    /// Duplicate packets (same block and ESI) ignored.
    pub duplicates: usize,
}

impl FountainReport {
    /// One line naming the skipped files, or empty.
    pub fn skipped_note(&self) -> String {
        let mut parts = Vec::new();
        if !self.bad.is_empty() {
            parts.push(format!("{} damaged", self.bad.len()));
        }
        if !self.stray.is_empty() {
            parts.push(format!("{} from another file", self.stray.len()));
        }
        if parts.is_empty() {
            String::new()
        } else {
            format!("skipped packet files: {}", parts.join(", "))
        }
    }
}

pub fn gather_fountain(dir: &Path) -> Result<Vec<u8>> {
    gather_fountain_report(dir).map(|(d, _)| d)
}

/// Rebuild from the `.rq` packets in `dir`. Damaged and stray packet files are
/// skipped (listed in the report); when too few are left the error says how many
/// more are needed ("have 4 of 10 needed, need 6 more").
/// Packets of the chosen object in a folder, deduplicated, with per-block counts.
struct Collected {
    rep: FountainReport,
    chosen: ([u8; 12], Option<[u8; 32]>),
    sizes: Vec<u32>,
    have: Vec<u32>,
    uniq: Vec<EncodingPacket>,
}

fn collect(dir: &Path) -> Result<Collected> {
    let mut rep = FountainReport::default();
    let mut files: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| err(e.to_string()))?
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("rq"))
        .collect();
    files.sort();
    let mut parsed = Vec::new();
    for p in files {
        match fs::read(&p) {
            Ok(b) => match parse_packet(&b) {
                Ok(x) => parsed.push((p, x)),
                Err(why) => rep.bad.push((p, why)),
            },
            Err(e) => rep.bad.push((p, e.to_string())),
        }
    }
    if parsed.is_empty() {
        let note = rep.skipped_note();
        return Err(err(if note.is_empty() {
            "no .rq fountain packets here".to_string()
        } else {
            format!("no usable .rq fountain packets here ({note})")
        }));
    }
    // Choose the object: the v2 object with the most packets, else the commonest v1 config.
    let mut by_obj: BTreeMap<([u8; 12], [u8; 32]), usize> = BTreeMap::new();
    let mut by_cfg: BTreeMap<[u8; 12], usize> = BTreeMap::new();
    for (_, x) in &parsed {
        match x.object {
            Some(o) => *by_obj.entry((x.cfg, o)).or_default() += 1,
            None => *by_cfg.entry(x.cfg).or_default() += 1,
        }
    }
    let chosen: ([u8; 12], Option<[u8; 32]>) = match by_obj
        .iter()
        .max_by_key(|(k, n)| (**n, std::cmp::Reverse(**k)))
    {
        Some(((c, o), _)) => (*c, Some(*o)),
        None => match by_cfg
            .iter()
            .max_by_key(|(k, n)| (**n, std::cmp::Reverse(**k)))
        {
            Some((c, _)) => (*c, None),
            None => return Err(err("no .rq fountain packets here")),
        },
    };
    // v2 packets of the chosen object first; old v1 packets with the same transmission
    // parameters after them (they carry no object id; the final check still applies).
    let mut ordered: Vec<EncodingPacket> = Vec::new();
    let mut v1_tail: Vec<EncodingPacket> = Vec::new();
    for (p, x) in parsed {
        if x.cfg != chosen.0 {
            rep.stray.push(p);
            continue;
        }
        match (x.object, chosen.1) {
            (Some(o), Some(c)) if o == c => ordered.push(x.pkt),
            (Some(_), _) => rep.stray.push(p),
            (None, _) => v1_tail.push(x.pkt),
        }
    }
    ordered.extend(v1_tail);
    let oti = ObjectTransmissionInformation::deserialize(&chosen.0);
    let sizes = block_sizes(&oti).ok_or_else(|| err("unusable transmission parameters"))?;
    rep.needed = sizes.iter().sum();
    let mut seen: HashSet<(u8, u32)> = HashSet::new();
    let mut have = vec![0u32; sizes.len()];
    let mut uniq = Vec::with_capacity(ordered.len());
    for pkt in ordered {
        let id = pkt.payload_id();
        if seen.insert((id.source_block_number(), id.encoding_symbol_id())) {
            have[usize::from(id.source_block_number())] += 1;
            uniq.push(pkt);
        } else {
            rep.duplicates += 1;
        }
    }
    Ok(Collected {
        rep,
        chosen,
        sizes,
        have,
        uniq,
    })
}

pub fn gather_fountain_report(dir: &Path) -> Result<(Vec<u8>, FountainReport)> {
    let Collected {
        mut rep,
        chosen,
        sizes,
        have,
        uniq,
    } = collect(dir)?;
    rep.packets = uniq.len();
    let mut dec = Decoder::new(ObjectTransmissionInformation::deserialize(&chosen.0));
    let mut out = None;
    for pkt in uniq {
        if let Some(data) = dec.decode(pkt) {
            out = Some(data);
            break;
        }
    }
    let note = rep.skipped_note();
    let note = if note.is_empty() {
        String::new()
    } else {
        format!("; {note}")
    };
    let Some(data) = out else {
        let usable: u32 = have.iter().zip(&sizes).map(|(h, k)| (*h).min(*k)).sum();
        let more: u32 = have
            .iter()
            .zip(&sizes)
            .map(|(h, k)| k.saturating_sub(*h))
            .sum();
        return Err(err(if more > 0 {
            format!(
                "not enough fountain packets yet: have {usable} of {} needed, need {more} more (keep raining){note}",
                rep.needed
            )
        } else {
            format!(
                "not enough fountain packets yet: have {} for {} needed; RaptorQ sometimes needs 1-2 extra, keep raining{note}",
                rep.packets, rep.needed
            )
        }));
    };
    if let Some(want) = chosen.1 {
        let got: [u8; 32] = Sha256::digest(&data).into();
        if got != want {
            return Err(err(
                "rebuilt bytes do not match the packets' object SHA-256 (forged or mixed packets); nothing written",
            ));
        }
    }
    Ok((data, rep))
}

/// Magic word at the start of a receiver report line (`gather --report`).
pub const NAK_MAGIC: &str = "SGNAK1";

/// Compact receiver report (deferred-NAK style, `sigil gather --report`): one short
/// ASCII line `SGNAK1 <object-id-prefix> <blocks> <have>/<needed> <need-list>` that fits
/// in one uplink packet. `<need-list>` gives, per source block, how many more packets
/// that block needs (K minus the distinct packets held, never negative), run-length
/// coded as comma-separated `count*value` or `value` items. Needs v2 packets (they carry
/// the object id). Reports what is here; it does not claim the data rebuilds.
/// How far a fountain folder got, for `gather --partial`. Never fails: a folder with no
/// usable packets reports zeros (damaged files counted, never as progress).
#[derive(Debug, Clone, Default)]
pub struct FountainProgress {
    /// Distinct packets of the chosen object (duplicates, damaged and stray not counted).
    pub packets_accepted: usize,
    /// Accepted packets that count toward a block (capped at each block's K).
    pub usable: u32,
    /// Source symbols needed in total.
    pub needed: u32,
    /// Packets still missing (at least; RaptorQ may want 1-2 extra).
    pub more: u32,
    pub blocks: usize,
    pub damaged: usize,
    pub stray: usize,
    pub duplicates: usize,
    /// The `gather --report` line, when the packets carry an object id.
    pub report: Option<String>,
}

pub fn fountain_progress(dir: &Path) -> FountainProgress {
    match collect(dir) {
        Ok(c) => {
            let usable: u32 = c.have.iter().zip(&c.sizes).map(|(h, k)| (*h).min(*k)).sum();
            let more: u32 = c
                .have
                .iter()
                .zip(&c.sizes)
                .map(|(h, k)| k.saturating_sub(*h))
                .sum();
            let report = c.chosen.1.map(|obj| {
                let need: Vec<u32> = c
                    .have
                    .iter()
                    .zip(&c.sizes)
                    .map(|(h, k)| k.saturating_sub(*h))
                    .collect();
                format_report(&obj, &need, usable, c.rep.needed)
            });
            FountainProgress {
                packets_accepted: c.uniq.len(),
                usable,
                needed: c.rep.needed,
                more,
                blocks: c.sizes.len(),
                damaged: c.rep.bad.len(),
                stray: c.rep.stray.len(),
                duplicates: c.rep.duplicates,
                report,
            }
        }
        Err(_) => FountainProgress {
            damaged: fs::read_dir(dir)
                .map(|rd| {
                    rd.flatten()
                        .filter(|e| e.path().extension().and_then(|x| x.to_str()) == Some("rq"))
                        .count()
                })
                .unwrap_or(0),
            ..FountainProgress::default()
        },
    }
}

pub fn receiver_report(dir: &Path) -> Result<String> {
    let c = collect(dir)?;
    let Some(obj) = c.chosen.1 else {
        return Err(err(
            "these are old v1 packets (no object id); --report needs packets from a current `deluge --fountain`",
        ));
    };
    let need: Vec<u32> = c
        .have
        .iter()
        .zip(&c.sizes)
        .map(|(h, k)| k.saturating_sub(*h))
        .collect();
    let usable: u32 = c.have.iter().zip(&c.sizes).map(|(h, k)| (*h).min(*k)).sum();
    let needed: u32 = c.sizes.iter().sum();
    Ok(format_report(&obj, &need, usable, needed))
}

/// Hex of the first 8 bytes of the object SHA-256 (the report's object id).
fn obj_prefix(obj: &[u8; 32]) -> String {
    obj[..8].iter().map(|b| format!("{b:02x}")).collect()
}

fn format_report(obj: &[u8; 32], need: &[u32], usable: u32, needed: u32) -> String {
    let mut items: Vec<String> = Vec::new();
    let mut i = 0;
    while i < need.len() {
        let v = need[i];
        let mut run = 1;
        while i + run < need.len() && need[i + run] == v {
            run += 1;
        }
        items.push(if run == 1 {
            v.to_string()
        } else {
            format!("{run}*{v}")
        });
        i += run;
    }
    format!(
        "{NAK_MAGIC} {} {} {usable}/{needed} {}",
        obj_prefix(obj),
        need.len(),
        items.join(",")
    )
}

/// Parse a receiver report and check it is for `file` (object id and block count must
/// match, or it is refused). Returns the per-block missing counts.
pub fn parse_report_for(file: &[u8], report: &str) -> Result<Vec<u32>> {
    let bad = || {
        err("not a Sigil receiver report (expected `SGNAK1 <id> <blocks> <have>/<need> <list>`)")
    };
    let parts: Vec<&str> = report.split_whitespace().collect();
    if parts.len() != 5 || parts[0] != NAK_MAGIC {
        return Err(bad());
    }
    let object: [u8; 32] = Sha256::digest(file).into();
    if parts[1] != obj_prefix(&object) {
        return Err(err(
            "this report is for a different file (object id does not match); nothing written",
        ));
    }
    let blocks: usize = parts[2].parse().map_err(|_| bad())?;
    let enc = Encoder::with_defaults(file, MTU);
    let sizes: Vec<u32> = enc
        .get_block_encoders()
        .iter()
        .map(|b| b.source_packets().len() as u32)
        .collect();
    if blocks != sizes.len() {
        return Err(err(
            "report block count does not match this file; nothing written",
        ));
    }
    let mut need = Vec::with_capacity(blocks);
    for item in parts[4].split(',') {
        let (run, v) = match item.split_once('*') {
            Some((r, v)) => (
                r.parse::<usize>().map_err(|_| bad())?,
                v.parse::<u32>().map_err(|_| bad())?,
            ),
            None => (1, item.parse::<u32>().map_err(|_| bad())?),
        };
        if run == 0 || need.len() + run > blocks {
            return Err(bad());
        }
        need.extend(std::iter::repeat_n(v, run));
    }
    if need.len() != blocks {
        return Err(bad());
    }
    for (n, k) in need.iter().zip(&sizes) {
        if n > k {
            return Err(err(
                "report asks for more packets than a block has source symbols; refused",
            ));
        }
    }
    Ok(need)
}

/// Answer a receiver report: write exactly the missing count of fresh random-ESI
/// packets per block of `file` into `dir` (never overwriting). Returns packets written.
pub fn deluge_answer_report(file: &[u8], dir: &Path, report: &str) -> Result<u32> {
    let need = parse_report_for(file, report)?;
    answer_with(file, dir, &need, &mut random_esi)
}

fn answer_with(
    file: &[u8],
    dir: &Path,
    need: &[u32],
    next_esi: &mut dyn FnMut() -> Result<u32>,
) -> Result<u32> {
    fs::create_dir_all(dir).map_err(|e| err(e.to_string()))?;
    let enc = Encoder::with_defaults(file, MTU);
    let cfg = enc.get_config().serialize();
    let object: [u8; 32] = Sha256::digest(file).into();
    let mut written = 0u32;
    for (sbn, (block, n)) in enc.get_block_encoders().iter().zip(need).enumerate() {
        let source = block.source_packets();
        let k = source.len() as u32;
        let sbn_u8 = u8::try_from(sbn).map_err(|_| err("internal: too many source blocks"))?;
        let mut taken = HashSet::new();
        let mut left = *n;
        while left > 0 {
            // Fresh repair symbols only (ESI >= K): the receiver may hold any source ones.
            let esi = next_esi()? & MAX_ESI;
            if esi < k || !taken.insert(esi) {
                continue;
            }
            let path = dir.join(format!("rain-{sbn_u8:03}-{esi:08}.rq"));
            if path.exists() {
                continue;
            }
            let pkt = expected_packet(block, &source, esi)?;
            write_new(&path, &packet_v2(&cfg, &object, &pkt))?;
            written += 1;
            left -= 1;
        }
    }
    Ok(written)
}

pub fn is_fountain_dir(dir: &Path) -> bool {
    fs::read_dir(dir)
        .ok()
        .into_iter()
        .flatten()
        .flatten()
        .any(|e| e.path().extension().and_then(|x| x.to_str()) == Some("rq"))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        use std::sync::atomic::{AtomicU64, Ordering};
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let d = std::env::temp_dir().join(format!(
            "sigil-ft-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn mark(n: usize) -> Vec<u8> {
        let mut x = 0x9e3779b97f4a7c15u64;
        let data: Vec<u8> = (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        crate::seal(&data, crate::Mode::Glyph, None, "f.bin", false).unwrap()
    }

    fn rq_files(d: &Path) -> Vec<PathBuf> {
        let mut v: Vec<_> = fs::read_dir(d)
            .unwrap()
            .flatten()
            .map(|e| e.path())
            .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("rq"))
            .collect();
        v.sort();
        v
    }

    fn esi_of(p: &Path) -> (u8, u32) {
        let x = parse_packet(&fs::read(p).unwrap()).unwrap();
        (
            x.pkt.payload_id().source_block_number(),
            x.pkt.payload_id().encoding_symbol_id(),
        )
    }

    #[test]
    fn report_for_100_blocks_fits_in_1kib() {
        let obj = [7u8; 32];
        // Worst case: every block needs a different (large) count, so no runs compress.
        let need: Vec<u32> = (0..100u32).map(|i| 56_403 - i).collect();
        let line = format_report(&obj, &need, 1_000_000, 5_640_300);
        assert!(line.len() <= 1024, "{} bytes", line.len());
        let all_done = format_report(&obj, &[0; 100], 10, 10);
        assert!(all_done.ends_with(" 100*0"), "{all_done}");
    }

    #[test]
    fn report_round_trip_answers_exact_missing_and_rebuilds() {
        let m = mark(200_000);
        let full = scratch("nak-full");
        deluge_fountain(&m, &full, 6).unwrap();
        let rx = scratch("nak-rx");
        // Receiver keeps only 5 packets: far short of K.
        for p in rq_files(&full).into_iter().take(5) {
            fs::copy(&p, rx.join(p.file_name().unwrap())).unwrap();
        }
        let line = receiver_report(&rx).unwrap();
        assert!(line.starts_with("SGNAK1 ") && line.len() <= 1024, "{line}");
        let need = parse_report_for(&m, &line).unwrap();
        let sizes: Vec<u32> = Encoder::with_defaults(&m, MTU)
            .get_block_encoders()
            .iter()
            .map(|b| b.source_packets().len() as u32)
            .collect();
        let want: u32 = sizes.iter().sum::<u32>() - 5;
        assert_eq!(need.iter().sum::<u32>(), want);
        // Sender answers into the receiver's folder: exactly the missing count.
        let mut seed = 0x1234_5678u64;
        let mut next = || {
            seed ^= seed << 13;
            seed ^= seed >> 7;
            seed ^= seed << 17;
            Ok(seed as u32)
        };
        let wrote = answer_with(&m, &rx, &need, &mut next).unwrap();
        assert_eq!(wrote, want);
        let after = receiver_report(&rx).unwrap();
        assert!(
            after.ends_with(&format!(" {}*0", sizes.len())) || after.ends_with(" 0"),
            "{after}"
        );
        // RaptorQ at exactly K almost always decodes; top up 2 more if this seed is unlucky.
        if gather_fountain(&rx).is_err() {
            answer_with(&m, &rx, &vec![2; sizes.len()], &mut next).unwrap();
        }
        assert_eq!(gather_fountain(&rx).unwrap(), m);
    }

    #[test]
    fn report_for_other_file_or_garbage_is_refused() {
        let m = mark(50_000);
        let d = scratch("nak-other");
        deluge_fountain(&m, &d, 1).unwrap();
        let line = receiver_report(&d).unwrap();
        let other = mark(60_000);
        assert!(parse_report_for(&other, &line).is_err());
        assert!(parse_report_for(&m, "SGNAK1 zz 1 0/1 1").is_err());
        assert!(parse_report_for(&m, "hello").is_err());
        let id = line.split_whitespace().nth(1).unwrap();
        assert!(parse_report_for(&m, &format!("SGNAK1 {id} 1 0/1 99999999")).is_err());
        assert!(parse_report_for(&m, &format!("SGNAK1 {id} 1 0/1 2*0")).is_err());
        let out = scratch("nak-other-out");
        assert!(deluge_answer_report(&other, &out, &line).is_err());
        assert!(rq_files(&out).is_empty());
    }

    #[test]
    fn random_esis_span_the_24_bit_space_and_round_trip() {
        let m = mark(200_000);
        let d = scratch("rand");
        let n = deluge_fountain(&m, &d, 4).unwrap();
        let files = rq_files(&d);
        assert_eq!(files.len() as u32, n);
        let esis: Vec<u32> = files.iter().map(|p| esi_of(p).1).collect();
        assert!(esis.iter().all(|e| *e <= MAX_ESI));
        // With K small and 2^24 choices, random ESIs land far above the old 0..K+extra.
        assert!(esis.iter().any(|e| *e > 1_000_000), "{esis:?}");
        let (back, rep) = gather_fountain_report(&d).unwrap();
        assert_eq!(back, m);
        assert!(rep.bad.is_empty() && rep.stray.is_empty());
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn sequential_keeps_the_old_order() {
        let m = mark(100_000);
        let d = scratch("seq");
        deluge_fountain_opts(&m, &d, 3, true).unwrap();
        let files = rq_files(&d);
        let k = rq_files(&d).len() as u32 - 3;
        let esis: Vec<u32> = files.iter().map(|p| esi_of(p).1).collect();
        assert_eq!(esis, (0..k + 3).collect::<Vec<_>>());
        assert_eq!(gather_fountain(&d).unwrap(), m);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn pooled_partial_shares_from_independent_senders_rebuild() {
        let m = mark(300_000);
        let (a, b, pool) = (scratch("a"), scratch("b"), scratch("pool"));
        deluge_fountain(&m, &a, 0).unwrap();
        deluge_fountain(&m, &b, 0).unwrap();
        let fa = rq_files(&a);
        let k = fa.len();
        assert!(k >= 4, "need a multi-symbol object, got k={k}");
        // Each sender alone shares only ~60%: not enough.
        let take = k * 6 / 10;
        for p in fa.iter().take(take) {
            fs::copy(p, pool.join(p.file_name().unwrap())).unwrap();
        }
        let e = gather_fountain(&pool).unwrap_err().to_string();
        assert!(
            e.contains(&format!(
                "have {take} of {k} needed, need {} more",
                k - take
            )),
            "{e}"
        );
        for p in rq_files(&b).iter().take(take) {
            fs::copy(p, pool.join(p.file_name().unwrap())).unwrap();
        }
        // Pooled, the two partial shares overlap in (almost) nothing and rebuild.
        let (back, rep) = gather_fountain_report(&pool).unwrap();
        assert_eq!(back, m);
        assert!(
            rep.duplicates <= 1,
            "random ESIs should rarely collide: {}",
            rep.duplicates
        );
        // Sequential senders overlap completely: the same pooling is still short.
        let (sa, sb, sp) = (scratch("sa"), scratch("sb"), scratch("sp"));
        deluge_fountain_opts(&m, &sa, 0, true).unwrap();
        deluge_fountain_opts(&m, &sb, 0, true).unwrap();
        for (i, p) in rq_files(&sa).iter().take(take).enumerate() {
            fs::copy(p, sp.join(format!("a-{i}.rq"))).unwrap();
        }
        for (i, p) in rq_files(&sb).iter().take(take).enumerate() {
            fs::copy(p, sp.join(format!("b-{i}.rq"))).unwrap();
        }
        let e = gather_fountain(&sp).unwrap_err().to_string();
        assert!(e.contains("need"), "{e}");
        for d in [a, b, pool, sa, sb, sp] {
            let _ = fs::remove_dir_all(&d);
        }
    }

    #[test]
    fn rerun_with_the_same_extra_is_a_no_op_and_still_rebuilds() {
        let m = mark(150_000);
        let d = scratch("overlap");
        deluge_fountain(&m, &d, 2).unwrap();
        let first = rq_files(&d);
        let rep = deluge_fountain_report(&m, &d, 2, false).unwrap();
        // --extra is a target: the folder already has K + 2, so nothing is written.
        assert_eq!((rep.written, rep.kept), (0, first.len() as u32));
        assert_eq!(rq_files(&d), first);
        let (back, _) = gather_fountain_report(&d).unwrap();
        assert_eq!(back, m);
        let _ = fs::remove_dir_all(&d);
    }

    fn distinct_esis(d: &Path) -> HashSet<(u8, u32)> {
        rq_files(d).iter().map(|p| esi_of(p)).collect()
    }

    #[test]
    fn random_extra_tops_up_to_the_target_instead_of_adding() {
        let m = mark(150_000);
        let d = scratch("topup");
        deluge_fountain(&m, &d, 2).unwrap();
        let k = rq_files(&d).len() - 2;
        let rep = deluge_fountain_report(&m, &d, 5, false).unwrap();
        assert_eq!(rq_files(&d).len(), k + 5);
        assert_eq!(
            (rep.target, rep.kept, rep.written),
            (k as u32 + 5, k as u32 + 2, 3)
        );
        assert!(rep.bad.is_empty() && rep.stray.is_empty());
        // No ESI collides: every file is a distinct (block, ESI).
        assert_eq!(distinct_esis(&d).len(), k + 5);
        // Repeat: no-op. A smaller --extra: also no-op (never deletes).
        let before = rq_files(&d);
        for extra in [5, 3, 0] {
            let rep = deluge_fountain_report(&m, &d, extra, false).unwrap();
            assert_eq!((rep.written, rep.kept), (0, k as u32 + 5));
        }
        assert_eq!(rq_files(&d), before);
        // Still decodes after the top-up.
        assert_eq!(gather_fountain(&d).unwrap(), m);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn random_top_up_with_a_stuck_esi_source_fails_closed() {
        let m = mark(100_000);
        let d = scratch("stuck");
        // A generator that always returns the same ID: the first packet lands, then
        // every later pick collides. Must error, not hang, and never over-count.
        let mut gen = || Ok(7u32);
        let e = deluge_fountain_with(&m, &d, 2, false, &mut gen);
        assert!(e.is_err(), "stuck generator must fail closed");
        assert_eq!(rq_files(&d).len(), 1);
        // A healthy source then tops the same folder up to exactly the target.
        let rep = deluge_fountain_report(&m, &d, 2, false).unwrap();
        assert_eq!(rep.kept, 1);
        assert_eq!(rep.target as usize, rq_files(&d).len());
        assert_eq!(gather_fountain(&d).unwrap(), m);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn sequential_extra_still_tops_up() {
        let m = mark(100_000);
        let d = scratch("seqtop");
        deluge_fountain_opts(&m, &d, 2, true).unwrap();
        let k = rq_files(&d).len() as u32 - 2;
        let rep = deluge_fountain_report(&m, &d, 5, true).unwrap();
        assert_eq!((rep.target, rep.kept, rep.written), (k + 5, k + 2, 3));
        let esis: Vec<u32> = rq_files(&d).iter().map(|p| esi_of(p).1).collect();
        assert_eq!(esis, (0..k + 5).collect::<Vec<_>>());
        let rep = deluge_fountain_report(&m, &d, 5, true).unwrap();
        assert_eq!(rep.written, 0);
        assert_eq!(gather_fountain(&d).unwrap(), m);
        let _ = fs::remove_dir_all(&d);
    }

    /// Rewrite one packet's symbol and recompute its (unkeyed) checksum.
    fn forge(p: &Path) {
        let b = fs::read(p).unwrap();
        let end = b.len() - 32;
        let mut body = b[..end].to_vec();
        body[60] ^= 0xFF;
        let h: [u8; 32] = Sha256::digest(&body).into();
        body.extend_from_slice(&h);
        fs::write(p, body).unwrap();
    }

    #[test]
    fn top_up_does_not_count_damaged_forged_or_stray_packets() {
        let m = mark(150_000);
        let d = scratch("toptamper");
        deluge_fountain(&m, &d, 2).unwrap();
        let files = rq_files(&d);
        let k = files.len() as u32 - 2;
        // One bit flip (checksum fails), one forgery (checksum recomputed), one stray.
        let mut b = fs::read(&files[0]).unwrap();
        b[60] ^= 0x01;
        fs::write(&files[0], &b).unwrap();
        forge(&files[1]);
        let forged = fs::read(&files[1]).unwrap();
        let o = scratch("topother");
        deluge_fountain(&mark(90_000), &o, 0).unwrap();
        fs::copy(&rq_files(&o)[0], d.join("zz-stray.rq")).unwrap();
        let rep = deluge_fountain_report(&m, &d, 2, false).unwrap();
        assert_eq!((rep.kept, rep.written, rep.target), (k, 2, k + 2));
        assert_eq!(rep.bad.len(), 2, "{:?}", rep.bad);
        assert!(
            rep.bad.iter().any(|(_, w)| w.contains("forged")),
            "{:?}",
            rep.bad
        );
        assert_eq!(rep.stray.len(), 1);
        // Nothing already there was overwritten.
        assert_eq!(fs::read(&files[0]).unwrap(), b);
        assert_eq!(fs::read(&files[1]).unwrap(), forged);
        // Existing design: the forged packet makes gather fail closed...
        let e = gather_fountain(&d).unwrap_err().to_string();
        assert!(e.contains("do not match"), "{e}");
        // ...and without it the topped-up folder rebuilds (damaged + stray skipped).
        fs::remove_file(&files[1]).unwrap();
        let (back, rep) = gather_fountain_report(&d).unwrap();
        assert_eq!(back, m);
        assert_eq!((rep.bad.len(), rep.stray.len()), (1, 1));
        let _ = fs::remove_dir_all(&d);
        let _ = fs::remove_dir_all(&o);
    }

    #[test]
    fn sequential_top_up_reports_a_mismatched_file_and_leaves_it() {
        let m = mark(100_000);
        let d = scratch("seqtamper");
        deluge_fountain_opts(&m, &d, 1, true).unwrap();
        let p = d.join("rain-00000.rq");
        forge(&p);
        let forged = fs::read(&p).unwrap();
        let rep = deluge_fountain_report(&m, &d, 1, true).unwrap();
        assert_eq!(rep.written, 0);
        assert_eq!(rep.kept + 1, rep.target);
        assert_eq!(rep.bad.len(), 1);
        assert_eq!(fs::read(&p).unwrap(), forged);
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn damaged_truncated_and_stray_packets_are_skipped() {
        let m = mark(200_000);
        let other = mark(90_000);
        let d = scratch("skip");
        deluge_fountain(&m, &d, 6).unwrap();
        let files = rq_files(&d);
        // bit flip in one, truncate another, garbage, an empty .rq, a 17-byte v1 stub
        let mut b = fs::read(&files[0]).unwrap();
        b[60] ^= 0x01;
        fs::write(&files[0], b).unwrap();
        let b = fs::read(&files[1]).unwrap();
        fs::write(&files[1], &b[..b.len() / 2]).unwrap();
        fs::write(d.join("junk.rq"), b"hello").unwrap();
        fs::write(d.join("empty.rq"), b"").unwrap();
        let mut stub = FT_MAGIC.to_vec();
        stub.push(1);
        stub.extend_from_slice(&[0u8; 12]);
        fs::write(d.join("stub.rq"), &stub).unwrap();
        // stray packets of a different file
        let o = scratch("other");
        deluge_fountain(&other, &o, 0).unwrap();
        for (i, p) in rq_files(&o).iter().take(2).enumerate() {
            fs::copy(p, d.join(format!("zz-stray-{i}.rq"))).unwrap();
        }
        let (back, rep) = gather_fountain_report(&d).unwrap();
        assert_eq!(back, m);
        assert_eq!(rep.bad.len(), 5, "{:?}", rep.bad);
        assert_eq!(rep.stray.len(), 2);
        assert!(rep.skipped_note().contains("5 damaged"));
        let _ = fs::remove_dir_all(&d);
        let _ = fs::remove_dir_all(&o);
    }

    #[test]
    fn forged_packet_with_valid_checksum_fails_closed() {
        let m = mark(120_000);
        let d = scratch("forge");
        deluge_fountain_opts(&m, &d, 0, true).unwrap();
        // Rewrite one packet's symbol and recompute its (unkeyed) checksum.
        let p = &rq_files(&d)[0];
        let b = fs::read(p).unwrap();
        let end = b.len() - 32;
        let mut body = b[..end].to_vec();
        body[60] ^= 0xFF;
        let h: [u8; 32] = Sha256::digest(&body).into();
        body.extend_from_slice(&h);
        fs::write(p, body).unwrap();
        let e = gather_fountain(&d).unwrap_err().to_string();
        assert!(e.contains("do not match"), "{e}");
        let _ = fs::remove_dir_all(&d);
    }

    #[test]
    fn hostile_headers_do_not_panic() {
        let d = scratch("hostile");
        // block number out of range, absurd transfer length, zero symbol size
        let m = mark(50_000);
        deluge_fountain_opts(&m, &d, 0, true).unwrap();
        let good = fs::read(&rq_files(&d)[0]).unwrap();
        for (at, val) in [(49usize, 0xFFu8), (5, 0xFF), (11, 0), (12, 0)] {
            let mut b = good[..good.len() - 32].to_vec();
            b[at] = val;
            let h: [u8; 32] = Sha256::digest(&b).into();
            b.extend_from_slice(&h);
            let _ = parse_packet(&b);
        }
        let _ = fs::remove_dir_all(&d);
    }
}
