//! Quick damage scan before a repair: what kind of damage, which repair path, and a
//! rough, padded time estimate (R1 step 2, "scan → estimate → decide").
//!
//! The scan only *reads*. It grades every shard the same way `mend` does (CRC-good,
//! present but CRC-failed, or missing), then sorts the damage into a few plain kinds so a
//! later step can route to the best repair method. The kind is a **hint**: it never
//! decides whether a result is accepted. Every repair is still kept only if the full
//! check (Merkle root, plus the true name when not encrypted) passes.
//!
//! Time estimates come from a simple throughput model measured on the 8-core shared
//! box on 18 November 2026 (release build; see `docs/MEND-SCAN.md`). They are padded
//! high and spoken in coarse units, as the 11 November 2026 wait-UX notes ask. On other
//! machines they are unverified.

use crate::header::{self, GradedShard, Header};
use crate::packhead::{self, Src};
use crate::Result;
use std::path::Path;

/// What the damage looks like. A hint for choosing a repair method, never a verdict.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum DamageKind {
    /// Every shard passed its CRC check.
    Clean,
    /// The file ends early: only the last shards are missing.
    Truncated,
    /// One contiguous run of shards is missing or wiped (for example a bad sector run).
    OneRegion,
    /// Several shards fail their CRC but still hold data: scattered bit flips.
    Scattered,
    /// More than one of the above.
    Mixed,
}

impl DamageKind {
    /// Short machine name (used in JSON).
    pub fn code(self) -> &'static str {
        match self {
            DamageKind::Clean => "clean",
            DamageKind::Truncated => "truncated",
            DamageKind::OneRegion => "one-region",
            DamageKind::Scattered => "scattered",
            DamageKind::Mixed => "mixed",
        }
    }

    /// Plain-English description.
    pub fn words(self) -> &'static str {
        match self {
            DamageKind::Clean => "no damage found",
            DamageKind::Truncated => "the end of the file is missing (cut short)",
            DamageKind::OneRegion => "one damaged stretch (a wiped or unreadable area)",
            DamageKind::Scattered => "scattered small errors (bit rot)",
            DamageKind::Mixed => "mixed damage (more than one kind)",
        }
    }

    fn merge(self, other: DamageKind) -> DamageKind {
        match (self, other) {
            (DamageKind::Clean, o) | (o, DamageKind::Clean) => o,
            (a, b) if a == b => a,
            _ => DamageKind::Mixed,
        }
    }
}

/// Which repair `sigil mend` is expected to need.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum RepairPath {
    /// Nothing to repair.
    NotNeeded,
    /// The quick repair: enough whole shards pass their CRC.
    Quick,
    /// The deeper repair for bit rot; every column is within the error-correction limit
    /// even if all damaged shards were wrong in the same place.
    Deeper,
    /// The deeper repair, past that per-column limit: it may still work (scattered flips
    /// rarely line up) but can take longer and can fail.
    DeeperHard,
    /// Fewer usable shards than the minimum needed (wiped-looking shards count as gone):
    /// this copy alone very likely cannot be rebuilt. `mend` still makes the final call.
    NotEnough,
}

impl RepairPath {
    /// Short machine name (used in JSON).
    pub fn code(self) -> &'static str {
        match self {
            RepairPath::NotNeeded => "none",
            RepairPath::Quick => "quick",
            RepairPath::Deeper => "deeper",
            RepairPath::DeeperHard => "deeper-hard",
            RepairPath::NotEnough => "not-enough",
        }
    }

    /// Plain-English description.
    pub fn words(self) -> &'static str {
        match self {
            RepairPath::NotNeeded => "no repair needed",
            RepairPath::Quick => "the quick repair should be enough",
            RepairPath::Deeper => "needs the deeper repair for bit rot (should work)",
            RepairPath::DeeperHard => {
                "needs the deeper repair, and the damage is heavy: it may take longer and may not succeed"
            }
            RepairPath::NotEnough => {
                "probably too damaged to rebuild from this copy alone (another copy of the same Sigil can be combined with it)"
            }
        }
    }
}

/// Shard counts and the verdict for one seal (a whole `.sg1`, or one chunk star).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct SealScan {
    /// Shards in the seal.
    pub n: usize,
    /// Shards needed to rebuild.
    pub k: usize,
    /// Shards that pass their CRC.
    pub clean: usize,
    /// Shards present but failing their CRC.
    pub damaged: usize,
    /// Shards not found in the file.
    pub missing: usize,
    /// Damaged shards that look wiped (a long run of one repeated byte).
    pub wiped_looking: usize,
    /// The damage kind.
    pub kind: DamageKind,
    /// The repair path.
    pub path: RepairPath,
}

/// Result of scanning a file.
#[derive(Clone, Debug, PartialEq)]
pub struct RepairScan {
    /// Bytes in the file.
    pub file_len: u64,
    /// Seals scanned (1 for a single `.sg1`, the chunk-star count for a large-file pack).
    pub seals: usize,
    /// Seals that need some repair.
    pub torn: usize,
    /// Totals over all seals.
    pub clean: usize,
    /// Damaged shards over all seals.
    pub damaged: usize,
    /// Missing shards over all seals.
    pub missing: usize,
    /// Overall damage kind.
    pub kind: DamageKind,
    /// The hardest repair any seal needs.
    pub path: RepairPath,
    /// Padded estimate of the repair time in seconds (the check of clean parts included).
    pub est_secs: f64,
}

/// A repeated-byte run this long inside a CRC-failed shard reads as "wiped". Random or
/// compressed data almost never has one; plain data might, so it stays a hint.
const WIPE_RUN: usize = 64;

// Throughput model (bytes per second), measured on the shared 8-core box, 18 Nov 2026,
// release build, then rounded down. See docs/MEND-SCAN.md for the raw timings.
/// Checking clean data (CRC + Merkle hashing).
const CHECK_BPS: f64 = 50e6;
/// Quick repair of a torn seal.
const QUICK_BPS: f64 = 30e6;
/// Deeper repair, damage within the per-column limit.
const DEEPER_BPS: f64 = 20e6;
/// Deeper repair past the per-column limit (the 10 MB worst case took 0.84 s on 16 Nov).
const DEEPER_HARD_BPS: f64 = 5e6;
/// Padding on top of the model, so finishing early is the usual surprise.
const PAD: f64 = 1.5;

fn longest_run(b: &[u8]) -> usize {
    let mut best = 0usize;
    let mut cur = 0usize;
    let mut prev: Option<u8> = None;
    for &x in b {
        if Some(x) == prev {
            cur += 1;
        } else {
            cur = 1;
            prev = Some(x);
        }
        best = best.max(cur);
    }
    best
}

/// Grade one seal held in memory.
pub fn scan_seal(file: &[u8]) -> Result<SealScan> {
    let (h, prefix, _) = header::locate_header(file)?;
    Ok(grade(file, &h, prefix))
}

fn grade(file: &[u8], h: &Header, prefix: usize) -> SealScan {
    let n = h.n as usize;
    let k = h.k as usize;
    let graded = header::gather_graded_shards(file, h, prefix);
    let mut clean = 0usize;
    let mut damaged = 0usize;
    let mut missing = 0usize;
    let mut wiped_looking = 0usize;
    // Per shard: 0 good, 1 wiped or missing, 2 damaged but holding data.
    let mut state = Vec::with_capacity(n);
    for g in &graded {
        match g {
            GradedShard::Hard(_) => {
                clean += 1;
                state.push(0u8);
            }
            GradedShard::Soft(b, _) => {
                damaged += 1;
                if longest_run(b) >= WIPE_RUN.min(b.len().max(1)) {
                    wiped_looking += 1;
                    state.push(1);
                } else {
                    state.push(2);
                }
            }
            GradedShard::Missing => {
                missing += 1;
                state.push(1);
            }
        }
    }
    let bad: Vec<usize> = (0..n).filter(|&i| state[i] != 0).collect();
    let one_run = bad.windows(2).all(|w| w[1] == w[0] + 1);
    let tail_missing = missing > 0
        && damaged == 0
        && graded[n - missing..]
            .iter()
            .all(|g| matches!(g, GradedShard::Missing));
    let flips = state.iter().filter(|&&s| s == 2).count();
    let kind = if bad.is_empty() {
        DamageKind::Clean
    } else if tail_missing {
        DamageKind::Truncated
    } else if one_run && (flips == 0 || (bad.len() >= 2 && bad.len() < n)) {
        DamageKind::OneRegion
    } else if missing == 0 && wiped_looking == 0 {
        DamageKind::Scattered
    } else {
        DamageKind::Mixed
    };
    let glyph = h.mode() == crate::Mode::Glyph;
    let path = if bad.is_empty() {
        RepairPath::NotNeeded
    } else if glyph {
        // Glyph has no parity: every shard must be whole.
        RepairPath::NotEnough
    } else if clean >= k {
        RepairPath::Quick
    } else if clean + damaged - wiped_looking < k {
        // Wiped-looking shards are counted as gone: a long run of one byte carries no
        // trace of the original. (Plain data can contain such runs, so this is a hint;
        // `mend` still tries and decides.)
        RepairPath::NotEnough
    } else if missing + wiped_looking + 2 * (damaged - wiped_looking) <= n - k {
        RepairPath::Deeper
    } else {
        RepairPath::DeeperHard
    };
    SealScan {
        n,
        k,
        clean,
        damaged,
        missing,
        wiped_looking,
        kind,
        path,
    }
}

fn path_secs(path: RepairPath, bytes: u64) -> f64 {
    let b = bytes as f64;
    match path {
        RepairPath::NotNeeded | RepairPath::NotEnough => b / CHECK_BPS,
        RepairPath::Quick => b / QUICK_BPS,
        RepairPath::Deeper => b / QUICK_BPS + b / DEEPER_BPS,
        RepairPath::DeeperHard => b / QUICK_BPS + b / DEEPER_HARD_BPS,
    }
}

/// Fold per-seal results into a file-level scan.
fn summarize(file_len: u64, seals: &[(SealScan, u64)]) -> RepairScan {
    let mut out = RepairScan {
        file_len,
        seals: seals.len(),
        torn: 0,
        clean: 0,
        damaged: 0,
        missing: 0,
        kind: DamageKind::Clean,
        path: RepairPath::NotNeeded,
        est_secs: 0.0,
    };
    let mut secs = 0.0f64;
    for (s, bytes) in seals {
        out.clean += s.clean;
        out.damaged += s.damaged;
        out.missing += s.missing;
        if s.path != RepairPath::NotNeeded {
            out.torn += 1;
        }
        out.kind = out.kind.merge(s.kind);
        out.path = out.path.max(s.path);
        secs += path_secs(s.path, *bytes);
    }
    out.est_secs = secs * PAD;
    out
}

/// Scan a single seal held in memory.
pub fn scan_bytes(file: &[u8]) -> Result<RepairScan> {
    let s = scan_seal(file)?;
    Ok(summarize(file.len() as u64, &[(s, file.len() as u64)]))
}

/// Scan a file on disk: a single `.sg1` or a large-file work pack (one chunk star in
/// memory at a time). Folder packs and atlas bags are not scanned yet.
pub fn scan_path(path: &Path) -> Result<RepairScan> {
    if crate::is_atlas_file(path)
        || crate::is_sealed_dir_pack(path)
        || crate::is_plain_dir_pack(path)
    {
        return Err(crate::Error::Msg(
            "the repair scan covers single Sigils and large-file packs for now, not folder packs or atlas bags".into(),
        ));
    }
    if crate::is_work_pack(path) {
        let mut src = packhead::FileSrc::open(path)?;
        let layout = packhead::layout(&mut src)?;
        let mut seals = Vec::with_capacity(layout.stars.len());
        for (i, &(off, len)) in layout.stars.iter().enumerate() {
            let size = usize::try_from(len)
                .map_err(|_| crate::Error::Msg(format!("chunk star {i} is too large")))?;
            let mut buf = vec![0u8; size];
            src.read_at(off, &mut buf)?;
            let s = scan_seal(&buf).map_err(|e| {
                crate::Error::Msg(format!(
                    "chunk star {i} of {}: map unreadable ({e})",
                    layout.stars.len()
                ))
            })?;
            seals.push((s, len));
        }
        return Ok(summarize(src.size(), &seals));
    }
    let data = std::fs::read(path).map_err(|e| crate::Error::Msg(e.to_string()))?;
    scan_bytes(&data)
}

/// A coarse, padded duration in one unit ("under 10 seconds", "about 3 minutes").
pub fn coarse_time(secs: f64) -> String {
    if secs < 10.0 {
        return "under 10 seconds".into();
    }
    if secs < 90.0 {
        let s = ((secs / 10.0).ceil() * 10.0) as u64;
        return format!("about {s} seconds");
    }
    let mins = secs / 60.0;
    if mins < 90.0 {
        return format!("about {} minutes", mins.ceil() as u64);
    }
    let hours = mins / 60.0;
    format!("about {} hours", hours.ceil() as u64)
}

impl RepairScan {
    /// Plain-English lines for a person (no trailing newline).
    pub fn describe(&self) -> String {
        let mut s = format!("Scan: {}.", self.kind.words());
        if self.kind != DamageKind::Clean {
            s.push_str(&format!(
                " Shards: {} good, {} damaged, {} missing",
                self.clean, self.damaged, self.missing
            ));
            if self.seals > 1 {
                s.push_str(&format!(
                    " ({} of {} chunks need repair)",
                    self.torn, self.seals
                ));
            }
            s.push('.');
        }
        s.push_str(&format!("\nRepair: {}.", self.path.words()));
        if self.path != RepairPath::NotEnough && self.path != RepairPath::NotNeeded {
            s.push_str(&format!(
                "\nEstimated time: {} on a computer like the one this was measured on (a rough guess, padded high).",
                coarse_time(self.est_secs)
            ));
        }
        s
    }

    /// JSON object (no surrounding comma).
    pub fn json(&self) -> String {
        format!(
            "{{\"kind\":\"{}\",\"path\":\"{}\",\"seals\":{},\"torn\":{},\"clean\":{},\"damaged\":{},\"missing\":{},\"est_secs\":{:.1}}}",
            self.kind.code(),
            self.path.code(),
            self.seals,
            self.torn,
            self.clean,
            self.damaged,
            self.missing,
            self.est_secs
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{seal, Mode};

    fn data(n: usize) -> Vec<u8> {
        let mut x = 0x9E37_79B9_7F4A_7C15u64;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect()
    }

    fn sealed() -> (Vec<u8>, Header, usize) {
        let bytes = seal(&data(200_000), Mode::Seal, None, "a.bin", false).expect("seal");
        let (h, prefix, _) = header::locate_header(&bytes).expect("header");
        (bytes, h, prefix)
    }

    fn shard_body(h: &Header, prefix: usize, i: usize) -> std::ops::Range<usize> {
        let lead = if h.ember() { header::HEADER_SIZE } else { 0 }
            + if h.vow() { header::VOW_SIZE } else { 0 };
        let off = prefix + i * header::shard_stride(h) + lead;
        off..off + h.shard_len as usize
    }

    #[test]
    fn clean_file_needs_nothing() {
        let (b, h, _) = sealed();
        let s = scan_bytes(&b).expect("scan");
        assert_eq!(s.kind, DamageKind::Clean);
        assert_eq!(s.path, RepairPath::NotNeeded);
        assert_eq!(s.clean, h.n as usize);
        assert_eq!(s.torn, 0);
    }

    #[test]
    fn one_wiped_shard_is_one_region_quick() {
        let (mut b, h, p) = sealed();
        let r = shard_body(&h, p, 1);
        b[r].fill(0);
        let s = scan_bytes(&b).expect("scan");
        assert_eq!(s.kind, DamageKind::OneRegion);
        assert_eq!(s.path, RepairPath::Quick);
        assert_eq!(s.damaged, 1);
        assert!(crate::pieces::mend_bytes(&b).is_ok());
    }

    #[test]
    fn flips_in_every_shard_are_scattered_deeper() {
        let (mut b, h, p) = sealed();
        for i in 0..h.n as usize {
            let r = shard_body(&h, p, i);
            b[r.start + 17 + i * 31] ^= 0x10;
        }
        let s = scan_bytes(&b).expect("scan");
        assert_eq!(s.kind, DamageKind::Scattered);
        assert_eq!(s.clean, 0);
        assert_eq!(s.path, RepairPath::DeeperHard);
        // The scan's hint does not change the outcome: the deeper repair still checks.
        let (fixed, soft) = crate::pieces::mend_bytes_ex(&b, true).expect("deeper repair");
        assert!(soft);
        assert_eq!(crate::unseal(&fixed, None).expect("open"), data(200_000));
    }

    #[test]
    fn cut_short_is_truncated() {
        let (b, h, p) = sealed();
        let r = shard_body(&h, p, h.n as usize - 1);
        let s = scan_bytes(&b[..r.start]).expect("scan");
        assert_eq!(s.kind, DamageKind::Truncated);
        assert_eq!(s.missing, 1);
        assert_eq!(s.path, RepairPath::Quick);
    }

    #[test]
    fn too_few_shards_is_not_enough() {
        let (mut b, h, p) = sealed();
        let lost = h.n as usize - h.k as usize + 1;
        for i in 0..lost {
            let r = shard_body(&h, p, i);
            b[r].fill(0);
        }
        let s = scan_bytes(&b).expect("scan");
        assert_eq!(s.path, RepairPath::NotEnough);
        assert_eq!(s.kind, DamageKind::OneRegion);
        // Fail closed: mend refuses too.
        assert!(crate::pieces::mend_bytes_ex(&b, true).is_err());
    }

    #[test]
    fn wipe_plus_flips_is_mixed() {
        let (mut b, h, p) = sealed();
        let r = shard_body(&h, p, 0);
        b[r].fill(0);
        let r = shard_body(&h, p, 5);
        b[r.start + 3] ^= 1;
        let s = scan_bytes(&b).expect("scan");
        assert_eq!(s.kind, DamageKind::Mixed);
        assert_eq!(s.path, RepairPath::Quick);
    }

    #[test]
    fn coarse_units() {
        assert_eq!(coarse_time(3.0), "under 10 seconds");
        assert_eq!(coarse_time(41.0), "about 50 seconds");
        assert_eq!(coarse_time(150.0), "about 3 minutes");
        assert_eq!(coarse_time(4.0 * 3600.0), "about 4 hours");
    }

    #[test]
    fn garbage_is_an_error_not_a_verdict() {
        assert!(scan_bytes(&data(5000)).is_err());
        assert!(scan_bytes(&[]).is_err());
    }
}
