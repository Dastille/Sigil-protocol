//! What a damaged Sigil Archive's condition is, and what the user can do about it.
//!
//! Two jobs, kept apart:
//!
//! 1. **Assessment** ([`Condition`]): does the archive open as-is, will `sigil mend`
//!    repair it, or is this copy beyond repair? When fewer pieces pass their checksum
//!    than the archive needs, the only honest way to answer "will `sigil mend` repair it?"
//!    is to run the very repair `sigil mend` would run. A **probe** does that in memory:
//!    it never writes a file, runs on at most [`PROBE_THREADS`] threads, skips seals
//!    larger than [`PROBE_MAX_SEAL_BYTES`], and stops at a per-command time limit
//!    ([`ProbeBudget`], default [`DEFAULT_PROBE_SECS`] seconds, `SIGIL_SCRY_PROBE_SECS`;
//!    `0` turns probing off). A probe that is skipped or runs out of time yields
//!    [`Condition::Unconfirmed`] (exit [`EXIT_UNCONFIRMED`]), never a guess either way.
//!    [`Condition::Repairable`] (exit [`EXIT_REPAIRABLE`]) is reported only after the
//!    probe's repair passed the same full check `sigil mend` requires.
//!
//! 2. **Guidance** ([`Situation`] → [`Remedy`]): one table, [`remedies`], maps the kind of
//!    archive and the situation to the next steps that really exist for that case; each
//!    [`Remedy`] renders to one short line under "What you can try:". Placeholders are
//!    written `<like-this>`; everything else is printed exactly as it must be typed.
//!
//! User-facing words follow the approved names: Sigil Archive, Tome, Ward / Warded,
//! Channel / mana, Frost Rune.

use crate::keys::Identity;
use crate::mend_out::shell_word;
use crate::packhead::{self, Src};
use crate::Result;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::{Path, PathBuf};
use std::time::{Duration, Instant};

/// Exit code: damaged, will not open as-is, and `sigil mend` will repair it (a probe ran
/// the same repair and it passed the full check).
pub const EXIT_REPAIRABLE: i32 = 5;

/// Exit code: damaged and will not open as-is; this check did not find out whether
/// `sigil mend` can repair it (probe skipped or out of time). Run `sigil mend` to find out.
pub const EXIT_UNCONFIRMED: i32 = 6;

/// Environment variable: seconds one command may spend on repair probes (`0` = no probes).
pub const PROBE_SECS_ENV: &str = "SIGIL_SCRY_PROBE_SECS";

/// Default probe time limit per command, in seconds.
pub const DEFAULT_PROBE_SECS: u64 = 3;

/// Largest single seal a probe will try to repair, in bytes.
pub const PROBE_MAX_SEAL_BYTES: usize = 32 * 1024 * 1024;

/// CPU threads a probe may use (keeps its memory to about two decoded copies).
pub const PROBE_THREADS: usize = 2;

// ---------------------------------------------------------------------------------------
// Probe budget
// ---------------------------------------------------------------------------------------

/// Why a probe did not give an answer.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ProbeSkip {
    /// Probing is turned off (`SIGIL_SCRY_PROBE_SECS=0`).
    Disabled,
    /// The seal is larger than [`PROBE_MAX_SEAL_BYTES`].
    TooLarge,
    /// The command's probe time limit ran out.
    TimeLimit,
    /// Ctrl-C was pressed while probing.
    Stopped,
}

impl ProbeSkip {
    fn words(self) -> &'static str {
        match self {
            ProbeSkip::Disabled => "repair check turned off by SIGIL_SCRY_PROBE_SECS=0",
            ProbeSkip::TooLarge => "too large for a quick repair check",
            ProbeSkip::TimeLimit => "the quick repair check ran out of time",
            ProbeSkip::Stopped => "the repair check was stopped",
        }
    }
}

/// Time limit shared by every probe in one command. Created once per command and passed
/// down, so a Tome or large-file archive with many damaged parts cannot multiply it.
#[derive(Clone, Debug)]
pub struct ProbeBudget {
    deadline: Option<Instant>,
}

impl ProbeBudget {
    /// Budget of `secs` seconds from now; `0` turns probing off.
    pub fn with_secs(secs: u64) -> Self {
        ProbeBudget {
            deadline: (secs > 0).then(|| Instant::now() + Duration::from_secs(secs)),
        }
    }

    /// Budget from [`PROBE_SECS_ENV`] (default [`DEFAULT_PROBE_SECS`]). A value that is
    /// not a whole number of seconds is an error, never a silent default.
    pub fn from_env() -> Result<Self> {
        let secs = crate::repair_ctl::secs_setting(PROBE_SECS_ENV, DEFAULT_PROBE_SECS)?;
        Ok(Self::with_secs(secs))
    }

    /// A budget that never probes.
    pub fn disabled() -> Self {
        ProbeBudget { deadline: None }
    }

    /// Run the repair `sigil mend` would run on one seal, in memory, within the budget.
    fn probe(&mut self, seal: &[u8], mode: MendMode) -> Probe {
        let Some(deadline) = self.deadline else {
            return Probe::NotRun(ProbeSkip::Disabled);
        };
        if seal.len() > PROBE_MAX_SEAL_BYTES {
            return Probe::NotRun(ProbeSkip::TooLarge);
        }
        if Instant::now() >= deadline {
            return Probe::NotRun(ProbeSkip::TimeLimit);
        }
        let _limit = crate::repair_ctl::DeadlineScope::enter(Some(deadline));
        let mut stats = crate::pieces::SoftMendStats::default();
        let soft = mode == MendMode::Deep;
        match crate::pieces::mend_bytes_stats_threads(seal, soft, &mut stats, PROBE_THREADS) {
            // The same acceptance test every `sigil mend` path applies to a repaired seal.
            Ok((healed, _)) if !crate::work::star_torn(&healed) => Probe::Repairs,
            Ok(_) => Probe::Fails,
            Err(_) if crate::repair_ctl::stop_requested() => Probe::NotRun(ProbeSkip::Stopped),
            Err(_) if crate::repair_ctl::deadline_passed() => Probe::NotRun(ProbeSkip::TimeLimit),
            Err(_) => Probe::Fails,
        }
    }
}

enum Probe {
    Repairs,
    Fails,
    NotRun(ProbeSkip),
}

/// Which repair `sigil mend` runs for an archive; a probe must run the same one.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum MendMode {
    /// Quick repair, then the deeper repair for bit rot (plain `sigil mend`).
    Deep,
    /// Quick repair only (`--hard-only`, and the body of a Warded Tome).
    QuickOnly,
}

// ---------------------------------------------------------------------------------------
// Condition
// ---------------------------------------------------------------------------------------

/// The condition of an archive (or one part of it), worst first in [`Condition::rank`].
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Condition {
    /// Every piece intact; nothing to do.
    Healthy,
    /// Opens as-is (enough intact pieces); `sigil mend` restores full redundancy.
    Torn(String),
    /// Will not open as-is; a probe ran `sigil mend`'s repair and it passed the full check.
    Repairable(String),
    /// Will not open as-is; whether `sigil mend` can repair it was not found out.
    Unconfirmed {
        /// What is damaged.
        why: String,
        /// Why the probe gave no answer.
        skip: ProbeSkip,
    },
    /// This copy alone cannot be restored.
    Unrecoverable(String),
}

impl Condition {
    fn rank(&self) -> u8 {
        match self {
            Condition::Healthy => 0,
            Condition::Torn(_) => 1,
            Condition::Repairable(_) => 2,
            Condition::Unconfirmed { .. } => 3,
            Condition::Unrecoverable(_) => 4,
        }
    }

    /// The worse of two conditions (the first one on a tie).
    pub fn worse(self, other: Condition) -> Condition {
        if other.rank() > self.rank() {
            other
        } else {
            self
        }
    }

    /// True when `self` is strictly worse than `other`.
    pub(crate) fn is_worse_than(&self, other: &Condition) -> bool {
        self.rank() > other.rank()
    }

    /// Prefix every reason with `what: ` (for a part or member).
    pub(crate) fn within(self, what: &str) -> Condition {
        match self {
            Condition::Healthy => Condition::Healthy,
            Condition::Torn(w) => Condition::Torn(format!("{what}: {w}")),
            Condition::Repairable(w) => Condition::Repairable(format!("{what}: {w}")),
            Condition::Unconfirmed { why, skip } => Condition::Unconfirmed {
                why: format!("{what}: {why}"),
                skip,
            },
            Condition::Unrecoverable(w) => Condition::Unrecoverable(format!("{what}: {w}")),
        }
    }

    /// Exit code `scry` uses for this condition (0, 5, 6 or 2).
    pub fn exit_code(&self) -> i32 {
        match self {
            Condition::Healthy | Condition::Torn(_) => 0,
            Condition::Repairable(_) => EXIT_REPAIRABLE,
            Condition::Unconfirmed { .. } => EXIT_UNCONFIRMED,
            Condition::Unrecoverable(_) => 2,
        }
    }

    /// Why this copy cannot be restored, when it cannot.
    pub fn unrecoverable_reason(&self) -> Option<&str> {
        match self {
            Condition::Unrecoverable(w) => Some(w),
            _ => None,
        }
    }

    /// True when the archive opens as it is (healthy or merely torn).
    pub fn opens_as_is(&self) -> bool {
        matches!(self, Condition::Healthy | Condition::Torn(_))
    }

    /// The one-line verdict printed after the report, or `None` when it opens as-is.
    /// `mend` is the `sigil mend …` command for this archive.
    pub fn headline(&self, mend: &str) -> Option<String> {
        match self {
            Condition::Healthy | Condition::Torn(_) => None,
            Condition::Repairable(why) => Some(format!("damaged — run {mend} ({why})")),
            Condition::Unconfirmed { why, skip } => Some(format!(
                "damaged — run {mend} to find out whether it can be repaired ({why}; {})",
                skip.words()
            )),
            Condition::Unrecoverable(why) => Some(not_recoverable(why)),
        }
    }
}

/// The text `scry` / `verify` print (and report as the JSON `error`) for a copy that
/// cannot be restored.
pub fn not_recoverable(why: &str) -> String {
    format!("NOT recoverable ({why}): too damaged to restore from this copy alone")
}

/// Assess one classic seal held in memory.
pub fn assess_seal(seal: &[u8], mode: MendMode, budget: &mut ProbeBudget) -> Condition {
    let (h, merkle_ok, live, k, recovered) = match crate::verify(seal) {
        Ok(v) => v,
        Err(e) => return Condition::Unrecoverable(format!("unreadable: {e}")),
    };
    let n = h.n as usize;
    if live >= k && (merkle_ok || live < n || recovered) {
        // Opens as-is (unchanged from the checks `scry` always made).
        if live < n || recovered || !merkle_ok {
            return Condition::Torn(format!(
                "{live}/{n} shards intact (need {k}){}",
                if recovered {
                    ", header recovered from keystone"
                } else {
                    ""
                }
            ));
        }
        return match crate::pieces::canonical_check(seal) {
            Some(Ok(crate::pieces::Canon::Differs)) => Condition::Torn(
                "redundant copies (shard or key-wrap spares) are damaged (data still intact)"
                    .into(),
            ),
            Some(Err(e)) => Condition::Unrecoverable(format!("repair check failed: {e}")),
            _ => Condition::Healthy,
        };
    }
    // Will not open as-is: too few intact shards, or every shard passes its checksum but
    // the set does not match the archive's hash tree.
    let damaged = if live >= k {
        format!("all {n} shards pass their checksums but do not match the archive's hash tree")
    } else {
        format!("live={live}/{n} need={k}")
    };
    if h.mode() == crate::Mode::Glyph {
        // Glyph has no spare pieces: every one must be whole.
        return Condition::Unrecoverable(damaged);
    }
    if h.encrypted() && h.private_label() && crate::pieces::sgto_from_prefix(seal, &h).is_none() {
        return Condition::Unrecoverable(format!("{damaged}; key wrap damaged"));
    }
    if live < k {
        if mode == MendMode::QuickOnly {
            return Condition::Unrecoverable(damaged);
        }
        // The deeper repair needs `k` shards that still hold data (CRC-failed counts).
        match crate::repair_scan::scan_seal(seal) {
            Ok(s) if s.clean + s.damaged >= k => {}
            Ok(_) => return Condition::Unrecoverable(damaged),
            Err(e) => return Condition::Unrecoverable(format!("unreadable: {e}")),
        }
    }
    // Plain words for the "damaged" lines; `damaged` (with `live=X/N need=K`) stays the
    // NOT recoverable reason, as before.
    let plain = if live >= k {
        "the shards do not match the archive's hash tree".to_string()
    } else {
        format!("{live} of {n} shards intact, {k} needed")
    };
    match budget.probe(seal, mode) {
        Probe::Repairs => Condition::Repairable(format!("{plain}; the deeper repair restores it")),
        Probe::Fails => Condition::Unrecoverable(damaged),
        Probe::NotRun(skip) => Condition::Unconfirmed { why: plain, skip },
    }
}

/// Assess a classic seal or an in-memory large-file archive.
pub fn assess_star(star: &[u8], mode: MendMode, budget: &mut ProbeBudget) -> Condition {
    if star.starts_with(&crate::work::WORK_MAGIC) {
        return assess_pack(&mut packhead::MemSrc(star), mode, budget);
    }
    assess_seal(star, mode, budget)
}

/// Assess a large-file archive on disk, one part in memory at a time.
pub fn assess_pack_path(
    input: &Path,
    mode: MendMode,
    budget: &mut ProbeBudget,
) -> Result<Condition> {
    let mut src = packhead::FileSrc::open(input)?;
    Ok(assess_pack(&mut src, mode, budget))
}

/// Same layout, part list and facet checks as `work::mend_pack_path`, so a pack is
/// called repairable only when that repair would accept it.
fn assess_pack<S: Src>(src: &mut S, mode: MendMode, budget: &mut ProbeBudget) -> Condition {
    let l = match crate::work::mend_layout(src) {
        Ok(l) => l,
        Err(e) => return Condition::Unrecoverable(format!("large-file archive unreadable: {e}")),
    };
    if (l.stars.len() as u64) < u64::from(l.head.stars) {
        return Condition::Unrecoverable(format!(
            "only {} of {} parts present",
            l.stars.len(),
            l.head.stars
        ));
    }
    let facets = l.facets().map(<[[u8; 32]]>::to_vec);
    // Head source and framing_rebuilt come from mend_layout, the same function
    // `sigil mend` uses, so this is not a second opinion.
    let mut worst = match (l.source == crate::HeadSource::Intact, l.framing_rebuilt) {
        (true, false) => Condition::Healthy,
        (true, true) => Condition::Torn("length framing damaged (sigil mend rebuilds it)".into()),
        (false, false) => Condition::Torn("archive head damaged (sigil mend rebuilds it)".into()),
        (false, true) => Condition::Torn(
            "archive head and length framing damaged (sigil mend rebuilds them)".into(),
        ),
    };
    for (i, &(off, len)) in l.stars.iter().enumerate() {
        let Ok(len) = usize::try_from(len) else {
            return Condition::Unrecoverable(format!("part {i} has an impossible length"));
        };
        let mut part = vec![0u8; len];
        if src.read_at(off, &mut part).is_err() {
            return Condition::Unrecoverable(format!("part {i} is cut off"));
        }
        let seal = if l.guarded {
            packhead::seal_part(&part)
        } else {
            part.as_slice()
        };
        if let Some(f) = facets.as_ref().and_then(|f| f.get(i)) {
            match crate::locate_header(seal) {
                Ok((h, _, _)) if &h.digest == f => {}
                _ => {
                    return Condition::Unrecoverable(format!(
                        "part {i} does not match the archive's index (swapped or damaged)"
                    ))
                }
            }
        }
        worst = worst.worse(assess_seal(seal, mode, budget).within(&format!("part {i}")));
        if matches!(worst, Condition::Unrecoverable(_)) {
            return worst;
        }
    }
    worst
}

/// Assess a classic `.sg1` or large-file archive on disk with plain `sigil mend`'s repair.
pub fn assess_path(input: &Path, budget: &mut ProbeBudget) -> Result<Condition> {
    // A pack whose official head is gone is still a large-file archive when
    // recover_path (from_guards / from_facets, the same path unseal uses) can
    // lay it out. That check is the existing is_damaged_work_pack helper.
    if crate::is_work_pack(input) || crate::is_damaged_work_pack_or_limit(input) {
        return assess_pack_path(input, MendMode::Deep, budget);
    }
    // A classic seal with intact framing that opens as is is checked a window at a time.
    if let Some(c) = crate::classic::assess_path(input)? {
        return Ok(c);
    }
    let data = std::fs::read(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
    Ok(assess_star(&data, MendMode::Deep, budget))
}

// ---------------------------------------------------------------------------------------
// Tomes
// ---------------------------------------------------------------------------------------

/// Members of a plain Tome, sorted by condition (read one member at a time).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct TomeInspection {
    /// Why the Tome ends early, when it does (members after that point are unknown).
    pub truncated: Option<String>,
    /// Members that open as-is (healthy or torn), in Tome order.
    pub intact: Vec<String>,
    /// The members of `intact` that `sigil mend` would still tidy up.
    pub torn: Vec<String>,
    /// Members that will not open as-is but `sigil mend` repairs: `(path, why)`.
    pub repairable: Vec<(String, String)>,
    /// Members that will not open as-is, repair not confirmed: `(path, why)`.
    pub unconfirmed: Vec<(String, String)>,
    /// Why the first member in `unconfirmed` got no answer.
    pub unconfirmed_skip: Option<ProbeSkip>,
    /// Members this copy cannot restore: `(path, why)`.
    pub unrecoverable: Vec<(String, String)>,
}

impl TomeInspection {
    /// The Tome's overall condition.
    pub fn condition(&self) -> Condition {
        if let Some(why) = &self.truncated {
            return Condition::Unrecoverable(why.clone());
        }
        if let Some((rel, why)) = self.unrecoverable.first() {
            return Condition::Unrecoverable(format!("member '{rel}': {why}"));
        }
        if let Some((rel, why)) = self.unconfirmed.first() {
            return Condition::Unconfirmed {
                why: format!("member '{rel}': {why}"),
                skip: self.unconfirmed_skip.unwrap_or(ProbeSkip::TimeLimit),
            };
        }
        if !self.repairable.is_empty() {
            let names: Vec<&str> = self.repairable.iter().map(|(r, _)| r.as_str()).collect();
            return Condition::Repairable(format!("member(s) need repair: {}", names.join(", ")));
        }
        if !self.torn.is_empty() {
            return Condition::Torn(self.torn.join(", "));
        }
        Condition::Healthy
    }
}

/// Read a plain Tome member by member and sort the members by condition. Member names in
/// a plain Tome are not secret (they are stored in the clear); a Warded Tome is never
/// read here.
pub fn inspect_plain_tome(input: &Path, budget: &mut ProbeBudget) -> Result<TomeInspection> {
    let io = |e: std::io::Error| crate::Error::Msg(e.to_string());
    let mut reader = BufReader::new(File::open(input).map_err(io)?);
    let mut head = [0u8; 9];
    let mut got = 0;
    while got < head.len() {
        match reader.read(&mut head[got..]).map_err(io)? {
            0 => break,
            m => got += m,
        }
    }
    if got < 4 || &head[..4] != b"SGDR" {
        return Err(crate::Error::Msg("not a Tome".into()));
    }
    let mut out = TomeInspection::default();
    if got < head.len() {
        out.truncated = Some("truncated Tome (cut off in its header)".into());
        return Ok(out);
    }
    let mut cnt = [0u8; 4];
    cnt.copy_from_slice(&head[5..9]);
    let n = u32::from_le_bytes(cnt);
    drop(reader);
    let mut file = packhead::FileSrc::open(input)?;
    let size = file.size();
    let mut pos = head.len() as u64;
    // `n` is untrusted; every member needs at least 10 bytes, so a short file ends the
    // loop (as a truncation) long before `n` is reached.
    for i in 0..n {
        crate::repair_ctl::check()?;
        let mut lb = [0u8; 2];
        if file.read_at(pos, &mut lb).is_err() {
            out.truncated = Some(format!(
                "truncated Tome (cut off at member {} of {n})",
                i + 1
            ));
            return Ok(out);
        }
        pos += 2;
        let mut name = vec![0u8; usize::from(u16::from_le_bytes(lb))];
        let mut sl = [0u8; 8];
        if file.read_at(pos, &mut name).is_err()
            || file.read_at(pos + name.len() as u64, &mut sl).is_err()
        {
            out.truncated = Some(format!(
                "truncated Tome (cut off at member {} of {n})",
                i + 1
            ));
            return Ok(out);
        }
        pos += name.len() as u64 + 8;
        let rel = String::from_utf8_lossy(&name).into_owned();
        let slen = u64::from_le_bytes(sl);
        // Where this star starts in the file: the 9-byte head plus what was read since.
        let start = pos;
        pos = start.saturating_add(slen);
        if start.checked_add(slen).is_none_or(|e| e > size) {
            out.truncated = Some(format!(
                "truncated Tome (cut off inside '{rel}'; incomplete copy or transfer)"
            ));
            return Ok(out);
        }
        // A large-file member is assessed in place, one part at a time; a classic star
        // (one AES-GCM message) is read into memory as before.
        let mut mag = [0u8; 4];
        if slen >= 4 {
            file.read_at(start, &mut mag)?;
        }
        let condition = if mag == crate::work::WORK_MAGIC {
            let mut w = packhead::SubSrc::new(&mut file, start, slen)?;
            assess_pack(&mut w, MendMode::Deep, budget)
        } else {
            let mut star = vec![0u8; slen as usize];
            file.read_at(start, &mut star)?;
            assess_star(&star, MendMode::Deep, budget)
        };
        match condition {
            Condition::Healthy => out.intact.push(rel),
            Condition::Torn(_) => {
                out.intact.push(rel.clone());
                out.torn.push(rel);
            }
            Condition::Repairable(w) => out.repairable.push((rel, w)),
            Condition::Unconfirmed { why, skip } => {
                out.unconfirmed_skip.get_or_insert(skip);
                out.unconfirmed.push((rel, why));
            }
            Condition::Unrecoverable(w) => out.unrecoverable.push((rel, w)),
        }
    }
    Ok(out)
}

/// Assess a Tome. A Warded Tome's body is assessed with the quick repair only, because
/// that is the repair `sigil mend` runs on it; its member names are never read.
pub fn assess_tome(
    input: &Path,
    budget: &mut ProbeBudget,
) -> Result<(Condition, Option<TomeInspection>)> {
    let sealed = match crate::sealed_dir_body_loc(input) {
        Ok(s) => s,
        Err(e) if e.to_string().starts_with("truncated Tome") => {
            // A cut-off Warded body: report the truncation, never any member name.
            let why = e.to_string();
            let insp = TomeInspection {
                truncated: Some(why.clone()),
                ..TomeInspection::default()
            };
            return Ok((Condition::Unrecoverable(why), Some(insp)));
        }
        Err(e) => return Err(e),
    };
    if let Some((_, off, len)) = sealed {
        // A large body is assessed in place, one part at a time; a classic body (one
        // AES-GCM message) is read into memory as before.
        let mut file = packhead::FileSrc::open(input)?;
        let mut mag = [0u8; 4];
        if len >= 4 {
            file.read_at(off, &mut mag)?;
        }
        let c = if mag == crate::work::WORK_MAGIC {
            let mut w = packhead::SubSrc::new(&mut file, off, len)?;
            assess_pack(&mut w, MendMode::QuickOnly, budget)
        } else {
            let mut body = vec![0u8; len as usize];
            file.read_at(off, &mut body)?;
            assess_star(&body, MendMode::QuickOnly, budget)
        };
        return Ok((c.within("Warded Tome body"), None));
    }
    let insp = inspect_plain_tome(input, budget)?;
    Ok((insp.condition(), Some(insp)))
}

// ---------------------------------------------------------------------------------------
// Constellations
// ---------------------------------------------------------------------------------------

/// Assess the stars of a constellation (folder, card or atlas bag). Returns the condition
/// and, when one star file of a folder needs `sigil mend`, that file's path. The keys
/// are needed only to read a Warded card. Stars inside an atlas bag are read from a
/// scratch copy (as `scry` always has); the probes themselves write nothing.
pub fn assess_constellation(
    input: &Path,
    pass: Option<&str>,
    identities: &[Identity],
    budget: &mut ProbeBudget,
) -> Result<(Condition, Option<PathBuf>)> {
    use crate::constellation as c;
    let resolved = crate::container::sky_for_read(input);
    let rpath = resolved.as_path();
    if crate::is_atlas_file(rpath) {
        // Stars inside an atlas bag are repaired by `sigil mend <bag>`, not one by one.
        let cond = c::with_extracted_atlas(rpath, |tmp| {
            let (chart, dir) = c::load_chart_keys(tmp, pass, identities)?;
            let card = c::find_card(tmp);
            Ok(c::assess_stars(&chart, &dir, card.as_deref(), budget).0)
        })?;
        return Ok((cond, None));
    }
    let (chart, dir) = c::load_chart_keys(rpath, pass, identities)?;
    let card = c::chart_card(rpath, &dir);
    Ok(c::assess_stars(&chart, &dir, card.as_deref(), budget))
}

// ---------------------------------------------------------------------------------------
// Guidance: one table from situation to remedies
// ---------------------------------------------------------------------------------------

/// The kind of archive a failure is about; it decides which remedies exist.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArchiveKind {
    /// A single-file Sigil Archive (`.sg1`).
    Single,
    /// A large-file Sigil Archive (many parts in one file).
    LargeFile,
    /// A Tome whose member names are in the clear.
    Tome,
    /// A Warded Tome (member names and contents locked).
    WardedTome,
    /// A constellation folder or card.
    Constellation,
    /// An atlas bag (a constellation packed into one file).
    Atlas,
}

impl ArchiveKind {
    /// Detect the kind from the file (cheap header reads only).
    pub fn of(path: &Path) -> ArchiveKind {
        let resolved = crate::container::sky_for_read(path);
        if crate::is_atlas_file(resolved.as_path()) {
            ArchiveKind::Atlas
        } else if crate::is_constellation_input(path) {
            ArchiveKind::Constellation
        } else if crate::is_sealed_dir_pack(path) {
            ArchiveKind::WardedTome
        } else if crate::is_dir_pack(path) {
            ArchiveKind::Tome
        } else if crate::is_work_pack(path) {
            ArchiveKind::LargeFile
        } else {
            ArchiveKind::Single
        }
    }

    /// Kinds that `sigil scatter`, `sigil deluge --channel` and `sigil frost place` accept,
    /// so `.sgp` pieces, Channel mana or Frost Rune drives may exist for them.
    fn has_pieces(self) -> bool {
        matches!(
            self,
            ArchiveKind::Single | ArchiveKind::Tome | ArchiveKind::WardedTome
        )
    }
}

/// The situation a failure leaves the user in.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Situation {
    /// Will not open as-is; `sigil mend` repairs it. `star` is the damaged star file of a
    /// constellation; `intact` the members of a plain Tome that open as-is.
    Repairable {
        star: Option<PathBuf>,
        intact: Vec<String>,
    },
    /// Will not open as-is; repair not confirmed.
    Unconfirmed {
        star: Option<PathBuf>,
        intact: Vec<String>,
    },
    /// This copy cannot be restored; `intact` as above.
    NotRecoverable { intact: Vec<String> },
    /// The file ends early (an incomplete copy or transfer).
    Truncated,
    /// `sigil mend` found no verified repair. `quick_only`: `--hard-only` was given.
    MendFailed {
        quick_only: bool,
        intact: Vec<String>,
    },
    /// `sigil mend A B …` pooled several copies and still found no verified repair.
    PooledMendFailed,
    /// A passphrase or key was given but does not unlock it.
    WrongKey,
    /// It is Warded and no passphrase or key was given.
    KeyRequired,
    /// `sigil gather` on a Channel folder: not enough mana yet. `receipt_saved`:
    /// `--partial` already wrote a progress receipt.
    ManaShort { receipt_saved: bool },
    /// `sigil gather` on a folder of `.sgp` pieces: not enough pieces.
    PiecesShort,
    /// `sigil frost mend`: not enough Frost Rune drives (`none`: no `usb-*` folder at all).
    DrivesShort { none: bool },
    /// `sigil gather --open` rebuilt the archive but could not open it with the
    /// passphrase given (`wrong`) or without one (`!wrong`).
    GatherOpenKey { wrong: bool },
}

/// One concrete next step; [`Remedy::render`] gives the exact line printed.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Remedy {
    /// `sigil mend --scan`: list the damage and the repair time (single and large-file).
    ScanDamage,
    /// `sigil mend`: repair into a new file.
    Mend,
    /// `sigil mend` without `--hard-only`.
    MendDeeper,
    /// `sigil mend` on the damaged star file of a constellation.
    MendStar(PathBuf),
    /// `sigil unseal --repair`: open with a one-off repair in memory (single-file only).
    OpenWithRepair,
    /// `sigil mend A B`: pool the good parts of another copy.
    PoolCopy,
    /// Pool yet more copies after a pooled mend failed.
    PoolMoreCopies,
    /// `sigil gather`: rebuild from `.sgp` pieces or Channel mana.
    GatherPieces,
    /// `sigil frost mend`: rebuild from Frost Rune drives.
    FrostMend,
    /// `sigil vault versions` / `sigil vault restore`.
    VaultRestore,
    /// Fetch another copy from the source.
    CopyAgain,
    /// Fetch another copy: this one is cut short.
    CopyAgainTruncated,
    /// `sigil unseal --only`: extract the members of a plain Tome that open as-is.
    RescueIntact {
        /// The first undamaged member (shown in the command).
        first: String,
    },
    /// The names of the undamaged members of a plain Tome.
    ListIntact {
        /// Names shown (at most a few).
        shown: Vec<String>,
        /// How many members are undamaged.
        total: usize,
    },
    /// Retype the passphrase, or give it in a file.
    PassphraseAgain,
    /// Give the passphrase that was missing.
    GivePassphrase,
    /// `--identity` / `--talisman`.
    GiveKey,
    /// Any other recipient's key opens it too.
    OtherRecipient,
    /// `--ward-file` for a member of a Tome with its own Ward.
    MemberWard,
    /// A lost passphrase or key cannot be reset.
    NoKeyReset,
    /// `sigil gather --report`.
    ManaReport,
    /// `sigil deluge --channel --answer` (run by the sender).
    ManaAnswer,
    /// `sigil deluge --channel --extra` (run by the sender).
    ManaExtra,
    /// `sigil gather --partial`.
    ManaPartial,
    /// Add `.sgp` pieces, then `sigil gather` again.
    MorePieces,
    /// Add a Frost Rune drive folder, then `sigil frost mend` again.
    MoreDrives,
    /// `sigil gather --open --pass-file`.
    GatherPassFile,
    /// `sigil gather`, then `sigil unseal --identity` (gather takes no key file).
    GatherThenUnseal,
}

/// Members named in the "undamaged files" line, at most.
const INTACT_SHOWN: usize = 8;

fn rescue(intact: &[String]) -> Vec<Remedy> {
    match intact.first() {
        None => Vec::new(),
        Some(first) => vec![
            Remedy::RescueIntact {
                first: first.clone(),
            },
            Remedy::ListIntact {
                shown: intact.iter().take(INTACT_SHOWN).cloned().collect(),
                total: intact.len(),
            },
        ],
    }
}

fn pieces_if(kind: ArchiveKind) -> Vec<Remedy> {
    if kind.has_pieces() {
        vec![Remedy::GatherPieces, Remedy::FrostMend]
    } else {
        Vec::new()
    }
}

/// The table: which next steps exist for this kind of archive in this situation, in the
/// order to try them. Every command a remedy prints is one this archive kind accepts.
pub fn remedies(kind: ArchiveKind, situation: &Situation) -> Vec<Remedy> {
    use ArchiveKind as K;
    use Remedy as R;
    match situation {
        Situation::Repairable { star, intact } | Situation::Unconfirmed { star, intact } => {
            let confirmed = matches!(situation, Situation::Repairable { .. });
            match (kind, star) {
                (K::Constellation, Some(s)) => vec![R::MendStar(s.clone())],
                (K::Constellation, None) => vec![R::CopyAgain],
                (K::Single, _) if confirmed => {
                    vec![R::ScanDamage, R::Mend, R::OpenWithRepair, R::PoolCopy]
                }
                (K::Single, _) => vec![R::ScanDamage, R::Mend, R::PoolCopy],
                (K::LargeFile, _) => vec![R::ScanDamage, R::Mend],
                (K::Tome, _) => [vec![R::Mend], rescue(intact)].concat(),
                (K::WardedTome | K::Atlas, _) => vec![R::Mend],
            }
        }
        Situation::NotRecoverable { intact } => match kind {
            K::Single => vec![R::PoolCopy, R::GatherPieces, R::FrostMend, R::VaultRestore],
            K::Tome => [
                rescue(intact),
                pieces_if(kind),
                vec![R::VaultRestore, R::CopyAgain],
            ]
            .concat(),
            K::WardedTome => [pieces_if(kind), vec![R::VaultRestore, R::CopyAgain]].concat(),
            K::LargeFile | K::Atlas | K::Constellation => vec![R::CopyAgain, R::VaultRestore],
        },
        Situation::Truncated => [
            vec![R::CopyAgainTruncated],
            pieces_if(kind),
            vec![R::VaultRestore],
        ]
        .concat(),
        Situation::MendFailed { quick_only, intact } => {
            let deeper = (*quick_only && kind != K::WardedTome)
                .then_some(R::MendDeeper)
                .into_iter()
                .collect::<Vec<_>>();
            let rest = remedies(
                kind,
                &Situation::NotRecoverable {
                    intact: intact.clone(),
                },
            );
            [deeper, rest].concat()
        }
        Situation::PooledMendFailed => {
            vec![
                R::PoolMoreCopies,
                R::GatherPieces,
                R::FrostMend,
                R::VaultRestore,
            ]
        }
        Situation::WrongKey => {
            let mut v = vec![R::PassphraseAgain, R::GiveKey, R::OtherRecipient];
            if matches!(kind, K::Tome | K::WardedTome) {
                v.push(R::MemberWard);
            }
            v.push(R::NoKeyReset);
            v
        }
        Situation::KeyRequired => vec![R::GivePassphrase, R::GiveKey],
        Situation::ManaShort { receipt_saved } => {
            let mut v = vec![R::ManaReport, R::ManaAnswer, R::ManaExtra];
            if !receipt_saved {
                v.push(R::ManaPartial);
            }
            v
        }
        Situation::PiecesShort => vec![R::MorePieces, R::FrostMend, R::VaultRestore],
        Situation::DrivesShort { .. } => vec![R::MoreDrives, R::GatherPieces, R::VaultRestore],
        Situation::GatherOpenKey { wrong } => {
            let mut v = vec![R::GatherPassFile, R::GatherThenUnseal];
            if *wrong {
                v.push(R::NoKeyReset);
            }
            v
        }
    }
}

impl Remedy {
    /// The exact line printed for this remedy. `target` is the archive (or folder) the
    /// command was run on, already quoted for the shell where needed.
    pub fn render(&self, target: &str) -> String {
        let t = target;
        match self {
            Remedy::ScanDamage => {
                format!("See what is damaged and how long a repair takes: sigil mend --scan {t}")
            }
            Remedy::Mend => {
                format!("Repair it into a new file (the original is kept): sigil mend {t}")
            }
            Remedy::MendDeeper => {
                format!("Try the deeper repair too (leave out --hard-only): sigil mend {t}")
            }
            Remedy::MendStar(star) => format!(
                "Repair the damaged star file, then put the repaired copy in its place: sigil mend {}",
                shell_word(&star.display().to_string())
            ),
            Remedy::OpenWithRepair => {
                format!("Or open it with a one-off repair in memory: sigil unseal --repair -o <out-file> {t}")
            }
            Remedy::PoolCopy => format!(
                "If you have another copy (backup, cloud, USB stick), combine them: sigil mend {t} <other-copy.sg1>"
            ),
            Remedy::PoolMoreCopies => {
                format!("Add any other copies you have: sigil mend {t} <another-copy.sg1>")
            }
            Remedy::GatherPieces => "If you kept .sgp pieces or Channel mana for it, rebuild from them: sigil gather <folder> -o <rebuilt.sg1>".into(),
            Remedy::FrostMend => "If it is on Frost Rune drives, rebuild from them: sigil frost mend <frost-folder> -o <rebuilt.sg1>".into(),
            Remedy::VaultRestore => "If it is kept in a Vault, restore an earlier version: sigil vault versions <vault>, then sigil vault restore --version <N> <vault>".into(),
            Remedy::CopyAgain => "Copy it again from where it came from (the original, a backup, or the sender)".into(),
            Remedy::CopyAgainTruncated => "This copy is cut short: copy it again from where it came from (the original, a backup, or the sender)".into(),
            Remedy::RescueIntact { first } => format!(
                "Get the undamaged files out now (one --only per file): sigil unseal --only {} -o <out-folder> {t}",
                shell_word(first)
            ),
            Remedy::ListIntact { shown, total } => {
                let more = total.saturating_sub(shown.len());
                let list = shown.join(", ");
                if more > 0 {
                    format!("Undamaged files ({total}): {list}, and {more} more")
                } else {
                    format!("Undamaged files ({total}): {list}")
                }
            }
            Remedy::PassphraseAgain => "Check the passphrase and try again: type it when asked (--pass -) or give --pass-file <file>".into(),
            Remedy::GivePassphrase => "Give the passphrase: type it when asked (--pass -) or give --pass-file <file>".into(),
            Remedy::GiveKey => "If it was Warded to a key, give that key: --identity <key.sgk> (or --talisman <file>)".into(),
            Remedy::OtherRecipient => "If it was Warded to several people, anyone on the list can open it with their own key".into(),
            Remedy::MemberWard => "If a file inside the Tome has its own Ward, give it too: --ward-file <path-in-tome>=<passphrase-file>".into(),
            Remedy::NoKeyReset => "A Ward has no reset: if the passphrase or key is lost, use an unencrypted backup or an earlier Vault version".into(),
            Remedy::ManaReport => {
                format!("Make a one-line report of what is missing: sigil gather --report {t}")
            }
            Remedy::ManaAnswer => "Send that line to the sender, who runs: sigil deluge --channel <file.sg1> --answer \"<report-line>\" -o <mana-folder>".into(),
            Remedy::ManaExtra => "Or ask the sender for more mana: sigil deluge --channel <file.sg1> --extra <N> -o <mana-folder>".into(),
            Remedy::ManaPartial => format!(
                "Save a progress receipt (no archive is written): sigil gather --partial -o <rebuilt.sg1> {t}"
            ),
            Remedy::MorePieces => format!(
                "Add more .sgp pieces to the folder (another drive, or ask the sender), then run: sigil gather {t} -o <rebuilt.sg1>"
            ),
            Remedy::GatherPassFile => format!(
                "Give the passphrase in a file: sigil gather {t} --open --pass-file <file> -o <out-file>"
            ),
            Remedy::GatherThenUnseal => format!(
                "If it was Warded to a key, rebuild it first, then open it: sigil gather {t} -o <rebuilt.sg1>, then sigil unseal --identity <key.sgk> -o <out-file> <rebuilt.sg1>"
            ),
            Remedy::MoreDrives => format!(
                "Copy the usb-* folder from another drive of this Frost Rune set into {t}, then run: sigil frost mend {t} -o <rebuilt.sg1>"
            ),
        }
    }
}

/// The "What you can try" lines for `target` in `situation`.
pub fn hints(kind: ArchiveKind, situation: &Situation, target: &Path) -> Vec<String> {
    hints_for_target(kind, situation, &shell_word(&target.display().to_string()))
}

/// [`hints`] with the target already rendered (for several copies at once).
pub fn hints_for_target(kind: ArchiveKind, situation: &Situation, target: &str) -> Vec<String> {
    remedies(kind, situation)
        .iter()
        .map(|r| r.render(target))
        .collect()
}

/// The situation for an archive in `condition` (`None` when it opens as-is).
pub fn situation_of(
    condition: &Condition,
    tome: Option<&TomeInspection>,
    star: Option<&Path>,
) -> Option<Situation> {
    let intact = tome.map(|t| t.intact.clone()).unwrap_or_default();
    let star = star.map(Path::to_path_buf);
    match condition {
        Condition::Healthy | Condition::Torn(_) => None,
        Condition::Repairable(_) => Some(Situation::Repairable { star, intact }),
        Condition::Unconfirmed { .. } => Some(Situation::Unconfirmed { star, intact }),
        Condition::Unrecoverable(_) if tome.is_some_and(|t| t.truncated.is_some()) => {
            Some(Situation::Truncated)
        }
        Condition::Unrecoverable(_) => Some(Situation::NotRecoverable { intact }),
    }
}

// ---------------------------------------------------------------------------------------
// Failures of commands that open an archive
// ---------------------------------------------------------------------------------------

/// A failure with its plain-English message, next steps and exit code.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Guidance {
    /// The message (also the JSON `error`).
    pub message: String,
    /// "What you can try" lines (also the optional JSON `hints`).
    pub hints: Vec<String>,
    /// The exit code.
    pub exit_code: i32,
}

/// What a key-related error means (from [`crate::readdata::cause_of`], the one place
/// that sorts error text into causes).
fn key_situation(err: &str) -> Option<Situation> {
    match crate::readdata::cause_of(err) {
        crate::readdata::Cause::KeyNeeded => Some(Situation::KeyRequired),
        crate::readdata::Cause::WrongKey => Some(Situation::WrongKey),
        crate::readdata::Cause::Damaged => None,
    }
}

/// The situation for a key error (`KeyRequired` / `WrongKey`), or `None` when `err` is
/// not about a key (sorted by [`crate::readdata::cause_of`]).
pub fn key_problem(err: &str) -> Option<Situation> {
    key_situation(err)
}

/// Guidance for an `unseal` / `open` / `scry` failure on `input`, or `None` when the
/// failure is neither a key problem nor damage (then the original error and exit code
/// stand). The decision comes from the archive's measured condition, not from the error
/// text: an archive that opens as-is never gets damage guidance.
pub fn diagnose_open_failure(
    input: &Path,
    err: &str,
    budget: &mut ProbeBudget,
) -> Option<Guidance> {
    let kind = match ArchiveKind::of(input) {
        ArchiveKind::Single if crate::is_damaged_work_pack_or_limit(input) => {
            ArchiveKind::LargeFile
        }
        k => k,
    };
    let target = shell_word(&input.display().to_string());
    if let Some(s) = key_situation(err) {
        return Some(Guidance {
            message: err.to_string(),
            hints: hints_for_target(kind, &s, &target),
            exit_code: 1,
        });
    }
    let (condition, tome, star) = match kind {
        ArchiveKind::Tome | ArchiveKind::WardedTome => {
            let (c, t) = assess_tome(input, budget).ok()?;
            (c, t, None)
        }
        ArchiveKind::Constellation | ArchiveKind::Atlas => {
            let (c, s) = assess_constellation(input, None, &[], budget).ok()?;
            (c, None, s)
        }
        ArchiveKind::LargeFile => (assess_path(input, budget).ok()?, None, None),
        ArchiveKind::Single => {
            let data = std::fs::read(input).ok()?;
            // No Sigil header anywhere (not a Sigil Archive, or every copy of its header
            // is gone): nothing to diagnose; the original error stands.
            crate::locate_header(&data).ok()?;
            (assess_star(&data, MendMode::Deep, budget), None, None)
        }
    };
    if condition.opens_as_is() {
        // Not damaged. An older archive reports a wrong key and damage with one message;
        // with the archive intact, it was the key.
        return err.contains(crate::LEGACY_OPEN_FAILED).then(|| Guidance {
            message: err.to_string(),
            hints: hints_for_target(kind, &Situation::WrongKey, &target),
            exit_code: 1,
        });
    }
    let situation = situation_of(&condition, tome.as_ref(), star.as_deref())?;
    let mend = crate::mend_out::mend_command(star.as_deref().unwrap_or(input));
    let headline = condition.headline(&mend)?;
    Some(Guidance {
        message: format!("Cannot open {target}: {headline}"),
        hints: hints_for_target(kind, &situation, &target),
        exit_code: condition.exit_code(),
    })
}

/// True when `err` is `sigil frost mend` finding no `usb-*` drive folder at all.
pub fn is_no_drives(err: &str) -> bool {
    err.starts_with(crate::kit::NO_DRIVES)
}

/// True when `err` says a `sigil gather` / `sigil frost mend` is short of pieces (as
/// opposed to an I/O or format error).
pub fn is_pieces_short(err: &str) -> bool {
    err.starts_with(crate::fountain::MANA_SHORT)
        || err.starts_with(crate::kit::NO_DRIVES)
        || (err.starts_with("need ") && err.contains(" pieces, have "))
        || (err.starts_with("Glyph needs all ") && err.contains(" pieces, have "))
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Incompressible bytes (so shard bodies sit where the test expects them).
    fn noise(n: usize) -> Vec<u8> {
        let mut x: u64 = 0x9E37_79B9_7F4A_7C15;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    fn seal(n: usize) -> Vec<u8> {
        let data = noise(n);
        crate::seal(&data, crate::Mode::Reflection, None, "t.bin", false).unwrap()
    }

    fn flip_every_shard(sg: &[u8]) -> Vec<u8> {
        let (h, prefix, _) = crate::locate_header(sg).unwrap();
        let sl = h.shard_len as usize;
        let mut out = sg.to_vec();
        for i in 0..h.n as usize {
            out[prefix + i * (8 + sl) + 8 + sl / 2] ^= 1;
        }
        out
    }

    #[test]
    fn healthy_and_bitrot_and_disabled_probe() {
        let sg = seal(40_000);
        let mut b = ProbeBudget::with_secs(30);
        assert_eq!(assess_seal(&sg, MendMode::Deep, &mut b), Condition::Healthy);
        let rot = flip_every_shard(&sg);
        assert!(matches!(
            assess_seal(&rot, MendMode::Deep, &mut b),
            Condition::Repairable(_)
        ));
        // The quick repair alone cannot fix it: never "repairable" for a quick-only mend.
        assert!(matches!(
            assess_seal(&rot, MendMode::QuickOnly, &mut b),
            Condition::Unrecoverable(_)
        ));
        let c = assess_seal(&rot, MendMode::Deep, &mut ProbeBudget::disabled());
        assert!(
            matches!(
                c,
                Condition::Unconfirmed {
                    skip: ProbeSkip::Disabled,
                    ..
                }
            ),
            "{c:?}"
        );
        assert_eq!(c.exit_code(), EXIT_UNCONFIRMED);
    }

    #[test]
    fn expired_budget_is_unconfirmed_not_a_verdict() {
        let rot = flip_every_shard(&seal(40_000));
        let mut b = ProbeBudget {
            deadline: Some(Instant::now()),
        };
        let c = assess_seal(&rot, MendMode::Deep, &mut b);
        assert!(
            matches!(
                c,
                Condition::Unconfirmed {
                    skip: ProbeSkip::TimeLimit,
                    ..
                }
            ),
            "{c:?}"
        );
        // The limit was scoped to the probe: nothing is left behind on this thread.
        assert!(crate::repair_ctl::current_deadline().is_none());
    }

    #[test]
    fn worse_orders_conditions() {
        let r = Condition::Repairable("a".into());
        let u = Condition::Unrecoverable("b".into());
        assert_eq!(r.clone().worse(u.clone()), u);
        assert_eq!(u.clone().worse(r), u);
        assert_eq!(
            Condition::Healthy
                .worse(Condition::Torn("t".into()))
                .exit_code(),
            0
        );
    }

    #[test]
    fn table_never_offers_commands_a_kind_rejects() {
        let all = [
            ArchiveKind::Single,
            ArchiveKind::LargeFile,
            ArchiveKind::Tome,
            ArchiveKind::WardedTome,
            ArchiveKind::Constellation,
            ArchiveKind::Atlas,
        ];
        let situations = [
            Situation::Repairable {
                star: None,
                intact: vec!["a".into()],
            },
            Situation::Unconfirmed {
                star: None,
                intact: vec!["a".into()],
            },
            Situation::NotRecoverable {
                intact: vec!["a".into()],
            },
            Situation::Truncated,
            Situation::MendFailed {
                quick_only: true,
                intact: vec!["a".into()],
            },
        ];
        for k in all {
            for s in &situations {
                let r = remedies(k, s);
                assert!(!r.is_empty(), "{k:?} {s:?}");
                // `unseal --repair` and pooling copies take single-file archives only.
                if k != ArchiveKind::Single {
                    assert!(!r.contains(&Remedy::OpenWithRepair), "{k:?} {s:?}");
                    assert!(!r.contains(&Remedy::PoolCopy), "{k:?} {s:?}");
                }
                // `mend --scan` covers single and large-file archives only.
                if !matches!(k, ArchiveKind::Single | ArchiveKind::LargeFile) {
                    assert!(!r.contains(&Remedy::ScanDamage), "{k:?} {s:?}");
                }
                // `scatter` / `deluge --channel` / `frost place` refuse large-file archives.
                if !k.has_pieces() {
                    assert!(!r.contains(&Remedy::GatherPieces), "{k:?} {s:?}");
                    assert!(!r.contains(&Remedy::FrostMend), "{k:?} {s:?}");
                }
                // Only a plain Tome lists (and extracts) member names.
                if k != ArchiveKind::Tome {
                    assert!(
                        !r.iter().any(|x| matches!(
                            x,
                            Remedy::RescueIntact { .. } | Remedy::ListIntact { .. }
                        )),
                        "{k:?} {s:?}"
                    );
                }
                // A constellation folder is not a `sigil mend` target.
                if k == ArchiveKind::Constellation {
                    assert!(!r.contains(&Remedy::Mend), "{k:?} {s:?}");
                }
            }
        }
        // A truncated Tome never suggests extracting members (their framing is gone).
        assert!(!remedies(ArchiveKind::Tome, &Situation::Truncated)
            .iter()
            .any(|x| matches!(x, Remedy::RescueIntact { .. })));
    }

    #[test]
    fn pieces_short_detection() {
        assert!(is_pieces_short("need 12 pieces, have 8"));
        assert!(is_pieces_short(
            "not enough mana yet: have 2 of 6 needed, need 4 more (keep raining)"
        ));
        assert!(!is_pieces_short("No such file or directory (os error 2)"));
        assert!(!is_pieces_short("need --output"));
    }
}
