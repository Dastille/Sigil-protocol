//! Failure assessment and plain-English recovery guidance across Sigil commands.
//!
//! All user-facing text here uses the approved terms (`Sigil Archive`, `Tome`,
//! `Ward`, `Channel` / `mana`, `Frost Rune`) and never exposes internal jargon
//! (`CEK`, `star bytes`, `folder pack`). Every option listed is checked for
//! applicability to the archive kind and damage state.

use crate::keys::Identity;
use crate::mend_out::shell_word;
use crate::packhead::{self, Src};
use crate::pieces::Canon;
use crate::repair_scan::{self, RepairPath};
use crate::Result;
use std::fs::File;
use std::io::{BufReader, Read};
use std::path::Path;

/// Exit code for an archive that cannot be opened as-is because it is damaged,
/// but `sigil mend` can repair it (distinct from `0` ok, `1` error/wrong key,
/// `2` not-recoverable).
pub const EXIT_REPAIRABLE: i32 = 5;

/// Max single-seal byte size for running an exact soft-mend probe during
/// `scry` / `unseal` diagnostics. Larger seals use `repair_scan` so checks stay fast.
const EXACT_SOFT_PROBE_MAX_BYTES: usize = 32 * 1024 * 1024;

/// Structural + repairability assessment of a single seal or archive.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum StarHealth {
    /// Healthy: every shard is intact and Merkle / canonical checks pass.
    Ok,
    /// Torn but still openable directly (`live >= k`); `sigil mend` restores full redundancy.
    QuickRepairable(String),
    /// Damaged below `k` intact shards (or rebuildable pack head) so `unseal` cannot
    /// open directly, but `sigil mend` can repair it (e.g. scattered bit rot).
    Mendable(String),
    /// Cannot be rebuilt from this copy alone.
    Unrecoverable(String),
}

impl StarHealth {
    pub fn unrecoverable_reason(&self) -> Option<&str> {
        match self {
            StarHealth::Unrecoverable(why) => Some(why.as_str()),
            _ => None,
        }
    }

    pub fn mendable_reason(&self) -> Option<&str> {
        match self {
            StarHealth::Mendable(why) => Some(why.as_str()),
            _ => None,
        }
    }
}

/// Overall `scry` / `verify` classification.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum ScryVerdict {
    Healthy,
    /// `live >= k`: `unseal` succeeds directly; `scry` prints `needs repair` and exits 0.
    QuickRepair(String),
    /// `live < k` (or head/star needs mend before `unseal`): `scry` prints `damaged — run sigil mend` and exits 5.
    DamagedMendable(String),
    /// Beyond single-copy repair: `scry` prints `NOT recoverable` and exits 2.
    NotRecoverable(String),
}

/// Complete plain-English failure message + applicable next steps + consistent exit code.
#[derive(Clone, Debug)]
pub struct FailureGuidance {
    pub message: String,
    pub hints: Vec<String>,
    pub exit_code: i32,
}

/// Plain-English summary of a plain (v1) Tome's members when checking or opening fails.
#[derive(Clone, Debug, Default)]
pub struct TomeInspection {
    pub truncated: bool,
    pub truncate_reason: Option<String>,
    pub intact: Vec<String>,
    pub quick_repair: Vec<String>,
    pub mendable: Vec<(String, String)>,
    pub unrecoverable: Vec<(String, String)>,
}

/// Assess a single classic `.sg1` seal held in memory.
pub fn assess_classic_bytes(star: &[u8]) -> StarHealth {
    match crate::verify(star) {
        Err(e) => StarHealth::Unrecoverable(format!("unreadable: {e}")),
        Ok((h, merkle_ok, live, k, recovered)) => {
            let n = h.n as usize;
            if live >= k {
                if live < n || recovered {
                    return StarHealth::QuickRepairable(format!(
                        "{live}/{n} shards intact (need {k}){}",
                        if recovered {
                            ", header recovered from keystone"
                        } else {
                            ""
                        }
                    ));
                }
                if !merkle_ok {
                    if star.len() <= EXACT_SOFT_PROBE_MAX_BYTES
                        && crate::pieces::mend_bytes_ex(star, true).is_ok()
                    {
                        return StarHealth::Mendable(format!(
                            "Merkle check failed ({live}/{n} intact, need {k}); repairable with sigil mend"
                        ));
                    }
                    return StarHealth::Unrecoverable(
                        "all shards present but Merkle root differs (corrupt shard data)".into(),
                    );
                }
                if let Some(res) = crate::pieces::canonical_check(star) {
                    return match res {
                        Ok(Canon::Same | Canon::TrailerOnly) => StarHealth::Ok,
                        Ok(Canon::Differs) => StarHealth::QuickRepairable(
                            "redundant copies (shard or key-wrap spares) are damaged (data still intact)".into(),
                        ),
                        Err(e) => StarHealth::Unrecoverable(format!("repair check failed: {e}")),
                    };
                }
                return StarHealth::Ok;
            }

            // Fewer than `k` shards passed per-shard CRC: check if deeper repair can heal bit rot.
            if h.encrypted()
                && h.private_label()
                && crate::pieces::sgto_from_prefix(star, &h).is_none()
            {
                return StarHealth::Unrecoverable(format!(
                    "live={live}/{n} need={k} (key wrap damaged)"
                ));
            }
            match repair_scan::scan_seal(star) {
                Err(e) => StarHealth::Unrecoverable(format!("unreadable: {e}")),
                Ok(scan) => match scan.path {
                    RepairPath::NotEnough | RepairPath::NotNeeded => {
                        StarHealth::Unrecoverable(format!("live={live}/{n} need={k}"))
                    }
                    RepairPath::Quick => {
                        StarHealth::QuickRepairable(format!("{live}/{n} shards intact (need {k})"))
                    }
                    RepairPath::Deeper | RepairPath::DeeperHard => {
                        if star.len() <= EXACT_SOFT_PROBE_MAX_BYTES {
                            if crate::pieces::mend_bytes_ex(star, true).is_ok() {
                                StarHealth::Mendable(format!(
                                    "only {live}/{n} shards intact (need {k}); repairable with deeper repair"
                                ))
                            } else {
                                StarHealth::Unrecoverable(format!("live={live}/{n} need={k}"))
                            }
                        } else {
                            StarHealth::Mendable(format!(
                                "only {live}/{n} shards intact (need {k}); scattered errors may be repairable with deeper repair"
                            ))
                        }
                    }
                },
            }
        }
    }
}

/// Assess either a classic `.sg1` or an in-memory SGWK large-file Sigil Archive.
pub fn assess_star_bytes(star: &[u8]) -> StarHealth {
    if star.starts_with(&crate::work::WORK_MAGIC) {
        let l = match packhead::layout(&mut packhead::MemSrc(star)) {
            Ok(l) => l,
            Err(e) => {
                return StarHealth::Unrecoverable(format!("large-file archive unreadable: {e}"))
            }
        };
        if (l.stars.len() as u64) < u64::from(l.head.stars) {
            return StarHealth::Unrecoverable(format!(
                "only {} of {} parts present",
                l.stars.len(),
                l.head.stars
            ));
        }
        let mut worst = StarHealth::Ok;
        for (i, &(o, n)) in l.stars.iter().enumerate() {
            let (a, b) = (o as usize, (o + n) as usize);
            let Some(part) = star.get(a..b) else {
                return StarHealth::Unrecoverable(format!("part {i} is cut off"));
            };
            let seal = if l.guarded {
                packhead::seal_part(part)
            } else {
                part
            };
            match assess_classic_bytes(seal) {
                StarHealth::Unrecoverable(w) => {
                    return StarHealth::Unrecoverable(format!("part {i}: {w}"))
                }
                StarHealth::Mendable(w) => {
                    if matches!(worst, StarHealth::Ok | StarHealth::QuickRepairable(_)) {
                        worst = StarHealth::Mendable(format!("part {i}: {w}"));
                    }
                }
                StarHealth::QuickRepairable(w) => {
                    if matches!(worst, StarHealth::Ok) {
                        worst = StarHealth::QuickRepairable(format!("part {i}: {w}"));
                    }
                }
                StarHealth::Ok => {}
            }
        }
        return worst;
    }
    assess_classic_bytes(star)
}

/// Assess a large-file (`SGWK`) Sigil Archive on disk one part at a time.
pub fn assess_work_pack_path(input: &Path) -> Result<StarHealth> {
    let (head, locs) = crate::index_pack(input)?;
    if (locs.len() as u64) < u64::from(head.stars) {
        return Ok(StarHealth::Unrecoverable(format!(
            "only {} of {} parts present",
            locs.len(),
            head.stars
        )));
    }
    let mut src = packhead::FileSrc::open(input)?;
    let layout = packhead::layout(&mut src).ok();
    let guarded = layout.as_ref().map(|l| l.guarded).unwrap_or(false);
    let head_damaged = layout
        .as_ref()
        .map(|l| l.source != crate::HeadSource::Intact)
        .unwrap_or(false);
    let mut worst = if head_damaged {
        StarHealth::Mendable("archive head damaged but rebuildable from facet list".into())
    } else {
        StarHealth::Ok
    };
    for loc in &locs {
        let mut part = vec![0u8; loc.star_len as usize];
        if src.read_at(loc.file_off, &mut part).is_err() || (part.len() as u64) < loc.star_len {
            return Ok(StarHealth::Unrecoverable(format!(
                "part {} is cut off",
                loc.index
            )));
        }
        let seal = if guarded {
            packhead::seal_part(&part)
        } else {
            part.as_slice()
        };
        match assess_classic_bytes(seal) {
            StarHealth::Unrecoverable(w) => {
                return Ok(StarHealth::Unrecoverable(format!(
                    "part {}: {w}",
                    loc.index
                )))
            }
            StarHealth::Mendable(w) => {
                if matches!(worst, StarHealth::Ok | StarHealth::QuickRepairable(_)) {
                    worst = StarHealth::Mendable(format!("part {}: {w}", loc.index));
                }
            }
            StarHealth::QuickRepairable(w) => {
                if matches!(worst, StarHealth::Ok) {
                    worst = StarHealth::QuickRepairable(format!("part {}: {w}", loc.index));
                }
            }
            StarHealth::Ok => {}
        }
    }
    Ok(worst)
}

/// Inspect a plain (v1) Tome streaming member-by-member to identify intact,
/// mendable, and unrecoverable members (or mid-archive truncation).
pub fn inspect_plain_tome(input: &Path) -> Result<TomeInspection> {
    let io = |e: std::io::Error| crate::Error::Msg(e.to_string());
    let f = File::open(input).map_err(io)?;
    let mut reader = BufReader::new(f);
    let mut magic = [0u8; 4];
    if reader.read_exact(&mut magic).is_err() || magic != *b"SGDR" {
        return Err(crate::Error::Msg("not a Tome archive".into()));
    }
    let mut ver = [0u8; 1];
    let mut cnt = [0u8; 4];
    if reader.read_exact(&mut ver).is_err() || reader.read_exact(&mut cnt).is_err() {
        return Ok(TomeInspection {
            truncated: true,
            truncate_reason: Some("truncated Tome (cut off in archive header)".into()),
            ..Default::default()
        });
    }
    let n = u32::from_le_bytes(cnt);
    let mut out = TomeInspection::default();
    for i in 0..n {
        let mut lb = [0u8; 2];
        if reader.read_exact(&mut lb).is_err() {
            out.truncated = true;
            out.truncate_reason = Some(format!(
                "truncated Tome (cut off at member {} of {n})",
                i + 1
            ));
            return Ok(out);
        }
        let nlen = u16::from_le_bytes(lb) as usize;
        let mut name = vec![0u8; nlen];
        let mut sl = [0u8; 8];
        if reader.read_exact(&mut name).is_err() || reader.read_exact(&mut sl).is_err() {
            out.truncated = true;
            out.truncate_reason = Some(format!(
                "truncated Tome (cut off inside member list at entry {} of {n})",
                i + 1
            ));
            return Ok(out);
        }
        let rel = String::from_utf8_lossy(&name).into_owned();
        let slen = u64::from_le_bytes(sl);
        let mut star = Vec::new();
        reader
            .by_ref()
            .take(slen)
            .read_to_end(&mut star)
            .map_err(io)?;
        if (star.len() as u64) < slen {
            out.truncated = true;
            out.truncate_reason = Some(format!(
                "truncated Tome (cut off inside '{rel}' data; incomplete copy or transfer)"
            ));
            return Ok(out);
        }
        match assess_star_bytes(&star) {
            StarHealth::Ok => out.intact.push(rel),
            StarHealth::QuickRepairable(_) => {
                out.intact.push(rel.clone());
                out.quick_repair.push(rel);
            }
            StarHealth::Mendable(why) => out.mendable.push((rel, why)),
            StarHealth::Unrecoverable(why) => out.unrecoverable.push((rel, why)),
        }
    }
    Ok(out)
}

/// Assess a plain `.sg1` or large-file (`SGWK`) archive for `scry` / `verify`.
pub fn scry_path_assessed(input: &Path) -> Result<(String, ScryVerdict)> {
    let s = crate::scry_path(input)?;
    let health = if crate::is_work_pack(input) {
        assess_work_pack_path(input)?
    } else {
        let data = std::fs::read(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
        assess_star_bytes(&data)
    };
    Ok(match health {
        StarHealth::Ok => (s, ScryVerdict::Healthy),
        StarHealth::QuickRepairable(why) => (s, ScryVerdict::QuickRepair(why)),
        StarHealth::Mendable(why) => {
            let s = match s.strip_prefix("ok  ") {
                Some(rest) => format!("damaged  {rest}"),
                None => s,
            };
            (s, ScryVerdict::DamagedMendable(why))
        }
        StarHealth::Unrecoverable(why) => {
            let s = match s.strip_prefix("ok  ") {
                Some(rest) => format!("NOT recoverable  {rest}"),
                None => format!("{s}\nNOT recoverable: {why}"),
            };
            (s, ScryVerdict::NotRecoverable(why))
        }
    })
}

/// Assess a Tome (`SGDR`, plain or sealed) for `scry` / `verify`.
pub fn scry_dir_assessed(
    input: &Path,
    pass: Option<&str>,
    companions: &[Vec<u8>],
    identities: &[Identity],
) -> Result<(String, ScryVerdict, Option<TomeInspection>)> {
    if let Some((_, body)) = crate::sealed_dir_body(input)? {
        let text = crate::scry_dir_keys(input, pass, companions, identities)?;
        let health = assess_star_bytes(&body);
        return Ok(match health {
            StarHealth::Ok => (text, ScryVerdict::Healthy, None),
            StarHealth::QuickRepairable(why) => (
                format!(
                    "{text}\nneeds mend: Warded Tome body (damaged but repairable; run: {})",
                    crate::mend_out::mend_command(input)
                ),
                ScryVerdict::QuickRepair(why),
                None,
            ),
            StarHealth::Mendable(why) => (
                format!(
                    "{text}\ndamaged — run {}",
                    crate::mend_out::mend_command(input)
                ),
                ScryVerdict::DamagedMendable(format!("Warded Tome body: {why}")),
                None,
            ),
            StarHealth::Unrecoverable(why) => (
                format!("{text}\nNOT recoverable: Warded Tome body: {why}"),
                ScryVerdict::NotRecoverable(format!("Warded Tome body: {why}")),
                None,
            ),
        });
    }

    let insp = inspect_plain_tome(input)?;
    let text = if insp.truncated {
        // Listing may fail on a truncated Tome; build a safe partial summary if list_dir_pack fails.
        crate::scry_dir_keys(input, pass, companions, identities).unwrap_or_else(|_| {
            format!(
                "Tome  {} intact member(s) before truncation",
                insp.intact.len()
            )
        })
    } else {
        crate::scry_dir_keys(input, pass, companions, identities)?
    };
    if insp.truncated {
        let why = insp
            .truncate_reason
            .clone()
            .unwrap_or_else(|| "truncated Tome (cut off mid-archive)".into());
        return Ok((
            format!("{text}\nNOT recoverable: {why}"),
            ScryVerdict::NotRecoverable(why),
            Some(insp),
        ));
    }
    if let Some((rel, why)) = insp.unrecoverable.first() {
        let reason = format!("{rel}: {why}");
        return Ok((
            format!("{text}\nNOT recoverable: {reason}"),
            ScryVerdict::NotRecoverable(reason),
            Some(insp),
        ));
    }
    if !insp.mendable.is_empty() {
        let names: Vec<&str> = insp.mendable.iter().map(|(r, _)| r.as_str()).collect();
        let why = format!("member(s) need repair: {}", names.join(", "));
        return Ok((
            format!(
                "{text}\ndamaged — run {} ({why})",
                crate::mend_out::mend_command(input)
            ),
            ScryVerdict::DamagedMendable(why),
            Some(insp),
        ));
    }
    if !insp.quick_repair.is_empty() {
        let names = insp.quick_repair.join(", ");
        return Ok((
            format!(
                "{text}\nneeds mend: {} (damaged but repairable, like merkle=open on one file; run: {})",
                names,
                crate::mend_out::mend_command(input)
            ),
            ScryVerdict::QuickRepair(names),
            Some(insp),
        ));
    }
    Ok((text, ScryVerdict::Healthy, Some(insp)))
}

/// Format intact member list concisely for `unseal --only` guidance.
fn format_intact_summary(intact: &[String], file_word: &str) -> Vec<String> {
    if intact.is_empty() {
        return Vec::new();
    }
    let sample = shell_word(&intact[0]);
    let mut out = vec![format!(
        "Extract undamaged files right now: sigil unseal --only {sample} -o <out-dir> {file_word}"
    )];
    let preview: Vec<&str> = intact.iter().take(8).map(String::as_str).collect();
    let more = intact.len().saturating_sub(preview.len());
    let list = if more > 0 {
        format!("{}, and {more} more", preview.join(", "))
    } else {
        preview.join(", ")
    };
    out.push(format!("Intact members ({}): {list}", intact.len()));
    out
}

/// Recovery options when `scry`/`verify` finds an archive damaged but mendable (`exit 5`).
pub fn hints_for_scry_mendable(
    target: &Path,
    is_work_pack: bool,
    tome: Option<&TomeInspection>,
    is_sealed_tome: bool,
    is_constellation: bool,
) -> Vec<String> {
    let arg = shell_word(&target.display().to_string());
    if is_constellation {
        return vec![
            format!("Repair the damaged star(s): sigil mend {arg}"),
            format!("Inspect intact members or extract unaffected files: sigil unseal --only <member> -o <out-dir> {arg}"),
        ];
    }
    if is_sealed_tome {
        return vec![
            format!("Repair this Warded Tome into a new copy (needs no key): sigil mend {arg}"),
            "If you have a second copy of this Warded Tome, keep it as a backup before opening"
                .into(),
        ];
    }
    if let Some(insp) = tome {
        let mut h = vec![format!(
            "Repair this Tome into a new file (keeps original untouched): sigil mend {arg}"
        )];
        h.extend(format_intact_summary(&insp.intact, &arg));
        return h;
    }
    if is_work_pack {
        return vec![
            format!("Inspect the damage and estimated repair time: sigil mend --scan {arg}"),
            format!("Repair this large Sigil Archive into a new file: sigil mend {arg}"),
        ];
    }
    vec![
        format!("Inspect the damage and estimated repair time: sigil mend --scan {arg}"),
        format!("Repair this Sigil Archive into a new file (keeps original untouched): sigil mend {arg}"),
        format!("Open once in memory without saving a repaired copy: sigil unseal --repair -o <out> {arg}"),
        format!("Combine good shards from another copy if you have one: sigil mend {arg} other-copy.sg1"),
    ]
}

/// Recovery options when `scry`/`verify`/`unseal`/`open` sees an archive beyond single-copy repair (`exit 2`).
pub fn hints_for_not_recoverable(
    target: &Path,
    is_work_pack: bool,
    tome: Option<&TomeInspection>,
    is_sealed_tome: bool,
    is_constellation: bool,
    truncated: bool,
) -> Vec<String> {
    let arg = shell_word(&target.display().to_string());
    if is_constellation {
        return vec![
            "Restore the missing or damaged star(s) from another copy of the Constellation or Atlas bag".into(),
            "If you saved .sgp shards or Channel .mana packets for a missing star: sigil gather <folder> -o <star.sg1>".into(),
            "If backed up across Frost Rune drives or a Vault: sigil frost mend <frost-dir> -o <star.sg1> or sigil vault versions <path>".into(),
            format!("Extract unaffected members individually: sigil unseal --only <member> -o <out-dir> {arg}"),
        ];
    }
    if truncated && (tome.is_some() || is_sealed_tome) {
        let h = vec![
            "Finish or re-copy the Tome from its original source (the transfer was cut short)".into(),
            "If sent via a Channel or saved shards, rebuild with: sigil gather <pieces-or-mana-folder> -o rebuilt.sg1".into(),
            "Check a Frost Rune cold backup (sigil frost mend) or Vault history (sigil vault versions)".into(),
        ];
        let _ = tome;
        return h;
    }
    if is_sealed_tome {
        return vec![
            "Find another copy of this Warded Tome (backup, cloud sync, or USB drive)".into(),
            "Rebuild from saved .sgp shards or Channel .mana packets: sigil gather <pieces-or-mana-folder> -o rebuilt.sg1".into(),
            "Rebuild from Frost Rune cold drives: sigil frost mend <frost-dir> -o rebuilt.sg1".into(),
            "Restore an earlier version if tracked in a Vault: sigil vault versions <vault-or-folder>".into(),
        ];
    }
    if let Some(insp) = tome {
        let mut h = format_intact_summary(&insp.intact, &arg);
        h.push(
            "Restore the damaged file(s) from another copy of the Tome or the original folder"
                .into(),
        );
        h.push("Check Vault versions or Segment Log history: sigil vault versions <vault-or-folder> (or sigil log ls <log-folder>)".into());
        return h;
    }
    if is_work_pack {
        return vec![
            "Replace or pool from another backup copy of this large Sigil Archive".into(),
            "Rebuild from saved .sgp shards or Channel .mana packets: sigil gather <pieces-or-mana-folder> -o rebuilt.sg1".into(),
            "Check Vault history for an earlier version: sigil vault versions <vault-or-path>".into(),
        ];
    }
    vec![
        format!("Combine good shards from another copy (backup, cloud sync, or USB stick): sigil mend {arg} other-copy.sg1"),
        "Rebuild from saved .sgp shards or Channel .mana packets: sigil gather <pieces-or-mana-folder> -o rebuilt.sg1".into(),
        "Rebuild from Frost Rune cold drives: sigil frost mend <frost-dir> -o rebuilt.sg1".into(),
        "Check Vault history for an earlier version: sigil vault versions <vault-or-path> (then sigil vault restore ...)".into(),
    ]
}

/// Recovery options when `sigil mend` fails (`exit 2`).
#[allow(clippy::too_many_arguments)]
pub fn hints_for_mend_failed(
    target: &Path,
    tried_deeper: bool,
    is_work_pack: bool,
    is_sealed_tome: bool,
    is_atlas: bool,
    copies_count: usize,
    tome: Option<&TomeInspection>,
    truncated: bool,
) -> Vec<String> {
    let arg = shell_word(&target.display().to_string());
    if copies_count > 1 {
        return vec![
            format!("Pool an additional copy if you have one: sigil mend {arg} <more-copies.sg1>"),
            "Rebuild from saved .sgp shards or Channel .mana packets: sigil gather <pieces-or-mana-folder> -o rebuilt.sg1".into(),
            "Rebuild from Frost Rune cold drives: sigil frost mend <frost-dir> -o rebuilt.sg1".into(),
            "Check Vault history for an earlier version: sigil vault versions <vault-or-path>".into(),
        ];
    }
    if is_atlas {
        return hints_for_not_recoverable(target, false, None, false, true, false);
    }
    if truncated || tome.is_some() || is_sealed_tome {
        return hints_for_not_recoverable(
            target,
            is_work_pack,
            tome,
            is_sealed_tome,
            false,
            truncated,
        );
    }
    let mut h = Vec::new();
    if !tried_deeper {
        h.push(format!(
            "Try the deeper repair for bit rot too (drop --hard-only): sigil mend {arg}"
        ));
    }
    h.extend(hints_for_not_recoverable(
        target,
        is_work_pack,
        None,
        false,
        false,
        false,
    ));
    h
}

/// Options when a wrong passphrase or secret key failed to unlock a Warded archive (`exit 1`).
pub fn hints_for_wrong_key(has_wards: bool) -> Vec<String> {
    let mut h = vec![
        "Check your passphrase and try again with --pass - (interactive) or --pass-file <path>".into(),
        "If Warded to a recipient key, pass the matching secret key with --identity <me.sgk>".into(),
        "If shared with multiple recipients, ask another listed recipient to unlock it with their .sgk key".into(),
    ];
    if has_wards {
        h.push("If a Tome member has its own Ward, check --ward-file <member>=<pwfile> (or --ward <member>:-)".into());
    } else {
        h.push("If a Tome member has its own Ward, pass --ward-file <member>=<pwfile> (or --ward <member>:-)".into());
    }
    h.push("Sigil Wards have no password reset — if the key is lost, check for an unencrypted backup or an earlier Vault version (sigil vault versions)".into());
    h
}

/// Options when an encrypted/Warded archive was opened without any key (`exit 1`).
pub fn hints_for_missing_key(is_tome_or_sky: bool) -> Vec<String> {
    let mut h = vec![
        "Provide the passphrase interactively with --pass - or from a file with --pass-file <path>".into(),
        "Or pass your authorized secret key with --identity <me.sgk> (or --talisman <keyfile> for a Talisman Ward)".into(),
    ];
    if is_tome_or_sky {
        h.push(
            "If this is a Warded Tome or Constellation, the key also unlocks hidden member names"
                .into(),
        );
    }
    h
}

/// Options when `sigil gather` does not yet have enough shards or Channel mana (`exit 2`).
pub fn hints_for_gather(dir: &Path, is_channel: bool, with_partial: bool) -> Vec<String> {
    let d = shell_word(&dir.display().to_string());
    if is_channel {
        let mut h = vec![
            format!("Print a compact one-line status report to send back to the sender: sigil gather --report {d}"),
            format!("Ask the sender to Channel only the missing mana from that report: sigil deluge --channel <file.sg1> --answer \"<report-line>\" -o {d}"),
            format!("Or ask the sender to Channel more mana packets into the folder: sigil deluge --channel <file.sg1> --extra <N> -o {d}"),
        ];
        if !with_partial {
            h.push(format!(
                "Save a progress receipt without writing an incomplete archive: sigil gather --partial -o <out.sg1> {d}"
            ));
        }
        return h;
    }
    vec![
        format!("Add more .sgp shard pieces to {d} (from another drive, peer, or sigil deluge --extra N) and run sigil gather again"),
        "If these pieces came from Frost Rune drives, place surviving usb-* folders in one directory and run: sigil frost mend <frost-dir> -o <out.sg1>".into(),
        "If you have two damaged .sg1 copies instead, pool their good shards with: sigil mend <copy1.sg1> <copy2.sg1>".into(),
    ]
}

/// Options when `sigil frost mend` does not have enough surviving `usb-*` drives (`exit 2`).
pub fn hints_for_frost_mend(dir: &Path, no_usb_dirs: bool) -> Vec<String> {
    let d = shell_word(&dir.display().to_string());
    if no_usb_dirs {
        return vec![
            format!("Copy the usb-* folders from your surviving Frost Rune drives into {d} and run sigil frost mend again"),
            format!("If you have raw .sgp shard files instead, use: sigil gather {d} -o <out.sg1>"),
        ];
    }
    vec![
        format!("Plug in another surviving drive from this Frost Rune set, copy its usb-* folder into {d}, and run sigil frost mend again"),
        "If you also have extra .sgp shard files or a damaged .sg1 copy, gather them into one folder and run: sigil gather <folder> -o <out.sg1>".into(),
        "Check Vault history if this archive is tracked in a Vault: sigil vault versions <vault-or-path>".into(),
    ]
}

pub fn is_wrong_key_err(msg: &str) -> bool {
    msg.contains("Wrong passphrase or key")
        || msg.contains("could not unwrap CEK")
        || msg.contains("wrong passphrase/identity")
        || msg.contains("Geas not met")
        || msg.contains("seal has no encrypt-to recipients; passphrase required")
}

pub fn is_missing_key_err(msg: &str) -> bool {
    msg.contains("passphrase or --identity required")
        || msg == "passphrase required"
        || msg.contains("member names are hidden; give --pass / --identity")
        || msg.contains("this pack is locked")
        || msg.contains("locked card")
}

/// Classify an `unseal` / `open` failure and attach plain-English recovery options.
pub fn classify_open_error(
    input: &Path,
    err: &str,
    wards: &[(String, String)],
    only: &[String],
    is_open_cmd: bool,
) -> FailureGuidance {
    let arg = shell_word(&input.display().to_string());
    let is_constellation = crate::is_constellation_input(input);
    let is_sealed_tome = crate::is_sealed_dir_pack(input);
    let is_plain_tome = !is_sealed_tome && crate::is_dir_pack(input);
    let is_work = crate::is_work_pack(input);

    // 1. Key errors first (when the shards already decoded, or a Warded Tome card refused the key).
    if is_missing_key_err(err) {
        return FailureGuidance {
            message: err.to_string(),
            hints: hints_for_missing_key(is_sealed_tome || is_plain_tome || is_constellation),
            exit_code: 1,
        };
    }
    if err.contains("wrong passphrase/identity, label edited, or past repair") {
        // Legacy AES-GCM (no SGTO): check whether shards are healthy; if damaged, report damage.
        if !is_work && !is_plain_tome && !is_sealed_tome && !is_constellation {
            if let Ok(bytes) = std::fs::read(input) {
                match assess_star_bytes(&bytes) {
                    StarHealth::Mendable(why) => {
                        return FailureGuidance {
                            message: format!(
                                "Cannot open {arg}: damaged — run sigil mend {arg} ({why})"
                            ),
                            hints: hints_for_scry_mendable(input, false, None, false, false),
                            exit_code: EXIT_REPAIRABLE,
                        };
                    }
                    StarHealth::Unrecoverable(why) => {
                        return FailureGuidance {
                            message: format!(
                                "Cannot open {arg}: too damaged to restore from this copy alone ({why})"
                            ),
                            hints: hints_for_not_recoverable(input, false, None, false, false, false),
                            exit_code: 2,
                        };
                    }
                    StarHealth::Ok | StarHealth::QuickRepairable(_) => {}
                }
            }
        }
        let mut hints = hints_for_wrong_key(!wards.is_empty());
        hints.push(format!(
            "Or check the archive structure without opening: sigil scry {arg}"
        ));
        return FailureGuidance {
            message: format!(
                "Wrong passphrase or key — this Sigil Archive is Warded (or the archive header was edited/damaged): {err}"
            ),
            hints,
            exit_code: 1,
        };
    }
    if is_wrong_key_err(err) {
        return FailureGuidance {
            message: err.to_string(),
            hints: hints_for_wrong_key(!wards.is_empty()),
            exit_code: 1,
        };
    }

    // 2. Truncated Tome (or Tome with damaged members).
    if err.contains("truncated Tome") || err.contains("truncated folder pack") {
        let insp = if is_plain_tome {
            inspect_plain_tome(input).ok()
        } else {
            None
        };
        return FailureGuidance {
            message: format!(
                "Cannot open Tome {arg}: truncated Tome (cut off mid-archive; incomplete copy or transfer)"
            ),
            hints: hints_for_not_recoverable(
                input,
                false,
                insp.as_ref(),
                is_sealed_tome,
                false,
                true,
            ),
            exit_code: 2,
        };
    }

    if is_plain_tome {
        if let Ok(insp) = inspect_plain_tome(input) {
            if insp.truncated {
                let why = insp
                    .truncate_reason
                    .clone()
                    .unwrap_or_else(|| "truncated Tome (cut off mid-archive)".into());
                return FailureGuidance {
                    message: format!("Cannot open Tome {arg}: {why}"),
                    hints: hints_for_not_recoverable(input, false, Some(&insp), false, false, true),
                    exit_code: 2,
                };
            }
            if let Some((rel, why)) = insp.unrecoverable.first() {
                return FailureGuidance {
                    message: format!(
                        "Cannot open Tome {arg}: too damaged — member '{rel}' cannot be restored ({why})"
                    ),
                    hints: hints_for_not_recoverable(
                        input,
                        false,
                        Some(&insp),
                        false,
                        false,
                        false,
                    ),
                    exit_code: 2,
                };
            }
            if let Some((rel, why)) = insp.mendable.first() {
                return FailureGuidance {
                    message: format!(
                        "Cannot open Tome {arg}: damaged — run sigil mend {arg} (member '{rel}': {why})"
                    ),
                    hints: hints_for_scry_mendable(input, false, Some(&insp), false, false),
                    exit_code: EXIT_REPAIRABLE,
                };
            }
        }
    }

    if is_sealed_tome {
        if let Ok(Some((_, body))) = crate::sealed_dir_body(input) {
            match assess_star_bytes(&body) {
                StarHealth::Mendable(why) => {
                    return FailureGuidance {
                        message: format!(
                            "Cannot open Warded Tome {arg}: damaged — run sigil mend {arg} ({why})"
                        ),
                        hints: hints_for_scry_mendable(input, false, None, true, false),
                        exit_code: EXIT_REPAIRABLE,
                    };
                }
                StarHealth::Unrecoverable(why) => {
                    return FailureGuidance {
                        message: format!(
                            "Cannot open Warded Tome {arg}: too damaged to restore from this copy alone ({why})"
                        ),
                        hints: hints_for_not_recoverable(input, false, None, true, false, false),
                        exit_code: 2,
                    };
                }
                StarHealth::Ok | StarHealth::QuickRepairable(_) => {}
            }
        }
    }

    if is_constellation {
        if let Ok((_, verdict)) = crate::recovery::scry_constellation_assessed(input, None, &[]) {
            match verdict {
                ScryVerdict::DamagedMendable(why) => {
                    return FailureGuidance {
                        message: format!(
                            "Cannot open Constellation {arg}: damaged — run sigil mend {arg} ({why})"
                        ),
                        hints: hints_for_scry_mendable(input, false, None, false, true),
                        exit_code: EXIT_REPAIRABLE,
                    };
                }
                ScryVerdict::NotRecoverable(why) => {
                    return FailureGuidance {
                        message: format!("Cannot open Constellation {arg}: too damaged ({why})"),
                        hints: hints_for_not_recoverable(input, false, None, false, true, false),
                        exit_code: 2,
                    };
                }
                _ => {}
            }
        }
    }

    if is_work {
        if let Ok(health) = assess_work_pack_path(input) {
            match health {
                StarHealth::Mendable(why) => {
                    return FailureGuidance {
                        message: format!(
                            "Cannot open {arg}: damaged — run sigil mend {arg} ({why})"
                        ),
                        hints: hints_for_scry_mendable(input, true, None, false, false),
                        exit_code: EXIT_REPAIRABLE,
                    };
                }
                StarHealth::Unrecoverable(why) => {
                    return FailureGuidance {
                        message: format!(
                            "Cannot open {arg}: too damaged to restore from this copy alone ({why})"
                        ),
                        hints: hints_for_not_recoverable(input, true, None, false, false, false),
                        exit_code: 2,
                    };
                }
                StarHealth::Ok | StarHealth::QuickRepairable(_) => {}
            }
        }
    } else if !is_plain_tome && !is_sealed_tome && !is_constellation {
        if let Ok(bytes) = std::fs::read(input) {
            match assess_star_bytes(&bytes) {
                StarHealth::Mendable(why) => {
                    let mut hints = hints_for_scry_mendable(input, false, None, false, false);
                    if is_open_cmd {
                        // Replace generic open-in-memory phrasing so it mentions `open` alternative clearly.
                        if let Some(slot) = hints.iter_mut().find(|s| s.contains("--repair")) {
                            *slot = format!(
                                "Or extract in memory without saving a repaired archive: sigil unseal --repair -o <out> {arg}"
                            );
                        }
                    }
                    return FailureGuidance {
                        message: format!(
                            "Cannot open {arg}: damaged — run sigil mend {arg} ({why})"
                        ),
                        hints,
                        exit_code: EXIT_REPAIRABLE,
                    };
                }
                StarHealth::Unrecoverable(why) => {
                    return FailureGuidance {
                        message: format!(
                            "Cannot open {arg}: too damaged to restore from this copy alone ({why})"
                        ),
                        hints: hints_for_not_recoverable(input, false, None, false, false, false),
                        exit_code: 2,
                    };
                }
                StarHealth::Ok | StarHealth::QuickRepairable(_) => {}
            }
        }
    }

    // 3. Fallback for damage-shaped errors or general errors.
    let _ = only;
    let damage_like = err.contains("need ")
        || err.contains("pieces")
        || err.contains("too damaged")
        || err.contains("past repair")
        || err.contains("not enough")
        || err.contains("Merkle")
        || err.contains("SHA-256 mismatch")
        || err.contains("failed to fill whole buffer")
        || err.contains("more than one seal");
    if damage_like {
        return FailureGuidance {
            message: format!("Cannot open {arg}: {err}"),
            hints: hints_for_not_recoverable(
                input,
                is_work,
                None,
                is_sealed_tome,
                is_constellation,
                false,
            ),
            exit_code: 2,
        };
    }

    FailureGuidance {
        message: err.to_string(),
        hints: vec![format!("Check archive structure first: sigil scry {arg}")],
        exit_code: 1,
    }
}

/// Assess a Constellation or Atlas bag for `scry` / `verify`.
pub fn scry_constellation_assessed(
    input: &Path,
    pass: Option<&str>,
    identities: &[Identity],
) -> Result<(String, ScryVerdict)> {
    let (text, bad) = crate::scry_constellation_checked(input, pass, identities)?;
    if let Some(why) = bad {
        return Ok((text, ScryVerdict::NotRecoverable(why)));
    }
    // Check whether any member star needs mend (quick vs deeper).
    let resolved = crate::container::sky_for_read(input);
    let rpath = resolved.as_path();
    let check_dir = |c: &crate::Chart, d: &Path, card: Option<&Path>| -> ScryVerdict {
        let by_digest = crate::constellation::index_stars(d, card);
        for m in c.members.iter().filter(|m| m.bytes.is_empty()) {
            if let Some(p) = crate::constellation::find_member_star(d, m, &by_digest) {
                if let Ok(bytes) = std::fs::read(&p) {
                    if let StarHealth::Mendable(why) = assess_star_bytes(&bytes) {
                        return ScryVerdict::DamagedMendable(format!("{}: {why}", m.name));
                    }
                }
            }
        }
        ScryVerdict::Healthy
    };
    let verdict = if crate::is_atlas_file(rpath) {
        crate::constellation::with_extracted_atlas(rpath, |tmp| {
            let (c, d) = crate::constellation::load_chart_keys(tmp, pass, identities)?;
            let k = crate::constellation::find_card(tmp);
            Ok(check_dir(&c, &d, k.as_deref()))
        })?
    } else {
        let (c, d) = crate::constellation::load_chart_keys(rpath, pass, identities)?;
        let card = if rpath.is_dir() {
            crate::constellation::find_card(rpath)
        } else if crate::is_constellation_mark(rpath) {
            Some(rpath.to_path_buf())
        } else {
            crate::constellation::find_card(&d)
        };
        check_dir(&c, &d, card.as_deref())
    };
    Ok((text, verdict))
}
