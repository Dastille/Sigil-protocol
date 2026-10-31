//! Structured `scry` / `verify` facts for `--json`, read from library data (headers, shard
//! counts, the same recoverability checks Scry and `doctor` use) — never from report text.

use crate::doctor::{health_file, Health};
use crate::Result;
use std::path::Path;

/// Overall condition, as scripts should branch on it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Verdict {
    /// Every piece checked is intact.
    Healthy,
    /// Damaged but repairable (`sigil mend`).
    NeedsRepair,
    /// Too few intact pieces left in this copy.
    NotRecoverable,
}

impl Verdict {
    /// `healthy`, `needs-repair` or `not-recoverable`.
    pub fn as_str(self) -> &'static str {
        match self {
            Verdict::Healthy => "healthy",
            Verdict::NeedsRepair => "needs-repair",
            Verdict::NotRecoverable => "not-recoverable",
        }
    }
}

/// Facts from a single-file mark's header and shards.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct MarkFacts {
    pub version: u8,
    /// Intact shards found.
    pub live: u32,
    /// Shards written.
    pub total: u32,
    /// Shards needed to restore.
    pub need: u32,
    pub shard_len: u32,
    pub merkle_closed: bool,
    /// The header was rebuilt from a backup copy.
    pub header_recovered: bool,
    pub encrypted: bool,
    pub compressed: bool,
    /// v3 private label: name and size are inside the lock.
    pub private_label: bool,
    /// Original size; `None` when the label is private.
    pub orig_len: Option<u64>,
}

/// Facts from a large-file (work) pack head.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct PackFacts {
    pub parts_total: u32,
    pub parts_present: u64,
    pub chunk_size: u32,
    pub overture: u32,
    /// Original size; `None` when hidden inside the lock.
    pub orig_len: Option<u64>,
}

/// Star counts of a constellation.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct StarCounts {
    pub members: u64,
    /// Members carried inside the card itself.
    pub packed: u64,
    /// Members whose star file was found.
    pub present: u64,
    pub missing: u64,
    pub needs_repair: u64,
    pub beyond_repair: u64,
}

/// What `scry --json` / `verify --json` report as `status`.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct ScryStatus {
    /// `mark`, `work-pack`, `folder-pack` or `constellation`.
    pub kind: &'static str,
    pub verdict: Verdict,
    /// Why the copy is not recoverable.
    pub reason: Option<String>,
    /// What is damaged but repairable.
    pub repair: Option<String>,
    pub mark: Option<MarkFacts>,
    pub pack: Option<PackFacts>,
    /// Folder pack: member count; `encrypted` says whether names are sealed.
    pub members: Option<u64>,
    pub encrypted: Option<bool>,
    pub stars: Option<StarCounts>,
}

fn verdict_of(bad: Option<String>, h: Health) -> (Verdict, Option<String>, Option<String>) {
    match (bad, h) {
        (Some(why), _) => (Verdict::NotRecoverable, Some(why), None),
        (None, Health::Ok) => (Verdict::Healthy, None, None),
        // Recoverable per Scry; doctor's finding is what needs mending.
        (None, Health::Mendable(m)) | (None, Health::Damaged(m)) => {
            (Verdict::NeedsRepair, None, Some(m))
        }
    }
}

/// Status of one file: a mark, a large-file pack or a folder pack (keyless).
pub fn scry_status_path(input: &Path) -> Result<ScryStatus> {
    let mut st = ScryStatus {
        kind: "mark",
        verdict: Verdict::Healthy,
        reason: None,
        repair: None,
        mark: None,
        pack: None,
        members: None,
        encrypted: None,
        stars: None,
    };
    let bad = if crate::is_dir_pack(input) {
        st.kind = "folder-pack";
        if let Some((n, _)) = crate::sealed_dir_body(input)? {
            st.members = Some(u64::from(n));
            st.encrypted = Some(true);
        } else {
            st.members = Some(crate::list_dir_pack(input)?.len() as u64);
            st.encrypted = Some(false);
        }
        crate::folder::dir_unrecoverable(input)?
    } else if crate::is_work_pack(input) {
        st.kind = "work-pack";
        let (head, locs) = crate::index_pack(input)?;
        st.pack = Some(PackFacts {
            parts_total: head.stars,
            parts_present: locs.len() as u64,
            chunk_size: head.chunk_size,
            overture: head.overture,
            orig_len: if crate::work::total_hidden(&head) {
                None
            } else {
                Some(head.orig_total)
            },
        });
        crate::path_unrecoverable(input)?
    } else {
        let data = std::fs::read(input).map_err(|e| crate::Error::Msg(e.to_string()))?;
        let (h, merkle_ok, live, k, recovered) = crate::verify(&data)?;
        st.mark = Some(MarkFacts {
            version: h.version,
            live: live as u32,
            total: u32::from(h.n),
            need: k as u32,
            shard_len: h.shard_len,
            merkle_closed: merkle_ok,
            header_recovered: recovered,
            encrypted: h.encrypted(),
            compressed: h.compressed(),
            private_label: h.private_label(),
            orig_len: if h.private_label() {
                None
            } else {
                Some(h.orig_len)
            },
        });
        crate::path_unrecoverable(input)?
    };
    let (v, reason, repair) = verdict_of(bad, health_file(input));
    st.verdict = v;
    st.reason = reason;
    st.repair = repair;
    Ok(st)
}

/// Status of a constellation (folder, card or atlas), trying `pass` / `identities` on a
/// locked card. Atlas members are not checked star by star (same as Scry).
pub fn scry_status_constellation(
    input: &Path,
    pass: Option<&str>,
    identities: &[crate::keys::Identity],
) -> Result<ScryStatus> {
    let (_, bad) = crate::scry_constellation_checked(input, pass, identities)?;
    let resolved = crate::container::sky_for_read(input);
    let input = resolved.as_path();
    let (chart, dir) = crate::constellation::load_chart_keys(input, pass, identities)?;
    let in_atlas = crate::is_atlas_file(input);
    let card = if input.is_dir() {
        crate::constellation::find_card(input)
    } else if crate::is_constellation_mark(input) {
        Some(input.to_path_buf())
    } else {
        crate::constellation::find_card(&dir)
    };
    let by_digest = crate::constellation::index_stars(&dir, card.as_deref());
    let mut c = StarCounts {
        members: chart.members.len() as u64,
        ..StarCounts::default()
    };
    let mut seen = std::collections::HashSet::new();
    let mut mend: Vec<String> = Vec::new();
    for m in &chart.members {
        if !m.bytes.is_empty() {
            c.packed += 1;
            continue;
        }
        if in_atlas {
            continue;
        }
        match crate::constellation::find_member_star(&dir, m, &by_digest) {
            None => c.missing += 1,
            Some(p) => {
                c.present += 1;
                if !seen.insert(p.clone()) {
                    continue;
                }
                match health_file(&p) {
                    Health::Ok => {}
                    Health::Mendable(w) => {
                        c.needs_repair += 1;
                        mend.push(format!("{}: {w}", m.name));
                    }
                    Health::Damaged(_) => c.beyond_repair += 1,
                }
            }
        }
    }
    let verdict = if bad.is_some() {
        Verdict::NotRecoverable
    } else if c.needs_repair > 0 {
        Verdict::NeedsRepair
    } else {
        Verdict::Healthy
    };
    Ok(ScryStatus {
        kind: "constellation",
        verdict,
        reason: bad,
        repair: if mend.is_empty() {
            None
        } else {
            Some(mend.join("; "))
        },
        mark: None,
        pack: None,
        members: None,
        encrypted: None,
        stars: Some(c),
    })
}
