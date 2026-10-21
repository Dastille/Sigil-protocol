//! `sigil gc`: reclaim orphans and temp files from a tidy container (or old layout).
//!
//! Safety rules (see `docs/CONTAINER.md`):
//!
//! * **Report-only by default.** Nothing is deleted unless `apply` is set.
//! * Never deletes a member the card / CHART still references. A constellation card that
//!   cannot be opened (locked, no keys) stops gc — it will not guess what is referenced.
//! * Never touches `cold/` (cold kits are history the owner chose to keep) nor files it
//!   does not recognise (they are listed as "left alone").
//! * Only containers are reclaimed; an old flat constellation is reported, not deleted
//!   (run `sigil tidy` first).
//! * Temp files (`*.part`, stale `.tidy-*` staging) are only reclaimed once they are older
//!   than `temp_age_secs`, so a write in progress is never pulled out from under itself.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime};

use crate::container;
use crate::keys::Identity;
use crate::Result;

/// Default minimum age before a temp file counts as abandoned.
pub const DEFAULT_TEMP_AGE_SECS: u64 = 3600;

fn err(s: impl Into<String>) -> crate::Error {
    crate::Error::Msg(s.into())
}

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum GcKind {
    /// Star on disk that no list entry needs.
    OrphanStar,
    /// Segment file beyond a segment log's INDEX (crashed append), old enough to be sure.
    OrphanSegment,
    /// Segment file of a log entry that a tombstone deleted (erasure still pending).
    DeletedSegment,
    /// Segment file whose batches were merged into a later compaction segment.
    SupersededSegment,
    /// `vN.sg1` that the CHART does not list.
    OrphanVersion,
    /// Second byte-identical copy of a star whose canonical sharded copy exists.
    DuplicateStar,
    /// Abandoned `*.part` write.
    Temp,
    /// Interrupted `sigil tidy` staging folder.
    StaleStaging,
    /// Shard folder left empty.
    EmptyDir,
    /// Key ring shard holding records of segments that are gone, merged away or shredded
    /// (segment-keys logs): the records are destroyed, the shard is rewritten without them.
    DeadKey,
}

impl GcKind {
    pub fn label(self) -> &'static str {
        match self {
            GcKind::OrphanStar => "orphan star",
            GcKind::OrphanSegment => "orphan segment",
            GcKind::DeletedSegment => "deleted segment",
            GcKind::SupersededSegment => "superseded seg.",
            GcKind::OrphanVersion => "orphan version",
            GcKind::DuplicateStar => "duplicate star",
            GcKind::Temp => "temp file",
            GcKind::StaleStaging => "stale staging",
            GcKind::EmptyDir => "empty folder",
            GcKind::DeadKey => "dead key(s)",
        }
    }
}

#[derive(Clone, Debug)]
pub struct GcItem {
    pub kind: GcKind,
    pub path: PathBuf,
    pub bytes: u64,
    /// True once deleted (always false on a dry run).
    pub removed: bool,
}

#[derive(Clone, Debug, Default)]
pub struct GcReport {
    /// `vault` or `constellation`.
    pub kind: String,
    pub root: PathBuf,
    /// `container` or `old layout`.
    pub layout: String,
    pub apply: bool,
    pub items: Vec<GcItem>,
    /// Members the card / CHART references that were found and kept.
    pub kept: usize,
    /// Files gc does not recognise and never touches.
    pub left: Vec<PathBuf>,
    pub notes: Vec<String>,
}

impl GcReport {
    pub fn reclaimable_bytes(&self) -> u64 {
        self.items.iter().map(|i| i.bytes).sum()
    }

    pub fn removed_count(&self) -> usize {
        self.items.iter().filter(|i| i.removed).count()
    }

    pub fn render(&self) -> String {
        let mut s = format!(
            "gc {} ({}, {})\n",
            self.root.display(),
            self.kind,
            self.layout
        );
        for i in &self.items {
            let rel = i.path.strip_prefix(&self.root).unwrap_or(&i.path);
            let verb = if i.removed {
                "removed "
            } else if self.apply {
                "FAILED  "
            } else {
                ""
            };
            s.push_str(&format!(
                "  {verb}{:<15} {}  ({} bytes)\n",
                i.kind.label(),
                rel.display(),
                i.bytes
            ));
        }
        s.push_str(&format!("  kept {} referenced member(s)\n", self.kept));
        for l in &self.left {
            let rel = l.strip_prefix(&self.root).unwrap_or(l);
            s.push_str(&format!("  left alone: {}\n", rel.display()));
        }
        for n in &self.notes {
            s.push_str(&format!("  note: {n}\n"));
        }
        let n = self.items.len();
        if n == 0 {
            s.push_str("nothing to reclaim\n");
        } else if self.apply {
            s.push_str(&format!(
                "reclaimed {} of {} item(s), {} bytes\n",
                self.removed_count(),
                n,
                self.items
                    .iter()
                    .filter(|i| i.removed)
                    .map(|i| i.bytes)
                    .sum::<u64>()
            ));
        } else {
            s.push_str(&format!(
                "dry run: nothing was changed. {} item(s), {} bytes could be reclaimed; re-run with --apply\n",
                n,
                self.reclaimable_bytes()
            ));
        }
        s
    }
}

pub struct GcOpts<'a> {
    /// Delete for real. `false` = report only (the default everywhere).
    pub apply: bool,
    /// Passphrase for a warded constellation card.
    pub pass: Option<&'a str>,
    /// Identities that open an encrypt-to card.
    pub identities: &'a [Identity],
    /// Temp files younger than this are left alone.
    pub temp_age_secs: u64,
}

impl Default for GcOpts<'_> {
    fn default() -> Self {
        GcOpts {
            apply: false,
            pass: None,
            identities: &[],
            temp_age_secs: DEFAULT_TEMP_AGE_SECS,
        }
    }
}

fn old_enough(p: &Path, secs: u64) -> bool {
    if secs == 0 {
        return true;
    }
    fs::metadata(p)
        .and_then(|m| m.modified())
        .ok()
        .and_then(|t| SystemTime::now().duration_since(t).ok())
        .map(|d| d >= Duration::from_secs(secs))
        .unwrap_or(false)
}

fn size_of(p: &Path) -> u64 {
    match fs::metadata(p) {
        Ok(m) if m.is_dir() => fs::read_dir(p)
            .map(|rd| rd.flatten().map(|e| size_of(&e.path())).sum())
            .unwrap_or(0),
        Ok(m) => m.len(),
        Err(_) => 0,
    }
}

fn name_of(p: &Path) -> String {
    p.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("")
        .to_string()
}

fn entries(dir: &Path) -> Vec<PathBuf> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir)
        .map(|r| r.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    v.sort();
    v
}

/// `v<digits>.sg1`
pub(crate) fn is_version_seal_name(n: &str) -> bool {
    n.strip_prefix('v')
        .and_then(|r| r.strip_suffix(".sg1"))
        .map(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or(false)
}

/// Sibling `.tidy-<name>` staging left by an interrupted `sigil tidy`.
fn stale_staging(root: &Path, opts: &GcOpts<'_>, rep: &mut GcReport) {
    let Some(parent) = root.parent() else { return };
    let parent = if parent.as_os_str().is_empty() {
        Path::new(".")
    } else {
        parent
    };
    let st = parent.join(format!(".tidy-{}", name_of(root)));
    if st.is_dir() && old_enough(&st, opts.temp_age_secs) {
        rep.items.push(GcItem {
            kind: GcKind::StaleStaging,
            path: st.clone(),
            bytes: size_of(&st),
            removed: false,
        });
    }
}

/// What a user path points at.
pub(crate) enum Target {
    /// Chart dir (`name.sigil/` container or `name.sgv/`).
    Vault(PathBuf),
    /// Constellation folder (container or old flat).
    Sky(PathBuf),
    /// Segment log container (`kind=log`).
    Log(PathBuf),
}

pub(crate) fn resolve_target(path: &Path) -> Result<Target> {
    let path = path.components().as_path().to_path_buf();
    for cand in [path.clone(), container::with_suffix(&path)] {
        if container::is_container(&cand)
            && container::read_manifest(&cand)
                .map(|m| m.kind == crate::seglog::KIND)
                .unwrap_or(false)
        {
            return Ok(Target::Log(cand));
        }
    }
    let sky = container::sky_for_read(&path);
    let is_sky_container = container::is_container(&sky)
        && container::read_manifest(&sky)
            .map(|m| m.kind == "constellation")
            .unwrap_or(false);
    if !is_sky_container {
        if let Ok((_live, vdir)) = crate::vault::resolve_paths(&path) {
            if vdir.join(crate::vault::CHART_NAME).is_file() {
                return Ok(Target::Vault(vdir));
            }
        }
    }
    if sky.is_dir() && crate::constellation::find_card(&sky).is_some() {
        return Ok(Target::Sky(sky));
    }
    Err(err(format!(
        "nothing found at {} (not a tracked vault, nor a constellation folder / container)",
        path.display()
    )))
}

/// Garbage-collect the vault or constellation at `path`.
pub fn gc(path: &Path, opts: &GcOpts<'_>) -> Result<GcReport> {
    match resolve_target(path).map_err(|_| {
        err(format!(
            "nothing to gc at {} (not a tracked vault, nor a constellation folder / container)",
            path.display()
        ))
    })? {
        Target::Vault(v) => gc_vault(&v, opts),
        Target::Sky(s) => gc_sky(&s, opts),
        Target::Log(l) => gc_log(&l, opts),
    }
}

/// Segment log: only segments *beyond* the INDEX (a crashed append) and old enough can go,
/// plus segment files the INDEX itself declares dead (deleted by a tombstone, or merged into a
/// compaction segment, judged only from entries the HEAD vouches for), abandoned temp files and
/// emptied shard folders. A segment that is still needed is never even a candidate; a damaged
/// INDEX or a HEAD ahead of the INDEX stops gc entirely.
fn gc_log(dir: &Path, opts: &GcOpts<'_>) -> Result<GcReport> {
    use crate::seglog::ExtraKind;
    let log = crate::seglog::Log::open(dir)?;
    let gate = crate::seglog::gc_gate(&log)?;
    let mut rep = GcReport {
        kind: "log".into(),
        root: dir.to_path_buf(),
        layout: "container".into(),
        apply: opts.apply,
        kept: gate.kept,
        ..Default::default()
    };
    for x in crate::seglog::scan_extras(&log, &gate.entries, gate.trusted, opts.temp_age_secs) {
        match x.kind {
            ExtraKind::Orphan => rep.items.push(GcItem {
                kind: GcKind::OrphanSegment,
                path: x.path,
                bytes: x.bytes,
                removed: false,
            }),
            ExtraKind::Temp => rep.items.push(GcItem {
                kind: GcKind::Temp,
                path: x.path,
                bytes: x.bytes,
                removed: false,
            }),
            ExtraKind::Stale(crate::seglog::Slot::DeadDeleted) => rep.items.push(GcItem {
                kind: GcKind::DeletedSegment,
                path: x.path,
                bytes: x.bytes,
                removed: false,
            }),
            ExtraKind::Stale(_) => rep.items.push(GcItem {
                kind: GcKind::SupersededSegment,
                path: x.path,
                bytes: x.bytes,
                removed: false,
            }),
            ExtraKind::EmptyDir => rep.items.push(GcItem {
                kind: GcKind::EmptyDir,
                path: x.path,
                bytes: 0,
                removed: false,
            }),
            ExtraKind::Recent => rep.notes.push(format!(
                "recent unindexed segment kept (append may be running): {}",
                x.path.display()
            )),
            ExtraKind::Unknown => rep.left.push(x.path),
        }
    }
    // Key records nothing needs any more (crypto-shred leftovers, deleted / merged segments,
    // crashed appends). Removing a record is a ring rewrite, not a file delete.
    if log.segkeys {
        match crate::seglog::dead_keys(&log, &gate) {
            Ok(dead) if !dead.is_empty() => {
                let mut shards: std::collections::BTreeMap<u64, Vec<u64>> =
                    std::collections::BTreeMap::new();
                for s in &dead {
                    shards
                        .entry(crate::seglog::keyring_shard_of(*s))
                        .or_default()
                        .push(*s);
                }
                let first = rep.items.len();
                for (shard, seqs) in &shards {
                    rep.items.push(GcItem {
                        kind: GcKind::DeadKey,
                        path: crate::seglog::keyring_shard_path(dir, *shard),
                        bytes: 0,
                        removed: false,
                    });
                    rep.notes.push(format!(
                        "dead key record(s) for segment(s) {} in keys/{shard:04}.sg1",
                        crate::seglog::fmt_ranges(&crate::seglog::compress(seqs))
                    ));
                }
                if opts.apply {
                    match crate::seglog::reclaim_dead_keys(&log) {
                        Ok(_) => rep.items[first..].iter_mut().for_each(|i| i.removed = true),
                        Err(e) => rep
                            .notes
                            .push(format!("could not destroy dead key records: {e}")),
                    }
                }
            }
            Ok(_) => {}
            Err(e) => rep.notes.push(e.to_string()),
        }
    }
    finish(&mut rep);
    Ok(rep)
}

fn finish(rep: &mut GcReport) {
    if !rep.apply {
        return;
    }
    // Files first, folders after (so emptied shard folders can go in the same run).
    let mut order: Vec<usize> = (0..rep.items.len()).collect();
    order.sort_by_key(|&i| matches!(rep.items[i].kind, GcKind::EmptyDir | GcKind::StaleStaging));
    for i in order {
        let it = &mut rep.items[i];
        if it.kind == GcKind::DeadKey {
            continue; // already handled by the log's own key ring code
        }
        let r = match it.kind {
            GcKind::StaleStaging => fs::remove_dir_all(&it.path),
            GcKind::EmptyDir => fs::remove_dir(&it.path),
            _ => fs::remove_file(&it.path),
        };
        match r {
            Ok(()) => it.removed = true,
            Err(e) => rep
                .notes
                .push(format!("could not remove {}: {e}", it.path.display())),
        }
    }
}

fn gc_vault(vdir: &Path, opts: &GcOpts<'_>) -> Result<GcReport> {
    let chart = crate::vault::load_chart(vdir)?;
    let is_container = crate::vault::is_container_vault_dir(vdir);
    let mut rep = GcReport {
        kind: "vault".into(),
        root: vdir.to_path_buf(),
        layout: if is_container {
            "container".into()
        } else {
            "old layout".into()
        },
        apply: opts.apply,
        ..Default::default()
    };
    let listed: HashSet<&str> = chart.versions.iter().map(|v| v.seal.as_str()).collect();
    let seals_dir = if is_container {
        vdir.join(container::VERSIONS_DIR)
    } else {
        vdir.to_path_buf()
    };
    for p in entries(&seals_dir) {
        let n = name_of(&p);
        if p.is_dir() {
            rep.left.push(p);
            continue;
        }
        if is_version_seal_name(&n) {
            if listed.contains(n.as_str()) {
                rep.kept += 1;
            } else {
                rep.items.push(GcItem {
                    kind: GcKind::OrphanVersion,
                    bytes: size_of(&p),
                    path: p,
                    removed: false,
                });
            }
        } else if n.ends_with(".part") {
            if old_enough(&p, opts.temp_age_secs) {
                rep.items.push(GcItem {
                    kind: GcKind::Temp,
                    bytes: size_of(&p),
                    path: p,
                    removed: false,
                });
            } else {
                rep.notes.push(format!("recent temp file kept: {n}"));
            }
        } else if !is_container && (n == crate::vault::CHART_NAME || n == crate::vault::DIRTY_NAME)
        {
            // regular sidecar files
        } else {
            rep.left.push(p);
        }
    }
    if is_container {
        for p in entries(vdir) {
            let n = name_of(&p);
            if n == container::CONTAINER_FILE
                || n == crate::vault::CHART_NAME
                || n == container::VERSIONS_DIR
                || n == container::COLD_DIR
            {
                continue;
            }
            if n.ends_with(".part") && p.is_file() {
                if old_enough(&p, opts.temp_age_secs) {
                    rep.items.push(GcItem {
                        kind: GcKind::Temp,
                        bytes: size_of(&p),
                        path: p,
                        removed: false,
                    });
                }
                continue;
            }
            rep.left.push(p);
        }
        let cold = vdir.join(container::COLD_DIR);
        if cold.is_dir() {
            rep.notes.push(format!(
                "cold/ holds {} kit folder(s); gc never touches cold kits",
                entries(&cold).len()
            ));
        }
        stale_staging(vdir, opts, &mut rep);
    }
    for v in &chart.versions {
        if !crate::vault::seal_path_in(vdir, &v.seal).is_file() {
            rep.notes.push(format!(
                "CHART lists v{} but its seal is missing (see `sigil doctor`)",
                v.n
            ));
        }
    }
    finish(&mut rep);
    Ok(rep)
}

/// 64-hex stem of a sharded star file name.
fn hex_stem(p: &Path) -> Option<[u8; 32]> {
    let n = name_of(p);
    let stem = n.strip_suffix(".sg1")?;
    if stem.len() != 64 {
        return None;
    }
    let b = hex::decode(stem).ok()?;
    b.try_into().ok()
}

fn star_digest(p: &Path) -> Option<[u8; 32]> {
    // New encrypted stars are keyed by their keyless private id (see constellation).
    if let Some(id) = crate::constellation::private_star_id(p) {
        return Some(id);
    }
    if crate::work::is_work_pack(p) {
        hex_stem(p)
    } else {
        crate::constellation::peek_digest(p)
    }
}

fn gc_sky(sky: &Path, opts: &GcOpts<'_>) -> Result<GcReport> {
    let is_container = container::is_container(sky);
    if is_container {
        container::read_manifest(sky)?;
    }
    let card = crate::constellation::find_card(sky).ok_or_else(|| err("no constellation card"))?;
    let chart = crate::constellation::load_chart_from_mark(&card, opts.pass, opts.identities).map_err(|e| {
        err(format!(
            "cannot open the card ({e}); gc will not guess which stars are referenced. Give --pass / --identity"
        ))
    })?;
    let mut rep = GcReport {
        kind: "constellation".into(),
        root: sky.to_path_buf(),
        layout: if is_container {
            "container".into()
        } else {
            "old layout".into()
        },
        apply: opts.apply && is_container,
        ..Default::default()
    };
    if !is_container {
        rep.notes.push("old flat layout: orphans are reported only; run `sigil tidy` first to let gc reclaim them".into());
    }
    let referenced: HashSet<[u8; 32]> = chart
        .members
        .iter()
        .filter(|m| m.bytes.is_empty())
        // `merkle` is the private id of a new encrypted star (its file key).
        .flat_map(|m| [m.digest, m.merkle])
        .filter(|d| *d != [0u8; 32])
        .collect();
    let embedded = chart.members.iter().filter(|m| !m.bytes.is_empty()).count();
    rep.kept += embedded;
    let mut seen_digest: HashSet<[u8; 32]> = HashSet::new();
    // Flat layout: scan root-level stars; container: stars/ plus any stray root-level star.
    let mut files: Vec<PathBuf> = Vec::new();
    let mut shard_dirs: Vec<(PathBuf, Vec<PathBuf>)> = Vec::new();
    let stars = sky.join(container::STARS_DIR);
    if is_container && stars.is_dir() {
        for shard in entries(&stars) {
            if shard.is_dir() {
                let ents = entries(&shard);
                files.extend(ents.iter().filter(|p| p.is_file()).cloned());
                shard_dirs.push((shard.clone(), ents));
            } else {
                files.push(shard);
            }
        }
    }
    for p in entries(sky) {
        let n = name_of(&p);
        if p.is_dir() {
            if !(n == container::STARS_DIR || n == container::COLD_DIR && is_container) {
                rep.left.push(p);
            }
            continue;
        }
        if p == card || n == container::CONTAINER_FILE {
            continue;
        }
        if n.ends_with(".part") {
            if is_container && old_enough(&p, opts.temp_age_secs) {
                rep.items.push(GcItem {
                    kind: GcKind::Temp,
                    bytes: size_of(&p),
                    path: p,
                    removed: false,
                });
            } else {
                rep.notes.push(format!("recent temp file kept: {n}"));
            }
            continue;
        }
        let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
        if ext == "sga" && crate::constellation::is_atlas_file(&p) {
            continue;
        }
        if ext == "sg1" && crate::constellation::is_constellation_mark(&p) {
            rep.notes
                .push(format!("another card-like mark left alone: {n}"));
            continue;
        }
        if ext == "sg1" {
            files.push(p);
        } else {
            rep.left.push(p);
        }
    }
    let canonical = |d: &[u8; 32]| container::star_path(sky, d);
    for p in files {
        let n = name_of(&p);
        if n.ends_with(".part") {
            if old_enough(&p, opts.temp_age_secs) {
                rep.items.push(GcItem {
                    kind: GcKind::Temp,
                    bytes: size_of(&p),
                    path: p,
                    removed: false,
                });
            } else {
                rep.notes.push(format!("recent temp file kept: {n}"));
            }
            continue;
        }
        if p.extension().and_then(|x| x.to_str()) != Some("sg1") {
            rep.left.push(p);
            continue;
        }
        let Some(d) = star_digest(&p) else {
            rep.left.push(p);
            continue;
        };
        if !referenced.contains(&d) {
            rep.items.push(GcItem {
                kind: GcKind::OrphanStar,
                bytes: size_of(&p),
                path: p,
                removed: false,
            });
            continue;
        }
        let canon = canonical(&d);
        if p == canon {
            if seen_digest.insert(d) {
                rep.kept += 1;
            }
            continue;
        }
        // Referenced, but not at its canonical path. A byte-identical copy is redundant only
        // when the canonical file really is there.
        let identical = canon.is_file()
            && crate::sha256_path(&canon).ok().is_some()
            && crate::sha256_path(&canon).ok() == crate::sha256_path(&p).ok();
        if identical {
            rep.items.push(GcItem {
                kind: GcKind::DuplicateStar,
                bytes: size_of(&p),
                path: p,
                removed: false,
            });
        } else if seen_digest.insert(d) {
            rep.kept += 1;
        }
    }
    // Shard folders that end up empty.
    let planned: HashSet<&Path> = rep.items.iter().map(|i| i.path.as_path()).collect();
    let mut empties = Vec::new();
    for (dir, ents) in &shard_dirs {
        if ents.iter().all(|e| planned.contains(e.as_path())) {
            empties.push(dir.clone());
        }
    }
    for dir in empties {
        rep.items.push(GcItem {
            kind: GcKind::EmptyDir,
            path: dir,
            bytes: 0,
            removed: false,
        });
    }
    // Referenced members whose star is nowhere (not gc's job to fix; point at doctor).
    let by_digest = crate::constellation::index_stars(sky, Some(&card));
    for m in chart.members.iter().filter(|m| m.bytes.is_empty()) {
        if crate::constellation::find_member_star(sky, m, &by_digest).is_none() {
            rep.notes.push(format!(
                "list entry {} has no star on disk (see `sigil doctor`)",
                m.name
            ));
        }
    }
    if is_container {
        stale_staging(sky, opts, &mut rep);
        let cold = sky.join(container::COLD_DIR);
        if cold.is_dir() {
            rep.notes.push("cold/ is never touched by gc".into());
        }
    }
    finish(&mut rep);
    Ok(rep)
}
