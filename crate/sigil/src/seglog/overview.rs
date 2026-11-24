//! Read-only overview helpers for a segment log: the live file set (newest version of every
//! `log add` path), a fast condition check that never opens segment bytes, and finding a file
//! by its stored name for `sigil log read --name`.
//!
//! Nothing here writes to the log or changes the `.sg1` / INDEX formats.

use std::collections::BTreeMap;
use std::path::Path;

use super::{
    check_private, container, err, fnd, load, segment_files, show_path, CheckOpts, CheckReport,
    Entry, Listing, Log, Op, Result, Severity, State,
};

/// One live file of a log: the newest version of a `log add` path that no tombstone deleted.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct LiveFile {
    /// Path relative to the backed-up folder, as stored (`posts/x.jpg`; control characters escaped).
    pub path: String,
    /// Plain size in bytes.
    pub size: u64,
    /// Segment (INDEX entry) holding this version.
    pub seq: u64,
    /// Unix seconds when this version was added.
    pub time: u64,
    /// Older versions of the same path still in the log (changed files keep their history).
    pub older: usize,
}

/// What [`live_files`] found, grouped the way an archivist counts a log.
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct LiveSet {
    /// Live named files, sorted by path.
    pub files: Vec<LiveFile>,
    /// Paths whose every version was deleted by a tombstone (or crypto-shredded).
    pub tombstoned_files: usize,
    /// Segments deleted by a tombstone, named or not.
    pub tombstoned_segments: usize,
    /// Live segments without a stored name (written by `log append` / `adopt`), and their bytes.
    pub unnamed: (usize, u64),
    /// Private INDEX entries whose name and size stay sealed (the index was not opened).
    pub sealed: usize,
    /// Older versions of live files kept in the log (superseded by a later `log add`).
    pub older_versions: usize,
}

impl LiveSet {
    /// Bytes of every live file plus every live unnamed segment.
    pub fn live_bytes(&self) -> u64 {
        self.files.iter().map(|f| f.size).sum::<u64>() + self.unnamed.1
    }
}

fn gone(st: &State, seq: u64) -> bool {
    st.deleted_by(seq).is_some() || st.is_shredded(seq)
}

/// The live file set of a listing. Reads only the INDEX facts already in the [`Listing`].
pub fn live_files(l: &Listing) -> LiveSet {
    let st = &l.state;
    let mut set = LiveSet {
        tombstoned_segments: st.deleted_count(),
        ..Default::default()
    };
    // every version of each path, oldest first
    let mut by_path: BTreeMap<Vec<u8>, Vec<&Entry>> = BTreeMap::new();
    for e in &l.entries {
        if e.op != Op::Seg {
            continue;
        }
        if e.is_locked() {
            if !gone(st, e.seq) {
                set.sealed += 1;
            }
            continue;
        }
        match e.path() {
            Some(p) => by_path.entry(p).or_default().push(e),
            None if !gone(st, e.seq) => {
                set.unnamed.0 += 1;
                set.unnamed.1 += e.size;
            }
            None => {}
        }
    }
    for (p, versions) in by_path {
        let live: Vec<&&Entry> = versions.iter().filter(|e| !gone(st, e.seq)).collect();
        match live.last() {
            Some(e) => {
                set.older_versions += live.len() - 1;
                set.files.push(LiveFile {
                    path: show_path(&p),
                    size: e.size,
                    seq: e.seq,
                    time: e.time,
                    older: live.len() - 1,
                });
            }
            None => set.tombstoned_files += 1,
        }
    }
    set
}

/// Live files whose path an exclude rule matches: they stay in the log ("excluded, kept"),
/// as `sigil log add --exclude` reports them.
pub fn excluded_kept(set: &LiveSet, ex: &super::Excluder) -> usize {
    set.files
        .iter()
        .filter(|f| ex.excluded(f.path.as_bytes()).is_some())
        .count()
}

/// Fast condition check: manifest, INDEX hash chain, HEAD (root, signature, signer) and that
/// every needed segment file is present, from one directory scan. Segment bytes are never
/// read, so bit rot inside a segment is not seen: that is [`super::check`]'s job
/// (`sigil log verify`). `verified` stays 0.
pub fn check_fast(path: &Path, opts: &CheckOpts<'_>) -> Result<CheckReport> {
    let mut rep = CheckReport::default();
    let dir = match super::resolve_dir(path) {
        Some(d) => d,
        None => return Err(err(format!("{} is not a segment log", path.display()))),
    };
    match container::read_manifest(&dir) {
        Ok(m) => rep.container_version = Some(m.version),
        Err(e) => {
            rep.findings.push(fnd(
                Severity::Error,
                "manifest",
                container::CONTAINER_FILE,
                e.to_string(),
                Some("restore CONTAINER from a copy"),
            ));
            return Ok(rep);
        }
    }
    let mut log = match Log::open_dir(&dir) {
        Ok(l) => l,
        Err(e) => {
            rep.findings.push(fnd(
                Severity::Error,
                "manifest",
                container::CONTAINER_FILE,
                e.to_string(),
                Some("upgrade sigil if the log format is newer"),
            ));
            return Ok(rep);
        }
    };
    let mut keyed = opts.pass.is_some() || !opts.identities.is_empty();
    if log.privindex {
        check_private(&mut log, opts, &mut keyed, &mut rep);
    }
    let loaded = load(&log, opts);
    rep.findings.extend(loaded.findings);
    rep.signed = loaded.head.as_ref().is_some_and(|h| h.sig.is_some());
    let st = loaded.index.state;
    let entries = loaded.index.entries;
    rep.entries = entries.len();
    rep.format = log.format;
    rep.segments = (1..=entries.len() as u64).filter(|s| st.is_seg(*s)).count();
    rep.deleted = st.deleted_count();
    rep.tombstones = st.tomb_count();
    rep.compactions = st.compact_count();
    rep.segkeys = log.segkeys;
    rep.shredded = st.shred_count();
    rep.handovers = st.handovers().len();
    let on_disk = segment_files(&log);
    for e in &entries {
        if !st.has_file(e.seq) || st.slot(e.seq) != super::Slot::Needed {
            continue;
        }
        if !on_disk.contains(&e.seq) {
            let p = log.segment_path(e.seq);
            let subject = p.strip_prefix(&dir).unwrap_or(&p).display().to_string();
            rep.findings.push(fnd(
                Severity::Error,
                "segment-missing",
                subject,
                format!("index entry {} has no segment file", e.seq),
                Some("restore the segment from a copy (any copy of the sealed .sg1 works)"),
            ));
        }
    }
    Ok(rep)
}

/// Find the segment to read for a stored file name (`sigil log read --name`).
///
/// `name` is the path relative to the backed-up folder (`posts/x.jpg`, a leading `./` is
/// ignored). An exact path wins; otherwise a unique path ending in `/name` is accepted (so a
/// bare file name works when only one folder has it). The newest version that no tombstone
/// deleted is returned, with a note when a newer version was deleted.
///
/// Errors (never a guess): the names are sealed in a private INDEX that was not opened; no
/// such name; more than one path ends in `name`; every version was deleted or shredded.
pub fn resolve_name(l: &Listing, name: &str) -> Result<(u64, String, Option<String>)> {
    let want = name.trim().trim_start_matches("./");
    if want.is_empty() {
        return Err(err("--name needs a file name, e.g. posts/photo.jpg"));
    }
    let st = &l.state;
    let mut by_path: BTreeMap<String, Vec<&Entry>> = BTreeMap::new();
    let mut sealed = 0usize;
    for e in &l.entries {
        if e.op != Op::Seg {
            continue;
        }
        if e.is_locked() {
            sealed += 1;
            continue;
        }
        if let Some(p) = e.path() {
            by_path.entry(show_path(&p)).or_default().push(e);
        }
    }
    let path = if by_path.contains_key(want) {
        want.to_string()
    } else {
        let tail = format!("/{want}");
        let hits: Vec<&String> = by_path.keys().filter(|p| p.ends_with(&tail)).collect();
        match hits.as_slice() {
            [one] => (*one).clone(),
            [] if sealed > 0 => {
                return Err(err(format!(
                    "file names in this log are sealed (private INDEX): give --pass / --identity to read {want:?} by name"
                )))
            }
            [] => {
                return Err(err(format!(
                    "no file named {want:?} in the log (names are paths inside the backed-up folder, e.g. posts/photo.jpg; see `sigil log ls`)"
                )))
            }
            many => {
                let shown: Vec<&str> = many.iter().take(5).map(|s| s.as_str()).collect();
                return Err(err(format!(
                    "{want:?} is ambiguous: {} files end in that name ({}{}); give the full path",
                    many.len(),
                    shown.join(", "),
                    if many.len() > 5 { ", …" } else { "" }
                )));
            }
        }
    };
    let versions = by_path.get(&path).map(Vec::as_slice).unwrap_or(&[]);
    let newest = versions.last().map(|e| e.seq);
    match versions.iter().rev().find(|e| !gone(st, e.seq)) {
        Some(e) => {
            let note = match newest {
                Some(n) if n != e.seq => Some(format!(
                    "the newest version of {path} (segment {n}) was deleted; reading the newest live one, segment {}",
                    e.seq
                )),
                _ => None,
            };
            Ok((e.seq, path, note))
        }
        None => {
            let n = newest.unwrap_or(0);
            let how = if st.is_shredded(n) {
                "crypto-shredded (its key is destroyed)".to_string()
            } else {
                match st.deleted_by(n) {
                    Some(t) => format!("deleted by tombstone #{t}"),
                    None => "deleted".to_string(),
                }
            };
            Err(err(format!(
                "{path} is {how}: no live version to read (segment {n}); `sigil log ls` shows its history"
            )))
        }
    }
}
