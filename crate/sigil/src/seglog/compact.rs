//! Tombstones and compaction for segment logs (slice 2). See `docs/SEGMENT-LOG.md`.
//!
//! * `tombstone` appends one chain-covered `op=tomb` line naming segments as deleted.
//! * `compact` merges live segments into fewer, larger ones (`op=compact` lines) and erases the
//!   files of deleted / merged-away segments. The INDEX is never rewritten: original entries stay
//!   where they are, so every anchor ever pinned still verifies.
//!
//! Crash-safe order of `compact --apply` (each step leaves a verifiable log):
//! merged segments written as unindexed files → manifest raised to `log=2` → INDEX lines
//! appended (the commit point) → HEAD rewritten → old files deleted last.

use std::fs;
use std::path::{Path, PathBuf};

use super::*;

// ---------------------------------------------------------------------------
// tombstone
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, Debug)]
pub enum TombTarget {
    Seq(u64),
    /// Inclusive range; entries in it that are not live data are skipped.
    Range(u64, u64),
}

#[derive(Debug)]
pub struct TombstoneReport {
    /// Seq of the new tombstone entry.
    pub entry: u64,
    pub deleted: Vec<u64>,
    /// In the requested range but deleted earlier (skipped).
    pub already: Vec<u64>,
    /// Plain bytes of deleted data that stay on disk until `compact --apply` / `gc --apply`.
    pub pending_bytes: u64,
    pub root: [u8; 32],
    pub signed: bool,
    pub notes: Vec<String>,
}

/// Append a tombstone entry. This is a *logical* delete: chain-covered and permanent (there is no
/// undelete), honoured by `read` / `ls` at once. The bytes are erased by `compact --apply`.
pub fn tombstone(path: &Path, target: TombTarget, reason: Option<&str>, identity: Option<&Identity>) -> Result<TombstoneReport> {
    let mut log = Log::open(path)?;
    signer_gate(&log, identity)?;
    if let Some(r) = reason {
        if r.len() > 500 {
            return Err(err("--reason is limited to 500 bytes"));
        }
    }
    let _guard = lock(&log)?;
    let (idx, notes) = prepare_write(&log)?;
    signer_gate_at(&log, &idx.entries, identity)?;
    let n = idx.entries.len() as u64;
    let st = &idx.state;
    let (from, to) = match target {
        TombTarget::Seq(s) => (s, s),
        TombTarget::Range(a, b) => (a, b),
    };
    if from == 0 || to < from {
        return Err(err("segment numbers start at 1 and --from must not exceed --to"));
    }
    if to > n {
        return Err(err(format!("segment {to} does not exist (the log has {n} entries)")));
    }
    let mut deleted = Vec::new();
    let mut already = Vec::new();
    for s in from..=to {
        if !st.is_seg(s) {
            if let TombTarget::Seq(_) = target {
                return Err(err(if st.is_tomb(s) {
                    format!("entry {s} is a tombstone record, not a segment")
                } else if st.is_signer(s) {
                    format!("entry {s} is a signer handover record, not a segment")
                } else {
                    format!("entry {s} is a compaction record; tombstone the original segments it covers (see `sigil log ls`)")
                }));
            }
            continue;
        }
        if st.deleted_by(s).is_some() {
            already.push(s);
        } else {
            deleted.push(s);
        }
    }
    if deleted.is_empty() {
        return Err(err(match target {
            TombTarget::Seq(s) => format!("segment {s} is already deleted (tombstone #{})", st.deleted_by(s).unwrap_or(0)),
            TombTarget::Range(a, b) => format!("nothing to delete in {a}..{b}: no live segments there"),
        }));
    }
    let pending: u64 = deleted.iter().map(|s| st.size_of(*s)).sum();
    let seq = n + 1;
    let mut body = format!("seq={seq} t={} op=tomb del={}", now(), fmt_ranges(&compress(&deleted)));
    if let Some(r) = reason.filter(|r| !r.is_empty()) {
        body.push_str(&format!(" reason={}", enc_reason(r)));
    }
    // The manifest goes first: an older sigil must refuse this log before it can see the line.
    upgrade_manifest(&mut log)?;
    let (_entries, head) = commit(&log, idx, &[body], identity)?;
    Ok(TombstoneReport { entry: seq, deleted, already, pending_bytes: pending, root: head.root, signed: head.sig.is_some(), notes })
}

// ---------------------------------------------------------------------------
// compact
// ---------------------------------------------------------------------------

/// Where `compact --apply` stops, to simulate a crash (tests only).
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CrashPoint {
    /// Merged segments are on disk, nothing else changed.
    AfterSegments,
    /// …and the manifest says `log=2`.
    AfterManifest,
    /// …and the INDEX has the new lines (HEAD still old).
    AfterIndex,
    /// …and HEAD is rewritten; no old file deleted yet.
    AfterHead,
    /// After the first old file was deleted.
    MidDelete,
}

pub struct CompactOpts<'a> {
    /// Keep the newest N batches out of the merge (they stay separate, easy to append to / tombstone).
    pub keep_last: Option<u64>,
    /// Only merge batches appended at least this many seconds ago.
    pub older_than_secs: Option<u64>,
    /// Only merge batches whose original seq is within `A..=B`.
    pub range: Option<(u64, u64)>,
    /// Do it. `false` (default) = report the plan, change nothing.
    pub apply: bool,
    /// Stop growing one merged segment at about this many plain bytes (it is sealed in memory).
    pub target_size: u64,
    /// Seal mode of the merged segments.
    pub mode: Mode,
    /// Passphrase / recipients for the merged segments (sources are opened with `read`).
    pub seal_pass: Option<&'a str>,
    pub recipients: &'a [PublicIdentity],
    /// Allow merging encrypted sources into an unencrypted merged segment.
    pub allow_decrypt: bool,
    /// Keys that open the source segments; also supplies the signing key for a signed log.
    pub read: ReadOpts<'a>,
    #[doc(hidden)]
    pub stop_after: Option<CrashPoint>,
}

impl Default for CompactOpts<'_> {
    fn default() -> Self {
        CompactOpts {
            keep_last: None,
            older_than_secs: None,
            range: None,
            apply: false,
            target_size: 64 << 20,
            mode: Mode::Reflection,
            seal_pass: None,
            recipients: &[],
            allow_decrypt: false,
            read: ReadOpts { pass: None, identities: &[] },
            stop_after: None,
        }
    }
}

/// One merged segment to be written.
#[derive(Clone, Debug)]
pub struct Group {
    /// Segment files (entry seqs) that are merged and then erased.
    pub sources: Vec<u64>,
    /// Original segments whose bytes go into the merged one (ascending).
    pub members: Vec<u64>,
    /// Deleted members dropped by the rewrite (their bytes are erased with the old files).
    pub dropped: Vec<u64>,
    /// Plain bytes of the merged segment.
    pub bytes: u64,
    /// Entry seq (and file name) of the merged segment.
    pub new_seq: u64,
}

/// A segment file that is only on disk because nobody erased it yet.
#[derive(Clone, Debug)]
pub struct PurgeFile {
    pub seq: u64,
    pub path: PathBuf,
    pub bytes: u64,
    pub why: Slot,
}

#[derive(Debug, Default)]
pub struct CompactReport {
    pub apply: bool,
    pub rule: String,
    pub groups: Vec<Group>,
    /// Dead files of deleted / merged-away segments (outside the groups' own sources).
    pub purge: Vec<PurgeFile>,
    /// Source files of the groups, erased after the new entries are committed.
    pub source_files: Vec<PurgeFile>,
    pub live_segments: usize,
    pub notes: Vec<String>,
    /// Sealed bytes of old files (sources + purge) / of the new merged files (apply only).
    pub bytes_before: u64,
    pub bytes_after: u64,
    pub removed: usize,
    /// Key ring records destroyed with the old files (segment-keys logs).
    pub keys_destroyed: usize,
    pub root: Option<[u8; 32]>,
}

impl CompactReport {
    pub fn render(&self, dir: &Path) -> String {
        let rel = |p: &Path| p.strip_prefix(dir).unwrap_or(p).display().to_string();
        let mut s = format!("log compact {}  rule: {}\n", dir.display(), self.rule);
        for g in &self.groups {
            s.push_str(&format!(
                "  merge segment file(s) {} → new segment {}: {} batch(es) [{}], {} plain bytes{}\n",
                g.sources.iter().map(|x| x.to_string()).collect::<Vec<_>>().join(", "),
                g.new_seq,
                g.members.len(),
                fmt_ranges(&compress(&g.members)),
                g.bytes,
                if g.dropped.is_empty() { String::new() } else { format!("; drops deleted {}", fmt_ranges(&compress(&g.dropped))) }
            ));
        }
        for p in &self.purge {
            s.push_str(&format!(
                "  erase {} ({}, {} bytes)\n",
                rel(&p.path),
                if p.why == Slot::DeadDeleted { "deleted by tombstone" } else { "merged away" },
                p.bytes
            ));
        }
        if self.groups.is_empty() && self.purge.is_empty() {
            s.push_str("  nothing to merge or erase\n");
        }
        for n in &self.notes {
            s.push_str(&format!("  note: {n}\n"));
        }
        if self.apply {
            s.push_str(&format!(
                "compacted: {} new segment(s), {} old file(s) erased{}, {} → {} sealed bytes{}\n",
                self.groups.len(),
                self.removed,
                if self.keys_destroyed > 0 { format!(", {} key record(s) destroyed", self.keys_destroyed) } else { String::new() },
                self.bytes_before,
                self.bytes_after,
                self.root.map(|r| format!("; new anchor {}", hex32(&r))).unwrap_or_default()
            ));
        } else if !(self.groups.is_empty() && self.purge.is_empty()) {
            s.push_str(&format!(
                "dry run: nothing was changed. {} merge(s), {} file(s) to erase; re-run with --apply\n",
                self.groups.len(),
                self.purge.len() + self.groups.iter().map(|g| g.sources.len()).sum::<usize>()
            ));
        }
        s
    }
}

fn sized(log: &Log, seq: u64, why: Slot) -> Option<PurgeFile> {
    let path = log.segment_path(seq);
    fs::metadata(&path).ok().map(|m| PurgeFile { seq, path, bytes: m.len(), why })
}

fn describe_rule(o: &CompactOpts<'_>) -> String {
    let mut v = Vec::new();
    if let Some(n) = o.keep_last {
        v.push(format!("keep the newest {n}"));
    }
    if let Some(t) = o.older_than_secs {
        v.push(format!("older than {t}s"));
    }
    if let Some((a, b)) = o.range {
        v.push(format!("seq {a}-{b}"));
    }
    if v.is_empty() {
        "every live segment".into()
    } else {
        v.join(" and ")
    }
}

/// Decide what to merge and what to erase. Pure: reads INDEX state only (plus file sizes).
fn plan(log: &Log, entries: &[Entry], state: &State, trusted: usize, opts: &CompactOpts<'_>, t_now: u64) -> (Vec<Group>, Vec<PurgeFile>, usize) {
    let n = entries.len() as u64;
    let st_t = State::build(&entries[..trusted]);
    // files nobody needs any more (judged only from entries the HEAD vouches for)
    let mut purge = Vec::new();
    for h in 1..=trusted as u64 {
        let slot = st_t.slot(h);
        if matches!(slot, Slot::DeadDeleted | Slot::DeadSuperseded) {
            if let Some(p) = sized(log, h, slot) {
                purge.push(p);
            }
        }
    }
    let segs: Vec<u64> = (1..=n).filter(|s| state.is_seg(*s)).collect();
    let kept_min = match opts.keep_last {
        Some(k) if k > 0 && !segs.is_empty() => Some(segs[segs.len().saturating_sub(k as usize)]),
        _ => None,
    };
    let eligible = |live: &[u64]| -> bool {
        let (Some(&lo), Some(&hi)) = (live.first(), live.last()) else { return false };
        if let Some(km) = kept_min {
            if hi >= km {
                return false;
            }
        }
        if let Some(secs) = opts.older_than_secs {
            let cutoff = t_now.saturating_sub(secs);
            if live.iter().any(|m| entries[*m as usize - 1].time > cutoff) {
                return false;
            }
        }
        if let Some((a, b)) = opts.range {
            if lo < a || hi > b {
                return false;
            }
        }
        true
    };
    let mut groups: Vec<Group> = Vec::new();
    let mut cur: Vec<u64> = Vec::new();
    let (mut cur_bytes, mut cur_dirty) = (0u64, false);
    let mut live_total = 0usize;
    let flush = |cur: &mut Vec<u64>, cur_bytes: &mut u64, cur_dirty: &mut bool, groups: &mut Vec<Group>| {
        if cur.len() >= 2 || (cur.len() == 1 && *cur_dirty) {
            let mut members: Vec<u64> = cur.iter().flat_map(|h| state.live_members(*h)).collect();
            members.sort_unstable();
            let mut dropped: Vec<u64> = cur.iter().flat_map(|h| state.deleted_members(*h)).collect();
            dropped.sort_unstable();
            let new_seq = n + 1 + groups.len() as u64;
            groups.push(Group { sources: std::mem::take(cur), members, dropped, bytes: *cur_bytes, new_seq });
        } else {
            cur.clear();
        }
        *cur_bytes = 0;
        *cur_dirty = false;
    };
    for h in 1..=n {
        if state.slot(h) != Slot::Needed {
            continue;
        }
        let live = state.live_members(h);
        live_total += live.len();
        let bytes: u64 = live.iter().map(|m| state.size_of(*m)).sum();
        let dirty = !state.deleted_members(h).is_empty();
        if dirty || eligible(&live) {
            if !cur.is_empty() && cur_bytes + bytes > opts.target_size {
                flush(&mut cur, &mut cur_bytes, &mut cur_dirty, &mut groups);
            }
            cur.push(h);
            cur_bytes += bytes;
            cur_dirty |= dirty;
        } else {
            flush(&mut cur, &mut cur_bytes, &mut cur_dirty, &mut groups);
        }
    }
    flush(&mut cur, &mut cur_bytes, &mut cur_dirty, &mut groups);
    // a dead holder's file never also belongs to a group (groups only hold needed ones)
    (groups, purge, live_total)
}

fn crash(opts: &CompactOpts<'_>, at: CrashPoint) -> Result<()> {
    if opts.stop_after == Some(at) {
        return Err(err(format!("simulated crash {at:?} (test hook)")));
    }
    Ok(())
}

/// Merge / erase according to `opts`. Dry-run unless `opts.apply`.
pub fn compact(path: &Path, opts: &CompactOpts<'_>) -> Result<CompactReport> {
    let mut log = Log::open(path)?;
    let _guard = if opts.apply { Some(lock(&log)?) } else { None };
    let mut loaded = load(&log, &CheckOpts::default());
    let refuse = |l: &Loaded| -> Result<()> {
        match l.findings.iter().find(|f| f.severity == Severity::Error) {
            Some(f) => Err(err(format!("refusing to compact: {} {}: {} (run `sigil log verify`)", f.code, f.subject, f.message))),
            None => Ok(()),
        }
    };
    refuse(&loaded)?;
    let mut rep = CompactReport { apply: opts.apply, rule: describe_rule(opts), ..Default::default() };
    // the signing key, when the log is signed and we are about to write HEAD (the current signer,
    // after any handovers)
    let current = signer_for(&log, &loaded.index.entries, loaded.index.entries.len() + 1);
    let signer: Option<&Identity> = current.and_then(|pk| {
        opts.read.identities.iter().find(|i| SigningKey::from_bytes(&i.ed25519_seed).verifying_key().to_bytes() == pk)
    });
    let lag = loaded.trusted < loaded.index.entries.len();
    let t_now = now();
    let (groups, _purge, _live) = plan(&log, &loaded.index.entries, &loaded.index.state, loaded.trusted, opts, t_now);
    if opts.apply && (lag || !groups.is_empty()) && log.signer.is_some() && signer.is_none() {
        return Err(err("this log is signed and compaction rewrites HEAD: give the signing key with --identity KEY.sgk"));
    }
    if lag {
        rep.notes.push(format!(
            "HEAD covers {} of {} entries (an earlier operation was interrupted); {}",
            loaded.trusted,
            loaded.index.entries.len(),
            if opts.apply { "the new HEAD covers them" } else { "files are judged dead only from the covered ones" }
        ));
    }
    if opts.apply && (lag || loaded.index.torn) {
        // Re-cover HEAD (when it lags) and trim a torn tail first, so that file deletion only ever
        // follows a HEAD that vouches for the entries it is based on.
        let idx = std::mem::take(&mut loaded.index);
        let entries = commit_index(&log, idx, &[])?;
        if lag {
            commit_head(&log, &entries, signer)?;
        }
        loaded = load(&log, &CheckOpts::default());
        refuse(&loaded)?;
    }
    let (groups, purge, live) = plan(&log, &loaded.index.entries, &loaded.index.state, loaded.trusted, opts, t_now);
    rep.live_segments = live;
    rep.purge = purge;
    rep.groups = groups;
    for g in &rep.groups {
        for h in &g.sources {
            if let Some(p) = sized(&log, *h, Slot::DeadSuperseded) {
                rep.source_files.push(p);
            }
        }
    }
    rep.bytes_before = rep.purge.iter().chain(&rep.source_files).map(|p| p.bytes).sum();
    if !opts.apply {
        return Ok(rep);
    }
    // --- apply ---------------------------------------------------------------------
    let entries = loaded.index.entries.clone();
    let st = loaded.index.state.clone();
    let mut written: Vec<PathBuf> = Vec::new();
    let mut new_keys: Vec<u64> = Vec::new();
    let mut bodies: Vec<String> = Vec::new();
    let built = (|| -> Result<()> {
        let mut rd = Reader::new(&log, &entries, &st, &opts.read);
        for g in &rep.groups {
            rd.keyed_seen = false;
            let mut plain = Vec::with_capacity(g.bytes as usize);
            for m in &g.members {
                plain.extend_from_slice(&rd.member(*m)?);
            }
            if log.segkeys && opts.seal_pass.filter(|p| !p.is_empty()).is_none() && opts.recipients.is_empty() {
                return Err(err(format!(
                    "this log has per-segment keys: give --seal-pass and/or --to so the key of merged segment {} can be wrapped and kept in the key ring",
                    g.new_seq
                )));
            }
            if !log.segkeys && rd.keyed_seen && opts.seal_pass.is_none() && opts.recipients.is_empty() && !opts.allow_decrypt {
                return Err(err(format!(
                    "merging into segment {} would store encrypted batches in the clear; give --seal-pass or --to for the merged segment, or --allow-decrypt",
                    g.new_seq
                )));
            }
            let sha = sha256(&plain);
            // a merged segment gets its own fresh key (wrapped into the ring), like any append
            let own_key = if log.segkeys { Some(keyring::new_key()?) } else { None };
            let sealed = match &own_key {
                Some((_, id)) => crate::seal_kn_to(&plain, opts.mode, None, &format!("compact-{}", g.new_seq), false, "", &[], None, crate::DEFAULT_PIECE, &[id.public()])?,
                None => crate::seal_kn_to(
                    &plain,
                    opts.mode,
                    opts.seal_pass,
                    &format!("compact-{}", g.new_seq),
                    false,
                    "",
                    &[],
                    None,
                    crate::DEFAULT_PIECE,
                    opts.recipients,
                )?,
            };
            let dest = log.segment_path(g.new_seq);
            write_atomic(&dest, &sealed)?;
            written.push(dest);
            if let Some((m, _)) = &own_key {
                new_keys.push(g.new_seq);
                keyring::put(&log, g.new_seq, m, opts.seal_pass, opts.recipients)?;
            }
            rep.bytes_after += sealed.len() as u64;
            bodies.push(format!(
                "seq={} t={t_now} size={} sha={} op=compact of={}",
                g.new_seq,
                plain.len(),
                hex32(&sha),
                fmt_ranges(&compress(&g.members))
            ));
        }
        Ok(())
    })();
    if let Err(e) = built {
        for p in &written {
            let _ = fs::remove_file(p);
        }
        if !new_keys.is_empty() {
            let _ = keyring::destroy(&log, &new_keys);
        }
        return Err(e);
    }
    crash(opts, CrashPoint::AfterSegments)?;
    let mut head_root = None;
    if !bodies.is_empty() {
        upgrade_manifest(&mut log)?;
        crash(opts, CrashPoint::AfterManifest)?;
        let all = commit_index(&log, std::mem::take(&mut loaded.index), &bodies)?;
        crash(opts, CrashPoint::AfterIndex)?;
        let head = commit_head(&log, &all, signer)?;
        head_root = Some(head.root);
        crash(opts, CrashPoint::AfterHead)?;
    }
    rep.root = head_root;
    // old files last
    let mut first = true;
    let victims: Vec<PathBuf> = rep.source_files.iter().chain(&rep.purge).map(|p| p.path.clone()).collect();
    let dead_seqs: Vec<u64> = rep.source_files.iter().chain(&rep.purge).map(|p| p.seq).collect();
    for p in victims {
        match fs::remove_file(&p) {
            Ok(()) => rep.removed += 1,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
            Err(e) => rep.notes.push(format!("could not erase {}: {e}", p.display())),
        }
        if first {
            first = false;
            crash(opts, CrashPoint::MidDelete)?;
        }
    }
    // The old keys go with the old files: nothing can open those segments any more, whatever copy
    // of the old ciphertext survives elsewhere.
    if log.segkeys {
        match keyring::destroy(&log, &dead_seqs) {
            Ok(gone) => rep.keys_destroyed = gone.len(),
            Err(e) => rep.notes.push(format!("could not destroy old key records: {e} (`sigil gc --apply` retries)")),
        }
    }
    // emptied shard folders
    for shard in sorted(&log.dir.join(SEGMENTS_DIR)) {
        if shard.is_dir() && fs::read_dir(&shard).map(|mut r| r.next().is_none()).unwrap_or(false) {
            let _ = fs::remove_dir(&shard);
        }
    }
    Ok(rep)
}
