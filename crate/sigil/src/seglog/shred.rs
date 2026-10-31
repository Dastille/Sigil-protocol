//! `sigil log shred`: crypto-shredding for segment-keys logs (slice 3). See `docs/SEGMENT-LOG.md`.
//!
//! A shred is a tombstone (`op=tomb … shred=1`) that is also *key destruction*: after the INDEX
//! line is committed (the commit point) the segment's record is removed from the key ring and the
//! now-unreadable ciphertext file is unlinked. The INDEX is only appended to, so the Merkle root,
//! the signed HEAD and every pinned anchor keep verifying.
//!
//! Crash-safe order: INDEX line → HEAD → key record destroyed → file unlinked. A crash after the
//! INDEX line leaves a key record the entry says is dead (`shred-key-present`); `sigil gc --apply`
//! (or the next signed operation followed by `gc`) finishes the job. Nothing is ever *less*
//! readable than the INDEX claims.

use super::*;

#[derive(Debug)]
pub struct ShredReport {
    /// Seq of the new shred entry.
    pub entry: u64,
    pub shredded: Vec<u64>,
    /// In the requested range but shredded earlier (skipped).
    pub already: Vec<u64>,
    /// Key ring records destroyed.
    pub keys_destroyed: usize,
    /// Ciphertext files unlinked.
    pub files_removed: usize,
    pub root: [u8; 32],
    pub signed: bool,
    pub notes: Vec<String>,
}

/// Crypto-shred segments of a `--segment-keys` log: record it in the INDEX, destroy the key,
/// unlink the ciphertext.
pub fn shred(
    path: &Path,
    target: TombTarget,
    reason: Option<&str>,
    identity: Option<&Identity>,
) -> Result<ShredReport> {
    shred_with(path, target, reason, identity, &ReasonKeys::default())
}

/// [`shred`]; in a private log `keys` (or the signing identity) open the index key that seals `reason`.
pub fn shred_with(
    path: &Path,
    target: TombTarget,
    reason: Option<&str>,
    identity: Option<&Identity>,
    keys: &ReasonKeys<'_>,
) -> Result<ShredReport> {
    let mut log = Log::open(path)?;
    if !log.segkeys {
        return Err(err(
            "this log has no per-segment keys, so there is no key to destroy (create one with `sigil log init --segment-keys`); `log tombstone` + `log compact --apply` is its erase path",
        ));
    }
    signer_gate(&log, identity)?;
    if reason.map(|r| r.len() > 500).unwrap_or(false) {
        return Err(err("--reason is limited to 500 bytes"));
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
        return Err(err(
            "segment numbers start at 1 and --from must not exceed --to",
        ));
    }
    if to > n {
        return Err(err(format!(
            "segment {to} does not exist (the log has {n} entries)"
        )));
    }
    let (mut targets, mut already) = (Vec::new(), Vec::new());
    for s in from..=to {
        if !st.is_seg(s) {
            if let TombTarget::Seq(_) = target {
                return Err(err(if st.is_tomb(s) {
                    format!("entry {s} is a tombstone record, not a segment")
                } else if st.is_signer(s) {
                    format!("entry {s} is a signer handover record, not a segment")
                } else {
                    format!("entry {s} is a compaction record; shred the original segments it covers (see `sigil log ls`)")
                }));
            }
            continue;
        }
        if st.is_shredded(s) {
            already.push(s);
        } else {
            targets.push(s);
        }
    }
    if let Some(s) = targets.iter().find(|&&s| !log.seg_keyed(s)) {
        return Err(err(format!(
            "segment {s} was written before segment keys were turned on (from seq {}), so it has no key to destroy; `log tombstone` + `log compact --apply` erases it",
            log.segkeys_from
        )));
    }
    if targets.is_empty() {
        return Err(err(match target {
            TombTarget::Seq(s) => format!(
                "segment {s} is already shredded (entry #{})",
                st.shredded_by(s).unwrap_or(0)
            ),
            TombTarget::Range(a, b) => {
                format!("nothing to shred in {a}..{b}: no segment there still has its key")
            }
        }));
    }
    // Segments merged by `compact` share one file and one key: they can only be shredded together.
    for &s in &targets {
        let h = st.holder_of(s);
        if let Some(m) = st
            .live_members(h)
            .into_iter()
            .find(|m| !targets.contains(m))
        {
            return Err(err(format!(
                "segment {s} sits in compaction segment {h} together with live segment {m}; they share one key. Shred them all together (--from/--to), or `log shred --seq {s} --rewrite` to rewrite only that file without it"
            )));
        }
    }
    let seq = n + 1;
    let visible = format!(
        "seq={seq} t={} op=tomb del={} shred=1",
        now(),
        fmt_ranges(&compress(&targets))
    );
    let body = tomb_body(&mut log, seq, visible, reason, identity, keys)?;
    // The manifest already says log=3 / segkeys=1 (set at init): no upgrade step.
    let (entries, head) = commit(&log, idx, &[body], identity)?;
    // The entry is committed and HEAD covers it: now make it true.
    let st2 = State::build(&entries);
    let mut holders: Vec<u64> = targets.iter().map(|s| st2.holder_of(*s)).collect();
    holders.sort_unstable();
    holders.dedup();
    let gone = keyring::destroy(&log, &holders).map_err(|e| {
        err(format!(
            "the shred is recorded (entry #{seq}) but destroying the key failed: {e}; fix that and run `sigil gc --apply` to finish"
        ))
    })?;
    let mut files_removed = 0usize;
    let mut notes = notes;
    for h in &holders {
        if st2.slot(*h) != Slot::Needed {
            match fs::remove_file(log.segment_path(*h)) {
                Ok(()) => files_removed += 1,
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => notes.push(format!("could not unlink the unreadable ciphertext of segment {h}: {e} (`sigil gc --apply` retries)")),
            }
        }
    }
    for shard in sorted(&log.dir.join(SEGMENTS_DIR)) {
        if shard.is_dir()
            && fs::read_dir(&shard)
                .map(|mut r| r.next().is_none())
                .unwrap_or(false)
        {
            let _ = fs::remove_dir(&shard);
        }
    }
    Ok(ShredReport {
        entry: seq,
        shredded: targets,
        already,
        keys_destroyed: gone.len(),
        files_removed,
        root: head.root,
        signed: head.sig.is_some(),
        notes,
    })
}

/// What [`shred_rewrite`] did: the tombstone entry, then the one-holder compaction.
#[derive(Debug)]
pub struct ShredRewriteReport {
    pub tomb: TombstoneReport,
    pub compact: CompactReport,
    /// The segment files that were rewritten (the holders of the erased batches).
    pub holders: Vec<u64>,
}

/// Erase batches that share a compaction segment with live ones: a tombstone, then a compaction of
/// **only** the segment file(s) holding them, so the other batches are re-sealed into a new file
/// (in a segment-keys log under a fresh key) and the old file and its key are destroyed. Other
/// segment files are not touched (dead files that were already waiting to be erased are erased).
/// Fails before writing anything when `copts.read` cannot open the holders or no key is given
/// for the new file.
pub fn shred_rewrite(
    path: &Path,
    target: TombTarget,
    reason: Option<&str>,
    identity: Option<&Identity>,
    keys: &ReasonKeys<'_>,
    copts: &CompactOpts<'_>,
) -> Result<ShredRewriteReport> {
    let mut log = Log::open(path)?;
    if log.privindex {
        log.unlock_index(copts.read.pass, copts.read.identities)?;
    }
    let (from, to) = match target {
        TombTarget::Seq(s) => (s, s),
        TombTarget::Range(a, b) => (a, b),
    };
    let holders = {
        let _guard = lock(&log)?;
        let (idx, _) = prepare_write(&log)?;
        let st = &idx.state;
        let n = idx.entries.len() as u64;
        if from == 0 || to < from || to > n {
            return Err(err(format!(
                "segments {from}..{to} are not in the log (it has {n} entries)"
            )));
        }
        let targets: Vec<u64> = (from..=to)
            .filter(|s| st.is_seg(*s) && st.deleted_by(*s).is_none())
            .collect();
        if targets.is_empty() {
            return Err(err("nothing to erase: no live segment in that range"));
        }
        let mut holders: Vec<u64> = targets.iter().map(|s| st.holder_of(*s)).collect();
        holders.sort_unstable();
        holders.dedup();
        // fail closed: every holder must open with the given keys before anything is written
        let mut ring = keyring::RingCache::new(&log);
        let mut keyed = false;
        for h in &holders {
            let e = idx
                .entries
                .get((*h as usize).wrapping_sub(1))
                .ok_or_else(|| err(format!("segment {h} has no INDEX entry")))?;
            let (_, k) = read_holder(&log, &mut ring, e, &copts.read).map_err(|er| {
                err(format!(
                    "cannot open segment file {h} with the given keys ({er}); nothing was changed"
                ))
            })?;
            keyed |= k;
        }
        let sealed = copts.seal_pass.is_some_and(|p| !p.is_empty()) || !copts.recipients.is_empty();
        if (log.segkeys || keyed) && !sealed && !copts.allow_decrypt {
            return Err(err(
                "give --seal-pass-file and/or --seal-to for the rewritten segment (its other batches are re-sealed); nothing was changed",
            ));
        }
        holders
    };
    let tomb = tombstone_with(path, target, reason, identity, keys)?;
    let only = holders.clone();
    let compact = compact(
        path,
        &CompactOpts {
            apply: true,
            only_files: Some(&only),
            keep_last: None,
            older_than_secs: None,
            range: None,
            target_size: copts.target_size,
            mode: copts.mode,
            seal_pass: copts.seal_pass,
            recipients: copts.recipients,
            allow_decrypt: copts.allow_decrypt,
            read: ReadOpts {
                pass: copts.read.pass,
                identities: copts.read.identities,
            },
            stop_after: copts.stop_after,
        },
    )
    .map_err(|e| {
        err(format!(
            "batches are tombstoned (entry #{}) but rewriting segment file(s) {} failed: {e}; run `sigil log compact --apply` to finish",
            tomb.entry,
            fmt_ranges(&compress(&holders))
        ))
    })?;
    Ok(ShredRewriteReport {
        tomb,
        compact,
        holders,
    })
}
