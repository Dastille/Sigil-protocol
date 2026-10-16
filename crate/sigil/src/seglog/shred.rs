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
    let log = Log::open(path)?;
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
                "segment {s} sits in compaction segment {h} together with live segment {m}; they share one key. Shred them all together (--from/--to), or `log tombstone` + `log compact --apply` to rewrite the file without it"
            )));
        }
    }
    let seq = n + 1;
    let mut body = format!(
        "seq={seq} t={} op=tomb del={} shred=1",
        now(),
        fmt_ranges(&compress(&targets))
    );
    if let Some(r) = reason.filter(|r| !r.is_empty()) {
        body.push_str(&format!(" reason={}", enc_reason(r)));
    }
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
