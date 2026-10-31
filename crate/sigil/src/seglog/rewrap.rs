//! `sigil log rewrap`: change who can open a log's **wrapped keys** (the per-segment key ring of a
//! `--segment-keys` log and the index key of a private-INDEX log) without touching a segment.
//!
//! Each wrapped key is an SGTO block (one record per `--to` recipient, plus an optional passphrase
//! record). Rewrap unwraps every key with the **current** `--pass-file` / `--identity` (which is
//! what authorises the change), then builds a new block: kept records stay byte for byte, added
//! ones use the same X25519 / Argon2id encodings as `seal --to` / `--pass`. Everything is computed
//! in memory first; a key that does not open, a damaged shard or `IXKEY.sg1`, or a result with no
//! recipient at all refuses the whole run before anything is written.
//!
//! Segment bodies, the INDEX and HEAD never change (their keys are the same keys, only wrapped to
//! other people), so the chain, anchors, proofs and signatures stay valid. What this does **not**
//! do: take back a key someone already unwrapped, or bytes they already read or copied (including
//! an old copy of the key ring). For that, `log compact` re-seals live data under new keys.

use super::*;

/// What [`rewrap`] changes.
pub struct RewrapOpts<'a> {
    /// Current passphrase (opens the keys today).
    pub pass: Option<&'a str>,
    /// Current identities (open the keys today).
    pub identities: &'a [Identity],
    /// Recipients to add.
    pub add: &'a [PublicIdentity],
    /// Recipients to remove.
    pub remove: &'a [PublicIdentity],
    /// New passphrase record (replaces any existing one).
    pub new_pass: Option<&'a str>,
    /// Remove the passphrase record.
    pub drop_pass: bool,
    /// Replace every recipient with exactly `add` + `new_pass`.
    pub replace: bool,
    /// Check and count only; write nothing.
    pub dry_run: bool,
}

#[derive(Debug, Default)]
pub struct RewrapReport {
    pub dir: PathBuf,
    /// Key ring shards / records re-wrapped.
    pub shards: usize,
    pub records: usize,
    /// The private-INDEX key was re-wrapped.
    pub index_key: bool,
    /// X25519 records `--remove-to` matched (over all keys).
    pub removed: usize,
    pub dry_run: bool,
}

impl RewrapReport {
    /// As JSON (`sigil log rewrap --json`, `sigil-log-rewrap=1`). Counts only: no keys, no
    /// recipients, no paths.
    pub fn to_json(&self) -> String {
        format!(
            "{{\"format\":\"sigil-log-rewrap=1\",\"dir\":{},\"dry_run\":{},\"shards\":{},\"records\":{},\"index_key\":{},\"removed\":{}}}\n",
            crate::doctor::json_str(&self.dir.display().to_string()),
            self.dry_run,
            self.shards,
            self.records,
            self.index_key,
            self.removed
        )
    }

    pub fn render(&self) -> String {
        let mut what = Vec::new();
        if self.shards > 0 {
            what.push(format!(
                "{} segment key(s) in {} shard(s)",
                self.records, self.shards
            ));
        }
        if self.index_key {
            what.push("the index key".to_string());
        }
        if what.is_empty() {
            what.push("no keys yet".to_string());
        }
        format!(
            "log rewrap {}{}: {}{}\n",
            self.dir.display(),
            if self.dry_run {
                " (dry run, nothing written)"
            } else {
                ""
            },
            what.join(" + "),
            if self.removed > 0 {
                format!(", {} recipient record(s) removed", self.removed)
            } else {
                String::new()
            }
        )
    }
}

pub fn rewrap(path: &Path, o: &RewrapOpts<'_>) -> Result<RewrapReport> {
    let log = Log::open(path)?;
    if !log.segkeys && !log.privindex {
        return Err(err(
            "this log has no wrapped keys (no --segment-keys, no private INDEX): each segment is sealed straight to its recipients; re-seal them with `sigil log compact` (--seal-pass-file / --to) instead",
        ));
    }
    if o.pass.is_none() && o.identities.is_empty() {
        return Err(err(
            "give the current --pass-file / --identity: the keys must open before they can be re-wrapped",
        ));
    }
    if o.add.is_empty() && o.remove.is_empty() && o.new_pass.is_none() && !o.drop_pass && !o.replace
    {
        return Err(err(
            "nothing to change: give --add-to, --remove-to, --new-pass-file, --drop-pass or --replace",
        ));
    }
    if o.replace && (!o.remove.is_empty() || o.drop_pass) {
        return Err(err(
            "--replace already drops every current recipient; leave out --remove-to / --drop-pass",
        ));
    }
    if o.drop_pass && o.new_pass.is_some() {
        return Err(err("--drop-pass and --new-pass-file contradict each other"));
    }
    let edit = crate::keys::SgtoEdit {
        replace: o.replace,
        remove: o.remove,
        drop_pass: o.drop_pass,
        add: o.add,
        new_pass: o.new_pass,
    };
    if !o.dry_run {
        // granting / revoking access is the writer's job: a reader can open the keys too
        writer_gate(&log, o.identities, "re-wrapping keys")?;
    }
    let _guard = if o.dry_run { None } else { Some(lock(&log)?) };
    let mut rep = RewrapReport {
        dir: log.dir.clone(),
        dry_run: o.dry_run,
        ..Default::default()
    };
    let shards = if log.segkeys {
        let (n, records, removed, shards) = keyring::rewrap_all(&log, o.pass, o.identities, &edit)?;
        rep.shards = n;
        rep.records = records;
        rep.removed += removed;
        shards
    } else {
        Vec::new()
    };
    let ix = if log.privindex {
        let (salt, wrap) = private::read_ixkey(&log.dir)
            .map_err(|e| err(format!("{e}; nothing was re-wrapped")))?;
        let k = zeroize::Zeroizing::new(
            crate::keys::unwrap_cek(&wrap, o.identities, o.pass, &salt).map_err(|_| {
                err("the index key does not open with the given --pass-file / --identity (the current keys); nothing was re-wrapped")
            })?,
        );
        let (nw, removed) = crate::keys::sgto_rewrap(&wrap, &k, &edit)
            .map_err(|e| err(format!("index key: {e}; nothing was re-wrapped")))?;
        rep.removed += removed;
        rep.index_key = true;
        Some((salt, nw))
    } else {
        None
    };
    if !o.remove.is_empty() && rep.removed == 0 {
        return Err(err(
            "--remove-to: none of those keys is a recipient of any wrapped key here; nothing was re-wrapped",
        ));
    }
    if o.dry_run {
        return Ok(rep);
    }
    for (shard, s) in &shards {
        keyring::store_rewrapped(&log, *shard, s)?;
    }
    if let Some((salt, w)) = ix {
        private::store_ixkey(&log.dir, &salt, &w)?;
    }
    Ok(rep)
}
