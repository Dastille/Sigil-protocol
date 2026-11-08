//! `sigil log epoch OLD NEW` / `sigil log check-epoch NEW`: epoch rollover (INDEX prune Option A,
//! `docs/INDEX-PRUNE-DESIGN.md`; spec in `docs/SEGMENT-LOG.md` "Epoch rollover").
//!
//! The old log is closed at its vouched HEAD `N:ROOT` and only read: it stays byte-for-byte as it
//! was and becomes the **archive** of the history before the cut (the tool never deletes it). A
//! **new** log (`log=10`, `epoch=1`, always signed) starts with one chained `op=epoch` line naming
//! the archive (`prev-log`, `prev-size`, `prev-root`) and the SHA-256 of a signed **epoch card**
//! (an ordinary `sigil-log-card=1` card over the archive, kept as `EPOCH.card`), followed by a copy
//! of every live batch at the cut (as `log privatize` copies them).
//!
//! Write order: the archive's `LOG.lock` is held throughout; the new log is built in a hidden
//! temporary sibling and renamed into place last, so a crash leaves either no new log (archive
//! untouched) or a complete one.

use std::fs;
use std::path::{Path, PathBuf};

use super::*;

/// The epoch card inside an epoch log (its SHA-256 is the epoch line's `card=`).
pub const EPOCH_CARD_FILE: &str = "EPOCH.card";

/// Options of [`epoch`].
pub struct EpochOpts<'a> {
    /// Signs the epoch card and is pinned as the new log's signer. Required; for a signed old log
    /// it must be its current signer.
    pub identity: Option<&'a Identity>,
    /// Opens the old log's encrypted segments / index key, and wraps the new log's keys and segments.
    pub pass: Option<&'a str>,
    /// Recipients the new log's keys and segments are wrapped to.
    pub to: &'a [PublicIdentity],
    /// Extra identities that open the old log's encrypted segments / index key.
    pub unlock: &'a [Identity],
    /// ECC mode of the copied segments.
    pub mode: Mode,
    /// Card name (default `epoch-<first 16 hex of the old log id>-<N>`).
    pub name: Option<&'a str>,
    /// Also write the epoch card here (must not exist), after the new log is in place.
    pub card_out: Option<&'a Path>,
}

/// What [`epoch`] did.
#[derive(Debug, Default)]
pub struct EpochReport {
    /// Archived (old) log id.
    pub prev_id: String,
    /// Entries of the archive covered by the cut.
    pub prev_size: u64,
    /// Merkle root of those entries.
    pub prev_root: [u8; 32],
    /// The new log's folder.
    pub dest: PathBuf,
    /// The new log's id.
    pub dest_id: String,
    /// The new log's HEAD root.
    pub dest_root: [u8; 32],
    /// The new log's entry count (the epoch line plus the copies).
    pub dest_size: u64,
    /// Epoch card name.
    pub card_name: String,
    /// SHA-256 of the epoch card bytes (the epoch line's `card=`).
    pub card_sha: [u8; 32],
    /// The extra card copy written with `card_out`.
    pub card_out: Option<PathBuf>,
    /// `(archive seq, new seq)` of every copied entry.
    pub copied: Vec<(u64, u64)>,
    /// Archive seqs not copied (deleted, or not data).
    pub skipped: Vec<u64>,
}

impl EpochReport {
    /// Human-readable summary.
    pub fn render(&self) -> String {
        let mut s = format!(
            "log epoch: new epoch {} ({}) started\n  archive {} closed at {}:{}\n  epoch card {} sha256 {}{}\n  {} live entr{} copied, {} skipped (deleted or not data); new HEAD {}:{}\n",
            self.dest.display(),
            self.dest_id,
            self.prev_id,
            self.prev_size,
            hex32(&self.prev_root),
            self.card_name,
            hex32(&self.card_sha),
            match &self.card_out {
                Some(p) => format!(" (also at {})", p.display()),
                None => String::new(),
            },
            self.copied.len(),
            if self.copied.len() == 1 { "y" } else { "ies" },
            self.skipped.len(),
            self.dest_size,
            hex32(&self.dest_root),
        );
        s.push_str("  the archive was only read; history before the cut (restore --at, old receipts) needs it. Deleting it is your call, not sigil's.\n");
        s
    }
}

#[cfg(test)]
thread_local! {
    /// Test-only crash simulation: stop `epoch` with an error after this step, without cleanup.
    static CRASH_AT: std::cell::Cell<u32> = const { std::cell::Cell::new(0) };
}

/// Test-only: make the next [`epoch`] on this thread "crash" after `step` (0 = off).
#[cfg(test)]
pub(crate) fn set_crash_at(step: u32) {
    CRASH_AT.with(|c| c.set(step));
}

/// Simulated crash point: in tests, `Err(Crash)` after `step` when armed.
fn crash_point(step: u32) -> std::result::Result<(), Crash> {
    #[cfg(test)]
    {
        if CRASH_AT.with(|c| c.get()) == step {
            return Err(Crash);
        }
    }
    let _ = step;
    Ok(())
}

/// A simulated crash (tests only): nothing is cleaned up, as after a real crash.
struct Crash;

enum Fail {
    Err(crate::Error),
    Crash,
}

impl From<crate::Error> for Fail {
    fn from(e: crate::Error) -> Self {
        Fail::Err(e)
    }
}

impl From<Crash> for Fail {
    fn from(_: Crash) -> Self {
        Fail::Crash
    }
}

fn public_key(id: &Identity) -> [u8; 32] {
    SigningKey::from_bytes(&id.ed25519_seed)
        .verifying_key()
        .to_bytes()
}

/// See the module docs.
pub fn epoch(old: &Path, new: &Path, opts: &EpochOpts<'_>) -> Result<EpochReport> {
    match epoch_inner(old, new, opts) {
        Ok(r) => Ok(r),
        Err(Fail::Err(e)) => Err(e),
        Err(Fail::Crash) => Err(err("simulated crash (test)")),
    }
}

fn epoch_inner(
    old: &Path,
    new: &Path,
    opts: &EpochOpts<'_>,
) -> std::result::Result<EpochReport, Fail> {
    let identity = opts.identity.ok_or_else(|| {
        err("log epoch needs --identity KEY.sgk: it signs the epoch card and the new log (an unsigned epoch link is too easy to forge, so there is no unsigned rollover)")
    })?;
    let pk = public_key(identity);
    let pass = opts.pass.filter(|p| !p.is_empty());
    let mut log = Log::open(old)?;
    if log.privindex {
        unlock_for_write(&mut log, pass, Some(identity), opts.unlock)?;
    }
    let final_dir = dir_for_init(new);
    if fs::symlink_metadata(&final_dir).is_ok() {
        return Err(err(format!(
            "{} already exists; log epoch never overwrites (choose another NEW)",
            final_dir.display()
        ))
        .into());
    }
    if let Some(c) = opts.card_out {
        if fs::symlink_metadata(c).is_ok() {
            return Err(err(format!(
                "{} already exists; refusing to overwrite (choose another --card-out)",
                c.display()
            ))
            .into());
        }
    }
    let fname = final_dir
        .file_name()
        .ok_or_else(|| err("bad NEW name"))?
        .to_string_lossy()
        .to_string();
    // 1. lock the archive: no append can run while it is being closed
    let guard = lock(&log)?;
    crash_point(1)?;
    let loaded = load(&log, &CheckOpts::default());
    if let Some(f) = loaded
        .findings
        .iter()
        .find(|f| f.severity == Severity::Error)
    {
        return Err(err(format!(
            "refusing to roll over a damaged log: {} {}: {} (run `sigil log verify` / `mend`)",
            f.code, f.subject, f.message
        ))
        .into());
    }
    let entries = &loaded.index.entries;
    let st = &loaded.index.state;
    let n = entries.len();
    let head = match &loaded.head {
        Some(h) if h.seq as usize == n && loaded.trusted == n && n > 0 && !loaded.index.torn => {
            h.clone()
        }
        _ => {
            return Err(err(
                "the log has no HEAD that vouches for every INDEX entry (empty, HEAD behind INDEX, or torn last line); run `sigil log verify` and append once before rolling over",
            )
            .into())
        }
    };
    match signer_for(&log, entries, n + 1) {
        Some(cur) if cur != pk => {
            return Err(err(format!(
                "--identity is not this log's current signer {}… (the new epoch must be signed by the key that holds the old one)",
                &hex32(&cur)[..16]
            ))
            .into())
        }
        _ => {}
    }
    // the epoch card: an ordinary card over the archive at its vouched HEAD, signed by --identity
    let default_name = format!("epoch-{}-{n}", log.id.chars().take(16).collect::<String>());
    let name = opts.name.unwrap_or(&default_name);
    let card = make_card(name, std::slice::from_ref(&log.dir), Some(identity))?;
    match card.children.first() {
        Some(CardChild::Log {
            log_id, size, root, ..
        }) if *log_id == log.id && *size == head.seq && *root == head.root => {}
        _ => {
            return Err(err(
                "internal: the epoch card does not pin the archive's HEAD (the log changed under the lock?)",
            )
            .into())
        }
    }
    let card_text = card.render();
    let card_sha = sha256(card_text.as_bytes());
    let link = EpochLink {
        prev_log: log.id.clone(),
        prev_size: head.seq,
        prev_root: head.root,
        card: card_sha,
    };
    // 2. build NEW in a hidden temporary sibling
    let mut rnd = [0u8; 4];
    getrandom::getrandom(&mut rnd).map_err(|e| err(e.to_string()))?;
    let tmp = final_dir.with_file_name(format!(
        ".{fname}.epoch-{}-{}{}",
        std::process::id(),
        hex::encode(rnd),
        container::CONTAINER_SUFFIX
    ));
    if fs::symlink_metadata(&tmp).is_ok() {
        return Err(err(format!("{} is in the way (remove it)", tmp.display())).into());
    }
    let ropts = ReadOpts {
        pass,
        identities: &[],
    };
    let mut ids: Vec<Identity> = vec![identity.clone()];
    ids.extend_from_slice(opts.unlock);
    let ropts = ReadOpts {
        identities: &ids,
        ..ropts
    };
    let built = build(
        &log, entries, st, &tmp, &link, &card_text, identity, opts, pass, &ropts,
    );
    let mut rep = match built {
        Ok(r) => r,
        Err(Fail::Crash) => return Err(Fail::Crash),
        Err(Fail::Err(e)) => {
            let _ = fs::remove_dir_all(&tmp);
            return Err(e.into());
        }
    };
    let named = (|| -> Result<()> {
        let mut m = container::read_manifest(&tmp)?;
        m.name = container::strip_suffix(&fname).to_string();
        container::write_manifest(&tmp, &m)
    })();
    if let Err(e) = named {
        let _ = fs::remove_dir_all(&tmp);
        return Err(e.into());
    }
    crash_point(5)?;
    // 3. the commit point
    if let Err(e) = fs::rename(&tmp, &final_dir) {
        let _ = fs::remove_dir_all(&tmp);
        return Err(io(e).into());
    }
    drop(guard);
    crash_point(6)?;
    if let Some(c) = opts.card_out {
        write_atomic(c, card_text.as_bytes())?;
        rep.card_out = Some(c.to_path_buf());
    }
    rep.prev_id = log.id.clone();
    rep.prev_size = head.seq;
    rep.prev_root = head.root;
    rep.dest = final_dir;
    rep.card_name = name.to_string();
    rep.card_sha = card_sha;
    Ok(rep)
}

#[allow(clippy::too_many_arguments)]
fn build(
    src: &Log,
    entries: &[Entry],
    st: &State,
    tmp: &Path,
    link: &EpochLink,
    card_text: &str,
    identity: &Identity,
    opts: &EpochOpts<'_>,
    pass: Option<&str>,
    ropts: &ReadOpts<'_>,
) -> std::result::Result<EpochReport, Fail> {
    let mut dlog = init_opts(
        tmp,
        &InitOpts {
            sign: Some(identity),
            segment_keys: src.segkeys,
            private_index: src.privindex,
            index_pass: if src.privindex { pass } else { None },
            index_to: if src.privindex { opts.to } else { &[] },
            pad: src.pad,
        },
    )?;
    crash_point(2)?;
    // manifest first: an older sigil refuses the folder before it can meet the epoch line
    let mut m = container::read_manifest(&dlog.dir)?;
    m.extra.insert("log".into(), LOG_FORMAT_EPOCH.to_string());
    m.extra.insert("epoch".into(), "1".into());
    container::write_manifest(&dlog.dir, &m)?;
    dlog.format = LOG_FORMAT_EPOCH;
    dlog.epoch = true;
    write_atomic(&dlog.dir.join(EPOCH_CARD_FILE), card_text.as_bytes())?;
    crash_point(3)?;
    let mut rep = EpochReport {
        dest_id: dlog.id.clone(),
        ..Default::default()
    };
    let mut idx = read_index(&dlog)?;
    let mut bodies: Vec<String> = vec![format!(
        "seq=1 t={} op=epoch prev-log={} prev-size={} prev-root={} card={}",
        now(),
        link.prev_log,
        link.prev_size,
        hex32(&link.prev_root),
        hex32(&link.card)
    )];
    let wraps = pass.is_some() || !opts.to.is_empty();
    let mut rd = Reader::new(src, entries, st, ropts);
    let mut next = 2u64;
    let mut size = 0u64;
    for e in entries {
        if e.op != Op::Seg || st.deleted_by(e.seq).is_some() || st.shredded_by(e.seq).is_some() {
            rep.skipped.push(e.seq);
            continue;
        }
        let data = rd
            .member(e.seq)
            .map_err(|x| err(format!("archive entry {}: {x}", e.seq)))?;
        if rd.keyed_seen && !wraps {
            return Err(err(
                "the archive's segments are encrypted: give --pass-file and/or --to so the copies in the new epoch are encrypted too (no silent downgrade to clear segments)",
            )
            .into());
        }
        let (sealed, key) = seal_segment(&dlog, next, &data, opts.mode, pass, opts.to)?;
        let sha = sha256(&data);
        let body = if dlog.privindex {
            private::sealed_body(
                &dlog,
                next,
                e.time,
                "",
                &sealed,
                &Hidden {
                    size: data.len() as u64,
                    sha,
                    path: e.path(),
                    reason: None,
                },
            )?
        } else {
            format!(
                "seq={next} t={} size={} sha={}{}{}",
                e.time,
                data.len(),
                hex32(&sha),
                e.path()
                    .map(|p| format!(" path={}", enc_bytes(&p)))
                    .unwrap_or_default(),
                star_field(&sealed)
            )
        };
        write_atomic(&dlog.segment_path(next), &sealed)?;
        if let Some(k) = &key {
            keyring::put(&dlog, next, k, pass, opts.to)?;
        }
        crash_point(4)?;
        bodies.push(body);
        rep.copied.push((e.seq, next));
        next += 1;
        if bodies.len() >= 256 {
            let (es, h) = commit(&dlog, std::mem::take(&mut idx), &bodies, Some(identity))?;
            rep.dest_root = h.root;
            size = es.len() as u64;
            bodies.clear();
            idx = read_index(&dlog)?;
        }
    }
    if !bodies.is_empty() {
        let (es, h) = commit(&dlog, idx, &bodies, Some(identity))?;
        rep.dest_root = h.root;
        size = es.len() as u64;
    }
    rep.dest_size = size;
    Ok(rep)
}

/// Why an epoch card does not match the epoch line (`want_signer`: the key that must have signed it).
pub(crate) fn card_problem(
    card: &Card,
    link: &EpochLink,
    want_signer: Option<[u8; 32]>,
) -> Option<String> {
    let Some((pk, _)) = card.signer else {
        return Some("the epoch card is unsigned (an epoch card must be signed)".into());
    };
    if let Some(w) = want_signer {
        if pk != w {
            return Some(format!(
                "the epoch card is signed by {}…, not by the epoch log's signer {}…",
                &hex32(&pk)[..16],
                &hex32(&w)[..16]
            ));
        }
    }
    match card.children.as_slice() {
        [CardChild::Log {
            log_id, size, root, ..
        }] if *log_id == link.prev_log && *size == link.prev_size && *root == link.prev_root => None,
        [CardChild::Log { .. }] => Some(
            "the epoch card's child is not the archive the epoch line names (prev-log / prev-size / prev-root differ)".into(),
        ),
        _ => Some("an epoch card has exactly one child: the archived log".into()),
    }
}

/// `verify` finding for the `EPOCH.card` of an epoch log, if anything is off.
pub(crate) fn card_finding(log: &Log, link: &EpochLink) -> Option<Finding> {
    let p = log.dir.join(EPOCH_CARD_FILE);
    let bytes = match fs::read(&p) {
        Ok(b) => b,
        Err(_) => {
            return Some(fnd(
                Severity::Warn,
                "epoch-card-missing",
                EPOCH_CARD_FILE,
                "no epoch card in this log (the signed epoch line still names the archive)",
                Some("keep the card from `log epoch --card-out` and check it with `sigil log check-epoch --card`"),
            ))
        }
    };
    let bad = |m: String| {
        Some(fnd(
            Severity::Error,
            "epoch-card",
            EPOCH_CARD_FILE,
            m,
            Some("restore EPOCH.card from the copy kept at rollover"),
        ))
    };
    if sha256(&bytes) != link.card {
        return bad(
            "SHA-256 of EPOCH.card is not the epoch line's card= (altered or replaced)".into(),
        );
    }
    let card = match std::str::from_utf8(&bytes)
        .map_err(|_| err("not UTF-8"))
        .and_then(Card::parse)
    {
        Ok(c) => c,
        Err(e) => return bad(e.to_string()),
    };
    card_problem(&card, link, log.signer).and_then(bad)
}

/// Options of [`check_epoch`].
#[derive(Default)]
pub struct EpochCheckOpts<'a> {
    /// The epoch card file (default: `EPOCH.card` inside the epoch log).
    pub card: Option<&'a Path>,
    /// The archived log: also check that its first `prev-size` entries have root `prev-root`.
    pub archive: Option<&'a Path>,
    /// Require the new log's HEAD and the card signed by this key (or, for HEAD, a key it handed over to).
    pub signer: Option<[u8; 32]>,
}

/// What [`check_epoch`] verified.
#[derive(Debug)]
pub struct EpochCheck {
    /// The epoch log's id.
    pub log_id: String,
    /// The link its first line records.
    pub link: EpochLink,
    /// Who signed the epoch card.
    pub card_signer: [u8; 32],
    /// With `archive`: the archive's entry count now (`>= prev_size`).
    pub archive_size: Option<u64>,
    /// Things worth telling the user.
    pub notes: Vec<String>,
}

impl EpochCheck {
    /// Human-readable summary.
    pub fn render(&self) -> String {
        let mut s = format!(
            "epoch OK: log {} continues archive {} at {}:{}\n  epoch card signed by {}\n",
            self.log_id,
            self.link.prev_log,
            self.link.prev_size,
            hex32(&self.link.prev_root),
            hex32(&self.card_signer)
        );
        match self.archive_size {
            Some(n) => s.push_str(&format!(
                "  archive checked: its first {} entries have the pinned root (now {n} entries)\n",
                self.link.prev_size
            )),
            None => s.push_str("  archive not given: the link is checked up to the card (give --archive OLD for card → root → archive)\n"),
        }
        for n in &self.notes {
            s.push_str(&format!("  note: {n}\n"));
        }
        s
    }
}

/// Check the whole link of an epoch log: the log verifies (chain, signed HEAD), its epoch line, the
/// card (hash, signature, child) and, with `archive`, the archive's root at the cut. Fails closed.
pub fn check_epoch(path: &Path, opts: &EpochCheckOpts<'_>) -> Result<EpochCheck> {
    let bad = |m: String| err(format!("epoch does not verify: {m}"));
    let log = Log::open(path)?;
    if !log.epoch {
        return Err(bad(format!(
            "{} is not an epoch log (no epoch=1 in its manifest)",
            path.display()
        )));
    }
    let rep = check(
        path,
        &CheckOpts {
            signer: opts.signer,
            ..CheckOpts::default()
        },
    )?;
    if let Some(f) = rep
        .findings
        .iter()
        .find(|f| f.severity == Severity::Error && !(opts.card.is_some() && f.code == "epoch-card"))
    {
        return Err(bad(format!("{} {}: {}", f.code, f.subject, f.message)));
    }
    let idx = read_index(&log)?;
    let link = idx
        .entries
        .first()
        .and_then(|e| e.epoch_link())
        .cloned()
        .ok_or_else(|| bad("seq 1 is not an epoch line".into()))?;
    let cpath = opts
        .card
        .map(Path::to_path_buf)
        .unwrap_or_else(|| log.dir.join(EPOCH_CARD_FILE));
    let bytes = fs::read(&cpath).map_err(|e| {
        bad(format!(
            "epoch card {}: {e} (give it with --card)",
            cpath.display()
        ))
    })?;
    if sha256(&bytes) != link.card {
        return Err(bad(format!(
            "{}: SHA-256 is not the epoch line's card= (altered, or another card)",
            cpath.display()
        )));
    }
    let text = std::str::from_utf8(&bytes).map_err(|_| bad("epoch card is not UTF-8".into()))?;
    let card = Card::parse(text).map_err(|e| bad(e.to_string()))?;
    if let Some(m) = card_problem(&card, &link, log.signer) {
        return Err(bad(m));
    }
    let card_signer = card.signer.map(|s| s.0).unwrap_or_default();
    if let Some(w) = opts.signer {
        if card_signer != w && log.signer != Some(w) {
            return Err(bad(format!(
                "the epoch card is not signed by the expected key {}…",
                &hex32(&w)[..16]
            )));
        }
    }
    let mut notes = Vec::new();
    // the archive's HEAD signer at the cut (embedded in the card) must be the card signer, unless the
    // archive shows that the authority was handed over to it by its last entry
    let head_signer = match card.children.first() {
        Some(CardChild::Log {
            signer: Some((pk, _)),
            ..
        }) => Some(*pk),
        _ => None,
    };
    let mut archive_size = None;
    if let Some(a) = opts.archive {
        let old = Log::open(a).map_err(|e| bad(format!("archive {}: {e}", a.display())))?;
        if old.id != link.prev_log {
            return Err(bad(format!(
                "archive {} has log id {}, but the epoch line names {}",
                a.display(),
                old.id,
                link.prev_log
            )));
        }
        let have = log_prefix_ok(&old, link.prev_size, &link.prev_root)
            .map_err(|m| bad(format!("archive {}: {m}", a.display())))?;
        if have > link.prev_size {
            notes.push(format!(
                "the archive has {} entr{} appended after the cut; they belong to no epoch",
                have - link.prev_size,
                if have - link.prev_size == 1 {
                    "y"
                } else {
                    "ies"
                }
            ));
        }
        let oidx = read_index(&old)?;
        let next_signer = signer_for(&old, &oidx.entries, link.prev_size as usize + 1);
        match (old.signer, next_signer) {
            (Some(_), Some(s)) if s != card_signer && head_signer != Some(card_signer) => {
                return Err(bad(format!(
                    "the epoch card is signed by {}…, but the archive's signer at the cut is {}…",
                    &hex32(&card_signer)[..16],
                    &hex32(&s)[..16]
                )))
            }
            _ => {}
        }
        archive_size = Some(have);
    } else if let Some(h) = head_signer {
        if h != card_signer {
            return Err(bad(format!(
                "the epoch card is signed by {}…, not by the archive's HEAD signer {}… (if the archive handed its key over at its last entry, check with --archive)",
                &hex32(&card_signer)[..16],
                &hex32(&h)[..16]
            )));
        }
    }
    Ok(EpochCheck {
        log_id: log.id.clone(),
        link,
        card_signer,
        archive_size,
        notes,
    })
}

/// Refuse `restore --at` before the epoch cut: the epoch log holds only the live state at the cut.
pub(crate) fn before_cut(entries: &[Entry], at: u64) -> Result<()> {
    if let Some((e, l)) = entries.first().and_then(|e| e.epoch_link().map(|l| (e, l))) {
        if at < e.time {
            return Err(err(format!(
                "{} is before the epoch cut ({}): this log holds only the live state at the cut; restore from the archive log {} (first {} entries)",
                iso_utc(at),
                iso_utc(e.time),
                l.prev_log,
                l.prev_size
            )));
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::BTreeMap;

    fn tmpdir(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sigil-epoch-unit-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn pk(i: &Identity) -> [u8; 32] {
        public_key(i)
    }

    /// Every file under `dir` with its bytes (to prove the archive is byte-identical).
    fn snapshot(dir: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
        let mut out = BTreeMap::new();
        let mut stack = vec![dir.to_path_buf()];
        while let Some(d) = stack.pop() {
            for e in fs::read_dir(&d).unwrap().flatten() {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                } else {
                    out.insert(
                        p.strip_prefix(dir).unwrap().to_path_buf(),
                        fs::read(&p).unwrap(),
                    );
                }
            }
        }
        out
    }

    fn errors(path: &Path) -> Vec<String> {
        check(path, &CheckOpts::default())
            .unwrap()
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .map(|f| format!("{} {}", f.code, f.message))
            .collect()
    }

    fn opts(id: &Identity) -> EpochOpts<'_> {
        EpochOpts {
            identity: Some(id),
            pass: None,
            to: &[],
            unlock: &[],
            mode: Mode::Reflection,
            name: None,
            card_out: None,
        }
    }

    /// A signed log with entries 1..=3, entry 2 tombstoned (4 entries).
    fn signed_log(d: &Path, id: &Identity) -> PathBuf {
        let p = d.join("ev.sigil");
        init(&p, Some(id)).unwrap();
        for b in [b"one".as_slice(), b"two", b"three"] {
            append(
                &p,
                b,
                &AppendOpts {
                    identity: Some(id),
                    ..Default::default()
                },
            )
            .unwrap();
        }
        tombstone(&p, TombTarget::Seq(2), Some("test"), Some(id)).unwrap();
        p
    }

    fn read_seq(p: &Path, seq: u64) -> Vec<u8> {
        let r = read_range(
            p,
            seq,
            seq,
            &ReadOpts {
                pass: None,
                identities: &[],
            },
            ReadMode::Single,
        )
        .unwrap();
        r.parts.into_iter().flat_map(|(_, b)| b).collect()
    }

    /// Rewrite INDEX line `seq` with `f`, re-chain every later line and write a HEAD signed by `id`
    /// (what someone holding the signing key, or only file access with `id = None`, can do).
    fn rewrite_line(p: &Path, seq: usize, f: impl Fn(&str) -> String, id: Option<&Identity>) {
        let log = Log::open(p).unwrap();
        let text = fs::read_to_string(log.dir.join(INDEX_FILE)).unwrap();
        let mut out = format!("{INDEX_MAGIC}\n");
        let mut prev = log.genesis();
        for (i, l) in text.lines().skip(1).enumerate() {
            let body = l.rsplit_once(" chain=").unwrap().0;
            let body = if i + 1 == seq {
                f(body)
            } else {
                body.to_string()
            };
            prev = chain_hash(&prev, &body);
            out.push_str(&format!("{body} chain={}\n", hex32(&prev)));
        }
        fs::write(log.dir.join(INDEX_FILE), &out).unwrap();
        let entries = parse_index(&out, &log.genesis()).entries;
        if let Some(id) = id {
            commit_head(&log, &entries, Some(id)).unwrap();
        }
    }

    #[test]
    fn rollover_round_trip_keeps_archive_byte_identical() {
        let d = tmpdir("roundtrip");
        let id = Identity::generate().unwrap();
        let old = signed_log(&d, &id);
        let before = snapshot(&old);
        let r = epoch(&old, &d.join("ev2"), &opts(&id)).unwrap();
        assert_eq!(snapshot(&old), before, "the archive is only read");
        assert_eq!((r.prev_size, r.dest_size), (4, 3));
        assert_eq!(r.copied, vec![(1, 2), (3, 3)]);
        assert_eq!(r.skipped, vec![2, 4]);
        let new = d.join("ev2.sigil");
        assert!(errors(&new).is_empty(), "{:?}", errors(&new));
        let log = Log::open(&new).unwrap();
        assert!(log.epoch && log.format == LOG_FORMAT_EPOCH && log.signer == Some(pk(&id)));
        let idx = read_index(&log).unwrap();
        let link = idx.entries[0].epoch_link().unwrap().clone();
        let olog = Log::open(&old).unwrap();
        let oidx = read_index(&olog).unwrap();
        assert_eq!(link.prev_log, olog.id);
        assert_eq!(link.prev_root, root_of(&oidx.entries));
        assert_eq!(
            link.card,
            sha256(&fs::read(new.join(EPOCH_CARD_FILE)).unwrap())
        );
        assert_eq!(read_seq(&new, 2), b"one");
        assert_eq!(read_seq(&new, 3), b"three");
        // the new epoch takes appends (seqs continue from the copies), and still verifies
        let a = append(
            &new,
            b"four",
            &AppendOpts {
                identity: Some(&id),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(a.seq, 4);
        assert!(errors(&new).is_empty());
        let c = check_epoch(
            &new,
            &EpochCheckOpts {
                archive: Some(&old),
                signer: Some(pk(&id)),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(c.archive_size, Some(4));
        assert!(c.notes.is_empty());
        // card-only check (no archive) also passes
        check_epoch(&new, &EpochCheckOpts::default()).unwrap();
        // a second rollover of an epoch log works too (epoch of an epoch)
        epoch(&new, &d.join("ev3"), &opts(&id)).unwrap();
        assert!(errors(&d.join("ev3.sigil")).is_empty());
    }

    #[test]
    fn identity_is_required_and_must_be_the_current_signer() {
        let d = tmpdir("ident");
        let id = Identity::generate().unwrap();
        let eve = Identity::generate().unwrap();
        let old = signed_log(&d, &id);
        let mut o = opts(&id);
        o.identity = None;
        let e = epoch(&old, &d.join("a"), &o).unwrap_err().to_string();
        assert!(e.contains("needs --identity"), "{e}");
        let e = epoch(&old, &d.join("b"), &opts(&eve))
            .unwrap_err()
            .to_string();
        assert!(e.contains("not this log's current signer"), "{e}");
        assert!(!d.join("a.sigil").exists() && !d.join("b.sigil").exists());
        // after a handover the new key holds the log
        rotate_signer(&old, &id, pk(&eve)).unwrap();
        let e = epoch(&old, &d.join("c"), &opts(&id))
            .unwrap_err()
            .to_string();
        assert!(e.contains("not this log's current signer"), "{e}");
        epoch(&old, &d.join("c"), &opts(&eve)).unwrap();
        check_epoch(
            &d.join("c.sigil"),
            &EpochCheckOpts {
                archive: Some(&old),
                ..Default::default()
            },
        )
        .unwrap();
    }

    #[test]
    fn unsigned_log_fails_closed_unless_identity_signs() {
        let d = tmpdir("unsigned");
        let id = Identity::generate().unwrap();
        let old = d.join("u.sigil");
        init(&old, None).unwrap();
        append(&old, b"x", &AppendOpts::default()).unwrap();
        let mut o = opts(&id);
        o.identity = None;
        assert!(epoch(&old, &d.join("u2"), &o).is_err());
        assert!(!d.join("u2.sigil").exists());
        epoch(&old, &d.join("u2"), &opts(&id)).unwrap();
        let new = d.join("u2.sigil");
        assert_eq!(Log::open(&new).unwrap().signer, Some(pk(&id)), "pinned");
        assert!(errors(&new).is_empty());
        check_epoch(
            &new,
            &EpochCheckOpts {
                archive: Some(&old),
                signer: Some(pk(&id)),
                ..Default::default()
            },
        )
        .unwrap();
        // the epoch log refuses unsigned appends like any signed log
        assert!(append(&new, b"y", &AppendOpts::default()).is_err());
    }

    #[test]
    fn edited_epoch_line_fails_closed() {
        let d = tmpdir("edited");
        let id = Identity::generate().unwrap();
        let old = signed_log(&d, &id);
        epoch(&old, &d.join("n"), &opts(&id)).unwrap();
        let new = d.join("n.sigil");
        // file access only: edit prev-size in place (chain breaks)
        let p = new.join(INDEX_FILE);
        let good = fs::read_to_string(&p).unwrap();
        fs::write(&p, good.replacen("prev-size=4", "prev-size=3", 1)).unwrap();
        let e = errors(&new);
        assert!(e.iter().any(|m| m.starts_with("index-chain")), "{e:?}");
        assert!(check_epoch(&new, &EpochCheckOpts::default()).is_err());
        // re-chained, HEAD unsigned / stale: the signed HEAD no longer matches
        fs::write(&p, &good).unwrap();
        rewrite_line(
            &new,
            1,
            |b| b.replacen("prev-size=4", "prev-size=3", 1),
            None,
        );
        assert!(!errors(&new).is_empty());
        // re-chained and re-signed by another key: the pinned signer refuses it
        let eve = Identity::generate().unwrap();
        rewrite_line(&new, 1, |b| b.to_string(), Some(&eve));
        let e = errors(&new);
        assert!(e.iter().any(|m| m.starts_with("head-signer")), "{e:?}");
    }

    #[test]
    fn wrong_prev_root_or_size_fails_closed_even_when_resigned() {
        let d = tmpdir("prev");
        let id = Identity::generate().unwrap();
        let old = signed_log(&d, &id);
        epoch(&old, &d.join("n"), &opts(&id)).unwrap();
        let new = d.join("n.sigil");
        // the key holder re-chains and re-signs a different prev-size: the card no longer matches
        rewrite_line(
            &new,
            1,
            |b| b.replacen("prev-size=4", "prev-size=3", 1),
            Some(&id),
        );
        let e = errors(&new);
        assert!(e.iter().any(|m| m.starts_with("epoch-card")), "{e:?}");
        let e = check_epoch(&new, &EpochCheckOpts::default())
            .unwrap_err()
            .to_string();
        assert!(e.contains("epoch card"), "{e}");
        // without the card, the archive catches it: the root at size 3 is not prev-root
        fs::remove_file(new.join(EPOCH_CARD_FILE)).unwrap();
        let e = errors(&new);
        assert!(e.is_empty(), "missing card is a warning only: {e:?}");
        assert!(
            check_epoch(&new, &EpochCheckOpts::default()).is_err(),
            "check-epoch needs the card"
        );
        let cp = d.join("other.card");
        let card = make_card("x", std::slice::from_ref(&old), Some(&id)).unwrap();
        fs::write(&cp, card.render()).unwrap();
        let e = check_epoch(
            &new,
            &EpochCheckOpts {
                card: Some(&cp),
                archive: Some(&old),
                ..Default::default()
            },
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("card="), "card bytes differ from the line: {e}");
        // a wrong prev-root, same size
        epoch(&old, &d.join("m"), &opts(&id)).unwrap();
        let m = d.join("m.sigil");
        let zero = "0".repeat(64);
        rewrite_line(
            &m,
            1,
            |b| {
                let (head, rest) = b.split_once("prev-root=").unwrap();
                format!("{head}prev-root={zero}{}", &rest[64..])
            },
            Some(&id),
        );
        let e = errors(&m);
        assert!(e.iter().any(|m| m.starts_with("epoch-card")), "{e:?}");
        // a different log as archive is refused by id
        epoch(&old, &d.join("k"), &opts(&id)).unwrap();
        let other = d.join("o.sigil");
        init(&other, Some(&id)).unwrap();
        let e = check_epoch(
            &d.join("k.sigil"),
            &EpochCheckOpts {
                archive: Some(&other),
                ..Default::default()
            },
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("log id"), "{e}");
        // an archive whose history was rewritten (entry 1 edited, re-chained) is refused by root
        rewrite_line(&old, 1, |b| b.replacen("size=3", "size=4", 1), Some(&id));
        let e = check_epoch(
            &d.join("k.sigil"),
            &EpochCheckOpts {
                archive: Some(&old),
                ..Default::default()
            },
        )
        .unwrap_err()
        .to_string();
        assert!(e.contains("root at 4 differs"), "{e}");
    }

    #[test]
    fn forged_or_unsigned_card_fails_closed() {
        let d = tmpdir("card");
        let id = Identity::generate().unwrap();
        let eve = Identity::generate().unwrap();
        let old = signed_log(&d, &id);
        epoch(&old, &d.join("n"), &opts(&id)).unwrap();
        let new = d.join("n.sigil");
        let good = fs::read(new.join(EPOCH_CARD_FILE)).unwrap();
        // replaced card (signed by eve): hash mismatch
        let forged = make_card("x", std::slice::from_ref(&old), Some(&eve))
            .unwrap()
            .render();
        fs::write(new.join(EPOCH_CARD_FILE), &forged).unwrap();
        assert!(errors(&new).iter().any(|m| m.starts_with("epoch-card")));
        assert!(check_epoch(&new, &EpochCheckOpts::default()).is_err());
        // eve's card with the line re-pointed at it and HEAD re-signed by the owner: wrong card signer
        let sha = hex32(&sha256(forged.as_bytes()));
        let good_sha = hex32(&sha256(&good));
        rewrite_line(&new, 1, |b| b.replacen(&good_sha, &sha, 1), Some(&id));
        let e = errors(&new);
        assert!(
            e.iter()
                .any(|m| m.contains("not by the epoch log's signer")),
            "{e:?}"
        );
        // an unsigned card, line re-pointed and re-signed
        let unsigned = make_card("x", std::slice::from_ref(&old), None)
            .unwrap()
            .render();
        fs::write(new.join(EPOCH_CARD_FILE), &unsigned).unwrap();
        let usha = hex32(&sha256(unsigned.as_bytes()));
        rewrite_line(&new, 1, |b| b.replacen(&sha, &usha, 1), Some(&id));
        let e = errors(&new);
        assert!(e.iter().any(|m| m.contains("unsigned")), "{e:?}");
        assert!(check_epoch(&new, &EpochCheckOpts::default()).is_err());
        // a byte-edited card (same signer) fails its own signature / root
        fs::write(
            new.join(EPOCH_CARD_FILE),
            String::from_utf8(good.clone())
                .unwrap()
                .replacen("size=4", "size=3", 1),
        )
        .unwrap();
        assert!(!errors(&new).is_empty());
    }

    #[test]
    fn epoch_line_only_at_seq_1_of_an_epoch_log() {
        let d = tmpdir("place");
        let id = Identity::generate().unwrap();
        let old = signed_log(&d, &id);
        epoch(&old, &d.join("n"), &opts(&id)).unwrap();
        let new = d.join("n.sigil");
        let line1 = fs::read_to_string(new.join(INDEX_FILE))
            .unwrap()
            .lines()
            .nth(1)
            .unwrap()
            .rsplit_once(" chain=")
            .unwrap()
            .0
            .to_string();
        // an epoch line at seq 2: damage
        rewrite_line(&new, 2, |_| line1.replacen("seq=1", "seq=2", 1), Some(&id));
        let e = errors(&new);
        assert!(e.iter().any(|m| m.starts_with("index-epoch")), "{e:?}");
        // the manifest without epoch=1 (log=10 kept): the seq-1 epoch line is damage
        let p = d.join("p");
        epoch(&old, &p, &opts(&id)).unwrap();
        let p = d.join("p.sigil");
        let mut m = container::read_manifest(&p).unwrap();
        m.extra.remove("epoch");
        container::write_manifest(&p, &m).unwrap();
        let e = errors(&p);
        assert!(e.iter().any(|m| m.starts_with("index-epoch")), "{e:?}");
        // epoch=1 with seq 1 a plain segment: damage
        let q = d.join("q.sigil");
        init(&q, Some(&id)).unwrap();
        append(
            &q,
            b"z",
            &AppendOpts {
                identity: Some(&id),
                ..Default::default()
            },
        )
        .unwrap();
        let mut m = container::read_manifest(&q).unwrap();
        m.extra.insert("log".into(), "10".into());
        m.extra.insert("epoch".into(), "1".into());
        container::write_manifest(&q, &m).unwrap();
        let e = errors(&q);
        assert!(e.iter().any(|m| m.starts_with("index-epoch")), "{e:?}");
        // epoch=1 needs log>=10 and a signer; log=9 is reserved
        m.extra.insert("log".into(), "8".into());
        container::write_manifest(&q, &m).unwrap();
        assert!(Log::open(&q).unwrap_err().to_string().contains("epoch=1"));
        m.extra.remove("epoch");
        m.extra.insert("log".into(), "9".into());
        container::write_manifest(&q, &m).unwrap();
        assert!(Log::open(&q).unwrap_err().to_string().contains("reserved"));
        m.extra.insert("log".into(), "11".into());
        container::write_manifest(&q, &m).unwrap();
        assert!(Log::open(&q).unwrap_err().to_string().contains("newer"));
        let u = d.join("u.sigil");
        init(&u, None).unwrap();
        let mut m = container::read_manifest(&u).unwrap();
        m.extra.insert("log".into(), "10".into());
        m.extra.insert("epoch".into(), "1".into());
        container::write_manifest(&u, &m).unwrap();
        assert!(Log::open(&u).unwrap_err().to_string().contains("signer"));
    }

    #[test]
    fn old_style_logs_still_open_and_verify() {
        // logs written exactly as before (log=1, log=2 after a tombstone, log=4 after a handover)
        // carry no epoch key and verify unchanged
        let d = tmpdir("oldstyle");
        let id = Identity::generate().unwrap();
        let p = d.join("a.sigil");
        init(&p, Some(&id)).unwrap();
        append(
            &p,
            b"a",
            &AppendOpts {
                identity: Some(&id),
                ..Default::default()
            },
        )
        .unwrap();
        let m = container::read_manifest(&p).unwrap();
        assert_eq!(m.extra.get("log").map(String::as_str), Some("1"));
        assert!(!m.extra.contains_key("epoch"));
        assert!(errors(&p).is_empty());
        let old = signed_log(&d, &id);
        let m = container::read_manifest(&old).unwrap();
        assert_eq!(m.extra.get("log").map(String::as_str), Some("2"));
        assert!(errors(&old).is_empty());
        // a hand-written slice-1 log (fixed bytes, as a sigil of 2026-10 wrote it): verifies
        let h = d.join("h.sigil");
        fs::create_dir_all(h.join(SEGMENTS_DIR)).unwrap();
        let lid = "00112233445566778899aabbccddeeff";
        let mut g = b"sigil-log-genesis-v1\0".to_vec();
        g.extend_from_slice(lid.as_bytes());
        let g = sha256(&g);
        let sealed = crate::seal_kn_to(
            b"hello",
            Mode::Reflection,
            None,
            "segment-1",
            false,
            "",
            &[],
            None,
            crate::DEFAULT_PIECE,
            &[],
        )
        .unwrap();
        let path = segment_path(&h, 1);
        fs::create_dir_all(path.parent().unwrap()).unwrap();
        fs::write(&path, &sealed).unwrap();
        let body = format!("seq=1 t=1760000000 size=5 sha={}", hex32(&sha256(b"hello")));
        let c = chain_hash(&g, &body);
        fs::write(
            h.join(INDEX_FILE),
            format!("{INDEX_MAGIC}\n{body} chain={}\n", hex32(&c)),
        )
        .unwrap();
        fs::write(
            h.join(HEAD_FILE),
            format!(
                "{HEAD_MAGIC}\nseq=1\nchain={}\nroot={}\nt=1760000000\n",
                hex32(&c),
                hex32(&crate::merkle::merkle_root(&[c]))
            ),
        )
        .unwrap();
        fs::write(
            h.join(container::CONTAINER_FILE),
            format!("sigil-container=1\nkind=log\nname=h\nlog=1\nlog-id={lid}\n"),
        )
        .unwrap();
        let rep = check(
            &h,
            &CheckOpts {
                quick: false,
                ..CheckOpts::default()
            },
        )
        .unwrap();
        let errs: Vec<_> = rep
            .findings
            .iter()
            .filter(|f| f.severity == Severity::Error)
            .collect();
        assert!(errs.is_empty(), "{errs:?}");
        assert_eq!(read_seq(&h, 1), b"hello");
    }

    #[test]
    fn crash_at_every_step_leaves_old_intact_or_a_valid_new_epoch() {
        let id = Identity::generate().unwrap();
        for step in 1..=6u32 {
            let d = tmpdir(&format!("crash{step}"));
            let old = signed_log(&d, &id);
            let before = snapshot(&old);
            set_crash_at(step);
            let r = epoch(&old, &d.join("n"), &opts(&id));
            set_crash_at(0);
            assert!(r.is_err(), "step {step}: the simulated crash stops the run");
            let mut after = snapshot(&old);
            after.remove(Path::new(LOCK_FILE));
            assert_eq!(after, before, "step {step}: archive untouched");
            assert!(
                errors(&old).is_empty(),
                "step {step}: archive still verifies"
            );
            let new = d.join("n.sigil");
            let temps = fs::read_dir(&d)
                .unwrap()
                .flatten()
                .filter(|e| {
                    e.file_name()
                        .to_string_lossy()
                        .starts_with(".n.sigil.epoch-")
                })
                .count();
            assert_eq!(
                temps,
                usize::from((2..=5).contains(&step)),
                "step {step}: crash leftovers"
            );
            if step < 6 {
                assert!(
                    !new.exists(),
                    "step {step}: no half-made NEW under its final name"
                );
                // the rollover can simply be run again (a leftover hidden temp folder is in the way of nothing)
                let _ = fs::remove_file(old.join(LOCK_FILE));
                epoch(&old, &d.join("n"), &opts(&id)).unwrap();
            }
            assert!(errors(&new).is_empty(), "step {step}: {:?}", errors(&new));
            check_epoch(
                &new,
                &EpochCheckOpts {
                    archive: Some(&old),
                    ..Default::default()
                },
            )
            .unwrap();
            // the archive still takes appends after a crash (only the stale lock, if any, is in the way)
            append(
                &old,
                b"more",
                &AppendOpts {
                    identity: Some(&id),
                    ..Default::default()
                },
            )
            .unwrap();
        }
    }

    #[test]
    fn appends_to_the_archive_after_the_cut_are_reported() {
        let d = tmpdir("after");
        let id = Identity::generate().unwrap();
        let old = signed_log(&d, &id);
        epoch(&old, &d.join("n"), &opts(&id)).unwrap();
        append(
            &old,
            b"late",
            &AppendOpts {
                identity: Some(&id),
                ..Default::default()
            },
        )
        .unwrap();
        let c = check_epoch(
            &d.join("n.sigil"),
            &EpochCheckOpts {
                archive: Some(&old),
                ..Default::default()
            },
        )
        .unwrap();
        assert_eq!(c.archive_size, Some(5));
        assert!(c.notes[0].contains("belong to no epoch"), "{:?}", c.notes);
    }

    #[test]
    fn encrypted_archive_needs_a_wrap_and_private_flags_carry_over() {
        let d = tmpdir("enc");
        let id = Identity::generate().unwrap();
        let p = d.join("e.sigil");
        init(&p, Some(&id)).unwrap();
        append(
            &p,
            b"secret",
            &AppendOpts {
                identity: Some(&id),
                pass: Some("pw"),
                ..Default::default()
            },
        )
        .unwrap();
        let mut o = opts(&id);
        o.pass = Some("pw");
        // --pass opens the archive and re-seals the copies under the same passphrase
        epoch(&p, &d.join("e2"), &o).unwrap();
        let seg = fs::read(segment_path(&d.join("e2.sigil"), 2)).unwrap();
        assert!(
            crate::locate_header(&seg).unwrap().0.encrypted(),
            "copy stays encrypted"
        );
        // opened with an identity only (no wrap): refused, nothing written
        let q = d.join("t.sigil");
        init(&q, Some(&id)).unwrap();
        append(
            &q,
            b"secret",
            &AppendOpts {
                identity: Some(&id),
                recipients: &[id.public()],
                ..Default::default()
            },
        )
        .unwrap();
        let e = epoch(&q, &d.join("t2"), &opts(&id))
            .unwrap_err()
            .to_string();
        assert!(e.contains("no silent downgrade"), "{e}");
        assert!(!d.join("t2.sigil").exists());
        // a private + segment-keys archive gives a private + segment-keys epoch
        let r = d.join("r.sigil");
        init_opts(
            &r,
            &InitOpts {
                sign: Some(&id),
                segment_keys: true,
                private_index: true,
                index_pass: Some("pw"),
                ..Default::default()
            },
        )
        .unwrap();
        append(
            &r,
            b"hidden",
            &AppendOpts {
                identity: Some(&id),
                pass: Some("pw"),
                ..Default::default()
            },
        )
        .unwrap();
        epoch(&r, &d.join("r2"), &o).unwrap();
        let n = d.join("r2.sigil");
        let l = Log::open(&n).unwrap();
        assert!(l.privindex && l.segkeys && l.epoch);
        assert!(errors(&n).is_empty(), "{:?}", errors(&n));
        let out = read_range(
            &n,
            2,
            2,
            &ReadOpts {
                pass: Some("pw"),
                identities: &[],
            },
            ReadMode::Single,
        )
        .unwrap();
        assert_eq!(out.parts[0].1, b"hidden");
        check_epoch(
            &n,
            &EpochCheckOpts {
                archive: Some(&r),
                ..Default::default()
            },
        )
        .unwrap();
    }
}
