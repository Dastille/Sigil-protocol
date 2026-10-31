//! `sigil log privatize SRC DEST`: turn a log with a public INDEX into a **new** log with a private
//! INDEX (`log=5`), so names, sizes and SHA-256s are sealed from then on.
//!
//! A public INDEX line's chain hash covers its `size=`, `sha=` and `path=` text, so those values
//! cannot be sealed in place without changing every chain hash (and so the HEAD, the Merkle roots
//! and every receipt, anchor and card made from the log). Rather than rewrite a log's history
//! silently, `privatize` copies it:
//!
//! * every live segment entry the source HEAD vouches for is read through the checked reader (the
//!   same checks as `log read` / `restore`) and sealed again into DEST, encrypted, under the new
//!   index key, keeping its time (`t=`) and its `log add` path; deleted (tombstoned / shredded)
//!   entries are not copied;
//! * DEST is built in a temporary sibling folder and renamed into place only when complete, so an
//!   error or a crash never leaves a half-made DEST under its final name; SRC is only read;
//! * DEST is a new log (new log id, new chain, new roots). Old receipts, anchors and cards still
//!   verify against SRC, not DEST. The report prints SRC's id and `SEQ:ROOT`, to pin as a link.

use std::fs;
use std::path::{Path, PathBuf};

use super::*;

/// Options of [`privatize`].
pub struct PrivatizeOpts<'a> {
    /// Opens SRC's encrypted segments (with `identities`), wraps DEST's index key and seals its segments.
    pub pass: Option<&'a str>,
    /// Identities that open SRC's encrypted segments.
    pub identities: &'a [Identity],
    /// Recipients DEST's index key (and segments) are wrapped to.
    pub to: &'a [PublicIdentity],
    /// Signs DEST; required when SRC is signed (and must be SRC's signer).
    pub sign: Option<&'a Identity>,
    /// ECC mode of the new segments.
    pub mode: Mode,
}

#[derive(Debug, Default)]
pub struct PrivatizeReport {
    pub src_id: String,
    pub src_size: u64,
    pub src_root: [u8; 32],
    pub dest: PathBuf,
    pub dest_id: String,
    pub dest_root: [u8; 32],
    /// `(source seq, dest seq)` of every copied entry.
    pub copied: Vec<(u64, u64)>,
    /// Source seqs not copied (deleted, or not segments: tombstones, signer lines, …).
    pub skipped: Vec<u64>,
    pub signed: bool,
}

impl PrivatizeReport {
    pub fn render(&self) -> String {
        format!(
            "log privatize: {} entr{} copied, {} skipped (deleted or not data)\n  from {} at {}:{}\n  to   {} ({}) root {}{}\n  (old receipts, anchors and cards stay valid for the source log only)\n",
            self.copied.len(),
            if self.copied.len() == 1 { "y" } else { "ies" },
            self.skipped.len(),
            self.src_id,
            self.src_size,
            hex32(&self.src_root),
            self.dest.display(),
            self.dest_id,
            hex32(&self.dest_root),
            if self.signed { ", signed" } else { "" }
        )
    }
}

/// See the module docs.
pub fn privatize(src: &Path, dest: &Path, opts: &PrivatizeOpts<'_>) -> Result<PrivatizeReport> {
    let log = Log::open(src)?;
    if log.privindex {
        return Err(err(format!(
            "{}: the INDEX is already private (use `sigil log rewrap` to change who can open it)",
            src.display()
        )));
    }
    let pass = opts.pass.filter(|p| !p.is_empty());
    if pass.is_none() && opts.to.is_empty() {
        return Err(err(
            "give --pass-file and/or --to: the new index key must be wrapped to someone who can open it later",
        ));
    }
    match (log.signer, opts.sign) {
        (Some(s), Some(id)) if SigningKey::from_bytes(&id.ed25519_seed).verifying_key().to_bytes() != s => {
            return Err(err(format!(
                "the source log is signed by {}; --sign must be that key so the copy keeps its signer",
                hex32(&s)
            )))
        }
        (Some(_), None) => {
            return Err(err(
                "the source log is signed: give --sign KEY.sgk (its signer) to sign the private copy",
            ))
        }
        _ => {}
    }
    let loaded = load(&log, &CheckOpts::default());
    if let Some(f) = loaded
        .findings
        .iter()
        .find(|f| f.severity == Severity::Error)
    {
        return Err(err(format!(
            "refusing to privatize a damaged log: {} {}: {} (run `sigil log verify` / `mend`)",
            f.code, f.subject, f.message
        )));
    }
    let entries = &loaded.index.entries;
    let st = &loaded.index.state;
    let trusted = trusted_len(&log, &loaded.index).min(entries.len());
    let head = match read_head(&log) {
        Some(Ok(h)) if h.seq == trusted as u64 => h,
        _ => {
            return Err(err(
                "the source has no HEAD it vouches for; run `sigil log verify`",
            ))
        }
    };
    let final_dir = dir_for_init(dest);
    if fs::symlink_metadata(&final_dir).is_ok() {
        return Err(err(format!(
            "{} already exists; privatize never overwrites (choose another DEST)",
            final_dir.display()
        )));
    }
    let fname = final_dir
        .file_name()
        .ok_or_else(|| err("bad DEST name"))?
        .to_string_lossy()
        .to_string();
    let tmp = final_dir.with_file_name(format!(
        ".{fname}.privatize-{}{}",
        std::process::id(),
        container::CONTAINER_SUFFIX
    ));
    if fs::symlink_metadata(&tmp).is_ok() {
        return Err(err(format!(
            "{} is in the way (left by a crash? remove it)",
            tmp.display()
        )));
    }
    let res = build(&log, entries, st, trusted, &tmp, opts, pass).and_then(|mut rep| {
        // the manifest name follows the final folder name
        let mut m = container::read_manifest(&tmp)?;
        m.name = container::strip_suffix(&fname).to_string();
        container::write_manifest(&tmp, &m)?;
        fs::rename(&tmp, &final_dir).map_err(io)?;
        rep.dest = final_dir.clone();
        Ok(rep)
    });
    match res {
        Ok(mut rep) => {
            rep.src_id = log.id.clone();
            rep.src_size = head.seq;
            rep.src_root = head.root;
            Ok(rep)
        }
        Err(e) => {
            let _ = fs::remove_dir_all(&tmp);
            Err(e)
        }
    }
}

fn build(
    src: &Log,
    entries: &[Entry],
    st: &State,
    trusted: usize,
    tmp: &Path,
    opts: &PrivatizeOpts<'_>,
    pass: Option<&str>,
) -> Result<PrivatizeReport> {
    let dlog = init_opts(
        tmp,
        &InitOpts {
            sign: opts.sign,
            segment_keys: src.segkeys,
            private_index: true,
            index_pass: pass,
            index_to: opts.to,
        },
    )?;
    let ropts = ReadOpts {
        pass: opts.pass,
        identities: opts.identities,
    };
    let mut rd = Reader::new(src, entries, st, &ropts);
    let mut rep = PrivatizeReport {
        dest_id: dlog.id.clone(),
        signed: opts.sign.is_some(),
        ..Default::default()
    };
    let mut idx = read_index(&dlog)?;
    let mut bodies: Vec<String> = Vec::new();
    let mut next = 1u64;
    for e in &entries[..trusted] {
        if e.op != Op::Seg || st.deleted_by(e.seq).is_some() || st.shredded_by(e.seq).is_some() {
            rep.skipped.push(e.seq);
            continue;
        }
        let data = rd
            .member(e.seq)
            .map_err(|x| err(format!("source entry {}: {x}", e.seq)))?;
        let (sealed, key) = seal_segment(&dlog, next, &data, opts.mode, pass, opts.to)?;
        let body = private::sealed_body(
            &dlog,
            next,
            e.time,
            "",
            &sealed,
            &Hidden {
                size: data.len() as u64,
                sha: sha256(&data),
                path: e.path(),
                reason: None,
            },
        )?;
        write_atomic(&dlog.segment_path(next), &sealed)?;
        if let Some(m) = &key {
            keyring::put(&dlog, next, m, pass, opts.to)?;
        }
        bodies.push(body);
        rep.copied.push((e.seq, next));
        next += 1;
        if bodies.len() >= 256 {
            let (_, h) = commit(&dlog, std::mem::take(&mut idx), &bodies, opts.sign)?;
            rep.dest_root = h.root;
            bodies.clear();
            idx = read_index(&dlog)?;
        }
    }
    if rep.copied.is_empty() {
        return Err(err("the source has no live data entries to copy"));
    }
    if !bodies.is_empty() {
        let (_, h) = commit(&dlog, idx, &bodies, opts.sign)?;
        rep.dest_root = h.root;
    }
    Ok(rep)
}
