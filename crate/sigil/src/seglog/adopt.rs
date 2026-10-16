//! `sigil log adopt`: tidy a loose pile of `.sg1` stars into a segment log.
//!
//! An ad-hoc "log" — a folder of daily `.sg1` batches, one star per export — becomes ordinary
//! segments of a `kind=log` container, **byte-for-byte**: a star is never unsealed, re-sealed or
//! decrypted. The INDEX needs only the plain size and true-name, and both are in every star's
//! header, so adoption works without any key and keeps each star's own ECC mode and protection
//! (`--pass`, `--to`). See `docs/SEGMENT-LOG.md` ("Adopting a pile of stars").
//!
//! Crash-safe order (each step leaves a verifiable log):
//! segments copied as unindexed files (fsync + read-back) → INDEX lines appended in one write
//! (the commit point) → HEAD rewritten → originals removed last (unless `keep`).
//!
//! Each adopted line carries an additive `src=<sha256 of the star file>` key. Readers ignore it
//! (the line is still a plain `log=1` segment line), but it makes `adopt` **idempotent**: a source
//! whose exact bytes were already adopted is not appended twice; it is only removed. So a run that
//! crashed between commit and cleanup is finished by simply running it again.

use std::cmp::Ordering;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use super::*;

pub struct AdoptOpts<'a> {
    /// Signing key (required exactly when the log pinned a signer).
    pub identity: Option<&'a Identity>,
    /// Leave the original files where they are (default: remove each one once it is committed).
    pub keep: bool,
    /// Show the plan and change nothing.
    pub dry_run: bool,
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum AdoptAction {
    /// Becomes segment `seq`.
    Adopt { seq: u64 },
    /// Exactly these bytes are already segment `seq` (an earlier adopt, or a duplicate file).
    Already { seq: u64 },
}

#[derive(Clone, Debug)]
pub struct AdoptItem {
    pub src: PathBuf,
    pub size: u64,
    pub sha: [u8; 32],
    pub action: AdoptAction,
    /// Header mode / protection, for the plan ("reflection", "seal+pass", …).
    pub kind: String,
}

#[derive(Debug, Default)]
pub struct AdoptReport {
    pub dir: PathBuf,
    pub items: Vec<AdoptItem>,
    /// Not adopted and left in place: (path, why).
    pub skipped: Vec<(PathBuf, String)>,
    /// Files in an expanded folder that are not `.sg1` stars (left alone).
    pub ignored: usize,
    /// Originals removed after commit.
    pub removed: usize,
    pub root: Option<[u8; 32]>,
    pub signed: bool,
    pub dry_run: bool,
    pub notes: Vec<String>,
}

impl AdoptReport {
    pub fn adopted(&self) -> usize {
        self.items
            .iter()
            .filter(|i| matches!(i.action, AdoptAction::Adopt { .. }))
            .count()
    }

    pub fn render(&self) -> String {
        let mut s = String::new();
        let verb = if self.dry_run {
            "would adopt"
        } else {
            "adopted"
        };
        for i in &self.items {
            let what = match &i.action {
                AdoptAction::Adopt { seq } => format!("{verb} as segment {seq}"),
                AdoptAction::Already { seq } => format!("already segment {seq}"),
            };
            s.push_str(&format!(
                "  {}  {} bytes  {}  sha256 {}…  {what}\n",
                i.src.display(),
                i.size,
                i.kind,
                &hex32(&i.sha)[..16]
            ));
        }
        for (p, why) in &self.skipped {
            s.push_str(&format!("  {}  left in place: {why}\n", p.display()));
        }
        let mut tail = format!(
            "log adopt {}: {} {}",
            self.dir.display(),
            verb,
            self.adopted()
        );
        let already = self.items.len() - self.adopted();
        if already > 0 {
            tail.push_str(&format!(", {already} already in the log"));
        }
        if !self.skipped.is_empty() {
            tail.push_str(&format!(", {} left in place", self.skipped.len()));
        }
        if self.ignored > 0 {
            tail.push_str(&format!(", {} non-star file(s) ignored", self.ignored));
        }
        if self.dry_run {
            tail.push_str("  (dry run: nothing changed)");
        } else {
            if self.removed > 0 {
                tail.push_str(&format!("; removed {} original(s)", self.removed));
            }
            if let Some(r) = &self.root {
                tail.push_str(&format!("  root {}…", &hex32(r)[..16]));
                if self.signed {
                    tail.push_str(" (signed)");
                }
            }
        }
        s.push_str(&tail);
        s.push('\n');
        s
    }
}

/// Compare file names with digit runs as numbers (`b-2` before `b-10`), then bytewise.
pub fn natural_cmp(a: &str, b: &str) -> Ordering {
    let (mut x, mut y) = (a.as_bytes(), b.as_bytes());
    loop {
        match (x.first(), y.first()) {
            (None, None) => return a.cmp(b),
            (None, _) => return Ordering::Less,
            (_, None) => return Ordering::Greater,
            (Some(c), Some(d)) if c.is_ascii_digit() && d.is_ascii_digit() => {
                let lx = x.iter().take_while(|c| c.is_ascii_digit()).count();
                let ly = y.iter().take_while(|c| c.is_ascii_digit()).count();
                let nx = trim_zeros(&x[..lx]);
                let ny = trim_zeros(&y[..ly]);
                let o = nx.len().cmp(&ny.len()).then_with(|| nx.cmp(ny));
                if o != Ordering::Equal {
                    return o;
                }
                x = &x[lx..];
                y = &y[ly..];
            }
            (Some(c), Some(d)) => {
                if c != d {
                    return c.cmp(d);
                }
                x = &x[1..];
                y = &y[1..];
            }
        }
    }
}

fn trim_zeros(d: &[u8]) -> &[u8] {
    let z = d.iter().take_while(|c| **c == b'0').count();
    &d[z.min(d.len().saturating_sub(1))..]
}

fn is_star_name(p: &Path) -> bool {
    p.extension()
        .and_then(|e| e.to_str())
        .map(|e| e.eq_ignore_ascii_case("sg1"))
        .unwrap_or(false)
}

/// `true` when `p` is the log itself or anything inside a `.sigil` container.
fn inside_container(p: &Path) -> bool {
    let abs = fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf());
    abs.ancestors().any(|a| container::is_container(a))
}

/// Expand sources: a folder gives its `*.sg1` children in natural name order (not recursive);
/// files are taken in the order given. Returns (files, ignored-count).
fn expand(sources: &[PathBuf]) -> Result<(Vec<PathBuf>, usize)> {
    let mut out = Vec::new();
    let mut ignored = 0usize;
    for s in sources {
        if s.is_dir() {
            if container::is_container(s) {
                return Err(err(format!(
                    "{} is already a sigil container; adopt takes loose .sg1 stars (a folder of them, or files)",
                    s.display()
                )));
            }
            let mut kids: Vec<PathBuf> = Vec::new();
            for e in fs::read_dir(s).map_err(io)? {
                let p = e.map_err(io)?.path();
                if p.is_file() && is_star_name(&p) {
                    kids.push(p);
                } else {
                    ignored += 1;
                }
            }
            kids.sort_by(|a, b| {
                natural_cmp(
                    &a.file_name().unwrap_or_default().to_string_lossy(),
                    &b.file_name().unwrap_or_default().to_string_lossy(),
                )
            });
            out.extend(kids);
        } else if s.is_file() {
            out.push(s.clone());
        } else {
            return Err(err(format!("{}: no such file or folder", s.display())));
        }
    }
    // the same path named twice is one source
    let mut seen = std::collections::HashSet::new();
    out.retain(|p| seen.insert(fs::canonicalize(p).unwrap_or_else(|_| p.clone())));
    Ok((out, ignored))
}

fn kind_of(h: &crate::header::Header) -> String {
    let mut k = format!("{:?}", h.mode()).to_lowercase();
    if h.encrypted() {
        k.push_str("+locked");
    }
    k
}

/// Adopt loose `.sg1` stars into the log at `path` as new segments, in order.
pub fn adopt(path: &Path, sources: &[PathBuf], opts: &AdoptOpts<'_>) -> Result<AdoptReport> {
    let log = Log::open(path)?;
    if log.segkeys {
        return Err(err(
            "this log has per-segment keys (--segment-keys): every segment must be sealed under its own key, \
             so existing stars cannot be adopted as they are; unseal them and `sigil log append` the bytes instead",
        ));
    }
    signer_gate(&log, opts.identity)?;
    if sources.is_empty() {
        return Err(err("give at least one .sg1 star or a folder of them"));
    }
    let (files, ignored) = expand(sources)?;
    let mut rep = AdoptReport {
        dir: log.dir.clone(),
        ignored,
        dry_run: opts.dry_run,
        ..Default::default()
    };

    let _guard = if opts.dry_run {
        None
    } else {
        Some(lock(&log)?)
    };
    let (idx, notes) = if opts.dry_run {
        let idx = read_index(&log)?;
        if let Some((line, _, msg)) = &idx.error {
            return Err(err(format!(
                "INDEX is damaged at line {line} ({msg}); run `sigil log verify`"
            )));
        }
        (idx, Vec::new())
    } else {
        let (idx, notes) = prepare_write(&log)?;
        signer_gate_at(&log, &idx.entries, opts.identity)?;
        (idx, notes)
    };
    rep.notes = notes;

    // what is already in the log, by source-file hash
    let mut known: BTreeMap<[u8; 32], u64> = BTreeMap::new();
    for e in &idx.entries {
        if let Some(src) = e
            .body
            .split_whitespace()
            .find_map(|t| t.strip_prefix("src="))
            .and_then(parse_hex32)
        {
            known.entry(src).or_insert(e.seq);
        }
    }

    let st = State::build(&idx.entries);
    let mut next = idx.entries.len() as u64 + 1;
    let mut bodies: Vec<String> = Vec::new();
    let mut staged: Vec<(PathBuf, Vec<u8>)> = Vec::new(); // (segment path, bytes) to write
    for f in files {
        if inside_container(&f) {
            rep.skipped
                .push((f, "inside a sigil container (not a loose star)".into()));
            continue;
        }
        let bytes = match fs::read(&f) {
            Ok(b) => b,
            Err(e) => {
                rep.skipped.push((f, format!("unreadable: {e}")));
                continue;
            }
        };
        let h = match crate::locate_header(&bytes) {
            Ok((h, _, _)) => h,
            Err(_) => {
                rep.skipped.push((f, "not a sigil star".into()));
                continue;
            }
        };
        match health_bytes(&bytes) {
            Health::Ok => {}
            Health::Mendable(m) => {
                rep.skipped.push((
                    f.clone(),
                    format!(
                        "{m}; run `sigil mend {}` first, then adopt again",
                        f.display()
                    ),
                ));
                continue;
            }
            Health::Damaged(m) => {
                rep.skipped.push((f, format!("damaged ({m}); not adopted")));
                continue;
            }
        }
        let src = sha256(&bytes);
        let kind = kind_of(&h);
        if let Some(&seq) = known.get(&src) {
            if let Some(t) = st.deleted_by(seq) {
                rep.skipped.push((f, format!("these exact bytes were segment {seq}, deleted by entry {t}; not adopted again")));
                continue;
            }
            rep.items.push(AdoptItem {
                src: f,
                size: h.orig_len,
                sha: h.digest,
                action: AdoptAction::Already { seq },
                kind,
            });
            continue;
        }
        let seq = next;
        next += 1;
        known.insert(src, seq);
        bodies.push(format!(
            "seq={seq} t={} size={} sha={} src={}",
            now(),
            h.orig_len,
            hex32(&h.digest),
            hex32(&src)
        ));
        staged.push((log.segment_path(seq), bytes));
        rep.items.push(AdoptItem {
            src: f,
            size: h.orig_len,
            sha: h.digest,
            action: AdoptAction::Adopt { seq },
            kind,
        });
    }
    if opts.dry_run {
        return Ok(rep);
    }

    // 1. segment files (unindexed until the commit; a crash leaves leftovers `gc` reclaims and the
    //    next append overwrites), each read back before we trust it
    for (seg, bytes) in &staged {
        write_atomic(seg, bytes)?;
        let back = fs::read(seg).map_err(io)?;
        if sha256(&back) != sha256(bytes) {
            return Err(err(format!(
                "{}: read-back differs from the source; nothing was committed",
                seg.display()
            )));
        }
    }
    // 2. INDEX (commit point), 3. HEAD — also refreshed when nothing new, so the head stays current
    if !bodies.is_empty() {
        let (_entries, head) = commit(&log, idx, &bodies, opts.identity)?;
        rep.root = Some(head.root);
        rep.signed = head.sig.is_some();
    }
    // 4. originals last
    if !opts.keep {
        for i in &rep.items {
            if fs::remove_file(&i.src).is_ok() {
                rep.removed += 1;
            }
        }
    }
    Ok(rep)
}

#[cfg(test)]
mod tests {
    use super::natural_cmp;
    use std::cmp::Ordering::*;

    #[test]
    fn natural_order() {
        assert_eq!(natural_cmp("b-2.sg1", "b-10.sg1"), Less);
        assert_eq!(natural_cmp("2026-10-09.sg1", "2026-10-10.sg1"), Less);
        assert_eq!(natural_cmp("a.sg1", "b.sg1"), Less);
        assert_eq!(natural_cmp("x007", "x7"), Less); // equal numbers: bytewise tie-break
        assert_eq!(natural_cmp("x", "x1"), Less);
        assert_eq!(natural_cmp("x0", "x0"), Equal);
    }
}
