//! `sigil doctor --scrub DIR`: periodic repair of plain `.sg1` marks in a folder.
//!
//! Each mark is checked; a damaged one gets the same in-memory salvage as
//! `sigil mend --soft` (per-column Reed-Solomon error correction, then soft-RS /
//! GMD-lite). The file is rewritten (temp file + rename) only when that salvage
//! passes the Merkle binding and true-name checks and the result verifies fully
//! healthy. Anything else is reported as uncorrectable and left byte-identical.
//! Work packs and other files are skipped. Symlinks are not followed.

use std::fs;
use std::path::{Path, PathBuf};

use crate::Result;

fn io(e: std::io::Error) -> crate::Error {
    crate::Error::Msg(e.to_string())
}

/// What scrub did to one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ScrubOutcome {
    /// Healthy; not touched.
    Clean,
    /// Damaged, repaired and rewritten (Merkle + true name checked).
    Repaired,
    /// Damaged beyond repair (or failed the checks); left byte-identical. Reason given.
    Uncorrectable(String),
    /// Not a plain mark (work pack, unreadable header, ...); not touched. Reason given.
    Skipped(String),
}

/// Result of scrubbing a folder: one entry per `.sg1` file, in path order.
#[derive(Debug, Default, Clone)]
pub struct ScrubReport {
    /// Each file and its outcome.
    pub files: Vec<(PathBuf, ScrubOutcome)>,
}

impl ScrubReport {
    /// Count of files with an outcome matching `f`.
    fn count(&self, f: impl Fn(&ScrubOutcome) -> bool) -> usize {
        self.files.iter().filter(|(_, o)| f(o)).count()
    }

    /// Files repaired this run.
    pub fn repaired(&self) -> usize {
        self.count(|o| *o == ScrubOutcome::Repaired)
    }

    /// Files found damaged beyond repair (left as they were).
    pub fn uncorrectable(&self) -> usize {
        self.count(|o| matches!(o, ScrubOutcome::Uncorrectable(_)))
    }

    /// CLI exit code: 0 all clean or repaired, 2 something uncorrectable.
    pub fn exit_code(&self) -> i32 {
        if self.uncorrectable() > 0 {
            2
        } else {
            0
        }
    }

    /// Plain-language log, one line per file plus a summary.
    pub fn render(&self) -> String {
        let mut s = String::new();
        for (p, o) in &self.files {
            let line = match o {
                ScrubOutcome::Clean => "ok".to_string(),
                ScrubOutcome::Repaired => "REPAIRED (Merkle + true name checked)".to_string(),
                ScrubOutcome::Uncorrectable(w) => format!("UNCORRECTABLE, left as is: {w}"),
                ScrubOutcome::Skipped(w) => format!("skipped: {w}"),
            };
            s.push_str(&format!("{}: {line}\n", p.display()));
        }
        s.push_str(&format!(
            "scrub: {} mark(s), {} repaired, {} uncorrectable, {} clean\n",
            self.files.len(),
            self.repaired(),
            self.uncorrectable(),
            self.count(|o| *o == ScrubOutcome::Clean)
        ));
        s
    }
}

fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for e in fs::read_dir(dir).map_err(io)? {
        let e = e.map_err(io)?;
        let ft = e.file_type().map_err(io)?;
        let p = e.path();
        if ft.is_dir() {
            walk(&p, out)?;
        } else if ft.is_file() && p.extension().and_then(|x| x.to_str()) == Some("sg1") {
            out.push(p);
        }
    }
    Ok(())
}

/// Fully healthy: every shard present with a good CRC, Merkle root matches, header not
/// recovered from a backup copy.
fn healthy(bytes: &[u8]) -> bool {
    matches!(crate::verify(bytes), Ok((h, true, live, _, false)) if live == h.n as usize)
}

/// Scrub one mark. Never writes unless the repaired bytes pass every check.
pub fn scrub_file(path: &Path) -> Result<ScrubOutcome> {
    let data = fs::read(path).map_err(io)?;
    if data.starts_with(&crate::work::WORK_MAGIC) {
        return Ok(ScrubOutcome::Skipped(
            "work pack (use `sigil mend --soft`)".into(),
        ));
    }
    if crate::verify(&data).is_err() {
        // No header we can read: mend may still find one; otherwise uncorrectable.
        if crate::mend_bytes_ex(&data, true).is_err() {
            return Ok(ScrubOutcome::Uncorrectable("no readable header".into()));
        }
    } else if healthy(&data) {
        return Ok(ScrubOutcome::Clean);
    }
    let healed = match crate::mend_bytes_ex(&data, true) {
        Ok((h, _)) => h,
        Err(e) => return Ok(ScrubOutcome::Uncorrectable(e.to_string())),
    };
    if !healthy(&healed) {
        return Ok(ScrubOutcome::Uncorrectable(
            "repair did not verify fully healthy".into(),
        ));
    }
    let mut tmp = path.as_os_str().to_os_string();
    tmp.push(".scrub-part");
    let tmp = PathBuf::from(tmp);
    fs::write(&tmp, &healed).map_err(io)?;
    if let Err(e) = fs::rename(&tmp, path) {
        let _ = fs::remove_file(&tmp);
        return Err(io(e));
    }
    Ok(ScrubOutcome::Repaired)
}

/// Scrub every `.sg1` under `dir` (recursive, symlinks not followed).
pub fn scrub_dir(dir: &Path) -> Result<ScrubReport> {
    let mut files = Vec::new();
    walk(dir, &mut files)?;
    files.sort();
    let mut rep = ScrubReport::default();
    for p in files {
        let o = scrub_file(&p)?;
        rep.files.push((p, o));
    }
    Ok(rep)
}
