//! `sigil doctor --scrub DIR`: periodic repair of plain `.sg1` marks in a folder.
//!
//! Each mark is checked; a damaged one gets the same in-memory salvage as
//! `sigil mend --soft` (per-column Reed-Solomon error correction, then soft-RS /
//! GMD-lite). The file is rewritten (temp file + rename) only when that salvage
//! passes the Merkle binding and true-name checks and the result verifies fully
//! healthy. Anything else is reported as uncorrectable and left byte-identical.
//! Work packs and other files are skipped. Symlinks are not followed.
//!
//! Scrub fails closed on pieces it cannot check: `.sgp` files (Frost Rune drives from
//! `sigil frost place`, or `sigil scatter` folders) are listed as NOT CHECKED and the
//! exit code is 3, so a scheduled scrub of cold drives never looks clean by checking nothing.

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
    /// Folders holding `.sgp` pieces that scrub could not check, with the piece count
    /// in each, in path order. A folder with a `KIT` manifest (Frost Rune root) is listed
    /// once for all pieces under it.
    pub unchecked: Vec<UncheckedPieces>,
}

/// A folder of `.sgp` pieces that `--scrub` found but cannot check.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UncheckedPieces {
    /// The folder: a Frost Rune root (has `KIT`) or the folder the pieces sit in.
    pub dir: PathBuf,
    /// Number of `.sgp` files found there (recursively for a Frost Rune root).
    pub pieces: usize,
    /// True when `dir` holds a Frost Rune `KIT` manifest (`sigil frost place` output).
    pub frost_root: bool,
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

    /// Total `.sgp` pieces found that scrub could not check.
    pub fn unchecked_pieces(&self) -> usize {
        self.unchecked.iter().map(|u| u.pieces).sum()
    }

    /// CLI exit code: 0 all clean or repaired; 2 something uncorrectable (damage found
    /// wins over the rest); 3 pieces found that scrub could not check (same meaning as
    /// `sigil doctor` exit 3: the check could not be done).
    pub fn exit_code(&self) -> i32 {
        if self.uncorrectable() > 0 {
            2
        } else if !self.unchecked.is_empty() {
            3
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
            "scrub: {} Sigil(s), {} repaired, {} uncorrectable, {} clean\n",
            self.files.len(),
            self.repaired(),
            self.uncorrectable(),
            self.count(|o| *o == ScrubOutcome::Clean)
        ));
        if !self.unchecked.is_empty() {
            s.push_str(&format!(
                "NOT CHECKED: {} piece file(s) (.sgp). Scrub only checks .sg1 files, so these \
                 were not checked at all and may be damaged or missing.\n",
                self.unchecked_pieces()
            ));
            for u in &self.unchecked {
                let d = u.dir.display();
                if u.frost_root {
                    s.push_str(&format!(
                        "  {d}: Frost Rune folder, {} piece(s). Check it with: \
                         sigil frost mend {d} -o check.sg1 && sigil verify check.sg1\n",
                        u.pieces
                    ));
                } else {
                    s.push_str(&format!(
                        "  {d}: {} piece(s). If this is one Frost Rune drive, copy it back next \
                         to the other usb-* folders and the KIT file and run `sigil frost mend` \
                         on that folder; if it is a scatter folder, run: \
                         sigil gather {d} -o check.sg1 && sigil verify check.sg1\n",
                        u.pieces
                    ));
                }
            }
        }
        s
    }
}

/// Walk `dir`: collect `.sg1` files into `out`, and count `.sgp` pieces per folder into
/// `pieces`. Inside a Frost Rune root (`KIT` manifest) every piece is counted for the root.
fn walk(
    dir: &Path,
    frost_root: Option<&Path>,
    out: &mut Vec<PathBuf>,
    pieces: &mut Vec<UncheckedPieces>,
) -> Result<()> {
    let here = match frost_root {
        Some(r) => r.to_path_buf(),
        None => dir.to_path_buf(),
    };
    let is_root = frost_root.is_none() && crate::kit::is_kit_dir(dir);
    let root = if is_root { Some(dir) } else { frost_root };
    for e in fs::read_dir(dir).map_err(io)? {
        let e = e.map_err(io)?;
        let ft = e.file_type().map_err(io)?;
        let p = e.path();
        let ext = p.extension().and_then(|x| x.to_str());
        if ft.is_dir() {
            walk(&p, root, out, pieces)?;
        } else if ft.is_file() && ext == Some("sg1") {
            out.push(p);
        } else if ft.is_file() && ext == Some("sgp") {
            match pieces.iter_mut().find(|u| u.dir == here) {
                Some(u) => u.pieces += 1,
                None => pieces.push(UncheckedPieces {
                    dir: here.clone(),
                    pieces: 1,
                    frost_root: root.is_some(),
                }),
            }
        }
    }
    if is_root && !pieces.iter().any(|u| u.dir == here) {
        // A KIT manifest with no pieces left is still a cold folder scrub cannot check.
        pieces.push(UncheckedPieces {
            dir: here,
            pieces: 0,
            frost_root: true,
        });
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

/// Scrub every `.sg1` under `dir` (recursive, symlinks not followed). `.sgp` pieces
/// (Frost Rune / scatter) are not checked; they are listed in
/// [`ScrubReport::unchecked`] and make [`ScrubReport::exit_code`] return 3.
pub fn scrub_dir(dir: &Path) -> Result<ScrubReport> {
    let mut files = Vec::new();
    let mut unchecked = Vec::new();
    walk(dir, None, &mut files, &mut unchecked)?;
    files.sort();
    unchecked.sort_by(|a, b| a.dir.cmp(&b.dir));
    let mut rep = ScrubReport {
        unchecked,
        ..ScrubReport::default()
    };
    for p in files {
        let o = scrub_file(&p)?;
        rep.files.push((p, o));
    }
    Ok(rep)
}
