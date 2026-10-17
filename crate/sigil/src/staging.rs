//! All-or-nothing output for restores that write many files (folder packs and
//! constellations).
//!
//! Every output file is first written in full to a hidden part file next to
//! its destination (`.<name>.<pid>-<n>.sigil-part`), flushed and synced. Only
//! when every member has unsealed and verified does [`Staging::commit`] rename
//! the part files over their destinations. If anything fails before that, the
//! part files and every directory this restore created are removed when the
//! [`Staging`] is dropped, and files that already existed are left untouched.
//!
//! Limits, stated plainly: the final renames are one per file, not one atomic
//! step across the whole folder. If a rename itself fails part-way through
//! commit (for example the disk is pulled), files renamed before it stay in
//! place; each of them is complete and verified, never a partial write. A crash
//! before commit can leave `.sigil-part` files behind; they are named so they
//! cannot be mistaken for restored files.

use crate::Result;
use std::ffi::OsString;
use std::fs::{self, File, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};

fn io(e: std::io::Error) -> crate::Error {
    crate::Error::Msg(e.to_string())
}

/// Output files of one restore, held as part files until [`Staging::commit`].
pub(crate) struct Staging {
    /// `(part file, final destination)` in the order they were written.
    parts: Vec<(PathBuf, PathBuf)>,
    /// Directories this restore created, outermost first.
    made: Vec<PathBuf>,
    seq: u32,
}

impl Staging {
    pub(crate) fn new() -> Self {
        Staging {
            parts: Vec::new(),
            made: Vec::new(),
            seq: 0,
        }
    }

    /// Create `dir` and any missing ancestors, remembering the ones created so
    /// a failed restore can remove them again.
    pub(crate) fn make_dir(&mut self, dir: &Path) -> Result<()> {
        let mut missing = Vec::new();
        let mut cur = Some(dir);
        while let Some(p) = cur {
            if p.as_os_str().is_empty() || p.exists() {
                break;
            }
            missing.push(p.to_path_buf());
            cur = p.parent();
        }
        for p in missing.into_iter().rev() {
            match fs::create_dir(&p) {
                Ok(()) => self.made.push(p),
                Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists && p.is_dir() => {}
                Err(e) => return Err(io(e)),
            }
        }
        Ok(())
    }

    /// Write the file that will become `out` through `f` into a new part file.
    pub(crate) fn write_with<T>(
        &mut self,
        out: &Path,
        f: impl FnOnce(&mut BufWriter<File>) -> Result<T>,
    ) -> Result<T> {
        if let Some(parent) = out.parent() {
            self.make_dir(parent)?;
        }
        let name = out
            .file_name()
            .ok_or_else(|| crate::Error::Msg(format!("no file name in {}", out.display())))?;
        let mut part_name = OsString::from(".");
        part_name.push(name);
        part_name.push(format!(".{}-{}.sigil-part", std::process::id(), self.seq));
        self.seq += 1;
        let part = out.with_file_name(part_name);
        let file = OpenOptions::new()
            .write(true)
            .create_new(true)
            .open(&part)
            .map_err(io)?;
        self.parts.push((part, out.to_path_buf()));
        let mut w = BufWriter::new(file);
        let v = f(&mut w)?;
        w.flush().map_err(io)?;
        let file = w
            .into_inner()
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        file.sync_all().map_err(io)?;
        Ok(v)
    }

    /// Write `bytes` as the file that will become `out`.
    pub(crate) fn write(&mut self, out: &Path, bytes: &[u8]) -> Result<()> {
        self.write_with(out, |w| w.write_all(bytes).map_err(io))
    }

    /// Rename every part file over its destination. Destinations that are
    /// directories are refused before anything is renamed.
    pub(crate) fn commit(mut self) -> Result<()> {
        if let Some((_, d)) = self.parts.iter().find(|(_, d)| d.is_dir()) {
            return Err(crate::Error::Msg(format!(
                "{} is a folder; nothing was restored",
                d.display()
            )));
        }
        let parts = std::mem::take(&mut self.parts);
        for (i, (part, dest)) in parts.iter().enumerate() {
            if let Err(e) = fs::rename(part, dest) {
                // Drop removes the parts not yet placed.
                self.parts = parts[i..].to_vec();
                self.made.clear();
                return Err(crate::Error::Msg(format!(
                    "restore stopped after placing {i} of {} files (each placed file is complete): {}: {e}",
                    parts.len(),
                    dest.display()
                )));
            }
        }
        self.made.clear();
        Ok(())
    }
}

impl Drop for Staging {
    fn drop(&mut self) {
        for (part, _) in &self.parts {
            let _ = fs::remove_file(part);
        }
        // Innermost first; remove_dir only removes empty directories.
        for d in self.made.iter().rev() {
            let _ = fs::remove_dir(d);
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!("sigil-staging-{tag}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    fn names(dir: &Path) -> Vec<String> {
        let mut v: Vec<String> = fs::read_dir(dir)
            .unwrap()
            .flatten()
            .map(|e| e.file_name().to_string_lossy().into_owned())
            .collect();
        v.sort();
        v
    }

    #[test]
    fn dropped_staging_removes_parts_and_created_dirs() {
        let root = scratch("drop");
        fs::write(root.join("old.txt"), b"old").unwrap();
        {
            let mut s = Staging::new();
            s.write(&root.join("old.txt"), b"new").unwrap();
            s.write(&root.join("a/b/c.txt"), b"c").unwrap();
            assert!(names(&root).iter().any(|n| n.ends_with(".sigil-part")));
            let r: Result<()> = s.write_with(&root.join("a/d.txt"), |w| {
                w.write_all(b"half").map_err(io)?;
                Err(crate::Error::Msg("boom".into()))
            });
            assert!(r.is_err());
        }
        assert_eq!(names(&root), vec!["old.txt"]);
        assert_eq!(fs::read(root.join("old.txt")).unwrap(), b"old");
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn commit_places_every_file() {
        let root = scratch("commit");
        fs::write(root.join("old.txt"), b"old").unwrap();
        let mut s = Staging::new();
        s.make_dir(&root.join("out")).unwrap();
        s.write(&root.join("out/x/y.txt"), b"y").unwrap();
        s.write(&root.join("old.txt"), b"new").unwrap();
        s.commit().unwrap();
        assert_eq!(names(&root), vec!["old.txt", "out"]);
        assert_eq!(fs::read(root.join("old.txt")).unwrap(), b"new");
        assert_eq!(fs::read(root.join("out/x/y.txt")).unwrap(), b"y");
        assert_eq!(names(&root.join("out/x")), vec!["y.txt"]);
        let _ = fs::remove_dir_all(&root);
    }

    #[test]
    fn commit_onto_a_folder_places_nothing() {
        let root = scratch("dir");
        fs::create_dir_all(root.join("taken")).unwrap();
        let mut s = Staging::new();
        s.write(&root.join("a.txt"), b"a").unwrap();
        s.write(&root.join("taken"), b"t").unwrap();
        assert!(s.commit().is_err());
        assert_eq!(names(&root), vec!["taken"]);
        let _ = fs::remove_dir_all(&root);
    }
}
