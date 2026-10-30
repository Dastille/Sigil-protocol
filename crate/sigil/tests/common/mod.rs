//! Shared test scratch folders: the same pattern as the library's private
//! `staging::TempDir` (PR #27). Each folder is `sigil-test-<tag>-<pid>-<seq>-<64 random
//! bits>` in the system temp folder, made by one exclusive `mkdir` (fails if anything
//! already has that name, so a planted folder or symlink is never reused or wiped),
//! mode 0700 on Unix, and removed with everything inside when dropped.
#![allow(dead_code)]

use std::path::{Path, PathBuf};

pub struct Scratch {
    path: PathBuf,
}

impl Scratch {
    pub fn path(&self) -> &Path {
        &self.path
    }
}

impl std::ops::Deref for Scratch {
    type Target = Path;
    fn deref(&self) -> &Path {
        &self.path
    }
}

impl AsRef<Path> for Scratch {
    fn as_ref(&self) -> &Path {
        &self.path
    }
}

impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.path);
    }
}

/// A fresh, empty, private scratch folder (panics only if the temp folder is unusable).
pub fn scratch(tag: &str) -> Scratch {
    use std::sync::atomic::{AtomicU64, Ordering};
    static SEQ: AtomicU64 = AtomicU64::new(0);
    for _ in 0..16 {
        let mut r = [0u8; 8];
        getrandom::getrandom(&mut r).expect("random temp name");
        let path = std::env::temp_dir().join(format!(
            "sigil-test-{tag}-{}-{}-{:016x}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed),
            u64::from_le_bytes(r)
        ));
        let mut b = std::fs::DirBuilder::new();
        #[cfg(unix)]
        {
            use std::os::unix::fs::DirBuilderExt;
            b.mode(0o700);
        }
        match b.create(&path) {
            Ok(()) => return Scratch { path },
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => panic!("scratch folder {}: {e}", path.display()),
        }
    }
    panic!("no free scratch folder name");
}
