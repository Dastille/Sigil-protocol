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

/// The CLI refuses a literal `--pass VALUE` / `--seal-pass VALUE` / `--ward PATH=PASSWORD`
/// (process list, shell history); `--ward` pairs become `--ward-file PATH=FILE` the same way.
/// Tests keep writing `"--pass", "pw"` for readability; this turns each such pair into
/// `--pass-file FILE` (`--seal-pass-file`), FILE an owner-only file holding the passphrase in a
/// private scratch folder. Empty / blank values and `-` are passed through unchanged, so the
/// CLI's own refusals and the hidden prompt are still what gets tested.
pub fn pass_via_file<I, S>(args: I) -> Vec<std::ffi::OsString>
where
    I: IntoIterator<Item = S>,
    S: AsRef<std::ffi::OsStr>,
{
    use std::ffi::OsString;
    use std::sync::OnceLock;
    static DIR: OnceLock<Scratch> = OnceLock::new();
    static N: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
    let file_for = |v: &str| -> OsString {
        let dir = DIR.get_or_init(|| scratch("passfiles"));
        let n = N.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let p = dir.join(format!("pass-{n}"));
        let mut o = std::fs::OpenOptions::new();
        o.write(true).create_new(true);
        #[cfg(unix)]
        {
            use std::os::unix::fs::OpenOptionsExt;
            o.mode(0o600);
        }
        use std::io::Write;
        let mut f = o.open(&p).expect("pass file");
        writeln!(f, "{v}").expect("write pass file");
        p.into_os_string()
    };
    let literal = |v: &str| !v.trim().is_empty() && v != "-";
    let args: Vec<OsString> = args.into_iter().map(|a| a.as_ref().to_owned()).collect();
    let mut out = Vec::with_capacity(args.len());
    let mut i = 0;
    while i < args.len() {
        let a = args[i].to_string_lossy().into_owned();
        let flag = match a.as_str() {
            "--pass" => Some("--pass-file"),
            "--seal-pass" => Some("--seal-pass-file"),
            _ => None,
        };
        if let (Some(f), Some(v)) = (flag, args.get(i + 1).and_then(|v| v.to_str())) {
            if literal(v) {
                out.push(f.into());
                out.push(file_for(v));
                i += 2;
                continue;
            }
        }
        // `--ward PATH=PASSWORD` → `--ward-file PATH=FILE` (PATH=- and PATH= pass through)
        if a == "--ward" {
            if let Some((path, pw)) = args
                .get(i + 1)
                .and_then(|v| v.to_str())
                .and_then(|v| v.split_once('='))
            {
                if literal(pw) {
                    let mut spec = OsString::from(format!("{path}="));
                    spec.push(file_for(pw));
                    out.push("--ward-file".into());
                    out.push(spec);
                    i += 2;
                    continue;
                }
            }
        }
        if let Some(v) = a.strip_prefix("--pass=").filter(|v| literal(v)) {
            out.push("--pass-file".into());
            out.push(file_for(v));
            i += 1;
            continue;
        }
        out.push(args[i].clone());
        i += 1;
    }
    out
}
