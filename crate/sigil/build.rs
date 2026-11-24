//! Build script: records the git commit for `sigil --version` as `SIGIL_GIT_COMMIT`
//! (short SHA, `-dirty` when tracked files have uncommitted changes). Any problem
//! (no git, not a checkout, built from a crates tarball) gives `unknown`; it never
//! fails the build.

use std::path::Path;
use std::process::Command;

fn git(dir: &Path, args: &[&str]) -> Option<String> {
    let out = Command::new("git")
        .current_dir(dir)
        .args(args)
        .output()
        .ok()?;
    if !out.status.success() {
        return None;
    }
    Some(String::from_utf8_lossy(&out.stdout).trim().to_string())
}

fn commit(dir: &Path) -> Option<String> {
    // Only trust git when this crate is tracked by the repository found (a tarball
    // unpacked inside some other checkout must not borrow that checkout's commit).
    git(dir, &["ls-files", "--error-unmatch", "build.rs"])?;
    let sha = git(dir, &["rev-parse", "--short=7", "HEAD"])?;
    if sha.len() < 7 || !sha.bytes().all(|b| b.is_ascii_hexdigit()) {
        return None;
    }
    let dirty = git(dir, &["status", "--porcelain", "--untracked-files=no"])
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    Some(if dirty { format!("{sha}-dirty") } else { sha })
}

fn main() {
    let dir = std::env::var_os("CARGO_MANIFEST_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| Path::new(".").to_path_buf());
    let c = commit(&dir).unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=SIGIL_GIT_COMMIT={c}");
    println!("cargo:rerun-if-changed=build.rs");
    println!("cargo:rerun-if-changed=src");
    println!("cargo:rerun-if-changed=Cargo.toml");
    if let Some(gd) = git(&dir, &["rev-parse", "--absolute-git-dir"]) {
        let gd = Path::new(&gd);
        for f in ["HEAD", "index", "packed-refs"] {
            println!("cargo:rerun-if-changed={}", gd.join(f).display());
        }
        if let Some(r) = git(&dir, &["symbolic-ref", "-q", "HEAD"]) {
            println!("cargo:rerun-if-changed={}", gd.join(r).display());
        }
    }
}
