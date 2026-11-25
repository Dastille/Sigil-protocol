//! Build script: records the git commit for `sigil --version` as `SIGIL_GIT_COMMIT`
//! (short SHA, `-dirty` when tracked files have uncommitted changes). When built
//! without `.git` (for example in a container context), an explicit validated
//! `SIGIL_GIT_COMMIT` environment variable (7–40 hex chars, optional `-dirty`)
//! is accepted. Any other case gives `unknown`; it never fails the build.

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

fn is_valid_commit_tag(s: &str) -> bool {
    let hex_part = s.strip_suffix("-dirty").unwrap_or(s);
    (7..=40).contains(&hex_part.len()) && hex_part.bytes().all(|b| b.is_ascii_hexdigit())
}

fn commit(dir: &Path) -> Option<String> {
    // Only trust git when this crate is tracked by the repository found (a tarball
    // unpacked inside some other checkout must not borrow that checkout's commit).
    git(dir, &["ls-files", "--error-unmatch", "build.rs"])?;
    let sha = git(dir, &["rev-parse", "--short=7", "HEAD"])?;
    if !is_valid_commit_tag(&sha) {
        return None;
    }
    let dirty = git(dir, &["status", "--porcelain", "--untracked-files=no"])
        .map(|s| !s.is_empty())
        .unwrap_or(false);
    Some(if dirty { format!("{sha}-dirty") } else { sha })
}

fn env_commit() -> Option<String> {
    let v = std::env::var("SIGIL_GIT_COMMIT").ok()?;
    let v = v.trim();
    is_valid_commit_tag(v).then(|| v.to_string())
}

fn main() {
    let dir = std::env::var_os("CARGO_MANIFEST_DIR")
        .map(std::path::PathBuf::from)
        .unwrap_or_else(|| Path::new(".").to_path_buf());
    let c = commit(&dir)
        .or_else(env_commit)
        .unwrap_or_else(|| "unknown".to_string());
    println!("cargo:rustc-env=SIGIL_GIT_COMMIT={c}");
    println!("cargo:rerun-if-env-changed=SIGIL_GIT_COMMIT");
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
