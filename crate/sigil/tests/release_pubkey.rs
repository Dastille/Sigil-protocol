//! The published minisign release public key must match every copy in the docs, and a
//! throwaway minisign key (when the tool is installed) must accept a good SHA256SUMS and
//! reject a flipped one.
mod common;

use std::fs;
use std::path::{Path, PathBuf};
use std::process::Command;

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn release_pubkey() -> PathBuf {
    repo_root().join("keys/sigil-release.pub")
}

const KEY_ID: &str = "6AA9D817CBAC87FA";
const KEY_LINE: &str = "RWT6h6zLF9ipahFYaGkWD1OdEeGyIVK4SDRi+0XIJmirk/4cSsdOqUNi";
const COMMENT: &str = "untrusted comment: minisign public key 6AA9D817CBAC87FA";

/// Files that must print the official public key (both lines) and the key id.
const MUST_PUBLISH: &[&str] = &[
    "README.md",
    "docs/START.md",
    "docs/WHITEPAPER.md",
    "docs/RELEASE-SIGNING-DESIGN.md",
    "scripts/RECOVER.txt.in",
];

fn walk_text_docs(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut st = vec![
        root.join("README.md"),
        root.join("docs"),
        root.join("scripts"),
        root.join("keys"),
    ];
    while let Some(p) = st.pop() {
        if p.is_dir() {
            for e in fs::read_dir(&p).unwrap().flatten() {
                st.push(e.path());
            }
            continue;
        }
        let name = p.file_name().unwrap().to_string_lossy();
        if name.ends_with(".md")
            || name.ends_with(".txt")
            || name.ends_with(".in")
            || name.ends_with(".pub")
            || name.ends_with(".sh")
        {
            out.push(p);
        }
    }
    out
}

#[test]
fn published_key_matches_repo_file_and_docs_do_not_drift() {
    let root = repo_root();
    let pub_bytes = fs::read(release_pubkey()).expect("keys/sigil-release.pub");
    let expected = format!("{COMMENT}\n{KEY_LINE}\n");
    assert_eq!(
        pub_bytes,
        expected.as_bytes(),
        "keys/sigil-release.pub must be the exact two-line minisign public key"
    );
    // The comment's key id is the official id (minisign's print order).
    assert!(
        std::str::from_utf8(&pub_bytes).unwrap().contains(KEY_ID),
        "public key file must name id {KEY_ID}"
    );

    for rel in MUST_PUBLISH {
        let text = fs::read_to_string(root.join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"));
        assert!(
            text.contains(COMMENT) && text.contains(KEY_LINE) && text.contains(KEY_ID),
            "{rel} must print the official public key (id {KEY_ID}) exactly"
        );
        assert!(
            !text.contains("TBD until key created"),
            "{rel} still says the key is TBD"
        );
    }

    for path in walk_text_docs(&root) {
        let text = match fs::read_to_string(&path) {
            Ok(t) => t,
            Err(_) => continue,
        };
        let rel = path.strip_prefix(&root).unwrap_or(&path).display();
        assert!(
            !text.contains("TBD until key created"),
            "{rel} still says the key is TBD"
        );
        // If a file prints the official key id, it must also print the official key line.
        if text.contains(KEY_ID) {
            assert!(
                text.contains(KEY_LINE),
                "{rel} names key id {KEY_ID} but does not include the official key line"
            );
        }
        // Any minisign-looking public key line in the docs must be the official one.
        for line in text.lines() {
            let line = line.trim().trim_start_matches('`').trim_end_matches('`');
            if line.starts_with("RW")
                && line.len() == 56
                && line
                    .chars()
                    .all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/')
            {
                assert_eq!(
                    line, KEY_LINE,
                    "{rel} prints a minisign public key that is not the official one: {line}"
                );
            }
        }
    }
}

fn minisign_cmd() -> Option<String> {
    if let Ok(p) = std::env::var("MINISIGN") {
        if Path::new(&p).is_file() {
            return Some(p);
        }
    }
    let o = Command::new("minisign").arg("-v").output().ok()?;
    o.status.success().then(|| "minisign".to_string())
}

/// Throwaway key in a temp dir (`-W`, no password): sign SHA256SUMS, verify OK, flip a
/// byte, verify fails. Skips (with a clear note) if minisign is not on PATH and MINISIGN
/// is unset. Never uses the project signing key.
#[test]
fn minisign_round_trip_accepts_good_sums_and_rejects_a_flip() {
    let Some(minisign) = minisign_cmd() else {
        eprintln!(
            "SKIP minisign_round_trip_accepts_good_sums_and_rejects_a_flip: \
             minisign not on PATH (and MINISIGN is unset). Install a user-space \
             minisign (prebuilt or cargo/source into $HOME/.local/bin) to run this check."
        );
        return;
    };

    let d = common::scratch("minisign-rt");
    let pub_path = d.join("test.pub");
    let sec_path = d.join("test.key");
    let sums = d.join("SHA256SUMS");
    fs::write(
        &sums,
        "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa  artefact\n",
    )
    .unwrap();

    let gen = Command::new(&minisign)
        .args([
            "-G",
            "-W",
            "-p",
            pub_path.to_str().unwrap(),
            "-s",
            sec_path.to_str().unwrap(),
        ])
        .output()
        .expect("minisign -G");
    assert!(
        gen.status.success(),
        "minisign -G failed: {}{}",
        String::from_utf8_lossy(&gen.stdout),
        String::from_utf8_lossy(&gen.stderr)
    );

    let sign = Command::new(&minisign)
        .current_dir(&d)
        .args(["-Sm", "SHA256SUMS", "-s"])
        .arg(&sec_path)
        .output()
        .expect("minisign -S");
    assert!(
        sign.status.success(),
        "minisign -S failed: {}{}",
        String::from_utf8_lossy(&sign.stdout),
        String::from_utf8_lossy(&sign.stderr)
    );
    assert!(d.join("SHA256SUMS.minisig").is_file());

    let ver = Command::new(&minisign)
        .current_dir(&d)
        .args(["-Vm", "SHA256SUMS", "-p"])
        .arg(&pub_path)
        .output()
        .expect("minisign -V");
    let vout = format!(
        "{}{}",
        String::from_utf8_lossy(&ver.stdout),
        String::from_utf8_lossy(&ver.stderr)
    );
    assert!(
        ver.status.success(),
        "verify of a clean SHA256SUMS failed: {vout}"
    );
    assert!(
        vout.to_lowercase().contains("signature") && vout.to_lowercase().contains("verified"),
        "unexpected minisign verify output: {vout}"
    );

    // Flip one byte of the checksum list; the signature must no longer verify.
    let mut bytes = fs::read(&sums).unwrap();
    bytes[0] ^= 0xff;
    fs::write(&sums, &bytes).unwrap();
    let bad = Command::new(&minisign)
        .current_dir(&d)
        .args(["-Vm", "SHA256SUMS", "-p"])
        .arg(&pub_path)
        .output()
        .expect("minisign -V (tampered)");
    let bout = format!(
        "{}{}",
        String::from_utf8_lossy(&bad.stdout),
        String::from_utf8_lossy(&bad.stderr)
    );
    assert!(
        !bad.status.success(),
        "minisign accepted a tampered SHA256SUMS: {bout}"
    );
}
