//! `--json` on `identity` (via the software test authenticator), `import-pgp`, `keygen`
//! (public key path), `overture`, `mount --export-dir`, `umount` and `dispatch`: exactly one
//! JSON line on stdout and never secret key bytes.
mod common;
use std::fs;
use std::path::Path;
use std::process::Command;

fn run(d: &Path, a: &[&str]) -> (i32, String, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(d)
        .env("SIGIL_SOFT_AUTHENTICATOR", d.join("soft.bin"))
        .env("PATH", "/usr/bin:/bin")
        .args(a)
        .output()
        .expect("run sigil");
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).to_string(),
        String::from_utf8_lossy(&o.stderr).to_string(),
    )
}
fn json(d: &Path, a: &[&str], want: i32) -> String {
    let (c, out, err) = run(d, a);
    assert_eq!(c, want, "{a:?}: {out}{err}");
    assert_eq!(out.lines().count(), 1, "{a:?}: {out}");
    assert!(out.starts_with('{') && out.ends_with("}\n"), "{out}");
    out
}
fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
/// No 16-byte window of `secret` shows up as hex in `j`.
fn no_secret(j: &str, secret: &[u8]) {
    let h = hex_of(secret);
    for i in (0..h.len().saturating_sub(32)).step_by(2) {
        assert!(!j.contains(&h[i..i + 32]), "secret bytes in {j}");
    }
}

#[test]
fn keygen_and_identity_as_json() {
    let d = common::scratch("json-identity");
    let j = json(&d, &["keygen", "-o", "k.sgk", "--json"], 0);
    assert!(
        j.contains("\"public\":\"k.sgk.pub\",\"x25519\":\"") && j.contains("\"passkey\":false"),
        "{j}"
    );
    let sk = fs::read(d.join("k.sgk")).unwrap();
    no_secret(&j, &sk[5..]);
    let j = json(&d, &["identity", "info", "k.sgk", "--json"], 0);
    assert!(
        j.contains("\"kind\":\"plain identity") && j.contains("\"ed25519\":\""),
        "{j}"
    );
    no_secret(&j, &sk[5..]);

    let j = json(&d, &["keygen", "--passkey", "-o", "pk.sgk", "--json"], 0);
    assert!(
        j.contains("\"public\":\"pk.sgk.pub\"") && j.contains("\"passkey\":true"),
        "{j}"
    );
    let j = json(&d, &["identity", "info", "pk.sgk", "--json"], 0);
    assert!(
        j.contains("\"kind\":\"passkey-protected\"") && j.contains("slot #0"),
        "{j}"
    );
    json(&d, &["identity", "add-passkey", "pk.sgk", "--json"], 0);
    json(
        &d,
        &[
            "identity",
            "remove-passkey",
            "pk.sgk",
            "--slot",
            "1",
            "--json",
        ],
        0,
    );
    let j = json(
        &d,
        &[
            "identity",
            "unprotect",
            "pk.sgk",
            "-o",
            "plain.sgk",
            "--json",
        ],
        0,
    );
    assert_eq!(
        j,
        "{\"ok\":true,\"cmd\":\"identity unprotect\",\"exit\":0}\n"
    );
    let plain = fs::read(d.join("plain.sgk")).unwrap();
    json(
        &d,
        &[
            "identity",
            "protect",
            "plain.sgk",
            "--passkey",
            "-o",
            "again.sgk",
            "--json",
        ],
        0,
    );
    let j = json(&d, &["identity", "info", "nope.sgk", "--json"], 1);
    assert!(
        j.starts_with("{\"ok\":false,\"cmd\":\"identity info\""),
        "{j}"
    );
    no_secret(&j, &plain[5..]);
}

#[test]
fn import_pgp_as_json() {
    let d = common::scratch("json-pgp");
    let fx = |n: &str| format!("{}/tests/fixtures/pgp/{n}", env!("CARGO_MANIFEST_DIR"));
    let j = json(
        &d,
        &[
            "import-pgp",
            &fx("pgpy256-pub.asc"),
            "--pub-out",
            "p.pub",
            "--json",
        ],
        0,
    );
    assert!(
        j.contains("\"fingerprint\":\"5834A3244168C7852AF2388EE03B0A4A27E9BCDA\""),
        "{j}"
    );
    assert!(
        j.contains("\"public\":\"p.pub\"") && j.contains("\"identity\":null"),
        "{j}"
    );
    let j = json(
        &d,
        &["import-pgp", "missing.asc", "--pub-out", "q.pub", "--json"],
        1,
    );
    assert!(j.starts_with("{\"ok\":false,\"cmd\":\"import-pgp\""), "{j}");
}

#[test]
fn overture_mount_umount_dispatch_as_json() {
    let d = common::scratch("json-mount");
    fs::write(d.join("f"), "hello\n").unwrap();
    let (c, _, e) = run(&d, &["seal", "f", "-o", "f.sg1"]);
    assert_eq!(c, 0, "{e}");
    let j = json(&d, &["overture", "f.sg1", "--json"], 0);
    assert!(
        j.contains("\"cmd\":\"overture\"") && j.contains("\"report\":\""),
        "{j}"
    );
    let j = json(
        &d,
        &["mount", "f.sg1", "unused", "--export-dir", "ex", "--json"],
        0,
    );
    assert_eq!(
        j,
        "{\"ok\":true,\"cmd\":\"mount\",\"exit\":0,\"output\":\"ex\"}\n"
    );
    assert_eq!(fs::read(d.join("ex/f")).unwrap(), b"hello\n");
    // a FUSE mount would block: --json needs --export-dir
    let (c, _, _) = run(&d, &["mount", "f.sg1", "mnt", "--json"]);
    assert_eq!(c, 2);
    let j = json(&d, &["umount", "not-mounted", "--json"], 1);
    assert!(j.starts_with("{\"ok\":false,\"cmd\":\"umount\""), "{j}");
    let j = json(&d, &["dispatch", "f.sg1", "--json"], 1);
    assert!(
        j.starts_with("{\"ok\":false,\"cmd\":\"dispatch\"") && j.contains("needs --rsync"),
        "{j}"
    );
}
