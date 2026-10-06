//! CLI: passphrase-protected OpenPGP secret import.
use std::path::Path;
use std::process::Command;

const LOCKED: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/pgp/locked-sec.asc");
const PGPY: &str = concat!(env!("CARGO_MANIFEST_DIR"), "/tests/fixtures/pgp/pgpy256-sec.asc");

fn sigil(dir: &Path, envs: &[(&str, &str)], args: &[&str]) -> std::process::Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sigil"));
    c.current_dir(dir).env_remove("SIGIL_PGP_PASSPHRASE").env_remove("SIGIL_SOFT_AUTHENTICATOR");
    for (k, v) in envs {
        c.env(k, v);
    }
    c.args(args).output().expect("run sigil")
}

#[test]
fn import_protected_pgp_secret_then_open() {
    let dir = std::env::temp_dir().join(format!("sigil-cli-pgp-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let ok = |o: std::process::Output| {
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        o
    };
    std::fs::write(dir.join("f.bin"), b"protected pgp import round trip").unwrap();

    // Wrong passphrase: refused, nothing written, passphrase not echoed.
    std::fs::write(dir.join("bad.txt"), "nope\n").unwrap();
    let o = sigil(&dir, &[], &["import-pgp", LOCKED, "-o", "me.sgk", "--passphrase-file", "bad.txt"]);
    assert!(!o.status.success());
    let all = format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr));
    assert!(all.contains("wrong passphrase") && !all.contains("nope"), "{all}");
    assert!(!dir.join("me.sgk").exists());

    // Passphrase file (first line; CRLF tolerated).
    std::fs::write(dir.join("pw.txt"), "hunter2\r\nignored\n").unwrap();
    ok(sigil(&dir, &[], &["import-pgp", LOCKED, "-o", "me.sgk", "--passphrase-file", "pw.txt"]));
    ok(sigil(&dir, &[], &["inscribe", "--to", "me.pub", "-o", "f.sg1", "f.bin"]));
    ok(sigil(&dir, &[], &["de-scribe", "--identity", "me.sgk", "-o", "back.bin", "f.sg1"]));
    assert_eq!(std::fs::read(dir.join("back.bin")).unwrap(), b"protected pgp import round trip");

    // Env var, straight into a passkey-protected identity (software test authenticator).
    let soft = dir.join("soft.bin");
    let soft = soft.to_str().unwrap();
    ok(sigil(
        &dir,
        &[("SIGIL_PGP_PASSPHRASE", "pgpy pass 256"), ("SIGIL_SOFT_AUTHENTICATOR", soft)],
        &["import-pgp", PGPY, "-o", "pk.sgk", "--pub-out", "pk.pub", "--passkey"],
    ));
    assert_eq!(&std::fs::read(dir.join("pk.sgk")).unwrap()[0..4], b"SGKW");
    ok(sigil(&dir, &[], &["inscribe", "--to", "pk.pub", "-o", "g.sg1", "f.bin"]));
    ok(sigil(
        &dir,
        &[("SIGIL_SOFT_AUTHENTICATOR", soft)],
        &["de-scribe", "--identity", "pk.sgk", "-o", "g.bin", "g.sg1"],
    ));
    let _ = std::fs::remove_dir_all(&dir);
}
