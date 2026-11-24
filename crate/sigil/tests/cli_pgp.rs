//! CLI: passphrase-protected OpenPGP secret import.
mod common;
use std::path::Path;
use std::process::Command;

const LOCKED: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/pgp/locked-sec.asc"
);
const PGPY: &str = concat!(
    env!("CARGO_MANIFEST_DIR"),
    "/tests/fixtures/pgp/pgpy256-sec.asc"
);

fn sigil(dir: &Path, envs: &[(&str, &str)], args: &[&str]) -> std::process::Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sigil"));
    c.current_dir(dir)
        .env_remove("SIGIL_PGP_PASSPHRASE")
        .env_remove("SIGIL_SOFT_AUTHENTICATOR");
    for (k, v) in envs {
        c.env(k, v);
    }
    c.args(common::pass_via_file(args))
        .output()
        .expect("run sigil")
}

/// Passphrase files must be private (mode 600): sigil refuses ones others can read.
fn secret(path: &Path, text: &str) {
    std::fs::write(path, text).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
fn import_protected_pgp_secret_then_open() {
    let dir = common::scratch("cli-pgp");
    let ok = |o: std::process::Output| {
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        o
    };
    std::fs::write(dir.join("f.bin"), b"protected pgp import round trip").unwrap();

    // Wrong passphrase: refused, nothing written, passphrase not echoed.
    secret(&dir.join("bad.txt"), "nope\n");
    let o = sigil(
        &dir,
        &[],
        &[
            "import-pgp",
            LOCKED,
            "-o",
            "me.sgk",
            "--passphrase-file",
            "bad.txt",
        ],
    );
    assert!(!o.status.success());
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(
        all.contains("wrong passphrase") && !all.contains("nope"),
        "{all}"
    );
    assert!(!dir.join("me.sgk").exists());

    // Passphrase file (first line; CRLF tolerated).
    secret(&dir.join("pw.txt"), "hunter2\r\nignored\n");
    ok(sigil(
        &dir,
        &[],
        &[
            "import-pgp",
            LOCKED,
            "-o",
            "me.sgk",
            "--passphrase-file",
            "pw.txt",
        ],
    ));
    ok(sigil(
        &dir,
        &[],
        &["inscribe", "--to", "me.pub", "-o", "f.sg1", "f.bin"],
    ));
    ok(sigil(
        &dir,
        &[],
        &[
            "de-scribe",
            "--identity",
            "me.sgk",
            "-o",
            "back.bin",
            "f.sg1",
        ],
    ));
    assert_eq!(
        std::fs::read(dir.join("back.bin")).unwrap(),
        b"protected pgp import round trip"
    );

    // Env var, straight into a passkey-protected identity (software test authenticator).
    let soft = dir.join("soft.bin");
    let soft = soft.to_str().unwrap();
    ok(sigil(
        &dir,
        &[
            ("SIGIL_PGP_PASSPHRASE", "pgpy pass 256"),
            ("SIGIL_SOFT_AUTHENTICATOR", soft),
        ],
        &[
            "import-pgp",
            PGPY,
            "-o",
            "pk.sgk",
            "--pub-out",
            "pk.pub",
            "--passkey",
        ],
    ));
    assert_eq!(&std::fs::read(dir.join("pk.sgk")).unwrap()[0..4], b"SGKW");
    ok(sigil(
        &dir,
        &[],
        &["inscribe", "--to", "pk.pub", "-o", "g.sg1", "f.bin"],
    ));
    ok(sigil(
        &dir,
        &[("SIGIL_SOFT_AUTHENTICATOR", soft)],
        &["de-scribe", "--identity", "pk.sgk", "-o", "g.bin", "g.sg1"],
    ));
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn import_rfc9580_aead_argon2_and_v6_keys_then_open() {
    let fx = |n: &str| format!("{}/tests/fixtures/pgp/{n}", env!("CARGO_MANIFEST_DIR"));
    let dir = common::scratch("cli-pgp9580");
    let ok = |o: std::process::Output| {
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        o
    };
    std::fs::write(dir.join("f.bin"), b"rfc 9580 import round trip").unwrap();

    // v4 key, Argon2id + AES-256-GCM (OpenPGP.js), passphrase file.
    secret(&dir.join("pw.txt"), "gcm pass\n");
    let gcm = fx("opjs-gcm-sec.asc");
    let o = ok(sigil(
        &dir,
        &[],
        &[
            "import-pgp",
            &gcm,
            "-o",
            "g.sgk",
            "--passphrase-file",
            "pw.txt",
        ],
    ));
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(
        out.contains("95CAAE6B3CCE171DFC890247B666E23CF612FBAF") && !out.contains("v6"),
        "{out}"
    );
    ok(sigil(
        &dir,
        &[],
        &["inscribe", "--to", "g.pub", "-o", "g.sg1", "f.bin"],
    ));
    ok(sigil(
        &dir,
        &[],
        &["de-scribe", "--identity", "g.sgk", "-o", "g.out", "g.sg1"],
    ));
    assert_eq!(
        std::fs::read(dir.join("g.out")).unwrap(),
        b"rfc 9580 import round trip"
    );

    // Wrong passphrase on an AEAD key: refused, nothing written.
    secret(&dir.join("bad.txt"), "gcm pas\n");
    let o = sigil(
        &dir,
        &[],
        &[
            "import-pgp",
            &gcm,
            "-o",
            "bad.sgk",
            "--passphrase-file",
            "bad.txt",
        ],
    );
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("wrong passphrase"));
    assert!(!dir.join("bad.sgk").exists());

    // v6 key (Sequoia sq 1.3, CFB) via env; full SHA-256 fingerprint printed.
    let o = ok(sigil(
        &dir,
        &[("SIGIL_PGP_PASSPHRASE", "sq v6 pass")],
        &["import-pgp", &fx("sq-v6-sec.asc"), "-o", "v6.sgk"],
    ));
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(
        out.contains("EC9E746153F62ADFF10E2CF04B347A727FA7442A5E0C2C6D2D58203647F01C37")
            && out.contains("(OpenPGP v6)"),
        "{out}"
    );
    ok(sigil(
        &dir,
        &[],
        &["inscribe", "--to", "v6.pub", "-o", "v6.sg1", "f.bin"],
    ));
    ok(sigil(
        &dir,
        &[],
        &[
            "de-scribe",
            "--identity",
            "v6.sgk",
            "-o",
            "v6.out",
            "v6.sg1",
        ],
    ));
    assert_eq!(
        std::fs::read(dir.join("v6.out")).unwrap(),
        b"rfc 9580 import round trip"
    );
    // The v6 primary signs: same public key as the RFC-format Ed25519 primary.
    ok(sigil(&dir, &[], &["sign", "v6.sg1", "--key", "v6.sgk"]));

    // RFC 9580 A.3 v6 certificate works directly as --to.
    ok(sigil(
        &dir,
        &[],
        &[
            "inscribe",
            "--to",
            &fx("rfc9580-a3-pub.asc"),
            "-o",
            "r.sg1",
            "f.bin",
        ],
    ));
    let _ = std::fs::remove_dir_all(&dir);
}
