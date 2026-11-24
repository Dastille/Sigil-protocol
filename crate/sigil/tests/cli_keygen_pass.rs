//! CLI: passphrase-protected identities (`keygen --pass - / --pass-file`, SGKP key file).
//! Unlock with `--identity-pass-file PATH` (or a hidden prompt); with neither, fail closed.
mod common;
use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn sigil(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run sigil")
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn ok(dir: &Path, args: &[&str]) -> Output {
    let o = sigil(dir, args);
    assert!(o.status.success(), "{args:?}: {}", text(&o));
    o
}

fn fails(dir: &Path, args: &[&str]) -> String {
    let o = sigil(dir, args);
    assert!(!o.status.success(), "{args:?} should fail: {}", text(&o));
    text(&o)
}

fn secret_file(dir: &Path, name: &str, body: &str) {
    fs::write(dir.join(name), body).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(dir.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
fn keygen_pass_file_round_trip_encrypt_to_and_sign() {
    let d = common::scratch("kg-pass");
    secret_file(&d, "pw", "correct horse battery\n");
    secret_file(&d, "bad", "not it\n");
    fs::write(d.join("f.bin"), b"payload for me\n").unwrap();

    let o = ok(&d, &["keygen", "-o", "me.sgk", "--pass-file", "pw"]);
    let out = String::from_utf8_lossy(&o.stdout);
    assert!(
        out.contains("identity → me.sgk  (passphrase-protected)  x25519 "),
        "{out}"
    );
    assert!(
        out.contains("public → me.sgk.pub  (encrypt-to: --to me.sgk.pub)"),
        "{out}"
    );
    assert!(out.contains("there is no reset"), "{out}");
    assert!(
        !String::from_utf8_lossy(&o.stderr).contains("warning"),
        "{}",
        text(&o)
    );
    let key = fs::read(d.join("me.sgk")).unwrap();
    assert_eq!(&key[0..4], b"SGKP");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        let mode = fs::metadata(d.join("me.sgk")).unwrap().permissions().mode() & 0o777;
        assert_eq!(mode, 0o600);
    }

    // Public half works without the passphrase (from .pub or from the .sgk header).
    ok(
        &d,
        &["inscribe", "--to", "me.sgk.pub", "-o", "f.sg1", "f.bin"],
    );
    ok(&d, &["inscribe", "--to", "me.sgk", "-o", "g.sg1", "f.bin"]);
    let info = String::from_utf8_lossy(&ok(&d, &["identity", "info", "me.sgk", "--json"]).stdout)
        .to_string();
    assert!(info.contains("\"kind\":\"passphrase-protected\""), "{info}");
    assert!(info.contains("Argon2id m=19456 KiB t=2 p=1"), "{info}");

    // No passphrase and no terminal: refused, nothing written.
    let e = fails(
        &d,
        &[
            "de-scribe",
            "--identity",
            "me.sgk",
            "-o",
            "out.bin",
            "f.sg1",
        ],
    );
    assert!(
        e.contains("there is no terminal here to ask for the passphrase"),
        "{e}"
    );
    assert!(e.contains("--identity-pass-file"), "{e}");
    assert!(!d.join("out.bin").exists());
    // Wrong passphrase: refused, nothing written.
    let e = fails(
        &d,
        &[
            "de-scribe",
            "--identity",
            "me.sgk",
            "--identity-pass-file",
            "bad",
            "-o",
            "out.bin",
            "f.sg1",
        ],
    );
    assert!(e.contains("wrong passphrase"), "{e}");
    assert!(!d.join("out.bin").exists());
    // Right passphrase (global flag may come before or after the subcommand).
    ok(
        &d,
        &[
            "de-scribe",
            "--identity",
            "me.sgk",
            "--identity-pass-file",
            "pw",
            "-o",
            "out.bin",
            "f.sg1",
        ],
    );
    assert_eq!(fs::read(d.join("out.bin")).unwrap(), b"payload for me\n");
    ok(
        &d,
        &[
            "--identity-pass-file",
            "pw",
            "de-scribe",
            "--identity",
            "me.sgk",
            "-o",
            "out2.bin",
            "g.sg1",
        ],
    );
    assert_eq!(fs::read(d.join("out2.bin")).unwrap(), b"payload for me\n");

    // Sign with the Ed25519 half; the signature verifies under the identity's public key.
    let e = fails(&d, &["sign", "f.sg1", "--key", "me.sgk"]);
    assert!(e.contains("passphrase-protected"), "{e}");
    assert!(!d.join("f.sg1.sig").exists());
    ok(
        &d,
        &[
            "sign",
            "f.sg1",
            "--key",
            "me.sgk",
            "--identity-pass-file",
            "pw",
        ],
    );
    let ed = info.split("\"ed25519\":\"").nth(1).unwrap()[..64].to_string();
    let v = text(&ok(&d, &["verify", "f.sg1"]));
    assert!(
        v.contains(&format!("attestation: good  pubkey={ed}")),
        "{v}"
    );

    // Damage: truncated or flipped key files fail closed with a clear message.
    fs::write(d.join("cut.sgk"), &key[..key.len() - 5]).unwrap();
    let e = fails(
        &d,
        &[
            "de-scribe",
            "--identity",
            "cut.sgk",
            "--identity-pass-file",
            "pw",
            "-o",
            "x",
            "f.sg1",
        ],
    );
    assert!(e.contains("damaged passphrase identity"), "{e}");
    let mut flip = key.clone();
    let n = flip.len();
    flip[n - 20] ^= 1;
    fs::write(d.join("flip.sgk"), &flip).unwrap();
    let e = fails(
        &d,
        &[
            "de-scribe",
            "--identity",
            "flip.sgk",
            "--identity-pass-file",
            "pw",
            "-o",
            "x",
            "f.sg1",
        ],
    );
    assert!(
        e.contains("wrong passphrase, or the identity file was changed or damaged"),
        "{e}"
    );
    assert!(!d.join("x").exists());
}

#[test]
fn keygen_pass_refusals() {
    let d = common::scratch("kg-pass-refuse");
    secret_file(&d, "pw", "pw\n");
    secret_file(&d, "empty", "  \n");
    fs::write(d.join("open"), "pw\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join("open"), fs::Permissions::from_mode(0o644)).unwrap();
    }
    let e = fails(&d, &["keygen", "-o", "k.sgk", "--pass", "hunter2"]);
    assert!(
        e.contains("a passphrase given as --pass VALUE is refused"),
        "{e}"
    );
    assert!(!e.contains("hunter2"), "{e}");
    let e = fails(&d, &["keygen", "-o", "k.sgk", "--pass", ""]);
    assert!(e.contains("empty passphrase"), "{e}");
    let e = fails(&d, &["keygen", "-o", "k.sgk", "--pass-file", "empty"]);
    assert!(e.contains("is empty"), "{e}");
    let e = fails(&d, &["keygen", "-o", "k.sgk", "--pass-file", "open"]);
    assert!(e.contains("can be read or changed by other users"), "{e}");
    // `--pass -` with no terminal: refused, nothing written.
    fails(&d, &["keygen", "-o", "k.sgk", "--pass", "-"]);
    let e = fails(
        &d,
        &["keygen", "-o", "k.sgk", "--pass-file", "pw", "--passkey"],
    );
    assert!(e.contains("cannot be used with"), "{e}");
    let e = fails(
        &d,
        &["keygen", "-o", "k.sgk", "--pass-file", "pw", "--legacy"],
    );
    assert!(e.contains("cannot be used with"), "{e}");
    assert!(!d.join("k.sgk").exists());
    assert!(!d.join("k.sgk.pub").exists());
    // --identity-pass-file follows the same file rules.
    ok(&d, &["keygen", "-o", "k.sgk", "--pass-file", "pw"]);
    fs::write(d.join("f"), "x").unwrap();
    ok(&d, &["inscribe", "--to", "k.sgk.pub", "-o", "f.sg1", "f"]);
    let e = fails(
        &d,
        &[
            "de-scribe",
            "--identity",
            "k.sgk",
            "--identity-pass-file",
            "open",
            "-o",
            "o",
            "f.sg1",
        ],
    );
    assert!(e.contains("can be read or changed by other users"), "{e}");
}

#[test]
fn plain_keygen_unchanged_but_warns() {
    let d = common::scratch("kg-plain-warn");
    let o = ok(&d, &["keygen", "-o", "me.sgk"]);
    let out = String::from_utf8_lossy(&o.stdout);
    let lines: Vec<&str> = out.lines().collect();
    assert_eq!(lines.len(), 3, "{out}");
    assert!(lines[0].starts_with("identity → me.sgk  x25519 "), "{out}");
    assert_eq!(
        lines[1],
        "public → me.sgk.pub  (encrypt-to: --to me.sgk.pub)"
    );
    assert_eq!(
        lines[2],
        "attest seed is inside .sgk; sign with --key me.sgk"
    );
    let err = String::from_utf8_lossy(&o.stderr);
    assert_eq!(err.lines().count(), 1, "{err}");
    assert!(err.starts_with("warning: me.sgk is not protected"), "{err}");
    assert!(
        err.contains("--pass -") && err.contains("--passkey"),
        "{err}"
    );
    let k = fs::read(d.join("me.sgk")).unwrap();
    assert_eq!(&k[0..4], b"SGIK");
    // Plain identities still open without any passphrase (the flag is ignored for them).
    fs::write(d.join("f"), "x").unwrap();
    ok(&d, &["inscribe", "--to", "me.sgk.pub", "-o", "f.sg1", "f"]);
    ok(
        &d,
        &["de-scribe", "--identity", "me.sgk", "-o", "o", "f.sg1"],
    );
}

#[test]
fn identity_protect_and_unprotect_with_passphrase() {
    let d = common::scratch("id-protect-pass");
    secret_file(&d, "pw", "a long passphrase\n");
    ok(&d, &["keygen", "-o", "plain.sgk"]);
    let plain = fs::read(d.join("plain.sgk")).unwrap();
    fs::write(d.join("f"), "data\n").unwrap();
    ok(
        &d,
        &["inscribe", "--to", "plain.sgk.pub", "-o", "f.sg1", "f"],
    );

    let e = fails(&d, &["identity", "protect", "plain.sgk", "-o", "p.sgk"]);
    assert!(e.contains("--passkey"), "{e}");
    let o = ok(
        &d,
        &[
            "identity",
            "protect",
            "plain.sgk",
            "-o",
            "p.sgk",
            "--pass-file",
            "pw",
        ],
    );
    assert!(
        text(&o).contains("protected → p.sgk  (passphrase, Argon2id)"),
        "{}",
        text(&o)
    );
    assert_eq!(&fs::read(d.join("p.sgk")).unwrap()[0..4], b"SGKP");
    let e = fails(
        &d,
        &[
            "identity",
            "protect",
            "p.sgk",
            "-o",
            "q.sgk",
            "--pass-file",
            "pw",
        ],
    );
    assert!(e.contains("already passphrase-protected"), "{e}");
    ok(
        &d,
        &[
            "de-scribe",
            "--identity",
            "p.sgk",
            "--identity-pass-file",
            "pw",
            "-o",
            "o",
            "f.sg1",
        ],
    );
    assert_eq!(fs::read(d.join("o")).unwrap(), b"data\n");
    let e = fails(&d, &["identity", "unprotect", "p.sgk", "-o", "back.sgk"]);
    assert!(e.contains("no terminal"), "{e}");
    ok(
        &d,
        &[
            "identity",
            "unprotect",
            "p.sgk",
            "-o",
            "back.sgk",
            "--identity-pass-file",
            "pw",
        ],
    );
    assert_eq!(fs::read(d.join("back.sgk")).unwrap(), plain);

    // --in-place replaces the plain file.
    ok(
        &d,
        &[
            "identity",
            "protect",
            "back.sgk",
            "--in-place",
            "--pass-file",
            "pw",
        ],
    );
    assert_eq!(&fs::read(d.join("back.sgk")).unwrap()[0..4], b"SGKP");
    assert!(!d.join("back.sgk.sigil-tmp").exists());
}
