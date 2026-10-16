//! CLI end-to-end: passkey-protected identity via the software test authenticator.
use std::path::Path;
use std::process::Command;

fn sigil(dir: &Path, soft: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .env("SIGIL_SOFT_AUTHENTICATOR", soft)
        .args(args)
        .output()
        .expect("run sigil")
}

#[test]
fn keygen_passkey_encrypt_to_open_sign_unprotect() {
    let dir = std::env::temp_dir().join(format!("sigil-cli-pk-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let soft = dir.join("soft.bin");
    let data: Vec<u8> = (0..200_000u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    std::fs::write(dir.join("f.bin"), &data).unwrap();

    let ok = |o: std::process::Output| {
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        o
    };
    ok(sigil(&dir, &soft, &["keygen", "--passkey", "-o", "me.sgk"]));
    assert_eq!(&std::fs::read(dir.join("me.sgk")).unwrap()[0..4], b"SGKW");
    ok(sigil(
        &dir,
        &soft,
        &["inscribe", "--to", "me.sgk.pub", "-o", "f.sg1", "f.bin"],
    ));
    ok(sigil(
        &dir,
        &soft,
        &[
            "de-scribe",
            "--identity",
            "me.sgk",
            "-o",
            "out.bin",
            "f.sg1",
        ],
    ));
    assert_eq!(std::fs::read(dir.join("out.bin")).unwrap(), data);
    ok(sigil(&dir, &soft, &["sign", "f.sg1", "--key", "me.sgk"]));

    // A different authenticator can't open it.
    let other = dir.join("other.bin");
    let o = sigil(
        &dir,
        &other,
        &["de-scribe", "--identity", "me.sgk", "-o", "x.bin", "f.sg1"],
    );
    assert!(!o.status.success());

    // Plain key → protect → unprotect is byte-exact; plain key still opens its seals.
    ok(sigil(&dir, &soft, &["keygen", "-o", "plain.sgk"]));
    ok(sigil(
        &dir,
        &soft,
        &["inscribe", "--to", "plain.sgk.pub", "-o", "g.sg1", "f.bin"],
    ));
    ok(sigil(
        &dir,
        &soft,
        &[
            "identity",
            "protect",
            "plain.sgk",
            "-o",
            "prot.sgk",
            "--passkey",
        ],
    ));
    ok(sigil(
        &dir,
        &soft,
        &[
            "de-scribe",
            "--identity",
            "prot.sgk",
            "-o",
            "g.bin",
            "g.sg1",
        ],
    ));
    ok(sigil(
        &dir,
        &soft,
        &["identity", "unprotect", "prot.sgk", "-o", "back.sgk"],
    ));
    assert_eq!(
        std::fs::read(dir.join("plain.sgk")).unwrap(),
        std::fs::read(dir.join("back.sgk")).unwrap()
    );
    ok(sigil(
        &dir,
        &soft,
        &[
            "de-scribe",
            "--identity",
            "plain.sgk",
            "-o",
            "g2.bin",
            "g.sg1",
        ],
    ));
    let _ = std::fs::remove_dir_all(&dir);
}
