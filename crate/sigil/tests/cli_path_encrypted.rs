//! `sigil path` into an encrypted (sealed v2) folder pack: walks with the key,
//! fails closed without it or with a wrong one, and never prints member names then.
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn run(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(args)
        .env_remove("CLICOLOR_FORCE")
        .env_remove("SIGIL_ASCII")
        .env_remove("SIGIL_WARD")
        .stdin(Stdio::null())
        .output()
        .expect("run sigil")
}

fn ok(dir: &Path, args: &[&str]) -> String {
    let o = run(dir, args);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout).expect("utf8")
}

#[test]
fn path_walks_encrypted_folder_pack_with_key_only() {
    let d = std::env::temp_dir().join(format!("sigil-encpath-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("album/secretdir")).expect("mkdir");
    std::fs::write(d.join("album/secretdir/hidden-name.txt"), b"hello").expect("w");
    std::fs::write(d.join("album/inner.txt"), b"inner bytes").expect("w");
    std::fs::write(d.join("pw.txt"), b"correct horse\n").expect("w");
    std::fs::write(d.join("bad.txt"), b"wrong pony\n").expect("w");
    #[cfg(unix)]
    for f in ["pw.txt", "bad.txt"] {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(d.join(f), std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    ok(
        &d,
        &["seal", "album", "-o", "enc.sg1", "--pass-file", "pw.txt"],
    );
    ok(&d, &["seal", "album", "-o", "plain.sg1"]);

    // Plain pack still walks without a key.
    let plain = ok(&d, &["path", "plain.sg1"]);
    assert!(plain.contains("hidden-name.txt"), "{plain}");

    // No key / wrong key: refused, no names leak.
    for args in [
        vec!["path", "enc.sg1"],
        vec!["ls", "enc.sg1", "--pretty"],
        vec!["path", "enc.sg1", "--pass-file", "bad.txt"],
        vec!["walk", "enc.sg1", "inner.txt", "--pass-file", "bad.txt"],
    ] {
        let o = run(&d, &args);
        assert!(!o.status.success(), "{args:?} should fail");
        let all = format!(
            "{}{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        );
        assert!(
            !all.contains("hidden-name") && !all.contains("secretdir"),
            "{all}"
        );
    }

    // With the key: same listing as the plain pack, pretty works, descend works.
    let enc = ok(&d, &["path", "enc.sg1", "--pass-file", "pw.txt"]);
    assert!(
        enc.contains("hidden-name.txt") && enc.contains("inner.txt"),
        "{enc}"
    );
    let pretty = ok(&d, &["ls", "enc.sg1", "--pretty", "--pass-file", "pw.txt"]);
    assert!(pretty.contains("hidden-name.txt"), "{pretty}");
    assert!(
        pretty.contains("1 dir ") && !pretty.contains("1 dirs"),
        "{pretty}"
    );
    ok(
        &d,
        &[
            "walk",
            "enc.sg1",
            "inner.txt",
            "--pass-file",
            "pw.txt",
            "-o",
            "out.bin",
        ],
    );
    assert_eq!(
        std::fs::read(d.join("out.bin")).expect("read"),
        b"inner bytes"
    );
    let _ = std::fs::remove_dir_all(&d);
}
