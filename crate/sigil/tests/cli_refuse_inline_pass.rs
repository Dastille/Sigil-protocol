//! A literal `--pass VALUE` (or `--seal-pass VALUE`) is refused before anything is read, derived
//! or written; `--pass-file` and `--pass -` stay the ways to give a passphrase.
//! (No `common::pass_via_file` here: these tests send the literal on purpose.)
mod common;
use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn raw(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .env_remove("SIGIL_SOFT_AUTHENTICATOR")
        .stdin(Stdio::null())
        .args(args)
        .output()
        .expect("run sigil")
}

fn listing(d: &Path) -> Vec<String> {
    let mut v: Vec<String> = fs::read_dir(d)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

fn pass_file(d: &Path) {
    fs::write(d.join("pw"), "correct horse\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join("pw"), fs::Permissions::from_mode(0o600)).unwrap();
    }
}

#[test]
fn literal_pass_refused_everywhere_nothing_written() {
    let d = common::scratch("inline-pass");
    fs::write(d.join("f.txt"), "secret\n").unwrap();
    fs::create_dir(d.join("dir")).unwrap();
    fs::write(d.join("dir/a.txt"), "a\n").unwrap();
    pass_file(&d);
    let o = raw(&d, &["log", "init", "ev"]);
    assert!(o.status.success());
    let cases: &[&[&str]] = &[
        &["seal", "--pass", "hunter2", "-o", "x.sg1", "f.txt"],
        &["seal", "--pass=hunter2", "-o", "x.sg1", "f.txt"],
        &["unseal", "--pass", "hunter2", "-o", "out.txt", "x.sg1"],
        &["log", "init", "ev2", "--pass", "hunter2"],
        &["log", "append", "ev", "f.txt", "--pass", "hunter2"],
        &["log", "add", "ev", "dir", "--pass", "hunter2"],
        &[
            "log", "read", "ev", "--seq", "1", "--pass", "hunter2", "-o", "r.txt",
        ],
        &[
            "log", "restore", "ev", "a.txt", "--pass", "hunter2", "-o", "r2",
        ],
        &[
            "mount",
            "ev",
            "mnt",
            "--export-dir",
            "exp",
            "--pass",
            "hunter2",
        ],
        &["log", "compact", "ev", "--seal-pass", "hunter2"],
    ];
    for args in cases {
        let before = listing(&d);
        let ev = fs::read(d.join("ev.sigil/INDEX")).ok();
        let o = raw(&d, args);
        let e = String::from_utf8_lossy(&o.stderr);
        assert!(!o.status.success(), "{args:?} succeeded");
        assert!(
            e.contains("refused") && e.contains("--pass-file") && !e.contains("hunter2"),
            "{args:?}: {e}"
        );
        assert_eq!(listing(&d), before, "{args:?} wrote something");
        assert_eq!(fs::read(d.join("ev.sigil/INDEX")).ok(), ev, "{args:?}");
    }
    // the safe ways still work
    let o = raw(&d, &["seal", "--pass-file", "pw", "-o", "x.sg1", "f.txt"]);
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let o = raw(
        &d,
        &["unseal", "--pass-file", "pw", "-o", "out.txt", "x.sg1"],
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    assert_eq!(fs::read(d.join("out.txt")).unwrap(), b"secret\n");
    // `--pass -` asks on a terminal; with none it fails without writing
    let o = raw(&d, &["seal", "--pass", "-", "-o", "y.sg1", "f.txt"]);
    assert!(!o.status.success());
    assert!(!d.join("y.sg1").exists());
    // empty still gets its own message
    let o = raw(&d, &["seal", "--pass", "", "-o", "y.sg1", "f.txt"]);
    assert!(String::from_utf8_lossy(&o.stderr).contains("empty passphrase"));
}

#[test]
fn literal_ward_refused_nothing_written() {
    let d = common::scratch("inline-ward");
    fs::create_dir(d.join("dir")).unwrap();
    fs::write(d.join("dir/a.txt"), "a\n").unwrap();
    pass_file(&d);
    let cases: &[&[&str]] = &[
        &[
            "seal",
            "--pass-file",
            "pw",
            "--ward",
            "a.txt=room-key",
            "-o",
            "x.sg1",
            "dir",
        ],
        &[
            "inscribe",
            "--pass-file",
            "pw",
            "--ward",
            "a.txt=room-key",
            "-o",
            "x.sg1",
            "dir",
        ],
    ];
    for args in cases {
        let before = listing(&d);
        let o = raw(&d, args);
        let e = String::from_utf8_lossy(&o.stderr);
        assert!(!o.status.success(), "{args:?} succeeded");
        assert!(
            e.contains("refused") && e.contains("--ward-file") && !e.contains("room-key"),
            "{args:?}: {e}"
        );
        assert_eq!(listing(&d), before, "{args:?} wrote something");
    }
    // the file form works
    fs::write(d.join("ward"), "room-key\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join("ward"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let o = raw(
        &d,
        &[
            "seal",
            "--pass-file",
            "pw",
            "--ward-file",
            "a.txt=ward",
            "-o",
            "x.sg1",
            "dir",
        ],
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    // `PATH=-` needs a terminal: refused here without writing
    let o = raw(
        &d,
        &[
            "seal",
            "--pass-file",
            "pw",
            "--ward",
            "a.txt=-",
            "-o",
            "y.sg1",
            "dir",
        ],
    );
    assert!(!o.status.success());
    assert!(!d.join("y.sg1").exists());
}
