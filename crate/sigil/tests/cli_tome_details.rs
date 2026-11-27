//! File details in a Tome from the command line: permissions, modified times and empty
//! folders come back by default; set-ID bits only with --exact-modes; dotfiles only
//! with --dotfiles; --no-file-details and --old-tome-layout write the older layouts.
#![cfg(unix)]
mod common;
use std::os::unix::fs::PermissionsExt;
use std::path::Path;
use std::process::{Command, Output};

fn sigil(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(args)
        .output()
        .expect("run sigil")
}

fn ok(dir: &Path, args: &[&str]) -> String {
    let o = sigil(dir, args);
    assert!(
        o.status.success(),
        "{args:?}\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn mode(p: &Path) -> u32 {
    std::fs::symlink_metadata(p).unwrap().permissions().mode() & 0o7777
}

fn tree(dir: &Path) {
    let src = dir.join("src");
    std::fs::create_dir_all(src.join("empty")).unwrap();
    std::fs::write(src.join("key.txt"), b"private").unwrap();
    std::fs::set_permissions(src.join("key.txt"), std::fs::Permissions::from_mode(0o600)).unwrap();
    std::fs::write(src.join("tool"), b"#!/bin/sh\n").unwrap();
    std::fs::set_permissions(src.join("tool"), std::fs::Permissions::from_mode(0o4750)).unwrap();
    std::fs::write(src.join(".env"), b"TOKEN=1").unwrap();
}

#[test]
fn details_round_trip_and_set_id_bits_only_on_request() {
    let d = common::scratch("cli-details");
    tree(&d);
    let err = ok(&d, &["seal", "-o", "t.sg1", "src"]);
    assert!(err.contains("add --dotfiles to pack them"), "{err}");
    assert!(!err.contains("permissions are not stored"), "{err}");
    assert_eq!(&std::fs::read(d.join("t.sg1")).unwrap()[..5], b"SGDR\x04");
    ok(&d, &["unseal", "t.sg1", "-o", "out"]);
    assert_eq!(mode(&d.join("out/key.txt")) & 0o077, 0);
    assert_eq!(mode(&d.join("out/tool")) & 0o7000, 0);
    assert_eq!(mode(&d.join("out/tool")) & 0o100, 0o100);
    assert!(d.join("out/empty").is_dir());
    assert!(!d.join("out/.env").exists());
    ok(&d, &["unseal", "t.sg1", "-o", "exact", "--exact-modes"]);
    assert_eq!(mode(&d.join("exact/tool")), 0o4750);
    // Dotfiles on request.
    ok(&d, &["seal", "--dotfiles", "-o", "dot.sg1", "src"]);
    ok(&d, &["unseal", "dot.sg1", "-o", "dot"]);
    assert_eq!(std::fs::read(d.join("dot/.env")).unwrap(), b"TOKEN=1");
}

#[test]
fn no_file_details_and_old_layout_write_the_older_layouts() {
    let d = common::scratch("cli-details-old");
    tree(&d);
    let err = ok(&d, &["seal", "--no-file-details", "-o", "n.sg1", "src"]);
    assert!(err.contains("permissions are not stored"), "{err}");
    assert_eq!(&std::fs::read(d.join("n.sg1")).unwrap()[..5], b"SGDR\x03");
    ok(&d, &["seal", "--old-tome-layout", "-o", "o.sg1", "src"]);
    assert_eq!(&std::fs::read(d.join("o.sg1")).unwrap()[..5], b"SGDR\x01");
    // Single files take neither flag.
    for flag in ["--dotfiles", "--no-file-details"] {
        let o = sigil(&d, &["seal", flag, "-o", "f.sg1", "src/key.txt"]);
        assert!(!o.status.success() && !d.join("f.sg1").exists(), "{flag}");
    }
}
