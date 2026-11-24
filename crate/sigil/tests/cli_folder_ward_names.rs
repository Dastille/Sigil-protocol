//! A folder pack locked only with per-file `--ward` passphrases used to keep every
//! member name and size in the clear. Safe by default now: `seal --ward` without
//! `--pass` / `--to` is refused (nothing written); with `--pass` the names are hidden
//! like any other locked folder pack; visible names need the explicit
//! `--ward-names-visible` opt-in, which warns. Old ward-only (v1) packs still open.
mod common;
use std::path::Path;
use std::process::{Command, Output};

fn sigil(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(common::pass_via_file(args))
        .output()
        .expect("run sigil")
}

fn ok(o: &Output) -> String {
    assert!(
        o.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn scratch(tag: &str) -> common::Scratch {
    let d = common::scratch(&format!("cli-wardnames-{tag}"));
    std::fs::create_dir_all(d.join("album/private-sub")).unwrap();
    std::fs::write(d.join("album/visible-name-a.txt"), b"alpha alpha").unwrap();
    std::fs::write(
        d.join("album/private-sub/tax-return-2025.pdf"),
        b"pretend pdf bytes 0123456789",
    )
    .unwrap();
    d
}

fn contains(hay: &[u8], needle: &[u8]) -> bool {
    hay.windows(needle.len()).any(|w| w == needle)
}

const WARD: &str = "private-sub/tax-return-2025.pdf=room-key";

#[test]
fn ward_only_folder_seal_is_refused_and_writes_nothing() {
    let d = scratch("refuse");
    let o = sigil(&d, &["seal", "--ward", WARD, "-o", "w.sg1", "album"]);
    assert!(!o.status.success(), "ward-only seal must be refused");
    let e = err(&o);
    assert!(
        e.contains("--pass") && e.contains("--ward-names-visible"),
        "{e}"
    );
    assert!(!d.join("w.sg1").exists(), "refused seal left a file behind");
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn ward_with_pass_hides_names_and_fails_closed() {
    let d = scratch("pass");
    ok(&sigil(
        &d,
        &[
            "seal", "--pass", "house", "--ward", WARD, "-o", "e.sg1", "album",
        ],
    ));
    let raw = std::fs::read(d.join("e.sg1")).unwrap();
    assert_eq!(&raw[0..5], b"SGDR\x02");
    for name in [&b"tax-return-2025"[..], b"visible-name-a", b"private-sub"] {
        assert!(!contains(&raw, name), "name fragment leaked in the clear");
    }
    let s = ok(&sigil(&d, &["scry", "e.sg1"]));
    assert!(
        s.contains("names hidden") && !s.contains("tax-return"),
        "{s}"
    );

    // Round trip: house key + ward.
    ok(&sigil(
        &d,
        &[
            "unseal", "--pass", "house", "--ward", WARD, "-o", "all", "e.sg1",
        ],
    ));
    assert_eq!(
        std::fs::read(d.join("all/private-sub/tax-return-2025.pdf")).unwrap(),
        b"pretend pdf bytes 0123456789"
    );
    assert_eq!(
        std::fs::read(d.join("all/visible-name-a.txt")).unwrap(),
        b"alpha alpha"
    );

    let refused = |args: &[&str], out: &str, what: &str| {
        let o = sigil(&d, args);
        assert!(!o.status.success(), "{what}: must fail");
        assert!(!d.join(out).exists(), "{what}: left output behind");
    };
    // The ward alone does not open the directory; the house key alone does not open the warded file.
    refused(
        &["unseal", "--ward", WARD, "-o", "w1", "e.sg1"],
        "w1",
        "ward only",
    );
    refused(
        &["unseal", "--pass", "house", "-o", "w2", "e.sg1"],
        "w2",
        "no ward",
    );
    refused(
        &[
            "unseal",
            "--pass",
            "house",
            "--ward",
            "private-sub/tax-return-2025.pdf=wrong",
            "-o",
            "w3",
            "e.sg1",
        ],
        "w3",
        "wrong ward",
    );
    // Truncation.
    std::fs::write(d.join("trunc.sg1"), &raw[..raw.len() - 9]).unwrap();
    refused(
        &[
            "unseal",
            "--pass",
            "house",
            "--ward",
            WARD,
            "-o",
            "t",
            "trunc.sg1",
        ],
        "t",
        "truncated",
    );
    // Outer member count flipped: inner pack no longer matches.
    let mut bad = raw.clone();
    bad[5] ^= 0x01;
    std::fs::write(d.join("count.sg1"), &bad).unwrap();
    refused(
        &[
            "unseal",
            "--pass",
            "house",
            "--ward",
            WARD,
            "-o",
            "c",
            "count.sg1",
        ],
        "c",
        "count flip",
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn ward_names_visible_is_an_explicit_opt_in_with_a_warning() {
    let d = scratch("optin");
    let o = sigil(
        &d,
        &[
            "seal",
            "--ward",
            WARD,
            "--ward-names-visible",
            "-o",
            "v.sg1",
            "album",
        ],
    );
    ok(&o);
    assert!(
        err(&o).contains("WARNING: --ward-names-visible"),
        "{}",
        err(&o)
    );
    let raw = std::fs::read(d.join("v.sg1")).unwrap();
    // Same v1 layout as ward-only packs written before this change.
    assert_eq!(&raw[0..5], b"SGDR\x01");
    assert!(contains(&raw, b"tax-return-2025"));
    // The warded file's contents stay locked.
    assert!(!contains(&raw, b"pretend pdf bytes"));
    ok(&sigil(&d, &["unseal", "--ward", WARD, "-o", "o", "v.sg1"]));
    assert_eq!(
        std::fs::read(d.join("o/private-sub/tax-return-2025.pdf")).unwrap(),
        b"pretend pdf bytes 0123456789"
    );
    let o = sigil(&d, &["unseal", "-o", "nokey", "v.sg1"]);
    assert!(!o.status.success() && !d.join("nokey").exists());

    // Meaningless with --pass / --to or without --ward: refused rather than ignored.
    for args in [
        vec![
            "seal",
            "--pass",
            "house",
            "--ward",
            WARD,
            "--ward-names-visible",
            "-o",
            "x1.sg1",
            "album",
        ],
        vec!["seal", "--ward-names-visible", "-o", "x2.sg1", "album"],
    ] {
        let o = sigil(&d, &args);
        assert!(!o.status.success(), "{args:?} must be refused");
        assert!(
            !d.join(args[args.len() - 2]).exists(),
            "{args:?} wrote output"
        );
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn ward_only_folder_vault_is_refused_before_tracking() {
    let d = scratch("vault");
    let o = sigil(&d, &["vault", "track", "album", "--ward", WARD]);
    assert!(!o.status.success(), "ward-only vault must be refused");
    let e = err(&o);
    assert!(
        e.contains("--pass") && !e.contains("--ward-names-visible"),
        "{e}"
    );
    let left: Vec<_> = std::fs::read_dir(&d)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .collect();
    assert_eq!(left, vec!["album".to_string()], "vault left {left:?}");
    ok(&sigil(
        &d,
        &["vault", "track", "album", "--pass", "house", "--ward", WARD],
    ));
    let _ = std::fs::remove_dir_all(&d);
}
