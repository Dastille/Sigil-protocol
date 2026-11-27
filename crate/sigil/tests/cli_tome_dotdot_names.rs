//! Names that merely contain `..` (`a..b.txt`, `x..y/z..w`) are ordinary names: they pack
//! into a Tome and come back out. A real `..` part, an absolute path or an empty part is
//! still refused, on every way out of a Tome, and a refused Tome writes nothing outside
//! the output folder.
mod common;
use std::fs;
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
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn fails(dir: &Path, args: &[&str]) -> String {
    let o = sigil(dir, args);
    assert!(
        !o.status.success(),
        "{args:?} should fail\nstdout: {}\nstderr: {}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stderr).into_owned()
}

const FILES: &[(&str, &[u8])] = &[
    ("a..b.txt", b"two dots inside a name"),
    ("x..y/z..w", b"two dots in a folder and a file name"),
    ("...", b"three dots"),
    ("..hidden", b"leading dots"),
    ("plain.txt", b"plain"),
];

fn tree(src: &Path) {
    for (rel, body) in FILES {
        let p = src.join(rel);
        fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
        fs::write(p, body).expect("write");
    }
}

fn same(out: &Path) {
    for (rel, body) in FILES {
        assert_eq!(
            fs::read(out.join(rel)).ok().as_deref(),
            Some(*body),
            "{rel} in {}",
            out.display()
        );
    }
}

#[test]
fn dotdot_inside_names_round_trips_every_layout_and_way_out() {
    let d = common::scratch("dotdot-names");
    tree(&d.join("src"));
    // `..hidden` and `...` are dotfiles: pack them on request.
    for (tome, extra) in [
        ("p.sg1", None),
        ("v1.sg1", Some("--old-tome-layout")),
        ("nd.sg1", Some("--no-file-details")),
    ] {
        let mut args = vec!["seal", "--dotfiles", "-o", tome, "src"];
        if let Some(e) = extra {
            args.insert(1, e);
        }
        ok(&d, &args);
        let out = format!("out-{tome}");
        ok(&d, &["unseal", tome, "-o", &out]);
        same(&d.join(&out));
        let exp = format!("exp-{tome}");
        ok(&d, &["mount", tome, "mnt", "--export-dir", &exp]);
        same(&d.join(&exp));
        let sal = format!("sal-{tome}");
        ok(&d, &["unseal", "--salvage", tome, "-o", &sal]);
        same(&d.join(&sal));
    }
    // A Warded Tome.
    fs::write(d.join("pw"), b"correct horse battery\n").expect("pw");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join("pw"), fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    ok(
        &d,
        &[
            "seal",
            "--dotfiles",
            "--pass-file",
            "pw",
            "-o",
            "w.sg1",
            "src",
        ],
    );
    ok(&d, &["unseal", "w.sg1", "--pass-file", "pw", "-o", "out-w"]);
    same(&d.join("out-w"));
    // One member by name.
    ok(&d, &["unseal", "p.sg1", "-o", "one", "--only", "x..y/z..w"]);
    assert!(d.join("one/x..y/z..w").is_file());
}

#[test]
fn dotdot_inside_names_in_a_constellation() {
    let d = common::scratch("dotdot-sky");
    fs::create_dir_all(d.join("in/x..y")).expect("mkdir");
    fs::write(d.join("in/a..b.txt"), b"alpha").expect("write");
    fs::write(d.join("in/x..y/z..w"), b"zulu").expect("write");
    ok(
        &d,
        &["constellation", "add", "Sky", "in", "--mode", "glyph"],
    );
    ok(&d, &["mount", "Sky.sigil", "mnt", "--export-dir", "out"]);
    assert_eq!(fs::read(d.join("out/a..b.txt")).expect("a..b"), b"alpha");
    assert_eq!(fs::read(d.join("out/x..y/z..w")).expect("z..w"), b"zulu");
}

/// Replace the first `from` in `bytes` with `to` (same length).
fn patch_first(bytes: &mut [u8], from: &[u8], to: &[u8]) {
    assert_eq!(from.len(), to.len());
    let at = bytes
        .windows(from.len())
        .position(|w| w == from)
        .expect("name in the Tome");
    bytes[at..at + to.len()].copy_from_slice(to);
}

/// Everything under `root`, as `/`-joined names (bounded: test trees are tiny).
fn listing(root: &Path) -> Vec<String> {
    let mut out = Vec::new();
    let mut todo = vec![root.to_path_buf()];
    while let Some(dir) = todo.pop() {
        let Ok(rd) = fs::read_dir(&dir) else { continue };
        for e in rd.flatten() {
            let p = e.path();
            out.push(
                p.strip_prefix(root)
                    .expect("under root")
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
            if p.is_dir() {
                todo.push(p);
            }
        }
    }
    out.sort();
    out
}

#[test]
fn a_tampered_tome_with_a_dotdot_part_is_refused_and_writes_nothing_outside() {
    // The plain older layout keeps member names in the clear: rewrite one same-length
    // name on disk into an escape (both sort before `keep.txt`, so the list order holds).
    // A member header keeps only the first 16 bytes of its name: with the same first 16
    // bytes the list check reaches the path check itself (`true`); otherwise the header
    // comparison may refuse first, and either refusal must write nothing.
    for (on_disk, evil, path_check) in [
        (
            "aaaaaaaaaaaaaaaa/qq/qq/escape.txt",
            "aaaaaaaaaaaaaaaa/../../escape.txt",
            true,
        ),
        (
            "aaaaaaaaaaaaaaaa/qq/escape.txt",
            "aaaaaaaaaaaaaaaa/../escape.txt",
            true,
        ),
        (
            "aaaaaaaaaaaaaaaa/q/escape.txt",
            "aaaaaaaaaaaaaaaa/./escape.txt",
            true,
        ),
        ("aa/escape.txt", "../escape.txt", false),
        ("aaaa/escape.txt", "/tmp/escape.txt", false),
        ("aa/b/escape.txt", "aa///escape.txt", false),
    ] {
        let d = common::scratch("dotdot-tamper");
        let base = d.join("work");
        let src = base.join("src");
        fs::create_dir_all(src.join(on_disk).parent().expect("parent")).expect("mkdir");
        fs::write(src.join(on_disk), b"evil").expect("write");
        fs::write(src.join("keep.txt"), b"fine").expect("write");
        ok(&base, &["seal", "--old-tome-layout", "-o", "t.sg1", "src"]);
        let mut bytes = fs::read(base.join("t.sg1")).expect("read");
        patch_first(&mut bytes, on_disk.as_bytes(), evil.as_bytes());
        fs::write(base.join("t.sg1"), &bytes).expect("write");
        let before = listing(&d);
        let e = fails(&base, &["unseal", "t.sg1", "-o", "out"]);
        if path_check {
            assert!(e.contains("refusing unsafe path in Tome"), "{evil}: {e}");
        }
        let e = fails(&base, &["mount", "t.sg1", "mnt", "--export-dir", "exp"]);
        if path_check {
            assert!(e.contains("unsafe path"), "{evil}: {e}");
        }
        // Salvage never trusts the name: whatever it saves stays inside its folder.
        let _ = sigil(&base, &["unseal", "--salvage", "t.sg1", "-o", "sal"]);
        let after: Vec<String> = listing(&d)
            .into_iter()
            .filter(|p| {
                !(p.starts_with("work/sal")
                    || p.starts_with("work/out")
                    || p.starts_with("work/exp"))
            })
            .collect();
        assert_eq!(before, after, "{evil}: something was written outside");
        assert!(!d.join("escape.txt").exists());
        assert!(!base.join("escape.txt").exists());
        // Nothing but the output folders may have appeared, and nothing named escape.txt
        // outside the salvage folder.
        for p in listing(&base) {
            if p.ends_with("escape.txt") {
                assert!(
                    p.starts_with("sal/") || p.starts_with("src/"),
                    "{evil}: {p}"
                );
            }
        }
    }
}

#[test]
fn dotdot_inside_names_in_a_vault_folder() {
    let d = common::scratch("dotdot-vault");
    fs::create_dir_all(d.join("live/x..y")).expect("mkdir");
    fs::write(d.join("live/a..b.txt"), b"one").expect("write");
    fs::write(d.join("live/x..y/z..w"), b"zulu").expect("write");
    ok(&d, &["vault", "track", "live"]);
    fs::write(d.join("live/a..b.txt"), b"two").expect("write");
    ok(&d, &["vault", "commit", "live"]);
    ok(&d, &["vault", "restore", "--version", "1", "live"]);
    assert_eq!(fs::read(d.join("live/a..b.txt")).expect("r"), b"one");
    assert_eq!(fs::read(d.join("live/x..y/z..w")).expect("r"), b"zulu");
    ok(
        &d,
        &["mount", "live", "mnt", "--vault", "--export-dir", "exp"],
    );
    assert_eq!(fs::read(d.join("exp/a..b.txt")).expect("r"), b"two");
}

/// A name that is a real `..` part once `\` is read as a separator never goes into a
/// Tome: Inscribe refuses before writing anything.
#[cfg(unix)]
#[test]
fn inscribe_refuses_a_name_it_could_not_restore() {
    let d = common::scratch("dotdot-pack");
    fs::create_dir_all(d.join("src")).expect("mkdir");
    fs::write(d.join("src/ok.txt"), b"fine").expect("write");
    fs::write(d.join("src/x\\..\\y"), b"tricky").expect("write");
    for extra in [None, Some("--old-tome-layout")] {
        let mut args = vec!["seal", "-o", "t.sg1", "src"];
        if let Some(e) = extra {
            args.insert(1, e);
        }
        let e = fails(&d, &args);
        assert!(e.contains("cannot be restored safely"), "{e}");
        assert!(!d.join("t.sg1").exists());
    }
}
