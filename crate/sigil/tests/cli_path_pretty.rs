//! `sigil path --pretty`: framed inspect card; plain output unchanged without the flag.
mod common;
use std::path::Path;
use std::process::{Command, Stdio};

fn sigil(dir: &Path, args: &[&str]) -> String {
    let o = Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(common::pass_via_file(args))
        .env_remove("CLICOLOR_FORCE")
        .env_remove("SIGIL_ASCII")
        .stdin(Stdio::null())
        .output()
        .expect("run sigil");
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout).expect("utf8")
}

#[test]
fn path_pretty_folder_and_mark() {
    let d = common::scratch("pretty");
    std::fs::create_dir_all(d.join("album/notes")).expect("mkdir");
    std::fs::write(d.join("album/notes/todo.txt"), b"hello").expect("w");
    std::fs::write(d.join("album/readme.txt"), b"readme").expect("w");
    std::fs::write(d.join("one.txt"), b"hi").expect("w");
    sigil(&d, &["seal", "album", "-o", "album.sg1"]);
    sigil(&d, &["seal", "one.txt", "-o", "one.sg1"]);

    let plain = sigil(&d, &["path", "album.sg1"]);
    assert!(
        plain.starts_with("trail  album.sg1\nkind   folder\n"),
        "{plain}"
    );
    assert!(plain.contains("file  notes/todo.txt  5 bytes"), "{plain}");

    let pretty = sigil(&d, &["path", "album.sg1", "--pretty"]);
    assert!(pretty.starts_with("  album.sg1\n"), "{pretty}");
    assert!(pretty.contains("  KIND      folder pack"), "{pretty}");
    assert!(
        pretty.contains("  STATUS    healthy · 2 files checked"),
        "{pretty}"
    );
    assert!(pretty.contains("\n  notes/\n    todo.txt"), "{pretty}");
    assert!(pretty.contains("  SHA-256   "), "{pretty}");
    assert!(
        !pretty.contains('\x1b'),
        "piped output must not carry color"
    );

    let mark = sigil(&d, &["ls", "one.sg1", "--pretty"]);
    assert!(mark.contains("  KIND      sealed file"), "{mark}");
    assert!(mark.contains("  NAME      one.txt"), "{mark}");
    assert!(mark.contains("  STATUS    healthy"), "{mark}");
    assert!(mark.contains("  REPAIR    "), "{mark}");
    let _ = std::fs::remove_dir_all(&d);
}

fn run(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(common::pass_via_file(args))
        .env_remove("CLICOLOR_FORCE")
        .env_remove("SIGIL_ASCII")
        .stdin(Stdio::null())
        .output()
        .expect("run sigil")
}

fn noise(n: usize, mut x: u64) -> Vec<u8> {
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn status_line(s: &str) -> &str {
    s.lines()
        .find(|l| l.trim_start().starts_with("STATUS"))
        .unwrap_or_else(|| panic!("no STATUS: {s}"))
}

/// The card's condition agrees with `scry --json`'s status: healthy, needs repair,
/// not recoverable; large-file packs and items inside a pack get one too.
#[test]
fn path_pretty_condition_agrees_with_status() {
    let d = common::scratch("pretty-status");
    std::fs::write(d.join("photo.jpg"), noise(300_000, 5)).expect("w");
    sigil(&d, &["seal", "photo.jpg", "-o", "photo.sg1"]);
    assert!(status_line(&sigil(&d, &["path", "photo.sg1", "--pretty"])).contains("healthy"));

    let mut b = std::fs::read(d.join("photo.sg1")).expect("r");
    let (a, z) = (b.len() / 2, b.len() * 55 / 100);
    b[a..z].fill(0);
    std::fs::write(d.join("torn.sg1"), &b).expect("w");
    let j = sigil(&d, &["scry", "torn.sg1", "--json"]);
    assert!(j.contains("\"health\":\"needs-repair\""), "{j}");
    let p = sigil(&d, &["path", "torn.sg1", "--pretty"]);
    assert!(status_line(&p).contains("needs repair"), "{p}");
    assert!(p.contains("sigil mend"), "{p}");

    let mut b = std::fs::read(d.join("photo.sg1")).expect("r");
    let (a, z) = (b.len() * 30 / 100, b.len() * 90 / 100);
    b[a..z].fill(0);
    std::fs::write(d.join("dead.sg1"), &b).expect("w");
    let t = sigil(&d, &["path", "dead.sg1", "--pretty"]);
    assert!(status_line(&t).contains("not recoverable"), "{t}");
    assert!(
        !t.contains("healthy") && !t.contains("still restore"),
        "{t}"
    );
    assert!(t.contains("cannot restore from this copy"), "{t}");

    // Large-file pack: had no condition line before.
    std::fs::write(d.join("big.bin"), noise(300_000, 9)).expect("w");
    sigil(
        &d,
        &["seal", "--chunk", "65536", "big.bin", "-o", "big.sg1"],
    );
    let p = sigil(&d, &["path", "big.sg1", "--pretty"]);
    assert!(
        p.contains("large-file pack") && status_line(&p).contains("healthy"),
        "{p}"
    );

    // An item inside a pack: the outer file's condition, said as such.
    std::fs::create_dir_all(d.join("album/notes")).expect("mkdir");
    std::fs::write(d.join("album/notes/todo.txt"), b"hello").expect("w");
    sigil(&d, &["seal", "album", "-o", "album.sg1"]);
    let p = sigil(&d, &["path", "album.sg1", "notes/todo.txt", "--pretty"]);
    assert!(status_line(&p).contains("healthy"), "{p}");
    assert!(p.contains("condition of the whole outer file"), "{p}");
    let top = sigil(&d, &["path", "album.sg1", "--pretty"]);
    assert!(!top.contains("whole outer file"), "{top}");
}

/// No key for an encrypted folder pack: refused, and no condition is claimed.
#[test]
fn path_pretty_key_needed_claims_nothing() {
    let d = common::scratch("pretty-key");
    std::fs::create_dir_all(d.join("album")).expect("mkdir");
    std::fs::write(d.join("album/a.txt"), b"alpha").expect("w");
    sigil(&d, &["seal", "--pass", "pw", "album", "-o", "album.sg1"]);
    let o = run(&d, &["path", "album.sg1", "--pretty"]);
    assert!(!o.status.success());
    let all = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(all.contains("--pass") && !all.contains("healthy"), "{all}");
    let p = sigil(&d, &["path", "album.sg1", "--pass", "pw", "--pretty"]);
    assert!(status_line(&p).contains("healthy"), "{p}");
}
