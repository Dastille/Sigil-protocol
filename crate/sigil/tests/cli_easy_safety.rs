//! scry/verify say "NOT recoverable" and exit nonzero when live < need; an empty
//! passphrase is refused everywhere; `--version`; `--pass -` never reads a
//! passphrase from anywhere but a terminal.
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn sigil(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run sigil")
}

fn out(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

fn ok(dir: &Path, args: &[&str]) -> String {
    let o = sigil(dir, args);
    assert!(o.status.success(), "{args:?}: {}{}", out(&o), err(&o));
    out(&o)
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sigil-cli-easy-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("album/sub")).unwrap();
    std::fs::write(d.join("album/a.txt"), b"alpha").unwrap();
    std::fs::write(d.join("album/sub/b.txt"), b"beta").unwrap();
    d
}

fn noise(n: usize) -> Vec<u8> {
    let mut x = 0x2545f4914f6cdd1du64;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// Zero `[from..to)` (fractions of the length) of a file.
fn wreck(p: &Path, from: f64, to: f64) {
    let mut b = std::fs::read(p).unwrap();
    let (a, z) = (
        (b.len() as f64 * from) as usize,
        (b.len() as f64 * to) as usize,
    );
    b[a..z].fill(0);
    std::fs::write(p, b).unwrap();
}

fn assert_not_recoverable(d: &Path, file: &str) {
    for cmd in ["scry", "verify"] {
        let o = sigil(d, &[cmd, file]);
        assert!(
            !o.status.success(),
            "{cmd} {file} must exit nonzero: {}",
            out(&o)
        );
        assert_eq!(o.status.code(), Some(2), "{cmd}: {}", err(&o));
        assert!(out(&o).contains("NOT recoverable"), "{cmd}: {}", out(&o));
        assert!(!out(&o).starts_with("ok"), "{cmd}: {}", out(&o));
        assert!(err(&o).contains("NOT recoverable"), "{cmd}: {}", err(&o));
    }
}

#[test]
fn scry_and_verify_report_not_recoverable() {
    let d = scratch("dead");
    std::fs::write(d.join("photo.jpg"), noise(300_000)).unwrap();
    ok(&d, &["seal", "-o", "photo.sg1", "photo.jpg"]);
    let good = ok(&d, &["scry", "photo.sg1"]);
    assert!(good.starts_with("ok  "), "{good}");
    // Torn but repairable: still ok, exit 0.
    std::fs::copy(d.join("photo.sg1"), d.join("torn.sg1")).unwrap();
    wreck(&d.join("torn.sg1"), 0.50, 0.55);
    let torn = ok(&d, &["scry", "torn.sg1"]);
    assert!(
        torn.starts_with("ok  ") && !torn.contains("live=16/16"),
        "{torn}"
    );
    // Past repair: NOT recoverable, exit 2.
    std::fs::copy(d.join("photo.sg1"), d.join("dead.sg1")).unwrap();
    wreck(&d.join("dead.sg1"), 0.30, 0.90);
    assert_not_recoverable(&d, "dead.sg1");
    let o = sigil(&d, &["unseal", "-o", "out.jpg", "dead.sg1"]);
    assert!(!o.status.success() && !d.join("out.jpg").exists());

    // Large-file pack: one chunk part past repair.
    std::fs::write(d.join("big.bin"), noise(6_000_000)).unwrap();
    ok(&d, &["seal", "-o", "big.sg1", "big.bin"]);
    assert!(ok(&d, &["scry", "big.sg1"]).starts_with("work"));
    wreck(&d.join("big.sg1"), 0.10, 0.45);
    assert_not_recoverable(&d, "big.sg1");

    // Folder packs: plain (member past repair) and encrypted (body past repair).
    ok(&d, &["seal", "-o", "p.sg1", "album"]);
    wreck(&d.join("p.sg1"), 0.20, 0.95);
    let o = sigil(&d, &["scry", "p.sg1"]);
    assert!(!o.status.success(), "{}", out(&o));
    ok(&d, &["seal", "--pass", "pw", "-o", "e.sg1", "album"]);
    wreck(&d.join("e.sg1"), 0.20, 0.95);
    let o = sigil(&d, &["scry", "e.sg1"]);
    assert!(!o.status.success(), "{}", out(&o));
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn empty_passphrase_is_refused_everywhere() {
    let d = scratch("empty");
    std::fs::write(d.join("f.txt"), b"hello").unwrap();
    ok(&d, &["seal", "--pass", "pw", "-o", "enc.sg1", "f.txt"]);
    let cases: Vec<(Vec<&str>, Option<&str>)> = vec![
        (
            vec!["seal", "--pass", "", "-o", "x.sg1", "f.txt"],
            Some("x.sg1"),
        ),
        (
            vec!["seal", "--pass", "", "-o", "xd.sg1", "album"],
            Some("xd.sg1"),
        ),
        (
            vec!["seal", "--pass=", "-o", "x2.sg1", "f.txt"],
            Some("x2.sg1"),
        ),
        (
            vec!["unseal", "--pass", "", "-o", "y.txt", "enc.sg1"],
            Some("y.txt"),
        ),
        (vec!["scry", "--pass", "", "enc.sg1"], None),
        (vec!["log", "init", "lg", "--pass", ""], Some("lg.sigil")),
        (vec!["vault", "track", "album", "--pass", ""], None),
        (
            vec!["seal", "--ward", "a.txt=", "-o", "w.sg1", "album"],
            Some("w.sg1"),
        ),
    ];
    for (args, made) in cases {
        let o = sigil(&d, &args);
        assert!(!o.status.success(), "{args:?} must be refused");
        assert!(
            err(&o).contains("empty passphrase"),
            "{args:?}: {}",
            err(&o)
        );
        if let Some(m) = made {
            assert!(!d.join(m).exists(), "{args:?} wrote {m}");
        }
    }
    // Library: an empty passphrase never silently writes a plain mark.
    assert!(sigil::seal(b"x", sigil::Mode::Seal, Some(""), "x", false).is_err());
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn version_flag() {
    let d = scratch("ver");
    let v = ok(&d, &["--version"]);
    assert!(v.starts_with("sigil "), "{v}");
    assert!(v.contains(env!("CARGO_PKG_VERSION")), "{v}");
    // ... plus the git commit the build came from, or "unknown" (never a build failure).
    let line = v.trim_end();
    let tail = line
        .strip_prefix(&format!("sigil {} (commit ", env!("CARGO_PKG_VERSION")))
        .and_then(|t| t.strip_suffix(')'))
        .unwrap_or_else(|| panic!("{v}"));
    let sha = tail.strip_suffix("-dirty").unwrap_or(tail);
    assert!(
        sha == "unknown" || (sha.len() >= 7 && sha.bytes().all(|b| b.is_ascii_hexdigit())),
        "{v}"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn pass_dash_needs_a_terminal_and_never_reads_stdin() {
    let d = scratch("dash");
    std::fs::write(d.join("f.txt"), b"hello").unwrap();
    // stdin piped (not a terminal): refused, nothing written, piped text not used.
    let mut child = Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(&d)
        .args(["seal", "--pass", "-", "-o", "x.sg1", "f.txt"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .env_remove("TERM")
        .spawn()
        .unwrap();
    {
        use std::io::Write;
        let mut si = child.stdin.take().unwrap();
        let _ = si.write_all(b"piped-secret\n");
    }
    let o = child.wait_with_output().unwrap();
    if o.status.success() {
        // A controlling terminal was available to the test runner: the prompt read
        // from it, not from stdin. Make sure the piped text was not the passphrase.
        let r = sigil(
            &d,
            &["unseal", "--pass", "piped-secret", "-o", "y.txt", "x.sg1"],
        );
        assert!(
            !r.status.success(),
            "stdin must never be read as the passphrase"
        );
    } else {
        assert!(err(&o).contains("terminal"), "{}", err(&o));
        assert!(!d.join("x.sg1").exists());
    }
    // Unseal of an encrypted file with no key and no terminal: the old clear error.
    ok(&d, &["seal", "--pass", "pw", "-o", "enc.sg1", "f.txt"]);
    let o = sigil(&d, &["unseal", "-o", "z.txt", "enc.sg1"]);
    assert!(!o.status.success());
    assert!(
        err(&o).contains("passphrase or --identity required"),
        "{}",
        err(&o)
    );
    let _ = std::fs::remove_dir_all(&d);
}
