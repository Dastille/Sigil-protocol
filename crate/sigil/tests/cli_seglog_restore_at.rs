//! `sigil log restore --at TIME / --seq N`: an older version by path and date.
mod common;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

fn run(d: &Path, a: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(d)
        .env_remove("SIGIL_SOFT_AUTHENTICATOR")
        .args(a)
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
fn ok(d: &Path, a: &[&str]) -> String {
    let o = run(d, a);
    assert!(o.status.success(), "{a:?}: {}", text(&o));
    text(&o)
}
fn fails(d: &Path, a: &[&str]) -> String {
    let o = run(d, a);
    assert!(!o.status.success(), "expected failure {a:?}: {}", text(&o));
    text(&o)
}
fn put(d: &Path, rel: &str, body: &str) {
    let p = d.join("photos").join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, body).unwrap();
}
fn now() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs()
}
/// Wait into the next second and return it: everything appended before is strictly earlier.
fn tick() -> u64 {
    let t = now();
    while now() == t {
        std::thread::sleep(Duration::from_millis(50));
    }
    now()
}

#[test]
fn older_versions_by_time_and_seq() {
    let d = common::scratch("restore-at");
    let before = now() - 1;
    ok(&d, &["log", "init", "ev"]);
    put(&d, "a/notes.txt", "v1\n");
    put(&d, "a/gone.txt", "gone\n");
    ok(&d, &["log", "add", "ev", "photos"]); // seq 1 a/gone, 2 a/notes v1
    let t1 = tick();
    put(&d, "a/notes.txt", "v2\n");
    put(&d, "a/new.txt", "new\n");
    ok(&d, &["log", "add", "ev", "photos"]); // seq 3 a/new, 4 a/notes v2
    let at = (t1 - 1).to_string();

    // file as of t1-1: v1; default still latest
    ok(
        &d,
        &[
            "log",
            "restore",
            "ev",
            "a/notes.txt",
            "--at",
            &at,
            "-o",
            "old.txt",
        ],
    );
    assert_eq!(fs::read_to_string(d.join("old.txt")).unwrap(), "v1\n");
    ok(
        &d,
        &["log", "restore", "ev", "a/notes.txt", "-o", "cur.txt"],
    );
    assert_eq!(fs::read_to_string(d.join("cur.txt")).unwrap(), "v2\n");
    // ISO form, as log ls prints
    let ls = ok(&d, &["log", "ls", "ev"]);
    let iso = ls
        .lines()
        .find(|l| l.contains("a/notes.txt"))
        .and_then(|l| l.split_whitespace().nth(1))
        .unwrap()
        .to_string();
    ok(
        &d,
        &[
            "log",
            "restore",
            "ev",
            "a/notes.txt",
            "--at",
            &iso,
            "-o",
            "iso.txt",
        ],
    );
    assert_eq!(fs::read_to_string(d.join("iso.txt")).unwrap(), "v1\n");
    // by seq
    ok(
        &d,
        &[
            "log",
            "restore",
            "ev",
            "a/notes.txt",
            "--seq",
            "2",
            "-o",
            "s2.txt",
        ],
    );
    assert_eq!(fs::read_to_string(d.join("s2.txt")).unwrap(), "v1\n");
    assert!(fails(
        &d,
        &[
            "log",
            "restore",
            "ev",
            "a/notes.txt",
            "--seq",
            "1",
            "-o",
            "x"
        ]
    )
    .contains("not a version of"));
    assert!(
        fails(&d, &["log", "restore", "ev", "a", "--seq", "2", "-o", "x"])
            .contains("not a version of")
    );
    assert!(fails(
        &d,
        &[
            "log",
            "restore",
            "ev",
            "a/notes.txt",
            "--seq",
            "99",
            "-o",
            "x"
        ]
    )
    .contains("not among"));
    assert!(!run(
        &d,
        &[
            "log",
            "restore",
            "ev",
            "a/notes.txt",
            "--seq",
            "2",
            "--at",
            &at,
            "-o",
            "x"
        ]
    )
    .status
    .success());

    // folder as of t1-1: only the first add
    ok(
        &d,
        &["log", "restore", "ev", "a", "--at", &at, "-o", "olddir"],
    );
    assert_eq!(
        fs::read_to_string(d.join("olddir/notes.txt")).unwrap(),
        "v1\n"
    );
    assert!(d.join("olddir/gone.txt").exists() && !d.join("olddir/new.txt").exists());

    // nothing yet at that time / bad time
    let e = fails(
        &d,
        &["log", "restore", "ev", "a/new.txt", "--at", &at, "-o", "x"],
    );
    assert!(e.contains("no version of"), "{e}");
    assert!(fails(
        &d,
        &[
            "log",
            "restore",
            "ev",
            "a",
            "--at",
            &before.to_string(),
            "-o",
            "x"
        ]
    )
    .contains("no version of"));
    assert!(fails(
        &d,
        &[
            "log",
            "restore",
            "ev",
            "a/notes.txt",
            "--at",
            "last tuesday",
            "-o",
            "x"
        ]
    )
    .contains("bad time"));
    assert!(!d.join("x").exists());

    // the version at that time deleted: refused, not swapped for an older one
    ok(&d, &["log", "tombstone", "ev", "--seq", "2"]);
    let e = fails(
        &d,
        &[
            "log",
            "restore",
            "ev",
            "a/notes.txt",
            "--at",
            &at,
            "-o",
            "y",
        ],
    );
    assert!(e.contains("deleted"), "{e}");
    assert!(fails(
        &d,
        &[
            "log",
            "restore",
            "ev",
            "a/notes.txt",
            "--seq",
            "2",
            "-o",
            "y"
        ]
    )
    .contains("deleted"));
    let o = ok(
        &d,
        &["log", "restore", "ev", "a", "--at", &at, "-o", "dir2"],
    );
    assert!(
        o.contains("deleted") && !d.join("dir2/notes.txt").exists(),
        "{o}"
    );
    assert!(!d.join("y").exists());

    // corrupt segment of the chosen version: all-or-nothing
    let target = d.join("ev.sigil/segments/0000/0000000001.sg1");
    let mut b = fs::read(&target).unwrap();
    let n = b.len();
    for x in &mut b[n / 2..] {
        *x ^= 0x5a;
    }
    fs::write(&target, b).unwrap();
    assert!(!run(
        &d,
        &["log", "restore", "ev", "a/gone.txt", "--at", &at, "-o", "z"]
    )
    .status
    .success());
    assert!(!run(
        &d,
        &["log", "restore", "ev", "a", "--at", &at, "-o", "zdir"]
    )
    .status
    .success());
    assert!(!d.join("z").exists() && !d.join("zdir").exists());
}

#[test]
fn private_log_restore_at_needs_key() {
    let d = common::scratch("restore-at-priv");
    fs::write(d.join("pw"), "pw\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join("pw"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    ok(
        &d,
        &["log", "init", "ev", "--private-index", "--pass-file", "pw"],
    );
    put(&d, "s.txt", "one\n");
    ok(&d, &["log", "add", "ev", "photos", "--pass-file", "pw"]);
    let t1 = tick();
    put(&d, "s.txt", "two\n");
    ok(&d, &["log", "add", "ev", "photos", "--pass-file", "pw"]);
    let at = (t1 - 1).to_string();
    assert!(!run(
        &d,
        &["log", "restore", "ev", "s.txt", "--at", &at, "-o", "o"]
    )
    .status
    .success());
    ok(
        &d,
        &[
            "log",
            "restore",
            "ev",
            "s.txt",
            "--at",
            &at,
            "-o",
            "o",
            "--pass-file",
            "pw",
        ],
    );
    assert_eq!(fs::read_to_string(d.join("o")).unwrap(), "one\n");
}
