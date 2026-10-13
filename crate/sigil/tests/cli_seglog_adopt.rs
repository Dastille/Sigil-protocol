//! `sigil log adopt`: tidy a loose pile of .sg1 stars into a segment log, byte-for-byte.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn sigil_cmd(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .env_remove("SIGIL_SOFT_AUTHENTICATOR")
        .args(args)
        .output()
        .expect("run sigil")
}

fn text(o: &Output) -> String {
    format!("{}{}", String::from_utf8_lossy(&o.stdout), String::from_utf8_lossy(&o.stderr))
}

fn ok(dir: &Path, args: &[&str]) -> String {
    let o = sigil_cmd(dir, args);
    assert!(o.status.success(), "{args:?}: {}", text(&o));
    text(&o)
}

fn fails(dir: &Path, args: &[&str]) -> String {
    let o = sigil_cmd(dir, args);
    assert!(!o.status.success(), "expected failure {args:?}: {}", text(&o));
    text(&o)
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sigil-log-adopt-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

/// Seal `body` as `pile/<name>` (extra args go to `sigil seal`).
fn star(d: &Path, name: &str, body: &str, extra: &[&str]) -> PathBuf {
    fs::create_dir_all(d.join("pile")).unwrap();
    fs::write(d.join("plain.tmp"), body).unwrap();
    let out = d.join("pile").join(name);
    let mut args = vec!["seal", "plain.tmp", "-o", out.to_str().unwrap()];
    args.extend_from_slice(extra);
    ok(d, &args);
    fs::remove_file(d.join("plain.tmp")).unwrap();
    out
}

fn index(d: &Path) -> String {
    fs::read_to_string(d.join("ev.sigil/INDEX")).unwrap()
}

#[test]
fn folder_adopted_in_natural_order_and_originals_removed() {
    let d = tmp("basic");
    let s10 = star(&d, "day-10.sg1", "ten\n", &[]);
    let s2 = star(&d, "day-2.sg1", "two\n", &[]);
    let s1 = star(&d, "day-1.sg1", "one\n", &["--mode", "seal"]);
    fs::write(d.join("pile/notes.txt"), "not a star").unwrap();
    let src_bytes = fs::read(&s2).unwrap();
    ok(&d, &["log", "init", "ev"]);

    // dry run changes nothing
    let plan = ok(&d, &["log", "adopt", "ev", "pile", "--dry-run"]);
    assert!(plan.contains("would adopt 3") && plan.contains("1 non-star file(s) ignored"), "{plan}");
    assert_eq!(index(&d).lines().count(), 1, "dry run wrote INDEX");
    assert!(s1.exists() && s2.exists() && s10.exists());

    let out = ok(&d, &["log", "adopt", "ev", "pile"]);
    assert!(out.contains("adopted 3") && out.contains("removed 3 original(s)"), "{out}");
    assert!(!s1.exists() && !s2.exists() && !s10.exists());
    assert!(d.join("pile/notes.txt").exists(), "non-star file must be left alone");

    // natural order: day-1, day-2, day-10
    let o = sigil_cmd(&d, &["log", "read", "ev"]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(o.stdout, b"one\ntwo\nten\n");
    // byte-for-byte: segment 2 is exactly the old file
    assert_eq!(fs::read(d.join("ev.sigil/segments/0000/0000000002.sg1")).unwrap(), src_bytes);
    // plain log=1 lines (plus the additive src= key); manifest not raised
    assert!(index(&d).lines().nth(1).unwrap().contains(" src="));
    assert!(fs::read_to_string(d.join("ev.sigil/CONTAINER")).unwrap().contains("log=1"));
    let v = ok(&d, &["log", "verify", "ev"]);
    assert!(!v.contains("ERROR"), "{v}");
    // a normal append continues after the adopted ones
    fs::write(d.join("b.txt"), "four\n").unwrap();
    let a = ok(&d, &["log", "append", "ev", "b.txt"]);
    assert!(a.contains("segment 4"), "{a}");
}

#[test]
fn locked_stars_adopted_without_any_key() {
    let d = tmp("locked");
    ok(&d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    star(&d, "a.sg1", "secret a\n", &["--pass", "hunter2"]);
    star(&d, "b.sg1", "secret b\n", &["--to", "me.pub"]);
    ok(&d, &["log", "init", "ev"]);
    let out = ok(&d, &["log", "adopt", "ev", "pile/a.sg1", "pile/b.sg1"]);
    assert!(out.contains("locked") && out.contains("adopted 2"), "{out}");
    // each opens with its own key
    let o = sigil_cmd(&d, &["log", "read", "ev", "--seq", "1", "--pass", "hunter2"]);
    assert_eq!(o.stdout, b"secret a\n", "{}", text(&o));
    let o = sigil_cmd(&d, &["log", "read", "ev", "--seq", "2", "--identity", "me.sgk"]);
    assert_eq!(o.stdout, b"secret b\n", "{}", text(&o));
    // keyless verify is clean
    let v = ok(&d, &["log", "verify", "ev"]);
    assert!(!v.contains("ERROR"), "{v}");
}

#[test]
fn rerun_is_idempotent() {
    let d = tmp("idem");
    star(&d, "a.sg1", "a\n", &[]);
    star(&d, "b.sg1", "b\n", &[]);
    ok(&d, &["log", "init", "ev"]);
    ok(&d, &["log", "adopt", "ev", "pile", "--keep"]);
    assert!(d.join("pile/a.sg1").exists());
    let lines = index(&d).lines().count();
    // second run: nothing appended, originals now cleaned up
    let out = ok(&d, &["log", "adopt", "ev", "pile"]);
    assert!(out.contains("adopted 0") && out.contains("2 already in the log") && out.contains("removed 2"), "{out}");
    assert_eq!(index(&d).lines().count(), lines);
    assert!(!d.join("pile/a.sg1").exists());
    // the same file named twice is one source
    let c = star(&d, "c.sg1", "c\n", &[]);
    let cs = c.to_str().unwrap();
    let out = ok(&d, &["log", "adopt", "ev", cs, cs]);
    assert!(out.contains("adopted 1"), "{out}");
}

#[test]
fn bad_stars_left_in_place() {
    let d = tmp("bad");
    star(&d, "good.sg1", "good\n", &[]);
    fs::write(d.join("pile/junk.sg1"), b"this is not a star at all").unwrap();
    ok(&d, &["log", "init", "ev"]);
    let o = sigil_cmd(&d, &["log", "adopt", "ev", "pile"]);
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    let t = text(&o);
    assert!(t.contains("adopted 1") && t.contains("junk.sg1") && t.contains("left in place"), "{t}");
    assert!(d.join("pile/junk.sg1").exists());
    assert!(!d.join("pile/good.sg1").exists());
}

#[test]
fn tombstoned_bytes_not_readopted() {
    let d = tmp("tomb");
    star(&d, "a.sg1", "a\n", &[]);
    ok(&d, &["log", "init", "ev"]);
    ok(&d, &["log", "adopt", "ev", "pile", "--keep"]);
    ok(&d, &["log", "tombstone", "ev", "--seq", "1"]);
    let o = sigil_cmd(&d, &["log", "adopt", "ev", "pile"]);
    let t = text(&o);
    assert_eq!(o.status.code(), Some(1), "{t}");
    assert!(t.contains("deleted by entry 2"), "{t}");
    assert!(d.join("pile/a.sg1").exists(), "user's copy of deleted data must stay");
}

#[test]
fn signed_and_segment_key_logs() {
    let d = tmp("gates");
    ok(&d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    star(&d, "a.sg1", "a\n", &[]);
    ok(&d, &["log", "init", "signed", "--identity", "me.sgk"]);
    let e = fails(&d, &["log", "adopt", "signed", "pile", "--keep"]);
    assert!(e.contains("--identity"), "{e}");
    let out = ok(&d, &["log", "adopt", "signed", "pile", "--keep", "--identity", "me.sgk"]);
    assert!(out.contains("(signed)"), "{out}");
    ok(&d, &["log", "init", "keyed", "--segment-keys"]);
    let e = fails(&d, &["log", "adopt", "keyed", "pile"]);
    assert!(e.contains("per-segment keys"), "{e}");
    assert!(d.join("pile/a.sg1").exists());
    // a container is not a pile
    ok(&d, &["log", "init", "plain"]);
    let e = fails(&d, &["log", "adopt", "plain", "keyed.sigil"]);
    assert!(e.contains("already a sigil container"), "{e}");
}
