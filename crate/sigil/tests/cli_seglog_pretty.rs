//! `sigil log ls --pretty` / `sigil path LOG --pretty`: the archivist page for a segment log
//! (identity, condition, extent, inventory, root), and `sigil log read --name`.
mod common;
use std::fs;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn run_env(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sigil"));
    c.current_dir(dir)
        .args(common::pass_via_file(args))
        .env_remove("CLICOLOR_FORCE")
        .env_remove("NO_COLOR")
        .env_remove("SIGIL_ASCII")
        .env_remove("SIGIL_SOFT_AUTHENTICATOR")
        .stdin(Stdio::null());
    for (k, v) in env {
        c.env(k, v);
    }
    c.output().expect("run sigil")
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn ok(dir: &Path, args: &[&str]) -> String {
    let o = run_env(dir, args, &[]);
    assert!(o.status.success(), "{args:?}: {}", text(&o));
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn fails(dir: &Path, args: &[&str]) -> String {
    let o = run_env(dir, args, &[]);
    assert!(!o.status.success(), "expected failure {args:?}: {}", text(&o));
    text(&o)
}

fn put(d: &Path, rel: &str, body: &[u8]) {
    let p = d.join("src").join(rel);
    fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
    fs::write(p, body).expect("write");
}

/// A signed log of 15 photos, 1 metadata file and 1 top-level file.
fn photo_log(tag: &str) -> common::Scratch {
    let d = common::scratch(tag);
    for i in 0..15 {
        put(&d, &format!("posts/p{i:02}.jpg"), &vec![b'a' + i as u8; 1000 + i]);
    }
    put(&d, "metadata/inventory.json", b"{}");
    put(&d, "README.txt", b"read me");
    ok(&d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    ok(&d, &["log", "init", "ev", "--identity", "me.sgk"]);
    ok(&d, &["log", "add", "ev", "src", "--identity", "me.sgk"]);
    d
}

fn seq_of(d: &Path, path: &str) -> String {
    let idx = fs::read_to_string(d.join("ev.sigil/INDEX")).expect("INDEX");
    idx.lines()
        .find(|l| l.contains(&format!("path={path} ")))
        .and_then(|l| l.split_whitespace().next())
        .and_then(|t| t.strip_prefix("seq="))
        .expect("seq")
        .to_string()
}

#[test]
fn pretty_page_layout_and_counts() {
    let d = photo_log("lp-layout");
    let s = ok(&d, &["log", "ls", "ev", "--pretty"]);
    let head = fs::read_to_string(d.join("ev.sigil/HEAD")).expect("HEAD");
    let root = head
        .lines()
        .find_map(|l| l.strip_prefix("root="))
        .expect("root");
    let pos = |k: &str| s.find(k).unwrap_or_else(|| panic!("{k} missing:\n{s}"));
    assert!(pos("LOG       ev.sigil") < pos("FORMAT    segment log"));
    assert!(pos("SIGNED    yes, by key ") < pos("STATUS    healthy"));
    assert!(pos("STATUS    healthy") < pos("FILES     17 live files · 0 tombstoned"));
    assert!(pos("FILES") < pos("SIZE"));
    assert!(pos("SEGMENTS  17 entries") < pos("posts/"));
    assert!(s.contains("fast check: chain, HEAD, 17 segments present"), "{s}");
    assert!(s.contains("deep check NOT run"), "{s}");
    // big folder collapsed, small folder listed in full
    assert!(s.contains("15 files  14.8 KiB"), "{s}");
    assert!(!s.contains("p00.jpg"), "{s}");
    assert!(s.contains("    inventory.json"), "{s}");
    assert!(s.contains(&format!("ROOT      {root}")), "{s}");
    assert!(!s.contains('\x1b'), "not a terminal: no color\n{s}");

    // `path LOG --pretty` gives the same page instead of ignoring the flag
    let p = ok(&d, &["path", "ev.sigil", "--pretty"]);
    assert!(p.contains("STATUS    healthy"), "{p}");
    assert!(p.contains(&format!("ROOT      {root}")), "{p}");

    // expand one folder, recent additions, deep check
    let e = ok(&d, &["log", "ls", "ev", "--pretty", "--expand", "posts", "--recent", "2", "--deep"]);
    assert!(e.contains("    p00.jpg") && e.contains("    p14.jpg"), "{e}");
    assert!(e.contains("RECENT 2 (newest first, UTC)"), "{e}");
    assert!(e.contains("deep check: 17 segments read bit for bit"), "{e}");
    assert!(!e.contains("deep check NOT run"), "{e}");
    assert!(fails(&d, &["log", "ls", "ev", "--pretty", "--expand", "nope"]).contains("no folder \"nope\""));
    // options need --pretty; plain listing unchanged
    fails(&d, &["log", "ls", "ev", "--deep"]);
    assert!(ok(&d, &["log", "ls", "ev"]).contains("seq  time (UTC)"));
}

#[test]
fn pretty_tombstoned_unnamed_and_excluded() {
    let d = photo_log("lp-tomb");
    fs::write(d.join("blob.bin"), b"no name").expect("w");
    ok(&d, &["log", "append", "ev", "blob.bin", "--identity", "me.sgk"]);
    let s = seq_of(&d, "README.txt");
    ok(&d, &["log", "tombstone", "ev", "--seq", &s, "--identity", "me.sgk", "--reason", "t"]);
    let p = ok(&d, &["log", "ls", "ev", "--pretty", "--exclude", "metadata/"]);
    assert!(p.contains("FILES     16 live files · 1 tombstoned · 1 excluded-kept"), "{p}");
    assert!(p.contains("(unnamed segments)"), "{p}");
    assert!(p.contains("1 segment  7 B"), "{p}");
    assert!(p.contains("19 entries · 1 deleted"), "{p}");
    assert!(!p.contains("README.txt"), "tombstoned file not in the inventory\n{p}");
}

#[test]
fn pretty_empty_log() {
    let d = common::scratch("lp-empty");
    ok(&d, &["log", "init", "ev"]);
    let p = ok(&d, &["log", "ls", "ev", "--pretty"]);
    assert!(p.contains("FILES     0 live files · 0 tombstoned"), "{p}");
    assert!(p.contains("no live files"), "{p}");
    assert!(p.contains("SIGNED    no"), "{p}");
    assert!(p.contains("ROOT      "), "{p}");
}

#[test]
fn pretty_private_index_sealed_and_opened() {
    let d = common::scratch("lp-priv");
    put(&d, "a/one.txt", b"one");
    put(&d, "two.txt", b"two");
    ok(&d, &["log", "init", "ev", "--private-index", "--pass", "pw"]);
    ok(&d, &["log", "add", "ev", "src", "--pass", "pw"]);
    let sealed = ok(&d, &["log", "ls", "ev", "--pretty"]);
    assert!(sealed.contains("private index (sealed)"), "{sealed}");
    assert!(sealed.contains("2 entries sealed (private index"), "{sealed}");
    assert!(sealed.contains("names sealed (give --pass / --identity)"), "{sealed}");
    assert!(!sealed.contains("one.txt"), "{sealed}");
    let open = ok(&d, &["log", "ls", "ev", "--pretty", "--pass", "pw"]);
    assert!(open.contains("private index (opened)"), "{open}");
    assert!(open.contains("FILES     2 live files"), "{open}");
    assert!(open.contains("one.txt") && open.contains("two.txt"), "{open}");
    // by name: sealed without the key, found with it
    assert!(fails(&d, &["log", "read", "ev", "--name", "two.txt"]).contains("sealed"));
    assert_eq!(ok(&d, &["log", "read", "ev", "--name", "two.txt", "--pass", "pw"]), "two");
}

#[test]
fn pretty_color_honours_no_color() {
    let d = photo_log("lp-color");
    let args = ["log", "ls", "ev", "--pretty"];
    let plain = run_env(&d, &args, &[("NO_COLOR", "1")]);
    assert!(plain.status.success());
    assert!(!plain.stdout.contains(&0x1b), "NO_COLOR: no escapes");
    let forced = run_env(&d, &args, &[("CLICOLOR_FORCE", "1")]);
    let f = String::from_utf8_lossy(&forced.stdout);
    assert!(f.contains("\x1b[38;5;179mLOG"), "gold labels when forced: {f}");
    let ascii = run_env(&d, &args, &[("SIGIL_ASCII", "1")]);
    assert!(ascii.stdout.is_ascii(), "SIGIL_ASCII=1: plain ASCII");
}

#[test]
fn pretty_reports_missing_segment() {
    let d = photo_log("lp-missing");
    let s = seq_of(&d, "README.txt");
    let seg = fs::read_dir(d.join("ev.sigil/segments"))
        .expect("segments")
        .flatten()
        .flat_map(|sh| fs::read_dir(sh.path()).expect("shard").flatten())
        .map(|f| f.path())
        .find(|p| {
            p.file_stem()
                .and_then(|n| n.to_str())
                .and_then(|n| n.parse::<u64>().ok())
                .is_some_and(|n| n.to_string() == s)
        })
        .expect("segment file");
    fs::remove_file(seg).expect("rm");
    let p = ok(&d, &["log", "ls", "ev", "--pretty"]);
    assert!(p.contains("STATUS    not recoverable"), "{p}");
    assert!(p.contains("has no segment file"), "{p}");
}

#[test]
fn read_by_name() {
    let d = photo_log("lp-name");
    // found: full path, ./path and a unique bare name
    assert_eq!(ok(&d, &["log", "read", "ev", "--name", "README.txt"]), "read me");
    assert_eq!(ok(&d, &["log", "read", "ev", "--name", "./metadata/inventory.json"]), "{}");
    assert_eq!(ok(&d, &["log", "read", "ev", "--name", "inventory.json"]), "{}");
    ok(&d, &["log", "read", "ev", "--name", "posts/p03.jpg", "-o", "out.jpg"]);
    assert_eq!(fs::read(d.join("out.jpg")).expect("out"), vec![b'd'; 1003]);
    // newest version wins
    put(&d, "README.txt", b"read me v2");
    ok(&d, &["log", "add", "ev", "src", "--identity", "me.sgk"]);
    assert_eq!(ok(&d, &["log", "read", "ev", "--name", "README.txt"]), "read me v2");
    // missing
    assert!(fails(&d, &["log", "read", "ev", "--name", "nope.jpg"]).contains("no file named \"nope.jpg\""));
    // ambiguous
    put(&d, "old/inventory.json", b"[]");
    ok(&d, &["log", "add", "ev", "src", "--identity", "me.sgk"]);
    let amb = fails(&d, &["log", "read", "ev", "--name", "inventory.json"]);
    assert!(amb.contains("ambiguous") && amb.contains("metadata/inventory.json") && amb.contains("old/inventory.json"), "{amb}");
    // tombstoned: the newest version deleted → the older live one, with a note
    let v2 = seq_of(&d, "README.txt");
    let idx = fs::read_to_string(d.join("ev.sigil/INDEX")).expect("INDEX");
    let newest = idx
        .lines()
        .filter(|l| l.contains("path=README.txt "))
        .filter_map(|l| l.split_whitespace().next()?.strip_prefix("seq=").map(String::from))
        .last()
        .expect("newest");
    assert_ne!(v2, newest);
    ok(&d, &["log", "tombstone", "ev", "--seq", &newest, "--identity", "me.sgk", "--reason", "bad"]);
    let o = run_env(&d, &["log", "read", "ev", "--name", "README.txt"], &[]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(o.stdout, b"read me");
    assert!(text(&o).contains("was deleted; reading the newest live one"), "{}", text(&o));
    // every version tombstoned → refused
    ok(&d, &["log", "tombstone", "ev", "--seq", &v2, "--identity", "me.sgk", "--reason", "gone"]);
    let t = fails(&d, &["log", "read", "ev", "--name", "README.txt"]);
    assert!(t.contains("deleted by tombstone") && t.contains("no live version"), "{t}");
    // --name is one file: not with --seq / ranges
    fails(&d, &["log", "read", "ev", "--name", "README.txt", "--seq", "1"]);
}
