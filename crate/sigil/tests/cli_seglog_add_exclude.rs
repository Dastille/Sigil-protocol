//! `sigil log add --exclude PATTERN` and `DIR/.sigilignore`: excluded files and whole folders are
//! never read or sealed, excluded paths already in the log are left alone (not missing, never
//! tombstoned), `--dry-run` lists what is skipped, and bad patterns refuse the run (fail closed).
mod common;
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn sigil_cmd(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .env_remove("SIGIL_SOFT_AUTHENTICATOR")
        .args(common::pass_via_file(args))
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

fn ok(dir: &Path, args: &[&str]) -> String {
    let o = sigil_cmd(dir, args);
    assert!(o.status.success(), "{args:?}: {}", text(&o));
    text(&o)
}

fn fails(dir: &Path, args: &[&str]) -> String {
    let o = sigil_cmd(dir, args);
    assert!(
        !o.status.success(),
        "expected failure {args:?}: {}",
        text(&o)
    );
    text(&o)
}

fn tmp(tag: &str) -> common::Scratch {
    let d = common::scratch(&format!("log-excl-{tag}"));
    d
}

fn put(d: &Path, rel: &str, body: &str) {
    let p = d.join("ig").join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, body).unwrap();
}

fn index(d: &Path) -> String {
    fs::read_to_string(d.join("ev.sigil/INDEX")).unwrap()
}

/// `path=` values of the INDEX, in order.
fn paths(d: &Path) -> Vec<String> {
    index(d)
        .lines()
        .filter_map(|l| {
            l.split_whitespace()
                .find_map(|t| t.strip_prefix("path="))
                .map(str::to_string)
        })
        .collect()
}

fn snapshot(c: &Path) -> BTreeMap<PathBuf, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![c.to_path_buf()];
    while let Some(p) = stack.pop() {
        for e in fs::read_dir(&p).unwrap() {
            let p = e.unwrap().path();
            if p.is_dir() {
                stack.push(p);
            } else {
                out.insert(p.clone(), fs::read(&p).unwrap());
            }
        }
    }
    out
}

/// An Instagram-export-like folder with a Python venv inside.
fn export(d: &Path) {
    put(d, "posts/1.jpg", "one\n");
    put(d, "posts/2.jpg", "two\n");
    put(d, "messages/inbox.json", "{}\n");
    put(d, ".tools-venv/bin/python", "#!venv\n");
    put(d, ".tools-venv/lib/site-packages/x.py", "x = 1\n");
    put(d, "posts/.tools-venv/nested.py", "nested\n");
    put(d, "posts/cache.tmp", "tmp\n");
}

#[test]
fn exclude_skips_whole_subtree_at_any_depth() {
    let d = tmp("subtree");
    export(&d);
    ok(&d, &["log", "init", "ev"]);
    let out = ok(
        &d,
        &[
            "log",
            "add",
            "ev",
            "ig",
            "--exclude",
            ".tools-venv/",
            "--exclude",
            "*.tmp",
        ],
    );
    assert!(out.contains("added 3, changed 0"), "{out}");
    assert!(out.contains(", excluded 3"), "{out}");
    assert!(
        out.contains("x .tools-venv/  excluded by \".tools-venv/\" (--exclude)"),
        "{out}"
    );
    assert!(
        out.contains("x posts/.tools-venv/  excluded by"),
        "nested: {out}"
    );
    assert!(
        out.contains("x posts/cache.tmp  excluded by \"*.tmp\""),
        "{out}"
    );
    assert!(
        !out.contains("site-packages"),
        "subtree not listed file by file: {out}"
    );
    assert_eq!(
        paths(&d),
        ["messages/inbox.json", "posts/1.jpg", "posts/2.jpg"]
    );
}

#[test]
fn anchored_pattern_only_matches_at_top() {
    let d = tmp("anchor");
    put(&d, "raw/a.dng", "a\n");
    put(&d, "keep/raw/b.dng", "b\n");
    put(&d, "raw/sub/c.dng", "c\n");
    ok(&d, &["log", "init", "ev"]);
    ok(&d, &["log", "add", "ev", "ig", "--exclude", "raw/*.dng"]);
    assert_eq!(paths(&d), ["keep/raw/b.dng", "raw/sub/c.dng"]);
}

#[test]
fn sigilignore_file_with_comments_and_blank_lines() {
    let d = tmp("ignorefile");
    export(&d);
    put(
        &d,
        ".sigilignore",
        "# Python tools for the export\n\n.tools-venv/\n   \n*.tmp   \n",
    );
    ok(&d, &["log", "init", "ev"]);
    let out = ok(&d, &["log", "add", "ev", "ig", "--dry-run"]);
    assert!(
        out.contains("x .tools-venv/  excluded by \".tools-venv/\" (.sigilignore line 3)"),
        "{out}"
    );
    assert!(
        out.contains("x posts/cache.tmp  excluded by \"*.tmp\" (.sigilignore line 5)"),
        "{out}"
    );
    assert!(
        out.contains("would have added 4"),
        "3 files + .sigilignore itself: {out}"
    );
    assert!(out.contains("dry run: nothing written"), "{out}");
    ok(&d, &["log", "add", "ev", "ig"]);
    assert_eq!(
        paths(&d),
        [
            ".sigilignore",
            "messages/inbox.json",
            "posts/1.jpg",
            "posts/2.jpg"
        ]
    );
    // --no-ignore-file: the venv is no longer skipped
    let out = ok(
        &d,
        &["log", "add", "ev", "ig", "--dry-run", "--no-ignore-file"],
    );
    assert!(out.contains("would have added 4,"), "{out}");
    assert!(!out.contains("excluded"), "{out}");
}

#[test]
fn excluded_paths_already_in_log_are_kept_not_tombstoned() {
    let d = tmp("kept");
    export(&d);
    ok(&d, &["log", "init", "ev"]);
    ok(&d, &["log", "add", "ev", "ig"]);
    assert_eq!(paths(&d).len(), 7);
    let before = snapshot(&d.join("ev.sigil"));

    // later the user decides the venv should not be backed up
    let out = ok(
        &d,
        &[
            "log",
            "add",
            "ev",
            "ig",
            "--exclude",
            ".tools-venv",
            "--dry-run",
        ],
    );
    assert!(out.contains("missing 0"), "excluded is not missing: {out}");
    assert!(out.contains(", excluded-kept 3"), "{out}");
    assert!(
        out.contains("~ .tools-venv/lib/site-packages/x.py  excluded, kept in log (segment"),
        "{out}"
    );
    assert!(!out.contains("! "), "nothing reported missing: {out}");

    // the real run writes nothing at all: no tombstone, no new HEAD
    let out = ok(&d, &["log", "add", "ev", "ig", "--exclude", ".tools-venv"]);
    assert!(
        out.contains("unchanged 4, missing 0")
            && out.contains("excluded-kept 3 (listed by --dry-run)"),
        "{out}"
    );
    assert!(out.contains("log unchanged"), "{out}");
    assert!(!index(&d).contains("op=tomb"));
    assert_eq!(snapshot(&d.join("ev.sigil")), before);

    // a genuinely removed, non-excluded file is still reported missing (and kept)
    fs::remove_file(d.join("ig/posts/2.jpg")).unwrap();
    let out = ok(&d, &["log", "add", "ev", "ig", "--exclude", ".tools-venv"]);
    assert!(out.contains("! posts/2.jpg  missing from source"), "{out}");
    assert!(out.contains("missing 1"), "{out}");
    assert!(!index(&d).contains("op=tomb"));
}

#[test]
fn excluded_file_in_log_deleted_from_source_is_still_not_missing() {
    let d = tmp("goneexcl");
    export(&d);
    ok(&d, &["log", "init", "ev"]);
    ok(&d, &["log", "add", "ev", "ig"]);
    fs::remove_dir_all(d.join("ig/.tools-venv")).unwrap();
    let out = ok(
        &d,
        &["log", "add", "ev", "ig", "--exclude", "**/.tools-venv/"],
    );
    assert!(
        out.contains("missing 0") && out.contains("excluded-kept 3"),
        "{out}"
    );
}

#[test]
fn bad_patterns_refuse_the_run_and_write_nothing() {
    let d = tmp("bad");
    export(&d);
    ok(&d, &["log", "init", "ev"]);
    let before = snapshot(&d.join("ev.sigil"));
    let e = fails(&d, &["log", "add", "ev", "ig", "--exclude", "[abc"]);
    assert!(e.contains("not closed"), "{e}");
    let e = fails(&d, &["log", "add", "ev", "ig", "--exclude", "!keep"]);
    assert!(e.contains("not supported"), "{e}");
    let e = fails(&d, &["log", "add", "ev", "ig", "--exclude", ""]);
    assert!(e.contains("empty pattern"), "{e}");
    put(&d, ".sigilignore", "ok\n!posts\n");
    let e = fails(&d, &["log", "add", "ev", "ig", "--dry-run"]);
    assert!(e.contains(".sigilignore line 2"), "{e}");
    assert_eq!(snapshot(&d.join("ev.sigil")), before);
    // a folder where the ignore file should be is refused, not ignored
    fs::remove_file(d.join("ig/.sigilignore")).unwrap();
    fs::create_dir_all(d.join("ig/.sigilignore")).unwrap();
    let e = fails(&d, &["log", "add", "ev", "ig"]);
    assert!(e.contains("not a regular file"), "{e}");
    assert_eq!(snapshot(&d.join("ev.sigil")), before);
}

#[cfg(unix)]
#[test]
fn excluded_folder_is_not_read() {
    use std::os::unix::fs::PermissionsExt;
    let d = tmp("unread");
    put(&d, "a.jpg", "a\n");
    put(&d, "locked/secret", "s\n");
    let locked = d.join("ig/locked");
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o000)).unwrap();
    ok(&d, &["log", "init", "ev"]);
    let o = sigil_cmd(&d, &["log", "add", "ev", "ig", "--exclude", "locked/"]);
    fs::set_permissions(&locked, fs::Permissions::from_mode(0o755)).unwrap();
    let out = text(&o);
    assert!(o.status.success(), "excluded folder never opened: {out}");
    assert!(!out.contains("unreadable"), "{out}");
    assert_eq!(paths(&d), ["a.jpg"]);
}

#[test]
fn excluded_symlink_is_excluded_not_special() {
    let d = tmp("link");
    put(&d, "a.jpg", "a\n");
    #[cfg(unix)]
    std::os::unix::fs::symlink("a.jpg", d.join("ig/link.jpg")).unwrap();
    ok(&d, &["log", "init", "ev"]);
    let out = ok(&d, &["log", "add", "ev", "ig", "--exclude", "link.*"]);
    if cfg!(unix) {
        assert!(out.contains("x link.jpg  excluded"), "{out}");
        assert!(out.contains("skipped-special 0"), "{out}");
    }
}
