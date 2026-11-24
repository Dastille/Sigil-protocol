//! Large-INDEX hot paths (`log ls` scans the segment folders once, `log read --seq` parses the
//! INDEX once): results must match what the per-entry checks said before.
mod common;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

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

#[test]
fn ls_presence_and_read_bounds() {
    let d = common::scratch("big-index");
    ok(&d, &["log", "init", "ev"]);
    for i in 1..=4 {
        let f = format!("f{i}");
        fs::write(d.join(&f), format!("batch {i}\n")).unwrap();
        ok(&d, &["log", "append", "ev", &f]);
    }
    let seg = |s: u64| d.join(format!("ev.sigil/segments/0000/{s:010}.sg1"));
    // segment 2 missing; segment 3 replaced by a directory of the same name; a stray look-alike
    fs::remove_file(seg(2)).unwrap();
    fs::remove_file(seg(3)).unwrap();
    fs::create_dir(seg(3)).unwrap();
    fs::write(d.join("ev.sigil/segments/0000/4.sg1"), "x").unwrap();
    let ls = ok(&d, &["log", "ls", "ev"]);
    let row = |s: &str| {
        ls.lines()
            .find(|l| l.split_whitespace().next() == Some(s))
            .unwrap_or_default()
            .to_string()
    };
    assert!(row("1").contains("ok"), "{ls}");
    assert!(!row("2").contains(" ok"), "{ls}");
    assert!(!row("3").contains(" ok"), "{ls}");
    assert!(row("4").contains("ok"), "{ls}");
    // read --seq: bounds still checked without the extra count pass
    let o = ok(&d, &["log", "read", "ev", "--seq", "4"]);
    assert_eq!(o, "batch 4\n");
    let o = run(&d, &["log", "read", "ev", "--seq", "9"]);
    assert!(!o.status.success(), "{}", text(&o));
    let o = run(&d, &["log", "read", "ev", "--from", "4", "--to", "9"]);
    assert!(!o.status.success(), "{}", text(&o));
    // an empty log still says so
    ok(&d, &["log", "init", "empty"]);
    let o = run(&d, &["log", "read", "empty"]);
    assert!(text(&o).contains("empty"), "{}", text(&o));
    assert!(!run(&d, &["log", "read", "empty", "--seq", "1"])
        .status
        .success());
}
