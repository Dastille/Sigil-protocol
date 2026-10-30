//! `gather --partial`: a short fountain folder still fails closed (exit 2, no mark), but
//! leaves a JSON progress receipt; damaged and foreign packets never count as progress.
mod common;
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

fn scratch(tag: &str) -> common::Scratch {
    let d = common::scratch(&format!("gp-{tag}"));
    d
}

fn mark() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fountain-v1/mark.sg1")
}

fn rq(d: &Path) -> Vec<PathBuf> {
    let mut v: Vec<_> = std::fs::read_dir(d)
        .expect("ls")
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("rq"))
        .collect();
    v.sort();
    v
}

/// Rain the fixture mark (6 needed, 8 sent) and keep `keep` packets in `short/`.
fn short(d: &Path, keep: usize) -> PathBuf {
    let m = mark();
    let o = sigil(
        d,
        &[
            "deluge",
            m.to_str().expect("p"),
            "--fountain",
            "--extra",
            "2",
            "-o",
            "r",
        ],
    );
    assert!(o.status.success());
    let s = d.join("short");
    std::fs::create_dir_all(&s).expect("mkdir");
    for p in rq(&d.join("r")).iter().take(keep) {
        std::fs::copy(p, s.join(p.file_name().expect("n"))).expect("cp");
    }
    s
}

#[test]
fn full_gather_unchanged_with_and_without_partial() {
    let d = scratch("full");
    short(&d, 8);
    for (out, extra) in [("a.sg1", None), ("b.sg1", Some("--partial"))] {
        let mut args = vec!["gather", "short", "-o", out];
        args.extend(extra);
        let o = sigil(&d, &args);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        assert_eq!(
            std::fs::read(d.join(out)).expect("r"),
            std::fs::read(mark()).expect("r")
        );
        assert!(!d.join(format!("{out}.partial.json")).exists());
    }
    let o = sigil(&d, &["gather", "short", "-o", "c.sg1", "--json"]);
    let j = String::from_utf8_lossy(&o.stdout);
    assert!(j.starts_with("{\"ok\":true,\"cmd\":\"gather\""), "{j}");
}

#[test]
fn short_folder_fails_closed_without_partial() {
    let d = scratch("closed");
    short(&d, 4);
    let o = sigil(&d, &["gather", "short", "-o", "no.sg1"]);
    assert!(!o.status.success());
    assert!(!d.join("no.sg1").exists());
    assert!(!d.join("no.sg1.partial.json").exists());
}

#[test]
fn partial_writes_receipt_and_exits_2_and_skips_bad_and_foreign() {
    let d = scratch("partial");
    let s = short(&d, 4);
    // A damaged packet file and packets of a different file: never progress.
    std::fs::write(s.join("junk.rq"), b"not a packet").expect("w");
    std::fs::write(d.join("other.bin"), vec![7u8; 3000]).expect("w");
    assert!(sigil(&d, &["seal", "other.bin", "-o", "other.sg1"])
        .status
        .success());
    assert!(sigil(&d, &["deluge", "other.sg1", "--fountain", "-o", "o"])
        .status
        .success());
    let foreign = rq(&d.join("o"));
    std::fs::copy(&foreign[0], s.join("zz-foreign.rq")).expect("cp");

    let o = sigil(&d, &["gather", "short", "-o", "no.sg1", "--partial"]);
    assert_eq!(
        o.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(!d.join("no.sg1").exists(), "no pretend-complete mark");
    let r = std::fs::read_to_string(d.join("no.sg1.partial.json")).expect("receipt");
    assert!(
        r.starts_with("{\"ok\":false,\"cmd\":\"gather\",\"exit\":2"),
        "{r}"
    );
    for f in [
        "\"partial\":true",
        "\"packets_accepted\":4",
        "\"packets_needed\":6",
        "\"packets_more\":2",
        "\"damaged_files\":1",
        "\"stray_files\":1",
        "\"artifact\":null",
        "\"reason\":",
    ] {
        assert!(r.contains(f), "{f} in {r}");
    }

    // --json: the same fields on one stdout line, no receipt file.
    let o = sigil(
        &d,
        &["gather", "short", "-o", "j.sg1", "--partial", "--json"],
    );
    assert_eq!(o.status.code(), Some(2));
    let j = String::from_utf8_lossy(&o.stdout);
    assert_eq!(j.lines().count(), 1, "{j}");
    assert!(
        j.contains("\"ok\":false") && j.contains("\"packets_accepted\":4"),
        "{j}"
    );
    assert!(!d.join("j.sg1").exists() && !d.join("j.sg1.partial.json").exists());
}

#[test]
fn partial_with_zero_valid_packets() {
    let d = scratch("zero");
    let s = d.join("empty");
    std::fs::create_dir_all(&s).expect("mkdir");
    std::fs::write(s.join("a.rq"), b"junk").expect("w");
    let o = sigil(&d, &["gather", "empty", "-o", "z.sg1", "--partial"]);
    assert_eq!(
        o.status.code(),
        Some(2),
        "{}",
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(!d.join("z.sg1").exists());
    let r = std::fs::read_to_string(d.join("z.sg1.partial.json")).expect("receipt");
    assert!(
        r.contains("\"packets_accepted\":0") && r.contains("\"damaged_files\":1"),
        "{r}"
    );
}
