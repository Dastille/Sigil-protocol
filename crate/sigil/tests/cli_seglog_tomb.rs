//! Segment log slice 2: tombstones + compaction (`sigil log tombstone / compact`), the `log=2`
//! upgrade rule, tamper detection on the new entries, anchors across compaction, crash points,
//! and that gc / doctor / verify / mend understand both.
use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime};

use sigil::seglog::{self, CompactOpts, CrashPoint};

fn sigil_cmd(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .env_remove("SIGIL_SOFT_AUTHENTICATOR")
        .args(args)
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

fn run(dir: &Path, args: &[&str]) -> (i32, String) {
    let o = sigil_cmd(dir, args);
    (o.status.code().unwrap_or(-1), text(&o))
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sigil-seglog2-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn seg(c: &Path, seq: u64) -> PathBuf {
    seglog::segment_path(c, seq)
}

fn append(d: &Path, text: &str) {
    fs::write(d.join("b.txt"), text).unwrap();
    ok(d, &["log", "append", "ev", "b.txt"]);
}

/// unsigned log `ev` with batches "batch 1\n" … "batch N\n"
fn sample(d: &Path, n: u64) -> PathBuf {
    ok(d, &["log", "init", "ev"]);
    for i in 1..=n {
        append(d, &format!("batch {i}\n"));
    }
    d.join("ev.sigil")
}

fn manifest(c: &Path) -> String {
    fs::read_to_string(c.join("CONTAINER")).unwrap()
}

fn index(c: &Path) -> String {
    fs::read_to_string(c.join("INDEX")).unwrap()
}

/// every file under `c` → bytes
fn snapshot(c: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, p: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for e in fs::read_dir(p).unwrap().flatten() {
            let path = e.path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                out.insert(
                    path.strip_prefix(root).unwrap().display().to_string(),
                    fs::read(&path).unwrap(),
                );
            }
        }
    }
    let mut m = BTreeMap::new();
    walk(c, c, &mut m);
    m
}

fn age(p: &Path, secs: u64) {
    let f = fs::OpenOptions::new()
        .write(true)
        .open(p)
        .or_else(|_| fs::File::open(p))
        .unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(secs))
        .unwrap();
}

fn anchor(d: &Path) -> String {
    let ls = ok(d, &["log", "ls", "ev"]);
    let l = ls.lines().find(|l| l.starts_with("anchor")).unwrap();
    l.rsplit(' ').next().unwrap().to_string()
}

/// A line an attacker with file access writes: valid chain, no signature involved.
fn forge_line(c: &Path, body: &str) {
    let idx = index(c);
    let prev = match idx.lines().last().and_then(|l| l.rsplit_once(" chain=")) {
        Some((_, h)) if idx.lines().count() > 1 => hex::decode(h.trim()).unwrap(),
        _ => {
            let id = manifest(c)
                .lines()
                .find_map(|l| l.strip_prefix("log-id=").map(String::from))
                .unwrap();
            let mut b = b"sigil-log-genesis-v1\0".to_vec();
            b.extend_from_slice(id.as_bytes());
            sigil::sha256(&b).to_vec()
        }
    };
    let mut b = b"sigil-log-entry-v1\0".to_vec();
    b.extend_from_slice(&prev);
    b.extend_from_slice(body.as_bytes());
    let chain = hex::encode(sigil::sha256(&b));
    fs::write(c.join("INDEX"), format!("{idx}{body} chain={chain}\n")).unwrap();
}

/// stdout only (notes go to stderr)
fn read_all(d: &Path) -> String {
    let o = sigil_cmd(d, &["log", "read", "ev"]);
    assert!(o.status.success(), "{}", text(&o));
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn log_stays_v1_until_first_tombstone_or_compaction() {
    let d = tmp("v1");
    let c = sample(&d, 3);
    assert!(manifest(&c).contains("\nlog=1\n"));
    let idx_before = index(&c);
    assert!(
        !idx_before.contains("op="),
        "slice-1 INDEX lines carry no op= key"
    );
    // nothing to merge, nothing deleted: compact is a no-op and must not upgrade the log
    let o = ok(&d, &["log", "compact", "ev", "--apply", "--keep-last", "3"]);
    assert!(o.contains("nothing to merge or erase"), "{o}");
    assert!(manifest(&c).contains("\nlog=1\n") && index(&c) == idx_before);
    // a failed tombstone must not upgrade it either
    fails(&d, &["log", "tombstone", "ev", "--seq", "9"]);
    fails(&d, &["log", "tombstone", "ev", "--from", "5", "--to", "6"]);
    assert!(manifest(&c).contains("\nlog=1\n") && index(&c) == idx_before);
    // appends keep working and stay v1
    append(&d, "batch 4\n");
    assert!(manifest(&c).contains("\nlog=1\n"));
    // first tombstone flips it
    ok(&d, &["log", "tombstone", "ev", "--seq", "2"]);
    let m = manifest(&c);
    assert!(
        m.contains("\nlog=2\n") && m.contains("sigil-container=1") && m.contains("kind=log"),
        "{m}"
    );
    // the seg lines written before are byte-identical (INDEX is append-only)
    assert!(index(&c).starts_with(&idx_before));
    // compaction alone also upgrades
    let d2 = tmp("v1b");
    let c2 = sample(&d2, 3);
    ok(&d2, &["log", "compact", "ev", "--apply"]);
    assert!(manifest(&c2).contains("\nlog=2\n"));
    assert!(index(&c2).contains("op=compact"));
}

#[test]
fn tombstone_roundtrip_ls_read_verify() {
    let d = tmp("tomb");
    let c = sample(&d, 5);
    let o = ok(
        &d,
        &[
            "log",
            "tombstone",
            "ev",
            "--seq",
            "2",
            "--reason",
            "user asked: erase me, please",
        ],
    );
    assert!(
        o.contains("tombstone 6") && o.contains("deleted segment(s) 2"),
        "{o}"
    );
    // ls shows the state and the reason
    let ls = ok(&d, &["log", "ls", "ev"]);
    assert!(ls.contains("entries=6") && ls.contains("log=2"), "{ls}");
    assert!(
        ls.contains("DELETED (tombstone #6)") && ls.contains("tombstone: deletes 2"),
        "{ls}"
    );
    assert!(
        ls.contains("user asked: erase me, please"),
        "reason round-trips through the INDEX: {ls}"
    );
    assert!(ls.contains("still on disk"), "{ls}");
    // read of the tombstoned seq errors clearly, others fine
    let e = fails(&d, &["log", "read", "ev", "--seq", "2"]);
    assert!(
        e.contains("deleted by tombstone #6") && e.contains("erase me"),
        "{e}"
    );
    assert_eq!(ok(&d, &["log", "read", "ev", "--seq", "3"]), "batch 3\n");
    // a tombstone record is not data
    assert!(fails(&d, &["log", "read", "ev", "--seq", "6"]).contains("tombstone record"));
    // ranges / whole-log reads skip it (stderr note); --strict refuses
    let o = sigil_cmd(&d, &["log", "read", "ev"]);
    assert!(o.status.success());
    assert_eq!(
        String::from_utf8_lossy(&o.stdout),
        "batch 1\nbatch 3\nbatch 4\nbatch 5\n"
    );
    assert!(String::from_utf8_lossy(&o.stderr).contains("skipped 1 deleted segment(s): 2"));
    assert_eq!(
        ok(&d, &["log", "read", "ev", "--from", "1", "--to", "3"])
            .replace("note: skipped 1 deleted segment(s): 2\n", ""),
        "batch 1\nbatch 3\n"
    );
    assert!(fails(&d, &["log", "read", "ev", "--strict"]).contains("deleted by tombstone"));
    // deleting twice, or a non-segment entry, is refused
    assert!(fails(&d, &["log", "tombstone", "ev", "--seq", "2"]).contains("already deleted"));
    assert!(fails(&d, &["log", "tombstone", "ev", "--seq", "6"]).contains("tombstone record"));
    // verify: chained, healthy structure; the pending erasure is a warning
    let (code, v) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 1, "{v}");
    assert!(
        v.contains("deleted-segment") && v.contains("tombstones") && v.contains("log=2"),
        "{v}"
    );
    // range tombstone clips to live data and skips what is already deleted
    let o = ok(&d, &["log", "tombstone", "ev", "--from", "1", "--to", "4"]);
    assert!(
        o.contains("deleted segment(s) 1,3-4") && o.contains("1 already deleted"),
        "{o}"
    );
    assert!(
        fails(&d, &["log", "tombstone", "ev", "--from", "1", "--to", "4"])
            .contains("nothing to delete")
    );
    assert!(fails(&d, &["log", "tombstone", "ev", "--from", "4", "--to", "2"]).contains("--from"));
    // with everything gone from the middle, the rest still reads
    assert_eq!(ok(&d, &["log", "read", "ev", "--seq", "5"]), "batch 5\n");
    // every segment file is still there until erased
    for s in 1..=5 {
        assert!(seg(&c, s).is_file());
    }
}

#[test]
fn tombstone_tamper_detection() {
    let d = tmp("tamper");
    let c = sample(&d, 4);
    ok(
        &d,
        &["log", "tombstone", "ev", "--seq", "2", "--reason", "gdpr"],
    );
    let good_idx = index(&c);
    let good_head = fs::read_to_string(c.join("HEAD")).unwrap();
    let pin = anchor(&d);
    let (code, o) = run(&d, &["log", "verify", "ev", "--anchor", &pin]);
    assert_eq!(code, 1, "{o}");
    let verify_code = |d: &Path| run(d, &["log", "verify", "ev"]);

    // 1. edit which segment the tombstone deletes → chain break
    fs::write(c.join("INDEX"), good_idx.replace("del=2", "del=3")).unwrap();
    let (code, o) = verify_code(&d);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("index-chain"), "{o}");
    assert!(fails(&d, &["log", "read", "ev"]).contains("damaged"));
    // 2. edit the reason
    fs::write(
        c.join("INDEX"),
        good_idx.replace("reason=gdpr", "reason=oops"),
    )
    .unwrap();
    assert!(verify_code(&d).1.contains("index-chain"));
    // 3. un-delete: drop the tombstone line → HEAD is ahead of INDEX
    let lines: Vec<&str> = good_idx.lines().collect();
    let cut = format!("{}\n", lines[..lines.len() - 1].join("\n"));
    fs::write(c.join("INDEX"), &cut).unwrap();
    let (code, o) = verify_code(&d);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("head-truncated"), "{o}");
    // 3b. an unsigned INDEX+HEAD pair rewound together can only be caught by an external anchor
    let (code, o) = run(&d, &["log", "verify", "ev", "--anchor", &pin]);
    assert_eq!(code, 2, "{o}");
    // 4. a tombstone line with a valid chain but nonsense content is rejected structurally
    for (body, what) in [
        ("seq=6 t=5 op=tomb del=9", "not earlier"),
        ("seq=6 t=5 op=tomb del=2-9", "not earlier"),
        ("seq=6 t=5 op=tomb del=2", "already deleted"),
        ("seq=6 t=5 op=tomb", "del="),
        ("seq=6 t=5 op=tomb del=0", "del="),
        ("seq=6 t=5 op=tomb del=3,3", "del="),
        ("seq=6 t=5 op=shred del=3", "not known"),
    ] {
        fs::write(c.join("INDEX"), &good_idx).unwrap();
        fs::write(c.join("HEAD"), &good_head).unwrap();
        // good_idx has 5 entries (4 segments + tombstone); the next entry is seq 6
        forge_line(&c, body);
        let (code, o) = run(&d, &["log", "verify", "ev"]);
        assert_eq!(code, 2, "{body}: {o}");
        assert!(o.contains(what) || o.contains("index-"), "{body}: {o}");
    }
    // 5. tombstone naming a tombstone / compaction entry
    fs::write(c.join("INDEX"), &good_idx).unwrap();
    forge_line(&c, "seq=6 t=5 op=tomb del=5");
    let o = verify_code(&d).1;
    assert!(o.contains("not a segment entry"), "{o}");
    // restore → healthy again (apart from pending erasure)
    fs::write(c.join("INDEX"), &good_idx).unwrap();
    fs::write(c.join("HEAD"), &good_head).unwrap();
    let (code, o) = verify_code(&d);
    assert_eq!(code, 1, "{o}");
    let (code, o) = run(&d, &["log", "verify", "ev", "--anchor", &pin]);
    assert_eq!(code, 1, "pin still holds: {o}");
    // a tombstone line under a log=1 manifest is damage, not data (what an older writer cannot produce)
    let m = manifest(&c);
    fs::write(c.join("CONTAINER"), m.replace("log=2", "log=1")).unwrap();
    let (code, o) = verify_code(&d);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("log-format") && o.contains("log=1"), "{o}");
    assert!(fails(&d, &["log", "append", "ev", "b.txt"]).contains("damaged"));
}

#[test]
fn newer_log_format_is_refused_by_every_command() {
    // An older sigil only knows log=1; the manifest is raised to 2 before the first new line is
    // written, so it refuses instead of reporting "missing segment". Here: a format this build
    // does not know plays the old reader's role.
    let d = tmp("newer");
    let c = sample(&d, 3);
    ok(&d, &["log", "tombstone", "ev", "--seq", "1"]);
    let m = manifest(&c);
    fs::write(c.join("CONTAINER"), m.replace("log=2", "log=9")).unwrap();
    for args in [
        vec!["log", "ls", "ev"],
        vec!["log", "read", "ev"],
        vec!["log", "append", "ev", "b.txt"],
        vec!["log", "tombstone", "ev", "--seq", "2"],
        vec!["log", "compact", "ev"],
        vec!["log", "mend", "ev"],
        vec!["gc", "ev"],
    ] {
        let e = fails(&d, &args);
        assert!(
            e.contains("newer than this sigil") && e.contains("upgrade"),
            "{args:?}: {e}"
        );
        assert!(
            !e.contains("segment-missing") && !e.contains("MISSING"),
            "{args:?}: {e}"
        );
    }
    for cmd in ["verify", "doctor"] {
        let (code, o) = run(
            &d,
            &["log", cmd, "ev"]
                .iter()
                .skip(if cmd == "doctor" { 1 } else { 0 })
                .copied()
                .collect::<Vec<_>>(),
        );
        assert_eq!(code, 2, "{o}");
        assert!(
            o.contains("newer than this sigil") && !o.contains("segment-missing"),
            "{o}"
        );
    }
}

#[test]
fn compaction_dry_run_changes_nothing_then_apply_merges() {
    let d = tmp("compact");
    let c = sample(&d, 6);
    let before = snapshot(&c);
    let o = ok(&d, &["log", "compact", "ev"]);
    assert!(o.contains("dry run") && o.contains("new segment 7"), "{o}");
    assert_eq!(snapshot(&c), before, "dry run must not touch a byte");
    // pin anchors from before the compaction
    let pin6 = anchor(&d);
    let all_before = read_all(&d);
    let o = ok(&d, &["log", "compact", "ev", "--apply", "--keep-last", "2"]);
    assert!(
        o.contains("compacted: 1 new segment(s), 4 old file(s) erased"),
        "{o}"
    );
    // seq identity is preserved: every original seq still reads, same bytes
    for i in 1..=6 {
        assert_eq!(
            ok(&d, &["log", "read", "ev", "--seq", &i.to_string()]),
            format!("batch {i}\n")
        );
    }
    assert_eq!(read_all(&d), all_before);
    assert_eq!(
        ok(&d, &["log", "read", "ev", "--from", "2", "--to", "4"]),
        "batch 2\nbatch 3\nbatch 4\n"
    );
    // files: 5 and 6 (kept) + the merged one; 1-4 erased
    for s in 1..=4 {
        assert!(!seg(&c, s).exists(), "segment {s} should be erased");
    }
    assert!(seg(&c, 5).is_file() && seg(&c, 6).is_file() && seg(&c, 7).is_file());
    // INDEX only grew
    let idx = index(&c);
    assert!(
        idx.lines().nth(7).unwrap().contains("op=compact of=1-4"),
        "{idx}"
    );
    // anchors pinned before the compaction still verify, and so does the new state
    ok(&d, &["log", "verify", "ev", "--anchor", &pin6]);
    let pin7 = anchor(&d);
    assert!(pin7.starts_with("7:"));
    let (code, o) = run(&d, &["log", "verify", "ev", "--anchor", &pin7]);
    assert_eq!(code, 0, "{o}");
    let ls = ok(&d, &["log", "ls", "ev"]);
    assert!(
        ls.contains("in #7") && ls.contains("compaction of 1-4"),
        "{ls}"
    );
    // the merged segment is an ordinary star holding the plain bytes
    ok(
        &d,
        &["unseal", seg(&c, 7).to_str().unwrap(), "-o", "merged.txt"],
    );
    assert_eq!(
        fs::read_to_string(d.join("merged.txt")).unwrap(),
        "batch 1\nbatch 2\nbatch 3\nbatch 4\n"
    );
    // plain `sigil verify` / `mend` work on it like on any star
    ok(&d, &["verify", seg(&c, 7).to_str().unwrap()]);
    // appending afterwards continues the numbering
    append(&d, "batch 7\n");
    assert!(seg(&c, 8).is_file());
    assert_eq!(ok(&d, &["log", "read", "ev", "--seq", "8"]), "batch 7\n");
    // a tombstone of a compacted member is allowed, naming the original seq
    assert!(fails(&d, &["log", "tombstone", "ev", "--seq", "7"]).contains("compaction record"));
    // second compaction merges the merged segment with the rest
    ok(&d, &["log", "compact", "ev", "--apply"]);
    assert_eq!(
        read_all(&d),
        "batch 1\nbatch 2\nbatch 3\nbatch 4\nbatch 5\nbatch 6\nbatch 7\n"
    );
    ok(
        &d,
        &["log", "verify", "ev", "--anchor", &pin6, "--anchor", &pin7],
    );
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 0, "{o}");
    assert_eq!(
        fs::read_dir(c.join("segments"))
            .unwrap()
            .flatten()
            .flat_map(|s| fs::read_dir(s.path()).unwrap().flatten())
            .count(),
        1,
        "one live segment file left"
    );
}

#[test]
fn compaction_rules_range_keep_last_older_than_target_size() {
    let d = tmp("rules");
    let c = sample(&d, 8);
    // --range
    let o = ok(&d, &["log", "compact", "ev", "--range", "3-5"]);
    assert!(o.contains("[3-5]") && !o.contains("[1"), "{o}");
    // --older-than: nothing is an hour old
    let o = ok(&d, &["log", "compact", "ev", "--older-than", "1h"]);
    assert!(o.contains("nothing to merge or erase"), "{o}");
    // …but everything is older than 0 seconds
    let o = ok(&d, &["log", "compact", "ev", "--older-than", "0s"]);
    assert!(o.contains("1-8"), "{o}");
    fails(&d, &["log", "compact", "ev", "--older-than", "soon"]);
    // --keep-last keeps the tail apart
    let o = ok(&d, &["log", "compact", "ev", "--keep-last", "3"]);
    assert!(o.contains("[1-5]"), "{o}");
    // rules combine (all must hold)
    let o = ok(
        &d,
        &["log", "compact", "ev", "--keep-last", "3", "--range", "2-4"],
    );
    assert!(o.contains("[2-4]"), "{o}");
    // target size splits groups: each batch is 8 bytes
    let o = ok(&d, &["log", "compact", "ev", "--target-size", "16"]);
    assert!(
        o.contains("new segment 9") && o.contains("new segment 12"),
        "{o}"
    );
    ok(
        &d,
        &["log", "compact", "ev", "--target-size", "16", "--apply"],
    );
    assert_eq!(
        read_all(&d),
        (1..=8).map(|i| format!("batch {i}\n")).collect::<String>()
    );
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 0, "{o}");
    let _ = c;
}

#[test]
fn tombstone_then_compact_erases_for_real_even_inside_a_compaction() {
    let d = tmp("erase");
    let c = sample(&d, 6);
    ok(&d, &["log", "compact", "ev", "--apply", "--range", "1-4"]);
    assert!(seg(&c, 7).is_file());
    ok(
        &d,
        &[
            "log",
            "tombstone",
            "ev",
            "--seq",
            "3",
            "--reason",
            "retention",
        ],
    );
    // the data still sits inside segment 7; verify says so
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 1, "{o}");
    assert!(
        o.contains("deleted-data") && o.contains("compaction segment 7") && o.contains("3"),
        "{o}"
    );
    assert!(ok(&d, &["log", "ls", "ev"]).contains("byte(s) of deleted data are still on disk"));
    let (code, o) = run(&d, &["doctor", "ev"]);
    assert_eq!(code, 1, "{o}");
    assert!(o.contains("deleted-data"), "{o}");
    // dry-run says what it would rewrite
    let before = snapshot(&c);
    let o = ok(&d, &["log", "compact", "ev"]);
    assert!(
        o.contains("drops deleted 3") && o.contains("[1-2,4-6]"),
        "{o}"
    );
    assert_eq!(snapshot(&c), before);
    // apply rewrites 7 (+ plain 5, 6, kept apart? no: everything eligible) without segment 3
    let old7 = fs::read(seg(&c, 7)).unwrap();
    ok(&d, &["log", "compact", "ev", "--apply"]);
    assert!(!seg(&c, 7).exists(), "the old merged file is gone");
    let ids: Vec<u64> = (1..=12).filter(|s| seg(&c, *s).is_file()).collect();
    assert_eq!(ids.len(), 1, "{ids:?}");
    let merged = fs::read(seg(&c, ids[0])).unwrap();
    assert_ne!(merged, old7);
    ok(
        &d,
        &[
            "unseal",
            seg(&c, ids[0]).to_str().unwrap(),
            "-o",
            "merged.txt",
        ],
    );
    let plain = fs::read_to_string(d.join("merged.txt")).unwrap();
    assert!(
        !plain.contains("batch 3") && plain.contains("batch 4") && plain.contains("batch 6"),
        "{plain}"
    );
    assert!(fails(&d, &["log", "read", "ev", "--seq", "3"]).contains("deleted"));
    assert_eq!(ok(&d, &["log", "read", "ev", "--seq", "4"]), "batch 4\n");
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 0, "{o}");
    let (code, o) = run(&d, &["doctor", "ev"]);
    assert_eq!(code, 0, "{o}");
    assert!(
        o.contains("tombstones") && o.contains("compactions"),
        "doctor reports tombstone/compaction state: {o}"
    );
    // plain deleted-only segments are simply erased (no merge needed)
    let d2 = tmp("erase2");
    let c2 = sample(&d2, 3);
    ok(&d2, &["log", "tombstone", "ev", "--seq", "2"]);
    let o = ok(
        &d2,
        &["log", "compact", "ev", "--apply", "--keep-last", "5"],
    );
    assert!(o.contains("1 old file(s) erased"), "{o}");
    assert!(!seg(&c2, 2).exists() && seg(&c2, 1).is_file() && seg(&c2, 3).is_file());
    assert_eq!(
        index(&c2).lines().count(),
        5,
        "no compact entry was needed: magic + 3 segs + 1 tombstone"
    );
    let (code, o) = run(&d2, &["log", "verify", "ev"]);
    assert_eq!(code, 0, "{o}");
}

#[test]
fn compaction_crash_points_leave_a_verifiable_log() {
    for point in [
        CrashPoint::AfterSegments,
        CrashPoint::AfterManifest,
        CrashPoint::AfterIndex,
        CrashPoint::AfterHead,
        CrashPoint::MidDelete,
    ] {
        let d = tmp(&format!("crash-{point:?}"));
        let c = sample(&d, 5);
        ok(&d, &["log", "tombstone", "ev", "--seq", "2"]);
        let want = "batch 1\nbatch 3\nbatch 4\nbatch 5\n";
        let e = seglog::compact(
            &c,
            &CompactOpts {
                apply: true,
                stop_after: Some(point),
                ..Default::default()
            },
        )
        .unwrap_err();
        assert!(e.to_string().contains("simulated crash"), "{e}");
        // 1. never a hard error, never a missing live segment, and everything still reads
        let (code, o) = run(&d, &["log", "verify", "ev"]);
        assert!(code <= 1, "{point:?}: {o}");
        assert!(
            !o.contains("segment-missing") && !o.contains("index-") && !o.contains("head-trunc"),
            "{point:?}: {o}"
        );
        assert_eq!(read_all(&d), want, "{point:?}");
        let idx_lines = index(&c).lines().count();
        match point {
            CrashPoint::AfterSegments | CrashPoint::AfterManifest => {
                assert_eq!(idx_lines, 1 + 5 + 1, "{point:?}: INDEX unchanged");
                assert!(seg(&c, 7).is_file(), "merged file is an orphan");
                let m = manifest(&c);
                assert!(m.contains("log=2"), "tombstone already raised it");
            }
            CrashPoint::AfterIndex => {
                assert_eq!(idx_lines, 1 + 5 + 1 + 1);
                assert!(o.contains("head-lag"), "{o}");
            }
            _ => assert_eq!(idx_lines, 1 + 5 + 1 + 1),
        }
        // 2. gc never deletes anything still needed, whatever the crash point
        let r = ok(&d, &["gc", "ev", "--apply", "--temp-age", "0"]);
        assert_eq!(read_all(&d), want, "{point:?}: after gc: {r}");
        if point == CrashPoint::AfterIndex {
            assert!(
                seg(&c, 1).is_file() && seg(&c, 7).is_file(),
                "entries beyond HEAD are not trusted to delete anything: {r}"
            );
        }
        // 3. re-running compact converges to a clean, healthy log
        ok(&d, &["log", "compact", "ev", "--apply"]);
        ok(&d, &["gc", "ev", "--apply", "--temp-age", "0"]);
        assert_eq!(read_all(&d), want, "{point:?}");
        let (code, o) = run(&d, &["log", "verify", "ev"]);
        assert_eq!(code, 0, "{point:?}: {o}");
        let live: Vec<u64> = (1..=12).filter(|s| seg(&c, *s).is_file()).collect();
        assert_eq!(live.len(), 1, "{point:?}: {live:?}");
        // the stale lock a real crash would leave only blocks until gc clears it
        fs::write(c.join("LOG.lock"), b"pid=1\n").unwrap();
        age(&c.join("LOG.lock"), 7200);
        ok(&d, &["gc", "ev", "--apply"]);
    }
}

#[test]
fn crash_after_head_leaves_superseded_files_that_gc_reclaims() {
    let d = tmp("crash-gc");
    let c = sample(&d, 4);
    seglog::compact(
        &c,
        &CompactOpts {
            apply: true,
            stop_after: Some(CrashPoint::AfterHead),
            ..Default::default()
        },
    )
    .unwrap_err();
    for s in 1..=4 {
        assert!(seg(&c, s).is_file());
    }
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 1, "{o}");
    assert!(
        o.contains("superseded-segment") && !o.contains("segment-missing"),
        "{o}"
    );
    let (code, o) = run(&d, &["doctor", "ev"]);
    assert_eq!(code, 1, "{o}");
    let r = ok(&d, &["gc", "ev"]);
    assert!(r.contains("dry run") && r.contains("superseded"), "{r}");
    assert!(seg(&c, 1).is_file(), "dry run");
    let r = ok(&d, &["gc", "ev", "--apply"]);
    assert!(r.contains("reclaimed 4 of"), "{r}");
    assert!(seg(&c, 5).is_file() && !seg(&c, 1).exists());
    assert_eq!(read_all(&d), "batch 1\nbatch 2\nbatch 3\nbatch 4\n");
    let (code, o) = run(&d, &["doctor", "ev", "--fix"]);
    assert_eq!(code, 0, "{o}");
    // doctor --fix on a fresh crash state erases the same dead files (and only those)
    let d2 = tmp("crash-fix");
    let c2 = sample(&d2, 3);
    ok(&d2, &["log", "tombstone", "ev", "--seq", "1"]);
    let (code, _) = run(&d2, &["doctor", "ev", "--fix"]);
    assert_eq!(code, 0);
    assert!(!seg(&c2, 1).exists() && seg(&c2, 2).is_file() && seg(&c2, 3).is_file());
}

#[test]
fn signed_log_tombstones_and_compaction() {
    let d = tmp("signed");
    ok(&d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    ok(&d, &["keygen", "-o", "eve.sgk", "--pub-out", "eve.pub"]);
    ok(&d, &["log", "init", "ev", "--identity", "me.sgk"]);
    for i in 1..=4 {
        fs::write(d.join("b.txt"), format!("batch {i}\n")).unwrap();
        ok(
            &d,
            &["log", "append", "ev", "b.txt", "--identity", "me.sgk"],
        );
    }
    let c = d.join("ev.sigil");
    // the tombstone is signed with the pinned key like every other entry
    assert!(fails(&d, &["log", "tombstone", "ev", "--seq", "2"]).contains("signed"));
    assert!(fails(
        &d,
        &[
            "log",
            "tombstone",
            "ev",
            "--seq",
            "2",
            "--identity",
            "eve.sgk"
        ]
    )
    .contains("not the key"));
    assert_eq!(index(&c).lines().count(), 5);
    let o = ok(
        &d,
        &[
            "log",
            "tombstone",
            "ev",
            "--seq",
            "2",
            "--identity",
            "me.sgk",
        ],
    );
    assert!(o.contains("(signed)"), "{o}");
    let v = run(&d, &["log", "verify", "ev", "--signer", "me.pub"]);
    assert_eq!(v.0, 1, "pending erasure only: {}", v.1);
    assert!(!v.1.contains("head-"), "{}", v.1);
    // forging a tombstone (valid chain, no key): HEAD does not cover it, so nothing is deleted on its say-so
    forge_line(&c, "seq=6 t=5 op=tomb del=3");
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 1, "{o}");
    assert!(o.contains("head-lag"), "{o}");
    ok(&d, &["gc", "ev", "--apply", "--temp-age", "0"]);
    assert!(
        seg(&c, 3).is_file(),
        "the forged tombstone beyond HEAD erased nothing"
    );
    assert!(
        !seg(&c, 2).exists(),
        "the signed tombstone's target was erased"
    );
    // compaction needs the key to re-cover, and refuses without it
    let e = fails(&d, &["log", "compact", "ev", "--apply"]);
    assert!(e.contains("signed") && e.contains("--identity"), "{e}");
    assert!(seg(&c, 3).is_file());
    // an attacker rewriting INDEX + HEAD cannot sign
    let idx = index(&c);
    let lines: Vec<&str> = idx.lines().collect();
    fs::write(
        c.join("INDEX"),
        format!("{}\n", lines[..lines.len() - 1].join("\n")),
    )
    .unwrap(); // drop the forged line again
               // sign-covered compaction
    ok(
        &d,
        &["log", "compact", "ev", "--apply", "--identity", "me.sgk"],
    );
    let (code, o) = run(&d, &["log", "verify", "ev", "--signer", "me.pub"]);
    assert_eq!(code, 0, "{o}");
    assert!(o.contains("signed"), "{o}");
    assert_eq!(read_all(&d), "batch 1\nbatch 3\nbatch 4\n");
    // strip the signature off the compaction's HEAD
    let good = fs::read_to_string(c.join("HEAD")).unwrap();
    let stripped: String = good
        .lines()
        .filter(|l| !l.starts_with("sig=") && !l.starts_with("signer="))
        .map(|l| format!("{l}\n"))
        .collect();
    fs::write(c.join("HEAD"), stripped).unwrap();
    assert!(run(&d, &["log", "verify", "ev"])
        .1
        .contains("head-unsigned"));
    // …and then neither gc nor compact will erase anything based on it
    let r = ok(&d, &["gc", "ev", "--apply", "--temp-age", "0"]);
    assert!(!r.contains("removed"), "{r}");
    fs::write(c.join("HEAD"), good).unwrap();
}

#[test]
fn encrypted_sources_are_never_silently_decrypted_by_compaction() {
    let d = tmp("enc");
    ok(&d, &["log", "init", "ev"]);
    for i in 1..=3 {
        fs::write(d.join("b.txt"), format!("secret {i}\n")).unwrap();
        ok(&d, &["log", "append", "ev", "b.txt", "--pass", "hunter2"]);
    }
    let c = d.join("ev.sigil");
    let before = snapshot(&c);
    // no key: cannot read the sources, nothing is written
    let e = fails(&d, &["log", "compact", "ev", "--apply"]);
    assert!(e.contains("segment"), "{e}");
    assert_eq!(
        snapshot(&c),
        before,
        "failed compaction leaves the tree untouched (no orphans)"
    );
    // key but no way to protect the output: refused
    let e = fails(
        &d,
        &["log", "compact", "ev", "--apply", "--pass", "hunter2"],
    );
    assert!(
        e.contains("in the clear") && e.contains("--seal-pass"),
        "{e}"
    );
    assert_eq!(snapshot(&c), before);
    // read key + seal passphrase works; the merged segment needs the new one
    ok(
        &d,
        &[
            "log",
            "compact",
            "ev",
            "--apply",
            "--pass",
            "hunter2",
            "--seal-pass",
            "s3cret",
        ],
    );
    fails(&d, &["log", "read", "ev", "--pass", "hunter2"]);
    assert_eq!(
        ok(&d, &["log", "read", "ev", "--pass", "s3cret", "--seq", "2"]),
        "secret 2\n"
    );
    // key-free verify is fine, keyed verify checks every member inside the merged segment
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 0, "{o}");
    let (code, o) = run(&d, &["log", "verify", "ev", "--pass", "s3cret"]);
    assert_eq!(code, 0, "{o}");
    // encrypt-to output
    let d2 = tmp("enc2");
    ok(&d2, &["keygen", "-o", "a.sgk", "--pub-out", "a.pub"]);
    ok(&d2, &["log", "init", "ev"]);
    for i in 1..=2 {
        fs::write(d2.join("b.txt"), format!("plain {i}\n")).unwrap();
        ok(&d2, &["log", "append", "ev", "b.txt"]);
    }
    ok(&d2, &["log", "compact", "ev", "--apply", "--to", "a.pub"]);
    fails(&d2, &["log", "read", "ev"]);
    assert_eq!(
        ok(
            &d2,
            &["log", "read", "ev", "--identity", "a.sgk", "--seq", "1"]
        ),
        "plain 1\n"
    );
    // explicit opt-out of the safety
    let d3 = tmp("enc3");
    ok(&d3, &["log", "init", "ev"]);
    for i in 1..=2 {
        fs::write(d3.join("b.txt"), format!("x{i}\n")).unwrap();
        ok(&d3, &["log", "append", "ev", "b.txt", "--pass", "p"]);
    }
    ok(
        &d3,
        &[
            "log",
            "compact",
            "ev",
            "--apply",
            "--pass",
            "p",
            "--allow-decrypt",
        ],
    );
    assert_eq!(ok(&d3, &["log", "read", "ev", "--seq", "2"]), "x2\n");
}

#[test]
fn keyed_verify_catches_a_compaction_that_does_not_match_its_members() {
    let d = tmp("lie");
    ok(&d, &["log", "init", "ev"]);
    for i in 1..=3 {
        fs::write(d.join("b.txt"), format!("batch {i}\n")).unwrap();
        ok(&d, &["log", "append", "ev", "b.txt", "--pass", "p"]);
    }
    let c = d.join("ev.sigil");
    // a "compaction" whose merged bytes are not the members' bytes, with a valid chain
    let fake = b"batch 1\nbatch 2\nBATCH 3\n";
    fs::write(d.join("fake.txt"), fake).unwrap();
    ok(&d, &["seal", "fake.txt", "-o", "fake.sg1", "--pass", "p"]);
    fs::copy(d.join("fake.sg1"), seg(&c, 4)).unwrap();
    let m = manifest(&c);
    fs::write(c.join("CONTAINER"), m.replace("log=1", "log=2")).unwrap();
    let digest = sigil::hex32(&sigil::sha256(fake));
    // a v3 (private-label) star binds to its entry by `star=`, its keyed fingerprint
    let star_bytes = fs::read(d.join("fake.sg1")).unwrap();
    let star = sigil::hex32(&sigil::locate_header(&star_bytes).unwrap().0.digest);
    forge_line(
        &c,
        &format!("seq=4 t=5 size=24 sha={digest} op=compact of=1-3 star={star}"),
    );
    // keyless verify cannot see content: the star's own digest matches the INDEX
    let (_code, o) = run(&d, &["log", "verify", "ev"]);
    assert!(!o.contains("segment-digest"), "{o}");
    // keyed verify compares every member with the INDEX
    let (code, o) = run(&d, &["log", "verify", "ev", "--pass", "p"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("segment-content"), "{o}");
    // and a read of a member refuses to hand out the mismatching bytes
    let e = fails(&d, &["log", "read", "ev", "--seq", "3", "--pass", "p"]);
    assert!(e.contains("does not match the index"), "{e}");
}

#[test]
fn mend_covers_compaction_segments_and_skips_dead_files() {
    let d = tmp("mend");
    let c = sample(&d, 4);
    ok(&d, &["log", "tombstone", "ev", "--seq", "1"]);
    ok(&d, &["log", "compact", "ev", "--apply"]);
    let live: Vec<u64> = (1..=8).filter(|s| seg(&c, *s).is_file()).collect();
    assert_eq!(live.len(), 1);
    let p = seg(&c, live[0]);
    let good = fs::read(&p).unwrap();
    let mut b = good.clone();
    let mid = b.len() / 2;
    b[mid..mid + 8].fill(0);
    fs::write(&p, b).unwrap();
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 1, "{o}");
    assert!(o.contains("bit-rot"), "{o}");
    let o = ok(&d, &["log", "mend", "ev"]);
    assert!(o.contains("healed 1"), "{o}");
    assert_eq!(fs::read(&p).unwrap(), good);
    // mend does not complain about the erased / merged-away files
    assert!(!o.contains("missing"), "{o}");
    assert_eq!(read_all(&d), "batch 2\nbatch 3\nbatch 4\n");
}

#[test]
fn compact_and_tombstone_refuse_on_a_damaged_log_and_never_touch_live_files() {
    let d = tmp("refuse");
    let c = sample(&d, 4);
    let idx = index(&c);
    fs::write(c.join("INDEX"), idx.replace("size=8", "size=9")).unwrap();
    assert!(fails(&d, &["log", "compact", "ev", "--apply"]).contains("refusing"));
    assert!(fails(&d, &["log", "tombstone", "ev", "--seq", "1"]).contains("damaged"));
    fs::write(c.join("INDEX"), idx).unwrap();
    assert!(manifest(&c).contains("log=1"));
    // a live segment file is never an erase candidate even when its neighbours are dead
    ok(&d, &["log", "tombstone", "ev", "--seq", "1"]);
    let r = ok(&d, &["gc", "ev", "--apply"]);
    assert!(r.contains("deleted segment"), "{r}");
    for s in 2..=4 {
        assert!(seg(&c, s).is_file(), "segment {s} is live");
    }
    assert!(!seg(&c, 1).exists());
    // stale lock blocks compaction (like append) and gc clears it
    fs::write(c.join("LOG.lock"), b"pid=1\n").unwrap();
    assert!(fails(&d, &["log", "compact", "ev", "--apply"]).contains("LOG.lock"));
    assert!(fails(&d, &["log", "tombstone", "ev", "--seq", "2"]).contains("LOG.lock"));
    // dry-run needs no lock
    ok(&d, &["log", "compact", "ev"]);
    age(&c.join("LOG.lock"), 7200);
    ok(&d, &["gc", "ev", "--apply"]);
    ok(&d, &["log", "compact", "ev", "--apply"]);
}
