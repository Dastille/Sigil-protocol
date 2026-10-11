//! Segment log slice 3: per-segment keys (`init --segment-keys`) and crypto-shredding
//! (`sigil log shred`): the opt-in / `log=3` rule, key ring round trip, shred (read fails clearly,
//! verify + anchors stay valid), compaction and gc / doctor / mend after a shred, signed logs,
//! interrupted shreds, and that plain logs are untouched.
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

fn run(dir: &Path, args: &[&str]) -> (i32, String) {
    let o = sigil_cmd(dir, args);
    (o.status.code().unwrap_or(-1), text(&o))
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sigil-seglog3-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn seg(c: &Path, seq: u64) -> PathBuf {
    seglog::segment_path(c, seq)
}

fn ring(c: &Path) -> PathBuf {
    c.join("keys").join("0000.sg1")
}

fn manifest(c: &Path) -> String {
    fs::read_to_string(c.join("CONTAINER")).unwrap()
}

fn index(c: &Path) -> String {
    fs::read_to_string(c.join("INDEX")).unwrap()
}

fn snapshot(c: &Path) -> BTreeMap<String, Vec<u8>> {
    fn walk(root: &Path, p: &Path, out: &mut BTreeMap<String, Vec<u8>>) {
        for e in fs::read_dir(p).unwrap().flatten() {
            let path = e.path();
            if path.is_dir() {
                walk(root, &path, out);
            } else {
                out.insert(path.strip_prefix(root).unwrap().display().to_string(), fs::read(&path).unwrap());
            }
        }
    }
    let mut m = BTreeMap::new();
    walk(c, c, &mut m);
    m
}

fn files(c: &Path) -> Vec<String> {
    snapshot(c).into_keys().collect()
}

fn anchor(d: &Path) -> String {
    let ls = ok(d, &["log", "ls", "ev"]);
    let l = ls.lines().find(|l| l.starts_with("anchor")).unwrap();
    l.rsplit(' ').next().unwrap().to_string()
}

fn age(p: &Path, secs: u64) {
    let f = fs::OpenOptions::new().write(true).open(p).or_else(|_| fs::File::open(p)).unwrap();
    f.set_modified(SystemTime::now() - Duration::from_secs(secs)).unwrap();
}

/// A segment-keys log `ev` with batches "batch 1\n" … "batch N\n", each key wrapped to a.pub.
fn sample(d: &Path, n: u64) -> PathBuf {
    ok(d, &["keygen", "-o", "a.sgk", "--pub-out", "a.pub"]);
    ok(d, &["log", "init", "ev", "--segment-keys"]);
    for i in 1..=n {
        fs::write(d.join("b.txt"), format!("batch {i}\n")).unwrap();
        ok(d, &["log", "append", "ev", "b.txt", "--to", "a.pub"]);
    }
    d.join("ev.sigil")
}

fn read_keyed(d: &Path, extra: &[&str]) -> String {
    let mut a = vec!["log", "read", "ev", "--identity", "a.sgk"];
    a.extend_from_slice(extra);
    let o = sigil_cmd(d, &a);
    assert!(o.status.success(), "{}", text(&o));
    String::from_utf8_lossy(&o.stdout).into_owned()
}

#[test]
fn per_segment_keys_are_opt_in_and_bump_the_format_only_at_init() {
    let d = tmp("optin");
    ok(&d, &["log", "init", "plain"]);
    let p = d.join("plain.sigil");
    let m = manifest(&p);
    assert!(m.contains("\nlog=1\n") && !m.contains("segkeys"), "{m}");
    assert!(!p.join("keys").exists(), "a plain log never grows a keys/ folder");
    // exactly the slice-1 manifest: the new feature adds no key to a log that does not use it
    let keys: Vec<&str> = m.lines().map(|l| l.split('=').next().unwrap()).collect();
    assert_eq!(keys, vec!["sigil-container", "kind", "name", "log", "log-id"], "{m}");
    fs::write(d.join("b.txt"), "x\n").unwrap();
    ok(&d, &["log", "append", "plain", "b.txt"]);
    assert!(!p.join("keys").exists());
    // a plain log has no key to destroy: refused, nothing touched
    let before = snapshot(&p);
    let e = fails(&d, &["log", "shred", "plain", "--seq", "1"]);
    assert!(e.contains("no per-segment keys") && e.contains("--segment-keys"), "{e}");
    assert_eq!(snapshot(&p), before);
    // …and its plain tombstone path still works and still gives log=2, not 3
    ok(&d, &["log", "tombstone", "plain", "--seq", "1"]);
    assert!(manifest(&p).contains("\nlog=2\n") && !manifest(&p).contains("segkeys"));
    // the opt-in log is log=3 from its first byte (the feature's first use)
    ok(&d, &["log", "init", "ev", "--segment-keys"]);
    let c = d.join("ev.sigil");
    let m = manifest(&c);
    assert!(m.contains("\nlog=3\n") && m.contains("\nsegkeys=1\n"), "{m}");
    assert!(c.join("keys").is_dir());
    assert!(run(&d, &["log", "verify", "ev"]).0 == 0);
}

#[test]
fn round_trip_with_recipients_and_passphrase() {
    let d = tmp("rt");
    let c = sample(&d, 3);
    // the layout: one container, keys/ next to segments/, nothing loose
    assert_eq!(
        files(&c),
        vec![
            "CONTAINER",
            "HEAD",
            "INDEX",
            "keys/0000.sg1",
            "segments/0000/0000000001.sg1",
            "segments/0000/0000000002.sg1",
            "segments/0000/0000000003.sg1"
        ]
    );
    assert!(!index(&c).contains("op="), "segment lines look exactly like slice 1");
    assert_eq!(read_keyed(&d, &[]), "batch 1\nbatch 2\nbatch 3\n");
    assert_eq!(read_keyed(&d, &["--seq", "2"]), "batch 2\n");
    // not readable without the key, with a clear message
    let e = fails(&d, &["log", "read", "ev"]);
    assert!(e.contains("cannot open the key of segment 1") && e.contains("--pass / --identity"), "{e}");
    // a segment on its own is sealed to a key nobody holds: plain unseal cannot open it
    let bytes = fs::read(seg(&c, 1)).unwrap();
    assert!(sigil::unseal(&bytes, None).is_err());
    assert!(sigil::unseal(&bytes, Some("anything")).is_err());
    // another identity cannot open it
    ok(&d, &["keygen", "-o", "eve.sgk", "--pub-out", "eve.pub"]);
    let e = fails(&d, &["log", "read", "ev", "--identity", "eve.sgk"]);
    assert!(e.contains("cannot open the key of segment 1"), "{e}");
    // a passphrase wraps the key just as well (and a log can mix wraps per append)
    fs::write(d.join("b.txt"), "batch 4\n").unwrap();
    ok(&d, &["log", "append", "ev", "b.txt", "--pass", "hunter2"]);
    assert_eq!(ok(&d, &["log", "read", "ev", "--pass", "hunter2", "--seq", "4"]), "batch 4\n");
    fails(&d, &["log", "read", "ev", "--pass", "wrong", "--seq", "4"]);
    // pass + --to together: either opens it
    fs::write(d.join("b.txt"), "batch 5\n").unwrap();
    ok(&d, &["log", "append", "ev", "b.txt", "--pass", "p2", "--to", "a.pub"]);
    assert_eq!(ok(&d, &["log", "read", "ev", "--pass", "p2", "--seq", "5"]), "batch 5\n");
    assert_eq!(read_keyed(&d, &["--seq", "5"]), "batch 5\n");
    // keyless and keyed verify (full ECC) both pass
    assert_eq!(run(&d, &["log", "verify", "ev"]).0, 0);
    let (code, o) = run(&d, &["log", "verify", "ev", "--identity", "a.sgk", "--pass", "hunter2"]);
    assert_eq!(code, 0, "segments 1-3 open with a.sgk, 4 with the passphrase, 5 with either: {o}");
    let (code, o) = run(&d, &["log", "verify", "ev", "--identity", "a.sgk"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("segment-unseal") && o.contains("segment 4"), "{o}");
}

#[test]
fn append_without_a_way_to_wrap_the_key_is_refused_and_writes_nothing() {
    let d = tmp("nowrap");
    let c = sample(&d, 1);
    let before = snapshot(&c);
    fs::write(d.join("b.txt"), "more\n").unwrap();
    let e = fails(&d, &["log", "append", "ev", "b.txt"]);
    assert!(e.contains("per-segment keys") && e.contains("--pass") && e.contains("--to"), "{e}");
    assert_eq!(snapshot(&c), before);
}

#[test]
fn shred_makes_the_segment_unreadable_but_the_log_still_verifies_and_anchors_hold() {
    let d = tmp("shred");
    let c = sample(&d, 4);
    let anchor_before = anchor(&d);
    let index_before = index(&c);
    let ring_before = fs::read(ring(&c)).unwrap();
    let ct_before = fs::read(seg(&c, 2)).unwrap();
    let o = ok(&d, &["log", "shred", "ev", "--seq", "2", "--reason", "gdpr request 42"]);
    assert!(o.contains("shred 5") && o.contains("1 key record(s) destroyed") && o.contains("1 ciphertext file(s) unlinked"), "{o}");
    assert!(o.contains("Copies of the key"), "the honest caveat is printed: {o}");
    // the INDEX was only appended to (every earlier byte intact)
    let idx = index(&c);
    assert!(idx.starts_with(&index_before));
    let last = idx.lines().last().unwrap();
    assert!(last.contains("op=tomb del=2 shred=1 reason=gdpr%20request%2042"), "{last}");
    // key record and ciphertext are gone; nothing else changed on disk
    assert_ne!(fs::read(ring(&c)).unwrap(), ring_before);
    assert!(!seg(&c, 2).exists() && seg(&c, 1).is_file() && seg(&c, 3).is_file());
    assert!(!files(&c).iter().any(|f| f.ends_with(".part")), "no scrub / temp leftovers: {:?}", files(&c));
    // reads: clear error for the shredded one, others fine
    let e = fails(&d, &["log", "read", "ev", "--identity", "a.sgk", "--seq", "2"]);
    assert!(e.contains("crypto-shredded") && e.contains("entry #5") && e.contains("gdpr request 42") && e.contains("cannot be recovered"), "{e}");
    assert_eq!(read_keyed(&d, &[]), "batch 1\nbatch 3\nbatch 4\n");
    let e = fails(&d, &["log", "read", "ev", "--identity", "a.sgk", "--strict"]);
    assert!(e.contains("crypto-shredded"), "{e}");
    // ls says so
    let ls = ok(&d, &["log", "ls", "ev"]);
    assert!(ls.contains("SHREDDED (entry #5)") && ls.contains("crypto-shred: deletes 2") && ls.contains("1 shredded"), "{ls}");
    // verify passes, keyless and keyed, even the full ECC pass; nothing is "missing" or "damaged"
    for args in [vec!["log", "verify", "ev"], vec!["log", "verify", "ev", "--identity", "a.sgk"]] {
        let (code, o) = run(&d, &args);
        assert_eq!(code, 0, "{o}");
        assert!(!o.contains("segment-missing") && !o.contains("key-missing") && !o.contains("bit-rot"), "{o}");
        assert!(o.contains("shreds"), "{o}");
    }
    let (code, o) = run(&d, &["doctor", "ev"]);
    assert_eq!(code, 0, "{o}");
    // the anchor pinned before the shred still verifies, and so does the new one
    let (code, o) = run(&d, &["log", "verify", "ev", "--anchor", &anchor_before]);
    assert_eq!(code, 0, "{o}");
    let (code, o) = run(&d, &["log", "verify", "ev", "--anchor", &anchor(&d)]);
    assert_eq!(code, 0, "{o}");
    // mend has nothing to do for a shredded segment and does not report it missing
    let o = ok(&d, &["log", "mend", "ev"]);
    assert!(o.contains("checked 3 segment(s), healed 0") && !o.contains("missing"), "{o}");
    // shredding twice, or an entry that is not a segment, is an error and changes nothing
    let snap = snapshot(&c);
    assert!(fails(&d, &["log", "shred", "ev", "--seq", "2"]).contains("already shredded"));
    assert!(fails(&d, &["log", "shred", "ev", "--seq", "5"]).contains("tombstone record"));
    assert!(fails(&d, &["log", "shred", "ev", "--seq", "99"]).contains("does not exist"));
    assert_eq!(snapshot(&c), snap);
    // a restored copy of the old ciphertext (a backup) stays unreadable without its key: the
    // ring has no record any more, and the log refuses to read it anyway
    fs::create_dir_all(seg(&c, 2).parent().unwrap()).unwrap();
    fs::write(seg(&c, 2), &ct_before).unwrap();
    let e = fails(&d, &["log", "read", "ev", "--identity", "a.sgk", "--seq", "2"]);
    assert!(e.contains("crypto-shredded"), "{e}");
    let (code, o) = run(&d, &["log", "verify", "ev", "--identity", "a.sgk"]);
    assert_eq!(code, 0, "a shredded file lying around is not damage: {o}");
    assert!(o.contains("shredded-segment") && !o.contains("segment-digest"), "{o}");
    let r = ok(&d, &["gc", "ev", "--apply"]);
    assert!(r.contains("deleted segment") && !seg(&c, 2).exists(), "{r}");
}

#[test]
fn shred_range_and_the_honest_limit_of_a_restored_key_ring() {
    let d = tmp("range");
    let c = sample(&d, 6);
    let ring_backup = fs::read(ring(&c)).unwrap();
    let ct2 = fs::read(seg(&c, 2)).unwrap();
    let o = ok(&d, &["log", "shred", "ev", "--from", "2", "--to", "4"]);
    assert!(o.contains("segment(s) 2-4"), "{o}");
    assert_eq!(read_keyed(&d, &[]), "batch 1\nbatch 5\nbatch 6\n");
    // The honest limit: someone who kept a copy of the key ring AND of the ciphertext before the
    // shred can still decrypt it by hand. sigil's own reads refuse, and verify says the shred is
    // incomplete here.
    fs::write(ring(&c), &ring_backup).unwrap();
    fs::write(seg(&c, 2), &ct2).unwrap();
    let e = fails(&d, &["log", "read", "ev", "--identity", "a.sgk", "--seq", "2"]);
    assert!(e.contains("crypto-shredded"), "{e}");
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 1, "{o}");
    assert!(o.contains("shred-key-present"), "{o}");
    // gc finishes the job (the same thing an interrupted shred needs)
    let dry = ok(&d, &["gc", "ev"]);
    assert!(dry.contains("dead key(s)") && dry.contains("2-4"), "{dry}");
    assert!(fs::read(ring(&c)).unwrap() == ring_backup, "dry run changes nothing");
    let r = ok(&d, &["gc", "ev", "--apply"]);
    assert!(r.contains("removed") && r.contains("dead key(s)"), "{r}");
    assert_eq!(run(&d, &["log", "verify", "ev"]).0, 0);
    assert_eq!(read_keyed(&d, &[]), "batch 1\nbatch 5\nbatch 6\n");
}

#[test]
fn compaction_after_a_shred_drops_dead_files_and_keys_and_keeps_anchors() {
    let d = tmp("compact");
    let c = sample(&d, 5);
    let a0 = anchor(&d);
    ok(&d, &["log", "shred", "ev", "--seq", "3"]);
    let a1 = anchor(&d);
    // dry run changes nothing
    let before = snapshot(&c);
    let o = ok(&d, &["log", "compact", "ev"]);
    assert!(o.contains("new segment 7") && o.contains("dry run"), "{o}");
    assert_eq!(snapshot(&c), before);
    // the merged segment gets its own key, wrapped like any append: say how
    let e = fails(&d, &["log", "compact", "ev", "--apply", "--identity", "a.sgk"]);
    assert!(e.contains("per-segment keys") && e.contains("--seal-pass") && e.contains("--to"), "{e}");
    assert_eq!(snapshot(&c), before, "failed compaction leaves no orphan file or key");
    let o = ok(&d, &["log", "compact", "ev", "--apply", "--identity", "a.sgk", "--to", "a.pub"]);
    assert!(o.contains("key record(s) destroyed"), "{o}");
    // only the merged segment (and its key) remain
    let live: Vec<u64> = (1..=8).filter(|s| seg(&c, *s).is_file()).collect();
    assert_eq!(live, vec![7]);
    assert_eq!(read_keyed(&d, &[]), "batch 1\nbatch 2\nbatch 4\nbatch 5\n");
    assert!(fails(&d, &["log", "read", "ev", "--identity", "a.sgk", "--seq", "3"]).contains("crypto-shredded"));
    for a in [&a0, &a1] {
        let (code, o) = run(&d, &["log", "verify", "ev", "--anchor", a, "--identity", "a.sgk"]);
        assert_eq!(code, 0, "{o}");
    }
    // gc / doctor are happy: nothing left to reclaim, no dead keys
    let r = ok(&d, &["gc", "ev"]);
    assert!(r.contains("nothing to reclaim"), "{r}");
    assert_eq!(run(&d, &["doctor", "ev"]).0, 0);
    // the new key is the only record in the ring: a stale copy of the old ring would hold more
    let o = ok(&d, &["log", "verify", "ev", "--identity", "a.sgk", "--anchor", &anchor(&d)]);
    assert!(o.contains("healthy"), "{o}");
}

#[test]
fn a_member_of_a_compaction_segment_can_only_be_shredded_with_its_siblings() {
    let d = tmp("merged");
    let c = sample(&d, 4);
    ok(&d, &["log", "compact", "ev", "--apply", "--identity", "a.sgk", "--to", "a.pub"]);
    assert!(seg(&c, 5).is_file());
    let before = snapshot(&c);
    let e = fails(&d, &["log", "shred", "ev", "--seq", "2"]);
    assert!(e.contains("compaction segment 5") && e.contains("share one key") && e.contains("tombstone"), "{e}");
    assert_eq!(snapshot(&c), before);
    // all of them together: the merged file's key is destroyed and the file goes
    let o = ok(&d, &["log", "shred", "ev", "--from", "1", "--to", "4"]);
    assert!(o.contains("1 key record(s) destroyed") && o.contains("1 ciphertext file(s) unlinked"), "{o}");
    assert!(!seg(&c, 5).exists());
    assert_eq!(run(&d, &["log", "verify", "ev"]).0, 0);
    // nothing readable is left
    let (code, o) = run(&d, &["log", "read", "ev", "--identity", "a.sgk"]);
    assert_eq!(code, 0, "{o}");
    assert!(o.contains("skipped 4 deleted"), "{o}");
}

#[test]
fn plain_tombstone_then_compact_also_destroys_the_old_key_and_a_tombstone_can_be_hardened() {
    let d = tmp("tomb");
    let c = sample(&d, 3);
    ok(&d, &["log", "tombstone", "ev", "--seq", "1"]);
    // the tombstoned segment is still on disk and keyed: shred hardens it
    assert!(seg(&c, 1).is_file());
    let o = ok(&d, &["log", "shred", "ev", "--seq", "1"]);
    assert!(o.contains("1 key record(s) destroyed"), "{o}");
    assert!(!seg(&c, 1).exists());
    // tombstone + compact: the key goes with the file
    ok(&d, &["log", "tombstone", "ev", "--seq", "2"]);
    let o = ok(&d, &["log", "compact", "ev", "--apply", "--identity", "a.sgk", "--to", "a.pub"]);
    assert!(o.contains("key record(s) destroyed"), "{o}");
    assert_eq!(read_keyed(&d, &[]), "batch 3\n");
    assert_eq!(run(&d, &["log", "verify", "ev", "--identity", "a.sgk"]).0, 0);
    assert_eq!(run(&d, &["gc", "ev"]).0, 0);
}

#[test]
fn compaction_crash_leaves_an_orphan_key_that_gc_reclaims() {
    let d = tmp("orphankey");
    let c = sample(&d, 3);
    ok(&d, &["log", "tombstone", "ev", "--seq", "2"]);
    let e = seglog::compact(
        &c,
        &CompactOpts {
            apply: true,
            stop_after: Some(CrashPoint::AfterSegments),
            recipients: &[sigil::PublicIdentity::load(&d.join("a.pub")).unwrap()],
            read: seglog::ReadOpts { pass: None, identities: &[sigil::Identity::load(&d.join("a.sgk")).unwrap()] },
            ..Default::default()
        },
    )
    .unwrap_err();
    assert!(e.to_string().contains("simulated crash"), "{e}");
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 1, "{o}");
    assert!(o.contains("orphan-key") && !o.contains("key-missing"), "{o}");
    assert_eq!(read_keyed(&d, &[]), "batch 1\nbatch 3\n");
    // the key of the merged file is only reclaimed together with its orphan file, never while an append could be mid-flight
    let r = ok(&d, &["gc", "ev", "--apply", "--temp-age", "0"]);
    assert!(r.contains("dead key(s)"), "{r}");
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 0, "{o}");
    assert_eq!(read_keyed(&d, &[]), "batch 1\nbatch 3\n");
}

#[test]
fn signed_log_shred_is_signed_and_needs_the_pinned_key() {
    let d = tmp("signed");
    ok(&d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    ok(&d, &["keygen", "-o", "eve.sgk", "--pub-out", "eve.pub"]);
    ok(&d, &["log", "init", "ev", "--identity", "me.sgk", "--segment-keys"]);
    for i in 1..=3 {
        fs::write(d.join("b.txt"), format!("batch {i}\n")).unwrap();
        ok(&d, &["log", "append", "ev", "b.txt", "--identity", "me.sgk", "--to", "me.pub"]);
    }
    let c = d.join("ev.sigil");
    let snap = snapshot(&c);
    assert!(fails(&d, &["log", "shred", "ev", "--seq", "2"]).contains("signed"));
    assert!(fails(&d, &["log", "shred", "ev", "--seq", "2", "--identity", "eve.sgk"]).contains("not the key"));
    assert_eq!(snapshot(&c), snap, "a refused shred changes nothing — the key is still there");
    let o = ok(&d, &["log", "shred", "ev", "--seq", "2", "--identity", "me.sgk"]);
    assert!(o.contains("(signed)"), "{o}");
    let (code, o) = run(&d, &["log", "verify", "ev", "--signer", "me.pub", "--identity", "me.sgk"]);
    assert_eq!(code, 0, "{o}");
    let o = ok(&d, &["log", "read", "ev", "--identity", "me.sgk"]);
    assert_eq!(o.lines().filter(|l| l.starts_with("batch")).collect::<Vec<_>>(), vec!["batch 1", "batch 3"]);
    // a forged shred line (valid chain, no signature) is not covered by HEAD: no key is destroyed on its say-so
    let idx = index(&c);
    let prev = idx.lines().last().unwrap().rsplit_once(" chain=").unwrap().1.to_string();
    let body = "seq=5 t=5 op=tomb del=3 shred=1";
    let mut b = b"sigil-log-entry-v1\0".to_vec();
    b.extend_from_slice(&hex::decode(prev).unwrap());
    b.extend_from_slice(body.as_bytes());
    fs::write(c.join("INDEX"), format!("{idx}{body} chain={}\n", hex::encode(sigil::sha256(&b)))).unwrap();
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 1, "{o}");
    assert!(o.contains("head-lag"), "{o}");
    ok(&d, &["gc", "ev", "--apply", "--temp-age", "0"]);
    assert!(seg(&c, 3).is_file(), "the forged shred beyond HEAD erased nothing");
    // reads honour the forged line like any unsigned tombstone, but the key is still in the ring
    fs::write(c.join("INDEX"), &idx).unwrap();
    assert_eq!(ok(&d, &["log", "read", "ev", "--identity", "me.sgk", "--seq", "3"]), "batch 3\n");
}

#[test]
fn shred_entries_in_a_log_without_segment_keys_are_damage_not_data() {
    let d = tmp("forged");
    ok(&d, &["log", "init", "ev"]);
    fs::write(d.join("b.txt"), "x\n").unwrap();
    ok(&d, &["log", "append", "ev", "b.txt"]);
    let c = d.join("ev.sigil");
    // hand-forged: log=2 manifest, shred line
    fs::write(c.join("CONTAINER"), manifest(&c).replace("log=1", "log=2")).unwrap();
    let idx = index(&c);
    let prev = idx.lines().last().unwrap().rsplit_once(" chain=").unwrap().1.to_string();
    let body = "seq=2 t=5 op=tomb del=1 shred=1";
    let mut b = b"sigil-log-entry-v1\0".to_vec();
    b.extend_from_slice(&hex::decode(prev).unwrap());
    b.extend_from_slice(body.as_bytes());
    fs::write(c.join("INDEX"), format!("{idx}{body} chain={}\n", hex::encode(sigil::sha256(&b)))).unwrap();
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("log-format") && o.contains("no per-segment keys"), "{o}");
}

#[test]
fn key_ring_damage_is_healed_by_mend_and_a_lost_ring_is_reported_not_guessed() {
    let d = tmp("ringdamage");
    let c = sample(&d, 3);
    let good = fs::read(ring(&c)).unwrap();
    // flip a few bytes inside the ECC budget
    let mut bad = good.clone();
    for i in 0..3 {
        let at = bad.len() / 2 + i * 7;
        bad[at] ^= 0xff;
    }
    fs::write(ring(&c), &bad).unwrap();
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert!(code <= 1, "{o}");
    // reading still works (the ring is a normal ECC star)
    assert_eq!(read_keyed(&d, &["--seq", "1"]), "batch 1\n");
    let (_, o2) = run(&d, &["log", "verify", "ev", "--identity", "a.sgk"]);
    assert!(o.contains("bit-rot") || o2.contains("bit-rot") || code == 0, "{o}{o2}");
    ok(&d, &["log", "mend", "ev"]);
    assert_eq!(run(&d, &["log", "verify", "ev"]).0, 0);
    assert_eq!(fs::read(ring(&c)).unwrap(), good, "mend restored the exact bytes");
    // the whole ring gone: every segment reports a missing key; nothing is invented
    fs::remove_file(ring(&c)).unwrap();
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("key-missing"), "{o}");
    let e = fails(&d, &["log", "read", "ev", "--identity", "a.sgk"]);
    assert!(e.contains("no key in the key ring"), "{e}");
    // garbage in place of the ring: reported, never panics
    fs::write(ring(&c), b"not a star").unwrap();
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("keyring-damaged"), "{o}");
    let (code, o) = run(&d, &["gc", "ev", "--apply"]);
    assert_eq!(code, 0, "gc does not touch an unreadable ring: {o}");
    assert_eq!(fs::read(ring(&c)).unwrap(), b"not a star");
}

#[test]
fn stray_files_in_keys_are_left_alone_and_abandoned_temp_files_are_reclaimed() {
    let d = tmp("strays");
    let c = sample(&d, 2);
    fs::write(c.join("keys").join("notes.txt"), "mine").unwrap();
    let stale = c.join("keys").join("0000.sg1.scrub.part");
    fs::write(&stale, "leftover").unwrap();
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 0, "{o}");
    assert!(o.contains("unknown-file") && o.contains("notes.txt"), "{o}");
    age(&stale, 7200);
    let r = ok(&d, &["gc", "ev", "--apply"]);
    assert!(r.contains("temp file") && !stale.exists(), "{r}");
    assert!(c.join("keys").join("notes.txt").is_file(), "unknown files are never deleted");
}

#[test]
fn newer_log_format_is_still_refused() {
    let d = tmp("newer");
    let c = sample(&d, 2);
    fs::write(c.join("CONTAINER"), manifest(&c).replace("log=3", "log=9")).unwrap();
    for args in [vec!["log", "ls", "ev"], vec!["log", "shred", "ev", "--seq", "1"], vec!["gc", "ev"]] {
        let e = fails(&d, &args);
        assert!(e.contains("newer than this sigil") && e.contains("upgrade"), "{args:?}: {e}");
    }
}
