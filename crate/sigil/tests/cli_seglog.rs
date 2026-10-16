//! Segment log (`sigil log …`): append / ls / read / verify / mend, tamper detection,
//! signing, crash recovery, and that gc / doctor understand log containers.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};
use std::time::{Duration, SystemTime};

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

/// (exit code, output)
fn run(dir: &Path, args: &[&str]) -> (i32, String) {
    let o = sigil_cmd(dir, args);
    (o.status.code().unwrap_or(-1), text(&o))
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sigil-seglog-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
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

fn seg(c: &Path, seq: u64) -> PathBuf {
    sigil::seglog::segment_path(c, seq)
}

/// log with `n` text segments "batch N\n", unsigned.
fn sample(dir: &Path, n: u64) -> PathBuf {
    ok(dir, &["log", "init", "ev"]);
    for i in 1..=n {
        fs::write(dir.join("b.txt"), format!("batch {i}\n")).unwrap();
        ok(dir, &["log", "append", "ev", "b.txt"]);
    }
    dir.join("ev.sigil")
}

fn zero_mid(p: &Path, len: usize) {
    let mut b = fs::read(p).unwrap();
    let mid = b.len() / 2;
    b[mid..mid + len].fill(0);
    fs::write(p, b).unwrap();
}

fn head_of(c: &Path) -> String {
    fs::read_to_string(c.join("HEAD")).unwrap()
}

#[test]
fn init_append_ls_read_verify() {
    let d = tmp("basic");
    let c = sample(&d, 3);
    assert!(c.join("CONTAINER").is_file() && c.join("INDEX").is_file() && c.join("HEAD").is_file());
    let m = fs::read_to_string(c.join("CONTAINER")).unwrap();
    assert!(
        m.contains("sigil-container=1") && m.contains("kind=log") && m.contains("name=ev"),
        "{m}"
    );
    for s in 1..=3 {
        assert!(seg(&c, s).is_file());
    }
    // stdin append
    let o = Command::new("sh")
        .current_dir(&d)
        .arg("-c")
        .arg(format!(
            "printf 'from stdin\\n' | {} log append ev -",
            env!("CARGO_BIN_EXE_sigil")
        ))
        .output()
        .unwrap();
    assert!(o.status.success(), "{}", text(&o));
    let ls = ok(&d, &["log", "ls", "ev"]);
    assert!(
        ls.contains("entries=4") && ls.contains("unsigned") && ls.contains("anchor"),
        "{ls}"
    );
    assert_eq!(ok(&d, &["log", "read", "ev", "--seq", "2"]), "batch 2\n");
    assert_eq!(
        ok(&d, &["log", "read", "ev", "--from", "2", "--to", "3"]),
        "batch 2\nbatch 3\n"
    );
    assert_eq!(
        ok(&d, &["log", "read", "ev"]),
        "batch 1\nbatch 2\nbatch 3\nfrom stdin\n"
    );
    ok(&d, &["log", "read", "ev", "--seq", "4", "-o", "out.bin"]);
    assert_eq!(fs::read(d.join("out.bin")).unwrap(), b"from stdin\n");
    let v = ok(&d, &["log", "verify", "ev"]);
    assert!(
        v.contains("result: healthy") && v.contains("4 segment"),
        "{v}"
    );
    // the segment is an ordinary star: plain `sigil` tools open it
    ok(
        &d,
        &["unseal", seg(&c, 1).to_str().unwrap(), "-o", "one.txt"],
    );
    assert_eq!(fs::read(d.join("one.txt")).unwrap(), b"batch 1\n");
    // `sigil ls` shows the log
    assert!(ok(&d, &["ls", "ev"]).contains("entries=4"));
    // bad ranges
    fails(&d, &["log", "read", "ev", "--seq", "9"]);
    fails(&d, &["log", "read", "ev", "--from", "3", "--to", "2"]);
    // init refuses to clobber
    fails(&d, &["log", "init", "ev"]);
    fails(&d, &["log", "append", "nothere", "b.txt"]);
}

#[test]
fn tamper_detection_unsigned_and_anchor() {
    let d = tmp("tamper");
    let c = sample(&d, 3);
    let ls = ok(&d, &["log", "ls", "ev"]);
    let anchor = ls
        .lines()
        .find_map(|l| l.strip_prefix("anchor (pin elsewhere, check with `verify --anchor`): "))
        .unwrap()
        .to_string();
    ok(&d, &["log", "verify", "ev", "--anchor", &anchor]);
    let good_index = fs::read_to_string(c.join("INDEX")).unwrap();
    let good_head = head_of(&c);

    // edit an entry's size in place → chain breaks
    fs::write(c.join("INDEX"), good_index.replacen("size=8", "size=9", 1)).unwrap();
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("index-chain"), "{o}");
    fails(&d, &["log", "read", "ev", "--seq", "2"]);
    fails(&d, &["log", "append", "ev", "b.txt"]);
    fs::write(c.join("INDEX"), &good_index).unwrap();

    // cut the last entry off the INDEX (HEAD still says 3) → truncation
    let cut: String = good_index
        .lines()
        .take(3)
        .map(|l| format!("{l}\n"))
        .collect();
    fs::write(c.join("INDEX"), &cut).unwrap();
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("head-truncated"), "{o}");
    fails(&d, &["log", "append", "ev", "b.txt"]);
    // gc refuses while HEAD is ahead of INDEX (the cut segment is still live data)
    let e = fails(&d, &["gc", "ev", "--apply", "--temp-age", "0"]);
    assert!(e.contains("gc refuses"), "{e}");
    assert!(seg(&c, 3).is_file());

    // consistent rollback (INDEX + HEAD both cut to 2): unsigned log can't notice, the anchor does
    let two: String = good_index
        .lines()
        .take(3)
        .map(|l| format!("{l}\n"))
        .collect();
    fs::write(c.join("INDEX"), &two).unwrap();
    let h2 = {
        let l = sigil::seglog::list(&c).unwrap();
        sigil::seglog::root_at(&l.entries, 2).unwrap()
    };
    let head2 = format!(
        "sigil-log-head=1\nseq=2\nchain={}\nroot={}\nt=1\n",
        sigil::hex32(&sigil::seglog::list(&c).unwrap().entries[1].chain),
        sigil::hex32(&h2)
    );
    fs::write(c.join("HEAD"), head2).unwrap();
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(
        code, 0,
        "unsigned rollback is invisible without an anchor: {o}"
    );
    let (code, o) = run(&d, &["log", "verify", "ev", "--anchor", &anchor]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("anchor") && o.contains("rolled back"), "{o}");
    fs::write(c.join("INDEX"), &good_index).unwrap();
    fs::write(c.join("HEAD"), &good_head).unwrap();
    ok(&d, &["log", "verify", "ev", "--anchor", &anchor]);

    // HEAD root edited
    fs::write(c.join("HEAD"), good_head.replacen("root=", "root=00", 1)).unwrap();
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 2, "{o}");
    fs::write(c.join("HEAD"), &good_head).unwrap();

    // a different (valid) star swapped in for segment 2
    let s2 = fs::read(seg(&c, 2)).unwrap();
    fs::copy(seg(&c, 1), seg(&c, 2)).unwrap();
    let (code, o) = run(&d, &["log", "verify", "ev", "--quick"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("segment-digest"), "{o}");
    fails(&d, &["log", "read", "ev", "--seq", "2"]);
    fs::write(seg(&c, 2), s2).unwrap();
    ok(&d, &["log", "verify", "ev"]);
}

#[test]
fn signed_log() {
    let d = tmp("signed");
    ok(&d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    ok(&d, &["keygen", "-o", "eve.sgk", "--pub-out", "eve.pub"]);
    let o = ok(&d, &["log", "init", "ev", "--identity", "me.sgk"]);
    assert!(o.contains("signed"), "{o}");
    fs::write(d.join("b.txt"), b"one\n").unwrap();
    // must sign, and with the pinned key
    assert!(fails(&d, &["log", "append", "ev", "b.txt"]).contains("signed"));
    assert!(fails(
        &d,
        &["log", "append", "ev", "b.txt", "--identity", "eve.sgk"]
    )
    .contains("not the key"));
    ok(
        &d,
        &["log", "append", "ev", "b.txt", "--identity", "me.sgk"],
    );
    fs::write(d.join("b.txt"), b"two\n").unwrap();
    ok(
        &d,
        &["log", "append", "ev", "b.txt", "--identity", "me.sgk"],
    );
    let c = d.join("ev.sigil");
    let v = ok(&d, &["log", "verify", "ev", "--signer", "me.pub"]);
    assert!(v.contains("healthy") && v.contains("signed"), "{v}");
    assert!(ok(&d, &["log", "ls", "ev"]).contains("signed by"));
    // wrong expected signer
    let (code, o) = run(&d, &["log", "verify", "ev", "--signer", "eve.pub"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("head-signer"), "{o}");
    // stripped signature
    let good = head_of(&c);
    let stripped: String = good
        .lines()
        .filter(|l| !l.starts_with("sig=") && !l.starts_with("signer="))
        .map(|l| format!("{l}\n"))
        .collect();
    fs::write(c.join("HEAD"), stripped).unwrap();
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("head-unsigned"), "{o}");
    // altered head (seq/time) under a valid-looking signature
    fs::write(c.join("HEAD"), good.replacen("\nt=", "\nt=9", 1)).unwrap();
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("head-signature"), "{o}");
    fs::write(c.join("HEAD"), &good).unwrap();
    // a re-chained INDEX (attacker recomputes every hash) still cannot produce a valid signature
    let idx = fs::read_to_string(c.join("INDEX")).unwrap();
    let forged = idx.replace("size=4", "size=5");
    fs::write(c.join("INDEX"), forged).unwrap();
    let (code, _o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 2);
    fs::write(c.join("INDEX"), idx).unwrap();
    ok(&d, &["log", "verify", "ev", "--signer", "me.pub"]);
    // an unsigned log cannot take a signing key
    ok(&d, &["log", "init", "plain"]);
    assert!(fails(
        &d,
        &["log", "append", "plain", "b.txt", "--identity", "me.sgk"]
    )
    .contains("unsigned"));
}

#[test]
fn keys_and_encrypted_segments() {
    let d = tmp("keys");
    ok(&d, &["keygen", "-o", "alice.sgk", "--pub-out", "alice.pub"]);
    ok(&d, &["log", "init", "ev"]);
    fs::write(d.join("b.txt"), b"secret one\n").unwrap();
    ok(&d, &["log", "append", "ev", "b.txt", "--pass", "hunter2"]);
    fs::write(d.join("b.txt"), b"secret two\n").unwrap();
    ok(&d, &["log", "append", "ev", "b.txt", "--to", "alice.pub"]);
    fs::write(d.join("b.txt"), b"plain three\n").unwrap();
    ok(&d, &["log", "append", "ev", "b.txt"]);
    // key-free verify still checks index, ECC and true-names
    let v = ok(&d, &["log", "verify", "ev"]);
    assert!(v.contains("healthy"), "{v}");
    // reading needs the key
    fails(&d, &["log", "read", "ev", "--seq", "1"]);
    assert_eq!(
        ok(
            &d,
            &["log", "read", "ev", "--seq", "1", "--pass", "hunter2"]
        ),
        "secret one\n"
    );
    assert_eq!(
        ok(
            &d,
            &["log", "read", "ev", "--seq", "2", "--identity", "alice.sgk"]
        ),
        "secret two\n"
    );
    // verify with keys also unseals
    let (code, o) = run(
        &d,
        &[
            "log",
            "verify",
            "ev",
            "--pass",
            "hunter2",
            "--identity",
            "alice.sgk",
        ],
    );
    assert_eq!(
        code, 2,
        "seg 3 is plain and seg 1/2 each need a different key: {o}"
    );
    let (code, o) = run(&d, &["log", "verify", "ev", "--identity", "alice.sgk"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("segment-unseal"), "{o}");
}

#[test]
fn mend_segments() {
    let d = tmp("mend");
    let c = sample(&d, 3);
    let good = fs::read(seg(&c, 2)).unwrap();
    let before_index = fs::read(c.join("INDEX")).unwrap();
    let before_head = head_of(&c);
    zero_mid(&seg(&c, 2), 8);
    // key-free verify sees the rot, repairable
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 1, "{o}");
    assert!(
        o.contains("bit-rot") && o.contains("repairable") && o.contains("sigil log mend"),
        "{o}"
    );
    // reading still works (ECC repairs in memory)
    assert_eq!(ok(&d, &["log", "read", "ev", "--seq", "2"]), "batch 2\n");
    let o = ok(&d, &["log", "mend", "ev"]);
    assert!(o.contains("healed 1") && o.contains("(2)"), "{o}");
    assert_eq!(
        fs::read(seg(&c, 2)).unwrap(),
        good,
        "mend restores the original bytes"
    );
    assert_eq!(fs::read(c.join("INDEX")).unwrap(), before_index);
    assert_eq!(head_of(&c), before_head);
    ok(&d, &["log", "verify", "ev"]);
    // plain `sigil mend` also works on a segment (it is an ordinary star)
    zero_mid(&seg(&c, 3), 8);
    ok(
        &d,
        &["mend", seg(&c, 3).to_str().unwrap(), "-o", "fixed.sg1"],
    );
    // beyond repair
    let mut b = fs::read(seg(&c, 1)).unwrap();
    let n = b.len();
    b[n / 8..n - n / 8].fill(0);
    fs::write(seg(&c, 1), b).unwrap();
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 2, "{o}");
    assert!(
        o.contains("bit-rot-unrecoverable") || o.contains("segment-digest"),
        "{o}"
    );
    let (code, o) = run(&d, &["log", "mend", "ev"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("segment 1"), "{o}");
}

#[test]
fn doctor_and_gc_understand_logs() {
    let d = tmp("dg");
    let c = sample(&d, 3);
    let (code, o) = run(&d, &["doctor", "ev"]);
    assert_eq!(code, 0, "{o}");
    assert!(o.contains("(log, container"), "{o}");
    // missing segment → ERROR, and gc/--fix never invent or delete anything live
    let keep = fs::read(seg(&c, 2)).unwrap();
    fs::remove_file(seg(&c, 2)).unwrap();
    let (code, o) = run(&d, &["doctor", "ev"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("segment-missing"), "{o}");
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 2, "{o}");
    ok(&d, &["gc", "ev", "--apply", "--temp-age", "0"]);
    assert!(seg(&c, 1).is_file() && seg(&c, 3).is_file());
    let (code, _) = run(&d, &["doctor", "ev", "--fix"]);
    assert_eq!(code, 2);
    assert!(seg(&c, 1).is_file() && seg(&c, 3).is_file());
    fs::write(seg(&c, 2), keep).unwrap();
    // rot via doctor
    zero_mid(&seg(&c, 1), 8);
    let (code, o) = run(&d, &["doctor", "ev"]);
    assert_eq!(code, 1, "{o}");
    assert!(o.contains("bit-rot"), "{o}");
    let (code, o) = run(&d, &["doctor", "ev", "--quick"]);
    assert_eq!(code, 0, "{o}");
    ok(&d, &["log", "mend", "ev"]);

    // orphan segment (crashed append: file written, INDEX never extended)
    let orphan = seg(&c, 4);
    fs::copy(seg(&c, 3), &orphan).unwrap();
    let junk = c.join("segments/0000/0000000004.sg1.part");
    fs::write(&junk, b"partial").unwrap();
    // young: only a note; gc leaves them
    let (code, o) = run(&d, &["doctor", "ev"]);
    assert_eq!(code, 0, "{o}");
    assert!(o.contains("recent-segment"), "{o}");
    let r = ok(&d, &["gc", "ev", "--apply"]);
    assert!(
        r.contains("nothing to reclaim") && orphan.is_file() && junk.is_file(),
        "{r}"
    );
    // old: reported, dry-run changes nothing, apply removes only the orphan + temp
    age(&orphan, 7200);
    age(&junk, 7200);
    let (code, o) = run(&d, &["doctor", "ev"]);
    assert_eq!(code, 1, "{o}");
    assert!(
        o.contains("orphan-segment") && o.contains("temp-file"),
        "{o}"
    );
    let r = ok(&d, &["gc", "ev"]);
    assert!(r.contains("dry run") && r.contains("orphan segment"), "{r}");
    assert!(orphan.is_file());
    let r = ok(&d, &["gc", "ev", "--apply"]);
    assert!(r.contains("reclaimed 2 of 2"), "{r}");
    assert!(!orphan.exists() && !junk.exists());
    for s in 1..=3 {
        assert!(seg(&c, s).is_file());
    }
    // an unknown file is left alone
    fs::write(c.join("notes.txt"), b"mine").unwrap();
    let r = ok(&d, &["gc", "ev", "--apply", "--temp-age", "0"]);
    assert!(r.contains("left alone: notes.txt"), "{r}");
    assert!(c.join("notes.txt").is_file());
    // tidy on a log container is a no-op; constellations can't be mixed into it
    let t = ok(&d, &["tidy", "ev.sigil"]);
    assert!(t.to_lowercase().contains("already"), "{t}");
    fs::create_dir_all(d.join("in")).unwrap();
    fs::write(d.join("in/x.txt"), b"x").unwrap();
    let e = fails(&d, &["constellation", "add", "ev.sigil", "in"]);
    assert!(e.contains("refusing to mix"), "{e}");
}

#[test]
fn crash_recovery() {
    let d = tmp("crash");
    let c = sample(&d, 2);
    // 1. crash after the segment was written but before INDEX: leftover at seq 3 is replaced
    fs::write(seg(&c, 3), b"junk from a crashed append").unwrap();
    fs::write(d.join("b.txt"), b"batch 3\n").unwrap();
    ok(&d, &["log", "append", "ev", "b.txt"]);
    assert_eq!(ok(&d, &["log", "read", "ev", "--seq", "3"]), "batch 3\n");
    ok(&d, &["log", "verify", "ev"]);
    // 2. crash after INDEX but before HEAD: head lags, next append re-covers
    let old_head = head_of(&c);
    fs::write(d.join("b.txt"), b"batch 4\n").unwrap();
    ok(&d, &["log", "append", "ev", "b.txt"]);
    let h4 = head_of(&c);
    // restore head of 3 entries while INDEX has 4
    fs::write(c.join("HEAD"), &old_head).unwrap();
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 1, "{o}");
    assert!(o.contains("head-lag"), "{o}");
    fs::write(d.join("b.txt"), b"batch 5\n").unwrap();
    let o = ok(&d, &["log", "append", "ev", "b.txt"]);
    assert!(o.contains("behind INDEX"), "{o}");
    ok(&d, &["log", "verify", "ev"]);
    assert_ne!(h4, head_of(&c));
    // 3. torn last INDEX line
    let mut idx = fs::read(c.join("INDEX")).unwrap();
    idx.extend_from_slice(b"seq=6 t=1 size=3 sha=ab");
    fs::write(c.join("INDEX"), idx).unwrap();
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 1, "{o}");
    assert!(o.contains("index-torn"), "{o}");
    fs::write(d.join("b.txt"), b"batch 6\n").unwrap();
    let o = ok(&d, &["log", "append", "ev", "b.txt"]);
    assert!(o.contains("torn"), "{o}");
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 0, "{o}");
    assert_eq!(ok(&d, &["log", "read", "ev", "--seq", "6"]), "batch 6\n");
    // 4. stale lock blocks appends; gc clears it once old
    fs::write(c.join("LOG.lock"), b"pid=1\n").unwrap();
    assert!(fails(&d, &["log", "append", "ev", "b.txt"]).contains("LOG.lock"));
    age(&c.join("LOG.lock"), 7200);
    ok(&d, &["gc", "ev", "--apply"]);
    ok(&d, &["log", "append", "ev", "b.txt"]);
}

#[test]
fn many_segments_shard_folders_and_json() {
    let d = tmp("many");
    ok(&d, &["log", "init", "ev.sigil"]);
    let c = d.join("ev.sigil");
    for i in 0..5u8 {
        fs::write(d.join("b.txt"), vec![i; 10]).unwrap();
        ok(
            &d,
            &["log", "append", "ev.sigil", "b.txt", "--mode", "glyph"],
        );
    }
    assert!(seg(&c, 1).starts_with(c.join("segments/0000")));
    assert!(sigil::seglog::segment_path(&c, 1234).ends_with("segments/0001/0000001234.sg1"));
    let (code, j) = run(&d, &["log", "verify", "ev", "--json"]);
    assert_eq!(code, 0, "{j}");
    assert!(
        j.contains("\"kind\":\"log\"") && j.contains("\"status\":\"healthy\""),
        "{j}"
    );
}
