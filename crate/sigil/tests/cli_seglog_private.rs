//! Private INDEX (`sigil log init --private-index`, `log=5`): sizes, SHA-256s and `log add` file
//! names are sealed in the INDEX; keyless verify / mend / gc keep working; `log add` still skips
//! unchanged files; receipts carry one entry's key; every alteration and every wrong key fails closed.
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

use sha2::{Digest, Sha256};

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
    let d = std::env::temp_dir().join(format!("sigil-log-private-{tag}-{}", std::process::id()));
    let _ = fs::remove_dir_all(&d);
    fs::create_dir_all(&d).unwrap();
    d
}

fn put(d: &Path, rel: &str, body: &str) {
    let p = d.join("photos").join(rel);
    fs::create_dir_all(p.parent().unwrap()).unwrap();
    fs::write(p, body).unwrap();
}

fn index(d: &Path) -> String {
    fs::read_to_string(d.join("ev.sigil/INDEX")).unwrap()
}

fn sha_hex(b: &[u8]) -> String {
    hex::encode(Sha256::digest(b))
}

/// Re-chain every INDEX line after `lines` were edited (what an attacker with write access to an
/// unsigned log can do), so only the box's own authentication can catch the edit.
fn rechain(d: &Path, lines: &[String]) {
    let manifest = fs::read_to_string(d.join("ev.sigil/CONTAINER")).unwrap();
    let id = manifest
        .lines()
        .find_map(|l| l.strip_prefix("log-id="))
        .unwrap()
        .trim()
        .to_string();
    let mut prev: [u8; 32] =
        Sha256::digest([b"sigil-log-genesis-v1\0".as_slice(), id.as_bytes()].concat()).into();
    let mut out = String::from("sigil-log-index=1\n");
    for l in lines {
        let body = &l[..l.rfind(" chain=").unwrap()];
        let c: [u8; 32] =
            Sha256::digest([b"sigil-log-entry-v1\0".as_slice(), &prev, body.as_bytes()].concat())
                .into();
        out.push_str(&format!("{body} chain={}\n", hex::encode(c)));
        prev = c;
    }
    fs::write(d.join("ev.sigil/INDEX"), out).unwrap();
}

fn entry_lines(d: &Path) -> Vec<String> {
    index(d).lines().skip(1).map(String::from).collect()
}

/// A signed private log backing up `photos/` to `me.pub`.
fn photo_log(tag: &str) -> PathBuf {
    let d = tmp(tag);
    ok(&d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    put(&d, "2024/trip/beach.jpg", "beach day");
    put(&d, "mum-birthday.jpg", "mum's birthday cake");
    ok(
        &d,
        &[
            "log",
            "init",
            "ev",
            "--identity",
            "me.sgk",
            "--private-index",
            "--to",
            "me.pub",
        ],
    );
    let o = ok(
        &d,
        &[
            "log",
            "add",
            "ev",
            "photos",
            "--to",
            "me.pub",
            "--identity",
            "me.sgk",
        ],
    );
    assert!(o.contains("added 2"), "{o}");
    d
}

#[test]
fn names_sizes_and_hashes_stay_out_of_the_index_and_add_still_skips_unchanged() {
    let d = photo_log("hide");
    let idx = index(&d);
    // nothing about the files is visible: no names, no plain SHA-256, no sizes
    for needle in [
        "beach",
        "mum-birthday",
        "2024",
        "path=",
        "size=9 ",
        "size=19 ",
    ] {
        assert!(!idx.contains(needle), "{needle} leaked: {idx}");
    }
    assert!(
        !idx.contains(&sha_hex(b"beach day")) && !idx.contains(&sha_hex(b"mum's birthday cake"))
    );
    assert!(
        idx.lines()
            .skip(1)
            .all(|l| l.contains(" size=0 ") && l.contains(" box=")),
        "{idx}"
    );
    let manifest = fs::read_to_string(d.join("ev.sigil/CONTAINER")).unwrap();
    assert!(
        manifest.contains("log=5") && manifest.contains("privindex=1"),
        "{manifest}"
    );
    assert!(d.join("ev.sigil/IXKEY.sg1").is_file());

    // a re-run with no changes writes nothing; a changed file is a new version
    let before = index(&d);
    let o = ok(
        &d,
        &[
            "log",
            "add",
            "ev",
            "photos",
            "--to",
            "me.pub",
            "--identity",
            "me.sgk",
        ],
    );
    assert!(
        o.contains("unchanged 2") && o.contains("nothing to do"),
        "{o}"
    );
    assert_eq!(index(&d), before);
    put(&d, "2024/trip/beach.jpg", "beach day, take two");
    let o = ok(
        &d,
        &[
            "log",
            "add",
            "ev",
            "photos",
            "--to",
            "me.pub",
            "--identity",
            "me.sgk",
            "--dry-run",
        ],
    );
    assert!(o.contains("changed (was segment 1)"), "{o}");
    let o = ok(
        &d,
        &[
            "log",
            "add",
            "ev",
            "photos",
            "--to",
            "me.pub",
            "--identity",
            "me.sgk",
        ],
    );
    assert!(o.contains("changed 1") && o.contains("unchanged 1"), "{o}");

    // keyless ls shows sealed rows; with the key it shows sizes and names
    let o = ok(&d, &["log", "ls", "ev"]);
    assert!(
        o.contains("sealed") && !o.contains("beach") && o.contains("private index"),
        "{o}"
    );
    let o = ok(&d, &["log", "ls", "ev", "--identity", "me.sgk"]);
    assert!(
        o.contains("2024/trip/beach.jpg")
            && o.contains("mum-birthday.jpg")
            && o.contains("private index: opened"),
        "{o}"
    );
    // reading back and verifying, with and without the key
    let o = sigil_cmd(
        &d,
        &["log", "read", "ev", "--seq", "3", "--identity", "me.sgk"],
    );
    assert_eq!(o.stdout, b"beach day, take two");
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 0, "{o}");
    assert!(o.contains("private-index"), "{o}");
    let (code, o) = run(&d, &["log", "verify", "ev", "--identity", "me.sgk"]);
    assert_eq!(code, 0, "{o}");
    let (code, o) = run(&d, &["doctor", "ev"]);
    assert_eq!(code, 0, "{o}");
    // gc does not treat the index key file as a stray
    let o = ok(&d, &["gc", "ev", "--apply"]);
    assert!(!o.contains("IXKEY"), "{o}");
    assert!(d.join("ev.sigil/IXKEY.sg1").is_file());
}

#[test]
fn receipts_carry_one_entry_key_and_check_the_file() {
    let d = photo_log("proof");
    ok(
        &d,
        &[
            "log",
            "prove",
            "ev",
            "--seq",
            "2",
            "--identity",
            "me.sgk",
            "-o",
            "r2.proof",
        ],
    );
    let r2 = fs::read_to_string(d.join("r2.proof")).unwrap();
    assert!(
        r2.contains("entry-key=") && !r2.contains("mum-birthday"),
        "{r2}"
    );
    let o = ok(
        &d,
        &[
            "log",
            "check-proof",
            "r2.proof",
            "--file",
            "photos/mum-birthday.jpg",
        ],
    );
    assert!(o.contains("file matches"), "{o}");
    // another file: refused
    let (code, o) = run(
        &d,
        &[
            "log",
            "check-proof",
            "r2.proof",
            "--file",
            "photos/2024/trip/beach.jpg",
        ],
    );
    assert_eq!(code, 2, "{o}");
    // an altered entry key, or the key of another entry: refused (key commitment)
    let k = r2
        .lines()
        .find_map(|l| l.strip_prefix("entry-key="))
        .unwrap()
        .to_string();
    let mut flipped = k.clone().into_bytes();
    flipped[10] = if flipped[10] == b'0' { b'1' } else { b'0' };
    fs::write(
        d.join("bad.proof"),
        r2.replace(&k, std::str::from_utf8(&flipped).unwrap()),
    )
    .unwrap();
    let (code, o) = run(&d, &["log", "check-proof", "bad.proof"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("entry-key="), "{o}");
    ok(
        &d,
        &[
            "log",
            "prove",
            "ev",
            "--seq",
            "1",
            "--identity",
            "me.sgk",
            "-o",
            "r1.proof",
        ],
    );
    let r1 = fs::read_to_string(d.join("r1.proof")).unwrap();
    let k1 = r1
        .lines()
        .find_map(|l| l.strip_prefix("entry-key="))
        .unwrap();
    fs::write(d.join("swap.proof"), r2.replace(&k, k1)).unwrap();
    let (code, o) = run(
        &d,
        &[
            "log",
            "check-proof",
            "swap.proof",
            "--file",
            "photos/mum-birthday.jpg",
        ],
    );
    assert_eq!(code, 2, "{o}");
    // without the key: inclusion still proves, the file cannot be checked
    ok(
        &d,
        &["log", "prove", "ev", "--seq", "2", "-o", "nokey.proof"],
    );
    let nk = fs::read_to_string(d.join("nokey.proof")).unwrap();
    assert!(!nk.contains("entry-key="), "{nk}");
    let o = ok(
        &d,
        &["log", "check-proof", "nokey.proof", "--signer", "me.pub"],
    );
    assert!(o.contains("sealed entry"), "{o}");
    let (code, o) = run(
        &d,
        &[
            "log",
            "check-proof",
            "nokey.proof",
            "--file",
            "photos/mum-birthday.jpg",
        ],
    );
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("sealed"), "{o}");
}

#[test]
fn tampering_and_wrong_keys_fail_closed() {
    let d = tmp("tamper");
    fs::write(d.join("a.txt"), "first batch").unwrap();
    fs::write(d.join("b.txt"), "second batch").unwrap();
    ok(&d, &["keygen", "-o", "eve.sgk", "--pub-out", "eve.pub"]);
    ok(
        &d,
        &["log", "init", "ev", "--private-index", "--pass", "pw"],
    );
    ok(&d, &["log", "append", "ev", "a.txt", "--pass", "pw"]);
    ok(&d, &["log", "append", "ev", "b.txt", "--pass", "pw"]);
    let good = entry_lines(&d);

    // wrong key: refused everywhere, verify reports it (exit 2)
    assert!(fails(&d, &["log", "ls", "ev", "--pass", "nope"]).contains("does not open"));
    assert!(fails(
        &d,
        &["log", "read", "ev", "--seq", "1", "--identity", "eve.sgk"]
    )
    .contains("does not open"));
    assert!(
        fails(&d, &["log", "append", "ev", "a.txt", "--pass", "nope"]).contains("does not open")
    );
    let (code, o) = run(&d, &["log", "verify", "ev", "--pass", "nope"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("index-key"), "{o}");
    // no key at all: a reader / writer that needs the sealed fields refuses
    assert!(fails(&d, &["log", "read", "ev", "--seq", "1"]).contains("private"));
    assert!(fails(&d, &["log", "compact", "ev"]).contains("private"));

    // a bit flip in a box (chain not fixed up): chain error
    let mut l = good.clone();
    let pos = l[0].find(" box=").unwrap() + 20;
    let mut b = l[0].clone().into_bytes();
    b[pos] = if b[pos] == b'a' { b'b' } else { b'a' };
    l[0] = String::from_utf8(b).unwrap();
    fs::write(
        d.join("ev.sigil/INDEX"),
        format!("sigil-log-index=1\n{}\n{}\n", l[0], l[1]),
    )
    .unwrap();
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("index-chain"), "{o}");

    // the same flip, re-chained (consistent rewrite of an unsigned log): the box itself refuses
    rechain(&d, &l);
    let (code, o) = run(&d, &["log", "verify", "ev", "--pass", "pw"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("index-box"), "{o}");
    assert!(fails(&d, &["log", "read", "ev", "--seq", "2", "--pass", "pw"]).contains("index-box"));

    // a truncated box, re-chained
    let mut t = good.clone();
    let cut = t[1].find(" box=").unwrap() + 5 + 40;
    let chain = t[1][t[1].rfind(" chain=").unwrap()..].to_string();
    t[1] = format!("{}{chain}", &t[1][..cut]);
    rechain(&d, &t);
    let (code, o) = run(&d, &["log", "verify", "ev", "--pass", "pw"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("index-box") && o.contains("truncated"), "{o}");

    // a box moved to another line (re-chained): bound to its seq and visible fields
    let mut m = good.clone();
    let box0 = &good[0][good[0].find(" box=").unwrap()..good[0].rfind(" chain=").unwrap()];
    let box1 = &good[1][good[1].find(" box=").unwrap()..good[1].rfind(" chain=").unwrap()];
    m[1] = good[1].replace(box1, box0);
    rechain(&d, &m);
    let (code, o) = run(&d, &["log", "verify", "ev", "--pass", "pw"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("index-box"), "{o}");

    // a plaintext line slipped into a private log: refused even without a key
    let mut p = good.clone();
    let star = p[1]
        .split_whitespace()
        .find_map(|t| t.strip_prefix("star="))
        .unwrap()
        .to_string();
    p[1] = format!(
        "seq=2 t=5 size=12 sha={} star={star} chain=00",
        sha_hex(b"second batch")
    );
    rechain(&d, &p);
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("index-private"), "{o}");

    // the intact INDEX opens again
    rechain(&d, &good);
    let o = sigil_cmd(&d, &["log", "read", "ev", "--seq", "2", "--pass", "pw"]);
    assert_eq!(o.stdout, b"second batch");
}

#[test]
fn manifest_rules_keep_old_logs_and_private_logs_apart() {
    let d = tmp("manifest");
    fs::write(d.join("a.txt"), "plain batch").unwrap();
    // an ordinary log is untouched: no IXKEY, log=1, sizes in the clear
    ok(&d, &["log", "init", "ev"]);
    ok(&d, &["log", "append", "ev", "a.txt"]);
    assert!(!d.join("ev.sigil/IXKEY.sg1").exists());
    let m = fs::read_to_string(d.join("ev.sigil/CONTAINER")).unwrap();
    assert!(m.contains("log=1") && !m.contains("privindex"), "{m}");
    assert!(index(&d).contains(&format!("sha={}", sha_hex(b"plain batch"))));
    // claiming privindex on it: the plaintext lines are refused, not silently trusted
    fs::write(
        d.join("ev.sigil/CONTAINER"),
        m.replace("log=1", "log=5")
            .replace("log-id=", "privindex=1\nlog-id="),
    )
    .unwrap();
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("index-private"), "{o}");
    // privindex=1 under an older format: refused
    fs::write(
        d.join("ev.sigil/CONTAINER"),
        m.replace("log-id=", "privindex=1\nlog-id="),
    )
    .unwrap();
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("privindex=1 but log<5"), "{o}");

    // a private log whose manifest loses privindex=1: its boxes are a format error
    let p = tmp("manifest-p");
    fs::write(p.join("a.txt"), "x").unwrap();
    ok(
        &p,
        &["log", "init", "ev", "--private-index", "--pass", "pw"],
    );
    ok(&p, &["log", "append", "ev", "a.txt", "--pass", "pw"]);
    let pm = fs::read_to_string(p.join("ev.sigil/CONTAINER")).unwrap();
    fs::write(
        p.join("ev.sigil/CONTAINER"),
        pm.replace("privindex=1\n", ""),
    )
    .unwrap();
    let (code, o) = run(&p, &["log", "verify", "ev"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("log-format"), "{o}");

    // init: --private-index needs a wrap key (a key alone now makes it private by default)
    assert!(ok(&d, &["log", "init", "x1", "--pass", "pw"]).contains("private INDEX"));
    assert!(fails(&d, &["log", "init", "x2", "--private-index"]).contains("--to and/or --pass"));
    assert!(
        fails(&d, &["log", "init", "x3", "--private-index", "--pass", ""])
            .contains("empty passphrase")
    );
    assert!(
        d.join("x1.sigil").exists() && !d.join("x2.sigil").exists() && !d.join("x3.sigil").exists()
    );
}

#[test]
fn private_logs_refuse_what_would_leak() {
    let d = tmp("refuse");
    ok(&d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    fs::write(d.join("a.txt"), "batch").unwrap();
    ok(
        &d,
        &["log", "init", "ev", "--private-index", "--to", "me.pub"],
    );
    // unencrypted segment (key opened by --unlock, but no --pass / --to): refused, nothing written
    let o = fails(&d, &["log", "append", "ev", "a.txt", "--unlock", "me.sgk"]);
    assert!(o.contains("must be encrypted"), "{o}");
    let o = fails(
        &d,
        &[
            "log", "append", "ev", "a.txt", "--unlock", "me.sgk", "--pass", "",
        ],
    );
    assert!(o.contains("empty passphrase"), "{o}");
    assert!(!d.join("ev.sigil/segments/0000/0000000001.sg1").exists());
    // no key to open the index: refused (public --to alone cannot write a box)
    assert!(fails(&d, &["log", "append", "ev", "a.txt", "--to", "me.pub"]).contains("private"));
    ok(
        &d,
        &[
            "log", "append", "ev", "a.txt", "--to", "me.pub", "--unlock", "me.sgk",
        ],
    );
    // reasons would be plaintext; adopt would copy stars without sealing their metadata; mount is later
    assert!(fails(
        &d,
        &["log", "tombstone", "ev", "--seq", "1", "--reason", "x"]
    )
    .contains("in the clear"));
    ok(&d, &["seal", "a.txt", "-o", "loose.sg1"]);
    assert!(fails(&d, &["log", "adopt", "ev", "loose.sg1", "--keep"]).contains("private"));
    assert!(fails(&d, &["mount", "ev", "view", "--export-dir", "out"]).contains("private INDEX"));
    ok(&d, &["log", "tombstone", "ev", "--seq", "1"]);
}

#[test]
fn compaction_keeps_members_readable_and_sealed() {
    let d = tmp("compact");
    ok(&d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    ok(
        &d,
        &[
            "log",
            "init",
            "ev",
            "--private-index",
            "--to",
            "me.pub",
            "--identity",
            "me.sgk",
        ],
    );
    for (i, body) in ["one\n", "two two\n", "three three three\n"]
        .iter()
        .enumerate()
    {
        let f = format!("b{i}.txt");
        fs::write(d.join(&f), body).unwrap();
        ok(
            &d,
            &[
                "log",
                "append",
                "ev",
                &f,
                "--to",
                "me.pub",
                "--identity",
                "me.sgk",
            ],
        );
    }
    ok(
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
    let o = ok(
        &d,
        &[
            "log",
            "compact",
            "ev",
            "--identity",
            "me.sgk",
            "--to",
            "me.pub",
            "--apply",
        ],
    );
    assert!(o.contains("new segment 5"), "{o}");
    let last = entry_lines(&d).pop().unwrap();
    assert!(
        last.contains("op=compact of=1,3") && last.contains(" size=0 ") && last.contains(" box="),
        "{last}"
    );
    let o = sigil_cmd(
        &d,
        &["log", "read", "ev", "--seq", "3", "--identity", "me.sgk"],
    );
    assert_eq!(o.stdout, b"three three three\n");
    let o = sigil_cmd(&d, &["log", "read", "ev", "--identity", "me.sgk"]);
    assert_eq!(o.stdout, b"one\nthree three three\n");
    let (code, o) = run(&d, &["log", "verify", "ev", "--identity", "me.sgk"]);
    assert_eq!(code, 0, "{o}");
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 0, "{o}");
}

#[test]
fn index_key_file_heals_with_mend() {
    let d = tmp("mend");
    fs::write(d.join("a.txt"), "batch").unwrap();
    ok(
        &d,
        &["log", "init", "ev", "--private-index", "--pass", "pw"],
    );
    ok(&d, &["log", "append", "ev", "a.txt", "--pass", "pw"]);
    let p = d.join("ev.sigil/IXKEY.sg1");
    let good = fs::read(&p).unwrap();
    let mut b = good.clone();
    let mid = b.len() / 2;
    b[mid..mid + 8].fill(0);
    fs::write(&p, b).unwrap();
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 1, "{o}");
    assert!(o.contains("bit-rot") && o.contains("IXKEY.sg1"), "{o}");
    let o = ok(&d, &["log", "mend", "ev"]);
    assert!(o.contains("IXKEY.sg1"), "{o}");
    assert_eq!(fs::read(&p).unwrap(), good);
    ok(&d, &["log", "ls", "ev", "--pass", "pw"]);
    // gone entirely: keyless verify says so; readers explain how to recover
    fs::remove_file(&p).unwrap();
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_eq!(code, 2, "{o}");
    assert!(o.contains("ixkey-missing"), "{o}");
    assert!(fails(&d, &["log", "ls", "ev", "--pass", "pw"]).contains("restore IXKEY.sg1"));
}
