//! `sigil log add LOG DIR`: back a folder up into a segment log, sealing only new or changed files
//! (one segment per file, additive `path=` key), reporting files gone from the source without ever
//! deleting them, and failing closed when the INDEX, a segment or the source is tampered with.
use std::collections::BTreeMap;
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

fn read_seq(dir: &Path, seq: u64, extra: &[&str]) -> Vec<u8> {
    let s = seq.to_string();
    let mut args = vec!["log", "read", "ev", "--seq", s.as_str()];
    args.extend_from_slice(extra);
    let o = sigil_cmd(dir, &args);
    assert!(o.status.success(), "{}", text(&o));
    o.stdout
}

fn tmp(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sigil-log-add-{tag}-{}", std::process::id()));
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

/// Every file of the container with its bytes (to prove "nothing written").
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

fn seg(d: &Path, seq: u64) -> PathBuf {
    sigil::seglog::segment_path(&d.join("ev.sigil"), seq)
}

#[test]
fn first_add_rerun_change_new_and_missing() {
    let d = tmp("cycle");
    put(&d, "a.jpg", "alpha\n");
    put(&d, "2024/trip/beach.jpg", "beach\n");
    put(&d, "2024/trip/deep/er/x.png", "x\n");
    put(&d, "b/c.txt", "c\n");
    fs::create_dir_all(d.join("photos/empty/folder")).unwrap();
    ok(&d, &["log", "init", "ev"]);

    let out = ok(&d, &["log", "add", "ev", "photos"]);
    assert!(
        out.contains("added 4, changed 0, unchanged 0, missing 0, skipped-special 0"),
        "{out}"
    );
    assert!(
        out.contains("+ 2024/trip/deep/er/x.png  2 bytes  new → segment 2"),
        "{out}"
    );
    // nested folders, stable byte order of the relative path
    assert_eq!(
        paths(&d),
        [
            "2024/trip/beach.jpg",
            "2024/trip/deep/er/x.png",
            "a.jpg",
            "b/c.txt"
        ]
    );
    // ordinary log=1 segment lines: the manifest is not raised
    assert!(fs::read_to_string(d.join("ev.sigil/CONTAINER"))
        .unwrap()
        .contains("log=1"));
    assert_eq!(read_seq(&d, 3, &[]), b"alpha\n");
    // no new kinds of files in the container (empty folders are not recorded either)
    for p in snapshot(&d.join("ev.sigil")).keys() {
        let r = p.strip_prefix(d.join("ev.sigil")).unwrap();
        assert!(
            ["CONTAINER", "INDEX", "HEAD"].contains(&r.to_str().unwrap())
                || r.starts_with("segments"),
            "unexpected {r:?}"
        );
    }

    // re-run with no changes: exit 0 and not one byte of the container changes
    let before = snapshot(&d.join("ev.sigil"));
    let out = ok(&d, &["log", "add", "ev", "photos"]);
    assert!(
        out.contains("added 0, changed 0, unchanged 4, missing 0") && out.contains("log unchanged"),
        "{out}"
    );
    assert_eq!(snapshot(&d.join("ev.sigil")), before);

    // one changed, one new, one removed from the source
    put(&d, "a.jpg", "ALPHA, edited\n");
    put(&d, "b/new.txt", "new\n");
    fs::remove_file(d.join("photos/b/c.txt")).unwrap();
    let out = ok(&d, &["log", "add", "ev", "photos"]);
    assert!(
        out.contains("added 1, changed 1, unchanged 2, missing 1, skipped-special 0"),
        "{out}"
    );
    assert!(
        out.contains("a.jpg  14 bytes  changed (was segment 3) → segment 5"),
        "{out}"
    );
    assert!(
        out.contains("! b/c.txt  missing from source (kept: segment 4)"),
        "{out}"
    );
    // the new version is a new segment; the old version and the vanished file stay readable
    assert_eq!(read_seq(&d, 5, &[]), b"ALPHA, edited\n");
    assert_eq!(read_seq(&d, 3, &[]), b"alpha\n");
    assert_eq!(read_seq(&d, 4, &[]), b"c\n");
    assert!(!index(&d).contains("op=tomb"), "nothing is tombstoned");
    // `log ls` names each file; verify is clean
    let ls = ok(&d, &["log", "ls", "ev"]);
    assert!(
        ls.contains("ok  a.jpg") && ls.contains("ok  b/new.txt"),
        "{ls}"
    );
    let v = ok(&d, &["log", "verify", "ev"]);
    assert!(v.contains("healthy"), "{v}");

    // still missing on the next run, still kept, still no write
    let before = snapshot(&d.join("ev.sigil"));
    let out = ok(&d, &["log", "add", "ev", "photos"]);
    assert!(out.contains("unchanged 4, missing 1"), "{out}");
    assert_eq!(snapshot(&d.join("ev.sigil")), before);
}

#[test]
fn dry_run_writes_nothing() {
    let d = tmp("dry");
    put(&d, "a.jpg", "a\n");
    put(&d, "sub/b.jpg", "b\n");
    ok(&d, &["log", "init", "ev"]);
    let before = snapshot(&d.join("ev.sigil"));
    let out = ok(&d, &["log", "add", "ev", "photos", "--dry-run"]);
    assert!(
        out.contains("would have added 2") && out.contains("dry run: nothing written"),
        "{out}"
    );
    assert_eq!(snapshot(&d.join("ev.sigil")), before);

    ok(&d, &["log", "add", "ev", "photos"]);
    put(&d, "a.jpg", "changed\n");
    put(&d, "c.jpg", "c\n");
    fs::remove_file(d.join("photos/sub/b.jpg")).unwrap();
    let before = snapshot(&d.join("ev.sigil"));
    let out = ok(&d, &["log", "add", "ev", "photos", "--dry-run"]);
    assert!(
        out.contains("would have added 1, changed 1, unchanged 0, missing 1")
            && out.contains("a.jpg  8 bytes  changed (was segment 1)\n")
            && out.contains("! sub/b.jpg  missing from source"),
        "{out}"
    );
    assert_eq!(snapshot(&d.join("ev.sigil")), before);
}

#[test]
fn stable_order_and_odd_names() {
    let d = tmp("order");
    // created in scrambled order; names with spaces, `=`, `%` and non-ASCII
    for n in ["b", "a/z", "a-b", "B", "a/b/c", "é t=1%.jpg"] {
        put(&d, n, n);
    }
    ok(&d, &["log", "init", "ev"]);
    ok(&d, &["log", "add", "ev", "photos"]);
    // byte order of the relative path ("B" < "a-b" < "a/b/c" < "a/z" < "b" < "é…")
    assert_eq!(
        paths(&d),
        ["B", "a-b", "a/b/c", "a/z", "b", "%C3%A9%20t%3D1%25.jpg"]
    );
    let ls = ok(&d, &["log", "ls", "ev"]);
    assert!(ls.contains("ok  é t=1%.jpg"), "{ls}");
    let out = ok(&d, &["log", "add", "ev", "photos"]);
    assert!(out.contains("unchanged 6"), "{out}");
}

#[cfg(unix)]
#[test]
fn symlinks_special_files_and_containers_skipped() {
    let d = tmp("special");
    put(&d, "a.jpg", "a\n");
    std::os::unix::fs::symlink("a.jpg", d.join("photos/link.jpg")).unwrap();
    std::os::unix::fs::symlink("/etc", d.join("photos/outside")).unwrap();
    let fifo = Command::new("mkfifo")
        .arg(d.join("photos/pipe"))
        .status()
        .unwrap();
    assert!(fifo.success());
    // the log itself lives inside the folder being backed up: never added to itself
    ok(&d, &["log", "init", "photos/ev"]);
    let out = ok(&d, &["log", "add", "photos/ev", "photos"]);
    assert!(
        out.contains("added 1, changed 0, unchanged 0, missing 0, skipped-special 4"),
        "{out}"
    );
    assert!(
        out.contains("- link.jpg  skipped: symbolic link")
            && out.contains("- outside  skipped: symbolic link")
            && out.contains("- pipe  skipped: special file")
            && out.contains("- ev.sigil  skipped: sigil container"),
        "{out}"
    );
    // a name with a newline and an escape byte cannot fake output lines
    put(
        &d,
        "evil\nlog add ev.sigil from photos: added 0\x1b[2J.jpg",
        "e\n",
    );
    let out = ok(&d, &["log", "add", "photos/ev", "photos"]);
    assert!(
        out.contains("+ evil\\nlog add ev.sigil from photos: added 0\\u{1b}[2J.jpg")
            && out.lines().filter(|l| l.starts_with("log add")).count() == 1,
        "{out}"
    );
    let ls = ok(&d, &["log", "ls", "photos/ev"]);
    assert!(ls.contains("ok  evil\\nlog add"), "{ls}");
    // a folder inside a container is refused
    let e = fails(&d, &["log", "add", "photos/ev", "photos/ev.sigil/segments"]);
    assert!(e.contains("inside a sigil container"), "{e}");
    // a file is not a folder
    let e = fails(&d, &["log", "add", "photos/ev", "photos/a.jpg"]);
    assert!(e.contains("not a folder"), "{e}");
}

#[test]
fn signed_log_add_and_wrong_identity() {
    let d = tmp("signed");
    ok(&d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    ok(&d, &["keygen", "-o", "other.sgk", "--pub-out", "other.pub"]);
    put(&d, "a.jpg", "a\n");
    put(&d, "b/c.jpg", "c\n");
    ok(&d, &["log", "init", "ev", "--identity", "me.sgk"]);
    let before = snapshot(&d.join("ev.sigil"));
    let e = fails(&d, &["log", "add", "ev", "photos"]);
    assert!(e.contains("--identity"), "{e}");
    let e = fails(
        &d,
        &["log", "add", "ev", "photos", "--identity", "other.sgk"],
    );
    assert!(e.contains("not the key this log is pinned to"), "{e}");
    assert_eq!(
        snapshot(&d.join("ev.sigil")),
        before,
        "refusals write nothing"
    );
    // a dry run needs no key
    let out = ok(&d, &["log", "add", "ev", "photos", "--dry-run"]);
    assert!(out.contains("would have added 2"), "{out}");

    let out = ok(&d, &["log", "add", "ev", "photos", "--identity", "me.sgk"]);
    assert!(out.contains("added 2") && out.contains("(signed)"), "{out}");
    let v = ok(&d, &["log", "verify", "ev", "--signer", "me.pub"]);
    assert!(v.contains("healthy"), "{v}");
    // an add entry proves like any other entry
    ok(&d, &["log", "prove", "ev", "--seq", "1", "-o", "a.proof"]);
    ok(
        &d,
        &[
            "log",
            "check-proof",
            "a.proof",
            "--file",
            "photos/a.jpg",
            "--signer",
            "me.pub",
        ],
    );
    put(&d, "a.jpg", "a, edited\n");
    let out = ok(&d, &["log", "add", "ev", "photos", "--identity", "me.sgk"]);
    assert!(
        out.contains("changed 1") && out.contains("(signed)"),
        "{out}"
    );
    let v = ok(&d, &["log", "verify", "ev", "--signer", "me.pub"]);
    assert!(v.contains("healthy"), "{v}");
}

#[test]
fn encrypted_and_segment_key_logs() {
    let d = tmp("keys");
    ok(&d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    put(&d, "a.jpg", "secret a\n");
    // --pass: the comparison needs no key, so an unchanged re-run is keyless
    ok(&d, &["log", "init", "ev"]);
    ok(&d, &["log", "add", "ev", "photos", "--pass", "hunter2"]);
    assert_eq!(read_seq(&d, 1, &["--pass", "hunter2"]), b"secret a\n");
    let out = ok(&d, &["log", "add", "ev", "photos"]);
    assert!(out.contains("unchanged 1"), "{out}");
    // but new files are not quietly stored unencrypted next to encrypted ones
    put(&d, "b.jpg", "secret b\n");
    let e = fails(&d, &["log", "add", "ev", "photos"]);
    assert!(e.contains("give --pass / --to again"), "{e}");
    let out = ok(&d, &["log", "add", "ev", "photos", "--to", "me.pub"]);
    assert!(out.contains("added 1"), "{out}");
    assert_eq!(read_seq(&d, 2, &["--identity", "me.sgk"]), b"secret b\n");
    let v = ok(
        &d,
        &[
            "log",
            "verify",
            "ev",
            "--pass",
            "hunter2",
            "--identity",
            "me.sgk",
        ],
    );
    assert!(v.contains("healthy"), "{v}");

    // per-segment keys: refused without a wrap, then each file gets its own key
    let k = tmp("keys-seg");
    ok(&k, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    put(&k, "a.jpg", "one\n");
    put(&k, "b.jpg", "two\n");
    ok(&k, &["log", "init", "ev", "--segment-keys"]);
    let before = snapshot(&k.join("ev.sigil"));
    let e = fails(&k, &["log", "add", "ev", "photos"]);
    assert!(e.contains("per-segment keys"), "{e}");
    assert_eq!(snapshot(&k.join("ev.sigil")), before);
    let out = ok(&k, &["log", "add", "ev", "photos", "--to", "me.pub"]);
    assert!(out.contains("added 2"), "{out}");
    assert_eq!(read_seq(&k, 2, &["--identity", "me.sgk"]), b"two\n");
    let out = ok(&k, &["log", "add", "ev", "photos", "--to", "me.pub"]);
    assert!(out.contains("unchanged 2"), "{out}");
    let v = ok(&k, &["log", "verify", "ev", "--identity", "me.sgk"]);
    assert!(v.contains("healthy"), "{v}");
    // one file can be crypto-shredded on its own; add does not bring those bytes back
    ok(&k, &["log", "shred", "ev", "--seq", "1"]);
    let out = ok(&k, &["log", "add", "ev", "photos", "--to", "me.pub"]);
    assert!(
        out.contains("= a.jpg  same bytes as segment 1, deleted by entry 3; not re-added")
            && out.contains("unchanged 1"),
        "{out}"
    );
    assert_eq!(read_seq(&k, 2, &["--identity", "me.sgk"]), b"two\n");
}

#[test]
fn tombstoned_version_not_readded_but_new_content_is() {
    let d = tmp("tomb");
    put(&d, "a.jpg", "a\n");
    ok(&d, &["log", "init", "ev"]);
    ok(&d, &["log", "add", "ev", "photos"]);
    ok(&d, &["log", "tombstone", "ev", "--seq", "1"]);
    let out = ok(&d, &["log", "add", "ev", "photos"]);
    assert!(
        out.contains("= a.jpg  same bytes as segment 1, deleted by entry 2; not re-added")
            && out.contains("missing 0"),
        "{out}"
    );
    put(&d, "a.jpg", "a, new content\n");
    let out = ok(&d, &["log", "add", "ev", "photos"]);
    assert!(out.contains("changed 1"), "{out}");
}

#[test]
fn source_change_with_same_size_and_mtime_is_caught() {
    let d = tmp("mtime");
    put(&d, "a.jpg", "aaaa\n");
    ok(&d, &["log", "init", "ev"]);
    ok(&d, &["log", "add", "ev", "photos"]);
    let p = d.join("photos/a.jpg");
    let mtime = fs::metadata(&p).unwrap().modified().unwrap();
    fs::write(&p, "bbbb\n").unwrap();
    fs::File::options()
        .write(true)
        .open(&p)
        .unwrap()
        .set_modified(mtime)
        .unwrap();
    let out = ok(&d, &["log", "add", "ev", "photos"]);
    assert!(out.contains("changed 1, unchanged 0"), "{out}");
    assert_eq!(read_seq(&d, 2, &[]), b"bbbb\n");
}

#[test]
fn bit_flip_in_a_segment_is_detected_by_verify() {
    let d = tmp("flip");
    put(&d, "a.jpg", &"photo bytes ".repeat(500));
    ok(&d, &["log", "init", "ev"]);
    ok(&d, &["log", "add", "ev", "photos"]);
    let p = seg(&d, 1);
    let mut b = fs::read(&p).unwrap();
    let mid = b.len() / 2;
    b[mid] ^= 0x01;
    fs::write(&p, b).unwrap();
    let (code, o) = run(&d, &["log", "verify", "ev"]);
    assert_ne!(code, 0, "{o}");
    assert!(o.contains("bit-rot"), "{o}");
    ok(&d, &["log", "mend", "ev"]);
    let v = ok(&d, &["log", "verify", "ev"]);
    assert!(v.contains("healthy"), "{v}");
}

#[test]
fn missing_or_swapped_segment_is_sealed_again() {
    let d = tmp("swap");
    put(&d, "a.jpg", "a\n");
    put(&d, "b.jpg", "b\n");
    ok(&d, &["log", "init", "ev"]);
    ok(&d, &["log", "add", "ev", "photos"]);
    // segment 1 (a.jpg) replaced by segment 2's star, segment 2 deleted
    fs::copy(seg(&d, 2), seg(&d, 1)).unwrap();
    fs::remove_file(seg(&d, 2)).unwrap();
    let out = ok(&d, &["log", "add", "ev", "photos"]);
    assert!(
        out.contains("a.jpg  2 bytes  sealed again (segment 1 file is not the star the INDEX recorded; was segment 1) → segment 3")
            && out.contains("b.jpg  2 bytes  sealed again (segment 2 file is missing; was segment 2) → segment 4")
            && out.contains("sealed again 2"),
        "{out}"
    );
    assert_eq!(read_seq(&d, 3, &[]), b"a\n");
    assert_eq!(read_seq(&d, 4, &[]), b"b\n");
}

fn chain(prev: &[u8; 32], body: &str) -> [u8; 32] {
    let mut h = Sha256::new();
    h.update(b"sigil-log-entry-v1\0");
    h.update(prev);
    h.update(body.as_bytes());
    h.finalize().into()
}

/// Append a line with a valid chain hash (what someone with write access but no key can do).
fn forge_line(d: &Path, body_wo_seq: &str) {
    let idx = index(d);
    let last = idx.lines().last().unwrap();
    let prev: [u8; 32] = hex::decode(last.rsplit_once(" chain=").unwrap().1)
        .unwrap()
        .try_into()
        .unwrap();
    let seq = idx.lines().count(); // magic line + n entries → next seq = n + 1
    let body = format!("seq={seq} t=1 {body_wo_seq}");
    let line = format!("{body} chain={}\n", hex::encode(chain(&prev, &body)));
    fs::write(d.join("ev.sigil/INDEX"), idx + &line).unwrap();
}

#[test]
fn tampered_index_never_causes_a_silent_skip() {
    // signed log: a forged line claiming the new content is already in, without a new signed HEAD
    let d = tmp("forge-signed");
    ok(&d, &["keygen", "-o", "me.sgk", "--pub-out", "me.pub"]);
    put(&d, "a.jpg", "old\n");
    ok(&d, &["log", "init", "ev", "--identity", "me.sgk"]);
    ok(&d, &["log", "add", "ev", "photos", "--identity", "me.sgk"]);
    put(&d, "a.jpg", "new\n");
    let sha = hex::encode(Sha256::digest(b"new\n"));
    forge_line(&d, &format!("size=4 sha={sha} path=a.jpg"));
    let out = ok(&d, &["log", "add", "ev", "photos", "--identity", "me.sgk"]);
    assert!(
        out.contains("not covered by a valid HEAD signature")
            && out.contains("a.jpg  4 bytes  changed (was segment 1) → segment 3"),
        "{out}"
    );
    assert_eq!(
        read_seq(&d, 3, &[]),
        b"new\n",
        "the real bytes are in the log"
    );

    // unsigned log: forged line + HEAD removed (so the forgery is "vouched"); the segment it points
    // at does not exist, so the file is sealed again instead of skipped
    let u = tmp("forge-unsigned");
    put(&u, "a.jpg", "old\n");
    ok(&u, &["log", "init", "ev"]);
    ok(&u, &["log", "add", "ev", "photos"]);
    put(&u, "a.jpg", "new\n");
    forge_line(&u, &format!("size=4 sha={sha} path=a.jpg"));
    fs::remove_file(u.join("ev.sigil/HEAD")).unwrap();
    let out = ok(&u, &["log", "add", "ev", "photos"]);
    assert!(
        out.contains(
            "a.jpg  4 bytes  sealed again (segment 2 file is missing; was segment 2) → segment 3"
        ),
        "{out}"
    );
    assert_eq!(read_seq(&u, 3, &[]), b"new\n");

    // an edited line breaks the chain: refused, dry run included, nothing written
    let e = tmp("edit");
    put(&e, "a.jpg", "old\n");
    ok(&e, &["log", "init", "ev"]);
    ok(&e, &["log", "add", "ev", "photos"]);
    put(&e, "a.jpg", "new\n");
    let idx = index(&e);
    let old_sha = hex::encode(Sha256::digest(b"old\n"));
    fs::write(e.join("ev.sigil/INDEX"), idx.replace(&old_sha, &sha)).unwrap();
    let before = snapshot(&e.join("ev.sigil"));
    let msg = fails(&e, &["log", "add", "ev", "photos", "--dry-run"]);
    assert!(msg.contains("INDEX is damaged"), "{msg}");
    let msg = fails(&e, &["log", "add", "ev", "photos"]);
    assert!(msg.contains("INDEX is damaged"), "{msg}");
    assert_eq!(snapshot(&e.join("ev.sigil")), before);
}

#[test]
fn truncated_log_refused() {
    let d = tmp("trunc");
    put(&d, "a.jpg", "a\n");
    put(&d, "b.jpg", "b\n");
    ok(&d, &["log", "init", "ev"]);
    ok(&d, &["log", "add", "ev", "photos"]);
    // cut the last INDEX entry off: HEAD now claims more than INDEX holds
    let idx = index(&d);
    let mut lines: Vec<&str> = idx.lines().collect();
    lines.pop();
    fs::write(d.join("ev.sigil/INDEX"), lines.join("\n") + "\n").unwrap();
    let before = snapshot(&d.join("ev.sigil"));
    for extra in [&["--dry-run"][..], &[][..]] {
        let mut args = vec!["log", "add", "ev", "photos"];
        args.extend_from_slice(extra);
        let msg = fails(&d, &args);
        assert!(msg.contains("truncated"), "{msg}");
    }
    assert_eq!(snapshot(&d.join("ev.sigil")), before);
}

#[test]
fn rename_empty_file_duplicates_and_second_folder() {
    let d = tmp("rename");
    put(&d, "a.jpg", "same\n");
    put(&d, "copy-of-a.jpg", "same\n");
    put(&d, "b.jpg", "b\n");
    ok(&d, &["log", "init", "ev"]);
    let out = ok(&d, &["log", "add", "ev", "photos"]);
    assert!(
        out.contains("added 3"),
        "identical files at two paths are stored twice: {out}"
    );
    // a rename is "missing" + "new"; an emptied file is a new, empty version
    fs::rename(d.join("photos/b.jpg"), d.join("photos/b2.jpg")).unwrap();
    fs::write(d.join("photos/a.jpg"), "").unwrap();
    let out = ok(&d, &["log", "add", "ev", "photos"]);
    assert!(
        out.contains("added 1, changed 1, unchanged 1, missing 1")
            && out.contains("a.jpg  0 bytes  changed (was segment 1) → segment 4")
            && out.contains("! b.jpg  missing from source (kept: segment 2)"),
        "{out}"
    );
    assert_eq!(read_seq(&d, 4, &[]), b"");
    assert_eq!(read_seq(&d, 1, &[]), b"same\n");
    // a second, unrelated folder in the same log: the first folder's files show as missing
    fs::create_dir_all(d.join("other")).unwrap();
    fs::write(d.join("other/x.jpg"), "x\n").unwrap();
    let out = ok(&d, &["log", "add", "ev", "other"]);
    assert!(
        out.contains("added 1, changed 0, unchanged 0, missing 4"),
        "{out}"
    );
}

#[test]
fn compact_mount_mode_and_restore() {
    let d = tmp("compact");
    put(&d, "a.jpg", "a\n");
    put(&d, "b.jpg", "b\n");
    put(&d, "c.jpg", "c\n");
    ok(&d, &["log", "init", "ev"]);
    ok(&d, &["log", "add", "ev", "photos"]);
    // merged into one compaction segment: the files still count as held (checked via the holder)
    ok(&d, &["log", "compact", "ev", "--apply"]);
    assert!(
        !seg(&d, 1).exists(),
        "old segment files erased by compaction"
    );
    let out = ok(&d, &["log", "add", "ev", "photos"]);
    assert!(out.contains("added 0, changed 0, unchanged 3"), "{out}");
    // one file back by seq, to a file
    ok(
        &d,
        &["log", "read", "ev", "--seq", "2", "-o", "b-restored.jpg"],
    );
    assert_eq!(fs::read(d.join("b-restored.jpg")).unwrap(), b"b\n");
    // mount view: one file per seq
    ok(
        &d,
        &[
            "mount",
            "ev",
            "view",
            "--export-dir",
            d.join("export").to_str().unwrap(),
        ],
    );
    assert_eq!(fs::read(d.join("export/0000000003")).unwrap(), b"c\n");
    // --mode reaches each file's segment: Seal is bigger than the Reflection default
    let big: String = (0..4000u32)
        .map(|i| char::from(b'a' + (i * 7919 % 26) as u8))
        .collect();
    put(&d, "big-r.bin", &big);
    ok(&d, &["log", "add", "ev", "photos"]);
    let r_len = fs::metadata(seg(&d, 5)).unwrap().len();
    put(&d, "big-s.bin", &big);
    ok(&d, &["log", "add", "ev", "photos", "--mode", "seal"]);
    let s_len = fs::metadata(seg(&d, 6)).unwrap().len();
    assert!(s_len > r_len, "seal {s_len} vs reflection {r_len}");
}

#[cfg(unix)]
#[test]
fn unreadable_file_listed_and_exit_1() {
    use std::os::unix::fs::PermissionsExt;
    let d = tmp("unreadable");
    put(&d, "a.jpg", "a\n");
    put(&d, "locked.jpg", "secret\n");
    let p = d.join("photos/locked.jpg");
    fs::set_permissions(&p, fs::Permissions::from_mode(0o000)).unwrap();
    if fs::read(&p).is_ok() {
        eprintln!("running as root: permissions do not stop reads; skipping");
        return;
    }
    ok(&d, &["log", "init", "ev"]);
    let (code, out) = run(&d, &["log", "add", "ev", "photos"]);
    assert_eq!(code, 1, "{out}");
    assert!(
        out.contains("? locked.jpg  unreadable, not added") && out.contains("added 1"),
        "{out}"
    );
    fs::set_permissions(&p, fs::Permissions::from_mode(0o644)).unwrap();
}
