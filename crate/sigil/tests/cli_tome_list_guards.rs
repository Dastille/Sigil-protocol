//! A plain Tome's folder list has no repair data of its own, so one damaged byte there
//! used to give wrong output with exit 0: a renamed member, two members sharing a name
//! (one silently overwriting the other), or a lowered member count dropping members.
//! These guards make Scry, unseal and Mend refuse such a copy with exit 2 ("folder
//! list damaged") and write nothing, while a copy that is really cut short is still
//! reported as cut short. Also: stored names with terminal control characters are
//! shown escaped, and a Tome whose first bytes are damaged is not called healthy.
mod common;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn sigil(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(common::pass_via_file(args))
        .stdin(Stdio::null())
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
    let o = sigil(dir, args);
    let t = text(&o);
    assert!(o.status.success(), "{args:?}: {t}");
    t
}

fn data(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// One folder-list entry: where its name starts, the name, and its star length field.
struct Entry {
    name_at: usize,
    name: Vec<u8>,
    len_at: usize,
}

fn entries(raw: &[u8]) -> Vec<Entry> {
    assert_eq!(&raw[..5], b"SGDR\x01", "plain v1 Tome");
    let count = u32::from_le_bytes(raw[5..9].try_into().expect("count"));
    let mut at = 9usize;
    let mut out = Vec::new();
    for _ in 0..count {
        let nlen = u16::from_le_bytes(raw[at..at + 2].try_into().expect("nlen")) as usize;
        let name_at = at + 2;
        let len_at = name_at + nlen;
        let slen = u64::from_le_bytes(raw[len_at..len_at + 8].try_into().expect("slen"));
        out.push(Entry {
            name_at,
            name: raw[name_at..len_at].to_vec(),
            len_at,
        });
        at = len_at + 8 + slen as usize;
    }
    assert_eq!(at, raw.len(), "list ends at end of file");
    out
}

/// A plain Tome of `files` small members `f/a0.bin`.. (plus one large member when `big`).
fn tome(d: &Path, files: usize, big: bool) -> Vec<u8> {
    std::fs::create_dir_all(d.join("f")).expect("mkdir");
    for i in 0..files {
        std::fs::write(d.join(format!("f/a{i}.bin")), data(3_000 + i, i as u64 + 7)).expect("w");
    }
    if big {
        std::fs::write(d.join("f/large.bin"), data(9 * 1024 * 1024, 5)).expect("w");
    }
    ok(d, &["seal", "--old-tome-layout", "f", "-o", "t.sg1"]);
    std::fs::read(d.join("t.sg1")).expect("r")
}

fn find(raw: &[u8], name: &[u8]) -> Entry {
    entries(raw)
        .into_iter()
        .find(|e| e.name.ends_with(name))
        .expect("member in list")
}

/// Scry, unseal and Mend all refuse with exit 2, say "folder list damaged" (plus
/// `why`), never print "healthy", and write nothing.
fn all_refuse(d: &Path, file: &str, why: &str) {
    let o = sigil(d, &["scry", file]);
    let t = text(&o);
    assert_eq!(o.status.code(), Some(2), "scry: {t}");
    assert!(
        t.contains("folder list damaged") && t.contains(why),
        "scry: {t}"
    );
    assert!(!t.contains("healthy"), "scry: {t}");
    assert!(
        !t.contains("cut short"),
        "scry must not blame the copy: {t}"
    );
    let o = sigil(d, &["unseal", file, "-o", "out"]);
    let t = text(&o);
    assert_eq!(o.status.code(), Some(2), "unseal: {t}");
    assert!(
        t.contains("folder list damaged") && t.contains(why),
        "unseal: {t}"
    );
    assert!(!d.join("out").exists(), "unseal wrote output: {t}");
    let o = sigil(d, &["mend", file, "-o", "mended.sg1"]);
    let t = text(&o);
    assert_eq!(o.status.code(), Some(2), "mend: {t}");
    assert!(
        t.contains("folder list damaged") && t.contains(why),
        "mend: {t}"
    );
    assert!(!d.join("mended.sg1").exists(), "mend wrote output: {t}");
}

#[test]
fn one_bit_name_collision_refuses_instead_of_overwriting_a_member() {
    // The step-3 case: one bit turned a name into another member's name, so the list
    // named every member but one file overwrote the other (n listed, n - 1 written).
    let d = common::scratch("guard-collide");
    let mut raw = tome(&d, 6, false);
    let e = find(&raw, b"a3.bin");
    let i = e.name_at + e.name.len() - 5; // the '3'
    raw[i] ^= 0x02; // '3' -> '1'
    assert_eq!(
        &raw[e.name_at..e.name_at + e.name.len()],
        b"a1.bin".as_slice()
    );
    std::fs::write(d.join("c.sg1"), &raw).expect("w");
    all_refuse(&d, "c.sg1", "two members are both named");
}

#[test]
fn renamed_member_disagreeing_with_its_own_header_is_refused() {
    let d = common::scratch("guard-rename");
    let mut raw = tome(&d, 3, false);
    let e = find(&raw, b"a2.bin");
    raw[e.name_at + e.name.len() - 4] ^= 0x01; // ".bin" -> "/bin"
    std::fs::write(d.join("r.sg1"), &raw).expect("w");
    all_refuse(&d, "r.sg1", "own header names");
}

#[test]
fn renamed_large_file_member_is_refused() {
    let d = common::scratch("guard-large");
    let mut raw = tome(&d, 1, true);
    let e = find(&raw, b"large.bin");
    raw[e.name_at + e.name.len() - 6] ^= 0x04; // "large" -> "largm"
    std::fs::write(d.join("l.sg1"), &raw).expect("w");
    all_refuse(&d, "l.sg1", "own header names");
}

#[test]
fn lowered_member_count_is_refused() {
    let d = common::scratch("guard-count");
    for drop in [1u32, 2] {
        let mut raw = tome(&d, 4, false);
        let n = u32::from_le_bytes(raw[5..9].try_into().expect("count"));
        raw[5..9].copy_from_slice(&(n - drop).to_le_bytes());
        let f = format!("n{drop}.sg1");
        std::fs::write(d.join(&f), &raw).expect("w");
        all_refuse(&d, &f, "another member follows the last one");
    }
}

#[test]
fn name_that_is_not_utf8_is_refused() {
    let d = common::scratch("guard-utf8");
    let mut raw = tome(&d, 3, false);
    let e = find(&raw, b"a1.bin");
    raw[e.name_at] ^= 0x80;
    std::fs::write(d.join("u.sg1"), &raw).expect("w");
    all_refuse(&d, "u.sg1", "not valid UTF-8");
}

#[test]
fn star_length_running_past_the_end_is_list_damage_not_a_cut_copy() {
    let d = common::scratch("guard-length");
    let mut raw = tome(&d, 3, false);
    let e = find(&raw, b"a0.bin");
    raw[e.len_at + 3] ^= 0x10; // length now far past the end of the file
    std::fs::write(d.join("p.sg1"), &raw).expect("w");
    all_refuse(&d, "p.sg1", "past the end");

    // A copy that really is cut short is still reported as cut short.
    let clean = std::fs::read(d.join("t.sg1")).expect("r");
    std::fs::write(d.join("cut.sg1"), &clean[..clean.len() - 300]).expect("w");
    let o = sigil(&d, &["scry", "cut.sg1"]);
    let t = text(&o);
    assert_ne!(o.status.code(), Some(0), "{t}");
    assert!(
        t.contains("cut short") && !t.contains("folder list damaged"),
        "{t}"
    );
}

#[test]
fn clean_tome_still_passes_every_guard() {
    let d = common::scratch("guard-clean");
    tome(&d, 5, true);
    ok(&d, &["scry", "t.sg1"]);
    ok(&d, &["unseal", "t.sg1", "-o", "out"]);
    ok(&d, &["mend", "t.sg1", "-o", "m.sg1"]);
    assert_eq!(
        std::fs::read(d.join("m.sg1")).expect("m"),
        std::fs::read(d.join("t.sg1")).expect("t")
    );
}

#[test]
fn damaged_tome_first_bytes_are_never_called_healthy() {
    let d = common::scratch("guard-head");
    std::fs::create_dir_all(d.join("f")).expect("mkdir");
    std::fs::write(d.join("f/x.bin"), data(4_000, 3)).expect("w");
    ok(&d, &["seal", "--old-tome-layout", "f", "-o", "plain.sg1"]);
    ok(
        &d,
        &["seal", "f", "-o", "warded.sg1", "--pass", "guard-pass-1"],
    );
    let warded = std::fs::read(d.join("warded.sg1")).expect("r");
    assert_eq!(&warded[..5], b"SGDR\x02", "Warded Tome");
    ok(&d, &["seal", "f", "-o", "protected.sg1"]);
    for base in ["plain.sg1", "warded.sg1", "protected.sg1"] {
        let raw = std::fs::read(d.join(base)).expect("r");
        for byte in [0usize, 2, 3, 4] {
            let mut bad = raw.clone();
            bad[byte] ^= 0x04;
            let f = format!("h{byte}-{base}");
            std::fs::write(d.join(&f), &bad).expect("w");
            let o = sigil(&d, &["scry", &f]);
            let t = text(&o);
            assert_eq!(o.status.code(), Some(2), "{f}: {t}");
            // An intact `SGDR` with an unknown version may be from a newer sigil.
            let why = if byte == 4 {
                "unknown Tome version"
            } else {
                "Tome head damaged"
            };
            assert!(t.contains(why), "{f}: {t}");
        }
    }
}

const ESC_NAME: &str = "e\u{1b}[31mred\u{7}.txt";

fn no_raw_controls(what: &str, o: &Output) {
    for (stream, b) in [("stdout", &o.stdout), ("stderr", &o.stderr)] {
        assert!(
            !b.iter().any(|&c| c == 0x1b || c == 0x07),
            "{what} {stream} printed a raw control byte: {:?}",
            String::from_utf8_lossy(b)
        );
    }
}

#[test]
fn terminal_escape_names_are_shown_escaped_in_tome_output() {
    let d = common::scratch("guard-ansi-tome");
    std::fs::create_dir_all(d.join("f")).expect("mkdir");
    std::fs::write(d.join("f").join(ESC_NAME), data(9_000, 4)).expect("w");
    std::fs::write(d.join("f/plain.txt"), b"plain").expect("w");
    ok(&d, &["seal", "--old-tome-layout", "f", "-o", "t.sg1"]);

    let o = sigil(&d, &["scry", "t.sg1"]);
    assert!(o.status.success(), "{}", text(&o));
    no_raw_controls("scry", &o);
    assert!(
        text(&o).contains("e\\u{1b}[31mred\\u{7}.txt"),
        "{}",
        text(&o)
    );
    let o = sigil(&d, &["ls", "t.sg1"]);
    assert!(o.status.success(), "{}", text(&o));
    no_raw_controls("ls", &o);
    assert!(
        text(&o).contains("e\\u{1b}[31mred\\u{7}.txt"),
        "{}",
        text(&o)
    );
    let o = sigil(&d, &["unseal", "t.sg1", "-o", "out"]);
    assert!(o.status.success(), "{}", text(&o));
    no_raw_controls("unseal", &o);
    // The file itself keeps its real name.
    assert!(d.join("out").join(ESC_NAME).is_file());

    // Damage the escape-named member so Scry and Mend name it.
    let mut raw = std::fs::read(d.join("t.sg1")).expect("r");
    let e = find(&raw, ESC_NAME.as_bytes());
    let star = e.len_at + 8;
    for k in (star + 200..star + 1_400).step_by(7) {
        raw[k] ^= 0xff;
    }
    std::fs::write(d.join("dmg.sg1"), &raw).expect("w");
    let o = sigil(&d, &["scry", "dmg.sg1"]);
    no_raw_controls("scry damaged", &o);
    assert!(
        text(&o).contains("e\\u{1b}[31mred\\u{7}.txt"),
        "{}",
        text(&o)
    );
    let o = sigil(&d, &["mend", "dmg.sg1", "-o", "m.sg1"]);
    assert!(o.status.success(), "{}", text(&o));
    no_raw_controls("mend", &o);
    assert!(
        text(&o).contains("healed: e\\u{1b}[31mred\\u{7}.txt"),
        "{}",
        text(&o)
    );

    // An error that quotes the stored name escapes it too.
    let mut bad = std::fs::read(d.join("t.sg1")).expect("r");
    let e = find(&bad, ESC_NAME.as_bytes());
    bad[e.len_at + 3] ^= 0x10;
    std::fs::write(d.join("bad.sg1"), &bad).expect("w");
    for args in [
        vec!["scry", "bad.sg1"],
        vec!["unseal", "bad.sg1", "-o", "o2"],
        vec!["mend", "bad.sg1", "-o", "m2.sg1"],
    ] {
        let o = sigil(&d, &args);
        assert_eq!(o.status.code(), Some(2), "{args:?}: {}", text(&o));
        no_raw_controls(args[0], &o);
    }
}

#[test]
fn terminal_escape_names_are_shown_escaped_for_a_single_archive() {
    let d = common::scratch("guard-ansi-one");
    let name = "x\u{1b}]0;title\u{7}y.txt";
    std::fs::write(d.join(name), b"hello").expect("w");
    let o = sigil(&d, &["seal", name, "-o", "s.sg1"]);
    assert!(o.status.success(), "{}", text(&o));
    no_raw_controls("seal", &o);
    let o = sigil(&d, &["scry", "s.sg1"]);
    assert!(o.status.success(), "{}", text(&o));
    no_raw_controls("scry", &o);
    assert!(
        text(&o).contains("x\\u{1b}]0;title\\u{7}y.txt"),
        "{}",
        text(&o)
    );
    let o = sigil(&d, &["unseal", "s.sg1", "-o", "back.txt"]);
    assert!(o.status.success(), "{}", text(&o));
    no_raw_controls("unseal", &o);
    // A failing command that echoes the name escapes it as well.
    let o = sigil(&d, &["unseal", name, "-o", "nope"]);
    assert!(!o.status.success());
    no_raw_controls("unseal error", &o);
}

#[test]
fn long_name_damaged_past_its_header_prefix_is_caught_by_the_name_order() {
    // A member header keeps only the first 16 bytes of the path, so a flip further in
    // is caught by the order Inscribe always writes names in (sorted, folder by folder).
    let d = common::scratch("guard-order");
    let deep = d.join("f/level00-folder-with-a-long-name/level01-folder-with-a-long-name");
    std::fs::create_dir_all(&deep).expect("mkdir");
    for i in 0..4 {
        std::fs::write(deep.join(format!("doc-{i:02}.dat")), data(2_000, i + 1)).expect("w");
    }
    ok(&d, &["seal", "--old-tome-layout", "f", "-o", "t.sg1"]);
    let mut raw = std::fs::read(d.join("t.sg1")).expect("r");
    let e = find(&raw, b"doc-01.dat");
    // "level01" -> "lewel01" (byte 33 of the name, well past the header's 16).
    let at = e.name_at + "level00-folder-with-a-long-name/le".len();
    assert_eq!(raw[at], b'v');
    raw[at] ^= 0x01;
    std::fs::write(d.join("o.sg1"), &raw).expect("w");
    all_refuse(&d, "o.sg1", "out of the order");
}

#[test]
fn tricky_but_valid_name_order_is_accepted() {
    // Sorting is per folder by name, so these names are in Inscribe's order even though
    // plain string order of the full paths would differ ('-' and ' ' sort before '/').
    let d = common::scratch("guard-order-ok");
    for p in [
        "f/a.txt",
        "f/a/x.txt",
        "f/a-b/y.txt",
        "f/a b/z.txt",
        "f/B.txt",
        "f/\u{e9}t\u{e9}.txt",
        "f/a/x/deeper.txt",
        "f/a0",
        "f/a/x0",
    ] {
        let p = d.join(p);
        std::fs::create_dir_all(p.parent().expect("parent")).expect("mkdir");
        std::fs::write(&p, p.to_string_lossy().as_bytes()).expect("w");
    }
    ok(&d, &["seal", "--old-tome-layout", "f", "-o", "t.sg1"]);
    ok(&d, &["scry", "t.sg1"]);
    ok(&d, &["unseal", "t.sg1", "-o", "out"]);
    ok(&d, &["mend", "t.sg1", "-o", "m.sg1"]);
    assert!(d.join("out/a/x/deeper.txt").is_file());
}
