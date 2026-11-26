//! Protected plain Tome (Tome v3): a new unlocked Tome keeps its folder list inside the
//! repair-protected body (the Warded Tome layout, not encrypted). Round trips in every
//! mode, older Tomes (fixtures written by the last build before v3) still open exactly,
//! and damage to the list either repairs or fails closed, never gives a wrong tree.
mod common;
use std::collections::BTreeMap;
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

fn xorshift(n: usize) -> Vec<u8> {
    let mut x: u64 = 0x2545_f491_4f6c_dd1d;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

/// The fixture source tree (see tests/fixtures/tome-v1/README.md).
fn fixture_src(d: &Path) {
    let s = xorshift(100_000);
    std::fs::create_dir_all(d.join("src/sub")).expect("mkdir");
    std::fs::write(d.join("src/a.txt"), b"alpha\n").expect("w");
    std::fs::write(d.join("src/sub/b.bin"), &s[..3_000]).expect("w");
    std::fs::write(d.join("src/sub/large.bin"), &s).expect("w");
}

/// A folder with long, deep names (like the fragility test's deep shape).
fn deep_src(d: &Path) {
    let mut dir = d.join("deep");
    for lvl in 0..3 {
        dir = dir.join(format!("level{lvl:02}-folder-with-a-long-name"));
        std::fs::create_dir_all(&dir).expect("mkdir");
        for i in 0..4 {
            let body = format!("level {lvl} document {i} ").repeat(40 + i);
            std::fs::write(
                dir.join(format!("document-number-{lvl}{i:02}-final-version.dat")),
                body,
            )
            .expect("w");
        }
    }
}

fn tree(root: &Path) -> BTreeMap<String, Vec<u8>> {
    let mut out = BTreeMap::new();
    let mut stack = vec![root.to_path_buf()];
    while let Some(d) = stack.pop() {
        for e in std::fs::read_dir(&d).expect("read_dir") {
            let p = e.expect("entry").path();
            if p.is_dir() {
                stack.push(p);
            } else {
                let rel = p
                    .strip_prefix(root)
                    .expect("rel")
                    .to_string_lossy()
                    .into_owned();
                out.insert(rel, std::fs::read(&p).expect("read"));
            }
        }
    }
    out
}

#[test]
fn new_unlocked_tomes_are_v3_and_round_trip_in_every_mode() {
    let d = common::scratch("prot-modes");
    fixture_src(&d);
    let want = tree(&d.join("src"));
    for mode in ["glyph", "reflection", "seal"] {
        for chunk in ["65536", "4194304"] {
            let f = format!("{mode}-{chunk}.sg1");
            ok(
                &d,
                &["seal", "--mode", mode, "--chunk", chunk, "-o", &f, "src"],
            );
            let raw = std::fs::read(d.join(&f)).expect("r");
            assert_eq!(&raw[..5], b"SGDR\x03", "{f}");
            let s = ok(&d, &["scry", &f]);
            assert!(s.contains("file  sub/large.bin  100000 bytes"), "{f}: {s}");
            assert!(!s.contains("names hidden"), "{f}: {s}");
            let l = ok(&d, &["ls", &f]);
            assert!(l.contains("sub/b.bin"), "{f}: {l}");
            let out = format!("out-{f}");
            ok(&d, &["unseal", &f, "-o", &out]);
            assert_eq!(tree(&d.join(&out)), want, "{f}");
            let one = format!("one-{f}");
            ok(&d, &["unseal", "--only", "sub/b.bin", "-o", &one, &f]);
            assert_eq!(
                std::fs::read(d.join(&one).join("sub/b.bin")).expect("b"),
                want["sub/b.bin"]
            );
            let m = format!("m-{f}");
            ok(&d, &["mend", &f, "-o", &m]);
            assert_eq!(
                std::fs::read(d.join(&m)).expect("m"),
                raw,
                "{f}: clean mend"
            );
        }
    }
}

#[test]
fn older_layout_on_request_and_with_a_key_unchanged() {
    let d = common::scratch("prot-old");
    fixture_src(&d);
    ok(&d, &["seal", "--old-tome-layout", "-o", "v1.sg1", "src"]);
    assert_eq!(
        &std::fs::read(d.join("v1.sg1")).expect("r")[..5],
        b"SGDR\x01"
    );
    ok(
        &d,
        &["seal", "--pass", "prot-pass-1", "-o", "v2.sg1", "src"],
    );
    assert_eq!(
        &std::fs::read(d.join("v2.sg1")).expect("r")[..5],
        b"SGDR\x02"
    );
    let o = sigil(
        &d,
        &[
            "seal",
            "--old-tome-layout",
            "--pass",
            "prot-pass-1",
            "-o",
            "x.sg1",
            "src",
        ],
    );
    assert!(
        !o.status.success() && !d.join("x.sg1").exists(),
        "{}",
        text(&o)
    );
}

#[test]
fn tomes_written_before_v3_still_open_exactly() {
    let d = common::scratch("prot-fixtures");
    fixture_src(&d);
    let want = tree(&d.join("src"));
    let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/tome-v1");
    for name in [
        "tome-v1-glyph.sg1",
        "tome-v1-reflection.sg1",
        "tome-v1-seal.sg1",
    ] {
        let raw = std::fs::read(fx.join(name)).expect("fixture");
        assert_eq!(&raw[..5], b"SGDR\x01", "{name}");
        std::fs::write(d.join(name), &raw).expect("w");
        let s = ok(&d, &["scry", name]);
        assert!(
            s.contains("file  sub/large.bin  100000 bytes"),
            "{name}: {s}"
        );
        assert!(ok(&d, &["ls", name]).contains("a.txt"));
        let out = format!("out-{name}");
        ok(&d, &["unseal", name, "-o", &out]);
        assert_eq!(tree(&d.join(&out)), want, "{name}");
        let m = format!("m-{name}");
        ok(&d, &["mend", name, "-o", &m]);
        assert_eq!(
            std::fs::read(d.join(&m)).expect("m"),
            raw,
            "{name}: mend changed it"
        );
    }
    let raw = std::fs::read(fx.join("tome-v2-pass.sg1")).expect("fixture");
    assert_eq!(&raw[..5], b"SGDR\x02");
    std::fs::write(d.join("w.sg1"), &raw).expect("w");
    ok(
        &d,
        &["unseal", "--pass", "fixture pass", "-o", "wout", "w.sg1"],
    );
    assert_eq!(tree(&d.join("wout")), want);
    let o = sigil(&d, &["unseal", "-o", "nokey", "w.sg1"]);
    assert!(!o.status.success() && !d.join("nokey").exists());
}

/// Every damaged copy either gives the exact tree (as-is or after `sigil mend`) or is
/// refused with nothing written. Returns (exact, refused).
fn never_wrong(d: &Path, f: &str, want: &BTreeMap<String, Vec<u8>>) -> (bool, bool) {
    let out = format!("o-{f}");
    let o = sigil(d, &["unseal", f, "-o", &out]);
    if o.status.success() {
        assert_eq!(
            &tree(&d.join(&out)),
            want,
            "{f}: exit 0 with a different tree"
        );
        return (true, false);
    }
    assert!(!d.join(&out).exists(), "{f}: refused but wrote output");
    let s = sigil(d, &["scry", f]);
    assert_ne!(
        s.status.code(),
        Some(0),
        "{f}: scry exit 0 on a copy that will not open"
    );
    let m = format!("m-{f}");
    let o = sigil(d, &["mend", "-y", f, "-o", &m]);
    if !o.status.success() {
        assert!(!d.join(&m).exists(), "{f}: mend refused but wrote output");
        return (false, true);
    }
    let out2 = format!("o2-{f}");
    let o = sigil(d, &["unseal", &m, "-o", &out2]);
    if o.status.success() {
        assert_eq!(
            &tree(&d.join(&out2)),
            want,
            "{f}: mended copy opens to a different tree"
        );
        return (true, false);
    }
    assert!(!d.join(&out2).exists());
    (false, true)
}

#[test]
fn damaged_list_and_head_repair_or_fail_closed() {
    let d = common::scratch("prot-damage");
    deep_src(&d);
    let want = tree(&d.join("deep"));
    ok(&d, &["seal", "-o", "t.sg1", "deep"]);
    let raw = std::fs::read(d.join("t.sg1")).expect("r");
    assert_eq!(&raw[..5], b"SGDR\x03");
    let mut exact = 0;
    // Single bit flips spread over the whole body, including where the folder list sits
    // (the start of the inner pack) and the end: the ".dat" -> ".dau" kind of damage.
    let body = 17..raw.len();
    for (i, at) in body.clone().step_by(body.len() / 48).enumerate() {
        let mut bad = raw.clone();
        bad[at] ^= 1 << (i % 8);
        let f = format!("flip{i}.sg1");
        std::fs::write(d.join(&f), &bad).expect("w");
        if never_wrong(&d, &f, &want).0 {
            exact += 1;
        }
    }
    assert_eq!(exact, 49, "single bit flips in the body are all repaired");
    // The head (outside the body): count and body length are rebuilt by mend.
    for (f, at) in [("count.sg1", 6usize), ("blen.sg1", 10)] {
        let mut bad = raw.clone();
        bad[at] ^= 0x08;
        std::fs::write(d.join(f), &bad).expect("w");
        let o = sigil(&d, &["unseal", f, "-o", "x"]);
        assert!(
            !o.status.success() && !d.join("x").exists(),
            "{f}: {}",
            text(&o)
        );
        let m = format!("m-{f}");
        let t = ok(&d, &["mend", "-y", f, "-o", &m]);
        assert!(t.contains("rebuilt"), "{f}: {t}");
        assert_eq!(std::fs::read(d.join(&m)).expect("m"), raw, "{f}");
    }
    // Truncation: refused, nothing written.
    for frac in [0.99f64, 0.9, 0.5] {
        let f = format!("cut{}.sg1", (frac * 100.0) as u32);
        std::fs::write(d.join(&f), &raw[..(raw.len() as f64 * frac) as usize]).expect("w");
        let (ok_exact, _) = never_wrong(&d, &f, &want);
        assert!(!ok_exact || frac > 0.6, "{f}: half a Tome cannot come back");
    }
    // A burst of zeros inside the body.
    let mut bad = raw.clone();
    let mid = raw.len() / 3;
    bad[mid..mid + 4096].fill(0);
    std::fs::write(d.join("burst.sg1"), &bad).expect("w");
    never_wrong(&d, "burst.sg1", &want);
}

#[test]
fn unknown_tome_version_is_refused_cleanly() {
    let d = common::scratch("prot-unknown");
    fixture_src(&d);
    ok(&d, &["seal", "-o", "t.sg1", "src"]);
    let mut raw = std::fs::read(d.join("t.sg1")).expect("r");
    raw[4] = 4;
    std::fs::write(d.join("v4.sg1"), &raw).expect("w");
    for args in [
        vec!["unseal", "v4.sg1", "-o", "o"],
        vec!["ls", "v4.sg1"],
        vec!["scry", "v4.sg1"],
        vec!["mend", "v4.sg1", "-o", "m.sg1"],
    ] {
        let o = sigil(&d, &args);
        let t = text(&o);
        assert!(!o.status.success(), "{args:?}: {t}");
        assert!(t.contains("unknown Tome version 4"), "{args:?}: {t}");
    }
    assert!(!d.join("o").exists() && !d.join("m.sg1").exists());
}

#[test]
fn a_protected_tome_can_get_sealed_names() {
    let d = common::scratch("prot-names");
    fixture_src(&d);
    let want = tree(&d.join("src"));
    ok(&d, &["seal", "-o", "t.sg1", "src"]);
    ok(
        &d,
        &[
            "seal-folder-names",
            "--pass",
            "prot-pass-2",
            "-o",
            "n.sg1",
            "t.sg1",
        ],
    );
    assert_eq!(
        &std::fs::read(d.join("n.sg1")).expect("r")[..5],
        b"SGDR\x02"
    );
    ok(
        &d,
        &["unseal", "--pass", "prot-pass-2", "-o", "out", "n.sg1"],
    );
    assert_eq!(tree(&d.join("out")), want);
}

#[test]
fn ward_only_tome_with_visible_names_is_protected_and_keeps_its_ward() {
    let d = common::scratch("prot-ward");
    fixture_src(&d);
    let want = tree(&d.join("src"));
    std::fs::write(d.join("wp"), "prot ward pass 3\n").expect("w");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(d.join("wp"), std::fs::Permissions::from_mode(0o600))
            .expect("chmod");
    }
    ok(
        &d,
        &[
            "seal",
            "--ward-file",
            "a.txt=wp",
            "--ward-names-visible",
            "-o",
            "w.sg1",
            "src",
        ],
    );
    assert_eq!(
        &std::fs::read(d.join("w.sg1")).expect("r")[..5],
        b"SGDR\x03"
    );
    let o = sigil(&d, &["unseal", "-o", "nokey", "w.sg1"]);
    assert!(
        !o.status.success() && !d.join("nokey").exists(),
        "{}",
        text(&o)
    );
    ok(
        &d,
        &["unseal", "--ward-file", "a.txt=wp", "-o", "out", "w.sg1"],
    );
    assert_eq!(tree(&d.join("out")), want);
}
