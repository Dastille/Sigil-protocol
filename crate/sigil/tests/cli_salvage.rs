//! `sigil unseal --salvage`: save what passes its own checks from a damaged Tome. Never a
//! wrong file under a real name, never an overwrite; exit 0 / 7 / 2 as documented.
mod common;
use std::collections::BTreeMap;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn sigil_env(dir: &Path, args: &[&str], env: &[(&str, &str)]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sigil"));
    c.current_dir(dir)
        .args(common::pass_via_file(args))
        .stdin(Stdio::null())
        .env_remove("SIGIL_OLD_TOME_LAYOUT");
    for (k, v) in env {
        c.env(k, v);
    }
    c.output().expect("run sigil")
}

fn sigil(dir: &Path, args: &[&str]) -> Output {
    sigil_env(dir, args, &[])
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn code(o: &Output) -> i32 {
    o.status.code().expect("exit code")
}

fn noise(n: usize, seed: u64) -> Vec<u8> {
    let mut x: u64 = 0x2545_f491_4f6c_dd1d ^ seed;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
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
                    .replace('\\', "/");
                out.insert(rel, std::fs::read(&p).expect("read"));
            }
        }
    }
    out
}

/// Ten files, one with a long deep name.
fn src(d: &Path) -> BTreeMap<String, Vec<u8>> {
    let s = d.join("src");
    std::fs::create_dir_all(s.join("sub/level00-folder-with-a-long-name")).expect("mkdir");
    for i in 0..8u64 {
        std::fs::write(
            s.join(format!("sub/f{i}.bin")),
            noise(2_000 + 3_000 * i as usize, i),
        )
        .expect("w");
    }
    std::fs::write(s.join("a.txt"), b"alpha\n").expect("w");
    std::fs::write(
        s.join("sub/level00-folder-with-a-long-name/document-final.dat"),
        noise(50_000, 99),
    )
    .expect("w");
    tree(&s)
}

/// Every written file is right: under its own name with its bytes, or under
/// recovered-names/ with the bytes of some source file. Returns (named, recovered).
fn all_right(out: &Path, want: &BTreeMap<String, Vec<u8>>) -> (usize, usize) {
    let (mut named, mut rec) = (0, 0);
    for (k, v) in tree(out) {
        if k.starts_with("recovered-names/") {
            assert!(
                want.values().any(|w| *w == v),
                "recovered {k} matches no source file"
            );
            rec += 1;
        } else {
            assert_eq!(want.get(&k), Some(&v), "{k} is wrong or unexpected");
            named += 1;
        }
    }
    (named, rec)
}

fn seal(d: &Path, out: &str, extra: &[&str], old: bool) {
    let mut a = vec!["seal", "src", "-o", out];
    a.extend_from_slice(extra);
    let o = sigil_env(
        d,
        &a,
        &[("SIGIL_OLD_TOME_LAYOUT", if old { "1" } else { "0" })],
    );
    assert!(o.status.success(), "{}", text(&o));
}

/// Offset of the list entry for `name` in a v1 Tome.
fn entry_of(raw: &[u8], name: &str) -> usize {
    let n = u32::from_le_bytes(raw[5..9].try_into().expect("4")) as usize;
    let mut off = 9;
    for _ in 0..n {
        let nl = u16::from_le_bytes([raw[off], raw[off + 1]]) as usize;
        let sl =
            u64::from_le_bytes(raw[off + 2 + nl..off + 10 + nl].try_into().expect("8")) as usize;
        if &raw[off + 2..off + 2 + nl] == name.as_bytes() {
            return off;
        }
        off += 10 + nl + sl;
    }
    panic!("no entry {name}");
}

#[test]
fn clean_tomes_of_every_layout_salvage_exactly_with_exit_0() {
    let d = common::scratch("salvage-clean");
    let want = src(&d);
    seal(&d, "v1.sg1", &[], true);
    seal(&d, "v3.sg1", &[], false);
    seal(&d, "v2.sg1", &["--pass", "pw"], false);
    for (t, key) in [("v1.sg1", false), ("v3.sg1", false), ("v2.sg1", true)] {
        let out = format!("o-{t}");
        let mut a = vec!["unseal", "--salvage", t, "-o", out.as_str()];
        if key {
            a.extend_from_slice(&["--pass", "pw"]);
        }
        let o = sigil(&d, &a);
        assert_eq!(code(&o), 0, "{t}: {}", text(&o));
        assert_eq!(tree(&d.join(&out)), want, "{t}");
        let rep =
            std::fs::read_to_string(d.join(format!("{out}.salvage-report.txt"))).expect("report");
        assert!(rep.contains("restored 10, renamed 0, lost 0"), "{rep}");
    }
    // A key given for an unlocked Tome does not get in the way.
    let o = sigil(
        &d,
        &["unseal", "--salvage", "v3.sg1", "-o", "o-k", "--pass", "pw"],
    );
    assert_eq!(code(&o), 0, "{}", text(&o));
}

#[test]
fn damaged_v1_list_saves_every_member_and_marks_unconfirmed_names() {
    let d = common::scratch("salvage-list");
    let want = src(&d);
    seal(&d, "v1.sg1", &[], true);
    let raw = std::fs::read(d.join("v1.sg1")).expect("r");
    // Plain unseal refuses a broken name length; salvage finds the data anyway.
    let mut a = raw.clone();
    a[entry_of(&raw, "a.txt")] ^= 0x40;
    std::fs::write(d.join("len.sg1"), &a).expect("w");
    // A changed name inside the 16 bytes the member's header keeps.
    let mut b = raw.clone();
    let e = entry_of(&raw, "sub/f3.bin");
    b[e + 2 + 5] = b'9';
    std::fs::write(d.join("name.sg1"), &b).expect("w");
    for t in ["len.sg1", "name.sg1"] {
        let out = format!("o-{t}");
        let o = sigil(&d, &["unseal", "--salvage", t, "-o", out.as_str()]);
        let msg = text(&o);
        assert_eq!(code(&o), 7, "{t}: {msg}");
        let (named, rec) = all_right(&d.join(&out), &want);
        assert_eq!((named, rec), (9, 1), "{t}: {msg}");
        assert!(
            msg.contains("renamed") && msg.contains("recovered-names/"),
            "{msg}"
        );
        assert!(
            !d.join(&out).join("sub/f9.bin").exists(),
            "a wrong name was used"
        );
    }
    let rep = std::fs::read_to_string(d.join("o-name.sg1.salvage-report.txt")).expect("report");
    assert!(rep.contains("sub/f9.bin -> recovered-names/"), "{rep}");
}

#[test]
fn truncated_tomes_save_what_is_whole_and_report_the_rest() {
    let d = common::scratch("salvage-trunc");
    let want = src(&d);
    seal(&d, "v1.sg1", &[], true);
    seal(&d, "v3.sg1", &[], false);
    for t in ["v1.sg1", "v3.sg1"] {
        let raw = std::fs::read(d.join(t)).expect("r");
        let cut = format!("cut-{t}");
        std::fs::write(d.join(&cut), &raw[..raw.len() * 99 / 100]).expect("w");
        let out = format!("o-{cut}");
        let o = sigil(
            &d,
            &["unseal", "--salvage", cut.as_str(), "-o", out.as_str()],
        );
        let msg = text(&o);
        // v3 repairs a 1% cut when the repair data allow it (then everything is saved).
        let (named, rec) = all_right(&d.join(&out), &want);
        if code(&o) == 0 {
            assert_eq!(named, 10, "{t}: {msg}");
        } else {
            assert_eq!(code(&o), 7, "{t}: {msg}");
            assert!(named + rec >= 1 && msg.contains("lost"), "{t}: {msg}");
        }
    }
}

#[test]
fn never_overwrites_and_renames_with_a_clear_suffix() {
    let d = common::scratch("salvage-taken");
    let want = src(&d);
    seal(&d, "v3.sg1", &[], false);
    std::fs::create_dir_all(d.join("out/sub")).expect("mkdir");
    std::fs::write(d.join("out/a.txt"), b"mine").expect("w");
    std::fs::write(d.join("out.salvage-report.txt"), b"old report").expect("w");
    let o = sigil(&d, &["unseal", "--salvage", "v3.sg1", "-o", "out"]);
    let msg = text(&o);
    assert_eq!(code(&o), 7, "{msg}");
    assert_eq!(std::fs::read(d.join("out/a.txt")).expect("r"), b"mine");
    assert_eq!(
        std::fs::read(d.join("out/a.txt.salvaged-1")).expect("r"),
        want["a.txt"]
    );
    assert_eq!(
        std::fs::read(d.join("out.salvage-report.txt")).expect("r"),
        b"old report"
    );
    let rep = std::fs::read_to_string(d.join("out.salvage-report-1.txt")).expect("report");
    assert!(
        rep.contains("a.txt -> a.txt.salvaged-1 (that name was already taken"),
        "{rep}"
    );
    // A file standing where a folder must go: the member is kept under a recovered name.
    std::fs::create_dir_all(d.join("out2")).expect("mkdir");
    std::fs::write(d.join("out2/sub"), b"a file").expect("w");
    let o = sigil(&d, &["unseal", "--salvage", "v3.sg1", "-o", "out2"]);
    let msg = text(&o);
    assert_eq!(code(&o), 7, "{msg}");
    assert_eq!(std::fs::read(d.join("out2/sub")).expect("r"), b"a file");
    assert!(
        msg.contains("its own folder path could not be made"),
        "{msg}"
    );
}

#[test]
fn warded_tome_needs_its_key_and_refusals_leave_nothing() {
    let d = common::scratch("salvage-key");
    src(&d);
    seal(&d, "v2.sg1", &["--pass", "pw"], false);
    let o = sigil(&d, &["unseal", "--salvage", "v2.sg1", "-o", "nokey"]);
    assert_eq!(code(&o), 1, "{}", text(&o));
    assert!(!d.join("nokey").exists());
    assert!(!d.join("nokey.salvage-report.txt").exists());
    std::fs::write(d.join("not.sg1"), b"hello, not a Tome").expect("w");
    let o = sigil(&d, &["unseal", "--salvage", "not.sg1", "-o", "x"]);
    assert_eq!(code(&o), 1, "{}", text(&o));
    assert!(!d.join("x").exists());
    // Wrong key on a damaged-beyond-repair body: nothing saved, exit 2, never 0.
    let raw = std::fs::read(d.join("v2.sg1")).expect("r");
    std::fs::write(d.join("cut.sg1"), &raw[..raw.len() / 2]).expect("w");
    let o = sigil(
        &d,
        &[
            "unseal",
            "--salvage",
            "cut.sg1",
            "-o",
            "half",
            "--pass",
            "pw",
        ],
    );
    assert_eq!(code(&o), 2, "{}", text(&o));
    assert!(tree(&d.join("half")).is_empty());
}

#[test]
fn a_limit_stops_and_reports_never_guesses() {
    let d = common::scratch("salvage-limit");
    src(&d);
    seal(&d, "v1.sg1", &[], true);
    let o = sigil(
        &d,
        &[
            "unseal",
            "--salvage",
            "v1.sg1",
            "-o",
            "o",
            "--max-secs",
            "0",
        ],
    );
    let msg = text(&o);
    assert_ne!(code(&o), 0, "{msg}");
    assert!(
        msg.contains("STOPPED") && msg.contains("--max-secs"),
        "{msg}"
    );
    assert!(tree(&d.join("o")).is_empty());
    // --max-secs needs --salvage; --salvage refuses options it cannot honour.
    let o = sigil(&d, &["unseal", "v1.sg1", "-o", "p", "--max-secs", "5"]);
    assert_ne!(code(&o), 0);
    let o = sigil(
        &d,
        &[
            "unseal",
            "--salvage",
            "--only",
            "a.txt",
            "v1.sg1",
            "-o",
            "p",
        ],
    );
    assert_ne!(code(&o), 0);
}

#[test]
fn per_file_wards_open_during_salvage() {
    let d = common::scratch("salvage-ward");
    let want = src(&d);
    seal(
        &d,
        "w.sg1",
        &["--ward", "a.txt=wpw", "--ward-names-visible"],
        false,
    );
    let wf = d.join("wpw.txt");
    std::fs::write(&wf, b"wpw\n").expect("w");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&wf, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
    let o = sigil(
        &d,
        &[
            "unseal",
            "--salvage",
            "w.sg1",
            "-o",
            "o",
            "--ward-file",
            "a.txt=wpw.txt",
        ],
    );
    assert_eq!(code(&o), 0, "{}", text(&o));
    assert_eq!(tree(&d.join("o")), want);
    // Without the Ward the warded file is lost (reported), the rest saved: exit 7.
    let o = sigil(&d, &["unseal", "--salvage", "w.sg1", "-o", "o2"]);
    let msg = text(&o);
    assert_eq!(code(&o), 7, "{msg}");
    assert!(msg.contains("lost") && msg.contains("a.txt"), "{msg}");
    assert!(!d.join("o2/a.txt").exists());
}
