//! CLI: easy repair by default. Plain `sigil mend` tries the quick (hard) repair, then the
//! deeper soft repair on its own; picks `<name>.mended.<ext>` next to the input when `-o`
//! is left out (never the input, never an existing file); and fails closed (nonzero exit,
//! no output file) when nothing passes the Merkle + true-name check.
mod common;
use std::path::Path;
use std::process::{Command, Output};

fn sigil(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(common::pass_via_file(args))
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

struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        self.0
    }
    fn bytes(&mut self, n: usize) -> Vec<u8> {
        (0..n).map(|_| self.next() as u8).collect()
    }
    fn flip(&mut self, b: &mut [u8], count: usize) {
        for _ in 0..count {
            let bit = (self.next() % (b.len() as u64 * 8)) as usize;
            b[bit / 8] ^= 1 << (bit % 8);
        }
    }
}

/// Files in `dir` whose name contains `.mended` or `.mend-part`.
fn mended_files(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .expect("read dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".mended") || n.contains(".mend-part"))
        .collect();
    v.sort();
    v
}

fn seal(dir: &Path, data: &[u8], extra: &[&str]) {
    std::fs::write(dir.join("photo.bin"), data).expect("write");
    let mut args = vec!["seal", "-o", "photo.sg1"];
    args.extend_from_slice(extra);
    args.push("photo.bin");
    let o = sigil(dir, &args);
    assert!(o.status.success(), "{}", text(&o));
}

/// Undamaged round trip: no -o → photo.mended.sg1, exact bytes back, input untouched.
#[test]
fn plain_mend_round_trip_default_name() {
    let d = common::scratch("mend-default-rt");
    let data = Rng(0x1234_5678_9abc_def1).bytes(120_000);
    seal(&d, &data, &[]);
    let before = std::fs::read(d.join("photo.sg1")).expect("read");
    let o = sigil(&d, &["mend", "photo.sg1"]);
    assert!(o.status.success(), "{}", text(&o));
    let t = text(&o);
    assert!(t.contains("photo.mended.sg1"), "{t}");
    assert!(t.contains("sigil verify photo.mended.sg1"), "{t}");
    assert!(!t.contains("deeper repair"), "quick repair was enough: {t}");
    assert_eq!(std::fs::read(d.join("photo.sg1")).expect("read"), before);
    let o = sigil(&d, &["unseal", "-o", "back.bin", "photo.mended.sg1"]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(std::fs::read(d.join("back.bin")).expect("read"), data);
}

/// Scattered bit flips in every shard: the quick repair alone refuses (`--hard-only`, exit
/// nonzero, nothing written); plain `mend` falls back to the deeper repair and says so.
#[test]
fn plain_mend_falls_back_to_soft() {
    let d = common::scratch("mend-default-fallback");
    let mut r = Rng(0x9e37_79b9_7f4a_7c15);
    let data = r.bytes(300_000);
    seal(&d, &data, &[]);
    let mut mark = std::fs::read(d.join("photo.sg1")).expect("read");
    r.flip(&mut mark, 200);
    std::fs::write(d.join("photo.sg1"), &mark).expect("write");

    let o = sigil(&d, &["mend", "--hard-only", "photo.sg1"]);
    assert!(!o.status.success(), "{}", text(&o));
    let t = text(&o);
    assert!(t.contains("Nothing was written"), "{t}");
    assert!(t.contains("sigil mend photo.sg1"), "full command: {t}");
    assert!(mended_files(&d).is_empty(), "{:?}", mended_files(&d));

    let o = sigil(&d, &["mend", "photo.sg1"]);
    assert!(o.status.success(), "{}", text(&o));
    let t = text(&o);
    assert!(t.contains("deeper repair"), "{t}");
    assert!(t.contains("soft salvage"), "{t}");
    assert_eq!(std::fs::read(d.join("photo.sg1")).expect("read"), mark);
    let o = sigil(&d, &["unseal", "-o", "back.bin", "photo.mended.sg1"]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(std::fs::read(d.join("back.bin")).expect("read"), data);

    // --soft keeps working; --soft with --hard-only is refused by the parser.
    let o = sigil(&d, &["mend", "--soft", "photo.sg1", "-o", "s.sg1"]);
    assert!(o.status.success(), "{}", text(&o));
    let o = sigil(&d, &["mend", "--soft", "--hard-only", "photo.sg1"]);
    assert!(!o.status.success());
}

/// Damage past both repairs: exit 2 ("too damaged"), plain message, no output file.
#[test]
fn plain_mend_both_fail_refuses_without_output() {
    let d = common::scratch("mend-default-bothfail");
    let mut r = Rng(0xdead_beef_cafe_f00d);
    let data = r.bytes(200_000);
    seal(&d, &data, &[]);
    let mut mark = std::fs::read(d.join("photo.sg1")).expect("read");
    let len = mark.len();
    r.flip(&mut mark, len / 2);
    std::fs::write(d.join("photo.sg1"), &mark).expect("write");
    let o = sigil(&d, &["mend", "photo.sg1"]);
    assert_eq!(o.status.code(), Some(2), "{}", text(&o));
    let t = text(&o);
    assert!(
        t.contains("could not repair") && t.contains("Nothing was written"),
        "{t}"
    );
    assert!(t.contains("sigil mend photo.sg1 <other-copy.sg1>"), "{t}");
    assert!(mended_files(&d).is_empty(), "{:?}", mended_files(&d));
    // Same with an explicit -o: nothing at that path either.
    let o = sigil(&d, &["mend", "photo.sg1", "-o", "out.sg1"]);
    assert!(!o.status.success());
    assert!(!d.join("out.sg1").exists());
    assert_eq!(std::fs::read(d.join("photo.sg1")).expect("read"), mark);
}

/// The default name never replaces an existing file and never equals the input; `--json`
/// reports the picked path.
#[test]
fn default_output_never_clobbers() {
    let d = common::scratch("mend-default-noclobber");
    let data = Rng(0x0bad_5eed_1234_4321).bytes(80_000);
    seal(&d, &data, &[]);
    std::fs::write(d.join("photo.mended.sg1"), b"keep me").expect("write");
    #[cfg(unix)]
    std::os::unix::fs::symlink("nowhere", d.join("photo.mended-2.sg1")).expect("symlink");
    let o = sigil(&d, &["mend", "photo.sg1", "--json"]);
    assert!(o.status.success(), "{}", text(&o));
    let out = String::from_utf8_lossy(&o.stdout);
    let want = if cfg!(unix) {
        "photo.mended-3.sg1"
    } else {
        "photo.mended-2.sg1"
    };
    assert!(
        out.contains(&format!("\"output\":\"{}", d.join(want).display())) || out.contains(want),
        "{out}"
    );
    assert_eq!(
        std::fs::read(d.join("photo.mended.sg1")).expect("read"),
        b"keep me"
    );
    assert!(d.join(want).is_file());
    let o = sigil(&d, &["unseal", "-o", "back.bin", want]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(std::fs::read(d.join("back.bin")).expect("read"), data);
}

/// Tamper sweep (bit flips, zeroed runs, truncation, encrypted with a wrong key): plain
/// `mend` either refuses with no output file, or writes a copy that unseals to exactly
/// the original. It never hands back different bytes.
#[test]
fn tamper_cases_fail_closed() {
    let d = common::scratch("mend-default-tamper");
    let mut r = Rng(0x5151_7272_9393_b4b4);
    let data = r.bytes(150_000);
    for encrypted in [false, true] {
        let extra: &[&str] = if encrypted {
            &["--pass", "right horse battery"]
        } else {
            &[]
        };
        seal(&d, &data, extra);
        let good = std::fs::read(d.join("photo.sg1")).expect("read");
        let unseal_args = |out: &str| -> Vec<String> {
            let mut v = vec![
                "unseal".to_string(),
                "-o".into(),
                out.into(),
                "photo.mended.sg1".into(),
            ];
            if encrypted {
                v.push("--pass".into());
                v.push("right horse battery".into());
            }
            v
        };
        let cases: Vec<(String, Vec<u8>)> = {
            let mut v = Vec::new();
            for flips in [1usize, 50, 400, 3000, 20000] {
                let mut m = good.clone();
                r.flip(&mut m, flips);
                v.push((format!("flips {flips}"), m));
            }
            for frac in [10usize, 4, 2] {
                let mut m = good.clone();
                m.truncate(good.len() - good.len() / frac);
                v.push((format!("truncate 1/{frac}"), m));
            }
            let mut m = good.clone();
            let mid = m.len() / 3;
            let third = m.len() / 3;
            m[mid..mid + third].fill(0);
            v.push(("zero third".into(), m));
            v
        };
        let (mut repaired, mut refused) = (0, 0);
        for (name, bytes) in cases {
            for f in mended_files(&d) {
                std::fs::remove_file(d.join(f)).expect("rm");
            }
            std::fs::write(d.join("photo.sg1"), &bytes).expect("write");
            let o = sigil(&d, &["mend", "photo.sg1"]);
            if !o.status.success() {
                assert!(
                    mended_files(&d).is_empty(),
                    "{name} (enc {encrypted}): refused but left {:?}",
                    mended_files(&d)
                );
                refused += 1;
                continue;
            }
            repaired += 1;
            let args = unseal_args("back.bin");
            let args: Vec<&str> = args.iter().map(|s| s.as_str()).collect();
            let u = sigil(&d, &args);
            assert!(u.status.success(), "{name} (enc {encrypted}): {}", text(&u));
            assert_eq!(
                std::fs::read(d.join("back.bin")).expect("read"),
                data,
                "{name} (enc {encrypted}): mend accepted wrong bytes"
            );
            if encrypted {
                let _ = std::fs::remove_file(d.join("wrong.bin"));
                let w = sigil(
                    &d,
                    &[
                        "unseal",
                        "-o",
                        "wrong.bin",
                        "photo.mended.sg1",
                        "--pass",
                        "wrong key",
                    ],
                );
                assert!(!w.status.success(), "{name}: wrong key opened it");
                assert!(
                    !d.join("wrong.bin").exists(),
                    "{name}: wrong key wrote output"
                );
            }
        }
        // The sweep must exercise both outcomes.
        assert!(
            repaired >= 2 && refused >= 2,
            "enc {encrypted}: repaired {repaired}, refused {refused}"
        );
    }
}
