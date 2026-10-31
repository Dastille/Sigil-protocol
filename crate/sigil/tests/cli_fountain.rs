//! `deluge --fountain`: random RaptorQ symbol IDs by default, `--sequential` for the
//! old order, old v1 `.rq` packets still gather, damaged/stray packet files are
//! skipped, and a short folder says how many more packets are needed.
mod common;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn sigil(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(common::pass_via_file(args))
        .output()
        .expect("run sigil")
}

fn ok(dir: &Path, args: &[&str]) -> (String, String) {
    let o = sigil(dir, args);
    let (a, b) = (
        String::from_utf8_lossy(&o.stdout).into_owned(),
        String::from_utf8_lossy(&o.stderr).into_owned(),
    );
    assert!(o.status.success(), "{args:?}: {a}{b}");
    (a, b)
}

fn scratch(tag: &str) -> common::Scratch {
    let d = common::scratch(&format!("cli-ft-{tag}"));
    d
}

fn fx() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/fountain-v1")
}

fn rq(d: &Path) -> Vec<PathBuf> {
    let mut v: Vec<_> = std::fs::read_dir(d)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| p.extension().and_then(|x| x.to_str()) == Some("rq"))
        .collect();
    v.sort();
    v
}

#[test]
fn old_v1_packets_still_gather() {
    let d = scratch("v1");
    let rain = fx().join("rain");
    ok(&d, &["gather", "-o", "back.sg1", rain.to_str().unwrap()]);
    assert_eq!(
        std::fs::read(d.join("back.sg1")).unwrap(),
        std::fs::read(fx().join("mark.sg1")).unwrap()
    );
    ok(&d, &["unseal", "-o", "plain.bin", "back.sg1"]);
    assert_eq!(
        std::fs::read(d.join("plain.bin")).unwrap(),
        std::fs::read(fx().join("plain.bin")).unwrap()
    );
    // Old and new packets of the same file pool together.
    let mix = d.join("mix");
    std::fs::create_dir_all(&mix).unwrap();
    for p in rq(&rain).iter().take(3) {
        std::fs::copy(p, mix.join(p.file_name().unwrap())).unwrap();
    }
    let mark = fx().join("mark.sg1");
    ok(
        &d,
        &[
            "deluge",
            mark.to_str().unwrap(),
            "--fountain",
            "--extra",
            "0",
            "-o",
            "new",
        ],
    );
    for p in rq(&d.join("new")).iter().take(5) {
        std::fs::copy(p, mix.join(p.file_name().unwrap())).unwrap();
    }
    ok(&d, &["gather", "-o", "mixed.sg1", "mix"]);
    assert_eq!(
        std::fs::read(d.join("mixed.sg1")).unwrap(),
        std::fs::read(&mark).unwrap()
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn default_is_random_sequential_is_old_order_and_short_folders_say_how_many() {
    let d = scratch("cli");
    let mark = fx().join("mark.sg1");
    let m = mark.to_str().unwrap();
    let (o, _) = ok(&d, &["deluge", m, "--fountain", "--extra", "2", "-o", "r"]);
    assert!(o.contains("random symbol IDs"), "{o}");
    let names: Vec<String> = rq(&d.join("r"))
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert_eq!(names.len(), 8);
    assert!(
        names.iter().all(|n| n.starts_with("rain-000-")),
        "{names:?}"
    );
    let (o, _) = ok(
        &d,
        &[
            "deluge",
            m,
            "--fountain",
            "--sequential",
            "--extra",
            "2",
            "-o",
            "s",
        ],
    );
    assert!(o.contains("sequential"), "{o}");
    assert!(d.join("s/rain-00000.rq").is_file() && d.join("s/rain-00007.rq").is_file());
    // --sequential without --fountain is refused.
    assert!(!sigil(&d, &["deluge", m, "--sequential", "-o", "x"])
        .status
        .success());

    // Short: keep 4 of the 6 needed.
    let short = d.join("short");
    std::fs::create_dir_all(&short).unwrap();
    for p in rq(&d.join("r")).iter().take(4) {
        std::fs::copy(p, short.join(p.file_name().unwrap())).unwrap();
    }
    std::fs::write(short.join("notes.rq"), b"not a packet").unwrap();
    let o = sigil(&d, &["gather", "-o", "no.sg1", "short"]);
    assert!(!o.status.success());
    let e = String::from_utf8_lossy(&o.stderr);
    assert!(e.contains("have 4 of 6 needed, need 2 more"), "{e}");
    assert!(e.contains("skipped packet files: 1 damaged"), "{e}");
    assert!(!d.join("no.sg1").exists());
    // Topped up from the other (sequential) sender: rebuilds, and names the skipped file.
    for p in rq(&d.join("s")).iter().take(4) {
        std::fs::copy(p, short.join(p.file_name().unwrap())).unwrap();
    }
    let (_, e) = ok(&d, &["gather", "-o", "yes.sg1", "short"]);
    assert!(e.contains("notes.rq"), "{e}");
    assert_eq!(
        std::fs::read(d.join("yes.sg1")).unwrap(),
        std::fs::read(&mark).unwrap()
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn extra_is_a_target_top_up_not_an_increment() {
    let d = scratch("topup");
    let mark = fx().join("mark.sg1");
    let m = mark.to_str().unwrap();
    // mark.sg1 has 6 source symbols: --extra 2 = 8 packets.
    let (o, _) = ok(&d, &["deluge", m, "--fountain", "--extra", "2", "-o", "r"]);
    assert!(o.contains("fountain 8 packets"), "{o}");
    assert!(
        !o.contains("topped up") && !o.contains("nothing written"),
        "{o}"
    );
    let (o, _) = ok(&d, &["deluge", m, "--fountain", "--extra", "5", "-o", "r"]);
    assert!(o.contains("fountain 11 packets"), "{o}");
    assert!(o.contains("kept 8 already there, wrote 3 new"), "{o}");
    assert_eq!(rq(&d.join("r")).len(), 11);
    let (o, _) = ok(&d, &["deluge", m, "--fountain", "--extra", "5", "-o", "r"]);
    assert!(o.contains("nothing written"), "{o}");
    assert_eq!(rq(&d.join("r")).len(), 11);
    // Old v1 packets of the same file count toward the target too.
    let v1 = d.join("v1");
    std::fs::create_dir_all(&v1).unwrap();
    for p in rq(&fx().join("rain")) {
        std::fs::copy(&p, v1.join(p.file_name().unwrap())).unwrap();
    }
    std::fs::write(v1.join("junk.rq"), b"not a packet").unwrap();
    let (o, e) = ok(&d, &["deluge", m, "--fountain", "--extra", "2", "-o", "v1"]);
    assert!(o.contains("nothing written"), "{o}");
    assert!(e.contains("not counted") && e.contains("junk.rq"), "{e}");
    ok(&d, &["gather", "-o", "back.sg1", "r"]);
    assert_eq!(
        std::fs::read(d.join("back.sg1")).unwrap(),
        std::fs::read(&mark).unwrap()
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[test]
fn loss_picks_the_packet_count_and_bad_values_are_refused() {
    let d = scratch("loss");
    // 82 source symbols of 16 KiB (one source block), deterministic bytes.
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let data: Vec<u8> = (0..1_336_608)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    std::fs::write(d.join("f.bin"), &data).unwrap();
    // K=82 at 10% loss, target 1e-4: 23 extra (exact-rational reference in fountain_loss).
    let (out, _) = ok(
        &d,
        &["deluge", "f.bin", "-o", "r", "--fountain", "--loss", "10%"],
    );
    assert!(out.contains("23 extra packets per block"), "{out}");
    assert_eq!(rq(&d.join("r")).len(), 105);
    let (out, _) = ok(
        &d,
        &[
            "deluge",
            "f.bin",
            "-o",
            "s",
            "--fountain",
            "--sequential",
            "--loss",
            "0.1",
        ],
    );
    assert!(out.contains("measured, not guaranteed"), "{out}");
    assert_eq!(rq(&d.join("s")).len(), 105);
    // Ten packets lost (under 10%): rebuilds the exact bytes.
    let files = rq(&d.join("r"));
    for f in files.iter().step_by(10) {
        std::fs::remove_file(f).unwrap();
    }
    ok(&d, &["gather", "r", "-o", "back.bin"]);
    assert_eq!(std::fs::read(d.join("back.bin")).unwrap(), data);
    // Fewer than K left: refuses and writes nothing.
    for f in rq(&d.join("r")).iter().skip(81) {
        std::fs::remove_file(f).unwrap();
    }
    let o = sigil(&d, &["gather", "r", "-o", "short.bin"]);
    assert!(!o.status.success());
    assert!(!d.join("short.bin").exists());
    // Refused: no --fountain, with --extra, a bare 10, 100%, negative, junk.
    for args in [
        &["deluge", "f.bin", "-o", "x", "--loss", "0.1"][..],
        &[
            "deluge",
            "f.bin",
            "-o",
            "x",
            "--fountain",
            "--loss",
            "0.1",
            "--extra",
            "5",
        ],
        &["deluge", "f.bin", "-o", "x", "--fountain", "--loss", "10"],
        &["deluge", "f.bin", "-o", "x", "--fountain", "--loss", "100%"],
        &["deluge", "f.bin", "-o", "x", "--fountain", "--loss", "-0.1"],
        &["deluge", "f.bin", "-o", "x", "--fountain", "--loss", "nan"],
    ] {
        let o = sigil(&d, args);
        assert!(!o.status.success(), "{args:?} should be refused");
        assert!(!d.join("x").exists(), "{args:?} wrote packets");
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// `gather --report` prints one short line; `deluge --fountain --answer` sends exactly
/// what it lists, and a report for another file is refused with nothing written.
#[test]
fn gather_report_then_deluge_answer_fills_the_gap() {
    let dir = common::scratch("cli-nak");
    std::fs::create_dir_all(dir.join("rx")).unwrap();
    let mut x = 0x2545_f491_4f6c_dd1du64;
    let data: Vec<u8> = (0..150_000u32)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    std::fs::write(dir.join("in.bin"), &data).unwrap();
    let run = |args: &[&str]| {
        std::process::Command::new(env!("CARGO_BIN_EXE_sigil"))
            .current_dir(&dir)
            .args(args)
            .output()
            .unwrap()
    };
    assert!(run(&["inscribe", "-o", "a.sg1", "in.bin"]).status.success());
    assert!(
        run(&["deluge", "--fountain", "--extra", "0", "-o", "tx", "a.sg1"])
            .status
            .success()
    );
    let mut pkts: Vec<_> = std::fs::read_dir(dir.join("tx"))
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    pkts.sort();
    for p in pkts.iter().take(3) {
        std::fs::copy(p, dir.join("rx").join(p.file_name().unwrap())).unwrap();
    }
    let rep = run(&["gather", "--report", "rx"]);
    assert!(
        rep.status.success(),
        "{}",
        String::from_utf8_lossy(&rep.stderr)
    );
    let line = String::from_utf8(rep.stdout).unwrap().trim().to_string();
    assert!(line.starts_with("SGNAK1 ") && line.len() <= 1024, "{line}");
    assert!(pkts.len() > 3, "{} packets", pkts.len());
    let missing = pkts.len() - 3;
    assert!(run(&[
        "deluge",
        "--fountain",
        "--answer",
        &line,
        "-o",
        "rx",
        "a.sg1"
    ])
    .status
    .success());
    let n = std::fs::read_dir(dir.join("rx")).unwrap().count();
    assert_eq!(n, 3 + missing);
    std::fs::write(dir.join("b.bin"), b"some other file entirely").unwrap();
    assert!(run(&["inscribe", "-o", "b.sg1", "b.bin"]).status.success());
    assert!(!run(&[
        "deluge",
        "--fountain",
        "--answer",
        &line,
        "-o",
        "rx2",
        "b.sg1"
    ])
    .status
    .success());
    assert!(!dir.join("rx2").exists() || std::fs::read_dir(dir.join("rx2")).unwrap().count() == 0);
    let _ = std::fs::remove_dir_all(&dir);
}
