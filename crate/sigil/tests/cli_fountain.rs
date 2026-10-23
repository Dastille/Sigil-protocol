//! `deluge --fountain`: random RaptorQ symbol IDs by default, `--sequential` for the
//! old order, old v1 `.rq` packets still gather, damaged/stray packet files are
//! skipped, and a short folder says how many more packets are needed.
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn sigil(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(args)
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

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sigil-cli-ft-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
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
