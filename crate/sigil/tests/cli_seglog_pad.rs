//! Padded segments (`log init --pad`, `log pad`, `log=7`): on-disk sizes show only a bucket.
mod common;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn run(d: &Path, a: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(d)
        .env_remove("SIGIL_SOFT_AUTHENTICATOR")
        .args(a)
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
fn ok(d: &Path, a: &[&str]) -> String {
    let o = run(d, a);
    assert!(o.status.success(), "{a:?}: {}", text(&o));
    text(&o)
}
fn pw(d: &Path) {
    fs::write(d.join("pw"), "secret\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join("pw"), fs::Permissions::from_mode(0o600)).unwrap();
    }
}
fn seg(d: &Path, log: &str, seq: u64) -> u64 {
    fs::metadata(d.join(format!("{log}.sigil/segments/0000/{seq:010}.sg1")))
        .unwrap()
        .len()
}
fn noise(n: usize) -> Vec<u8> {
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}
fn bodies() -> Vec<Vec<u8>> {
    vec![
        b"a".to_vec(),
        vec![7u8; 1500],
        vec![9u8; 3900],
        (0..200_000u32).map(|i| (i * 31 % 251) as u8).collect(),
        noise(3000),
    ]
}

#[test]
fn padded_log_round_trips_and_hides_small_sizes() {
    let d = common::scratch("pad");
    pw(&d);
    ok(&d, &["log", "init", "ev", "--pass-file", "pw", "--pad"]);
    let m = fs::read_to_string(d.join("ev.sigil/CONTAINER")).unwrap();
    assert!(m.contains("log=7") && m.contains("pad=padme"), "{m}");
    for (i, b) in bodies().iter().enumerate() {
        let f = format!("f{i}");
        fs::write(d.join(&f), b).unwrap();
        ok(&d, &["log", "append", "ev", &f, "--pass-file", "pw"]);
    }
    // 1 byte, 1500 and 3900 bytes all pad to the 4 KiB floor: identical file sizes
    assert_eq!(seg(&d, "ev", 1), seg(&d, "ev", 2));
    assert_eq!(seg(&d, "ev", 2), seg(&d, "ev", 3));
    // incompressible 3000 bytes: the same bucket, the same file size
    assert_eq!(seg(&d, "ev", 5), seg(&d, "ev", 1));
    for (i, b) in bodies().iter().enumerate() {
        let o = format!("o{i}");
        ok(
            &d,
            &[
                "log",
                "read",
                "ev",
                "--seq",
                &(i + 1).to_string(),
                "-o",
                &o,
                "--pass-file",
                "pw",
            ],
        );
        assert_eq!(&fs::read(d.join(&o)).unwrap(), b, "seq {}", i + 1);
    }
    // ls with the key shows the real sizes
    let ls = ok(&d, &["log", "ls", "ev", "--pass-file", "pw"]);
    assert!(ls.contains(" 1500 ") && ls.contains(" 200000 "), "{ls}");
    assert_eq!(
        run(&d, &["log", "verify", "ev", "--pass-file", "pw"])
            .status
            .code(),
        Some(0),
        "{}",
        text(&run(&d, &["log", "verify", "ev", "--pass-file", "pw"]))
    );
    // compaction keeps members exact (merged segment padded too)
    ok(
        &d,
        &[
            "log",
            "compact",
            "ev",
            "--apply",
            "--pass-file",
            "pw",
            "--seal-pass-file",
            "pw",
        ],
    );
    assert_ne!(
        run(&d, &["log", "verify", "ev", "--pass-file", "pw"])
            .status
            .code(),
        Some(2)
    );
    ok(
        &d,
        &[
            "log",
            "read",
            "ev",
            "--seq",
            "2",
            "-o",
            "c2",
            "--pass-file",
            "pw",
        ],
    );
    assert_eq!(fs::read(d.join("c2")).unwrap(), bodies()[1]);
}

#[test]
fn enable_on_existing_private_log_and_public_refused() {
    let d = common::scratch("pad-on");
    pw(&d);
    ok(&d, &["log", "init", "ev", "--pass-file", "pw"]);
    fs::write(d.join("a"), "a").unwrap();
    ok(&d, &["log", "append", "ev", "a", "--pass-file", "pw"]);
    let before = seg(&d, "ev", 1);
    assert!(ok(&d, &["log", "pad", "ev"]).contains("padding on"));
    assert!(ok(&d, &["log", "pad", "ev"]).contains("already"));
    ok(&d, &["log", "append", "ev", "a", "--pass-file", "pw"]);
    assert_eq!(seg(&d, "ev", 1), before, "old segment untouched");
    assert!(seg(&d, "ev", 2) > before + 2000, "new segment padded");
    for s in ["1", "2"] {
        ok(
            &d,
            &[
                "log",
                "read",
                "ev",
                "--seq",
                s,
                "-o",
                &format!("r{s}"),
                "--pass-file",
                "pw",
            ],
        );
        assert_eq!(fs::read(d.join(format!("r{s}"))).unwrap(), b"a");
    }
    // public logs: refused (sizes are in the INDEX anyway)
    ok(&d, &["log", "init", "pub"]);
    assert!(!run(&d, &["log", "pad", "pub"]).status.success());
    assert!(!run(&d, &["log", "init", "pub2", "--pad"]).status.success());
}
