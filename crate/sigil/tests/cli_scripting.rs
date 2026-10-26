//! CLI scripting surface: `sigil seal -` (stdin), `unseal -o -` (stdout), `--json`
//! result lines with documented exit codes, and `verify --read-data[-subset]`.
use std::io::Write;
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn run(dir: &Path, args: &[&str], stdin: Option<&[u8]>) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sigil"));
    c.current_dir(dir)
        .args(args)
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .stdin(if stdin.is_some() {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    let mut ch = c.spawn().expect("spawn sigil");
    if let Some(b) = stdin {
        let mut i = ch.stdin.take().expect("stdin");
        // sigil may refuse and exit before reading (broken pipe is fine).
        let _ = i.write_all(b);
    }
    ch.wait_with_output().expect("wait sigil")
}

fn tmp(tag: &str) -> std::path::PathBuf {
    let d = std::env::temp_dir().join(format!("sigil-scripting-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).expect("mkdir");
    d
}

fn pass_file(d: &Path) {
    let p = d.join("pw");
    std::fs::write(&p, "correct horse battery\n").expect("pw");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(&p, std::fs::Permissions::from_mode(0o600)).expect("chmod");
    }
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn bytes(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 31 % 251) as u8).collect()
}

#[test]
fn pipe_seal_then_unseal_to_stdout_small_and_large() {
    let d = tmp("pipe");
    pass_file(&d);
    for (name, n) in [("small", 5000usize), ("large", 9 * 1024 * 1024)] {
        let data = bytes(n);
        let out = format!("{name}.sg1");
        let o = run(
            &d,
            &["seal", "-", "--pass-file", "pw", "-o", &out, "--json"],
            Some(&data),
        );
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        let j = stdout(&o);
        assert!(
            j.starts_with("{\"ok\":true,\"cmd\":\"seal\",\"exit\":0"),
            "{j}"
        );
        assert_eq!(j.lines().count(), 1, "stdout is only the JSON line: {j}");
        let o = run(&d, &["unseal", &out, "--pass-file", "pw", "-o", "-"], None);
        assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
        assert_eq!(o.stdout, data, "{name} round trip");
    }
    // The private staging folder is gone.
    let left: Vec<_> = std::fs::read_dir(&d)
        .expect("ls")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.contains(".stdin-"))
        .collect();
    assert!(left.is_empty(), "{left:?}");
}

#[test]
fn stdin_name_is_stored() {
    let d = tmp("name");
    let o = run(
        &d,
        &["seal", "-", "-o", "n.sg1", "--stdin-name", "dump.sql"],
        Some(b"select 1;"),
    );
    assert!(o.status.success());
    let o = run(&d, &["verify", "n.sg1"], None);
    assert!(stdout(&o).contains("name=dump.sql"), "{}", stdout(&o));
    let o = run(
        &d,
        &["seal", "-", "-o", "n2.sg1", "--stdin-name", "a/b"],
        Some(b"x"),
    );
    assert_eq!(o.status.code(), Some(1));
}

#[test]
fn empty_stdin_fails_closed_with_json() {
    let d = tmp("empty");
    let o = run(&d, &["seal", "-", "-o", "e.sg1", "--json"], Some(b""));
    assert_eq!(o.status.code(), Some(1));
    let j = stdout(&o);
    assert!(
        j.starts_with("{\"ok\":false,\"cmd\":\"seal\",\"exit\":1"),
        "{j}"
    );
    assert!(j.contains("stdin was empty"), "{j}");
    assert!(!d.join("e.sg1").exists());
}

#[test]
fn unseal_stdout_refuses_json_and_folders() {
    let d = tmp("refuse");
    std::fs::write(d.join("f.txt"), b"hello").expect("w");
    assert!(run(&d, &["seal", "f.txt", "-o", "f.sg1"], None)
        .status
        .success());
    let o = run(&d, &["unseal", "f.sg1", "-o", "-", "--json"], None);
    assert_eq!(o.status.code(), Some(1));
    std::fs::create_dir_all(d.join("fold")).expect("mkdir");
    std::fs::write(d.join("fold/a"), b"a").expect("w");
    assert!(run(&d, &["seal", "fold", "-o", "fold.sg1"], None)
        .status
        .success());
    let o = run(&d, &["unseal", "fold.sg1", "-o", "-"], None);
    assert_eq!(o.status.code(), Some(1));
    assert!(o.stdout.is_empty());
}

#[test]
fn unseal_json_and_wrong_key() {
    let d = tmp("ujson");
    pass_file(&d);
    std::fs::write(d.join("f.txt"), bytes(1000)).expect("w");
    assert!(run(
        &d,
        &["seal", "f.txt", "--pass-file", "pw", "-o", "f.sg1"],
        None
    )
    .status
    .success());
    let o = run(
        &d,
        &[
            "unseal",
            "f.sg1",
            "--pass-file",
            "pw",
            "-o",
            "back",
            "--json",
        ],
        None,
    );
    assert!(o.status.success());
    assert!(
        stdout(&o).contains("\"output_bytes\":1000"),
        "{}",
        stdout(&o)
    );
    std::fs::write(d.join("bad"), "wrong passphrase here\n").expect("w");
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(d.join("bad"), std::fs::Permissions::from_mode(0o600))
            .expect("chmod");
    }
    let o = run(
        &d,
        &["unseal", "f.sg1", "--pass-file", "bad", "-o", "x", "--json"],
        None,
    );
    assert!(!o.status.success());
    assert!(stdout(&o).starts_with("{\"ok\":false,\"cmd\":\"unseal\""));
    assert!(!d.join("x").exists());
}

#[test]
fn verify_read_data_subset_and_receipt() {
    let d = tmp("deep");
    pass_file(&d);
    std::fs::write(d.join("big"), bytes(13 * 1024 * 1024)).expect("w");
    assert!(run(
        &d,
        &["seal", "big", "--pass-file", "pw", "-o", "big.sg1"],
        None
    )
    .status
    .success());
    // Cheap default verify needs no key and does no deep read.
    let o = run(&d, &["verify", "big.sg1", "--json"], None);
    assert!(o.status.success());
    assert!(!stdout(&o).contains("read_data"));
    let o = run(
        &d,
        &[
            "verify",
            "big.sg1",
            "--pass-file",
            "pw",
            "--read-data-subset",
            "25%",
            "--subset-offset",
            "1",
            "--json",
        ],
        None,
    );
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    let j = stdout(&o);
    assert!(j.contains("\"read_data\":{\"kind\":\"work\""), "{j}");
    assert!(j.contains("\"checked\":[1]"), "{j}");
    assert!(j.contains("\"failed\":[]"), "{j}");
    let o = run(
        &d,
        &["verify", "big.sg1", "--pass-file", "pw", "--read-data"],
        None,
    );
    assert!(o.status.success());
    // No key: the deep read cannot open the parts → exit 2, failures listed.
    let o = run(&d, &["verify", "big.sg1", "--read-data", "--json"], None);
    assert_eq!(o.status.code(), Some(2), "{}", stdout(&o));
    assert!(stdout(&o).contains("\"ok\":false"));
    // Bad percentages are refused by the parser.
    let o = run(&d, &["verify", "big.sg1", "--read-data-subset", "0%"], None);
    assert_eq!(o.status.code(), Some(2)); // clap usage error
    let o = run(
        &d,
        &["verify", "big.sg1", "--read-data-subset", "150"],
        None,
    );
    assert!(!o.status.success());
}
