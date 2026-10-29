//! Ward passwords off the command line: `--ward-file PATH=PWFILE` reads one from a file
//! (same rules as `--pass-file`: first line, owner-only permissions, not empty) and
//! `--ward PATH=-` asks on the terminal. A literal `--ward PATH=PASSWORD` still works
//! but warns. Every refusal writes nothing.
use std::path::{Path, PathBuf};
use std::process::{Command, Output, Stdio};

fn sigil(dir: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run sigil")
}

fn ok(o: &Output) -> String {
    assert!(
        o.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn err(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).into_owned()
}

#[cfg(unix)]
fn write_secret(path: &Path, body: &[u8], mode: u32) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(mode)).unwrap();
}

fn scratch(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("sigil-cli-wardfile-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("album/private-sub")).unwrap();
    std::fs::write(d.join("album/visible-name-a.txt"), b"alpha alpha").unwrap();
    std::fs::write(
        d.join("album/private-sub/tax-return-2025.pdf"),
        b"pretend pdf bytes 0123456789",
    )
    .unwrap();
    #[cfg(unix)]
    {
        write_secret(&d.join("house.pw"), b"house-key\n", 0o600);
        write_secret(&d.join("room.pw"), b"room-key\n", 0o600);
        write_secret(&d.join("wrong.pw"), b"not-the-room-key\n", 0o600);
    }
    d
}

const MEMBER: &str = "private-sub/tax-return-2025.pdf";
const WARD_WARNING: &str = "WARNING: a ward password given as --ward PATH=PASSWORD";

#[cfg(unix)]
#[test]
fn ward_file_round_trips_without_a_warning_and_matches_the_literal_form() {
    let d = scratch("rt");
    let wf = format!("{MEMBER}=room.pw");
    let o = sigil(
        &d,
        &[
            "seal",
            "--pass-file",
            "house.pw",
            "--ward-file",
            &wf,
            "-o",
            "e.sg1",
            "album",
        ],
    );
    ok(&o);
    assert!(!err(&o).contains("WARNING"), "{}", err(&o));
    let raw = std::fs::read(d.join("e.sg1")).unwrap();
    assert!(!raw.windows(8).any(|w| w == b"room-key"));

    ok(&sigil(
        &d,
        &[
            "unseal",
            "--pass-file",
            "house.pw",
            "--ward-file",
            &wf,
            "-o",
            "a",
            "e.sg1",
        ],
    ));
    assert_eq!(
        std::fs::read(d.join("a/private-sub/tax-return-2025.pdf")).unwrap(),
        b"pretend pdf bytes 0123456789"
    );
    // The file form and the literal form are the same password (old commands still work),
    // and the literal form warns.
    let lit = format!("{MEMBER}=room-key");
    let o = sigil(
        &d,
        &[
            "unseal",
            "--pass",
            "house-key",
            "--ward",
            &lit,
            "-o",
            "b",
            "e.sg1",
        ],
    );
    ok(&o);
    assert!(err(&o).contains(WARD_WARNING), "{}", err(&o));
    assert_eq!(
        std::fs::read(d.join("b/private-sub/tax-return-2025.pdf")).unwrap(),
        b"pretend pdf bytes 0123456789"
    );

    // Fail closed: wrong ward file, a flipped bit, a truncated pack.
    let wrong = format!("{MEMBER}=wrong.pw");
    let o = sigil(
        &d,
        &[
            "unseal",
            "--pass-file",
            "house.pw",
            "--ward-file",
            &wrong,
            "-o",
            "w",
            "e.sg1",
        ],
    );
    assert!(
        !o.status.success() && !d.join("w").exists(),
        "wrong ward opened"
    );
    let mut flip = raw.clone();
    let mid = flip.len() / 2;
    flip[mid] ^= 0x40;
    std::fs::write(d.join("flip.sg1"), &flip).unwrap();
    let o = sigil(
        &d,
        &[
            "unseal",
            "--pass-file",
            "house.pw",
            "--ward-file",
            &wf,
            "-o",
            "f",
            "flip.sg1",
        ],
    );
    if o.status.success() {
        // Sigil may repair a single flipped bit; then the output must be exact.
        assert_eq!(
            std::fs::read(d.join("f/private-sub/tax-return-2025.pdf")).unwrap(),
            b"pretend pdf bytes 0123456789"
        );
    }
    std::fs::write(d.join("trunc.sg1"), &raw[..raw.len() - 9]).unwrap();
    let o = sigil(
        &d,
        &[
            "unseal",
            "--pass-file",
            "house.pw",
            "--ward-file",
            &wf,
            "-o",
            "t",
            "trunc.sg1",
        ],
    );
    assert!(
        !o.status.success() && !d.join("t").exists(),
        "truncated pack opened"
    );
    let _ = std::fs::remove_dir_all(&d);
}

#[cfg(unix)]
#[test]
fn bad_ward_files_are_refused_and_nothing_is_written() {
    let d = scratch("bad");
    write_secret(&d.join("open.pw"), b"room-key\n", 0o644);
    write_secret(&d.join("empty.pw"), b"\n", 0o600);
    let cases: Vec<(String, &str)> = vec![
        (format!("{MEMBER}=open.pw"), "chmod 600"),
        (format!("{MEMBER}=empty.pw"), "empty"),
        (format!("{MEMBER}=missing.pw"), "cannot read"),
        (format!("{MEMBER}="), "names no password file"),
        (MEMBER.to_string(), "PATH=PWFILE"),
    ];
    for (i, (spec, why)) in cases.iter().enumerate() {
        let out = format!("x{i}.sg1");
        let o = sigil(
            &d,
            &[
                "seal",
                "--pass-file",
                "house.pw",
                "--ward-file",
                spec,
                "-o",
                &out,
                "album",
            ],
        );
        assert!(!o.status.success(), "{spec} must be refused");
        assert!(err(&o).contains(why), "{spec}: {}", err(&o));
        assert!(!d.join(&out).exists(), "{spec}: wrote output");
    }
    let _ = std::fs::remove_dir_all(&d);
}

#[cfg(unix)]
#[test]
fn one_path_with_two_passwords_is_refused() {
    let d = scratch("dup");
    let lit = format!("{MEMBER}=room-key");
    let wf = format!("{MEMBER}=room.pw");
    let o = sigil(
        &d,
        &[
            "seal",
            "--pass-file",
            "house.pw",
            "--ward",
            &lit,
            "--ward-file",
            &wf,
            "-o",
            "d.sg1",
            "album",
        ],
    );
    assert!(!o.status.success());
    assert!(err(&o).contains("more than once"), "{}", err(&o));
    assert!(!d.join("d.sg1").exists());
    let _ = std::fs::remove_dir_all(&d);
}

#[cfg(unix)]
#[test]
fn ward_dash_needs_a_terminal_and_never_reads_piped_input() {
    let d = scratch("dash");
    let spec = format!("{MEMBER}=-");
    let mut child = Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(&d)
        .args([
            "seal",
            "--pass-file",
            "house.pw",
            "--ward",
            &spec,
            "-o",
            "p.sg1",
            "album",
        ])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::piped())
        .spawn()
        .expect("spawn sigil");
    {
        use std::io::Write;
        let mut stdin = child.stdin.take().expect("stdin");
        let _ = stdin.write_all(b"room-key\nroom-key\n");
    }
    let o = child.wait_with_output().expect("wait");
    assert!(!o.status.success(), "piped ward password was accepted");
    assert!(!d.join("p.sg1").exists());
    assert!(err(&o).contains("--ward-file"), "{}", err(&o));
    // A literal "-" is never stored as a password.
    assert!(!err(&o).contains(WARD_WARNING), "{}", err(&o));
    let _ = std::fs::remove_dir_all(&d);
}
