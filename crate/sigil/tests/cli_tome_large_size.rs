//! Listing a Tome shows a large member's real size, never a placeholder "0 bytes".
//!
//! A file bigger than one chunk is stored inside the Tome as a large-file pack. When the
//! Tome is locked, that pack's head writes its total as 0 (the real total is inside the
//! lock). Listing with the key must open the lock and show the true size; a member under
//! its own Ward (whose key was not given) shows no size, like a small warded file.
mod common;
use std::path::Path;
use std::process::{Command, Output, Stdio};

const BIG_LEN: usize = 5_000_000;

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

#[cfg(unix)]
fn write_secret(path: &Path, body: &[u8]) {
    use std::os::unix::fs::PermissionsExt;
    std::fs::write(path, body).unwrap();
    std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600)).unwrap();
}

fn scratch(tag: &str) -> common::Scratch {
    let d = common::scratch(&format!("cli-tome-large-size-{tag}"));
    std::fs::create_dir_all(d.join("src")).unwrap();
    // Varied bytes (a simple LCG), so nothing about the content is special.
    let mut x: u32 = 0x2026_1126;
    let big: Vec<u8> = (0..BIG_LEN)
        .map(|_| {
            x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
            (x >> 24) as u8
        })
        .collect();
    std::fs::write(d.join("src/big.bin"), &big).unwrap();
    std::fs::write(d.join("src/small.txt"), b"hi\n").unwrap();
    #[cfg(unix)]
    {
        write_secret(&d.join("house.pw"), b"house-key\n");
        write_secret(&d.join("room.pw"), b"room-key\n");
    }
    d
}

fn big_line(listing: &str) -> String {
    listing
        .lines()
        .find(|l| l.contains("big.bin"))
        .unwrap_or_else(|| panic!("no big.bin line in:\n{listing}"))
        .to_string()
}

#[test]
fn plain_tome_lists_large_member_size() {
    let d = scratch("plain");
    ok(&sigil(&d, &["seal", "src", "-o", "t.sg1"]));
    let line = big_line(&ok(&sigil(&d, &["path", "t.sg1"])));
    assert!(line.contains(&format!("{BIG_LEN} bytes")), "{line}");
}

#[cfg(unix)]
#[test]
fn locked_tome_lists_large_member_true_size_with_key() {
    let d = scratch("locked");
    ok(&sigil(
        &d,
        &["seal", "src", "-o", "t.sg1", "--pass-file", "house.pw"],
    ));
    let listing = ok(&sigil(&d, &["path", "t.sg1", "--pass-file", "house.pw"]));
    let line = big_line(&listing);
    assert!(line.contains(&format!("{BIG_LEN} bytes")), "{line}");
    assert!(!line.contains(" 0 bytes"), "{line}");
    let scry = ok(&sigil(&d, &["scry", "t.sg1", "--pass-file", "house.pw"]));
    let line = big_line(&scry);
    assert!(line.contains(&format!("{BIG_LEN} bytes")), "{line}");
}

#[cfg(unix)]
#[test]
fn warded_large_member_shows_no_size_not_zero() {
    let d = scratch("warded");
    ok(&sigil(
        &d,
        &[
            "seal",
            "src",
            "-o",
            "t.sg1",
            "--pass-file",
            "house.pw",
            "--ward-file",
            "big.bin=room.pw",
        ],
    ));
    let listing = ok(&sigil(&d, &["path", "t.sg1", "--pass-file", "house.pw"]));
    let line = big_line(&listing);
    assert!(
        !line.contains("bytes"),
        "warded size must stay hidden: {line}"
    );
    // The unwarded member still shows its size.
    assert!(listing.contains("small.txt  3 bytes"), "{listing}");
}
