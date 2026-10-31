//! `verify --read-data[-subset]` on folder packs: every picked member is opened to its
//! original bytes; no key, a wrong key, a ward-locked member or damage fails closed.
mod common;
use std::fs;
use std::path::Path;
use std::process::{Command, Output};

fn sigil(d: &Path, args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(d)
        .env_remove("SIGIL_SOFT_AUTHENTICATOR")
        .args(common::pass_via_file(args))
        .output()
        .expect("run sigil")
}

fn ok(d: &Path, args: &[&str]) -> String {
    let o = sigil(d, args);
    assert!(
        o.status.success(),
        "{args:?}: {}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    String::from_utf8_lossy(&o.stdout).into_owned()
}

fn fails(d: &Path, args: &[&str]) -> String {
    let o = sigil(d, args);
    assert!(!o.status.success(), "{args:?} should fail");
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn noise(n: usize, mut x: u64) -> Vec<u8> {
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn tree(d: &Path) {
    fs::create_dir_all(d.join("docs/sub")).unwrap();
    fs::write(d.join("docs/a.txt"), b"alpha alpha alpha").unwrap();
    fs::write(d.join("docs/b.txt"), b"bravo").unwrap();
    fs::write(d.join("docs/sub/c.bin"), noise(50_000, 3)).unwrap();
    fs::write(d.join("docs/sub/d.bin"), noise(20_000, 9)).unwrap();
}

#[test]
fn plain_folder_pack_deep_read() {
    let d = common::scratch("rd-folder-plain");
    tree(&d);
    ok(&d, &["seal", "-o", "docs.sg1", "docs"]);
    let j = ok(&d, &["verify", "docs.sg1", "--read-data", "--json"]);
    assert!(j.contains("\"read_data\":{\"kind\":\"folder\""), "{j}");
    assert!(j.contains("\"total_parts\":4,\"checked\":[0,1,2,3]"), "{j}");
    assert!(
        j.contains("\"bytes_read\":70022,\"failed\":[],\"skipped\":[]"),
        "{j}"
    );
    let j = ok(
        &d,
        &[
            "verify",
            "docs.sg1",
            "--read-data-subset",
            "25%",
            "--subset-offset",
            "2",
            "--json",
        ],
    );
    assert!(j.contains("\"checked\":[2]"), "{j}");
}

#[test]
fn sealed_folder_pack_needs_the_key() {
    let d = common::scratch("rd-folder-sealed");
    tree(&d);
    ok(&d, &["seal", "--pass", "pw", "-o", "docs.sg1", "docs"]);
    let j = ok(
        &d,
        &[
            "verify",
            "docs.sg1",
            "--pass",
            "pw",
            "--read-data",
            "--json",
        ],
    );
    assert!(j.contains("\"total_parts\":4,\"checked\":[0,1,2,3]"), "{j}");
    assert!(j.contains("\"bytes_read\":70022,\"failed\":[]"), "{j}");
    // No key: refused, nothing reported as opened.
    let e = fails(&d, &["verify", "docs.sg1", "--read-data", "--json"]);
    assert!(!e.contains("\"bytes_read\":70022"), "{e}");
    assert!(!e.contains("too damaged") && e.contains("--pass"), "{e}");
    // Wrong key: refused.
    let e = fails(
        &d,
        &[
            "verify",
            "docs.sg1",
            "--pass",
            "nope",
            "--read-data",
            "--json",
        ],
    );
    assert!(!e.contains("\"failed\":[]"), "{e}");
}

#[test]
fn ward_locked_member_fails_closed() {
    let d = common::scratch("rd-folder-ward");
    tree(&d);
    fs::write(d.join("wpw"), "ward secret\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join("wpw"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    ok(
        &d,
        &[
            "seal",
            "--pass",
            "pw",
            "--ward-file",
            "a.txt=wpw",
            "-o",
            "docs.sg1",
            "docs",
        ],
    );
    let e = fails(
        &d,
        &[
            "verify",
            "docs.sg1",
            "--pass",
            "pw",
            "--read-data",
            "--json",
        ],
    );
    assert!(e.contains("\"ok\":false") && e.contains("a.txt"), "{e}");
    assert!(
        e.contains("\"cause\":\"wrong-key\"") && e.contains("--ward"),
        "{e}"
    );
    assert!(
        e.contains("key problem, not damage") && !e.contains("too damaged"),
        "{e}"
    );
    // Only the warded member failed; the rest were opened.
    assert!(e.contains("\"failed\":[{\"part\":0,"), "{e}");
}

#[test]
fn damaged_member_is_reported() {
    let d = common::scratch("rd-folder-dmg");
    tree(&d);
    ok(&d, &["seal", "-o", "docs.sg1", "docs"]);
    let mut b = fs::read(d.join("docs.sg1")).unwrap();
    let (a, z) = (b.len() * 30 / 100, b.len() * 95 / 100);
    b[a..z].fill(0);
    fs::write(d.join("docs.sg1"), b).unwrap();
    let o = sigil(&d, &["verify", "docs.sg1", "--read-data", "--json"]);
    assert!(!o.status.success());
    assert_eq!(o.status.code(), Some(2));
    let j = String::from_utf8_lossy(&o.stdout);
    assert!(!j.contains("\"failed\":[],"), "{j}");
    // Real damage keeps the damage wording and never reads as a key problem.
    assert!(
        j.contains("NOT recoverable") && !j.contains("key problem"),
        "{j}"
    );
}
