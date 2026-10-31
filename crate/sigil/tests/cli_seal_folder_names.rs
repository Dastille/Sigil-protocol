//! `sigil seal-folder-names OLD -o NEW`: an old folder pack (SGDR v1, names in the clear) becomes a
//! sealed-directory pack (v2) without re-inscribing the folder.
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
fn fails(d: &Path, a: &[&str]) -> String {
    let o = run(d, a);
    assert!(!o.status.success(), "expected failure {a:?}: {}", text(&o));
    text(&o)
}
fn pw(d: &Path, name: &str, v: &str) {
    fs::write(d.join(name), format!("{v}\n")).unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join(name), fs::Permissions::from_mode(0o600)).unwrap();
    }
}
fn has(b: &[u8], s: &str) -> bool {
    b.windows(s.len()).any(|w| w == s.as_bytes())
}
fn tree(d: &Path) {
    fs::create_dir_all(d.join("src/sub")).unwrap();
    fs::write(d.join("src/sub/tax-return-2025.pdf"), "secret content\n").unwrap();
    fs::write(d.join("src/readme-public.txt"), "hello\n").unwrap();
}

#[test]
fn ward_only_pack_gets_sealed_names() {
    let d = common::scratch("seal-names-ward");
    pw(&d, "pw", "outer");
    pw(&d, "wf", "ward");
    tree(&d);
    ok(
        &d,
        &[
            "inscribe",
            "src",
            "-o",
            "old.sg1",
            "--ward-file",
            "sub/tax-return-2025.pdf=wf",
            "--ward-names-visible",
        ],
    );
    let old = fs::read(d.join("old.sg1")).unwrap();
    assert!(has(&old, "tax-return-2025"));
    // refusals: no key, literal --pass, wrong key without --allow-new-key; nothing is written
    fails(&d, &["seal-folder-names", "old.sg1", "-o", "new.sg1"]);
    fails(
        &d,
        &[
            "seal-folder-names",
            "old.sg1",
            "-o",
            "new.sg1",
            "--pass",
            "outer",
        ],
    );
    let e = fails(
        &d,
        &[
            "seal-folder-names",
            "old.sg1",
            "-o",
            "new.sg1",
            "--pass-file",
            "pw",
        ],
    );
    assert!(e.contains("--allow-new-key"), "{e}");
    assert!(!d.join("new.sg1").exists());
    ok(
        &d,
        &[
            "seal-folder-names",
            "old.sg1",
            "-o",
            "new.sg1",
            "--pass-file",
            "pw",
            "--allow-new-key",
        ],
    );
    assert_eq!(fs::read(d.join("old.sg1")).unwrap(), old, "input untouched");
    let new = fs::read(d.join("new.sg1")).unwrap();
    assert!(!has(&new, "tax-return-2025") && !has(&new, "readme-public"));
    let keyless = ok(&d, &["scry", "new.sg1"]);
    assert!(
        keyless.contains("names hidden") && !keyless.contains("tax-return"),
        "{keyless}"
    );
    assert!(ok(&d, &["scry", "new.sg1", "--pass-file", "pw"]).contains("sub/tax-return-2025.pdf"));
    ok(&d, &["verify", "new.sg1"]);
    // the warded member still needs its ward; the clear one now needs the new key
    ok(
        &d,
        &[
            "unseal",
            "new.sg1",
            "-o",
            "out",
            "--pass-file",
            "pw",
            "--ward-file",
            "sub/tax-return-2025.pdf=wf",
        ],
    );
    assert_eq!(
        fs::read_to_string(d.join("out/sub/tax-return-2025.pdf")).unwrap(),
        "secret content\n"
    );
    assert_eq!(
        fs::read_to_string(d.join("out/readme-public.txt")).unwrap(),
        "hello\n"
    );
    fails(&d, &["unseal", "new.sg1", "-o", "out2"]);
    // existing output, already-sealed input: refused
    fails(
        &d,
        &[
            "seal-folder-names",
            "old.sg1",
            "-o",
            "new.sg1",
            "--pass-file",
            "pw",
            "--allow-new-key",
        ],
    );
    let e = fails(
        &d,
        &[
            "seal-folder-names",
            "new.sg1",
            "-o",
            "x.sg1",
            "--pass-file",
            "pw",
        ],
    );
    assert!(e.contains("already"), "{e}");
}

#[test]
fn plain_pack_gets_sealed_names_and_contents() {
    let d = common::scratch("seal-names-plain");
    pw(&d, "pw", "outer");
    tree(&d);
    ok(&d, &["inscribe", "src", "-o", "old.sg1"]);
    // no encrypted members: no key check needed
    ok(
        &d,
        &[
            "seal-folder-names",
            "old.sg1",
            "-o",
            "new.sg1",
            "--pass-file",
            "pw",
        ],
    );
    let new = fs::read(d.join("new.sg1")).unwrap();
    assert!(!has(&new, "tax-return-2025") && !has(&new, "secret content"));
    ok(&d, &["unseal", "new.sg1", "-o", "out", "--pass-file", "pw"]);
    assert_eq!(
        fs::read_to_string(d.join("out/readme-public.txt")).unwrap(),
        "hello\n"
    );
    pw(&d, "bad", "nope");
    fails(
        &d,
        &["unseal", "new.sg1", "-o", "out3", "--pass-file", "bad"],
    );
}
