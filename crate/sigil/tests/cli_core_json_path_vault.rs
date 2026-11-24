//! `--json` on `path`, `vault status`, `vault versions`, `gc`, `tidy` and `sign`: one result
//! line on stdout, human lines on stderr, the usual exit codes, no secrets.
mod common;
use std::fs;
use std::path::Path;
use std::process::Command;

fn run(d: &Path, a: &[&str]) -> (i32, String, String) {
    let o = Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(d)
        .args(a)
        .output()
        .expect("run sigil");
    (
        o.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&o.stdout).to_string(),
        String::from_utf8_lossy(&o.stderr).to_string(),
    )
}
fn ok(d: &Path, a: &[&str]) {
    let (c, o, e) = run(d, a);
    assert_eq!(c, 0, "{a:?}: {o}{e}");
}
fn json(d: &Path, a: &[&str], want: i32) -> String {
    let (c, out, err) = run(d, a);
    assert_eq!(c, want, "{a:?}: {out}{err}");
    assert_eq!(out.lines().count(), 1, "{out}");
    assert!(out.starts_with('{') && out.ends_with("}\n"), "{out}");
    out
}

#[test]
fn path_json_plain_and_locked_pack() {
    let d = common::scratch("json-path");
    fs::create_dir_all(d.join("dir")).unwrap();
    fs::write(d.join("dir/a.txt"), "aa\n").unwrap();
    fs::write(d.join("dir/q \"x\".txt"), "qqq\n").unwrap();
    ok(&d, &["seal", "dir", "-o", "plain.sg1"]);
    let j = json(&d, &["path", "plain.sg1", "--json"], 0);
    assert!(j.starts_with("{\"ok\":true,\"cmd\":\"path\",\"exit\":0,\"view\":{\"trail\":[\"plain.sg1\"],\"kind\":\"folder\""), "{j}");
    assert!(
        j.contains("{\"path\":\"q \\\"x\\\".txt\",\"size\":4,\"nest\":false,\"sha256\":\""),
        "{j}"
    );
    let j = json(
        &d,
        &["path", "plain.sg1", "a.txt", "-o", "got", "--json"],
        0,
    );
    assert!(
        j.contains("\"output\":\"got\",\"output_bytes\":3") && j.contains("\"kind\":\"leaf\""),
        "{j}"
    );
    assert_eq!(fs::read(d.join("got")).unwrap(), b"aa\n");
    let (c, _, e) = run(&d, &["path", "plain.sg1", "--json", "--pretty"]);
    assert_eq!(c, 2, "{e}");

    // encrypted pack: names only with the key; without it ok:false and no names
    fs::write(d.join("pw"), "path-secret\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join("pw"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    ok(
        &d,
        &["seal", "dir", "-o", "locked.sg1", "--pass-file", "pw"],
    );
    let j = json(&d, &["path", "locked.sg1", "--json"], 1);
    assert!(
        j.starts_with("{\"ok\":false,\"cmd\":\"path\"") && !j.contains("a.txt"),
        "{j}"
    );
    let j = json(
        &d,
        &["path", "locked.sg1", "--pass-file", "pw", "--json"],
        0,
    );
    assert!(
        j.contains("\"path\":\"a.txt\"") && !j.contains("path-secret"),
        "{j}"
    );
    // a folder that is not a .sg1 points at the right command
    let j = json(&d, &["path", "dir", "--json"], 1);
    assert!(j.contains("takes a .sg1 file"), "{j}");
}

#[test]
fn vault_gc_tidy_sign_as_json() {
    let d = common::scratch("json-vault");
    fs::write(d.join("n.txt"), "one\n").unwrap();
    ok(&d, &["vault", "track", "n.txt"]);
    let j = json(&d, &["vault", "status", "n.txt", "--json"], 0);
    assert!(
        j.starts_with("{\"ok\":true,\"cmd\":\"vault status\",\"exit\":0,\"status\":{\"live\":"),
        "{j}"
    );
    assert!(
        j.contains("\"tip\":1,\"drift\":\"match\"") && j.contains("\"tip_size\":4"),
        "{j}"
    );
    fs::write(d.join("n.txt"), "two!\n").unwrap();
    let j = json(&d, &["vault", "status", "n.txt", "--json"], 0);
    assert!(j.contains("\"drift\":\"changed\""), "{j}");
    ok(&d, &["vault", "commit", "n.txt"]);
    let j = json(&d, &["vault", "versions", "n.txt", "--json"], 0);
    assert!(
        j.contains("\"tip\":2,\"versions\":[{\"n\":1,")
            && j.contains("{\"n\":2,\"seal\":\"v2.sg1\""),
        "{j}"
    );
    assert!(j.contains("\"recipients\":0"), "{j}");
    let j = json(&d, &["vault", "status", "missing.txt", "--json"], 0);
    assert!(
        j.contains("\"tip\":0,\"drift\":\"missing-vault\",\"live_sha256\":null"),
        "{j}"
    );

    let j = json(&d, &["gc", "n.txt", "--json"], 0);
    assert!(
        j.contains("\"report\":{\"kind\":\"vault\"")
            && j.contains("\"apply\":false")
            && j.contains("\"kept\":2"),
        "{j}"
    );
    let j = json(&d, &["tidy", "n.txt", "--dry-run", "--json"], 0);
    assert!(j.contains("\"already\":true"), "{j}");

    ok(&d, &["keygen", "-o", "k.sgk"]);
    ok(&d, &["seal", "n.txt", "-o", "n.sg1"]);
    let j = json(&d, &["sign", "n.sg1", "--key", "k.sgk", "--json"], 0);
    assert_eq!(
        j,
        "{\"ok\":true,\"cmd\":\"sign\",\"exit\":0,\"attestation\":\"n.sg1.sig\"}\n"
    );
    let j = json(&d, &["sign", "n.sg1", "--key", "nope.sgk", "--json"], 1);
    assert!(j.starts_with("{\"ok\":false,\"cmd\":\"sign\""), "{j}");
}
