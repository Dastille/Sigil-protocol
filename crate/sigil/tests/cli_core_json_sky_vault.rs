//! `--json` on `constellation add/scry/atlas/remove`, vault writes (`track`, `commit`,
//! `restore`, `prune`, `remove`, `recipients`, `retention`), `deluge`, `keygen` and
//! `seal-folder-names`: exactly one JSON line on stdout, human lines on stderr.
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
fn json(d: &Path, a: &[&str], want: i32) -> String {
    let (c, out, err) = run(d, a);
    assert_eq!(c, want, "{a:?}: {out}{err}");
    assert_eq!(out.lines().count(), 1, "{a:?}: {out}");
    assert!(out.starts_with('{') && out.ends_with("}\n"), "{out}");
    out
}

#[test]
fn constellation_as_json() {
    let d = common::scratch("json-sky");
    fs::write(d.join("a"), "aa\n").unwrap();
    fs::write(d.join("b"), "bb\n").unwrap();
    let j = json(&d, &["constellation", "add", "sky", "a", "--json"], 0);
    assert_eq!(j, "{\"ok\":true,\"cmd\":\"constellation add\",\"exit\":0,\"added\":1,\"linked\":0,\"skipped\":0,\"replaced\":0,\"new_bytes\":3}\n");
    json(&d, &["constellation", "add", "sky", "b", "--json"], 0);
    let j = json(&d, &["constellation", "add", "sky", "a", "--json"], 0);
    assert!(
        j.contains("\"added\":0") && j.contains("\"skipped\":1"),
        "{j}"
    );
    let j = json(&d, &["constellation", "scry", "sky", "--json"], 0);
    assert!(
        j.contains("\"report\":\"constellation  title=sky  stars=2"),
        "{j}"
    );
    let j = json(
        &d,
        &["constellation", "atlas", "sky", "-o", "bag.sga", "--json"],
        0,
    );
    assert!(j.contains("\"files\":3,\"output\":\"bag.sga\""), "{j}");
    let j = json(
        &d,
        &["constellation", "remove", "sky", "a", "--dry-run", "--json"],
        0,
    );
    assert!(j.contains("\"dry_run\":true,\"removed\":[\"a\"]"), "{j}");
    let j = json(&d, &["constellation", "remove", "sky", "a", "--json"], 0);
    assert!(
        j.contains("\"dry_run\":false") && j.contains("\"remaining\":1"),
        "{j}"
    );
    let j = json(&d, &["constellation", "remove", "sky", "zzz", "--json"], 1);
    assert!(
        j.starts_with("{\"ok\":false,\"cmd\":\"constellation remove\""),
        "{j}"
    );
}

#[test]
fn vault_writes_as_json() {
    let d = common::scratch("json-vault-writes");
    fs::write(d.join("n"), "v1\n").unwrap();
    let j = json(&d, &["vault", "track", "n", "--json"], 0);
    assert!(j.starts_with("{\"ok\":true,\"cmd\":\"vault track\",\"exit\":0,\"version\":1,\"size\":3,\"sha256\":\""), "{j}");
    let j = json(&d, &["vault", "commit", "n", "--json"], 0);
    assert!(
        j.contains("\"version\":1") && j.contains("\"skipped\":true"),
        "{j}"
    );
    fs::write(d.join("n"), "v2!\n").unwrap();
    let j = json(&d, &["vault", "commit", "n", "--json"], 0);
    assert!(
        j.contains("\"version\":2,\"size\":4") && j.contains("\"skipped\":false"),
        "{j}"
    );
    let j = json(
        &d,
        &[
            "vault",
            "restore",
            "n",
            "--version",
            "1",
            "--force",
            "--json",
        ],
        0,
    );
    assert!(
        j.contains("\"version\":1,\"size\":3") && j.contains("\"mended\":false"),
        "{j}"
    );
    assert_eq!(fs::read(d.join("n")).unwrap(), b"v1\n");
    fs::write(d.join("n"), "v3!!\n").unwrap();
    json(&d, &["vault", "commit", "n", "--json"], 0);
    let j = json(
        &d,
        &[
            "vault",
            "remove",
            "n",
            "--version",
            "1",
            "--dry-run",
            "--force-drop",
            "--json",
        ],
        0,
    );
    assert!(
        j.contains("\"removed\":1") && j.contains("\"dry_run\":true"),
        "{j}"
    );
    let j = json(&d, &["vault", "prune", "n", "--keep", "1", "--json"], 0);
    assert!(j.contains("\"kept\":1,\"tip\":3,\"removed\":[1,2]"), "{j}");
    let j = json(&d, &["vault", "retention", "n", "--json"], 0);
    assert_eq!(j, "{\"ok\":true,\"cmd\":\"vault retention\",\"exit\":0}\n");
    let j = json(&d, &["vault", "recipients", "n", "--json"], 0);
    assert_eq!(j, "{\"ok\":true,\"cmd\":\"vault recipients\",\"exit\":0}\n");
    let j = json(&d, &["vault", "commit", "missing", "--json"], 1);
    assert!(
        j.starts_with("{\"ok\":false,\"cmd\":\"vault commit\""),
        "{j}"
    );
}

#[test]
fn deluge_keygen_seal_folder_names_as_json() {
    let d = common::scratch("json-misc");
    fs::write(d.join("a"), "payload\n").unwrap();
    let (c, _, e) = run(&d, &["seal", "a", "-o", "a.sg1"]);
    assert_eq!(c, 0, "{e}");
    let j = json(&d, &["deluge", "a.sg1", "-o", "rain", "--json"], 0);
    assert_eq!(
        j,
        "{\"ok\":true,\"cmd\":\"deluge\",\"exit\":0,\"output\":\"rain\"}\n"
    );
    let (c, _, e) = run(&d, &["deluge", "a.sg1", "-o", "r2", "--json", "--watch"]);
    assert_eq!(c, 2, "{e}");

    let j = json(&d, &["keygen", "-o", "k.sgk", "--json"], 0);
    assert!(
        j.starts_with(
            "{\"ok\":true,\"cmd\":\"keygen\",\"exit\":0,\"output\":\"k.sgk\",\"output_bytes\":"
        ),
        "{j}"
    );
    let key = fs::read(d.join("k.sgk")).unwrap();
    assert!(!j.contains(&hex_of(&key)), "secret key in JSON: {j}");

    fs::create_dir_all(d.join("dir")).unwrap();
    fs::write(d.join("dir/x"), "x\n").unwrap();
    fs::write(d.join("pw"), "names-secret\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        fs::set_permissions(d.join("pw"), fs::Permissions::from_mode(0o600)).unwrap();
    }
    let (c, _, e) = run(
        &d,
        &[
            "seal",
            "dir",
            "-o",
            "old.sg1",
            "--ward-names-visible",
            "--ward-file",
            "x=pw",
        ],
    );
    assert_eq!(c, 0, "{e}");
    let j = json(
        &d,
        &[
            "seal-folder-names",
            "old.sg1",
            "-o",
            "new.sg1",
            "--pass-file",
            "pw",
            "--json",
        ],
        0,
    );
    assert!(
        j.contains("\"output\":\"new.sg1\"") && j.contains("\"files\":1,\"out_bytes\":"),
        "{j}"
    );
    assert!(!j.contains("names-secret"), "{j}");
}

fn hex_of(b: &[u8]) -> String {
    b.iter().map(|x| format!("{x:02x}")).collect()
}
