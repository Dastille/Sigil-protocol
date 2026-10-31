//! `--json` on `scry`, `mend`, `scatter`, `kit place` and `kit mend`: one result line on stdout
//! (`{"ok":…,"cmd":…,"exit":…}` plus fields), human lines on stderr, the usual exit codes.
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
/// The JSON line is the only thing on stdout.
fn json(d: &Path, a: &[&str], want: i32) -> String {
    let (c, out, err) = run(d, a);
    assert_eq!(c, want, "{a:?}: {out}{err}");
    assert_eq!(out.lines().count(), 1, "{out}");
    assert!(out.starts_with('{') && out.ends_with("}\n"), "{out}");
    out
}
fn sample(d: &Path) -> Vec<u8> {
    let data: Vec<u8> = (0..40_000u32).map(|i| (i * 7 + i / 13) as u8).collect();
    fs::write(d.join("f"), &data).unwrap();
    let (c, _, e) = run(d, &["seal", "f", "-o", "f.sg1"]);
    assert_eq!(c, 0, "{e}");
    fs::read(d.join("f.sg1")).unwrap()
}

#[test]
fn scry_and_mend_as_json() {
    let d = common::scratch("core-json-mend");
    let full = sample(&d);
    let j = json(&d, &["scry", "f.sg1", "--json"], 0);
    assert!(
        j.starts_with("{\"ok\":true,\"cmd\":\"scry\",\"exit\":0,\"report\":\"ok  v2"),
        "{j}"
    );
    fs::write(d.join("torn.sg1"), &full[..300]).unwrap();
    let j = json(&d, &["scry", "torn.sg1", "--json"], 2);
    assert!(
        j.starts_with("{\"ok\":false,\"cmd\":\"scry\",\"exit\":2,\"error\":\"NOT recoverable"),
        "{j}"
    );

    let mut hurt = full.clone();
    let m = hurt.len() / 2;
    hurt[m..m + 200].fill(0);
    fs::write(d.join("hurt.sg1"), &hurt).unwrap();
    let j = json(&d, &["mend", "hurt.sg1", "-o", "fixed.sg1", "--json"], 0);
    assert!(
        j.starts_with(
            "{\"ok\":true,\"cmd\":\"mend\",\"exit\":0,\"output\":\"fixed.sg1\",\"output_bytes\":"
        ),
        "{j}"
    );
    assert!(j.contains("\"kind\":\"mark\",\"live\":16,\"n\":16,\"need\":12,\"merkle\":true,\"soft_salvage\":false"), "{j}");
    assert_eq!(fs::read(d.join("fixed.sg1")).unwrap(), full);
    let j = json(&d, &["mend", "torn.sg1", "-o", "x.sg1", "--json"], 1);
    assert!(j.starts_with("{\"ok\":false,\"cmd\":\"mend\""), "{j}");
    assert!(!d.join("x.sg1").exists());
}

#[test]
fn scatter_and_kit_as_json() {
    let d = common::scratch("core-json-kit");
    let full = sample(&d);
    let j = json(&d, &["scatter", "f.sg1", "-o", "pieces", "--json"], 0);
    assert_eq!(
        j,
        "{\"ok\":true,\"cmd\":\"scatter\",\"exit\":0,\"output\":\"pieces\",\"pieces\":16}\n"
    );
    let j = json(&d, &["kit", "place", "f.sg1", "-o", "kit", "--json"], 0);
    assert!(
        j.contains("\"cmd\":\"kit place\"")
            && j.contains("\"drives\":4,\"pieces\":16,\"per_drive\":[4,4,4,4],\"star\":\""),
        "{j}"
    );
    fs::remove_dir_all(d.join("kit/usb-2")).unwrap();
    let j = json(&d, &["kit", "mend", "kit", "-o", "back.sg1", "--json"], 0);
    assert!(j.starts_with("{\"ok\":true,\"cmd\":\"kit mend\",\"exit\":0,\"output\":\"back.sg1\",\"output_bytes\":"), "{j}");
    assert_eq!(fs::read(d.join("back.sg1")).unwrap(), full);
    // two sticks lost: 8 of 16 pieces, below k=12
    fs::remove_dir_all(d.join("kit/usb-0")).unwrap();
    let j = json(&d, &["kit", "mend", "kit", "-o", "nope.sg1", "--json"], 1);
    assert!(j.starts_with("{\"ok\":false,\"cmd\":\"kit mend\""), "{j}");
}
