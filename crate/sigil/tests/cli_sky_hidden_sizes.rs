//! Constellation Scry never prints `0 bytes` for a member whose size is hidden in a
//! private label: with the key it shows the real size, without it "size hidden".
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
    let t = format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    );
    assert!(o.status.success(), "{args:?}: {t}");
    t
}

fn tree(d: &Path) {
    fs::create_dir_all(d.join("docs/sub")).unwrap();
    fs::write(d.join("docs/a.txt"), b"alpha alpha alpha").unwrap();
    fs::write(d.join("docs/sub/c.bin"), vec![7u8; 60_000]).unwrap();
    fs::write(d.join("docs/empty.txt"), b"").unwrap();
}

fn line<'a>(t: &'a str, name: &str) -> &'a str {
    t.lines()
        .find(|l| l.starts_with("star ") && l.contains(&format!("  {name}  ")))
        .unwrap_or_else(|| panic!("no line for {name}: {t}"))
}

#[test]
fn locked_card_sizes_are_real_or_hidden_never_zero() {
    let d = common::scratch("sky-hidden-sizes");
    tree(&d);
    // Right after `add` the list is shown without opening labels: hidden, not zero.
    let t = ok(&d, &["constellation", "add", "--pass", "pw", "Enc", "docs"]);
    assert!(line(&t, "a.txt").contains("size hidden"), "{t}");
    assert!(!line(&t, "a.txt").contains("0 bytes"), "{t}");
    assert!(line(&t, "sub/c.bin").contains("size hidden"), "{t}");
    // A truly empty file is still 0 bytes.
    assert!(line(&t, "empty.txt").contains("  0 bytes  "), "{t}");

    for args in [
        &["constellation", "scry", "Enc", "--pass", "pw"][..],
        &["scry", "Enc", "--pass", "pw"][..],
        &["constellation", "scry", "Enc", "--pass", "pw", "--json"][..],
    ] {
        let t = ok(&d, args);
        let t = t.replace("\\n", "\n");
        assert!(line(&t, "a.txt").contains("  17 bytes  "), "{args:?}: {t}");
        assert!(
            line(&t, "sub/c.bin").contains("  60000 bytes  "),
            "{args:?}: {t}"
        );
        assert!(
            line(&t, "empty.txt").contains("  0 bytes  "),
            "{args:?}: {t}"
        );
    }
}

#[test]
fn plain_card_sizes_unchanged() {
    let d = common::scratch("sky-plain-sizes");
    tree(&d);
    ok(&d, &["constellation", "add", "Sky", "docs"]);
    let t = ok(&d, &["constellation", "scry", "Sky"]);
    assert!(line(&t, "a.txt").contains("  17 bytes  "), "{t}");
    assert!(line(&t, "sub/c.bin").contains("  60000 bytes  "), "{t}");
    assert!(!t.contains("size hidden"), "{t}");
}
