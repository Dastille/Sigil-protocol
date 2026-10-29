//! `sigil path --pretty`: framed inspect card; plain output unchanged without the flag.
use std::path::Path;
use std::process::{Command, Stdio};

fn sigil(dir: &Path, args: &[&str]) -> String {
    let o = Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(args)
        .env_remove("CLICOLOR_FORCE")
        .env_remove("SIGIL_ASCII")
        .stdin(Stdio::null())
        .output()
        .expect("run sigil");
    assert!(o.status.success(), "{}", String::from_utf8_lossy(&o.stderr));
    String::from_utf8(o.stdout).expect("utf8")
}

#[test]
fn path_pretty_folder_and_mark() {
    let d = std::env::temp_dir().join(format!("sigil-pretty-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(d.join("album/notes")).expect("mkdir");
    std::fs::write(d.join("album/notes/todo.txt"), b"hello").expect("w");
    std::fs::write(d.join("album/readme.txt"), b"readme").expect("w");
    std::fs::write(d.join("one.txt"), b"hi").expect("w");
    sigil(&d, &["seal", "album", "-o", "album.sg1"]);
    sigil(&d, &["seal", "one.txt", "-o", "one.sg1"]);

    let plain = sigil(&d, &["path", "album.sg1"]);
    assert!(
        plain.starts_with("trail  album.sg1\nkind   folder\n"),
        "{plain}"
    );
    assert!(plain.contains("file  notes/todo.txt  5 bytes"), "{plain}");

    let pretty = sigil(&d, &["path", "album.sg1", "--pretty"]);
    assert!(pretty.starts_with("  SIGIL"), "{pretty}");
    assert!(pretty.contains("\n  album.sg1\n"), "{pretty}");
    assert!(pretty.contains("  TREE\n  0000  notes/"), "{pretty}");
    assert!(pretty.contains("  0001    todo.txt"), "{pretty}");
    assert!(pretty.contains("FILE SHA-256\n  0000  "), "{pretty}");
    assert!(
        !pretty.contains('\x1b'),
        "piped output must not carry color"
    );

    let mark = sigil(&d, &["ls", "one.sg1", "--pretty"]);
    assert!(mark.contains("HEALTH      healthy"), "{mark}");
    assert!(mark.contains("NAME        one.txt"), "{mark}");
    let _ = std::fs::remove_dir_all(&d);
}
