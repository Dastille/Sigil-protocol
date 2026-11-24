//! Regression (PR #27 follow-up): test scratch folders are exclusive and unguessable.
//! Integration tests used `temp_dir()/sigil-<tag>-<pid>`, wiping and reusing whatever
//! already sat at that name. A folder planted there is now neither used nor removed.
mod common;

use std::fs;

#[test]
fn scratch_is_fresh_private_and_ignores_planted_old_names() {
    let pid = std::process::id();
    let planted: Vec<_> = ["sigil-cli-blank", "sigil-pretty", "sigil-encpath"]
        .iter()
        .map(|t| std::env::temp_dir().join(format!("{t}-{pid}")))
        .collect();
    for p in &planted {
        fs::create_dir_all(p).expect("plant");
        fs::write(p.join("planted.txt"), b"attacker").expect("plant file");
    }

    let a = common::scratch("cli-blank");
    let b = common::scratch("cli-blank");
    assert_ne!(a.path(), b.path());
    for s in [&a, &b] {
        assert!(!planted.iter().any(|p| p == s.path()));
        assert_eq!(
            fs::read_dir(s.path()).expect("read").count(),
            0,
            "starts empty"
        );
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let mode = fs::metadata(s.path()).expect("meta").permissions().mode();
            assert_eq!(mode & 0o777, 0o700);
        }
    }
    let gone = a.path().to_path_buf();
    drop(a);
    assert!(!gone.exists(), "removed on drop");

    for p in &planted {
        assert!(p.join("planted.txt").exists(), "planted folder left alone");
        let _ = fs::remove_dir_all(p);
    }
}
