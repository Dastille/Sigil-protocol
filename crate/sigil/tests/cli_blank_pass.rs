//! CLI: `--pass "   "` and a pass file whose first line is only spaces are refused.
mod common;
use std::path::Path;
use std::process::{Command, Stdio};

fn sigil(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run sigil")
}

#[test]
fn blank_pass_and_blank_pass_file_are_refused() {
    let d = common::scratch("cli-blank");
    std::fs::write(d.join("a.txt"), b"hello").unwrap();
    let o = sigil(&d, &["seal", "a.txt", "-o", "a.sg1", "--pass", "   "]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("only spaces"));
    std::fs::write(d.join("pw"), "   \nreal\n").unwrap();
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        std::fs::set_permissions(d.join("pw"), std::fs::Permissions::from_mode(0o600)).unwrap();
    }
    let o = sigil(&d, &["seal", "a.txt", "-o", "a.sg1", "--pass-file", "pw"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("only spaces"));
    assert!(!d.join("a.sg1").exists());
    let _ = std::fs::remove_dir_all(&d);
}
