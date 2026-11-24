//! CLI: the repair "wait screen" — ask before a long repair (terminal only), skip with
//! exit 4 when nobody can be asked and the estimate is over the unattended budget, and
//! Ctrl-C stops without writing anything. Thresholds are lowered with the documented
//! `SIGIL_MEND_ASK_SECS` / `SIGIL_MEND_UNATTENDED_SECS` settings so small files trigger them.
mod common;
use std::io::{Read, Write};
use std::path::Path;
use std::process::{Command, Output, Stdio};

fn sigil_env(dir: &Path, env: &[(&str, &str)], args: &[&str]) -> Output {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sigil"));
    c.current_dir(dir).args(args);
    for (k, v) in env {
        c.env(k, v);
    }
    c.output().expect("run sigil")
}

fn text(o: &Output) -> String {
    format!(
        "{}{}",
        String::from_utf8_lossy(&o.stdout),
        String::from_utf8_lossy(&o.stderr)
    )
}

fn data(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect()
}

fn files(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .expect("read dir")
        .filter_map(|e| e.ok())
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

/// Seal `n` bytes as photo.sg1, then flip one bit every `step` bytes after the header
/// (scattered bit rot: every shard fails its CRC, so the deeper repair runs).
fn rotten(dir: &Path, n: usize, step: usize) {
    std::fs::write(dir.join("photo.bin"), data(n, 0x5eed)).expect("write");
    let o = sigil_env(dir, &[], &["seal", "-o", "photo.sg1", "photo.bin"]);
    assert!(o.status.success(), "{}", text(&o));
    let mut b = std::fs::read(dir.join("photo.sg1")).expect("read");
    let mut i = 4096;
    while i < b.len() {
        b[i] ^= 0x10;
        i += step;
    }
    std::fs::write(dir.join("photo.sg1"), &b).expect("write");
}

#[test]
fn no_terminal_over_budget_skips_with_exit_4_and_writes_nothing() {
    let t = common::scratch("mend-wait");
    let d = t.path();
    rotten(d, 200_000, 1000);
    let before = files(d);
    let budget = [("SIGIL_MEND_UNATTENDED_SECS", "0")];
    let o = sigil_env(d, &budget, &["mend", "photo.sg1"]);
    let out = text(&o);
    assert_eq!(o.status.code(), Some(4), "{out}");
    assert!(
        out.contains("repair skipped") && out.contains("--yes"),
        "{out}"
    );
    assert_eq!(files(d), before, "nothing may be written");

    let o = sigil_env(d, &budget, &["mend", "--json", "photo.sg1"]);
    let j = String::from_utf8_lossy(&o.stdout).to_string();
    assert!(
        j.contains("\"exit\":4") && j.contains("\"skipped\":true"),
        "{j}"
    );
    assert_eq!(files(d), before);

    // --yes starts anyway, and the copy opens to the original bytes.
    let o = sigil_env(
        d,
        &budget,
        &["mend", "--yes", "-o", "fixed.sg1", "photo.sg1"],
    );
    assert!(o.status.success(), "{}", text(&o));
    let o = sigil_env(d, &[], &["unseal", "fixed.sg1", "-o", "back.bin"]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(
        std::fs::read(d.join("back.bin")).expect("read"),
        data(200_000, 0x5eed)
    );

    // Default budget (15 minutes): a small repair just runs, no question, no skip.
    let o = sigil_env(d, &[], &["mend", "-o", "fixed2.sg1", "photo.sg1"]);
    assert!(o.status.success(), "{}", text(&o));
}

#[test]
fn bad_wait_setting_is_refused_and_writes_nothing() {
    let t = common::scratch("mend-wait");
    let d = t.path();
    rotten(d, 100_000, 1000);
    let before = files(d);
    let o = sigil_env(
        d,
        &[("SIGIL_MEND_UNATTENDED_SECS", "soon")],
        &["mend", "photo.sg1"],
    );
    assert_eq!(o.status.code(), Some(1), "{}", text(&o));
    assert!(text(&o).contains("whole number"), "{}", text(&o));
    assert_eq!(files(d), before);
}

/// Run `sigil ARGS` on a pseudo-terminal through util-linux `script`, so stdin and stderr
/// are terminals. Types `first`; then, if `wait_for` is `(text, keys)`, waits until the
/// output contains `text` and types `keys`.
#[cfg(target_os = "linux")]
fn on_terminal(
    dir: &Path,
    env: &[(&str, &str)],
    args: &str,
    first: &[u8],
    wait_for: Option<(&str, &[u8])>,
) -> Option<(Option<i32>, String)> {
    if Command::new("script").arg("--version").output().is_err() {
        eprintln!("skipping: util-linux `script` not available");
        return None;
    }
    let cmd = format!("{} {args}", env!("CARGO_BIN_EXE_sigil"));
    let mut c = Command::new("script");
    c.current_dir(dir)
        .args(["-qec", &cmd, "/dev/null"])
        .stdin(Stdio::piped())
        .stdout(Stdio::piped())
        .stderr(Stdio::null());
    for (k, v) in env {
        c.env(k, v);
    }
    let mut child = c.spawn().expect("spawn script");
    let mut stdin = child.stdin.take().expect("stdin");
    let mut stdout = child.stdout.take().expect("stdout");
    let buf = std::sync::Arc::new(std::sync::Mutex::new(Vec::<u8>::new()));
    let b2 = buf.clone();
    let reader = std::thread::spawn(move || {
        let mut chunk = [0u8; 4096];
        while let Ok(n) = stdout.read(&mut chunk) {
            if n == 0 {
                break;
            }
            b2.lock().expect("lock").extend_from_slice(&chunk[..n]);
        }
    });
    stdin.write_all(first).expect("type");
    stdin.flush().expect("flush");
    if let Some((needle, keys)) = wait_for {
        let t0 = std::time::Instant::now();
        while !String::from_utf8_lossy(&buf.lock().expect("lock")).contains(needle) {
            assert!(t0.elapsed().as_secs() < 60, "never saw {needle:?}");
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        stdin.write_all(keys).expect("type");
        stdin.flush().expect("flush");
    }
    let status = child.wait().expect("wait");
    drop(stdin);
    reader.join().expect("reader");
    let out = String::from_utf8_lossy(&buf.lock().expect("lock")).into_owned();
    Some((status.code(), out))
}

#[cfg(target_os = "linux")]
#[test]
fn terminal_decline_writes_nothing_and_yes_repairs() {
    let t = common::scratch("mend-wait");
    let d = t.path();
    rotten(d, 200_000, 1000);
    let before = files(d);
    let ask = [("SIGIL_MEND_ASK_SECS", "0")];
    let Some((code, out)) = on_terminal(d, &ask, "mend photo.sg1", b"n\n", None) else {
        return;
    };
    assert!(out.contains("Keep going? [y/N]"), "{out}");
    assert!(out.contains("repair skipped"), "{out}");
    assert_eq!(code, Some(4), "{out}");
    assert_eq!(files(d), before, "declining must write nothing");

    // Just Enter is "no" too (safe default).
    let Some((code, _)) = on_terminal(d, &ask, "mend photo.sg1", b"\n", None) else {
        return;
    };
    assert_eq!(code, Some(4));
    assert_eq!(files(d), before);

    let Some((code, out)) = on_terminal(d, &ask, "mend -o fixed.sg1 photo.sg1", b"y\n", None)
    else {
        return;
    };
    assert_eq!(code, Some(0), "{out}");
    let o = sigil_env(d, &[], &["unseal", "fixed.sg1", "-o", "back.bin"]);
    assert!(o.status.success(), "{}", text(&o));
    assert_eq!(
        std::fs::read(d.join("back.bin")).expect("read"),
        data(200_000, 0x5eed)
    );
}

#[cfg(target_os = "linux")]
#[test]
fn ctrl_c_mid_repair_stops_and_leaves_no_output() {
    let t = common::scratch("mend-wait");
    let d = t.path();
    // A wiped stretch plus scattered bit rot: the deeper repair runs for a few hundred ms,
    // far longer than typing Ctrl-C takes. If a very fast machine still finishes first,
    // try again (up to 3 times); every stopped run must leave no file behind.
    rotten(d, 3_000_000, 150);
    let mut b = std::fs::read(d.join("photo.sg1")).expect("read");
    let a = b.len() / 4;
    b[a..a + 400_000].fill(0);
    std::fs::write(d.join("photo.sg1"), &b).expect("write");
    let before = files(d);
    let mut stopped = 0;
    for _ in 0..3 {
        let Some((code, out)) = on_terminal(
            d,
            &[("SIGIL_MEND_ASK_SECS", "0")],
            "mend -o fixed.sg1 photo.sg1",
            b"y\n",
            // Printed once the Ctrl-C handler is in place; \x03 is Ctrl-C on a terminal.
            Some(("Working on it now", b"\x03")),
        ) else {
            return;
        };
        if code == Some(130) {
            assert!(out.contains("repair stopped"), "{out}");
            assert_eq!(
                files(d),
                before,
                "a stopped repair must leave no file behind"
            );
            stopped += 1;
            break;
        }
        // Lost the race: the repair finished first and wrote a checked copy.
        assert_eq!(code, Some(0), "{out}");
        std::fs::remove_file(d.join("fixed.sg1")).expect("remove");
    }
    assert_eq!(stopped, 1, "Ctrl-C never arrived during the repair");
}
