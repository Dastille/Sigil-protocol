//! `sigil log verify` checks a big segment without copying it: the segment is memory-mapped,
//! shards are borrowed, and the "are the redundant copies intact" step re-encodes a megabyte of
//! columns at a time. Before this, a healthy segment of S bytes cost about 7.5 × S of private
//! memory (measured: 10.3 GiB for a 1.33 GiB segment; 28.7 GB for the 3.79 GB Instagram one).
//! Linux only: the peak is read from /proc.
#![cfg(target_os = "linux")]
mod common;
use std::process::{Command, Stdio};

fn rss_anon_kib(pid: u32) -> Option<u64> {
    let s = std::fs::read_to_string(format!("/proc/{pid}/status")).ok()?;
    s.lines()
        .find_map(|l| l.strip_prefix("RssAnon:"))
        .and_then(|v| v.trim().trim_end_matches("kB").trim().parse().ok())
}

#[test]
fn verify_big_segment_private_memory_stays_small() {
    let d = common::scratch("verify-mem");
    let src = d.join("src");
    std::fs::create_dir_all(&src).expect("mkdir");
    // 80 MiB of incompressible bytes: one segment above the 64 MiB mapping threshold
    let mut x: u64 = 0x9e37_79b9_7f4a_7c15;
    let data: Vec<u8> = (0..80 << 20)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x as u8
        })
        .collect();
    std::fs::write(src.join("big.bin"), &data).expect("write");
    drop(data);
    let sigil = env!("CARGO_BIN_EXE_sigil");
    let run = |args: &[&str]| {
        let o = Command::new(sigil)
            .current_dir(&d)
            .args(args)
            .output()
            .expect("run");
        assert!(
            o.status.success(),
            "{args:?}: {}",
            String::from_utf8_lossy(&o.stderr)
        );
    };
    run(&["log", "init", "ev"]);
    run(&["log", "add", "ev", "src"]);

    let mut child = Command::new(sigil)
        .current_dir(&d)
        .args(["log", "verify", "ev"])
        .stdout(Stdio::piped())
        .spawn()
        .expect("spawn");
    let mut peak = 0u64;
    while child.try_wait().expect("wait").is_none() {
        if let Some(k) = rss_anon_kib(child.id()) {
            peak = peak.max(k);
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    let out = child.wait_with_output().expect("output");
    assert!(out.status.success());
    assert!(String::from_utf8_lossy(&out.stdout).contains("result: healthy"));
    // the old path held ~600 MiB here; the bounded one a few MiB
    assert!(
        peak < 48 * 1024,
        "peak private memory {peak} KiB for an 80 MiB segment"
    );
}
