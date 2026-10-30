//! `sigil show`: HTTP Range serving that players (Plex/Jellyfin .strm, VLC/mpv by URL)
//! rely on — 200/206/416, suffix ranges, HEAD, MIME, parallel connections, refusals.
mod common;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::TcpStream;
use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct Show(Child);
impl Drop for Show {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn tmp(tag: &str) -> common::Scratch {
    let d = common::scratch(&format!("show-{tag}"));
    d
}

fn sigil(dir: &Path, args: &[&str]) -> std::process::Output {
    Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args(args)
        .stdin(Stdio::null())
        .output()
        .expect("run sigil")
}

fn start(dir: &Path, mark: &str) -> (Show, String) {
    let mut c = Command::new(env!("CARGO_BIN_EXE_sigil"))
        .current_dir(dir)
        .args([
            "show",
            mark,
            "--bind",
            "127.0.0.1:0",
            "--strm",
            "lib/film.strm",
        ])
        .stdin(Stdio::null())
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()
        .expect("spawn show");
    let out = c.stdout.take().expect("stdout");
    let show = Show(c);
    let mut r = BufReader::new(out);
    let mut line = String::new();
    loop {
        line.clear();
        assert!(r.read_line(&mut line).expect("read") > 0, "show exited");
        if let Some(rest) = line.strip_prefix("Showing on ") {
            let addr = rest.split_whitespace().next().expect("addr").to_string();
            std::thread::spawn(move || {
                let mut sink = Vec::new();
                let _ = r.read_to_end(&mut sink);
            });
            return (show, addr);
        }
    }
}

/// (status line, headers lowercased, body)
fn get(addr: &str, method: &str, path: &str, range: Option<&str>) -> (String, String, Vec<u8>) {
    let mut s = TcpStream::connect(addr).expect("connect");
    s.set_read_timeout(Some(Duration::from_secs(30))).ok();
    let mut req = format!("{method} {path} HTTP/1.1\r\nHost: x\r\n");
    if let Some(r) = range {
        req.push_str(&format!("Range: {r}\r\n"));
    }
    req.push_str("\r\n");
    s.write_all(req.as_bytes()).expect("send");
    let mut all = Vec::new();
    let _ = s.read_to_end(&mut all);
    let split = all
        .windows(4)
        .position(|w| w == b"\r\n\r\n")
        .expect("header end");
    let head = String::from_utf8_lossy(&all[..split]).to_string();
    let body = all[split + 4..].to_vec();
    let status = head.lines().next().unwrap_or("").to_string();
    (status, head.to_ascii_lowercase(), body)
}

fn data(n: usize) -> Vec<u8> {
    (0..n).map(|i| (i * 7 % 253) as u8).collect()
}

fn check_ranges(addr: &str, want: &[u8]) {
    let len = want.len();
    let (st, h, b) = get(addr, "GET", "/play", None);
    assert!(st.contains("200"), "{st}");
    assert!(
        !h.contains("content-range"),
        "200 has no Content-Range: {h}"
    );
    assert!(h.contains("content-type: video/mp4"), "{h}");
    assert!(h.contains("accept-ranges: bytes"));
    assert_eq!(b, want);
    let (st, h, b) = get(addr, "GET", "/play", Some("bytes=100-199"));
    assert!(st.contains("206"), "{st}");
    assert!(
        h.contains(&format!("content-range: bytes 100-199/{len}")),
        "{h}"
    );
    assert_eq!(b, &want[100..200]);
    // Straddle a 4 MiB slice boundary (work pack) / any middle span.
    let a = 4 * 1024 * 1024 - 10;
    let (a, z) = if len > a + 20 {
        (a, a + 19)
    } else {
        (len / 2, len / 2 + 19)
    };
    let (st, _, b) = get(
        addr,
        "GET",
        "/play/film.mp4",
        Some(&format!("bytes={a}-{z}")),
    );
    assert!(st.contains("206"), "{st}");
    assert_eq!(b, &want[a..=z]);
    let (st, h, b) = get(addr, "GET", "/play", Some("bytes=-1000"));
    assert!(st.contains("206"), "{st}");
    assert!(h.contains(&format!(
        "content-range: bytes {}-{}/{len}",
        len - 1000,
        len - 1
    )));
    assert_eq!(b, &want[len - 1000..]);
    let (st, h, _) = get(addr, "GET", "/play", Some(&format!("bytes={len}-")));
    assert!(st.contains("416"), "{st}");
    assert!(h.contains(&format!("content-range: bytes */{len}")), "{h}");
    let (st, h, b) = get(addr, "HEAD", "/play", None);
    assert!(st.contains("200"));
    assert!(h.contains(&format!("content-length: {len}")));
    assert!(b.is_empty());
    let (st, _, _) = get(addr, "GET", "/nope", None);
    assert!(st.contains("404"), "{st}");
    let (st, _, _) = get(addr, "POST", "/play", None);
    assert!(st.contains("405"), "{st}");
    // Parallel seeks (players open several connections at once).
    let hs: Vec<_> = (0..6)
        .map(|i| {
            let addr = addr.to_string();
            let off = (len / 7) * i;
            std::thread::spawn(move || {
                get(
                    &addr,
                    "GET",
                    "/play",
                    Some(&format!("bytes={off}-{}", off + 4095)),
                )
            })
        })
        .collect();
    for (i, h) in hs.into_iter().enumerate() {
        let (st, _, b) = h.join().expect("join");
        let off = (len / 7) * i;
        assert!(st.contains("206"));
        assert_eq!(b, &want[off..off + 4096]);
    }
}

#[test]
fn show_plain_sg1_ranges() {
    let d = tmp("plain");
    let want = data(300_000);
    std::fs::write(d.join("film.mp4"), &want).expect("w");
    assert!(sigil(&d, &["seal", "film.mp4", "-o", "film.sg1"])
        .status
        .success());
    let (_s, addr) = start(&d, "film.sg1");
    assert!(std::fs::read_to_string(d.join("lib/film.strm"))
        .expect("strm")
        .ends_with("/play\n"));
    check_ranges(&addr, &want);
}

#[test]
fn show_work_pack_ranges() {
    let d = tmp("work");
    let want = data(11 * 1024 * 1024 + 123);
    std::fs::write(d.join("film.mp4"), &want).expect("w");
    assert!(sigil(&d, &["seal", "film.mp4", "-o", "film.sg1"])
        .status
        .success());
    let (_s, addr) = start(&d, "film.sg1");
    check_ranges(&addr, &want);
}

#[test]
fn show_refuses_folder_wrap() {
    let d = tmp("folder");
    std::fs::create_dir_all(d.join("f")).expect("mkdir");
    std::fs::write(d.join("f/a.mp4"), b"x").expect("w");
    assert!(sigil(&d, &["seal", "f", "-o", "f.sg1"]).status.success());
    let o = sigil(&d, &["show", "f.sg1", "--bind", "127.0.0.1:0"]);
    assert!(!o.status.success());
    assert!(String::from_utf8_lossy(&o.stderr).contains("sigil mount"));
    let o = sigil(&d, &["show", "f", "--bind", "127.0.0.1:0"]);
    assert!(!o.status.success());
}
