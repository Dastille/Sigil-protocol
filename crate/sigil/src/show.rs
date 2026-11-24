//! Showing: serve one sealed file over HTTP with byte ranges, so anything that can play
//! a URL (a `.strm` in Plex/Jellyfin/Kodi/Emby, VLC "Open Network Stream", mpv, a
//! browser) can play and seek it. Work packs De-scribe only the slices asked for.
//!
//! Each connection gets its own thread (players probe, play and seek on separate
//! connections at once). Unlocked work-pack slices are cached in RAM, at most
//! [`STAR_CACHE`] at a time, so a long film never fills memory.

use crate::work::StarLoc;
use crate::{payload_name, unseal_path, unseal_star_at, Result, WORK_MAGIC};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex, MutexGuard};
use std::time::{Duration, Instant};

/// Most unlocked work-pack slices kept in RAM at once (4 MiB each by default).
pub const STAR_CACHE: usize = 8;

struct Stage {
    file: PathBuf,
    ready: bool,
    work_len: Option<u64>,
    locs: Vec<StarLoc>,
    stars: HashMap<u32, Vec<u8>>,
}

struct Shared {
    mark: PathBuf,
    pass: Option<String>,
    mime: &'static str,
    stage: Mutex<Stage>,
    last: Mutex<Instant>,
}

fn lock<T>(m: &Mutex<T>) -> MutexGuard<'_, T> {
    m.lock().unwrap_or_else(std::sync::PoisonError::into_inner)
}

fn err(e: impl std::fmt::Display) -> crate::Error {
    crate::Error::Msg(e.to_string())
}

pub fn run_showing(
    mark: &Path,
    bind: &str,
    plex_dir: Option<&Path>,
    strm: Option<&Path>,
    public_base: &str,
    pass: Option<&str>,
    idle_secs: u64,
) -> Result<()> {
    if mark.is_dir() || crate::is_dir_pack(mark) || crate::is_constellation_input(mark) {
        return Err(crate::Error::Msg(
            "show plays ONE sealed file (a .sg1 or a large-file pack). For a folder wrap or \
             constellation use `sigil mount` (any app) or unseal the one file first"
                .into(),
        ));
    }
    let name = payload_name(mark)?;
    let url = format!("{}/play", public_base.trim_end_matches('/'));
    if let Some(dir) = plex_dir {
        fs::create_dir_all(dir).map_err(err)?;
        let path = dir.join(strm_name(&name));
        fs::write(&path, format!("{url}\n")).map_err(err)?;
        println!("wrote Plex stub {}", path.display());
    }
    if let Some(path) = strm {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).map_err(err)?;
        }
        fs::write(path, format!("{url}\n")).map_err(err)?;
        println!("wrote {}", path.display());
    }
    let tmp = std::env::temp_dir().join(format!("sigil-showing-{}", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let shared = Arc::new(Shared {
        mark: mark.to_path_buf(),
        pass: pass.map(str::to_string),
        mime: mime_for(&name),
        stage: Mutex::new(Stage {
            file: tmp.clone(),
            ready: false,
            work_len: None,
            locs: Vec::new(),
            stars: HashMap::new(),
        }),
        last: Mutex::new(Instant::now()),
    });

    let listener = TcpListener::bind(bind).map_err(err)?;
    listener.set_nonblocking(true).map_err(err)?;
    let at = listener
        .local_addr()
        .map(|a| a.to_string())
        .unwrap_or_else(|_| bind.to_string());
    println!("Showing on {at} → {url}");
    println!("Play the .strm in Plex/Jellyfin, or open {url} in VLC/mpv. Seeking works (HTTP Range). Work packs unlock only the slices the player reads.");
    println!("Idle {idle_secs}s then the temp copy is deleted. Ctrl-C to stop.");
    let _ = std::io::stdout().flush();

    let idle = Duration::from_secs(idle_secs.max(30));
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                *lock(&shared.last) = Instant::now();
                let _ = stream.set_nonblocking(false);
                let sh = Arc::clone(&shared);
                std::thread::spawn(move || {
                    if let Err(e) = handle(stream, &sh) {
                        eprintln!("showing: {e}");
                    }
                });
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let quiet = lock(&shared.last).elapsed();
                if quiet > idle {
                    let mut st = lock(&shared.stage);
                    if !st.stars.is_empty() {
                        st.stars.clear();
                        println!("idle — dropped unlocked slices from RAM");
                    }
                    if st.ready {
                        let _ = fs::remove_file(&tmp);
                        st.ready = false;
                        println!("idle — deleted temp copy {}", tmp.display());
                    }
                }
                std::thread::sleep(Duration::from_millis(50));
            }
            Err(e) => return Err(err(e)),
        }
    }
}

fn strm_name(name: &str) -> String {
    let stem = Path::new(name)
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("movie");
    if stem.ends_with(".strm") {
        stem.to_string()
    } else {
        format!("{stem}.strm")
    }
}

/// Content-Type from the stored file name (players use it to pick a demuxer).
pub fn mime_for(name: &str) -> &'static str {
    let ext = Path::new(name)
        .extension()
        .and_then(|e| e.to_str())
        .map(str::to_ascii_lowercase)
        .unwrap_or_default();
    match ext.as_str() {
        "mp4" | "m4v" => "video/mp4",
        "mkv" => "video/x-matroska",
        "webm" => "video/webm",
        "mov" => "video/quicktime",
        "avi" => "video/x-msvideo",
        "ts" | "m2ts" => "video/mp2t",
        "mp3" => "audio/mpeg",
        "m4a" | "aac" => "audio/mp4",
        "flac" => "audio/flac",
        "ogg" | "oga" => "audio/ogg",
        "opus" => "audio/opus",
        "wav" => "audio/wav",
        _ => "application/octet-stream",
    }
}

/// A parsed `Range:` header (single range only; anything else is ignored → 200).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Want {
    From(u64, Option<u64>),
    Suffix(u64),
}

pub fn parse_range(s: &str) -> Option<Want> {
    let s = s.trim().strip_prefix("bytes=")?.trim();
    if s.contains(',') {
        return None;
    }
    let (a, b) = s.split_once('-')?;
    let (a, b) = (a.trim(), b.trim());
    if a.is_empty() {
        return b.parse().ok().map(Want::Suffix);
    }
    let start: u64 = a.parse().ok()?;
    let end = if b.is_empty() {
        None
    } else {
        let e: u64 = b.parse().ok()?;
        if e < start {
            return None;
        }
        Some(e)
    };
    Some(Want::From(start, end))
}

/// Inclusive byte span for a request on a `len`-byte file. `Err(())` = 416.
pub fn resolve(want: Option<Want>, len: u64) -> std::result::Result<Option<(u64, u64)>, ()> {
    match want {
        None => Ok(None),
        Some(_) if len == 0 => Err(()),
        Some(Want::Suffix(0)) => Err(()),
        Some(Want::Suffix(n)) => Ok(Some((len.saturating_sub(n), len - 1))),
        Some(Want::From(s, _)) if s >= len => Err(()),
        Some(Want::From(s, e)) => Ok(Some((s, e.unwrap_or(len - 1).min(len - 1)))),
    }
}

fn not_satisfiable(stream: &mut TcpStream, len: u64, extra: &str) {
    let _ = write!(
        stream,
        "HTTP/1.1 416 Range Not Satisfiable\r\nContent-Range: bytes */{len}\r\nContent-Length: 0\r\n{extra}Connection: close\r\n\r\n"
    );
}

/// Write status + headers; returns the inclusive span to send (None = nothing to send).
fn head(
    stream: &mut TcpStream,
    mime: &str,
    want: Option<Want>,
    len: u64,
) -> Result<Option<(u64, u64)>> {
    let span = match resolve(want, len) {
        Err(()) => {
            not_satisfiable(stream, len, "");
            return Ok(None);
        }
        Ok(s) => s,
    };
    let hdr = match span {
        Some((s, e)) => format!(
            "HTTP/1.1 206 Partial Content\r\nAccept-Ranges: bytes\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nContent-Range: bytes {s}-{e}/{len}\r\nConnection: close\r\n\r\n",
            e - s + 1
        ),
        None => format!(
            "HTTP/1.1 200 OK\r\nAccept-Ranges: bytes\r\nContent-Type: {mime}\r\nContent-Length: {len}\r\nConnection: close\r\n\r\n"
        ),
    };
    stream.write_all(hdr.as_bytes()).map_err(err)?;
    Ok(match span {
        Some(s) => Some(s),
        None if len == 0 => None,
        None => Some((0, len - 1)),
    })
}

fn handle(mut stream: TcpStream, sh: &Shared) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    let mut reader = BufReader::new(stream.try_clone().map_err(err)?);
    let mut line = String::new();
    reader.read_line(&mut line).map_err(err)?;
    let req = line.clone();
    let mut want = None;
    loop {
        line.clear();
        if reader.read_line(&mut line).map_err(err)? == 0 || line.trim().is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("range:") {
            want = parse_range(rest);
        }
    }
    let mut parts = req.split_whitespace();
    let method = parts.next().unwrap_or("");
    let path = parts.next().unwrap_or("");
    if method != "GET" && method != "HEAD" {
        let _ = stream.write_all(
            b"HTTP/1.1 405 Method Not Allowed\r\nAllow: GET, HEAD\r\nContent-Length: 0\r\nConnection: close\r\n\r\n",
        );
        return Ok(());
    }
    let head_only = method == "HEAD";
    if path != "/play" && !path.starts_with("/play/") && !path.starts_with("/play?") {
        let body = b"sigil showing: the file is at /play\n";
        let _ = write!(
            stream,
            "HTTP/1.1 404 Not Found\r\nContent-Type: text/plain\r\nContent-Length: {}\r\nConnection: close\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(body);
        return Ok(());
    }
    if is_work_pack(&sh.mark) {
        return serve_work(&mut stream, sh, want, head_only);
    }

    let path = {
        let mut st = lock(&sh.stage);
        if !st.ready {
            println!("De-scribe to temp {} …", st.file.display());
            unseal_path(&sh.mark, &st.file, sh.pass.as_deref(), &[])?;
            st.ready = true;
            println!("ready ({})", st.file.display());
        }
        st.file.clone()
    };
    *lock(&sh.last) = Instant::now();
    // Open before the idle sweep can remove it; an open handle keeps reading on unix.
    let mut f = File::open(&path).map_err(err)?;
    let len = f.metadata().map_err(err)?.len();
    let Some((start, end)) = head(&mut stream, sh.mime, want, len)? else {
        return Ok(());
    };
    if head_only {
        return Ok(());
    }
    f.seek(SeekFrom::Start(start)).map_err(err)?;
    let mut left = end - start + 1;
    let mut buf = vec![0u8; 64 * 1024];
    while left > 0 {
        let n = left.min(buf.len() as u64) as usize;
        let got = f.read(&mut buf[..n]).map_err(err)?;
        if got == 0 {
            break;
        }
        if stream.write_all(&buf[..got]).is_err() {
            return Ok(()); // player hung up (seek / stop): normal
        }
        left -= got as u64;
        *lock(&sh.last) = Instant::now();
    }
    Ok(())
}

fn is_work_pack(mark: &Path) -> bool {
    let mut mag = [0u8; 4];
    File::open(mark)
        .and_then(|mut f| f.read_exact(&mut mag))
        .ok();
    mag == WORK_MAGIC
}

/// One unlocked slice (cached, at most [`STAR_CACHE`] kept; farthest from `idx` evicted).
fn star_bytes(sh: &Shared, loc: &StarLoc) -> Result<Vec<u8>> {
    let mut st = lock(&sh.stage);
    if let Some(b) = st.stars.get(&loc.index) {
        return Ok(b.clone());
    }
    println!("unlock slice {}", loc.index);
    let plain = unseal_star_at(&sh.mark, loc, sh.pass.as_deref(), &[])?;
    if plain.len() != loc.orig_len as usize {
        return Err(crate::Error::Msg(format!(
            "slice {} is {} bytes, the index said {}; refusing to serve shifted bytes",
            loc.index,
            plain.len(),
            loc.orig_len
        )));
    }
    while st.stars.len() >= STAR_CACHE {
        let far = st
            .stars
            .keys()
            .copied()
            .max_by_key(|k| k.abs_diff(loc.index));
        match far {
            Some(k) => {
                st.stars.remove(&k);
            }
            None => break,
        }
    }
    st.stars.insert(loc.index, plain.clone());
    Ok(plain)
}

fn serve_work(
    stream: &mut TcpStream,
    sh: &Shared,
    want: Option<Want>,
    head_only: bool,
) -> Result<()> {
    let (len, locs) = {
        let mut st = lock(&sh.stage);
        if st.work_len.is_none() {
            let (head, locs) =
                crate::work::index_pack_keys(&sh.mark, sh.pass.as_deref(), &[], &[])?;
            st.work_len = Some(head.orig_total);
            st.locs = locs;
            println!(
                "work pack: {} slices, {} bytes — unlocking only what the player reads",
                st.locs.len(),
                head.orig_total
            );
        }
        (st.work_len.unwrap_or(0), st.locs.clone())
    };
    // Every byte of the span must be in a slice we have, checked BEFORE any header,
    // so a half-copied pack never sends a body that stops early or lies.
    let span = match resolve(want, len) {
        Ok(Some(sp)) => Some(sp),
        Ok(None) if len > 0 => Some((0, len - 1)),
        _ => None,
    };
    if let Some((s, e)) = span {
        let mut cur = s;
        while cur <= e {
            match locs
                .iter()
                .find(|l| cur >= l.orig_off && cur < l.orig_off + u64::from(l.orig_len))
            {
                Some(l) => cur = l.orig_off + u64::from(l.orig_len),
                None => {
                    not_satisfiable(stream, len, "X-Sigil: overture-incomplete\r\n");
                    return Ok(());
                }
            }
        }
    }
    let Some((start, end)) = head(stream, sh.mime, want, len)? else {
        return Ok(());
    };
    if head_only {
        return Ok(());
    }
    let mut cur = start;
    while cur <= end {
        let Some(loc) = locs
            .iter()
            .find(|l| cur >= l.orig_off && cur < l.orig_off + u64::from(l.orig_len))
        else {
            break;
        };
        let plain = star_bytes(sh, loc)?;
        let inner = (cur - loc.orig_off) as usize;
        let take = ((end - cur + 1) as usize).min(plain.len().saturating_sub(inner));
        if take == 0 {
            break;
        }
        if stream.write_all(&plain[inner..inner + take]).is_err() {
            return Ok(()); // player hung up (seek / stop): normal
        }
        cur += take as u64;
        *lock(&sh.last) = Instant::now();
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ranges() {
        assert_eq!(parse_range("bytes=0-99"), Some(Want::From(0, Some(99))));
        assert_eq!(parse_range(" bytes=5-"), Some(Want::From(5, None)));
        assert_eq!(parse_range("bytes=-500"), Some(Want::Suffix(500)));
        assert_eq!(parse_range("bytes=0-1,5-6"), None);
        assert_eq!(parse_range("bytes=9-3"), None);
        assert_eq!(parse_range("items=0-1"), None);
        assert_eq!(resolve(None, 10), Ok(None));
        assert_eq!(resolve(Some(Want::Suffix(4)), 10), Ok(Some((6, 9))));
        assert_eq!(resolve(Some(Want::Suffix(40)), 10), Ok(Some((0, 9))));
        assert_eq!(resolve(Some(Want::Suffix(0)), 10), Err(()));
        assert_eq!(resolve(Some(Want::From(10, None)), 10), Err(()));
        assert_eq!(resolve(Some(Want::From(2, Some(99))), 10), Ok(Some((2, 9))));
    }

    #[test]
    fn mime() {
        assert_eq!(mime_for("Film.MKV"), "video/x-matroska");
        assert_eq!(mime_for("a.mp4"), "video/mp4");
        assert_eq!(mime_for("noext"), "application/octet-stream");
    }
}
