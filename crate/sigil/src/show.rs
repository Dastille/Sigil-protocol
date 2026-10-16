//! Showing: HTTP-range to Plex/Jellyfin. Work packs De-scribe only the slices asked for.

use crate::work::StarLoc;
use crate::{index_pack, payload_name, unseal_path, unseal_star_at, Result, WORK_MAGIC};
use std::collections::HashMap;
use std::fs::{self, File};
use std::io::{BufRead, BufReader, Read, Seek, SeekFrom, Write};
use std::net::{TcpListener, TcpStream};
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};
use std::time::{Duration, Instant};

struct Stage {
    file: PathBuf,
    ready: bool,
    work_len: Option<u64>,
    locs: Vec<StarLoc>,
    stars: HashMap<u32, Vec<u8>>,
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
    let name = payload_name(mark)?;
    let url = format!("{}/play", public_base.trim_end_matches('/'));
    if let Some(dir) = plex_dir {
        fs::create_dir_all(dir).map_err(|e| crate::Error::Msg(e.to_string()))?;
        let path = dir.join(strm_name(&name));
        fs::write(&path, format!("{url}\n")).map_err(|e| crate::Error::Msg(e.to_string()))?;
        println!("wrote Plex stub {}", path.display());
    }
    if let Some(path) = strm {
        if let Some(p) = path.parent() {
            fs::create_dir_all(p).map_err(|e| crate::Error::Msg(e.to_string()))?;
        }
        fs::write(path, format!("{url}\n")).map_err(|e| crate::Error::Msg(e.to_string()))?;
        println!("wrote {}", path.display());
    }
    let tmp = std::env::temp_dir().join(format!("sigil-showing-{}", std::process::id()));
    let _ = fs::remove_file(&tmp);
    let stage = Arc::new(Mutex::new(Stage {
        file: tmp.clone(),
        ready: false,
        work_len: None,
        locs: Vec::new(),
        stars: HashMap::new(),
    }));
    let last = Arc::new(Mutex::new(Instant::now()));
    let mark = mark.to_path_buf();
    let pass = pass.map(|s| s.to_string());

    let listener = TcpListener::bind(bind).map_err(|e| crate::Error::Msg(e.to_string()))?;
    listener
        .set_nonblocking(true)
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    println!("Showing on {bind} → {url}");
    println!("Plex/Jellyfin: Play the .strm. Work packs only unlock the slices the player reads (not the whole film first).");
    println!("Idle {idle_secs}s then the temp copy is deleted. Ctrl-C to stop. Local only.");

    let idle = Duration::from_secs(idle_secs.max(30));
    loop {
        match listener.accept() {
            Ok((stream, _)) => {
                *last
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
                if let Err(e) = handle(stream, &mark, pass.as_deref(), &stage, &last) {
                    eprintln!("showing: {e}");
                }
            }
            Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                let quiet = last
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .elapsed();
                if quiet > idle {
                    let mut st = stage
                        .lock()
                        .unwrap_or_else(std::sync::PoisonError::into_inner);
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
                std::thread::sleep(Duration::from_millis(200));
            }
            Err(e) => return Err(crate::Error::Msg(e.to_string())),
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

fn handle(
    mut stream: TcpStream,
    mark: &Path,
    pass: Option<&str>,
    stage: &Arc<Mutex<Stage>>,
    last: &Arc<Mutex<Instant>>,
) -> Result<()> {
    stream.set_read_timeout(Some(Duration::from_secs(30))).ok();
    let mut reader = BufReader::new(
        stream
            .try_clone()
            .map_err(|e| crate::Error::Msg(e.to_string()))?,
    );
    let mut line = String::new();
    reader
        .read_line(&mut line)
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    let mut range: Option<(u64, Option<u64>)> = None;
    let req = line.clone();
    loop {
        line.clear();
        reader
            .read_line(&mut line)
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        if line == "\r\n" || line == "\n" || line.is_empty() {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if let Some(rest) = lower.strip_prefix("range:") {
            range = parse_range(rest.trim());
        }
    }
    let get = req.starts_with("GET ") || req.starts_with("HEAD ");
    let head_only = req.starts_with("HEAD ");
    if !get {
        let _ = stream.write_all(b"HTTP/1.1 405 Method Not Allowed\r\nContent-Length: 0\r\n\r\n");
        return Ok(());
    }
    if !req.contains("/play") {
        let body = b"sigil showing\n";
        let _ = write!(
            stream,
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: {}\r\n\r\n",
            body.len()
        );
        let _ = stream.write_all(body);
        return Ok(());
    }

    if is_work_pack(mark) {
        return serve_work(&mut stream, mark, pass, stage, last, range, head_only);
    }

    let path = {
        let st = stage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if !st.ready {
            println!("De-scribe to temp {} …", st.file.display());
            drop(st);
            unseal_path(
                mark,
                &stage
                    .lock()
                    .unwrap_or_else(std::sync::PoisonError::into_inner)
                    .file,
                pass,
                &[],
            )?;
            let mut st = stage
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            st.ready = true;
            println!("ready ({})", st.file.display());
            st.file.clone()
        } else {
            st.file.clone()
        }
    };
    *last
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
    let meta = fs::metadata(&path).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let len = meta.len();
    let (start, end) = match range {
        Some((s, e)) => {
            let end = e
                .unwrap_or(len.saturating_sub(1))
                .min(len.saturating_sub(1));
            if s >= len {
                let _ = stream
                    .write_all(b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\n\r\n");
                return Ok(());
            }
            (s, end)
        }
        None => (0, len.saturating_sub(1)),
    };
    let chunk = end - start + 1;
    let status = if range.is_some() {
        "HTTP/1.1 206 Partial Content"
    } else {
        "HTTP/1.1 200 OK"
    };
    let hdr = format!(
        "{status}\r\nAccept-Ranges: bytes\r\nContent-Type: application/octet-stream\r\nContent-Length: {chunk}\r\nContent-Range: bytes {start}-{end}/{len}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(hdr.as_bytes())
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    if head_only {
        return Ok(());
    }
    let mut f = File::open(&path).map_err(|e| crate::Error::Msg(e.to_string()))?;
    f.seek(SeekFrom::Start(start))
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    let mut left = chunk;
    let mut buf = [0u8; 64 * 1024];
    while left > 0 {
        let n = left.min(buf.len() as u64) as usize;
        let got = f
            .read(&mut buf[..n])
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        if got == 0 {
            break;
        }
        stream
            .write_all(&buf[..got])
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        left -= got as u64;
        *last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
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

fn serve_work(
    stream: &mut TcpStream,
    mark: &Path,
    pass: Option<&str>,
    stage: &Arc<Mutex<Stage>>,
    last: &Arc<Mutex<Instant>>,
    range: Option<(u64, Option<u64>)>,
    head_only: bool,
) -> Result<()> {
    {
        let mut st = stage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner);
        if st.locs.is_empty() {
            let (head, locs) = index_pack(mark)?;
            st.work_len = Some(head.orig_total);
            st.locs = locs;
            println!(
                "work pack: {} slices, {} bytes — unlocking only what the player reads",
                st.locs.len(),
                head.orig_total
            );
        }
    }
    let len = stage
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .work_len
        .unwrap_or(0);
    let (start, end) = match range {
        Some((s, e)) => {
            let end = e
                .unwrap_or(len.saturating_sub(1))
                .min(len.saturating_sub(1));
            if s >= len {
                let _ = stream
                    .write_all(b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\n\r\n");
                return Ok(());
            }
            (s, end)
        }
        None => (0, len.saturating_sub(1)),
    };
    let chunk = end - start + 1;
    let status = if range.is_some() {
        "HTTP/1.1 206 Partial Content"
    } else {
        "HTTP/1.1 200 OK"
    };
    let hdr = format!(
        "{status}\r\nAccept-Ranges: bytes\r\nContent-Type: application/octet-stream\r\nContent-Length: {chunk}\r\nContent-Range: bytes {start}-{end}/{len}\r\nConnection: close\r\n\r\n"
    );
    stream
        .write_all(hdr.as_bytes())
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
    if head_only {
        return Ok(());
    }
    let locs = stage
        .lock()
        .unwrap_or_else(std::sync::PoisonError::into_inner)
        .locs
        .clone();
    let mut cur = start;
    while cur <= end {
        let loc = match locs
            .iter()
            .find(|l| cur >= l.orig_off && cur < l.orig_off + l.orig_len as u64)
        {
            Some(l) => l,
            None => {
                let _ = stream.write_all(
                    b"HTTP/1.1 416 Range Not Satisfiable\r\nContent-Length: 0\r\nX-Sigil: overture-incomplete\r\n\r\n",
                );
                return Ok(());
            }
        };
        {
            let mut st = stage
                .lock()
                .unwrap_or_else(std::sync::PoisonError::into_inner);
            if let std::collections::hash_map::Entry::Vacant(e) = st.stars.entry(loc.index) {
                println!("unlock slice {}", loc.index);
                let plain = unseal_star_at(mark, loc, pass, &[])?;
                e.insert(plain);
            }
        }
        let plain = stage
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner)
            .stars
            .get(&loc.index)
            .cloned()
            .unwrap_or_default();
        let inner = (cur - loc.orig_off) as usize;
        let take = ((end - cur + 1) as usize).min(plain.len().saturating_sub(inner));
        stream
            .write_all(&plain[inner..inner + take])
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
        cur += take as u64;
        *last
            .lock()
            .unwrap_or_else(std::sync::PoisonError::into_inner) = Instant::now();
        if take == 0 {
            break;
        }
    }
    Ok(())
}

fn parse_range(s: &str) -> Option<(u64, Option<u64>)> {
    let s = s.trim().strip_prefix("bytes=")?;
    let mut parts = s.splitn(2, '-');
    let a = parts.next()?.trim();
    let b = parts.next()?.trim();
    let start: u64 = a.parse().ok()?;
    let end = if b.is_empty() {
        None
    } else {
        Some(b.parse().ok()?)
    };
    Some((start, end))
}
