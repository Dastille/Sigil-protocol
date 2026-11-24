//! Privacy check for public files: fails `cargo test` when a text file in the
//! repository matches a rule in `scripts/privacy-denylist.txt` (format
//! documented there) or in the optional local file named by
//! `SIGIL_PRIVACY_DENY_EXTRA`.
//!
//! Text files are scanned line by line. PDFs are scanned through `pdftotext`
//! (poppler-utils); if it is missing the check fails and says so, unless
//! `SIGIL_PRIVACY_SKIP_PDF=1` is set, which skips PDFs with a printed warning.
//! JPEG and PNG files are scanned in their metadata segments (EXIF, XMP, ICC,
//! comments, text chunks), not their pixel data.

use std::fs;
use std::path::{Path, PathBuf};

#[derive(Default)]
struct Rules {
    deny: Vec<String>,
    allow: Vec<String>,
    allow_file: Vec<String>,
}

fn parse_rules(text: &str, rules: &mut Rules) {
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(t) = line.strip_prefix("deny ") {
            rules.deny.push(t.trim().to_lowercase());
        } else if let Some(t) = line.strip_prefix("allow ") {
            rules.allow.push(t.trim().to_string());
        } else if let Some(t) = line.strip_prefix("allow-file ") {
            rules.allow_file.push(t.trim().to_string());
        } else {
            panic!("privacy denylist: unknown rule line: {raw}");
        }
    }
}

fn repo_root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../..")
        .canonicalize()
        .unwrap()
}

fn load_rules() -> Rules {
    let mut rules = tracked_rules();
    if let Ok(extra) = std::env::var("SIGIL_PRIVACY_DENY_EXTRA") {
        if !extra.is_empty() {
            let text = fs::read_to_string(&extra).expect("read SIGIL_PRIVACY_DENY_EXTRA");
            parse_rules(&text, &mut rules);
        }
    }
    rules
}

fn is_word(c: u8) -> bool {
    c.is_ascii_alphanumeric() || c == b'_'
}

/// Case-insensitive search for `term` in `line`, whole-word at alphanumeric edges.
fn contains_term(line: &str, term: &str) -> bool {
    let hay = line.to_lowercase();
    let (h, t) = (hay.as_bytes(), term.as_bytes());
    if t.is_empty() || t.len() > h.len() {
        return false;
    }
    let mut start = 0;
    while let Some(off) = hay[start..].find(term) {
        let i = start + off;
        let before_ok = !is_word(t[0]) || i == 0 || !is_word(h[i - 1]);
        let j = i + t.len();
        let after_ok = !is_word(t[t.len() - 1]) || j == h.len() || !is_word(h[j]);
        if before_ok && after_ok {
            return true;
        }
        start = i + 1;
        while !hay.is_char_boundary(start) {
            start += 1;
        }
    }
    false
}

/// A UUID-shaped token (8-4-4-4-12 hex) anywhere in the line.
fn has_uuid(line: &str) -> bool {
    let b = line.as_bytes();
    let groups = [8, 4, 4, 4, 12];
    let total = 36;
    if b.len() < total {
        return false;
    }
    'outer: for s in 0..=b.len() - total {
        if s > 0 && b[s - 1].is_ascii_hexdigit() {
            continue;
        }
        let mut p = s;
        for (gi, g) in groups.iter().enumerate() {
            for _ in 0..*g {
                if !b[p].is_ascii_hexdigit() {
                    continue 'outer;
                }
                p += 1;
            }
            if gi < 4 {
                if b[p] != b'-' {
                    continue 'outer;
                }
                p += 1;
            }
        }
        if p == b.len() || !b[p].is_ascii_hexdigit() {
            return true;
        }
    }
    false
}

/// Blank out each allowed span (case-sensitive) so the rest of the line is still scanned.
fn mask_allowed(line: &str, rules: &Rules) -> String {
    let mut out = line.to_string();
    for a in &rules.allow {
        if !a.is_empty() {
            out = out.replace(a.as_str(), &" ".repeat(a.len()));
        }
    }
    out
}

fn scan_text(label: &str, text: &str, rules: &Rules, hits: &mut Vec<String>) {
    for (n, raw) in text.lines().enumerate() {
        let masked = mask_allowed(raw, rules);
        let line = masked.as_str();
        for term in &rules.deny {
            if contains_term(line, term) {
                hits.push(format!("{label}:{}: denied term {term:?}", n + 1));
            }
        }
        if line.to_lowercase().contains("machine") && has_uuid(line) {
            hits.push(format!("{label}:{}: machine id-shaped UUID", n + 1));
        }
    }
}

fn walk(dir: &Path, root: &Path, rules: &Rules, hits: &mut Vec<String>) {
    let mut entries: Vec<_> = fs::read_dir(dir).unwrap().flatten().collect();
    entries.sort_by_key(|e| e.path());
    for e in entries {
        let p = e.path();
        let name = e.file_name();
        let name = name.to_string_lossy();
        let ft = e.file_type().unwrap();
        if ft.is_symlink() || name == ".git" {
            continue; // `.git` is a folder, or a file in a worktree
        }
        if ft.is_dir() {
            if matches!(name.as_ref(), "target" | "node_modules") {
                continue;
            }
            walk(&p, root, rules, hits);
            continue;
        }
        let rel = p
            .strip_prefix(root)
            .unwrap_or(&p)
            .to_string_lossy()
            .replace('\\', "/");
        if rules.allow_file.contains(&rel) {
            continue;
        }
        let Ok(bytes) = fs::read(&p) else { continue };
        scan_bytes(&p, &rel, bytes, rules, hits);
    }
}

fn ext_of(p: &Path) -> String {
    p.extension()
        .map(|e| e.to_string_lossy().to_lowercase())
        .unwrap_or_default()
}

fn scan_bytes(p: &Path, label: &str, bytes: Vec<u8>, rules: &Rules, hits: &mut Vec<String>) {
    match ext_of(p).as_str() {
        "pdf" => scan_pdf(p, label, rules, hits),
        "jpg" | "jpeg" => scan_text(label, &printable_runs(&jpeg_metadata(&bytes)), rules, hits),
        "png" => scan_text(label, &printable_runs(&png_metadata(&bytes)), rules, hits),
        _ => {
            if bytes.contains(&0) {
                return; // other binary (test fixtures, fonts): not scanned
            }
            if let Ok(text) = String::from_utf8(bytes) {
                scan_text(label, &text, rules, hits);
            }
        }
    }
}

/// PDF text through `pdftotext`. Fails closed when the tool is missing.
fn scan_pdf(p: &Path, label: &str, rules: &Rules, hits: &mut Vec<String>) {
    if std::env::var("SIGIL_PRIVACY_SKIP_PDF").as_deref() == Ok("1") {
        eprintln!("privacy check: WARNING: SIGIL_PRIVACY_SKIP_PDF=1, not scanning {label}");
        return;
    }
    match std::process::Command::new("pdftotext")
        .args(["-q", "-enc", "UTF-8"])
        .arg(p)
        .arg("-")
        .output()
    {
        Ok(out) if out.status.success() => {
            scan_text(label, &String::from_utf8_lossy(&out.stdout), rules, hits);
            let meta = std::process::Command::new("pdfinfo").arg(p).output();
            if let Ok(m) = meta {
                scan_text(
                    &format!("{label} (metadata)"),
                    &String::from_utf8_lossy(&m.stdout),
                    rules,
                    hits,
                );
            }
        }
        Ok(out) => hits.push(format!(
            "{label}: pdftotext failed ({}); cannot check this PDF",
            out.status
        )),
        Err(e) => hits.push(format!(
            "{label}: cannot scan PDF text: pdftotext not found ({e}). Install poppler-utils, \
             or set SIGIL_PRIVACY_SKIP_PDF=1 to skip PDFs knowingly"
        )),
    }
}

/// Runs of 4+ printable ASCII bytes, one per line.
fn printable_runs(b: &[u8]) -> String {
    let mut out = String::new();
    let mut cur = String::new();
    for &c in b {
        if (0x20..0x7f).contains(&c) {
            cur.push(c as char);
        } else {
            if cur.len() >= 4 {
                out.push_str(&cur);
                out.push('\n');
            }
            cur.clear();
        }
    }
    if cur.len() >= 4 {
        out.push_str(&cur);
        out.push('\n');
    }
    out
}

/// JPEG APPn and COM segments before the image data (EXIF, XMP, ICC, comments).
fn jpeg_metadata(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if b.len() < 4 || b[0] != 0xFF || b[1] != 0xD8 {
        return b.to_vec(); // not a JPEG: scan everything
    }
    let mut i = 2;
    while i + 4 <= b.len() && b[i] == 0xFF {
        let marker = b[i + 1];
        if marker == 0xDA || marker == 0xD9 {
            break; // start of scan / end of image
        }
        let len = u16::from_be_bytes([b[i + 2], b[i + 3]]) as usize;
        let end = (i + 2 + len).min(b.len());
        if (0xE0..=0xEF).contains(&marker) || marker == 0xFE {
            out.extend_from_slice(&b[i + 4..end]);
            out.push(0);
        }
        i = end;
    }
    // Anything after the end-of-image marker is also metadata-like.
    if let Some(pos) = b.windows(2).rposition(|w| w == [0xFF, 0xD9]) {
        out.extend_from_slice(&b[pos + 2..]);
    }
    out
}

/// PNG chunks that are not image data (text, EXIF, ICC, time).
fn png_metadata(b: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    if b.len() < 8 || &b[..8] != b"\x89PNG\r\n\x1a\n" {
        return b.to_vec();
    }
    let mut i = 8;
    while i + 8 <= b.len() {
        let len = u32::from_be_bytes([b[i], b[i + 1], b[i + 2], b[i + 3]]) as usize;
        let kind = &b[i + 4..i + 8];
        let end = (i + 8 + len).min(b.len());
        if kind != b"IDAT" {
            out.extend_from_slice(&b[i + 8..end]);
            out.push(0);
        }
        i = end + 4;
    }
    out
}

fn scan_path(p: &Path, root: &Path, rules: &Rules, hits: &mut Vec<String>) {
    if p.is_dir() {
        walk(p, root, rules, hits);
    } else if let Ok(bytes) = fs::read(p) {
        scan_bytes(p, &p.to_string_lossy(), bytes, rules, hits);
    }
}

#[test]
fn public_files_carry_no_private_details() {
    let rules = load_rules();
    let root = repo_root();
    let mut hits = Vec::new();
    walk(&root, &root, &rules, &mut hits);
    if let Ok(extra) = std::env::var("SIGIL_PRIVACY_SCAN_EXTRA") {
        for p in extra.split(':').filter(|s| !s.is_empty()) {
            let p = Path::new(p);
            scan_path(p, p, &rules, &mut hits);
        }
    }
    assert!(
        hits.is_empty(),
        "privacy check failed ({} hit(s)); see scripts/privacy-denylist.txt:\n{}",
        hits.len(),
        hits.join("\n")
    );
}

fn tracked_rules() -> Rules {
    let mut rules = Rules::default();
    let path = repo_root().join("scripts/privacy-denylist.txt");
    parse_rules(
        &fs::read_to_string(&path).expect("read denylist"),
        &mut rules,
    );
    rules
}

fn scan_temp(files: &[(&str, String)], rules: &Rules) -> Vec<String> {
    let dir = std::env::temp_dir().join(format!(
        "sigil-privacy-{}-{}",
        std::process::id(),
        files.len()
    ));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    for (name, body) in files {
        fs::write(dir.join(name), body).unwrap();
    }
    let mut hits = Vec::new();
    walk(&dir, &dir, rules, &mut hits);
    fs::remove_dir_all(&dir).unwrap();
    hits
}

#[test]
fn planted_file_is_caught_and_clean_file_passes() {
    let rules = tracked_rules();
    // Built at run time so this source file itself stays clean.
    let home = ["/ho", "me/someone/"].concat();
    let ws = ["/work", "space/"].concat();
    let m = "machine";
    let id = "0a1b2c3d-0000-4000-8000-00000000abcd";
    let hits = scan_temp(
        &[
            ("home.md", format!("Archive at {home}backup.sigil\n")),
            ("ws.md", format!("Receipt in {ws}receipts\n")),
            ("id.md", format!("{m} {id}\n")),
            ("clean.md", "Archive at /home/me/backup.sigil\n".to_string()),
            (
                "mixed-home.md",
                format!("Example /home/me/x; real copy at {home}x\n"),
            ),
            ("mixed-ws.md", format!("Example /home/me/x and {ws}x\n")),
        ],
        &rules,
    );
    assert!(hits.iter().any(|h| h.starts_with("home.md:1:")), "{hits:?}");
    assert!(hits.iter().any(|h| h.starts_with("ws.md:1:")), "{hits:?}");
    assert!(hits.iter().any(|h| h.starts_with("id.md:1:")), "{hits:?}");
    assert!(!hits.iter().any(|h| h.starts_with("clean.md")), "{hits:?}");
    // An allowed placeholder exempts only itself, not the rest of the line.
    assert!(
        hits.iter().any(|h| h.starts_with("mixed-home.md:1:")),
        "{hits:?}"
    );
    assert!(
        hits.iter().any(|h| h.starts_with("mixed-ws.md:1:")),
        "{hits:?}"
    );
}

#[test]
fn image_metadata_is_scanned_but_pixels_are_not() {
    let rules = tracked_rules();
    let home = ["/ho", "me/someone/"].concat();
    // Minimal JPEG: SOI, COM segment with a path, SOS, "pixel" bytes, EOI.
    let mut leak = vec![0xFF, 0xD8, 0xFF, 0xFE];
    let com = format!("saved from {home}pic.jpg");
    leak.extend_from_slice(&((com.len() + 2) as u16).to_be_bytes());
    leak.extend_from_slice(com.as_bytes());
    leak.extend_from_slice(&[0xFF, 0xDA, 0x00, 0x02]);
    let mut pixels = vec![0xFF, 0xD8, 0xFF, 0xDA, 0x00, 0x02];
    pixels.extend_from_slice(home.as_bytes()); // inside image data: ignored
    pixels.extend_from_slice(&[0xFF, 0xD9]);
    leak.extend_from_slice(&[0xFF, 0xD9]);
    let dir = std::env::temp_dir().join(format!("sigil-privacy-img-{}", std::process::id()));
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    fs::write(dir.join("leak.jpg"), &leak).unwrap();
    fs::write(dir.join("pixels.jpg"), &pixels).unwrap();
    let mut hits = Vec::new();
    walk(&dir, &dir, &rules, &mut hits);
    fs::remove_dir_all(&dir).unwrap();
    assert!(hits.iter().any(|h| h.starts_with("leak.jpg:")), "{hits:?}");
    assert!(
        !hits.iter().any(|h| h.starts_with("pixels.jpg")),
        "{hits:?}"
    );
}

#[test]
fn extra_rules_add_terms_and_exemptions() {
    let mut rules = tracked_rules();
    parse_rules("deny examplehost\nallow credit: examplehost\n", &mut rules);
    let hits = scan_temp(
        &[
            ("a.md", "Timed on ExampleHost.\n".to_string()),
            ("b.md", "credit: examplehost\n".to_string()),
            (
                "d.md",
                "credit: examplehost, also examplehost\n".to_string(),
            ),
            ("c.md", "examplehosts is another word\n".to_string()),
        ],
        &rules,
    );
    assert!(hits.iter().any(|h| h.starts_with("a.md:1:")), "{hits:?}");
    assert!(!hits.iter().any(|h| h.starts_with("b.md")), "{hits:?}");
    assert!(hits.iter().any(|h| h.starts_with("d.md:1:")), "{hits:?}");
    assert!(!hits.iter().any(|h| h.starts_with("c.md")), "{hits:?}");
}

#[test]
fn word_edges() {
    let ws = ["/work", "space/"].concat();
    assert!(contains_term("on ExampleHost/Linux", "examplehost"));
    assert!(!contains_term("examplehosts", "examplehost"));
    assert!(contains_term(&format!("x {ws}receipts"), &ws));
    assert!(has_uuid("id 0a1b2c3d-0000-4000-8000-00000000abcd."));
    assert!(!has_uuid("0a1b2c3d-0000-4000-8000"));
}
