//! `sigil log ls --pretty` (and `sigil path LOG --pretty`): a segment log laid out like a
//! finding aid for archivists and backup techs, in the same gold/cream field slab as
//! [`super::render_path_view`]:
//!
//! 1. identity: log name, format, signed yes/no and the signer's key fingerprint;
//! 2. condition: healthy / needs repair / not recoverable, and which check produced it;
//! 3. extent: live files, tombstoned, excluded-kept, total size, segments;
//! 4. inventory: live files by folder, big folders collapsed to one line;
//! 5. one checksum: the current Merkle root.
//!
//! The renderer adds no facts of its own: every line comes from a [`LogPage`] the caller
//! filled from the INDEX, HEAD and a [`crate::seglog::CheckReport`].

use std::collections::BTreeMap;

use super::{human_bytes, Health, Style, KEY_W, SLAB_MIN};
use crate::seglog::{LiveFile, LiveSet};

/// Folders holding more files than this (in total, subfolders included) collapse to one line
/// unless expanded.
pub const COLLAPSE_OVER: usize = 12;

/// How deep the condition check went.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CheckDepth {
    /// INDEX chain, HEAD and segment presence only; no segment bytes read.
    Fast,
    /// Every needed segment read and checked bit for bit (`sigil log verify`).
    Deep,
}

/// Everything the log page shows.
#[derive(Clone, Debug)]
pub struct LogPage {
    /// Log name (folder name, e.g. `photos.sigil`).
    pub name: String,
    /// Where the log lives (its folder), shown as the page title.
    pub location: String,
    /// `log=N` of the manifest.
    pub format: u32,
    /// HEAD carries a signature.
    pub signed: bool,
    /// The key that signed HEAD (or the pinned signer when HEAD is unsigned).
    pub signer: Option<[u8; 32]>,
    /// `Some(opened)` for a private INDEX.
    pub private_index: Option<bool>,
    /// The log seals every segment under its own key.
    pub segment_keys: bool,
    /// Condition, when a check ran.
    pub health: Option<Health>,
    /// Which check produced [`LogPage::health`].
    pub depth: CheckDepth,
    /// Segment files the check found present (fast) or read (deep).
    pub checked: usize,
    /// The live file set.
    pub live: LiveSet,
    /// Live files an exclude rule matches (`None`: no rules were given).
    pub excluded_kept: Option<usize>,
    /// INDEX entries (segments, tombstones and other records).
    pub entries: usize,
    /// HEAD's seq and Merkle root.
    pub root: Option<(u64, [u8; 32])>,
    /// Folders to list in full (paths relative to the log's source, no trailing `/` needed).
    pub expand: Vec<String>,
    /// Show the N most recently added live files.
    pub recent: usize,
}

/// Thousands separators: `6765` → `6,765`.
pub fn group(n: usize) -> String {
    let s = n.to_string();
    let mut out = String::new();
    for (i, c) in s.chars().enumerate() {
        if i > 0 && (s.len() - i) % 3 == 0 {
            out.push(',');
        }
        out.push(c);
    }
    out
}

fn plural(n: usize, one: &str, many: &str) -> String {
    format!("{} {}", group(n), if n == 1 { one } else { many })
}

#[derive(Default)]
struct Dir<'a> {
    dirs: BTreeMap<&'a str, Dir<'a>>,
    files: Vec<(&'a str, &'a LiveFile)>,
    count: usize,
    bytes: u64,
}

fn build<'a>(files: &'a [LiveFile]) -> Dir<'a> {
    let mut root = Dir::default();
    for f in files {
        let mut parts: Vec<&str> = f.path.split('/').filter(|p| !p.is_empty()).collect();
        let Some(leaf) = parts.pop() else { continue };
        let mut cur = &mut root;
        cur.count += 1;
        cur.bytes += f.size;
        for p in parts {
            cur = cur.dirs.entry(p).or_default();
            cur.count += 1;
            cur.bytes += f.size;
        }
        cur.files.push((leaf, f));
    }
    root
}

/// One inventory row: indented name, right-hand facts, folder?
type Row = (String, String, bool);

fn rows(d: &Dir<'_>, prefix: &str, depth: usize, expand: &[String], out: &mut Vec<Row>) {
    let pad = "  ".repeat(depth);
    for (name, child) in &d.dirs {
        let full = format!("{prefix}{name}");
        let slash = format!("{full}/");
        let open_all = expand.iter().any(|e| slash.starts_with(e.as_str()));
        let on_path = expand.iter().any(|e| e.starts_with(&slash));
        let facts = format!(
            "{}  {}",
            plural(child.count, "file", "files"),
            human_bytes(child.bytes)
        );
        out.push((format!("{pad}{name}/"), facts, true));
        if open_all || on_path || child.count <= COLLAPSE_OVER {
            let sub_expand: Vec<String> = if open_all {
                vec![String::new()]
            } else {
                expand.to_vec()
            };
            rows(child, &format!("{full}/"), depth + 1, &sub_expand, out);
        }
    }
    for (leaf, f) in &d.files {
        out.push((format!("{pad}{leaf}"), human_bytes(f.size), false));
    }
}

/// Does any live file sit under folder `dir`?
pub fn has_folder(files: &[LiveFile], dir: &str) -> bool {
    let d = format!("{}/", dir.trim_end_matches('/'));
    files.iter().any(|f| f.path.starts_with(&d))
}

/// Render the log page (see the module docs). Plain text when `st.color` is off.
pub fn render_log_page(p: &LogPage, st: &Style) -> String {
    let (rule_ch, sep) = if st.unicode {
        ("─", " · ")
    } else {
        ("-", ", ")
    };
    let mut fields: Vec<(String, String)> = Vec::new(); // (plain, styled)
    let mut add = |k: &str, v: &str, vs: String| {
        fields.push((
            format!("{k:<KEY_W$}{v}"),
            format!("{}{vs}", st.gold(&format!("{k:<KEY_W$}"))),
        ));
    };

    // 1. Identity.
    add("LOG", &p.name, p.name.clone());
    let mut fmt = format!("segment log, format {}", p.format);
    match p.private_index {
        Some(true) => fmt.push_str(&format!("{sep}private index (opened)")),
        Some(false) => fmt.push_str(&format!("{sep}private index (sealed)")),
        None => {}
    }
    if p.segment_keys {
        fmt.push_str(&format!("{sep}per-segment keys"));
    }
    add("FORMAT", &fmt, fmt.clone());
    let fp = |k: &[u8; 32]| {
        let h = hex::encode(k);
        h[..16].to_string()
    };
    match (p.signed, p.signer) {
        (true, Some(k)) => {
            let v = format!("yes, by key {}", fp(&k));
            add("SIGNED", &v, v.clone());
        }
        (false, Some(k)) => {
            let v = format!("NO (signer {} pinned, HEAD unsigned)", fp(&k));
            add("SIGNED", &v, st.paint("31", &v));
        }
        (true, None) => add("SIGNED", "yes", "yes".into()),
        (false, None) => add("SIGNED", "no", st.dim("no")),
    }

    // 2. Condition.
    let how = match p.depth {
        CheckDepth::Fast => format!(
            "fast check: chain, HEAD, {} present",
            plural(p.checked, "segment", "segments")
        ),
        CheckDepth::Deep => format!(
            "deep check: {} read bit for bit",
            plural(p.checked, "segment", "segments")
        ),
    };
    match &p.health {
        Some(Health::Healthy) => add(
            "STATUS",
            "healthy",
            st.paint("32", "healthy"),
        ),
        Some(Health::NeedsRepair(what)) => {
            add("STATUS", "needs repair", st.paint("33", "needs repair"));
            add("", what, st.dim(what));
        }
        Some(Health::NotRecoverable(why)) => {
            add("STATUS", "not recoverable", st.paint("31", "not recoverable"));
            add("", why, st.dim(why));
        }
        None => {
            let v = "not checked";
            add("STATUS", v, st.dim(v));
        }
    }
    if p.health.is_some() {
        add("", &how, st.dim(&how));
    }
    if p.depth == CheckDepth::Fast {
        let v = "deep check NOT run (add --deep, or sigil log verify)";
        add("", v, st.dim(v));
    }

    // 3. Extent.
    let l = &p.live;
    let mut files = plural(l.files.len(), "live file", "live files");
    files.push_str(&format!("{sep}{} tombstoned", group(l.tombstoned_files)));
    if let Some(n) = p.excluded_kept {
        files.push_str(&format!("{sep}{} excluded-kept", group(n)));
    }
    add("FILES", &files, files.clone());
    if l.sealed > 0 {
        let v = format!(
            "{} sealed (private index: give --pass / --identity)",
            plural(l.sealed, "entry", "entries")
        );
        add("", &v, st.dim(&v));
    }
    let mut size = human_bytes(l.live_bytes());
    if l.sealed > 0 {
        size.push_str(" (sealed entries not counted)");
    }
    add("SIZE", &size, size.clone());
    let mut segs = plural(p.entries, "entry", "entries");
    if l.older_versions > 0 {
        segs.push_str(&format!(
            "{sep}{}",
            plural(l.older_versions, "older version", "older versions")
        ));
    }
    if l.tombstoned_segments > 0 {
        segs.push_str(&format!(
            "{sep}{} deleted",
            group(l.tombstoned_segments)
        ));
    }
    add("SEGMENTS", &segs, segs.clone());

    // 4. Inventory.
    let tree = build(&l.files);
    let expand: Vec<String> = p
        .expand
        .iter()
        .map(|e| format!("{}/", e.trim_matches('/')))
        .collect();
    let mut inv: Vec<Row> = Vec::new();
    rows(&tree, "", 0, &expand, &mut inv);
    if l.unnamed.0 > 0 {
        inv.push((
            "(unnamed segments)".into(),
            format!(
                "{}  {}",
                plural(l.unnamed.0, "segment", "segments"),
                human_bytes(l.unnamed.1)
            ),
            true,
        ));
    }
    let mut recent: Vec<Row> = Vec::new();
    if p.recent > 0 {
        let mut by_seq: Vec<&LiveFile> = l.files.iter().collect();
        by_seq.sort_by_key(|f| std::cmp::Reverse(f.seq));
        for f in by_seq.into_iter().take(p.recent) {
            recent.push((
                f.path.clone(),
                format!(
                    "{}  {}",
                    crate::seglog::iso_utc(f.time),
                    human_bytes(f.size)
                ),
                false,
            ));
        }
    }

    // 5. Checksum.
    let root = p.root.map(|(_, r)| hex::encode(r));

    // Layout.
    let wd = |s: &str| s.chars().count();
    let mut width = SLAB_MIN.max(wd(&p.location));
    for (plain, _) in &fields {
        width = width.max(wd(plain));
    }
    for (n, f, _) in inv.iter().chain(&recent) {
        width = width.max(wd(n) + 2 + wd(f));
    }
    if let Some(r) = &root {
        width = width.max(KEY_W + wd(r));
    }
    let m = "  ";
    let rule = format!("{m}{}", st.dim(&rule_ch.repeat(width)));
    let mut out = vec![format!("{m}{}", st.bold(&p.location)), rule.clone()];
    out.extend(fields.iter().map(|(_, s)| format!("{m}{s}")));
    let row = |(n, f, is_dir): &Row| {
        let gap = width.saturating_sub(wd(n) + wd(f));
        let name = if *is_dir { st.bold(n) } else { n.clone() };
        format!("{m}{name}{}{}", " ".repeat(gap), st.dim(f))
    };
    out.push(rule.clone());
    if inv.is_empty() {
        let v = if l.sealed > 0 {
            "names sealed (give --pass / --identity)"
        } else {
            "no live files"
        };
        out.push(format!("{m}{}", st.dim(v)));
    } else {
        out.extend(inv.iter().map(row));
    }
    if !recent.is_empty() {
        out.push(rule.clone());
        out.push(format!(
            "{m}{}",
            st.gold(&format!("RECENT {} (newest first, UTC)", recent.len()))
        ));
        out.extend(recent.iter().map(row));
    }
    out.push(rule);
    match root {
        Some(r) => out.push(format!("{m}{}{r}", st.gold(&format!("{:<KEY_W$}", "ROOT")))),
        None => {
            let v = "none (no HEAD yet)";
            out.push(format!(
                "{m}{}{}",
                st.gold(&format!("{:<KEY_W$}", "ROOT")),
                st.dim(v)
            ));
        }
    }
    out.iter()
        .map(|l| l.trim_end())
        .collect::<Vec<_>>()
        .join("\n")
}

/// Condition from a log check's findings: any error a `sigil log mend` hint covers means
/// needs repair, any other error means not recoverable from this copy; warnings (left-over
/// files, a lagging HEAD) read as needs repair with the first one named.
pub fn health_from_findings(findings: &[crate::doctor::Finding], arg: &str) -> Health {
    use crate::doctor::Severity;
    let errs: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Error)
        .collect();
    let mendable = |f: &&crate::doctor::Finding| {
        f.hint
            .as_deref()
            .is_some_and(|h| h.starts_with("sigil log mend"))
    };
    if let Some(bad) = errs.iter().find(|f| !mendable(f)) {
        return Health::NotRecoverable(format!(
            "{}: {} ({} problem(s); see sigil log verify {arg})",
            bad.subject,
            bad.message,
            errs.len()
        ));
    }
    let warns: Vec<_> = findings
        .iter()
        .filter(|f| f.severity == Severity::Warn)
        .collect();
    if !errs.is_empty() || !warns.is_empty() {
        let first = errs.first().or(warns.first());
        let what = first.map_or(String::new(), |f| f.message.clone());
        let n = errs.len() + warns.len();
        let run = if errs.iter().chain(&warns).any(mendable) {
            format!("run: sigil log mend {arg}")
        } else {
            format!("see: sigil log verify {arg}")
        };
        return Health::NeedsRepair(format!("{what} ({n} finding(s)); {run}"));
    }
    Health::Healthy
}

/// What to show beyond the defaults (`sigil log ls --pretty` options).
#[derive(Clone, Default)]
pub struct PageOpts<'a> {
    /// Passphrase that opens a private INDEX.
    pub pass: Option<&'a str>,
    /// Identities that open a private INDEX.
    pub identities: &'a [crate::keys::Identity],
    /// Run the full bit-level check (`sigil log verify`) instead of the fast one.
    pub deep: bool,
    /// Folders to list in full.
    pub expand: Vec<String>,
    /// Show the N most recently added live files.
    pub recent: usize,
    /// Exclude patterns (as given to `log add --exclude`) for the excluded-kept count.
    pub exclude: Vec<String>,
}

/// Gather a [`LogPage`] for the log at `path`: one INDEX read, one directory scan, and the
/// fast check (or the deep one with `deep`). Read-only.
pub fn log_page(path: &std::path::Path, o: &PageOpts<'_>) -> crate::Result<LogPage> {
    use crate::seglog;
    let l = seglog::list_with(path, o.pass, o.identities)?;
    let live = seglog::live_files(&l);
    for e in &o.expand {
        if !has_folder(&live.files, e) {
            return Err(crate::Error::Msg(format!(
                "no folder {:?} among the live files (folders are paths inside the backed-up folder, e.g. posts)",
                e.trim_end_matches('/')
            )));
        }
    }
    let excluded_kept = if o.exclude.is_empty() {
        None
    } else {
        let ex = seglog::Excluder::new(&o.exclude, std::path::Path::new("."), false)
            .map_err(crate::Error::Msg)?;
        Some(seglog::excluded_kept(&live, &ex))
    };
    let copts = seglog::CheckOpts {
        pass: o.pass,
        identities: o.identities,
        quick: false,
        ..Default::default()
    };
    let rep = if o.deep {
        seglog::check(path, &copts)?
    } else {
        seglog::check_fast(path, &copts)?
    };
    let checked = if o.deep {
        rep.verified
    } else {
        l.entries
            .iter()
            .zip(&l.present)
            .filter(|(e, p)| **p && l.state.slot(e.seq) == seglog::Slot::Needed)
            .count()
    };
    let head = l.head.as_ref();
    let name = l
        .log
        .dir
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| l.log.dir.display().to_string());
    Ok(LogPage {
        name,
        location: std::fs::canonicalize(&l.log.dir)
            .unwrap_or_else(|_| l.log.dir.clone())
            .display()
            .to_string(),
        format: l.log.format,
        signed: head.is_some_and(|h| h.sig.is_some()),
        signer: head.and_then(|h| h.signer).or(l.log.signer),
        private_index: l.log.privindex.then(|| l.log.index_readable()),
        segment_keys: l.log.segkeys,
        health: Some(health_from_findings(&rep.findings, &path.display().to_string())),
        depth: if o.deep { CheckDepth::Deep } else { CheckDepth::Fast },
        checked,
        entries: l.entries.len(),
        root: head.map(|h| (h.seq, h.root)),
        live,
        excluded_kept,
        expand: o.expand.clone(),
        recent: o.recent,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    const ASCII: Style = Style {
        color: false,
        unicode: false,
    };
    const UNI: Style = Style {
        color: false,
        unicode: true,
    };

    fn lf(path: &str, size: u64, seq: u64) -> LiveFile {
        LiveFile {
            path: path.into(),
            size,
            seq,
            time: 1_794_810_295 + seq,
            older: 0,
        }
    }

    fn page(files: Vec<LiveFile>) -> LogPage {
        LogPage {
            name: "ig.sigil".into(),
            location: "/backups/ig.sigil".into(),
            format: 1,
            signed: true,
            signer: Some([0xb9; 32]),
            private_index: None,
            segment_keys: false,
            health: Some(Health::Healthy),
            depth: CheckDepth::Fast,
            checked: files.len(),
            entries: files.len(),
            live: LiveSet {
                files,
                ..Default::default()
            },
            excluded_kept: None,
            root: Some((3, [0xfe; 32])),
            expand: Vec::new(),
            recent: 0,
        }
    }

    fn big() -> Vec<LiveFile> {
        let mut v: Vec<LiveFile> = (0..30)
            .map(|i| lf(&format!("posts/p{i:02}.jpg"), 1024 * 1024, i + 1))
            .collect();
        v.push(lf("metadata/inventory.json", 2048, 31));
        v.push(lf("README.txt", 10, 32));
        v.sort_by(|a, b| a.path.cmp(&b.path));
        v
    }

    #[test]
    fn order_and_collapse() {
        let s = render_log_page(&page(big()), &UNI);
        let lines: Vec<&str> = s.lines().collect();
        assert_eq!(lines[0], "  /backups/ig.sigil", "{s}");
        let pos = |k: &str| s.find(k).unwrap_or_else(|| panic!("{k} missing: {s}"));
        // identity → condition → extent → inventory → checksum
        assert!(pos("LOG ") < pos("FORMAT"));
        assert!(pos("FORMAT") < pos("SIGNED"));
        assert!(pos("SIGNED") < pos("STATUS"));
        assert!(pos("STATUS") < pos("FILES"));
        assert!(pos("FILES") < pos("SIZE"));
        assert!(pos("SIZE") < pos("SEGMENTS"));
        assert!(pos("SEGMENTS") < pos("posts/"));
        assert!(pos("posts/") < pos("ROOT"));
        assert!(s.contains("SIGNED    yes, by key b9b9b9b9b9b9b9b9"), "{s}");
        assert!(s.contains("STATUS    healthy\n"), "{s}");
        assert!(s.contains("deep check NOT run"), "{s}");
        assert!(s.contains("FILES     32 live files · 0 tombstoned"), "{s}");
        // big folder collapsed to one line, small folder listed
        assert!(s.contains("posts/"), "{s}");
        assert!(s.contains("30 files  30.0 MiB"), "{s}");
        assert!(!s.contains("p00.jpg"), "collapsed: {s}");
        assert!(s.contains("  inventory.json"), "{s}");
        assert!(s.contains(&format!("ROOT      {}", "fe".repeat(32))), "{s}");
        // no hexdumps, no row numbers, no banners
        assert!(!s.contains("0000:"), "{s}");
        assert!(!s.contains("==="), "{s}");
        assert_eq!(s.matches("ROOT").count(), 1, "{s}");
    }

    #[test]
    fn expand_and_recent() {
        let mut p = page(big());
        p.expand = vec!["posts".into()];
        p.recent = 2;
        let s = render_log_page(&p, &ASCII);
        assert!(s.contains("  p00.jpg"), "{s}");
        assert!(s.contains("  p29.jpg"), "{s}");
        assert!(s.contains("RECENT 2 (newest first, UTC)"), "{s}");
        let r = s.find("RECENT").unwrap_or(0);
        assert!(s[r..].find("README.txt") < s[r..].find("metadata/inventory.json"), "{s}");
        assert!(s.is_ascii(), "SIGIL_ASCII: {s}");
    }

    #[test]
    fn empty_log() {
        let mut p = page(Vec::new());
        p.root = None;
        p.signed = false;
        p.signer = None;
        let s = render_log_page(&p, &UNI);
        assert!(s.contains("FILES     0 live files · 0 tombstoned"), "{s}");
        assert!(s.contains("no live files"), "{s}");
        assert!(s.contains("ROOT      none (no HEAD yet)"), "{s}");
        assert!(s.contains("SIGNED    no"), "{s}");
    }

    #[test]
    fn tombstoned_unnamed_sealed_and_excluded() {
        let mut p = page(vec![lf("a.txt", 5, 1)]);
        p.live.tombstoned_files = 1;
        p.live.tombstoned_segments = 1;
        p.live.unnamed = (3, 3 * 1024);
        p.live.sealed = 2;
        p.excluded_kept = Some(4);
        p.private_index = Some(false);
        let s = render_log_page(&p, &UNI);
        assert!(s.contains("1 live file · 1 tombstoned · 4 excluded-kept"), "{s}");
        assert!(s.contains("(unnamed segments)"), "{s}");
        assert!(s.contains("3 segments  3.0 KiB"), "{s}");
        assert!(s.contains("2 entries sealed (private index"), "{s}");
        assert!(s.contains("private index (sealed)"), "{s}");
        assert!(s.contains("1 deleted"), "{s}");
    }

    #[test]
    fn color_only_when_asked() {
        let plain = render_log_page(&page(big()), &UNI);
        assert!(!plain.contains('\x1b'), "{plain}");
        let c = Style {
            color: true,
            unicode: true,
        };
        let s = render_log_page(&page(big()), &c);
        assert!(s.contains("\x1b[38;5;179mLOG"), "gold labels: {s}");
        assert!(s.contains("\x1b[32mhealthy"), "{s}");
    }

    #[test]
    fn findings_to_health() {
        use crate::doctor::{Finding, Severity};
        let f = |sev, hint: Option<&str>| Finding {
            severity: sev,
            code: "x",
            subject: "segments/0000/1.sg1".into(),
            message: "m".into(),
            hint: hint.map(String::from),
        };
        assert_eq!(health_from_findings(&[], "L"), Health::Healthy);
        assert!(matches!(
            health_from_findings(&[f(Severity::Warn, Some("sigil log mend PATH"))], "L"),
            Health::NeedsRepair(_)
        ));
        assert!(matches!(
            health_from_findings(&[f(Severity::Error, None)], "L"),
            Health::NotRecoverable(_)
        ));
        assert_eq!(
            health_from_findings(&[f(Severity::Info, None)], "L"),
            Health::Healthy
        );
    }

    #[test]
    fn groups() {
        assert_eq!(group(6765), "6,765");
        assert_eq!(group(999), "999");
        assert_eq!(group(1_000_000), "1,000,000");
    }
}
