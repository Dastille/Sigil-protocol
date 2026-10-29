//! Human inspect view for `sigil path --pretty`, laid out like a finding aid:
//! identity → condition → extent → inventory → identifier.
//!
//! Plain output ([`crate::PathView::format`]) stays the stable, script-friendly default.
//! This renderer adds no facts of its own: every line comes from the [`PathView`], from a
//! Scry verdict the caller already computed, or from the outer file's SHA-256 that
//! `sigil path` hashes anyway.

use crate::nest::{NestKind, PathView};
use std::collections::BTreeMap;

/// How [`render_path_view`] should style text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Style {
    /// Emit ANSI SGR codes (brand gold labels, dim rules, green/yellow/red status).
    pub color: bool,
    /// Use Unicode rules and separators; `false` gives pure ASCII.
    pub unicode: bool,
}

impl Style {
    /// Decide from the environment: color when stdout is a terminal and `NO_COLOR`
    /// is unset, or whenever `CLICOLOR_FORCE` is set to a non-`0` value.
    /// `SIGIL_ASCII=1` switches to pure ASCII.
    pub fn from_env(stdout_is_tty: bool) -> Self {
        let on = |k: &str| {
            std::env::var(k)
                .map(|v| !v.is_empty() && v != "0")
                .unwrap_or(false)
        };
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        Style {
            color: on("CLICOLOR_FORCE") || (stdout_is_tty && !no_color),
            unicode: !on("SIGIL_ASCII"),
        }
    }

    fn paint(&self, code: &str, s: &str) -> String {
        if self.color && !s.is_empty() {
            format!("\x1b[{code}m{s}\x1b[0m")
        } else {
            s.to_string()
        }
    }
    fn bold(&self, s: &str) -> String {
        self.paint("1", s)
    }
    fn dim(&self, s: &str) -> String {
        self.paint("2", s)
    }
    /// Brand gold (`#c29965`) for field labels: 256-color 179.
    fn gold(&self, s: &str) -> String {
        self.paint("38;5;179", s)
    }
}

/// Condition of a mark or folder pack, from an existing Scry verdict.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Health {
    /// Every piece checked is intact.
    Healthy,
    /// Damaged but repairable with `sigil mend`; the string says what is damaged.
    NeedsRepair(String),
    /// Too few intact pieces left; the string is Scry's reason.
    NotRecoverable(String),
}

/// Pieces of a single-file mark, read from its Scry line (`live=16/16 need=12`).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Pieces {
    /// Intact pieces found.
    pub live: u32,
    /// Pieces written.
    pub total: u32,
    /// Pieces needed to restore.
    pub need: u32,
}

fn field<'a>(line: &'a str, key: &str) -> Option<&'a str> {
    line.split_whitespace()
        .find_map(|w| w.strip_prefix(key).and_then(|r| r.strip_prefix('=')))
}

/// Piece counts from a single-file Scry line, when present.
pub fn pieces_from_scry(line: &str) -> Option<Pieces> {
    let (live, total) = field(line, "live")?.split_once('/')?;
    Some(Pieces {
        live: live.parse().ok()?,
        total: total.parse().ok()?,
        need: field(line, "need")?.parse().ok()?,
    })
}

/// Health of a single-file mark from [`crate::scry_path_checked`] output.
/// Returns `None` when the line is not a single-file report (e.g. a work pack).
pub fn health_from_mark_scry(line: &str, bad: Option<&str>) -> Option<Health> {
    if let Some(why) = bad {
        return Some(Health::NotRecoverable(why.to_string()));
    }
    if !line.starts_with("ok") {
        return None;
    }
    let mut hurt = Vec::new();
    if let Some(p) = pieces_from_scry(line) {
        if p.live < p.total {
            hurt.push(format!("{} of {} pieces lost", p.total - p.live, p.total));
        }
    }
    if field(line, "merkle").is_some_and(|m| m != "closed") {
        hurt.push("merkle tree open".to_string());
    }
    if field(line, "keystone").is_some_and(|k| k != "intact") {
        hurt.push("keystone damaged".to_string());
    }
    Some(if hurt.is_empty() {
        Health::Healthy
    } else {
        Health::NeedsRepair(hurt.join(", "))
    })
}

/// Health of a folder pack from [`crate::scry_dir_checked`] output.
pub fn health_from_dir_scry(text: &str, bad: Option<&str>) -> Health {
    if let Some(why) = bad {
        return Health::NotRecoverable(why.to_string());
    }
    match text.lines().find_map(|l| l.strip_prefix("needs mend: ")) {
        Some(rest) => {
            let what = rest.split(" (").next().unwrap_or(rest);
            Health::NeedsRepair(what.to_string())
        }
        None => Health::Healthy,
    }
}

/// Facts beyond the [`PathView`] that the caller already computed.
#[derive(Clone, Debug, Default)]
pub struct Extra<'a> {
    /// Condition, when a Scry verdict was run.
    pub health: Option<Health>,
    /// Single-file Scry line (`ok  v2  live=… need=… orig=…`), for extent and repair budget.
    pub scry_line: Option<&'a str>,
}

/// Human byte size: `5 B`, `1.2 KiB`, `3.4 MiB`, …
pub fn human_bytes(n: u64) -> String {
    const UNITS: [&str; 5] = ["KiB", "MiB", "GiB", "TiB", "PiB"];
    if n < 1024 {
        return format!("{n} B");
    }
    let mut v = n as f64 / 1024.0;
    let mut i = 0;
    while v >= 1024.0 && i + 1 < UNITS.len() {
        v /= 1024.0;
        i += 1;
    }
    format!("{v:.1} {}", UNITS[i])
}

#[derive(Default)]
struct Node {
    dirs: BTreeMap<String, Node>,
    files: Vec<(String, Option<u64>, bool)>,
}

fn build_tree(view: &PathView) -> Node {
    let mut root = Node::default();
    for e in &view.entries {
        let mut parts: Vec<&str> = e.path.split('/').filter(|p| !p.is_empty()).collect();
        let Some(leaf) = parts.pop() else { continue };
        let mut cur = &mut root;
        for p in parts {
            cur = cur.dirs.entry(p.to_string()).or_default();
        }
        cur.files.push((leaf.to_string(), e.orig, e.nest));
    }
    root
}

fn count_dirs(n: &Node) -> usize {
    n.dirs.values().map(|c| 1 + count_dirs(c)).sum()
}

/// Inventory rows: (indented name, is directory, nested seal?, size).
fn tree_rows(node: &Node, depth: usize, out: &mut Vec<(String, bool, bool, String)>) {
    let pad = "  ".repeat(depth);
    for (name, child) in &node.dirs {
        out.push((format!("{pad}{name}/"), true, false, String::new()));
        tree_rows(child, depth + 1, out);
    }
    for (name, size, nest) in &node.files {
        let s = size.map(human_bytes).unwrap_or_default();
        out.push((format!("{pad}{name}"), false, *nest, s));
    }
}

/// Narrowest slab (columns after the 2-space margin): phone-safe.
pub const SLAB_MIN: usize = 38;
const KEY_W: usize = 10;

fn w(s: &str) -> usize {
    s.chars().count()
}

/// One field line: plain text (for width) and styled text.
struct Line {
    plain: String,
    styled: String,
}

fn kind_label(k: &NestKind) -> &'static str {
    match k {
        NestKind::DirPack => "folder pack",
        NestKind::Mark => "sealed file",
        NestKind::Work => "large-file pack",
        NestKind::Leaf => "file inside a pack",
    }
}

/// Render a [`PathView`] as a branded field slab: identity, condition, extent,
/// inventory, then a one-line SHA-256 of the outer file (top level only).
pub fn render_path_view(view: &PathView, extra: &Extra<'_>, st: &Style) -> String {
    let (rule_ch, sep, crumb, ell) = if st.unicode {
        ("─", " · ", " → ", "…")
    } else {
        ("-", ", ", " > ", "...")
    };
    let mut fields: Vec<Line> = Vec::new();
    let mut add = |k: &str, v: &str, vs: String| {
        fields.push(Line {
            plain: format!("{k:<KEY_W$}{v}"),
            styled: format!("{}{vs}", st.gold(&format!("{k:<KEY_W$}"))),
        });
    };

    // Identity.
    add(
        "KIND",
        kind_label(&view.kind),
        kind_label(&view.kind).into(),
    );
    if let Some(name) = &view.payload_name {
        if matches!(view.kind, NestKind::Mark | NestKind::Work) {
            add("NAME", name, name.clone());
        }
    }

    // Condition.
    let checked = |n: usize| {
        if view.kind == NestKind::DirPack && n > 0 {
            format!("{sep}{n} files checked")
        } else {
            String::new()
        }
    };
    match &extra.health {
        Some(Health::Healthy) => {
            let tail = checked(view.entries.len());
            add(
                "STATUS",
                &format!("healthy{tail}"),
                format!("{}{}", st.paint("32", "healthy"), st.dim(&tail)),
            );
        }
        Some(Health::NeedsRepair(what)) => {
            add("STATUS", "needs repair", st.paint("33", "needs repair"));
            add("", what, st.dim(what));
            add(
                "",
                "run: sigil mend <in> -o <out>",
                st.dim("run: sigil mend <in> -o <out>"),
            );
        }
        Some(Health::NotRecoverable(why)) => {
            add(
                "STATUS",
                "not recoverable",
                st.paint("31", "not recoverable"),
            );
            add("", why, st.dim(why));
        }
        None if matches!(view.kind, NestKind::DirPack | NestKind::Mark) => {
            let v = "not checked here (run sigil scry)";
            add("STATUS", v, st.dim(v));
        }
        None => {}
    }

    // Extent.
    let mut tree: Vec<(String, bool, bool, String)> = Vec::new();
    match view.kind {
        NestKind::DirPack => {
            let t = build_tree(view);
            let total: u64 = view.entries.iter().filter_map(|e| e.orig).sum();
            let nests = view.entries.iter().filter(|e| e.nest).count();
            let mut v = format!(
                "{} files{sep}{} dirs{sep}{}",
                view.entries.len(),
                count_dirs(&t),
                human_bytes(total)
            );
            if nests > 0 {
                v.push_str(&format!("{sep}{nests} sealed inside"));
            }
            add("HOLDS", &v, v.clone());
            tree_rows(&t, 0, &mut tree);
        }
        NestKind::Leaf => {
            if let Some(n) = view.entries.first().and_then(|e| e.orig) {
                add("SIZE", &human_bytes(n), human_bytes(n));
            }
        }
        _ => {}
    }
    if let Some(line) = extra.scry_line {
        if let Some(n) = field(line, "orig").and_then(|v| v.parse::<u64>().ok()) {
            add("SIZE", &human_bytes(n), human_bytes(n));
        }
        if let Some(p) = pieces_from_scry(line) {
            let v = format!("{} of {} pieces intact, needs {}", p.live, p.total, p.need);
            add("REPAIR", &v, v.clone());
            let spare = p.live.saturating_sub(p.need);
            let v2 = format!("can lose {spare} more and still restore");
            add("", &v2, st.dim(&v2));
        }
    }
    if view.nest_payload {
        let v = "holds another seal; add `.` to open";
        add("NESTED", v, v.into());
    }

    // Identifier.
    let sha = if view.trail.len() == 1 {
        view.seen.first().map(hex::encode)
    } else {
        None
    };
    let sha_short = sha
        .as_ref()
        .map(|h| format!("{}{ell}{}", &h[..16], &h[h.len() - 16..]));

    // Layout.
    let title = view.trail.join(crumb);
    let mut width = SLAB_MIN.max(w(&title));
    for f in &fields {
        width = width.max(w(&f.plain));
    }
    for (n, _, nest, sz) in &tree {
        let tag = if *nest { 8 } else { 0 };
        width = width.max(w(n) + tag + 2 + w(sz));
    }
    if let Some(s) = &sha_short {
        width = width.max(KEY_W + w(s));
    }
    let m = "  ";
    let rule = format!("{m}{}", st.dim(&rule_ch.repeat(width)));
    let mut out = vec![format!("{m}{}", st.bold(&title)), rule.clone()];
    out.extend(fields.iter().map(|f| format!("{m}{}", f.styled)));
    if !tree.is_empty() {
        out.push(rule.clone());
        for (n, is_dir, nest, sz) in &tree {
            let tag = if *nest { "  (seal)" } else { "" };
            let gap = width.saturating_sub(w(n) + w(tag) + w(sz));
            let name = if *is_dir { st.bold(n) } else { n.clone() };
            out.push(format!(
                "{m}{name}{}{}{}",
                st.paint("36", tag),
                " ".repeat(gap),
                st.dim(sz)
            ));
        }
    }
    if let Some(s) = sha_short {
        out.push(rule);
        out.push(format!(
            "{m}{}{s}",
            st.gold(&format!("{:<KEY_W$}", "SHA-256"))
        ));
    }
    out.iter()
        .map(|l| l.trim_end())
        .collect::<Vec<_>>()
        .join("\n")
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nest::PathEntry;

    const ASCII: Style = Style {
        color: false,
        unicode: false,
    };

    fn folder() -> PathView {
        let e = |p: &str, n: u64| PathEntry {
            path: p.into(),
            orig: Some(n),
            nest: false,
            digest: None,
        };
        PathView {
            trail: vec!["album.sg1".into()],
            kind: NestKind::DirPack,
            entries: vec![
                e("notes/todo.txt", 5),
                e("photos/cat.jpg", 4),
                e("readme.txt", 6),
            ],
            payload_name: None,
            nest_payload: false,
            seen: vec![[0xab; 32]],
        }
    }

    fn mark() -> PathView {
        PathView {
            trail: vec!["one.sg1".into()],
            kind: NestKind::Mark,
            entries: vec![],
            payload_name: Some("one.txt".into()),
            nest_payload: false,
            seen: vec![[0xcd; 32]],
        }
    }

    #[test]
    fn folder_finding_aid_order() {
        let x = Extra {
            health: Some(Health::Healthy),
            scry_line: None,
        };
        let s = render_path_view(&folder(), &x, &ASCII);
        assert!(s.is_ascii(), "{s}");
        let l: Vec<&str> = s.lines().collect();
        assert_eq!(l[0], "  album.sg1");
        assert_eq!(l[2], "  KIND      folder pack");
        assert_eq!(l[3], "  STATUS    healthy, 3 files checked");
        assert_eq!(l[4], "  HOLDS     3 files, 2 dirs, 15 B");
        assert!(s.contains("\n  notes/\n    todo.txt"), "{s}");
        assert!(
            s.contains("  SHA-256   abababababababab...abababababababab"),
            "{s}"
        );
        assert!(l.iter().all(|x| x.len() <= 52), "{s}");
        assert!(!s.contains("0000"), "no fake offsets");
    }

    #[test]
    fn mark_status_then_repair_budget() {
        let line = "ok  v2  live=16/16 need=12 merkle=closed keystone=intact orig=2";
        let x = Extra {
            health: health_from_mark_scry(line, None),
            scry_line: Some(line),
        };
        let s = render_path_view(&mark(), &x, &ASCII);
        let st = s.find("STATUS    healthy").expect("status");
        let sz = s.find("SIZE      2 B").expect("size");
        assert!(st < sz, "{s}");
        assert!(
            s.contains("REPAIR    16 of 16 pieces intact, needs 12"),
            "{s}"
        );
        assert!(s.contains("can lose 4 more and still restore"), "{s}");
        assert!(!s.contains("merkle"), "jargon dropped when fine: {s}");
    }

    #[test]
    fn health_verdicts() {
        let torn = "ok  v2  live=14/16 need=12 merkle=open keystone=intact orig=2";
        assert_eq!(
            health_from_mark_scry(torn, None),
            Some(Health::NeedsRepair(
                "2 of 16 pieces lost, merkle tree open".into()
            ))
        );
        assert!(matches!(
            health_from_mark_scry("NOT recoverable  v2", Some("too few")),
            Some(Health::NotRecoverable(_))
        ));
        assert_eq!(health_from_mark_scry("work  name=x", None), None);
        let d = "folder  files=1 dirs=0\nneeds mend: a.txt (damaged but repairable, …)";
        assert_eq!(
            health_from_dir_scry(d, None),
            Health::NeedsRepair("a.txt".into())
        );
    }

    #[test]
    fn unknown_status_is_honest_and_color_is_gold() {
        let s = render_path_view(&folder(), &Extra::default(), &ASCII);
        assert!(s.contains("STATUS    not checked here"), "{s}");
        let c = Style {
            color: true,
            unicode: true,
        };
        let s = render_path_view(&folder(), &Extra::default(), &c);
        assert!(s.contains("\x1b[38;5;179mKIND"), "{s}");
    }

    #[test]
    fn sizes() {
        assert_eq!(human_bytes(5), "5 B");
        assert_eq!(human_bytes(2048), "2.0 KiB");
    }
}
