//! Human "inspect" card for `sigil path --pretty`: a framed header, the facts the
//! view already carries, and an indented tree of folder members.
//!
//! Plain output ([`crate::PathView::format`]) stays the stable, script-friendly default.
//! This renderer adds no facts of its own: every line comes from the [`PathView`] or
//! from the caller-supplied Scry report line.

use crate::nest::{NestKind, PathView};
use std::collections::BTreeMap;

/// How [`render_path_view`] should style text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Style {
    /// Emit ANSI SGR codes (bold, dim, green/yellow/red).
    pub color: bool,
    /// Use Unicode box-drawing; `false` falls back to ASCII `+-|`.
    pub unicode: bool,
}

impl Style {
    /// Decide from the environment: color when stdout is a terminal and `NO_COLOR`
    /// is unset, or whenever `CLICOLOR_FORCE` is set to a non-`0` value.
    pub fn from_env(stdout_is_tty: bool) -> Self {
        let force = std::env::var("CLICOLOR_FORCE")
            .map(|v| !v.is_empty() && v != "0")
            .unwrap_or(false);
        let no_color = std::env::var_os("NO_COLOR").is_some_and(|v| !v.is_empty());
        let ascii = std::env::var("SIGIL_ASCII")
            .map(|v| !v.is_empty() && v != "0")
            .unwrap_or(false);
        Style {
            color: force || (stdout_is_tty && !no_color),
            unicode: !ascii,
        }
    }

    fn paint(&self, code: &str, s: &str) -> String {
        if self.color {
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

/// One body row: left text (already styled), its visible width, optional right text.
struct Row {
    left: String,
    left_w: usize,
    right: String,
    right_w: usize,
}

fn row(left: String, left_w: usize, right: String, right_w: usize) -> Row {
    Row {
        left,
        left_w,
        right,
        right_w,
    }
}

fn walk(node: &Node, depth: usize, st: &Style, out: &mut Vec<Row>) {
    let pad = "  ".repeat(depth);
    for (name, child) in &node.dirs {
        let label = format!("{name}/");
        let w = pad.chars().count() + label.chars().count();
        out.push(row(
            format!("{pad}{}", st.bold(&label)),
            w,
            String::new(),
            0,
        ));
        walk(child, depth + 1, st, out);
    }
    for (name, size, nest) in &node.files {
        let tag = if *nest { "  ◆ nest" } else { "" };
        let tag = if st.unicode {
            tag.to_string()
        } else {
            tag.replace('◆', "*")
        };
        let w = pad.chars().count() + name.chars().count() + tag.chars().count();
        let left = format!("{pad}{name}{}", st.paint("36", &tag));
        let r = size.map(human_bytes).unwrap_or_default();
        let rw = r.chars().count();
        out.push(row(left, w, st.dim(&r), rw));
    }
}

fn kv(st: &Style, k: &str, v: &str) -> Row {
    let key = format!("{k:<7}");
    row(
        format!("{} {v}", st.dim(&key)),
        key.chars().count() + 1 + v.chars().count(),
        String::new(),
        0,
    )
}

/// Turn a Scry report line (`ok  v2  live=16/16 need=12 …`) into health rows.
/// `bad` is the not-recoverable reason, when Scry gave one.
fn scry_rows(st: &Style, line: &str, bad: Option<&str>) -> Vec<Row> {
    let mut rows = Vec::new();
    let mut words = line.split_whitespace();
    let status = words.next().unwrap_or("?");
    let (code, word) = match (bad, status) {
        (Some(_), _) => ("31", "not recoverable"),
        (None, "ok") => ("32", "healthy"),
        (None, other) => ("33", other),
    };
    let health = st.paint(code, word);
    rows.push(row(
        format!("{} {health}", st.dim("health ")),
        8 + word.chars().count(),
        String::new(),
        0,
    ));
    if let Some(why) = bad {
        rows.push(kv(st, "why", why));
    }
    let mut facts: Vec<String> = Vec::new();
    for w in words {
        if let Some((k, v)) = w.split_once('=') {
            match k {
                "live" => facts.push(format!("shards {v} live")),
                "need" => facts.push(format!("need {v}")),
                "merkle" => facts.push(format!("merkle {v}")),
                "keystone" => facts.push(format!("keystone {v}")),
                "orig" => {
                    if let Ok(n) = v.parse::<u64>() {
                        rows.push(kv(st, "size", &human_bytes(n)));
                    }
                }
                _ => {}
            }
        } else if w.starts_with('v') && w.len() <= 3 {
            rows.push(kv(st, "format", w));
        }
    }
    if !facts.is_empty() {
        rows.push(kv(st, "seal", &facts.join(" · ")));
    }
    rows
}

/// Render a [`PathView`] as a framed card. `scry` is an optional Scry report line
/// plus not-recoverable reason for the outer mark; pass `None` to omit health.
pub fn render_path_view(view: &PathView, scry: Option<(&str, Option<&str>)>, st: &Style) -> String {
    let (h, v, tl, tr, bl, br, ml, mr) = if st.unicode {
        ("─", "│", "┌", "┐", "└", "┘", "├", "┤")
    } else {
        ("-", "|", "+", "+", "+", "+", "+", "+")
    };
    let crumb_sep = if st.unicode { " → " } else { " > " };
    let title = format!("{} · {}", view.trail.join(crumb_sep), view.kind.label());

    let mut head: Vec<Row> = Vec::new();
    if let Some(name) = &view.payload_name {
        if matches!(view.kind, NestKind::Mark | NestKind::Work) {
            head.push(kv(st, "name", name));
        }
    }
    let mut body: Vec<Row> = Vec::new();
    match view.kind {
        NestKind::DirPack => {
            let tree = build_tree(view);
            let total: u64 = view.entries.iter().filter_map(|e| e.orig).sum();
            let nests = view.entries.iter().filter(|e| e.nest).count();
            let mut dirs = 0usize;
            fn count(n: &Node, d: &mut usize) {
                for c in n.dirs.values() {
                    *d += 1;
                    count(c, d);
                }
            }
            count(&tree, &mut dirs);
            let mut s = format!(
                "{} files · {} dirs · {}",
                view.entries.len(),
                dirs,
                human_bytes(total)
            );
            if nests > 0 {
                s.push_str(&format!(" · {nests} nested"));
            }
            head.push(kv(st, "holds", &s));
            walk(&tree, 0, st, &mut body);
        }
        NestKind::Leaf => {
            if let Some(n) = view.entries.first().and_then(|e| e.orig) {
                head.push(kv(st, "size", &human_bytes(n)));
            }
        }
        _ => {}
    }
    if let Some((line, bad)) = scry {
        head.extend(scry_rows(st, line, bad));
    }
    if view.nest_payload {
        head.push(kv(st, "nest", "payload is a seal — add `.` to descend"));
    }

    let inner = head
        .iter()
        .chain(body.iter())
        .map(|r| r.left_w + if r.right_w > 0 { r.right_w + 4 } else { 0 })
        .max()
        .unwrap_or(0)
        .max(title.chars().count() + 4)
        .max(24);
    let rule = |l: &str, label: &str, r: &str| -> String {
        let lab = if label.is_empty() {
            String::new()
        } else {
            format!(" {label} ")
        };
        let fill = (inner + 2).saturating_sub(1 + lab.chars().count());
        format!("{l}{h}{}{}{r}", st.bold(&lab), h.repeat(fill))
    };
    let line = |r: &Row| -> String {
        let gap = inner - r.left_w - r.right_w;
        format!("{v} {}{}{} {v}", r.left, " ".repeat(gap), r.right)
    };
    let mut out = vec![rule(tl, &title, tr)];
    out.extend(head.iter().map(line));
    if !body.is_empty() {
        out.push(rule(ml, "tree", mr));
        out.extend(body.iter().map(line));
    }
    out.push(rule(bl, "", br));
    let out = out.join("\n");
    if st.unicode {
        out
    } else {
        out.replace('·', "/").replace('—', "-").replace('→', ">")
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::nest::PathEntry;

    fn view() -> PathView {
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
            seen: vec![],
        }
    }

    #[test]
    fn tree_and_frame() {
        let st = Style {
            color: false,
            unicode: true,
        };
        let s = render_path_view(&view(), None, &st);
        assert!(s.starts_with("┌─ album.sg1 · folder "), "{s}");
        assert!(s.contains("├─ tree "), "{s}");
        assert!(s.contains("│ notes/"), "{s}");
        assert!(s.contains("│   todo.txt"), "{s}");
        assert!(s.contains("3 files · 2 dirs · 15 B"), "{s}");
        let widths: Vec<usize> = s.lines().map(|l| l.chars().count()).collect();
        assert!(widths.windows(2).all(|w| w[0] == w[1]), "{s}");
        assert!(!s.contains('\x1b'));
    }

    #[test]
    fn ascii_and_health() {
        let st = Style {
            color: false,
            unicode: false,
        };
        let mut v = view();
        v.kind = NestKind::Mark;
        v.entries.clear();
        v.payload_name = Some("one.txt".into());
        let s = render_path_view(
            &v,
            Some(("ok  v2  live=16/16 need=12 merkle=closed orig=2", None)),
            &st,
        );
        assert!(s.is_ascii(), "{s}");
        assert!(s.contains("health  healthy"), "{s}");
        assert!(s.contains("shards 16/16 live · need 12") || s.contains("shards 16/16 live"));
        let bad = render_path_view(&v, Some(("torn  v2", Some("too few shards"))), &st);
        assert!(bad.contains("not recoverable"), "{bad}");
    }

    #[test]
    fn sizes() {
        assert_eq!(human_bytes(5), "5 B");
        assert_eq!(human_bytes(2048), "2.0 KiB");
    }
}
