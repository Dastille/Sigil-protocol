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

fn count_dirs(n: &Node) -> usize {
    n.dirs.values().map(|c| 1 + count_dirs(c)).sum()
}

/// Minimum slab width (columns, excluding the 2-space margin): phone-friendly.
pub const SLAB_MIN: usize = 38;
const KEY_W: usize = 12;

fn w(s: &str) -> usize {
    s.chars().count()
}

impl Style {
    /// Brand gold (`#c29965`) for kickers, labels, rules: 256-color 179.
    fn gold(&self, s: &str) -> String {
        self.paint("38;5;179", s)
    }
}

/// Tree rows as (name with indent, size, nested?).
fn tree_rows(node: &Node, depth: usize, out: &mut Vec<(String, String, bool)>) {
    let pad = "  ".repeat(depth);
    for (name, child) in &node.dirs {
        out.push((format!("{pad}{name}/"), String::new(), false));
        tree_rows(child, depth + 1, out);
    }
    for (name, size, nest) in &node.files {
        out.push((
            format!("{pad}{name}"),
            size.map(human_bytes).unwrap_or_default(),
            *nest,
        ));
    }
}

/// Field rows (KEY, value lines) from a Scry report line (`ok  v2  live=16/16 …`).
fn scry_fields(st: &Style, line: &str, bad: Option<&str>) -> Vec<(String, Vec<String>)> {
    let mut rows = Vec::new();
    let mut words = line.split_whitespace();
    let status = words.next().unwrap_or("?");
    let (code, word) = match (bad, status) {
        (Some(_), _) => ("31", "not recoverable"),
        (None, "ok") => ("32", "healthy"),
        (None, other) => ("33", other),
    };
    rows.push(("HEALTH".into(), vec![st.paint(code, word)]));
    if let Some(why) = bad {
        rows.push(("WHY".into(), vec![why.to_string()]));
    }
    let (mut shards, mut chain) = (Vec::new(), Vec::new());
    for wd in words {
        if let Some((k, v)) = wd.split_once('=') {
            match k {
                "live" => shards.push(format!("shards {v} live")),
                "need" => shards.push(format!("need {v}")),
                "merkle" => chain.push(format!("merkle {v}")),
                "keystone" => chain.push(format!("keystone {v}")),
                "orig" => {
                    if let Ok(n) = v.parse::<u64>() {
                        rows.push(("SIZE".into(), vec![human_bytes(n)]));
                    }
                }
                _ => {}
            }
        } else if wd.starts_with('v') && wd.len() <= 3 {
            rows.push(("FORMAT".into(), vec![wd.to_string()]));
        }
    }
    let seal: Vec<String> = [shards, chain]
        .into_iter()
        .filter(|g| !g.is_empty())
        .map(|g| g.join(" · "))
        .collect();
    if !seal.is_empty() {
        rows.push(("SEAL".into(), seal));
    }
    rows
}

/// Genesis-block style hexdump rows of a digest: `0000  aa bb … ee ff  |........|`.
fn hex_rows(st: &Style, d: &[u8; 32]) -> Vec<(String, usize)> {
    d.chunks(8)
        .enumerate()
        .map(|(i, c)| {
            let hex: Vec<String> = c.iter().map(|b| format!("{b:02x}")).collect();
            let asc: String = c
                .iter()
                .map(|&b| if b.is_ascii_graphic() { b as char } else { '.' })
                .collect();
            let off = format!("{:04x}", i * 8);
            let hex = hex.join(" ");
            let width = 4 + 2 + w(&hex) + 2 + 10;
            (
                format!("{}  {hex}  {}", st.dim(&off), st.dim(&format!("|{asc}|"))),
                width,
            )
        })
        .collect()
}

/// Render a [`PathView`] as a genesis-block style field slab with Sigil brand kickers.
/// `scry` is an optional Scry report line plus not-recoverable reason for the outer
/// mark; pass `None` to omit health. The SHA-256 strip shows only for the outer file
/// (the digest `sigil path` already computes of the bytes on disk).
pub fn render_path_view(view: &PathView, scry: Option<(&str, Option<&str>)>, st: &Style) -> String {
    let (rule_ch, dot) = if st.unicode {
        ("─", "·")
    } else {
        ("-", ".")
    };
    let sep = if st.unicode { " · " } else { " / " };
    let crumb = if st.unicode { " → " } else { " > " };

    let mut fields: Vec<(String, Vec<String>)> = Vec::new();
    let mut plain_fields: Vec<(String, Vec<String>)> = Vec::new();
    let mut push = |k: &str, v: Vec<String>, pv: Vec<String>| {
        fields.push((k.into(), v));
        plain_fields.push((k.into(), pv));
    };
    push(
        "KIND",
        vec![view.kind.label().into()],
        vec![view.kind.label().into()],
    );
    if let Some(name) = &view.payload_name {
        if matches!(view.kind, NestKind::Mark | NestKind::Work) {
            push("NAME", vec![name.clone()], vec![name.clone()]);
        }
    }
    let mut tree: Vec<(String, String, bool)> = Vec::new();
    match view.kind {
        NestKind::DirPack => {
            let t = build_tree(view);
            let total: u64 = view.entries.iter().filter_map(|e| e.orig).sum();
            let nests = view.entries.iter().filter(|e| e.nest).count();
            let mut parts = vec![
                format!("{} files", view.entries.len()),
                format!("{} dirs", count_dirs(&t)),
                human_bytes(total),
            ];
            if nests > 0 {
                parts.push(format!("{nests} nested"));
            }
            let v = parts.join(sep);
            push("HOLDS", vec![v.clone()], vec![v]);
            tree_rows(&t, 0, &mut tree);
        }
        NestKind::Leaf => {
            if let Some(n) = view.entries.first().and_then(|e| e.orig) {
                push("SIZE", vec![human_bytes(n)], vec![human_bytes(n)]);
            }
        }
        _ => {}
    }
    if let Some((line, bad)) = scry {
        let plain = Style {
            color: false,
            unicode: st.unicode,
        };
        for (a, b) in scry_fields(st, line, bad)
            .into_iter()
            .zip(scry_fields(&plain, line, bad))
        {
            push(&a.0, a.1, b.1);
        }
    }
    if view.nest_payload {
        let v = "payload is a seal; add `.` to descend".to_string();
        push("NEST", vec![v.clone()], vec![v]);
    }
    let digest = if view.trail.len() == 1 {
        view.seen.first()
    } else {
        None
    };

    // Width: widest content, at least SLAB_MIN.
    let title = view.trail.join(crumb);
    let mut width = SLAB_MIN.max(w(&title));
    for (_, vs) in &plain_fields {
        for v in vs {
            width = width.max(KEY_W + w(v));
        }
    }
    for (n, sz, nest) in &tree {
        width = width.max(6 + w(n) + if *nest { 7 } else { 0 } + 2 + w(sz));
    }
    if digest.is_some() {
        width = width.max(41);
    }

    let m = "  ";
    let rule = format!("{m}{}", st.dim(&rule_ch.repeat(width)));
    let kind_tag = view.kind.label().to_uppercase();
    let dots = width.saturating_sub(5 + w(&kind_tag));
    let mut out = vec![
        format!(
            "{m}{}{}{}",
            st.gold(&st.bold("SIGIL")),
            st.dim(&dot.repeat(dots)),
            st.gold(&kind_tag)
        ),
        format!("{m}{}", st.bold(&title)),
        rule.clone(),
    ];
    for ((k, vs), (_, pvs)) in fields.iter().zip(plain_fields.iter()) {
        for (i, (v, _pv)) in vs.iter().zip(pvs.iter()).enumerate() {
            let key = if i == 0 { k.as_str() } else { "" };
            out.push(format!("{m}{}{v}", st.gold(&format!("{key:<KEY_W$}"))));
        }
    }
    out.push(rule.clone());
    if !tree.is_empty() {
        out.push(format!("{m}{}", st.gold("TREE")));
        for (i, (n, sz, nest)) in tree.iter().enumerate() {
            let tag = if *nest {
                if st.unicode {
                    "  ◆ nest"
                } else {
                    "  * nest"
                }
            } else {
                ""
            };
            let lw = 6 + w(n) + w(tag);
            let gap = width.saturating_sub(lw + w(sz));
            let name = if sz.is_empty() && !*nest {
                st.bold(n)
            } else {
                n.clone()
            };
            out.push(format!(
                "{m}{}  {name}{}{}{}",
                st.dim(&format!("{i:04}")),
                st.paint("36", tag),
                " ".repeat(gap),
                st.dim(sz)
            ));
        }
        out.push(rule.clone());
    }
    if let Some(d) = digest {
        out.push(format!("{m}{}", st.gold("FILE SHA-256")));
        for (row, _) in hex_rows(st, d) {
            out.push(format!("{m}{row}"));
        }
        out.push(rule);
    }
    let out: Vec<&str> = out.iter().map(|l| l.trim_end()).collect();
    let out = out.join("\n");
    if st.unicode {
        out
    } else {
        out.replace('—', "-").replace('·', "/")
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
    fn slab_layout() {
        let st = Style {
            color: false,
            unicode: true,
        };
        let s = render_path_view(&view(), None, &st);
        let l: Vec<&str> = s.lines().collect();
        assert!(
            l[0].starts_with("  SIGIL·") && l[0].ends_with("FOLDER"),
            "{s}"
        );
        assert_eq!(l[1], "  album.sg1");
        assert!(s.contains("  KIND        folder"), "{s}");
        assert!(s.contains("3 files · 2 dirs · 15 B"), "{s}");
        assert!(s.contains("  TREE\n  0000  notes/"), "{s}");
        assert!(s.contains("  0001    todo.txt"), "{s}");
        assert!(l.iter().all(|x| x.chars().count() <= 42), "{s}");
        assert!(!s.contains('\x1b'));
        assert!(!s.contains("SHA-256"), "no digest in view → no strip");
    }

    #[test]
    fn ascii_health_and_hex() {
        let st = Style {
            color: false,
            unicode: false,
        };
        let mut v = view();
        v.kind = NestKind::Mark;
        v.entries.clear();
        v.payload_name = Some("one.txt".into());
        v.seen = vec![[0x41; 32]];
        let s = render_path_view(
            &v,
            Some((
                "ok  v2  live=16/16 need=12 merkle=closed keystone=intact orig=2",
                None,
            )),
            &st,
        );
        assert!(s.is_ascii(), "{s}");
        assert!(s.contains("  HEALTH      healthy"), "{s}");
        assert!(
            s.contains("  SEAL        shards 16/16 live / need 12\n              merkle closed"),
            "{s}"
        );
        assert!(
            s.contains("  0000  41 41 41 41 41 41 41 41  |AAAAAAAA|"),
            "{s}"
        );
        assert!(s.contains("  0018  "), "{s}");
        let bad = render_path_view(&v, Some(("torn  v2", Some("too few shards"))), &st);
        assert!(bad.contains("not recoverable"), "{bad}");
    }

    #[test]
    fn color_uses_brand_gold() {
        let st = Style {
            color: true,
            unicode: true,
        };
        let s = render_path_view(&view(), None, &st);
        assert!(s.contains("\x1b[38;5;179m"), "{s}");
    }

    #[test]
    fn sizes() {
        assert_eq!(human_bytes(5), "5 B");
        assert_eq!(human_bytes(2048), "2.0 KiB");
    }
}
