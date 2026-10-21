//! Skip rules for `sigil log add`: `--exclude PATTERN` (repeatable) and a `.sigilignore` file at
//! the top of the source folder. In-house glob matcher, no dependency.
//!
//! **Pattern language** (a small, documented subset of `.gitignore`; matched against the path
//! relative to the source folder, `/`-separated, byte for byte, case-sensitive):
//!
//! * `*` any run of characters except `/`; `?` one character except `/`;
//! * `[abc]`, `[a-z]`, `[!a-z]` / `[^a-z]` one character from (or not from) a set, never `/`;
//! * `**/` at the start or after a `/`: zero or more folders; a trailing `/**`: everything inside;
//!   `**` anywhere else: any run of characters including `/`;
//! * `\x` the character `x` itself (to write a literal `*`, `?`, `[`, `#`, `!` or `\`);
//! * a pattern with no `/` (other than a trailing one) matches the **name** at any depth
//!   (`.tools-venv` skips every folder or file called `.tools-venv`); a pattern with a `/` in it is
//!   anchored at the top of the source folder (`raw/tmp`, `/build`);
//! * a trailing `/` matches folders only (`cache/`).
//!
//! A folder that matches is skipped **with everything under it** (it is not even read). In a
//! `.sigilignore` file there is one pattern per line; blank lines and lines starting with `#` are
//! ignored and trailing spaces/tabs are trimmed (write `\ ` to keep one). A leading `!` (re-include
//! in `.gitignore`) is **refused** rather than silently read as a literal, as is any malformed
//! pattern (unclosed `[`, a lone trailing `\`, an empty pattern): the run stops before reading or
//! writing anything, so a typo can never quietly widen or narrow what is backed up.

use std::path::Path;

/// Name of the ignore file read from the top of the source folder (unless switched off).
pub const IGNORE_FILE: &str = ".sigilignore";

#[derive(Clone, Debug, PartialEq, Eq)]
enum Tok {
    /// One literal byte.
    Lit(u8),
    /// `?`: one byte other than `/`.
    One,
    /// `*`: any run of bytes other than `/`.
    Star,
    /// `**`: any run of bytes, `/` included.
    Any,
    /// `**/`: empty, or any run of bytes ending in `/`.
    Dirs,
    /// `[...]`: one byte (never `/`) in (or, negated, not in) the inclusive ranges.
    Class { neg: bool, ranges: Vec<(u8, u8)> },
}

/// One compiled pattern.
#[derive(Clone, Debug)]
pub struct ExcludePattern {
    toks: Vec<Tok>,
    anchored: bool,
    dir_only: bool,
    /// The pattern as written.
    pub text: String,
    /// Where it came from: `--exclude` or `.sigilignore line N`.
    pub origin: String,
}

/// An error in a skip pattern (the run is refused).
fn bad(origin: &str, text: &str, why: &str) -> String {
    format!("bad exclude pattern {text:?} ({origin}): {why}")
}

impl ExcludePattern {
    /// Compile one pattern (see the module docs). `origin` is only used in messages.
    pub fn parse(pat: &[u8], origin: &str) -> std::result::Result<Self, String> {
        let text = String::from_utf8_lossy(pat).into_owned();
        if pat.first() == Some(&b'!') {
            return Err(bad(
                origin,
                &text,
                "a leading `!` (re-include) is not supported; write `\\!` for a name starting with `!`",
            ));
        }
        let mut p = pat;
        let dir_only = p.last() == Some(&b'/') && !ends_escaped(p);
        if dir_only {
            p = &p[..p.len() - 1];
        }
        let leading_slash = p.first() == Some(&b'/');
        if leading_slash {
            p = &p[1..];
        }
        if p.is_empty() {
            return Err(bad(origin, &text, "empty pattern"));
        }
        let mut toks = Vec::new();
        let mut has_slash = false;
        let mut i = 0;
        while i < p.len() {
            let c = p[i];
            match c {
                b'\\' => {
                    let Some(&n) = p.get(i + 1) else {
                        return Err(bad(origin, &text, "a lone `\\` at the end"));
                    };
                    if n == b'/' {
                        has_slash = true;
                    }
                    toks.push(Tok::Lit(n));
                    i += 2;
                }
                b'?' => {
                    toks.push(Tok::One);
                    i += 1;
                }
                b'*' => {
                    if p.get(i + 1) == Some(&b'*') {
                        let at_seg_start = i == 0 || p[i - 1] == b'/';
                        if at_seg_start && p.get(i + 2) == Some(&b'/') {
                            toks.push(Tok::Dirs);
                            has_slash = true;
                            i += 3;
                        } else {
                            toks.push(Tok::Any);
                            i += 2;
                        }
                        // a third `*` and beyond change nothing
                        while p.get(i) == Some(&b'*') {
                            i += 1;
                        }
                    } else {
                        toks.push(Tok::Star);
                        i += 1;
                    }
                }
                b'[' => {
                    let (tok, used) = parse_class(&p[i..])
                        .ok_or_else(|| bad(origin, &text, "a `[` set is not closed with `]`"))?;
                    toks.push(tok);
                    i += used;
                }
                _ => {
                    if c == b'/' {
                        has_slash = true;
                    }
                    toks.push(Tok::Lit(c));
                    i += 1;
                }
            }
        }
        Ok(ExcludePattern {
            toks,
            anchored: leading_slash || has_slash,
            dir_only,
            text,
            origin: origin.to_string(),
        })
    }

    /// Does this pattern match the entry at relative path `rel` (`is_dir`: it is a folder)?
    /// Only the entry itself is tested; [`Excluder::excluded`] also tests its parent folders.
    pub fn matches(&self, rel: &[u8], is_dir: bool) -> bool {
        if self.dir_only && !is_dir {
            return false;
        }
        let subject = if self.anchored {
            rel
        } else {
            match rel.iter().rposition(|&b| b == b'/') {
                Some(k) => &rel[k + 1..],
                None => rel,
            }
        };
        glob(&self.toks, subject)
    }
}

/// True when the last byte of `p` is escaped by an odd run of `\` before it.
fn ends_escaped(p: &[u8]) -> bool {
    let n = p.len().saturating_sub(1);
    p[..n].iter().rev().take_while(|&&b| b == b'\\').count() % 2 == 1
}

/// Parse a `[...]` set at the start of `p`; returns the token and the bytes it used.
fn parse_class(p: &[u8]) -> Option<(Tok, usize)> {
    let mut i = 1;
    let neg = matches!(p.get(i), Some(b'!') | Some(b'^'));
    if neg {
        i += 1;
    }
    let mut ranges = Vec::new();
    let mut first = true;
    loop {
        let mut c = *p.get(i)?;
        if c == b']' && !first {
            return Some((Tok::Class { neg, ranges }, i + 1));
        }
        first = false;
        if c == b'\\' {
            i += 1;
            c = *p.get(i)?;
        }
        i += 1;
        if p.get(i) == Some(&b'-') && p.get(i + 1).is_some_and(|&b| b != b']') {
            let mut hi = *p.get(i + 1)?;
            i += 2;
            if hi == b'\\' {
                hi = *p.get(i)?;
                i += 1;
            }
            ranges.push((c.min(hi), c.max(hi)));
        } else {
            ranges.push((c, c));
        }
    }
}

/// Glob match of `toks` against all of `s`. Dynamic programming over (token, byte) positions, so
/// the cost is at most tokens × bytes whatever the pattern (no exponential backtracking).
fn glob(toks: &[Tok], s: &[u8]) -> bool {
    // ok[j]: the tokens consumed so far can match s[..j]
    let mut ok = vec![false; s.len() + 1];
    ok[0] = true;
    for t in toks {
        let mut next = vec![false; s.len() + 1];
        for j in 0..=s.len() {
            if !ok[j] {
                continue;
            }
            match t {
                Tok::Lit(c) => {
                    if s.get(j) == Some(c) {
                        next[j + 1] = true;
                    }
                }
                Tok::One => {
                    if s.get(j).is_some_and(|&b| b != b'/') {
                        next[j + 1] = true;
                    }
                }
                Tok::Class { neg, ranges } => {
                    if let Some(&b) = s.get(j) {
                        let hit = ranges.iter().any(|&(lo, hi)| (lo..=hi).contains(&b));
                        if b != b'/' && hit != *neg {
                            next[j + 1] = true;
                        }
                    }
                }
                Tok::Star => {
                    next[j] = true;
                    let mut k = j;
                    while k < s.len() && s[k] != b'/' {
                        k += 1;
                        next[k] = true;
                    }
                }
                Tok::Any => {
                    for n in next.iter_mut().skip(j) {
                        *n = true;
                    }
                }
                Tok::Dirs => {
                    next[j] = true;
                    for k in j..s.len() {
                        if s[k] == b'/' {
                            next[k + 1] = true;
                        }
                    }
                }
            }
        }
        ok = next;
    }
    ok[s.len()]
}

/// The full set of skip rules for one run.
#[derive(Clone, Debug, Default)]
pub struct Excluder {
    /// Compiled patterns, `--exclude` ones first, then the ignore file's in line order.
    pub patterns: Vec<ExcludePattern>,
    /// Number of patterns read from the ignore file.
    pub from_file: usize,
}

impl Excluder {
    /// Build the rules: every `--exclude` pattern, then (when `read_ignore_file`) the lines of
    /// `src/.sigilignore` if that file exists. Any bad pattern, or an ignore file that exists but
    /// cannot be read, is an error.
    pub fn new(
        cli: &[String],
        src: &Path,
        read_ignore_file: bool,
    ) -> std::result::Result<Self, String> {
        let mut ex = Excluder::default();
        for c in cli {
            ex.patterns
                .push(ExcludePattern::parse(c.as_bytes(), "--exclude")?);
        }
        if read_ignore_file {
            let f = src.join(IGNORE_FILE);
            match std::fs::symlink_metadata(&f) {
                Err(e) if e.kind() == std::io::ErrorKind::NotFound => {}
                Err(e) => return Err(format!("{}: {e}", f.display())),
                Ok(md) if !md.is_file() => {
                    return Err(format!(
                        "{} is not a regular file (refusing to guess what to skip)",
                        f.display()
                    ))
                }
                Ok(_) => {
                    let body = std::fs::read(&f).map_err(|e| format!("{}: {e}", f.display()))?;
                    let pats = parse_ignore_file(&body)?;
                    ex.from_file = pats.len();
                    ex.patterns.extend(pats);
                }
            }
        }
        Ok(ex)
    }

    /// No rules at all.
    pub fn is_empty(&self) -> bool {
        self.patterns.is_empty()
    }

    /// The first pattern matching the entry itself (not its parents).
    pub fn matching(&self, rel: &[u8], is_dir: bool) -> Option<&ExcludePattern> {
        self.patterns.iter().find(|p| p.matches(rel, is_dir))
    }

    /// The first pattern that skips the **file** at `rel`: one matching any of its parent folders,
    /// or the file itself. Used for paths already in the log, which the walk never reaches.
    pub fn excluded(&self, rel: &[u8]) -> Option<&ExcludePattern> {
        if self.is_empty() {
            return None;
        }
        for (k, &b) in rel.iter().enumerate() {
            if b == b'/' {
                if let Some(p) = self.matching(&rel[..k], true) {
                    return Some(p);
                }
            }
        }
        self.matching(rel, false)
    }
}

/// Parse the body of a `.sigilignore` file (see the module docs).
pub fn parse_ignore_file(body: &[u8]) -> std::result::Result<Vec<ExcludePattern>, String> {
    let mut out = Vec::new();
    for (n, raw) in body.split(|&b| b == b'\n').enumerate() {
        let mut line = raw.strip_suffix(b"\r").unwrap_or(raw);
        if line.first() == Some(&b'#') {
            continue;
        }
        while let Some((&last, rest)) = line.split_last() {
            if (last == b' ' || last == b'\t') && !ends_escaped(line) {
                line = rest;
            } else {
                break;
            }
        }
        if line.is_empty() {
            continue;
        }
        out.push(ExcludePattern::parse(
            line,
            &format!("{IGNORE_FILE} line {}", n + 1),
        )?);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pat(p: &str) -> ExcludePattern {
        ExcludePattern::parse(p.as_bytes(), "test").unwrap()
    }

    fn ex(ps: &[&str]) -> Excluder {
        Excluder {
            patterns: ps.iter().map(|p| pat(p)).collect(),
            from_file: 0,
        }
    }

    #[test]
    fn name_patterns_float_to_any_depth() {
        let p = pat(".tools-venv");
        assert!(p.matches(b".tools-venv", true));
        assert!(p.matches(b"a/b/.tools-venv", true));
        assert!(!p.matches(b"a/.tools-venv-old", true));
        let s = pat("*.tmp");
        assert!(s.matches(b"x.tmp", false) && s.matches(b"d/e/x.tmp", false));
        assert!(!s.matches(b"x.tmp.jpg", false));
    }

    #[test]
    fn slash_anchors_and_star_stays_in_one_folder() {
        let p = pat("raw/*.dng");
        assert!(p.matches(b"raw/a.dng", false));
        assert!(!p.matches(b"x/raw/a.dng", false), "anchored at the top");
        assert!(!p.matches(b"raw/sub/a.dng", false), "* does not cross /");
        let l = pat("/build");
        assert!(l.matches(b"build", true) && !l.matches(b"a/build", true));
    }

    #[test]
    fn double_star_forms() {
        let p = pat("**/cache");
        assert!(p.matches(b"cache", true) && p.matches(b"a/b/cache", true));
        let m = pat("a/**/b");
        for s in [&b"a/b"[..], b"a/x/b", b"a/x/y/b"] {
            assert!(m.matches(s, false), "{}", String::from_utf8_lossy(s));
        }
        assert!(!m.matches(b"a/xb", false));
        let t = pat("logs/**");
        assert!(t.matches(b"logs/x/y.txt", false) && !t.matches(b"logs", true));
        let any = pat("a**z");
        assert!(any.matches(b"abcz", false) && any.matches(b"d/abz", false));
        let deep = pat("x/**z");
        assert!(deep.matches(b"x/a/b/z", false), "** elsewhere crosses /");
    }

    #[test]
    fn dir_only_classes_and_escapes() {
        let d = pat("cache/");
        assert!(d.matches(b"x/cache", true) && !d.matches(b"x/cache", false));
        let c = pat("img[0-9].jpg");
        assert!(c.matches(b"img7.jpg", false) && !c.matches(b"imgx.jpg", false));
        let n = pat("[!.]*");
        assert!(n.matches(b"a", false) && !n.matches(b".hidden", false));
        let e = pat(r"\*star\?");
        assert!(e.matches(b"*star?", false) && !e.matches(b"xstar?", false));
        let bang = pat(r"\!keep");
        assert!(bang.matches(b"!keep", false));
        let q = pat("?.txt");
        assert!(q.matches(b"a.txt", false) && !q.matches(b"ab.txt", false));
    }

    #[test]
    fn malformed_patterns_are_refused() {
        for p in ["", "/", "!x", "[abc", "a\\", "[]"] {
            assert!(
                ExcludePattern::parse(p.as_bytes(), "t").is_err(),
                "{p:?} should be refused"
            );
        }
    }

    #[test]
    fn ignore_file_comments_blanks_trailing_space() {
        let body = b"# venvs\n\n.tools-venv/\r\n  \n*.log   \n\\#literal\nkeep\\ \n";
        let ps = parse_ignore_file(body).unwrap();
        let texts: Vec<&str> = ps.iter().map(|p| p.text.as_str()).collect();
        assert_eq!(texts, [".tools-venv/", "*.log", "\\#literal", "keep\\ "]);
        assert_eq!(ps[1].origin, ".sigilignore line 5");
        assert!(ps[2].matches(b"#literal", false));
        assert!(ps[3].matches(b"keep ", false));
        let e = parse_ignore_file(b"ok\n!nope\n").unwrap_err();
        assert!(e.contains("line 2"), "{e}");
    }

    #[test]
    fn excluded_checks_parent_folders_of_logged_paths() {
        let x = ex(&[".tools-venv/", "raw/tmp"]);
        assert_eq!(
            x.excluded(b"ig/.tools-venv/lib/site.py")
                .map(|p| p.text.as_str()),
            Some(".tools-venv/")
        );
        assert!(x.excluded(b"raw/tmp/a.jpg").is_some());
        assert!(x.excluded(b"raw/tmpx/a.jpg").is_none());
        assert!(
            x.excluded(b"photos/.tools-venv").is_none(),
            "dir-only: a file of that name stays"
        );
        assert!(Excluder::default().excluded(b"a/b").is_none());
    }

    #[test]
    fn huge_star_patterns_stay_cheap() {
        let p = pat("*a*a*a*a*a*a*a*a*a*a*b");
        let s = vec![b'a'; 4000];
        assert!(!p.matches(&s, false));
    }

    #[test]
    fn ignore_file_must_be_regular_and_readable() {
        let d = std::env::temp_dir().join(format!("sigil-excl-unit-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(d.join(IGNORE_FILE)).unwrap();
        assert!(Excluder::new(&[], &d, true).is_err());
        assert!(Excluder::new(&[], &d, false).unwrap().is_empty());
        std::fs::remove_dir_all(d.join(IGNORE_FILE)).unwrap();
        assert!(
            Excluder::new(&[], &d, true).unwrap().is_empty(),
            "absent is fine"
        );
        std::fs::write(d.join(IGNORE_FILE), "a\n# c\nb/\n").unwrap();
        let x = Excluder::new(&["z".into()], &d, true).unwrap();
        assert_eq!((x.patterns.len(), x.from_file), (3, 2));
    }
}
