//! Nest + breadcrumb: walk into .sg1 seals embedded in SGDR packs (or wrapped marks)
//! without permanently unpacking the durable store.

use crate::folder::{list_dir_pack, looks_like_nest_name, read_dir_entry_star, DirEntry, DIR_MAGIC};
use crate::work::WORK_MAGIC;
use crate::{hex32, locate_header, unseal_ex, Result};
use std::fs;
use std::path::{Path, PathBuf};

/// Hard ceiling on nest descent (breadcrumb segments). CLI `--depth` may lower it.
pub const MAX_NEST_DEPTH: usize = 32;

const SGIL: [u8; 4] = *b"SGIL";

#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NestKind {
    DirPack,
    Mark,
    Work,
    Leaf,
}

impl NestKind {
    pub fn label(&self) -> &'static str {
        match self {
            NestKind::DirPack => "folder",
            NestKind::Mark => "mark",
            NestKind::Work => "work",
            NestKind::Leaf => "leaf",
        }
    }
}

/// Classify raw bytes (peek magic / header).
pub fn kind_of_bytes(data: &[u8]) -> NestKind {
    if data.len() >= 4 && data[..4] == DIR_MAGIC {
        return NestKind::DirPack;
    }
    if data.len() >= 4 && data[..4] == WORK_MAGIC {
        return NestKind::Work;
    }
    if data.len() >= 4 && (data[..4] == SGIL || locate_header(data).is_ok()) {
        return NestKind::Mark;
    }
    NestKind::Leaf
}

pub fn is_nestable_bytes(data: &[u8]) -> bool {
    !matches!(kind_of_bytes(data), NestKind::Leaf)
}

/// One line in a listing at the current breadcrumb stop.
#[derive(Clone, Debug)]
pub struct PathEntry {
    pub path: String,
    pub orig: Option<u64>,
    pub nest: bool,
    pub digest: Option<[u8; 32]>,
}

/// Snapshot of where `sigil path` is looking.
#[derive(Clone, Debug)]
pub struct PathView {
    pub trail: Vec<String>,
    pub kind: NestKind,
    pub entries: Vec<PathEntry>,
    /// Single-file mark: payload name from header (when known).
    pub payload_name: Option<String>,
    /// Single-file mark whose unsealed payload is itself a seal.
    pub nest_payload: bool,
    /// True-name digests of each nest layer entered (for cycles).
    pub seen: Vec<[u8; 32]>,
}

impl PathView {
    pub fn breadcrumb(&self) -> String {
        if self.trail.is_empty() {
            return String::new();
        }
        self.trail.join(" → ")
    }

    pub fn format(&self) -> String {
        let mut out = String::new();
        out.push_str("trail  ");
        out.push_str(&self.breadcrumb());
        out.push('\n');
        out.push_str(&format!("kind   {}\n", self.kind.label()));
        if self.nest_payload {
            out.push_str("nest   payload is a seal (use --into . to descend)\n");
        }
        if let Some(name) = &self.payload_name {
            if self.kind == NestKind::Mark || self.kind == NestKind::Work {
                out.push_str(&format!("name   {name}\n"));
            }
        }
        match self.kind {
            NestKind::DirPack => {
                out.push_str(&format!("files  {}\n", self.entries.len()));
                for e in &self.entries {
                    if e.nest {
                        out.push_str("nest  ");
                    } else {
                        out.push_str("file  ");
                    }
                    out.push_str(&e.path);
                    if let Some(n) = e.orig {
                        out.push_str(&format!("  {n} bytes"));
                    }
                    out.push('\n');
                }
            }
            NestKind::Mark if self.nest_payload => {
                out.push_str("hint   --into .  (unwrap nested seal)\n");
            }
            NestKind::Leaf => {
                if let Some(n) = self.entries.first().and_then(|e| e.orig) {
                    out.push_str(&format!("size   {n} bytes\n"));
                }
            }
            _ => {}
        }
        out.trim_end().to_string()
    }
}

fn mark_id(bytes: &[u8]) -> [u8; 32] {
    crate::sha256(bytes)
}

fn push_seen(seen: &mut Vec<[u8; 32]>, id: [u8; 32]) -> Result<()> {
    if seen.iter().any(|s| s == &id) {
        return Err(crate::Error::Msg(format!(
            "nest cycle refused (mark {} already on the trail)",
            &hex32(&id)[..16]
        )));
    }
    seen.push(id);
    Ok(())
}

fn check_depth(depth: usize, max_depth: usize) -> Result<()> {
    if depth > max_depth {
        return Err(crate::Error::Msg(format!(
            "nest depth {depth} exceeds cap {max_depth}"
        )));
    }
    Ok(())
}

fn view_dir_bytes(data: &[u8], trail: Vec<String>, seen: Vec<[u8; 32]>) -> Result<PathView> {
    let tmp = std::env::temp_dir().join(format!(
        "sigil-nest-list-{}-{}",
        std::process::id(),
        trail.len()
    ));
    fs::write(&tmp, data).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let entries = list_dir_pack(&tmp);
    let _ = fs::remove_file(&tmp);
    let entries = entries?;
    Ok(PathView {
        trail,
        kind: NestKind::DirPack,
        entries: entries
            .into_iter()
            .map(|e: DirEntry| PathEntry {
                path: e.path,
                orig: e.orig,
                nest: e.nest,
                digest: e.digest,
            })
            .collect(),
        payload_name: None,
        nest_payload: false,
        seen,
    })
}

fn view_mark_bytes(
    data: &[u8],
    trail: Vec<String>,
    seen: Vec<[u8; 32]>,
    pass: Option<&str>,
) -> Result<PathView> {
    let kind = kind_of_bytes(data);
    match kind {
        NestKind::DirPack => view_dir_bytes(data, trail, seen),
        NestKind::Work => {
            let name = if data.len() >= 4 {
                // work head name is after magic+ver+chunk+orig — reuse payload via temp
                let tmp = std::env::temp_dir().join(format!(
                    "sigil-nest-wk-{}-{}",
                    std::process::id(),
                    trail.len()
                ));
                fs::write(&tmp, data).map_err(|e| crate::Error::Msg(e.to_string()))?;
                let n = crate::work::payload_name(&tmp).ok();
                let _ = fs::remove_file(&tmp);
                n
            } else {
                None
            };
            Ok(PathView {
                trail,
                kind: NestKind::Work,
                entries: vec![],
                payload_name: name,
                nest_payload: false,
                seen,
            })
        }
        NestKind::Mark => {
            let (h, _, _) = locate_header(data)?;
            let mut nest_payload = looks_like_nest_name(&h.name);
            // Try unseal when not encrypted, or when pass given, to confirm payload magic.
            if !h.encrypted() || pass.is_some() {
                match unseal_ex(data, pass, &[]) {
                    Ok(plain) if is_nestable_bytes(&plain) => nest_payload = true,
                    Ok(_) => {
                        if !looks_like_nest_name(&h.name) {
                            nest_payload = false;
                        }
                    }
                    Err(_) => {}
                }
            }
            Ok(PathView {
                trail,
                kind: NestKind::Mark,
                entries: vec![],
                payload_name: if h.name.is_empty() {
                    None
                } else {
                    Some(h.name)
                },
                nest_payload,
                seen,
            })
        }
        NestKind::Leaf => Ok(PathView {
            trail,
            kind: NestKind::Leaf,
            entries: vec![PathEntry {
                path: "(leaf)".into(),
                orig: Some(data.len() as u64),
                nest: false,
                digest: None,
            }],
            payload_name: None,
            nest_payload: false,
            seen,
        }),
    }
}

/// List the outer mark (or the view after breadcrumb segments).
pub fn path_walk(
    mark: &Path,
    into: &[String],
    pass: Option<&str>,
    wards: &[(String, String)],
    max_depth: usize,
) -> Result<PathView> {
    let max_depth = max_depth.min(MAX_NEST_DEPTH);
    check_depth(into.len(), max_depth)?;

    let root_bytes = fs::read(mark).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let root_label = mark
        .file_name()
        .and_then(|s| s.to_str())
        .unwrap_or("mark")
        .to_string();

    let mut seen = Vec::new();
    push_seen(&mut seen, mark_id(&root_bytes))?;

    let mut trail = vec![root_label];
    let mut cur = root_bytes;
    let mut depth = 0usize;

    for (i, step) in into.iter().enumerate() {
        depth += 1;
        check_depth(depth, max_depth)?;
        let step = step.trim().trim_start_matches("./");
        // Prefer the name of the layer we are leaving (header / segment) for the trail.
        let from_name = match kind_of_bytes(&cur) {
            NestKind::Mark => locate_header(&cur)
                .ok()
                .map(|(h, _, _)| h.name)
                .filter(|s| !s.is_empty()),
            _ => None,
        };
        let next = descend_one(&cur, step, pass, wards, &trail)?;
        let id = mark_id(&next);
        push_seen(&mut seen, id)?;
        let label = if step.is_empty() || step == "." {
            from_name
                .or_else(|| payload_label(&next))
                .unwrap_or_else(|| format!("nest-{}", i + 1))
        } else {
            step.replace('\\', "/")
                .rsplit('/')
                .next()
                .unwrap_or(step)
                .to_string()
        };
        trail.push(label);
        cur = next;
    }

    view_mark_bytes(&cur, trail, seen, pass)
}

fn payload_label(data: &[u8]) -> Option<String> {
    match kind_of_bytes(data) {
        NestKind::DirPack => Some("folder.sg1".into()),
        NestKind::Work | NestKind::Mark => {
            let tmp = std::env::temp_dir().join(format!("sigil-nest-lbl-{}", std::process::id()));
            let _ = fs::write(&tmp, data);
            let n = crate::work::payload_name(&tmp).ok().filter(|s| !s.is_empty());
            let _ = fs::remove_file(&tmp);
            n.or_else(|| {
                locate_header(data)
                    .ok()
                    .map(|(h, _, _)| h.name)
                    .filter(|s| !s.is_empty())
            })
        }
        NestKind::Leaf => None,
    }
}

fn pass_for(rel: &str, default: Option<&str>, wards: &[(String, String)]) -> Option<String> {
    for (p, w) in wards {
        if p == rel {
            return Some(w.clone());
        }
    }
    default.map(|s| s.to_string())
}

/// One descent step from current bytes + segment → next nest layer bytes (still a seal or leaf).
fn descend_one(
    cur: &[u8],
    step: &str,
    pass: Option<&str>,
    wards: &[(String, String)],
    trail: &[String],
) -> Result<Vec<u8>> {
    let kind = kind_of_bytes(cur);
    match kind {
        NestKind::DirPack => {
            if step.is_empty() || step == "." {
                return Err(crate::Error::Msg(
                    "folder pack needs a path segment (e.g. --into inner.sg1)".into(),
                ));
            }
            // Write cur to temp only to reuse streaming reader by path.
            let tmp = std::env::temp_dir().join(format!(
                "sigil-nest-dir-{}-{}",
                std::process::id(),
                trail.len()
            ));
            fs::write(&tmp, cur).map_err(|e| crate::Error::Msg(e.to_string()))?;
            let star = read_dir_entry_star(&tmp, step);
            let _ = fs::remove_file(&tmp);
            let star = star?;
            let file_pass = pass_for(step, pass, wards);
            // Star is itself a seal of the file bytes. Unseal → payload (may be nested .sg1).
            if star.starts_with(&WORK_MAGIC) {
                let tmp2 = std::env::temp_dir().join(format!(
                    "sigil-nest-wk2-{}-{}",
                    std::process::id(),
                    trail.len()
                ));
                fs::write(&tmp2, &star).map_err(|e| crate::Error::Msg(e.to_string()))?;
                let out = tmp2.with_extension("bin");
                crate::work::unseal_path(&tmp2, &out, file_pass.as_deref(), &[])?;
                let plain = fs::read(&out).map_err(|e| crate::Error::Msg(e.to_string()))?;
                let _ = fs::remove_file(&tmp2);
                let _ = fs::remove_file(&out);
                Ok(plain)
            } else {
                unseal_ex(&star, file_pass.as_deref(), &[])
            }
        }
        NestKind::Mark => {
            // Unwrap one seal layer. step may be ".", payload name, or empty.
            let (h, _, _) = locate_header(cur)?;
            if !step.is_empty()
                && step != "."
                && !h.name.is_empty()
                && step != h.name
                && !h.name.ends_with(step)
                && !looks_like_nest_name(step)
            {
                // Allow --into . / --into <header-name> / --into something.sg1
                // Reject unrelated paths so typos fail loudly.
                if !h.name.contains(step) {
                    return Err(crate::Error::Msg(format!(
                        "mark payload is '{}' — use --into . or that name (trail: {})",
                        h.name,
                        trail.join(" → ")
                    )));
                }
            }
            let plain = unseal_ex(cur, pass, &[])?;
            if !is_nestable_bytes(&plain) && step != "." && !step.is_empty() {
                // User asked to descend into a leaf by name — still return leaf bytes.
                return Ok(plain);
            }
            if !is_nestable_bytes(&plain) {
                return Err(crate::Error::Msg(format!(
                    "payload is not a nested seal (trail: {})",
                    trail.join(" → ")
                )));
            }
            Ok(plain)
        }
        NestKind::Work => Err(crate::Error::Msg(
            "work packs are not nested folder seals; De-scribe the work pack instead".into(),
        )),
        NestKind::Leaf => Err(crate::Error::Msg(format!(
            "cannot descend into a leaf (trail: {})",
            trail.join(" → ")
        ))),
    }
}

/// Extract only the leaf (or nested mark bytes) reached by `into` into `dest`.
/// Durable outer `.sg1` is never modified. Temp-friendly: caller owns `dest`.
pub fn path_extract(
    mark: &Path,
    into: &[String],
    dest: &Path,
    pass: Option<&str>,
    wards: &[(String, String)],
    max_depth: usize,
) -> Result<(PathBuf, Vec<String>)> {
    let view = path_walk(mark, into, pass, wards, max_depth)?;
    // Re-walk to get final bytes (path_walk does not return them).
    let max_depth = max_depth.min(MAX_NEST_DEPTH);
    let root_bytes = fs::read(mark).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let mut cur = root_bytes;
    let trail = view.trail.clone();
    let mut seen = Vec::new();
    push_seen(&mut seen, mark_id(&cur))?;
    for (i, step) in into.iter().enumerate() {
        check_depth(i + 1, max_depth)?;
        let step = step.trim().trim_start_matches("./");
        let next = descend_one(&cur, step, pass, wards, &trail[.. i + 1.min(trail.len())])?;
        push_seen(&mut seen, mark_id(&next))?;
        cur = next;
    }
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| crate::Error::Msg(e.to_string()))?;
    }
    fs::write(dest, &cur).map_err(|e| crate::Error::Msg(e.to_string()))?;
    Ok((dest.to_path_buf(), trail))
}

/// Convenience: list outer mark only.
pub fn path_list(
    mark: &Path,
    pass: Option<&str>,
    max_depth: usize,
) -> Result<PathView> {
    path_walk(mark, &[], pass, &[], max_depth)
}

/// Public cycle helper for tests.
pub fn refuse_if_cycle(seen: &[[u8; 32]], next: &[u8; 32]) -> Result<()> {
    if seen.iter().any(|s| s == next) {
        return Err(crate::Error::Msg(format!(
            "nest cycle refused (mark {} already on the trail)",
            &hex32(next)[..16]
        )));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{seal, Mode};
    fn tmp(name: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "sigil-nest-{}-{}-{}",
            name,
            std::process::id(),
            std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .unwrap()
                .subsec_nanos()
        ));
        let _ = fs::remove_dir_all(&d);
        fs::create_dir_all(&d).unwrap();
        d
    }

    #[test]
    fn nest_folder_with_inner_sg1() {
        let dir = tmp("folder");
        let inner_src = dir.join("notes.txt");
        fs::write(&inner_src, b"deep notes").unwrap();
        let inner_sg1 = dir.join("inner.sg1");
        let sealed = seal(b"deep notes", Mode::Reflection, None, "notes.txt", false).unwrap();
        fs::write(&inner_sg1, &sealed).unwrap();

        let tree = dir.join("tree");
        fs::create_dir_all(&tree).unwrap();
        fs::write(tree.join("readme.txt"), b"top").unwrap();
        fs::copy(&inner_sg1, tree.join("inner.sg1")).unwrap();

        let outer = dir.join("outer.sg1");
        crate::folder::inscribe_dir(
            &tree,
            &outer,
            Mode::Reflection,
            None,
            "",
            &[],
            4 * 1024 * 1024,
            &[],
        )
        .unwrap();

        let view = path_list(&outer, None, MAX_NEST_DEPTH).unwrap();
        assert_eq!(view.kind, NestKind::DirPack);
        assert!(view.breadcrumb().contains("outer.sg1"), "{}", view.breadcrumb());
        let nest = view.entries.iter().find(|e| e.path == "inner.sg1");
        assert!(nest.is_some(), "{:?}", view.entries);
        assert!(nest.unwrap().nest, "inner.sg1 should be flagged nest");
        let plain = view.entries.iter().find(|e| e.path == "readme.txt");
        assert!(plain.is_some());
        assert!(!plain.unwrap().nest);

        let into = vec!["inner.sg1".into()];
        let inner_view = path_walk(&outer, &into, None, &[], MAX_NEST_DEPTH).unwrap();
        assert!(
            inner_view.breadcrumb().contains("inner.sg1"),
            "{}",
            inner_view.breadcrumb()
        );
        assert!(inner_view.nest_payload || inner_view.kind == NestKind::Mark);
        assert_eq!(inner_view.kind, NestKind::Mark);

        // Extract leaf bytes of the nested mark (still a seal) then unseal
        let dest = dir.join("extracted.sg1");
        path_extract(&outer, &into, &dest, None, &[], MAX_NEST_DEPTH).unwrap();
        let got = crate::unseal(&fs::read(&dest).unwrap(), None).unwrap();
        assert_eq!(got, b"deep notes");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn nest_single_file_payload_is_mark() {
        let dir = tmp("wrap");
        let inner = seal(b"wrapped leaf", Mode::Glyph, None, "leaf.txt", false).unwrap();
        let wrap = seal(&inner, Mode::Glyph, None, "inner.sg1", false).unwrap();
        let path = dir.join("wrap.sg1");
        fs::write(&path, &wrap).unwrap();

        let view = path_list(&path, None, MAX_NEST_DEPTH).unwrap();
        assert_eq!(view.kind, NestKind::Mark);
        assert!(view.nest_payload, "payload should be detected as nest");

        let into = vec![".".into()];
        let inner_view = path_walk(&path, &into, None, &[], MAX_NEST_DEPTH).unwrap();
        assert_eq!(inner_view.kind, NestKind::Mark);
        assert!(!inner_view.nest_payload);
        assert!(
            inner_view.breadcrumb().contains("wrap.sg1"),
            "{}",
            inner_view.breadcrumb()
        );

        let dest = dir.join("inner.sg1");
        path_extract(&path, &into, &dest, None, &[], MAX_NEST_DEPTH).unwrap();
        assert_eq!(crate::unseal(&fs::read(&dest).unwrap(), None).unwrap(), b"wrapped leaf");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn nest_depth_cap() {
        let dir = tmp("depth");
        // Build a chain of single-file wraps: L0 = leaf seal, L1 wraps L0, ...
        let mut bytes = seal(b"bottom", Mode::Glyph, None, "bottom.txt", false).unwrap();
        for i in 0..5 {
            bytes = seal(&bytes, Mode::Glyph, None, &format!("L{i}.sg1"), false).unwrap();
        }
        let top = dir.join("top.sg1");
        fs::write(&top, &bytes).unwrap();

        // 5 wraps → need 5 --into . to reach the leaf seal; depth 2 should fail on 3rd
        let into: Vec<String> = (0..3).map(|_| ".".into()).collect();
        let err = path_walk(&top, &into, None, &[], 2).unwrap_err();
        assert!(
            err.to_string().contains("depth") || err.to_string().contains("cap"),
            "{err}"
        );

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn nest_cycle_refused() {
        let a = [1u8; 32];
        let b = [2u8; 32];
        assert!(refuse_if_cycle(&[a], &b).is_ok());
        let err = refuse_if_cycle(&[a, b], &a).unwrap_err();
        assert!(err.to_string().contains("cycle"), "{err}");

        // Construct a real walk cycle: outer SGDR whose nested entry unseals to the same outer bytes.
        let dir = tmp("cycle");
        let tree = dir.join("tree");
        fs::create_dir_all(&tree).unwrap();
        fs::write(tree.join("a.txt"), b"x").unwrap();
        let outer = dir.join("outer.sg1");
        crate::folder::inscribe_dir(
            &tree,
            &outer,
            Mode::Glyph,
            None,
            "",
            &[],
            4 * 1024 * 1024,
            &[],
        )
        .unwrap();
        let outer_bytes = fs::read(&outer).unwrap();
        // Wrap outer bytes as a nested .sg1, then build a cage pack containing that nest
        // plus we will walk cage → mirror.sg1 (= outer) → and if we could put cage inside
        // outer we'd cycle. Instead: seal outer as mirror, put in cage; then seal cage
        // and place THAT as the payload of a mark that equals something on the trail.
        let mirror = seal(&outer_bytes, Mode::Glyph, None, "mirror.sg1", false).unwrap();
        let cage_src = dir.join("cage_src");
        fs::create_dir_all(&cage_src).unwrap();
        fs::write(cage_src.join("mirror.sg1"), &mirror).unwrap();
        let cage = dir.join("cage.sg1");
        crate::folder::inscribe_dir(
            &cage_src,
            &cage,
            Mode::Glyph,
            None,
            "",
            &[],
            4 * 1024 * 1024,
            &[],
        )
        .unwrap();
        // cage → mirror.sg1 yields outer SGDR. Manually feed outer's bytes as if descending
        // again into a nest that is the cage itself:
        let cage_bytes = fs::read(&cage).unwrap();
        let mut seen = vec![mark_id(&cage_bytes), mark_id(&outer_bytes)];
        // Re-entering cage bytes should refuse
        let err = push_seen(&mut seen, mark_id(&cage_bytes)).unwrap_err();
        assert!(err.to_string().contains("cycle"), "{err}");

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn nest_breadcrumb_string() {
        let dir = tmp("crumb");
        let tree = dir.join("tree");
        fs::create_dir_all(&tree).unwrap();
        let inner = seal(b"z", Mode::Reflection, None, "z.txt", false).unwrap();
        fs::write(tree.join("inner.sg1"), &inner).unwrap();
        let outer = dir.join("outer.sg1");
        crate::folder::inscribe_dir(
            &tree,
            &outer,
            Mode::Reflection,
            None,
            "",
            &[],
            4 * 1024 * 1024,
            &[],
        )
        .unwrap();
        let v = path_walk(&outer, &["inner.sg1".into()], None, &[], 32).unwrap();
        let bc = v.breadcrumb();
        assert!(bc.contains('→'), "{bc}");
        assert!(bc.contains("outer.sg1"), "{bc}");
        assert!(bc.contains("inner.sg1"), "{bc}");
        let _ = fs::remove_dir_all(&dir);
    }
}
