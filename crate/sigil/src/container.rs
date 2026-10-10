//! Tidy container: one `name.sigil/` folder per thing (vault or constellation).
//!
//! ```text
//! notes.txt.sigil/            (vault)            Sky.sigil/          (constellation)
//!   CONTAINER                                      CONTAINER
//!   CHART                                          Sky.sg1          (card)
//!   versions/v1.sg1 v2.sg1 …                       stars/ab/<fp>.sg1
//!   cold/            (optional prune target)       Sky.sga          (optional atlas)
//! ```
//!
//! `CONTAINER` is a tiny `key=value` manifest; the first line is `sigil-container=1`.
//! Unknown keys are ignored (additive). A higher major version is refused clearly.
//! Old layouts (`<live>.sgv/` sidecars, flat constellation folders) keep opening forever;
//! `sigil tidy` moves them into a container without rewriting any `.sg1` byte.
//! See `docs/CONTAINER.md`.

use std::collections::BTreeMap;
use std::fs;
use std::path::{Path, PathBuf};

use crate::Result;

pub const CONTAINER_SUFFIX: &str = ".sigil";
pub const CONTAINER_FILE: &str = "CONTAINER";
pub const CONTAINER_VERSION: u32 = 1;
pub const STARS_DIR: &str = "stars";
pub const VERSIONS_DIR: &str = "versions";
pub const COLD_DIR: &str = "cold";
/// Stars that could not be filed by fingerprint (no readable digest) keep their old name here.
pub const BY_NAME_DIR: &str = "by-name";

fn err(s: impl Into<String>) -> crate::Error {
    crate::Error::Msg(s.into())
}

#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Manifest {
    pub version: u32,
    /// `vault` or `constellation` (unknown kinds are kept as-is).
    pub kind: String,
    /// Human name of the thing (`notes.txt`, `Sky`).
    pub name: String,
    /// Unknown keys, preserved on rewrite.
    pub extra: BTreeMap<String, String>,
}

impl Manifest {
    pub fn new(kind: &str, name: &str) -> Self {
        Manifest {
            version: CONTAINER_VERSION,
            kind: kind.into(),
            name: name.into(),
            extra: BTreeMap::new(),
        }
    }

    pub fn render(&self) -> String {
        let mut s = format!(
            "sigil-container={}\nkind={}\nname={}\n",
            self.version, self.kind, self.name
        );
        for (k, v) in &self.extra {
            s.push_str(&format!("{k}={v}\n"));
        }
        s
    }

    pub fn parse(text: &str) -> Result<Self> {
        let mut version = None;
        let mut kind = String::new();
        let mut name = String::new();
        let mut extra = BTreeMap::new();
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((k, v)) = line.split_once('=') else { continue };
            match k {
                "sigil-container" => {
                    version = Some(
                        v.trim()
                            .parse::<u32>()
                            .map_err(|_| err(format!("bad sigil-container version: {v}")))?,
                    )
                }
                "kind" => kind = v.to_string(),
                "name" => name = v.to_string(),
                _ => {
                    extra.insert(k.to_string(), v.to_string());
                }
            }
        }
        let version = version.ok_or_else(|| err("not a sigil CONTAINER (missing sigil-container=)"))?;
        if version > CONTAINER_VERSION {
            return Err(err(format!(
                "container format {version} is newer than this sigil understands ({CONTAINER_VERSION}); upgrade sigil"
            )));
        }
        Ok(Manifest { version, kind, name, extra })
    }
}

/// True when `path` ends in `.sigil`.
pub fn has_suffix(path: &Path) -> bool {
    path.components()
        .as_path()
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.ends_with(CONTAINER_SUFFIX) && n.len() > CONTAINER_SUFFIX.len())
        .unwrap_or(false)
}

/// `path` + `.sigil` (trailing slash ignored).
pub fn with_suffix(path: &Path) -> PathBuf {
    let p = path.components().as_path();
    let mut s = p.as_os_str().to_os_string();
    s.push(CONTAINER_SUFFIX);
    PathBuf::from(s)
}

/// Strip `.sigil` from a name.
pub fn strip_suffix(name: &str) -> &str {
    name.strip_suffix(CONTAINER_SUFFIX).filter(|s| !s.is_empty()).unwrap_or(name)
}

/// A directory holding a `CONTAINER` manifest.
pub fn is_container(dir: &Path) -> bool {
    dir.join(CONTAINER_FILE).is_file()
}

pub fn read_manifest(dir: &Path) -> Result<Manifest> {
    let text = fs::read_to_string(dir.join(CONTAINER_FILE))
        .map_err(|e| err(format!("read {}: {e}", dir.join(CONTAINER_FILE).display())))?;
    Manifest::parse(&text)
}

/// Create `dir` (if needed) and write its manifest unless one is already there.
pub fn ensure(dir: &Path, kind: &str, name: &str) -> Result<()> {
    fs::create_dir_all(dir).map_err(|e| err(e.to_string()))?;
    if is_container(dir) {
        read_manifest(dir)?;
        return Ok(());
    }
    write_manifest(dir, &Manifest::new(kind, name))
}

pub fn write_manifest(dir: &Path, m: &Manifest) -> Result<()> {
    let part = dir.join(format!("{CONTAINER_FILE}.part"));
    fs::write(&part, m.render()).map_err(|e| err(e.to_string()))?;
    fs::rename(&part, dir.join(CONTAINER_FILE)).map_err(|e| err(e.to_string()))
}

/// Sharded star path: `stars/ab/<64-hex>.sg1`.
pub fn star_path(root: &Path, digest: &[u8; 32]) -> PathBuf {
    let h = hex::encode(digest);
    root.join(STARS_DIR).join(&h[..2]).join(format!("{h}.sg1"))
}

/// Pick the directory a constellation lives in for `sigil constellation add SKY`:
/// an existing folder (old flat or container) is used as-is; else an existing
/// `SKY.sigil` container; else a new container at `SKY.sigil` (or `SKY` if it already
/// ends in `.sigil`).
pub fn sky_for_add(sky: &Path) -> PathBuf {
    if sky.is_dir() || has_suffix(sky) {
        return sky.to_path_buf();
    }
    with_suffix(sky)
}

/// Resolve a constellation path for reading: `SKY` falls back to `SKY.sigil/`.
pub fn sky_for_read(sky: &Path) -> PathBuf {
    if !sky.exists() {
        let c = with_suffix(sky);
        if is_container(&c) {
            return c;
        }
    }
    sky.to_path_buf()
}

/// True when the folder should get the container layout for new writes:
/// it already is a container, or it is brand new / empty (no flat card yet).
pub fn new_sky_is_container(sky: &Path) -> bool {
    if is_container(sky) {
        return true;
    }
    match fs::read_dir(sky) {
        Ok(mut rd) => rd.next().is_none(),
        Err(_) => true,
    }
}

// ---------------------------------------------------------------------------
// `sigil tidy`: move an old layout into a container. Copy → verify → rename → remove.
// ---------------------------------------------------------------------------

/// Test-only fault injection (lets tests prove a failed tidy leaves the original intact).
#[doc(hidden)]
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum TidyFault {
    /// Abort with an error after this many files were copied into staging.
    FailAfterCopies(usize),
    /// Flip a byte in the first copied `.sg1` so fingerprint verification must refuse.
    CorruptFirstStar,
}

#[derive(Default)]
pub struct TidyOpts<'a> {
    pub dry_run: bool,
    /// Optional keys: when the card / chart opens, tidy also proves no star went missing.
    pub pass: Option<&'a str>,
    pub identities: &'a [crate::Identity],
    #[doc(hidden)]
    pub fault: Option<TidyFault>,
}

#[derive(Debug, Default)]
pub struct TidyReport {
    /// `vault` or `constellation`; empty when already tidy.
    pub kind: String,
    pub from: PathBuf,
    pub to: PathBuf,
    /// (old path, path inside the container) for each moved file.
    pub moved: Vec<(PathBuf, PathBuf)>,
    /// Files tidy did not touch (not part of the vault / constellation).
    pub left: Vec<PathBuf>,
    pub dry_run: bool,
    pub already: bool,
    /// True when the list / chart was opened and every star / version was found in the container.
    pub list_checked: bool,
}

impl TidyReport {
    pub fn render(&self) -> String {
        let mut s = String::new();
        if self.already {
            s.push_str(&format!("already tidy: {}\n", self.to.display()));
            return s;
        }
        let verb = if self.dry_run { "would move" } else { "moved" };
        s.push_str(&format!(
            "tidy {} {} → {}\n",
            self.kind,
            self.from.display(),
            self.to.display()
        ));
        for (a, b) in &self.moved {
            let rel = b.strip_prefix(&self.to).unwrap_or(b);
            s.push_str(&format!("  {verb} {} → {}\n", a.display(), rel.display()));
        }
        for l in &self.left {
            s.push_str(&format!("  left alone: {}\n", l.display()));
        }
        s.push_str(&format!(
            "{} {} file{}{}{}\n",
            if self.dry_run { "dry run:" } else { "done:" },
            self.moved.len(),
            if self.moved.len() == 1 { "" } else { "s" },
            if self.dry_run { "" } else { ", fingerprints verified" },
            if self.list_checked { ", list checked" } else { "" },
        ));
        s
    }
}

fn file_name_str(p: &Path) -> String {
    p.file_name().and_then(|n| n.to_str()).unwrap_or("").to_string()
}

fn is_version_seal_name(n: &str) -> bool {
    n.strip_prefix('v')
        .and_then(|r| r.strip_suffix(".sg1"))
        .map(|d| !d.is_empty() && d.bytes().all(|b| b.is_ascii_digit()))
        .unwrap_or(false)
}

fn sorted_entries(dir: &Path) -> Result<Vec<PathBuf>> {
    let mut v: Vec<PathBuf> = fs::read_dir(dir)
        .map_err(|e| err(format!("read {}: {e}", dir.display())))?
        .flatten()
        .map(|e| e.path())
        .collect();
    v.sort();
    Ok(v)
}

fn walk_rel(root: &Path, dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
    for p in sorted_entries(dir)? {
        if p.is_dir() {
            walk_rel(root, &p, out)?;
        } else {
            out.push(p.strip_prefix(root).unwrap_or(&p).to_path_buf());
        }
    }
    Ok(())
}

/// Plan: (source file, path relative to the container root).
struct Plan {
    kind: &'static str,
    name: String,
    from: PathBuf,
    to: PathBuf,
    items: Vec<(PathBuf, PathBuf)>,
    left: Vec<PathBuf>,
    /// Old folder removed when empty after the move.
    old_dir: PathBuf,
}

fn plan_vault(sgv: &Path) -> Result<Plan> {
    let live_name = file_name_str(sgv);
    let stem = live_name
        .strip_suffix(crate::vault::VAULT_SUFFIX)
        .ok_or_else(|| err("vault chart dir must end with .sgv"))?
        .to_string();
    let to = sgv.parent().unwrap_or(Path::new(".")).join(format!("{stem}{CONTAINER_SUFFIX}"));
    let mut rels = Vec::new();
    walk_rel(sgv, sgv, &mut rels)?;
    let mut items = Vec::new();
    for rel in rels {
        let src = sgv.join(&rel);
        let top = rel.components().count() == 1;
        let n = file_name_str(&rel);
        let dest = if top && is_version_seal_name(&n) {
            Path::new(VERSIONS_DIR).join(&n)
        } else {
            rel.clone()
        };
        items.push((src, dest));
    }
    Ok(Plan {
        kind: "vault",
        name: stem,
        from: sgv.to_path_buf(),
        to,
        items,
        left: Vec::new(),
        old_dir: sgv.to_path_buf(),
    })
}

fn plan_constellation(dir: &Path) -> Result<Plan> {
    use crate::constellation::{find_card, is_atlas_file, is_constellation_mark};
    let name = file_name_str(dir);
    if has_suffix(dir) {
        return Err(err(format!(
            "{} ends in .sigil but has no CONTAINER; rename it first",
            dir.display()
        )));
    }
    let to = with_suffix(dir);
    let card = find_card(dir).ok_or_else(|| err("no constellation card in this folder"))?;
    let mut items = Vec::new();
    let mut left = Vec::new();
    let mut taken = std::collections::HashSet::new();
    for p in sorted_entries(dir)? {
        let n = file_name_str(&p);
        if p.is_dir() || n.starts_with('.') || n.ends_with(".part") {
            left.push(p);
            continue;
        }
        let ext = p.extension().and_then(|x| x.to_str()).unwrap_or("");
        if p == card || (ext == "sg1" && is_constellation_mark(&p)) || (ext == "sga" && is_atlas_file(&p)) {
            items.push((p.clone(), PathBuf::from(&n)));
            continue;
        }
        if ext != "sg1" {
            left.push(p);
            continue;
        }
        let digest = if crate::work::is_work_pack(&p) {
            None
        } else {
            crate::locate_header(&{
                let mut buf = vec![0u8; 96 * 1024];
                let mut f = fs::File::open(&p).map_err(|e| err(e.to_string()))?;
                let k = std::io::Read::read(&mut f, &mut buf).map_err(|e| err(e.to_string()))?;
                buf.truncate(k);
                buf
            })
            .ok()
            .map(|(h, _, _)| h.digest)
        };
        let rel = match digest {
            Some(d) => {
                let r = star_path(Path::new(""), &d);
                if taken.insert(r.clone()) {
                    r
                } else {
                    Path::new(STARS_DIR).join(BY_NAME_DIR).join(&n)
                }
            }
            None => Path::new(STARS_DIR).join(BY_NAME_DIR).join(&n),
        };
        items.push((p, rel));
    }
    Ok(Plan {
        kind: "constellation",
        name: crate::container::strip_suffix(&name).to_string(),
        from: dir.to_path_buf(),
        to,
        items,
        left,
        old_dir: dir.to_path_buf(),
    })
}

fn sha_file(p: &Path) -> Result<[u8; 32]> {
    crate::sha256_path(p)
}

fn copy_verified(src: &Path, dest: &Path) -> Result<()> {
    if let Some(parent) = dest.parent() {
        fs::create_dir_all(parent).map_err(|e| err(e.to_string()))?;
    }
    fs::copy(src, dest).map_err(|e| err(format!("copy {}: {e}", src.display())))?;
    fs::File::open(dest)
        .and_then(|f| f.sync_all())
        .map_err(|e| err(e.to_string()))?;
    Ok(())
}

/// Migrate an old-layout vault (`live` or `live.sgv/`) or flat constellation folder into
/// a `name.sigil/` container. Never rewrites `.sg1` bytes: files are copied, their
/// SHA-256 fingerprints compared, the staging folder renamed into place, and only then
/// are the old files removed. Any failure before the rename leaves the original untouched.
pub fn tidy(path: &Path, opts: &TidyOpts<'_>) -> Result<TidyReport> {
    let path = path.components().as_path().to_path_buf();
    // Already a container?
    for cand in [path.clone(), with_suffix(&path)] {
        if is_container(&cand) {
            let legacy = crate::vault::legacy_vault_dir_for(&path);
            if !legacy.join(crate::vault::CHART_NAME).is_file() {
                read_manifest(&cand)?;
                return Ok(TidyReport { to: cand, already: true, dry_run: opts.dry_run, ..Default::default() });
            }
            return Err(err(format!(
                "both {} and {} exist; refusing to merge (move one aside)",
                cand.display(),
                legacy.display()
            )));
        }
    }
    let name = file_name_str(&path);
    let sgv = if name.ends_with(crate::vault::VAULT_SUFFIX) {
        Some(path.clone())
    } else {
        let l = crate::vault::legacy_vault_dir_for(&path);
        if l.join(crate::vault::CHART_NAME).is_file() { Some(l) } else { None }
    };
    let plan = if let Some(sgv) = sgv.filter(|s| s.join(crate::vault::CHART_NAME).is_file()) {
        plan_vault(&sgv)?
    } else if path.is_dir() && crate::constellation::find_card(&path).is_some() {
        plan_constellation(&path)?
    } else {
        return Err(err(format!(
            "nothing to tidy at {} (not a vault live path / .sgv chart, nor a constellation folder)",
            path.display()
        )));
    };
    if plan.to.exists() {
        return Err(err(format!("{} already exists; refusing to overwrite", plan.to.display())));
    }
    let mut report = TidyReport {
        kind: plan.kind.into(),
        from: plan.from.clone(),
        to: plan.to.clone(),
        moved: plan.items.iter().map(|(s, r)| (s.clone(), plan.to.join(r))).collect(),
        left: plan.left.clone(),
        dry_run: opts.dry_run,
        ..Default::default()
    };
    if opts.dry_run {
        return Ok(report);
    }

    let parent = plan.to.parent().unwrap_or(Path::new(".")).to_path_buf();
    let staging = parent.join(format!(".tidy-{}", file_name_str(&plan.to)));
    if staging.exists() {
        // Leftover from an interrupted tidy: the original was never touched, start over.
        fs::remove_dir_all(&staging).map_err(|e| err(format!("clear stale {}: {e}", staging.display())))?;
    }
    let result = (|| -> Result<bool> {
        fs::create_dir_all(&staging).map_err(|e| err(e.to_string()))?;
        if plan.kind == "vault" {
            fs::create_dir_all(staging.join(VERSIONS_DIR)).map_err(|e| err(e.to_string()))?;
        }
        write_manifest(&staging, &Manifest::new(plan.kind, &plan.name))?;
        let mut corrupted = false;
        for (i, (src, rel)) in plan.items.iter().enumerate() {
            if let Some(TidyFault::FailAfterCopies(k)) = opts.fault {
                if i == k {
                    return Err(err("injected tidy failure"));
                }
            }
            let dest = staging.join(rel);
            if dest.exists() {
                return Err(err(format!("two files map to {}; refusing", rel.display())));
            }
            copy_verified(src, &dest)?;
            if opts.fault == Some(TidyFault::CorruptFirstStar)
                && !corrupted
                && dest.extension().map(|e| e == "sg1").unwrap_or(false)
            {
                let mut b = fs::read(&dest).map_err(|e| err(e.to_string()))?;
                let k = b.len() / 2;
                b[k] ^= 0xff;
                fs::write(&dest, b).map_err(|e| err(e.to_string()))?;
                corrupted = true;
            }
        }
        // Verify every fingerprint against the original, after all copies are on disk.
        for (src, rel) in &plan.items {
            let a = sha_file(src)?;
            let b = sha_file(&staging.join(rel))?;
            if a != b {
                return Err(err(format!(
                    "fingerprint mismatch for {} after copy; refusing (original untouched)",
                    src.display()
                )));
            }
        }
        // Structural check: the container must open at least as well as the old layout.
        if plan.kind == "vault" {
            let chart = crate::vault::load_chart(&staging)?;
            for v in &chart.versions {
                let p = crate::vault::seal_path_in(&staging, &v.seal);
                let old = crate::vault::seal_path_in(&plan.from, &v.seal);
                if old.is_file() && !p.is_file() {
                    return Err(err(format!("version v{} missing in container; refusing", v.n)));
                }
            }
            Ok(true)
        } else {
            match (
                crate::constellation::missing_in(&plan.from, opts.pass, opts.identities),
                crate::constellation::missing_in(&staging, opts.pass, opts.identities),
            ) {
                (Ok(old), Ok(new)) => {
                    if new.len() > old.len() {
                        return Err(err(format!(
                            "container would miss stars the old folder had ({}); refusing",
                            new.join(", ")
                        )));
                    }
                    Ok(true)
                }
                // Locked card without keys: byte-level verification only.
                _ => Ok(false),
            }
        }
    })();
    let checked = match result {
        Ok(c) => c,
        Err(e) => {
            let _ = fs::remove_dir_all(&staging);
            return Err(e);
        }
    };
    report.list_checked = checked;
    fs::rename(&staging, &plan.to).map_err(|e| {
        let _ = fs::remove_dir_all(&staging);
        err(format!("rename into {}: {e}", plan.to.display()))
    })?;
    // Container is complete and preferred by every reader from here on.
    for (src, _) in &plan.items {
        let _ = fs::remove_file(src);
    }
    remove_empty_dirs(&plan.old_dir);
    if plan.old_dir.exists() && plan.kind == "vault" {
        report.left.push(plan.old_dir.clone());
    }
    Ok(report)
}

fn remove_empty_dirs(dir: &Path) {
    if let Ok(rd) = fs::read_dir(dir) {
        for e in rd.flatten() {
            if e.path().is_dir() {
                remove_empty_dirs(&e.path());
            }
        }
    }
    let _ = fs::remove_dir(dir);
}
