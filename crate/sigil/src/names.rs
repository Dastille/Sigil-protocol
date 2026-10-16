//! Human-readable names for container members.
//!
//! Inside a `name.sigil/` the stars are filed by fingerprint (`stars/ab/<sha256>.sg1`) and the
//! versions as `versions/vN.sg1`. This module maps those back to the names the owner knows —
//! list names from the constellation card (`docs/a.txt`), `notes.txt@v3` from the CHART —
//! for `sigil ls`, `sigil mount` and the breadcrumb trail. Purely a view: nothing on disk
//! changes and unreadable (locked) cards simply fall back to the plain file names.

use std::path::{Path, PathBuf};

use crate::keys::Identity;
use crate::Result;

fn err(s: impl Into<String>) -> crate::Error {
    crate::Error::Msg(s.into())
}

/// One list entry of a constellation.
#[derive(Clone, Debug)]
pub struct SkyEntry {
    /// Name on the list (`docs/a.txt`).
    pub name: String,
    pub digest: [u8; 32],
    pub size: u64,
    /// The star file for this name, when it is on disk.
    pub star: Option<PathBuf>,
}

/// A constellation directory (container, old flat folder, or a name that resolves to
/// `NAME.sigil/`) when `input` is one.
pub fn sky_dir(input: &Path) -> Option<PathBuf> {
    let d = crate::container::sky_for_read(input);
    (d.is_dir() && crate::constellation::find_card(&d).is_some()).then_some(d)
}

/// The chart dir (`.sigil` / `.sgv`) when `input` names a vault *folder*, or a live path that
/// no longer exists on disk. A live path that exists is a plain file/folder, not a listing.
pub fn vault_dir(input: &Path) -> Option<PathBuf> {
    if sky_dir(input).is_some() {
        return None;
    }
    let (live, vdir) = crate::vault::resolve_paths(input).ok()?;
    if !vdir.join(crate::vault::CHART_NAME).is_file() {
        return None;
    }
    let is_chart_dir = input.is_dir()
        && input
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| {
                n.ends_with(crate::vault::VAULT_SUFFIX)
                    || n.ends_with(crate::container::CONTAINER_SUFFIX)
            })
            .unwrap_or(false);
    (is_chart_dir || !live.exists()).then_some(vdir)
}

/// List a constellation by name (needs `pass` / `identities` for a locked card).
pub fn sky_entries(
    sky: &Path,
    pass: Option<&str>,
    identities: &[Identity],
) -> Result<Vec<SkyEntry>> {
    let card = crate::constellation::find_card(sky)
        .ok_or_else(|| err("no constellation card in this folder"))?;
    let chart =
        crate::constellation::load_chart_from_mark(&card, pass, identities).map_err(|e| {
            err(format!(
                "{e} (locked card: give --pass / --identity to see names)"
            ))
        })?;
    let by_digest = crate::constellation::index_stars(sky, Some(&card));
    let mut out: Vec<SkyEntry> = chart
        .members
        .iter()
        .map(|m| SkyEntry {
            name: m.name.clone(),
            digest: m.digest,
            size: m.orig_len,
            star: if m.bytes.is_empty() {
                crate::constellation::find_member_star(sky, m, &by_digest)
            } else {
                None
            },
        })
        .collect();
    out.sort_by(|a, b| a.name.cmp(&b.name));
    Ok(out)
}

/// Text listing of a constellation, optionally narrowed to names under `prefix`.
pub fn render_sky(sky: &Path, entries: &[SkyEntry], prefix: &str) -> String {
    let mut s = format!(
        "{}  constellation  {} name(s)\n",
        sky.display(),
        entries.len()
    );
    let shown: Vec<&SkyEntry> = entries
        .iter()
        .filter(|e| prefix.is_empty() || e.name.starts_with(prefix))
        .collect();
    let w = shown.iter().map(|e| e.name.len()).max().unwrap_or(0);
    for e in &shown {
        let state = if e.star.is_some() {
            String::new()
        } else {
            "  MISSING star".to_string()
        };
        s.push_str(&format!(
            "  {:<w$}  {:>12} bytes  {}{}\n",
            e.name,
            e.size,
            &crate::hex32(&e.digest)[..8],
            state,
            w = w
        ));
    }
    s
}

/// `name@vN` label for a vault version.
pub fn version_label(chart_name: &str, n: u32) -> String {
    format!("{chart_name}@v{n}")
}

/// Text listing of a vault's versions with `name@vN` names.
pub fn render_vault(vdir: &Path) -> Result<String> {
    let chart = crate::vault::load_chart(vdir)?;
    let name = chart
        .live
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("vault")
        .to_string();
    let mut s = format!(
        "{}  vault  tip=v{}  retention={}  {} version(s)\n",
        vdir.display(),
        chart.tip,
        chart.retention.label(),
        chart.versions.len()
    );
    let mut vs = chart.versions.clone();
    vs.sort_by_key(|v| v.n);
    for v in vs {
        let present = crate::vault::seal_path_in(vdir, &v.seal).is_file();
        s.push_str(&format!(
            "  {:<24} {:>12} bytes  {}{}{}\n",
            version_label(&name, v.n),
            v.size,
            &crate::hex32(&v.digest)[..8],
            if v.n == chart.tip { "  (tip)" } else { "" },
            if present { "" } else { "  MISSING seal" }
        ));
    }
    Ok(s)
}

/// Parse `v3`, `@v3`, `@3`, `3` or `name@v3`.
pub fn parse_version_ref(s: &str) -> Option<u32> {
    let t = s.rsplit('@').next().unwrap_or(s);
    let t = t.strip_suffix(".sg1").unwrap_or(t);
    t.strip_prefix('v').unwrap_or(t).parse().ok()
}

/// The seal path of version `n` inside a chart dir, if the CHART lists it.
pub fn version_seal(vdir: &Path, n: u32) -> Result<PathBuf> {
    let chart = crate::vault::load_chart(vdir)?;
    let v = chart.versions.iter().find(|v| v.n == n).ok_or_else(|| {
        err(format!(
            "no version v{n} in this vault (see `sigil ls` of the container)"
        ))
    })?;
    Ok(crate::vault::seal_path_in(vdir, &v.seal))
}

/// A friendly breadcrumb label for a mark that lives inside a container:
/// `stars/ab/<fp>.sg1` → its list name, `versions/vN.sg1` → `name@vN`. `None` when the file is
/// not inside a container or the card cannot be read (the caller keeps the file name).
pub fn friendly_label(mark: &Path, pass: Option<&str>, identities: &[Identity]) -> Option<String> {
    let abs = mark.canonicalize().ok()?;
    let file = abs.file_name()?.to_str()?.to_string();
    let parent = abs.parent()?;
    // versions/vN.sg1
    if parent.file_name().and_then(|n| n.to_str()) == Some(crate::container::VERSIONS_DIR) {
        let root = parent.parent()?;
        if crate::container::is_container(root) {
            let n = crate::gc::is_version_seal_name(&file)
                .then(|| parse_version_ref(&file))
                .flatten()?;
            let chart = crate::vault::load_chart(root).ok()?;
            let name = chart.live.file_name()?.to_str()?.to_string();
            return Some(version_label(&name, n));
        }
        return None;
    }
    // stars/<xx>/<fp>.sg1 (or stars/by-name/…)
    let root = parent.parent()?.parent()?;
    if parent.parent()?.file_name().and_then(|n| n.to_str()) != Some(crate::container::STARS_DIR)
        || !crate::container::is_container(root)
    {
        return None;
    }
    let card = crate::constellation::find_card(root)?;
    let chart = crate::constellation::load_chart_from_mark(&card, pass, identities).ok()?;
    let digest: [u8; 32] = if crate::work::is_work_pack(&abs) {
        hex::decode(file.strip_suffix(".sg1")?)
            .ok()?
            .try_into()
            .ok()?
    } else {
        crate::constellation::peek_digest(&abs)?
    };
    let names: Vec<&str> = chart
        .members
        .iter()
        .filter(|m| m.digest == digest)
        .map(|m| m.name.as_str())
        .collect();
    match names.len() {
        0 => None,
        1 => Some(names[0].to_string()),
        _ => Some(names.join(" = ")),
    }
}
