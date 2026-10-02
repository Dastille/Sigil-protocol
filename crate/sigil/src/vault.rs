//! Vault: version tip + drift detect for a live path.
//!
//! Each tracked file gets a sidecar chart dir `<live>.sgv/` holding a `CHART`
//! index and immutable version seals `v1.sg1`, `v2.sg1`, …. New Inscribe =
//! new version entry; tip moves. History is never rewritten inside one seal.
//!
//! Retention: **full** (default, keep all seals) or **light** (newest N hot;
//! older seals archive to a cold kit before leaving the chart). See
//! `docs/VAULT-RETENTION.md`.

use crate::folder::is_dir_pack;
use crate::header::locate_header;
use crate::keys::{Identity, PublicIdentity};
use crate::pieces::mend_bytes;
use crate::{
    hex32, seal_kn_to, sha256, sha256_path, unseal_ex_keys, Mode, Result, DEFAULT_PIECE,
};
use std::fs;
use std::path::{Path, PathBuf};
use std::time::{SystemTime, UNIX_EPOCH};

pub const CHART_NAME: &str = "CHART";
pub const VAULT_SUFFIX: &str = ".sgv";
const CHART_MAGIC: &str = "sigil-vault=1";
/// Sidecar left in a `--export-dir --writable` tree (no passphrases).
pub const DIRTY_NAME: &str = ".sigil-dirty";
const DIRTY_MAGIC: &str = "sigil-dirty=1";

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Drift {
    /// Live SHA-256 matches tip true-name.
    Match,
    /// Live present but digest differs from tip.
    Changed,
    /// Tip seal file missing from the chart dir.
    MissingSeal,
    /// Live path gone (chart still there).
    MissingLive,
    /// No `.sgv` chart for this path.
    MissingVault,
}

impl Drift {
    pub fn label(self) -> &'static str {
        match self {
            Drift::Match => "match",
            Drift::Changed => "changed",
            Drift::MissingSeal => "missing-seal",
            Drift::MissingLive => "missing-live",
            Drift::MissingVault => "missing-vault",
        }
    }
}

#[derive(Clone, Debug)]
pub struct VersionEntry {
    pub n: u32,
    pub seal: String,
    pub digest: [u8; 32],
    pub size: u64,
    pub time: u64,
}

/// How many version seals stay hot in the `.sgv` chart.
///
/// **Full** (default): keep every version — like a Bitcoin full node.
/// **Light**: keep only the newest `keep` versions hot; older seals should
/// move to a cold kit (`--cold`) before leaving the chart — like a pruned node.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RetentionPolicy {
    Full,
    Light { keep: u32 },
}

impl RetentionPolicy {
    pub fn label(self) -> &'static str {
        match self {
            RetentionPolicy::Full => "full",
            RetentionPolicy::Light { .. } => "light",
        }
    }

    pub fn keep(self) -> Option<u32> {
        match self {
            RetentionPolicy::Full => None,
            RetentionPolicy::Light { keep } => Some(keep),
        }
    }
}

impl Default for RetentionPolicy {
    fn default() -> Self {
        RetentionPolicy::Full
    }
}

#[derive(Clone, Debug)]
pub struct Chart {
    pub live: PathBuf,
    pub vault_dir: PathBuf,
    pub tip: u32,
    pub versions: Vec<VersionEntry>,
    pub retention: RetentionPolicy,
}

#[derive(Clone, Debug)]
pub struct TrackReport {
    pub live: PathBuf,
    pub vault_dir: PathBuf,
    pub version: u32,
    pub digest: [u8; 32],
    pub size: u64,
}

#[derive(Clone, Debug)]
pub struct StatusReport {
    pub live: PathBuf,
    pub vault_dir: PathBuf,
    pub tip: u32,
    pub drift: Drift,
    pub live_digest: Option<[u8; 32]>,
    pub tip_digest: Option<[u8; 32]>,
    pub tip_size: Option<u64>,
}

#[derive(Clone, Debug)]
pub struct CommitReport {
    pub version: u32,
    pub digest: [u8; 32],
    pub size: u64,
    pub skipped: bool,
}

#[derive(Clone, Debug)]
pub struct RestoreReport {
    pub version: u32,
    pub digest: [u8; 32],
    pub size: u64,
    pub path: PathBuf,
    pub mended: bool,
}

#[derive(Clone, Debug)]
pub struct PruneReport {
    pub removed: Vec<u32>,
    pub kept: u32,
    pub tip: u32,
    /// Cold kit root used when pruning (if any).
    pub cold_dir: Option<PathBuf>,
}

/// Metadata written beside a writable export tree (never stores passphrases).
#[derive(Clone, Debug)]
pub struct DirtyMeta {
    /// User input path used for mount (live / `.sgv` / bare `.sg1`).
    pub source: PathBuf,
    /// Durable seal path that was exported (tip `.sg1` or bare mark).
    pub seal: PathBuf,
    /// Vault-tracked live file, when known.
    pub live: Option<PathBuf>,
    /// True when export came from a vault tip.
    pub vault: bool,
    /// `single` (one payload file) or `folder` (SGDR — commit stubbed this slice).
    pub kind: String,
}

impl DirtyMeta {
    pub fn write(&self, export_root: &Path) -> Result<()> {
        let mut body = format!("{DIRTY_MAGIC}\n");
        body.push_str(&format!("source={}\n", self.source.display()));
        body.push_str(&format!("seal={}\n", self.seal.display()));
        if let Some(live) = &self.live {
            body.push_str(&format!("live={}\n", live.display()));
        }
        body.push_str(&format!("vault={}\n", if self.vault { 1 } else { 0 }));
        body.push_str(&format!("kind={}\n", self.kind));
        body.push_str("writable=1\n");
        fs::write(export_root.join(DIRTY_NAME), body).map_err(|e| crate::Error::Msg(e.to_string()))
    }

    pub fn read(export_root: &Path) -> Result<Self> {
        let path = export_root.join(DIRTY_NAME);
        let text = fs::read_to_string(&path).map_err(|e| {
            crate::Error::Msg(format!(
                "no {} in {} ({e}) — export with `sigil mount … --export-dir DIR --writable`",
                DIRTY_NAME,
                export_root.display()
            ))
        })?;
        let mut source = None;
        let mut seal = None;
        let mut live = None;
        let mut vault = false;
        let mut kind = "single".to_string();
        let mut saw = false;
        for line in text.lines() {
            let line = line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            if line == DIRTY_MAGIC {
                saw = true;
                continue;
            }
            if let Some(rest) = line.strip_prefix("source=") {
                source = Some(PathBuf::from(rest));
            } else if let Some(rest) = line.strip_prefix("seal=") {
                seal = Some(PathBuf::from(rest));
            } else if let Some(rest) = line.strip_prefix("live=") {
                if !rest.is_empty() {
                    live = Some(PathBuf::from(rest));
                }
            } else if let Some(rest) = line.strip_prefix("vault=") {
                vault = rest == "1" || rest.eq_ignore_ascii_case("true");
            } else if let Some(rest) = line.strip_prefix("kind=") {
                kind = rest.to_string();
            }
        }
        if !saw {
            return Err(crate::Error::Msg(format!(
                "bad {}: missing {DIRTY_MAGIC}",
                path.display()
            )));
        }
        Ok(DirtyMeta {
            source: source.ok_or_else(|| crate::Error::Msg("dirty sidecar missing source=".into()))?,
            seal: seal.ok_or_else(|| crate::Error::Msg("dirty sidecar missing seal=".into()))?,
            live,
            vault,
            kind,
        })
    }
}

/// Build dirty-sidecar fields for a mount/export of `input` resolving to `seal`.
pub fn dirty_meta_for(input: &Path, seal: &Path, prefer_vault: bool) -> Result<DirtyMeta> {
    let source = if input.exists() {
        fs::canonicalize(input).unwrap_or_else(|_| input.to_path_buf())
    } else {
        input.to_path_buf()
    };
    let seal = if seal.exists() {
        fs::canonicalize(seal).unwrap_or_else(|_| seal.to_path_buf())
    } else {
        seal.to_path_buf()
    };
    let kind = if is_dir_pack(&seal) {
        "folder".to_string()
    } else {
        "single".to_string()
    };
    let name = input
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("");
    let mut vault = prefer_vault || name.ends_with(VAULT_SUFFIX);
    let mut live = None;
    if vault || vault_dir_for(input).join(CHART_NAME).is_file() {
        vault = true;
        let (l, _) = resolve_paths(input)?;
        live = Some(if l.exists() {
            fs::canonicalize(&l).unwrap_or(l)
        } else {
            l
        });
    } else if vault_dir_for(&source).join(CHART_NAME).is_file() {
        // Bare .sg1 that happens to sit next to a vault? Prefer tip path live when seal is tip.
        vault = true;
        let (l, _) = resolve_paths(&source)?;
        live = Some(l);
    }
    // If seal lives inside a `.sgv` chart dir, treat as vault tip.
    if !vault {
        if let Some(parent) = seal.parent() {
            let pname = parent
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("");
            if pname.ends_with(VAULT_SUFFIX) && parent.join(CHART_NAME).is_file() {
                vault = true;
                let (l, _) = resolve_paths(parent)?;
                live = Some(if l.exists() {
                    fs::canonicalize(&l).unwrap_or(l)
                } else {
                    l
                });
            }
        }
    }
    Ok(DirtyMeta {
        source,
        seal,
        live,
        vault,
        kind,
    })
}

/// Sidecar chart dir for a live path: `notes.txt` → `notes.txt.sgv/`.
pub fn vault_dir_for(live: &Path) -> PathBuf {
    let mut s = live.as_os_str().to_os_string();
    s.push(VAULT_SUFFIX);
    PathBuf::from(s)
}

/// Resolve a user path that may be the live file or the `.sgv` dir.
pub fn resolve_paths(path: &Path) -> Result<(PathBuf, PathBuf)> {
    let path = if path.exists() {
        fs::canonicalize(path).unwrap_or_else(|_| path.to_path_buf())
    } else {
        path.to_path_buf()
    };
    if path.is_dir()
        && path
            .file_name()
            .and_then(|n| n.to_str())
            .map(|n| n.ends_with(VAULT_SUFFIX))
            .unwrap_or(false)
    {
        let live = live_from_vault_dir(&path)?;
        return Ok((live, path));
    }
    if path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| n.ends_with(VAULT_SUFFIX))
        .unwrap_or(false)
    {
        let live = live_from_vault_dir(&path)?;
        return Ok((live, path));
    }
    let vault = vault_dir_for(&path);
    Ok((path, vault))
}

fn live_from_vault_dir(vault: &Path) -> Result<PathBuf> {
    let name = vault
        .file_name()
        .and_then(|n| n.to_str())
        .ok_or_else(|| crate::Error::Msg("bad vault path".into()))?;
    let stem = name
        .strip_suffix(VAULT_SUFFIX)
        .ok_or_else(|| crate::Error::Msg(format!("vault dir must end with {VAULT_SUFFIX}")))?;
    Ok(vault
        .parent()
        .unwrap_or_else(|| Path::new("."))
        .join(stem))
}

fn seal_name(n: u32) -> String {
    format!("v{n}.sg1")
}

fn now_unix() -> u64 {
    SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0)
}

fn parse_hex32(s: &str) -> Result<[u8; 32]> {
    let raw = hex::decode(s).map_err(|e| crate::Error::Msg(format!("bad digest hex: {e}")))?;
    if raw.len() != 32 {
        return Err(crate::Error::Msg(format!(
            "digest must be 32 bytes, got {}",
            raw.len()
        )));
    }
    let mut out = [0u8; 32];
    out.copy_from_slice(&raw);
    Ok(out)
}

fn write_chart(chart: &Chart) -> Result<()> {
    fs::create_dir_all(&chart.vault_dir).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let live_name = chart
        .live
        .file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("live");
    let mut body = format!("{CHART_MAGIC}\nlive={live_name}\ntip={}\n", chart.tip);
    match chart.retention {
        RetentionPolicy::Full => {
            body.push_str("retention=full\n");
        }
        RetentionPolicy::Light { keep } => {
            body.push_str(&format!("retention=light\nkeep={keep}\n"));
        }
    }
    for v in &chart.versions {
        body.push_str(&format!(
            "version={} seal={} digest={} size={} time={}\n",
            v.n,
            v.seal,
            hex32(&v.digest),
            v.size,
            v.time
        ));
    }
    fs::write(chart.vault_dir.join(CHART_NAME), body).map_err(|e| crate::Error::Msg(e.to_string()))
}

/// Load chart from a vault dir (must contain CHART).
pub fn load_chart(vault_dir: &Path) -> Result<Chart> {
    let text = fs::read_to_string(vault_dir.join(CHART_NAME))
        .map_err(|e| crate::Error::Msg(format!("read CHART: {e}")))?;
    let mut tip = 0u32;
    let mut live_name: Option<String> = None;
    let mut versions = Vec::new();
    let mut saw_magic = false;
    let mut retention_kind: Option<String> = None;
    let mut retention_keep: Option<u32> = None;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if line == CHART_MAGIC {
            saw_magic = true;
            continue;
        }
        if let Some(rest) = line.strip_prefix("live=") {
            live_name = Some(rest.to_string());
        } else if let Some(rest) = line.strip_prefix("tip=") {
            tip = rest
                .parse()
                .map_err(|_| crate::Error::Msg(format!("bad tip: {rest}")))?;
        } else if let Some(rest) = line.strip_prefix("retention=") {
            retention_kind = Some(rest.trim().to_ascii_lowercase());
        } else if let Some(rest) = line.strip_prefix("keep=") {
            // Chart-level light keep=N (not a version= line field).
            retention_keep = Some(
                rest.parse()
                    .map_err(|_| crate::Error::Msg(format!("bad keep: {rest}")))?,
            );
        } else if let Some(rest) = line.strip_prefix("version=") {
            // version=N seal=vN.sg1 digest=… size=… time=…
            let mut n = 0u32;
            let mut seal = String::new();
            let mut digest = None;
            let mut size = 0u64;
            let mut time = 0u64;
            // First token is the version number (no key) after "version="
            let parts: Vec<&str> = rest.split_whitespace().collect();
            if parts.is_empty() {
                return Err(crate::Error::Msg("empty version line".into()));
            }
            // Either "N seal=…" or key=value pairs; first field may be bare N
            let mut idx = 0;
            if !parts[0].contains('=') {
                n = parts[0]
                    .parse()
                    .map_err(|_| crate::Error::Msg(format!("bad version number: {}", parts[0])))?;
                idx = 1;
            }
            for p in &parts[idx..] {
                if let Some((k, v)) = p.split_once('=') {
                    match k {
                        "version" => {
                            n = v.parse().map_err(|_| {
                                crate::Error::Msg(format!("bad version number: {v}"))
                            })?;
                        }
                        "seal" => seal = v.to_string(),
                        "digest" => digest = Some(parse_hex32(v)?),
                        "size" => {
                            size = v
                                .parse()
                                .map_err(|_| crate::Error::Msg(format!("bad size: {v}")))?
                        }
                        "time" => {
                            time = v
                                .parse()
                                .map_err(|_| crate::Error::Msg(format!("bad time: {v}")))?
                        }
                        _ => {}
                    }
                }
            }
            if seal.is_empty() {
                seal = seal_name(n);
            }
            let digest = digest.ok_or_else(|| {
                crate::Error::Msg(format!("version {n} missing digest in CHART"))
            })?;
            versions.push(VersionEntry {
                n,
                seal,
                digest,
                size,
                time,
            });
        }
    }
    if !saw_magic && !text.starts_with(CHART_MAGIC) {
        // tolerate missing magic only if we got versions; otherwise refuse
        if versions.is_empty() {
            return Err(crate::Error::Msg(
                "not a sigil vault CHART (missing sigil-vault=1)".into(),
            ));
        }
    }
    versions.sort_by_key(|v| v.n);
    let live = if let Some(name) = live_name {
        vault_dir
            .parent()
            .unwrap_or_else(|| Path::new("."))
            .join(name)
    } else {
        live_from_vault_dir(vault_dir)?
    };
    if tip == 0 {
        tip = versions.last().map(|v| v.n).unwrap_or(0);
    }
    let retention = match retention_kind.as_deref() {
        None | Some("full") => RetentionPolicy::Full,
        Some("light") => {
            let keep = retention_keep.unwrap_or(1);
            if keep == 0 {
                return Err(crate::Error::Msg(
                    "CHART retention=light needs keep≥1".into(),
                ));
            }
            RetentionPolicy::Light { keep }
        }
        Some(other) => {
            // Unknown retention value: tolerate as full (extras stay forward-compat).
            let _ = other;
            RetentionPolicy::Full
        }
    };
    Ok(Chart {
        live,
        vault_dir: vault_dir.to_path_buf(),
        tip,
        versions,
        retention,
    })
}

fn entry_by_n<'a>(chart: &'a Chart, n: u32) -> Result<&'a VersionEntry> {
    chart
        .versions
        .iter()
        .find(|v| v.n == n)
        .ok_or_else(|| crate::Error::Msg(format!("version v{n} not in CHART")))
}

/// Path to the tip version seal (`vN.sg1`) for a live file or `.sgv` chart dir.
pub fn tip_seal_path(path: &Path) -> Result<(PathBuf, u32)> {
    let (_live, vault_dir) = resolve_paths(path)?;
    if !vault_dir.join(CHART_NAME).is_file() {
        return Err(crate::Error::Msg(format!(
            "not tracked (no {}). Run `sigil vault track` first.",
            vault_dir.display()
        )));
    }
    let chart = load_chart(&vault_dir)?;
    let entry = entry_by_n(&chart, chart.tip)?;
    let seal = chart.vault_dir.join(&entry.seal);
    if !seal.is_file() {
        return Err(crate::Error::Msg(format!(
            "missing tip seal {} for v{}",
            seal.display(),
            chart.tip
        )));
    }
    Ok((seal, chart.tip))
}

fn payload_name(live: &Path) -> String {
    live.file_name()
        .and_then(|n| n.to_str())
        .unwrap_or("file")
        .chars()
        .take(16)
        .collect()
}

/// Start tracking a live file: create `.sgv/`, seal v1, set tip.
/// Optional `recipients` (`--to`) wrap the version seal with SGTO; passphrase Ward still works alone.
pub fn track(
    live: &Path,
    mode: Mode,
    pass: Option<&str>,
    recipients: &[PublicIdentity],
) -> Result<TrackReport> {
    if !live.is_file() {
        return Err(crate::Error::Msg(format!(
            "vault track needs a regular file (got {})",
            live.display()
        )));
    }
    let (live, vault_dir) = resolve_paths(live)?;
    if vault_dir.join(CHART_NAME).is_file() {
        return Err(crate::Error::Msg(format!(
            "already tracked ({} exists). Use `sigil vault commit` for a new version.",
            vault_dir.join(CHART_NAME).display()
        )));
    }
    let data = fs::read(&live).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let digest = sha256(&data);
    let size = data.len() as u64;
    let name = payload_name(&live);
    let sg1 = seal_version(&data, mode, pass, &name, recipients)?;
    fs::create_dir_all(&vault_dir).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let seal_file = seal_name(1);
    fs::write(vault_dir.join(&seal_file), &sg1).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let chart = Chart {
        live: live.clone(),
        vault_dir: vault_dir.clone(),
        tip: 1,
        versions: vec![VersionEntry {
            n: 1,
            seal: seal_file,
            digest,
            size,
            time: now_unix(),
        }],
        retention: RetentionPolicy::Full,
    };
    write_chart(&chart)?;
    Ok(TrackReport {
        live,
        vault_dir,
        version: 1,
        digest,
        size,
    })
}

fn seal_version(
    data: &[u8],
    mode: Mode,
    pass: Option<&str>,
    name: &str,
    recipients: &[PublicIdentity],
) -> Result<Vec<u8>> {
    seal_kn_to(
        data,
        mode,
        pass,
        name,
        false,
        "",
        &[],
        None,
        DEFAULT_PIECE,
        recipients,
    )
}

/// Drift of live vs tip true-name.
pub fn status(path: &Path) -> Result<StatusReport> {
    let (live, vault_dir) = resolve_paths(path)?;
    if !vault_dir.join(CHART_NAME).is_file() {
        return Ok(StatusReport {
            live,
            vault_dir,
            tip: 0,
            drift: Drift::MissingVault,
            live_digest: None,
            tip_digest: None,
            tip_size: None,
        });
    }
    let chart = load_chart(&vault_dir)?;
    let tip_n = chart.tip;
    let tip_entry = match entry_by_n(&chart, tip_n) {
        Ok(e) => e.clone(),
        Err(_) => {
            return Ok(StatusReport {
                live: chart.live,
                vault_dir: chart.vault_dir,
                tip: tip_n,
                drift: Drift::MissingSeal,
                live_digest: None,
                tip_digest: None,
                tip_size: None,
            });
        }
    };
    let seal_path = chart.vault_dir.join(&tip_entry.seal);
    if !seal_path.is_file() {
        return Ok(StatusReport {
            live: chart.live,
            vault_dir: chart.vault_dir,
            tip: tip_n,
            drift: Drift::MissingSeal,
            live_digest: None,
            tip_digest: Some(tip_entry.digest),
            tip_size: Some(tip_entry.size),
        });
    }
    if !live.is_file() {
        return Ok(StatusReport {
            live: chart.live,
            vault_dir: chart.vault_dir,
            tip: tip_n,
            drift: Drift::MissingLive,
            live_digest: None,
            tip_digest: Some(tip_entry.digest),
            tip_size: Some(tip_entry.size),
        });
    }
    let live_digest = sha256_path(&live)?;
    let drift = if live_digest == tip_entry.digest {
        Drift::Match
    } else {
        Drift::Changed
    };
    Ok(StatusReport {
        live: chart.live,
        vault_dir: chart.vault_dir,
        tip: tip_n,
        drift,
        live_digest: Some(live_digest),
        tip_digest: Some(tip_entry.digest),
        tip_size: Some(tip_entry.size),
    })
}

/// Re-seal live into the next version (tip moves). Skips if match unless `force`.
/// Optional `recipients` (`--to`) apply SGTO on the new version seal.
pub fn commit(
    path: &Path,
    mode: Mode,
    pass: Option<&str>,
    force: bool,
    recipients: &[PublicIdentity],
) -> Result<CommitReport> {
    let (live, vault_dir) = resolve_paths(path)?;
    if !vault_dir.join(CHART_NAME).is_file() {
        return Err(crate::Error::Msg(format!(
            "not tracked (no {}). Run `sigil vault track` first.",
            vault_dir.display()
        )));
    }
    if !live.is_file() {
        return Err(crate::Error::Msg(format!(
            "live file missing: {} (restore a version, or recreate the file)",
            live.display()
        )));
    }
    let data = fs::read(&live).map_err(|e| crate::Error::Msg(e.to_string()))?;
    commit_bytes(&live, &vault_dir, &data, mode, pass, force, recipients)
}

fn commit_bytes(
    live: &Path,
    vault_dir: &Path,
    data: &[u8],
    mode: Mode,
    pass: Option<&str>,
    force: bool,
    recipients: &[PublicIdentity],
) -> Result<CommitReport> {
    let mut chart = load_chart(vault_dir)?;
    chart.live = live.to_path_buf();
    let digest = sha256(data);
    if let Ok(tip) = entry_by_n(&chart, chart.tip) {
        if tip.digest == digest && !force {
            return Ok(CommitReport {
                version: chart.tip,
                digest,
                size: tip.size,
                skipped: true,
            });
        }
    }
    let next = chart.versions.iter().map(|v| v.n).max().unwrap_or(0) + 1;
    let name = payload_name(live);
    let sg1 = seal_version(data, mode, pass, &name, recipients)?;
    let seal_file = seal_name(next);
    fs::write(vault_dir.join(&seal_file), &sg1).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let size = data.len() as u64;
    chart.versions.push(VersionEntry {
        n: next,
        seal: seal_file,
        digest,
        size,
        time: now_unix(),
    });
    chart.tip = next;
    write_chart(&chart)?;
    Ok(CommitReport {
        version: next,
        digest,
        size,
        skipped: false,
    })
}

/// Re-seal cleartext from a writable `--export-dir` tree into the next vault version.
///
/// Requires `.sigil-dirty` sidecar (from `mount … --writable`). Single-file vault tips only;
/// folder/SGDR dirty re-seal returns a clear stub error this slice.
/// On success, updates the live path to match committed bytes (old seals stay immutable).
pub fn commit_from_export(
    export_dir: &Path,
    mode: Mode,
    pass: Option<&str>,
    force: bool,
    recipients: &[PublicIdentity],
) -> Result<CommitReport> {
    if !export_dir.is_dir() {
        return Err(crate::Error::Msg(format!(
            "export dir not found: {}",
            export_dir.display()
        )));
    }
    let meta = DirtyMeta::read(export_dir)?;
    if meta.kind == "folder" || is_dir_pack(&meta.seal) {
        return Err(crate::Error::Msg(
            "folder dirty re-seal not in this slice (single-file vault tip only)".into(),
        ));
    }
    if !meta.vault {
        return Err(crate::Error::Msg(
            "export is not vault-tracked; `sigil vault track` the live file first, then mount --vault --writable".into(),
        ));
    }
    let live = meta.live.clone().ok_or_else(|| {
        crate::Error::Msg("dirty sidecar missing live= for vault export".into())
    })?;
    let (_resolved_live, vault_dir) = resolve_paths(&live)?;
    if !vault_dir.join(CHART_NAME).is_file() {
        return Err(crate::Error::Msg(format!(
            "not tracked (no {}). Run `sigil vault track` first.",
            vault_dir.display()
        )));
    }
    let data = read_export_payload(export_dir)?;
    let report = commit_bytes(&live, &vault_dir, &data, mode, pass, force, recipients)?;
    if !report.skipped {
        if let Some(parent) = live.parent() {
            fs::create_dir_all(parent).map_err(|e| crate::Error::Msg(e.to_string()))?;
        }
        fs::write(&live, &data).map_err(|e| crate::Error::Msg(e.to_string()))?;
    }
    Ok(report)
}

/// Collect the single cleartext payload from a dirty export (ignores `.sigil-dirty`).
fn read_export_payload(export_dir: &Path) -> Result<Vec<u8>> {
    let mut files = Vec::new();
    fn walk(dir: &Path, out: &mut Vec<PathBuf>) -> Result<()> {
        for ent in fs::read_dir(dir).map_err(|e| crate::Error::Msg(e.to_string()))? {
            let ent = ent.map_err(|e| crate::Error::Msg(e.to_string()))?;
            let p = ent.path();
            let name = p.file_name().and_then(|n| n.to_str()).unwrap_or("");
            if name == DIRTY_NAME || name.starts_with('.') {
                continue;
            }
            if p.is_dir() {
                walk(&p, out)?;
            } else if p.is_file() {
                out.push(p);
            }
        }
        Ok(())
    }
    walk(export_dir, &mut files)?;
    if files.is_empty() {
        return Err(crate::Error::Msg(format!(
            "no cleartext files in export {}",
            export_dir.display()
        )));
    }
    if files.len() != 1 {
        return Err(crate::Error::Msg(format!(
            "folder dirty re-seal not in this slice (found {} files under {})",
            files.len(),
            export_dir.display()
        )));
    }
    fs::read(&files[0]).map_err(|e| crate::Error::Msg(e.to_string()))
}

/// List versions from the chart (full retention).
pub fn list_versions(path: &Path) -> Result<Chart> {
    let (_live, vault_dir) = resolve_paths(path)?;
    if !vault_dir.join(CHART_NAME).is_file() {
        return Err(crate::Error::Msg(format!(
            "not tracked (no {})",
            vault_dir.display()
        )));
    }
    load_chart(&vault_dir)
}

/// Restore tip (or `version`) over the live path. Mends a torn seal first if needed.
/// `identities` (`--identity`) unwrap encrypt-to CEKs when present.
pub fn restore(
    path: &Path,
    version: Option<u32>,
    pass: Option<&str>,
    identities: &[Identity],
) -> Result<RestoreReport> {
    let (live, vault_dir) = resolve_paths(path)?;
    if !vault_dir.join(CHART_NAME).is_file() {
        return Err(crate::Error::Msg(format!(
            "not tracked (no {})",
            vault_dir.display()
        )));
    }
    let chart = load_chart(&vault_dir)?;
    let n = version.unwrap_or(chart.tip);
    let entry = entry_by_n(&chart, n)?.clone();
    let seal_path = chart.vault_dir.join(&entry.seal);
    if !seal_path.is_file() {
        return Err(crate::Error::Msg(format!(
            "missing seal {} for v{n}",
            seal_path.display()
        )));
    }
    let raw = fs::read(&seal_path).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let mut mended = false;
    let seal_bytes = match unseal_ex_keys(&raw, pass, &[], identities) {
        Ok(_) => raw,
        Err(_) => {
            // Try mend, then unseal the healed mark.
            let healed = mend_bytes(&raw)?;
            mended = true;
            // Persist healed seal so the chart stays usable (same version file).
            fs::write(&seal_path, &healed).map_err(|e| crate::Error::Msg(e.to_string()))?;
            healed
        }
    };
    let plain = unseal_ex_keys(&seal_bytes, pass, &[], identities)?;
    let digest = sha256(&plain);
    if digest != entry.digest {
        // Prefer header true-name if chart drifted; still refuse mismatch vs seal header.
        let (h, _, _) = locate_header(&seal_bytes)?;
        if digest != h.digest {
            return Err(crate::Error::Msg(
                "restored bytes do not match seal true-name".into(),
            ));
        }
    }
    if let Some(parent) = live.parent() {
        fs::create_dir_all(parent).map_err(|e| crate::Error::Msg(e.to_string()))?;
    }
    fs::write(&live, &plain).map_err(|e| crate::Error::Msg(e.to_string()))?;
    Ok(RestoreReport {
        version: n,
        digest,
        size: plain.len() as u64,
        path: live,
        mended,
    })
}

/// Drop old version seals, keeping the newest `keep` (and always the tip).
///
/// Under **light** retention, seals that would leave the chart must go to
/// `--cold DIR` first (kit place when possible, else a plain `.sg1` copy),
/// unless `--force-drop` is set. **Full** retention with an explicit keep
/// still allows drop-without-cold (legacy); pass `--cold` to archive anyway.
pub fn prune(path: &Path, keep: u32) -> Result<PruneReport> {
    prune_with(path, keep, None, false)
}

/// Like [`prune`], with optional cold-kit handoff and force-drop escape hatch.
pub fn prune_with(
    path: &Path,
    keep: u32,
    cold: Option<&Path>,
    force_drop: bool,
) -> Result<PruneReport> {
    if keep == 0 {
        return Err(crate::Error::Msg("--keep must be ≥ 1".into()));
    }
    let (_live, vault_dir) = resolve_paths(path)?;
    let mut chart = load_chart(&vault_dir)?;
    chart.versions.sort_by_key(|v| v.n);
    let tip = chart.tip;
    let mut removed = Vec::new();
    let cold_owned = cold.map(|p| p.to_path_buf());
    if chart.versions.len() <= keep as usize {
        return Ok(PruneReport {
            removed,
            kept: chart.versions.len() as u32,
            tip,
            cold_dir: cold_owned,
        });
    }
    let cutoff = chart.versions.len() - keep as usize;
    let dropping: Vec<VersionEntry> = chart
        .versions
        .iter()
        .enumerate()
        .filter(|(i, v)| *i < cutoff && v.n != tip)
        .map(|(_, v)| v.clone())
        .collect();
    if !dropping.is_empty() {
        let is_light = matches!(chart.retention, RetentionPolicy::Light { .. });
        if is_light && cold.is_none() && !force_drop {
            return Err(crate::Error::Msg(
                "light retention prune would drop version seals — pass --cold DIR                  (kit-place / archive) or --force-drop to discard without a cold kit"
                    .into(),
            ));
        }
        if let Some(cold_root) = cold {
            fs::create_dir_all(cold_root).map_err(|e| crate::Error::Msg(e.to_string()))?;
            for v in &dropping {
                cold_archive_version(&chart.vault_dir, v, cold_root)?;
            }
        }
    }
    let mut kept_entries = Vec::new();
    for (i, v) in chart.versions.iter().enumerate() {
        if i < cutoff && v.n != tip {
            let p = chart.vault_dir.join(&v.seal);
            let _ = fs::remove_file(&p);
            removed.push(v.n);
        } else {
            kept_entries.push(v.clone());
        }
    }
    chart.versions = kept_entries;
    write_chart(&chart)?;
    Ok(PruneReport {
        removed,
        kept: chart.versions.len() as u32,
        tip,
        cold_dir: cold_owned,
    })
}

/// Place a version seal into `cold_root/vN/` via kit place when safe; else copy the `.sg1`.
fn cold_archive_version(vault_dir: &Path, entry: &VersionEntry, cold_root: &Path) -> Result<()> {
    let seal_path = vault_dir.join(&entry.seal);
    let bytes = fs::read(&seal_path).map_err(|e| {
        crate::Error::Msg(format!(
            "read seal {} for cold archive: {e}",
            seal_path.display()
        ))
    })?;
    let dest = cold_root.join(format!("v{}", entry.n));
    fs::create_dir_all(&dest).map_err(|e| crate::Error::Msg(e.to_string()))?;
    match crate::kit::place(&bytes, &dest, crate::kit::DEFAULT_DRIVES) {
        Ok(_) => Ok(()),
        Err(kit_err) => {
            // Glyph (no repair budget) or Reflection with too few drives: keep the mark as a file.
            let archive_name = if entry.seal.is_empty() {
                seal_name(entry.n)
            } else {
                entry.seal.clone()
            };
            fs::write(dest.join(&archive_name), &bytes).map_err(|e| {
                crate::Error::Msg(format!(
                    "cold plain copy to {}: {e} (kit place also failed: {kit_err})",
                    dest.display()
                ))
            })?;
            let note = format!(
                "sigil-cold-archive=1\nkind=plain-sg1\nseal={archive_name}\nkit_error={kit_err}\n"
            );
            let _ = fs::write(dest.join("ARCHIVE"), note);
            Ok(())
        }
    }
}

/// Read retention policy from a live path / `.sgv`.
pub fn get_retention(path: &Path) -> Result<RetentionPolicy> {
    let (_live, vault_dir) = resolve_paths(path)?;
    if !vault_dir.join(CHART_NAME).is_file() {
        return Err(crate::Error::Msg(format!(
            "not tracked (no {}). Run `sigil vault track` first.",
            vault_dir.display()
        )));
    }
    Ok(load_chart(&vault_dir)?.retention)
}

/// Set chart retention (`full` or `light` with keep≥1) and rewrite CHART.
pub fn set_retention(path: &Path, policy: RetentionPolicy) -> Result<RetentionPolicy> {
    if let RetentionPolicy::Light { keep } = policy {
        if keep == 0 {
            return Err(crate::Error::Msg("light --keep must be ≥ 1".into()));
        }
    }
    let (_live, vault_dir) = resolve_paths(path)?;
    if !vault_dir.join(CHART_NAME).is_file() {
        return Err(crate::Error::Msg(format!(
            "not tracked (no {}). Run `sigil vault track` first.",
            vault_dir.display()
        )));
    }
    let mut chart = load_chart(&vault_dir)?;
    chart.retention = policy;
    write_chart(&chart)?;
    Ok(policy)
}

pub fn format_retention(policy: RetentionPolicy) -> String {
    match policy {
        RetentionPolicy::Full => "retention=full (keep all version seals in the chart)".into(),
        RetentionPolicy::Light { keep } => format!(
            "retention=light keep={keep} (newest {keep} hot; older need --cold before prune)"
        ),
    }
}

/// Keep count to apply after a successful commit: explicit `--keep`, else light policy, else none.
pub fn commit_prune_keep(chart: &Chart, keep_override: Option<u32>) -> Option<u32> {
    if let Some(k) = keep_override {
        return Some(k);
    }
    chart.retention.keep()
}

/// After a non-skipped commit, prune when light policy (or explicit keep) says so.
pub fn maybe_prune_after_commit(
    path: &Path,
    keep_override: Option<u32>,
    cold: Option<&Path>,
    force_drop: bool,
) -> Result<Option<PruneReport>> {
    let (_live, vault_dir) = resolve_paths(path)?;
    let chart = load_chart(&vault_dir)?;
    let Some(keep) = commit_prune_keep(&chart, keep_override) else {
        return Ok(None);
    };
    Ok(Some(prune_with(path, keep, cold, force_drop)?))
}

pub fn format_status(s: &StatusReport) -> String {
    let tip_d = s
        .tip_digest
        .map(|d| hex32(&d)[..12].to_string())
        .unwrap_or_else(|| "-".into());
    let live_d = s
        .live_digest
        .map(|d| hex32(&d)[..12].to_string())
        .unwrap_or_else(|| "-".into());
    format!(
        "vault {}  tip=v{}  drift={}  live={}  tip_digest={}  live_digest={}",
        s.live.display(),
        s.tip,
        s.drift.label(),
        s.live.display(),
        tip_d,
        live_d
    )
}

pub fn format_versions(chart: &Chart) -> String {
    let ret = match chart.retention {
        RetentionPolicy::Full => "full".to_string(),
        RetentionPolicy::Light { keep } => format!("light keep={keep}"),
    };
    let mut out = format!(
        "vault {}  tip=v{}  versions={}  retention={}\n",
        chart.live.display(),
        chart.tip,
        chart.versions.len(),
        ret
    );
    for v in &chart.versions {
        let mark = if v.n == chart.tip { " *" } else { "" };
        out.push_str(&format!(
            "  v{}  {}  {} bytes  digest={}{}\n",
            v.n,
            v.seal,
            v.size,
            &hex32(&v.digest)[..12],
            mark
        ));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::Mode;

    fn tmpdir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!(
            "sigil-vault-{tag}-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        dir
    }

    #[test]
    fn track_status_commit_restore_roundtrip() {
        let dir = tmpdir("round");
        let live = dir.join("notes.txt");
        fs::write(&live, b"hello vault v1").unwrap();

        let t = track(&live, Mode::Glyph, None, &[]).unwrap();
        assert_eq!(t.version, 1);
        assert!(vault_dir_for(&live).join(CHART_NAME).is_file());

        let st = status(&live).unwrap();
        assert_eq!(st.drift, Drift::Match);
        assert_eq!(st.tip, 1);

        fs::write(&live, b"hello vault v2 changed").unwrap();
        let st2 = status(&live).unwrap();
        assert_eq!(st2.drift, Drift::Changed);

        let c = commit(&live, Mode::Glyph, None, false, &[]).unwrap();
        assert!(!c.skipped);
        assert_eq!(c.version, 2);
        assert_eq!(status(&live).unwrap().drift, Drift::Match);

        // Restore v1 over live
        let r = restore(&live, Some(1), None, &[]).unwrap();
        assert_eq!(r.version, 1);
        assert_eq!(fs::read(&live).unwrap(), b"hello vault v1");
        assert_eq!(status(&live).unwrap().drift, Drift::Changed);

        // Commit again → v3
        let c3 = commit(&live, Mode::Glyph, None, false, &[]).unwrap();
        assert_eq!(c3.version, 3);

        let chart = list_versions(&live).unwrap();
        assert_eq!(chart.tip, 3);
        assert_eq!(chart.versions.len(), 3);

        // skip commit when match
        let skip = commit(&live, Mode::Glyph, None, false, &[]).unwrap();
        assert!(skip.skipped);
        assert_eq!(skip.version, 3);

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn missing_live_and_prune() {
        let dir = tmpdir("miss");
        let live = dir.join("doc.bin");
        fs::write(&live, b"aaa").unwrap();
        track(&live, Mode::Glyph, None, &[]).unwrap();
        fs::write(&live, b"bbb").unwrap();
        commit(&live, Mode::Glyph, None, false, &[]).unwrap();
        fs::write(&live, b"ccc").unwrap();
        commit(&live, Mode::Glyph, None, false, &[]).unwrap();

        fs::remove_file(&live).unwrap();
        assert_eq!(status(&live).unwrap().drift, Drift::MissingLive);

        restore(&live, Some(1), None, &[]).unwrap();
        assert_eq!(fs::read(&live).unwrap(), b"aaa");

        let p = prune(&live, 2).unwrap();
        assert!(p.removed.contains(&1));
        assert_eq!(p.kept, 2);
        assert!(list_versions(&live)
            .unwrap()
            .versions
            .iter()
            .all(|v| v.n != 1));

        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn restore_mends_torn_seal() {
        let dir = tmpdir("mend");
        let live = dir.join("x.dat");
        fs::write(&live, b"mend-me-please-0123456789abcdef").unwrap();
        track(&live, Mode::Seal, None, &[]).unwrap();
        let chart = list_versions(&live).unwrap();
        let seal_path = chart.vault_dir.join(&chart.versions[0].seal);
        let mut bytes = fs::read(&seal_path).unwrap();
        // Corrupt a middle byte in a shard region (past header) — Seal can mend.
        if bytes.len() > 200 {
            bytes[200] ^= 0xff;
            fs::write(&seal_path, &bytes).unwrap();
        }
        fs::write(&live, b"garbage").unwrap();
        let r = restore(&live, Some(1), None, &[]).unwrap();
        assert_eq!(fs::read(&live).unwrap(), b"mend-me-please-0123456789abcdef");
        assert_eq!(r.digest, sha256(b"mend-me-please-0123456789abcdef"));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn track_commit_encrypt_to_roundtrip() {
        let dir = tmpdir("enc");
        let live = dir.join("secret.txt");
        fs::write(&live, b"vault-encrypt-v1").unwrap();
        let alice = crate::Identity::generate().unwrap();
        let t = track(&live, Mode::Glyph, None, &[alice.public()]).unwrap();
        assert_eq!(t.version, 1);
        let tip = tip_seal_path(&live).unwrap().0;
        let raw = fs::read(&tip).unwrap();
        // Needs identity (or would need pass) to open
        assert!(crate::unseal_ex_keys(&raw, None, &[], &[]).is_err());
        assert_eq!(
            crate::unseal_ex_keys(&raw, None, &[], &[alice.clone()]).unwrap(),
            b"vault-encrypt-v1"
        );

        fs::write(&live, b"vault-encrypt-v2").unwrap();
        let c = commit(&live, Mode::Glyph, None, false, &[alice.public()]).unwrap();
        assert_eq!(c.version, 2);
        let tip2 = tip_seal_path(&live).unwrap().0;
        assert_eq!(
            crate::unseal_ex_keys(&fs::read(&tip2).unwrap(), None, &[], &[alice.clone()]).unwrap(),
            b"vault-encrypt-v2"
        );

        fs::write(&live, b"garbage").unwrap();
        let r = restore(&live, Some(1), None, &[alice]).unwrap();
        assert_eq!(r.version, 1);
        assert_eq!(fs::read(&live).unwrap(), b"vault-encrypt-v1");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn commit_from_export_advances_tip() {
        let dir = tmpdir("from-exp");
        let live = dir.join("notes.txt");
        fs::write(&live, b"export-v1").unwrap();
        track(&live, Mode::Glyph, None, &[]).unwrap();
        let tip = tip_seal_path(&live).unwrap().0;

        let export = dir.join("dirty");
        fs::create_dir_all(&export).unwrap();
        // Simulate writable export payload + sidecar
        fs::write(export.join("notes.txt"), b"export-v1").unwrap();
        let meta = DirtyMeta {
            source: live.clone(),
            seal: tip.clone(),
            live: Some(live.clone()),
            vault: true,
            kind: "single".into(),
        };
        meta.write(&export).unwrap();

        // No change → skip
        let skip = commit_from_export(&export, Mode::Glyph, None, false, &[]).unwrap();
        assert!(skip.skipped);
        assert_eq!(skip.version, 1);

        fs::write(export.join("notes.txt"), b"export-v2-edited").unwrap();
        let c = commit_from_export(&export, Mode::Glyph, None, false, &[]).unwrap();
        assert!(!c.skipped);
        assert_eq!(c.version, 2);
        assert_eq!(fs::read(&live).unwrap(), b"export-v2-edited");
        assert_eq!(status(&live).unwrap().drift, Drift::Match);
        assert_eq!(list_versions(&live).unwrap().tip, 2);
        // Old tip seal still present
        assert!(dir.join("notes.txt.sgv").join("v1.sg1").is_file());
        assert!(dir.join("notes.txt.sgv").join("v2.sg1").is_file());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn commit_from_export_folder_stub() {
        let dir = tmpdir("folder-stub");
        let export = dir.join("dirty");
        fs::create_dir_all(&export).unwrap();
        fs::write(export.join("a.txt"), b"a").unwrap();
        let meta = DirtyMeta {
            source: dir.join("tree.sg1"),
            seal: dir.join("tree.sg1"),
            live: None,
            vault: true,
            kind: "folder".into(),
        };
        meta.write(&export).unwrap();
        let err = commit_from_export(&export, Mode::Glyph, None, false, &[]).unwrap_err();
        assert!(
            err.to_string().contains("folder dirty re-seal not in this slice"),
            "{err}"
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn retention_full_default_and_set_light() {
        let dir = tmpdir("ret-default");
        let live = dir.join("doc.txt");
        fs::write(&live, b"v1").unwrap();
        track(&live, Mode::Glyph, None, &[]).unwrap();
        assert_eq!(get_retention(&live).unwrap(), RetentionPolicy::Full);
        // CHART without retention= still loads as full
        let chart_path = vault_dir_for(&live).join(CHART_NAME);
        let raw = fs::read_to_string(&chart_path).unwrap();
        assert!(raw.contains("retention=full"), "{raw}");

        set_retention(&live, RetentionPolicy::Light { keep: 2 }).unwrap();
        assert_eq!(
            get_retention(&live).unwrap(),
            RetentionPolicy::Light { keep: 2 }
        );
        let raw2 = fs::read_to_string(&chart_path).unwrap();
        assert!(raw2.contains("retention=light"), "{raw2}");
        assert!(raw2.contains("keep=2"), "{raw2}");

        set_retention(&live, RetentionPolicy::Full).unwrap();
        assert_eq!(get_retention(&live).unwrap(), RetentionPolicy::Full);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn light_auto_prune_after_commit_with_cold() {
        let dir = tmpdir("ret-light-cold");
        let live = dir.join("notes.txt");
        fs::write(&live, b"alpha").unwrap();
        track(&live, Mode::Seal, None, &[]).unwrap();
        set_retention(&live, RetentionPolicy::Light { keep: 2 }).unwrap();

        fs::write(&live, b"bravo").unwrap();
        assert!(!commit(&live, Mode::Seal, None, false, &[]).unwrap().skipped);
        fs::write(&live, b"charlie").unwrap();
        assert!(!commit(&live, Mode::Seal, None, false, &[]).unwrap().skipped);
        fs::write(&live, b"delta").unwrap();
        assert!(!commit(&live, Mode::Seal, None, false, &[]).unwrap().skipped);

        // 4 versions hot until prune — light policy alone does not prune inside commit()
        assert_eq!(list_versions(&live).unwrap().versions.len(), 4);

        let cold = dir.join("cold-kit");
        let p = maybe_prune_after_commit(&live, None, Some(&cold), false)
            .unwrap()
            .expect("light should prune");
        assert_eq!(p.kept, 2);
        assert!(p.removed.contains(&1) && p.removed.contains(&2));
        assert_eq!(list_versions(&live).unwrap().versions.len(), 2);
        // tip still v4; restore works
        assert_eq!(list_versions(&live).unwrap().tip, 4);
        assert!(cold.join("v1").is_dir());
        assert!(cold.join("v2").is_dir());
        // Seal → kit place should leave KIT under cold/v1
        assert!(
            crate::kit::is_kit_dir(&cold.join("v1"))
                || cold.join("v1").join("v1.sg1").is_file(),
            "cold/v1 should be kit or plain archive"
        );
        assert!(!vault_dir_for(&live).join("v1.sg1").is_file());
        assert!(vault_dir_for(&live).join("v3.sg1").is_file());
        assert!(vault_dir_for(&live).join("v4.sg1").is_file());

        restore(&live, Some(3), None, &[]).unwrap();
        assert_eq!(fs::read(&live).unwrap(), b"charlie");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn light_prune_requires_cold_or_force_drop() {
        let dir = tmpdir("ret-force");
        let live = dir.join("x.bin");
        fs::write(&live, b"1").unwrap();
        track(&live, Mode::Glyph, None, &[]).unwrap();
        set_retention(&live, RetentionPolicy::Light { keep: 1 }).unwrap();
        fs::write(&live, b"2").unwrap();
        commit(&live, Mode::Glyph, None, false, &[]).unwrap();
        fs::write(&live, b"3").unwrap();
        commit(&live, Mode::Glyph, None, false, &[]).unwrap();

        let err = prune_with(&live, 1, None, false).unwrap_err();
        assert!(
            err.to_string().contains("--cold") || err.to_string().contains("force-drop"),
            "{err}"
        );
        assert_eq!(list_versions(&live).unwrap().versions.len(), 3);

        let p = prune_with(&live, 1, None, true).unwrap();
        assert_eq!(p.kept, 1);
        assert!(p.removed.len() >= 2);
        assert_eq!(list_versions(&live).unwrap().tip, 3);
        // Glyph cold path: plain copy when --cold used
        let cold = dir.join("cold");
        fs::write(&live, b"4").unwrap();
        commit(&live, Mode::Glyph, None, false, &[]).unwrap();
        // now tip=4, hot has tip only if we pruned to 1 — need another version
        fs::write(&live, b"5").unwrap();
        commit(&live, Mode::Glyph, None, false, &[]).unwrap();
        set_retention(&live, RetentionPolicy::Light { keep: 1 }).unwrap();
        let p2 = prune_with(&live, 1, Some(&cold), false).unwrap();
        assert!(!p2.removed.is_empty());
        let archived = cold
            .read_dir()
            .unwrap()
            .filter_map(|e| e.ok())
            .filter(|e| e.path().is_dir())
            .count();
        assert!(archived >= 1, "expected cold/vN dirs");
        // Glyph → plain .sg1 archive
        let any_plain = cold
            .read_dir()
            .unwrap()
            .filter_map(|e| e.ok())
            .any(|e| {
                let p = e.path();
                p.is_dir()
                    && (p.join("ARCHIVE").is_file()
                        || p.join("v1.sg1").is_file()
                        || p.join(format!("{}.sg1", e.file_name().to_string_lossy())).is_file()
                        || fs::read_dir(&p).ok().map(|rd| {
                            rd.filter_map(|x| x.ok())
                                .any(|x| x.path().extension().map(|e| e == "sg1").unwrap_or(false))
                        }).unwrap_or(false))
            });
        assert!(any_plain || crate::kit::is_kit_dir(&cold.join(format!("v{}", p2.removed[0]))));
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn full_prune_still_drops_without_cold() {
        let dir = tmpdir("ret-full-prune");
        let live = dir.join("f.txt");
        fs::write(&live, b"a").unwrap();
        track(&live, Mode::Glyph, None, &[]).unwrap();
        assert_eq!(get_retention(&live).unwrap(), RetentionPolicy::Full);
        for (i, b) in [(2u8, b"b" as &[u8]), (3, b"c"), (4, b"d")] {
            let _ = i;
            fs::write(&live, b).unwrap();
            commit(&live, Mode::Glyph, None, false, &[]).unwrap();
        }
        let p = prune(&live, 2).unwrap();
        assert_eq!(p.kept, 2);
        assert!(p.removed.contains(&1));
        assert!(maybe_prune_after_commit(&live, None, None, false)
            .unwrap()
            .is_none());
        let _ = fs::remove_dir_all(&dir);
    }
}
