//! Vault: version tip + drift detect for a live path.
//!
//! Each tracked file gets a sidecar chart dir `<live>.sgv/` holding a `CHART`
//! index and immutable version seals `v1.sg1`, `v2.sg1`, …. New Inscribe =
//! new version entry; tip moves. History is never rewritten inside one seal.
//!
//! Retention: **full** (default, keep all seals) or **light** (newest N hot;
//! older seals archive to a cold kit before leaving the chart). See
//! `docs/VAULT-RETENTION.md`.
//!
//! Folder vaults (`vault track DIR`): same chart, but each `vN.sg1` is an
//! ordinary SGDR folder pack and the CHART carries an additive `kind=folder`
//! line. The version digest is a **tree true-name** (SHA-256 over a sorted
//! `rel\0size\0sha256` manifest); it lives only in CHART — the SGDR layout
//! is unchanged. Tip model: the chart's tip seal is the durable truth; the
//! live directory (or a `--writable` export tree) is a working copy that
//! commit reads from and restore writes to. See `docs/VAULT-MOUNT-NEST.md`.
//!
//! Remembered recipients: `track --to` / `commit --to` write additive `to=<x25519>.<ed25519>`
//! CHART lines (public keys only). Later commits — including `commit --from-export` — reuse
//! them when no `--to` is given, so an encrypt-to vault never silently goes plain. See
//! `docs/VAULT-RECIPIENTS.md`.

use crate::folder::{inscribe_dir_to, is_dir_pack, tree_files, unseal_dir_mend_keys};
use crate::header::locate_header;
use crate::keys::{Identity, PublicIdentity};
use crate::pieces::mend_bytes;
use crate::{
    hex32, seal_kn_to, sha256, sha256_path, unseal_ex_keys, Mode, Result, DEFAULT_CHUNK,
    DEFAULT_PIECE,
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
const TREE_MAGIC: &str = "sigil-tree=1";

/// What a vault's live path is: one regular file, or a directory (SGDR versions).
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum ChartKind {
    /// Live is a regular file; each `vN.sg1` is a single-file mark (default; legacy charts).
    #[default]
    Single,
    /// Live is a directory; each `vN.sg1` is an SGDR folder pack. CHART line `kind=folder`.
    Folder,
}

impl ChartKind {
    pub fn label(self) -> &'static str {
        match self {
            ChartKind::Single => "single",
            ChartKind::Folder => "folder",
        }
    }
}

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, Default)]
pub enum RetentionPolicy {
    #[default]
    Full,
    Light {
        keep: u32,
    },
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

#[derive(Clone, Debug)]
pub struct Chart {
    pub live: PathBuf,
    pub vault_dir: PathBuf,
    pub tip: u32,
    pub versions: Vec<VersionEntry>,
    pub retention: RetentionPolicy,
    /// `single` (default; no CHART line) or `folder` (`kind=folder`).
    pub kind: ChartKind,
    /// Remembered encrypt-to recipients (`to=` lines). New versions are sealed to
    /// these when commit gets no explicit `--to`. Empty = none remembered (plain charts
    /// stay byte-identical). Public keys only — never secrets or passphrases.
    pub recipients: Vec<PublicIdentity>,
    /// `to=-`: owner explicitly chose plain (non encrypt-to) future versions.
    pub plain_ok: bool,
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
    /// Optional human note (e.g. folder live dir left untouched because it had local edits).
    pub note: Option<String>,
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
    /// `single` (one payload file) or `folder` (SGDR pack → folder vault re-seal).
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
            source: source
                .ok_or_else(|| crate::Error::Msg("dirty sidecar missing source=".into()))?,
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
    let name = input.file_name().and_then(|n| n.to_str()).unwrap_or("");
    let mut vault = prefer_vault
        || is_chart_dir_name(name) && Path::new(input).join(CHART_NAME).is_file()
        || name.ends_with(VAULT_SUFFIX);
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
            let pname = parent.file_name().and_then(|n| n.to_str()).unwrap_or("");
            let container_parent = if pname == crate::container::VERSIONS_DIR {
                parent
                    .parent()
                    .filter(|g| is_container_vault_dir(g) && g.join(CHART_NAME).is_file())
            } else {
                None
            };
            let chart_dir = if pname.ends_with(VAULT_SUFFIX) && parent.join(CHART_NAME).is_file() {
                Some(parent)
            } else {
                container_parent
            };
            if let Some(parent) = chart_dir {
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

/// Old sidecar chart dir for a live path: `notes.txt` → `notes.txt.sgv/`.
pub fn legacy_vault_dir_for(live: &Path) -> PathBuf {
    // `photos/` and `photos` name the same live dir → `photos.sgv` (not `photos/.sgv`).
    let live = live.components().as_path();
    let mut s = live.as_os_str().to_os_string();
    s.push(VAULT_SUFFIX);
    PathBuf::from(s)
}

/// Chart dir for a live path. An existing tidy container `notes.txt.sigil/` wins,
/// then an old `notes.txt.sgv/` sidecar (still read forever); a path tracked for the
/// first time gets the container.
pub fn vault_dir_for(live: &Path) -> PathBuf {
    let c = crate::container::with_suffix(live);
    if c.join(CHART_NAME).is_file() {
        return c;
    }
    let old = legacy_vault_dir_for(live);
    if old.join(CHART_NAME).is_file() {
        return old;
    }
    c
}

/// True when this chart dir uses the container layout (`*.sigil`, seals under `versions/`).
pub fn is_container_vault_dir(vault_dir: &Path) -> bool {
    crate::container::has_suffix(vault_dir)
}

/// Where version seal `seal` (e.g. `v3.sg1`) lives inside a chart dir.
pub fn seal_path_in(vault_dir: &Path, seal: &str) -> PathBuf {
    if is_container_vault_dir(vault_dir) {
        vault_dir.join(crate::container::VERSIONS_DIR).join(seal)
    } else {
        vault_dir.join(seal)
    }
}

/// Path of version `n`'s seal for a live path / chart dir (either layout).
/// Test-only helper: production code resolves seal paths via `seal_path_in`.
#[cfg(test)]
pub fn version_seal_path(path: &Path, n: u32) -> Result<PathBuf> {
    let (_l, vault_dir) = resolve_paths(path)?;
    Ok(seal_path_in(&vault_dir, &seal_name(n)))
}

fn prepare_vault_dir(vault_dir: &Path, live: &Path) -> Result<()> {
    if is_container_vault_dir(vault_dir) {
        let name = live.file_name().and_then(|n| n.to_str()).unwrap_or("live");
        crate::container::ensure(vault_dir, "vault", name)?;
        fs::create_dir_all(vault_dir.join(crate::container::VERSIONS_DIR))
            .map_err(|e| crate::Error::Msg(e.to_string()))?;
    } else {
        fs::create_dir_all(vault_dir).map_err(|e| crate::Error::Msg(e.to_string()))?;
    }
    Ok(())
}

fn is_chart_dir_name(name: &str) -> bool {
    name.ends_with(VAULT_SUFFIX)
        || (name.ends_with(crate::container::CONTAINER_SUFFIX) && name.len() > 6)
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
            .map(is_chart_dir_name)
            .unwrap_or(false)
        && (path.join(CHART_NAME).is_file()
            || path.extension().map(|e| e == "sgv").unwrap_or(false))
    {
        let live = live_from_vault_dir(&path)?;
        return Ok((live, path));
    }
    if path
        .file_name()
        .and_then(|n| n.to_str())
        .map(|n| {
            n.ends_with(VAULT_SUFFIX)
                || (n.ends_with(crate::container::CONTAINER_SUFFIX)
                    && path.join(CHART_NAME).is_file())
        })
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
        .or_else(|| name.strip_suffix(crate::container::CONTAINER_SUFFIX))
        .ok_or_else(|| {
            crate::Error::Msg(format!("vault dir must end with {VAULT_SUFFIX} or .sigil"))
        })?;
    Ok(vault.parent().unwrap_or_else(|| Path::new(".")).join(stem))
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
    // Additive: single-file charts stay byte-identical to pre-folder CHARTs.
    if chart.kind == ChartKind::Folder {
        body.push_str("kind=folder\n");
    }
    match chart.retention {
        RetentionPolicy::Full => {
            body.push_str("retention=full\n");
        }
        RetentionPolicy::Light { keep } => {
            body.push_str(&format!("retention=light\nkeep={keep}\n"));
        }
    }
    // Additive: only vaults that use encrypt-to carry `to=` lines.
    for r in &chart.recipients {
        body.push_str(&format!("to={}\n", recipient_token(r)));
    }
    if chart.recipients.is_empty() && chart.plain_ok {
        body.push_str("to=-\n");
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
    let mut kind = ChartKind::Single;
    let mut recipients: Vec<PublicIdentity> = Vec::new();
    let mut plain_ok = false;
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
        } else if let Some(rest) = line.strip_prefix("kind=") {
            kind = match rest.trim() {
                "folder" => ChartKind::Folder,
                _ => ChartKind::Single,
            };
        } else if let Some(rest) = line.strip_prefix("to=") {
            if rest.trim() == "-" {
                plain_ok = true;
            } else {
                let r = parse_recipient_token(rest.trim())?;
                if !recipients.iter().any(|x| x.x25519_pk == r.x25519_pk) {
                    recipients.push(r);
                }
            }
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
            let digest = digest
                .ok_or_else(|| crate::Error::Msg(format!("version {n} missing digest in CHART")))?;
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
        kind,
        plain_ok: plain_ok && recipients.is_empty(),
        recipients,
    })
}

/// CHART token for one recipient: `<x25519 hex>.<ed25519 hex>` (public halves only).
fn recipient_token(r: &PublicIdentity) -> String {
    format!("{}.{}", hex::encode(r.x25519_pk), hex::encode(r.ed25519_pk))
}

fn parse_recipient_token(s: &str) -> Result<PublicIdentity> {
    let (x, e) = s.split_once('.').unwrap_or((s, ""));
    let x =
        parse_hex32(x).map_err(|_| crate::Error::Msg(format!("bad CHART to= recipient: {s}")))?;
    let e = if e.is_empty() {
        [0u8; 32]
    } else {
        parse_hex32(e).map_err(|_| crate::Error::Msg(format!("bad CHART to= recipient: {s}")))?
    };
    Ok(PublicIdentity {
        x25519_pk: x,
        ed25519_pk: e,
    })
}

fn dedup_recipients(rs: &[PublicIdentity]) -> Vec<PublicIdentity> {
    let mut out: Vec<PublicIdentity> = Vec::new();
    for r in rs {
        if !out.iter().any(|x| x.x25519_pk == r.x25519_pk) {
            out.push(r.clone());
        }
    }
    out
}

/// True when a single-file seal carries an SGTO block with at least one X25519 wrap.
fn seal_is_encrypt_to(raw: &[u8]) -> bool {
    let Ok((h, _, _)) = locate_header(raw) else {
        return false;
    };
    if !h.encrypted() {
        return false;
    }
    match crate::header::sgto_slice(&h, raw) {
        Some(b) => crate::keys::sgto_has_recipients(b),
        None => false,
    }
}

/// Recipients a new version should be sealed to.
///
/// Explicit `--to` wins and replaces the remembered set. Otherwise the remembered set
/// is reused. Legacy guard: a chart with nothing remembered whose single-file tip is
/// encrypt-to refuses to commit plain unless the owner ran `vault recipients --clear`.
fn effective_recipients(chart: &Chart, explicit: &[PublicIdentity]) -> Result<Vec<PublicIdentity>> {
    if !explicit.is_empty() {
        return Ok(dedup_recipients(explicit));
    }
    if !chart.recipients.is_empty() || chart.plain_ok {
        return Ok(chart.recipients.clone());
    }
    if chart.kind == ChartKind::Single {
        if let Ok(e) = entry_by_n(chart, chart.tip) {
            if let Ok(raw) = fs::read(seal_path_in(&chart.vault_dir, &e.seal)) {
                if seal_is_encrypt_to(&raw) {
                    return Err(crate::Error::Msg(format!(
                        "tip v{} is encrypt-to but this chart has no remembered recipients \
                         (tracked before remembered --to). Pass --to again once (it will be \
                         remembered), or `sigil vault recipients {} --clear` to go plain on purpose",
                        chart.tip,
                        chart.live.display()
                    )));
                }
            }
        }
    }
    Ok(Vec::new())
}

fn entry_by_n(chart: &Chart, n: u32) -> Result<&VersionEntry> {
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
    let seal = seal_path_in(&chart.vault_dir, &entry.seal);
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
    track_ex(live, mode, pass, recipients, &[])
}

/// Like [`track`]; a **directory** live path becomes a folder vault (SGDR versions).
/// `wards` (`--ward rel=pass`) apply per-file passphrases inside folder versions.
pub fn track_ex(
    live: &Path,
    mode: Mode,
    pass: Option<&str>,
    recipients: &[PublicIdentity],
    wards: &[(String, String)],
) -> Result<TrackReport> {
    if live.is_dir() {
        return track_dir(live, mode, pass, recipients, wards);
    }
    if !live.is_file() {
        return Err(crate::Error::Msg(format!(
            "vault track needs a regular file or a directory (got {})",
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
    prepare_vault_dir(&vault_dir, &live)?;
    let seal_file = seal_name(1);
    fs::write(seal_path_in(&vault_dir, &seal_file), &sg1)
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
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
        kind: ChartKind::Single,
        recipients: dedup_recipients(recipients),
        plain_ok: false,
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

/// Why a folder vault locked only by per-file wards is refused (names would show).
const VAULT_WARD_ONLY_REFUSED: &str = "a folder vault locked only with --ward would show every file name and size to anyone: add --pass (or --to) as well; the wards still lock their files";

fn track_dir(
    live: &Path,
    mode: Mode,
    pass: Option<&str>,
    recipients: &[PublicIdentity],
    wards: &[(String, String)],
) -> Result<TrackReport> {
    // Refuse before the vault directory is created, so nothing is left behind.
    if !wards.is_empty() && pass.is_none() && recipients.is_empty() {
        return Err(crate::Error::Msg(VAULT_WARD_ONLY_REFUSED.into()));
    }
    let (live, vault_dir) = resolve_paths(live)?;
    if vault_dir.join(CHART_NAME).is_file() {
        return Err(crate::Error::Msg(format!(
            "already tracked ({} exists). Use `sigil vault commit` for a new version.",
            vault_dir.join(CHART_NAME).display()
        )));
    }
    if vault_dir.starts_with(&live) {
        return Err(crate::Error::Msg(
            "vault chart cannot live inside the tracked folder".into(),
        ));
    }
    let (digest, size, _n) = tree_digest(&live)?;
    prepare_vault_dir(&vault_dir, &live)?;
    let seal_file = seal_name(1);
    seal_tree_version(
        &live,
        &seal_path_in(&vault_dir, &seal_file),
        mode,
        pass,
        recipients,
        wards,
    )?;
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
        kind: ChartKind::Folder,
        recipients: dedup_recipients(recipients),
        plain_ok: false,
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

/// Tree true-name of a directory: SHA-256 over `sigil-tree=1` + sorted
/// `rel\0size\0sha256hex\n` lines (dotfiles skipped — same set folder Inscribe packs).
/// Returns `(digest, total_bytes, file_count)`.
pub fn tree_digest(dir: &Path) -> Result<([u8; 32], u64, u32)> {
    let files = tree_files(dir)?;
    let mut manifest = format!("{TREE_MAGIC}\n");
    let mut total = 0u64;
    for (rel, path) in &files {
        let size = path
            .metadata()
            .map_err(|e| crate::Error::Msg(e.to_string()))?
            .len();
        total += size;
        manifest.push_str(&format!("{rel}\0{size}\0{}\n", hex32(&sha256_path(path)?)));
    }
    Ok((sha256(manifest.as_bytes()), total, files.len() as u32))
}

/// Seal `src` as an SGDR pack at `out` (written via `.part` + rename; never overwrites).
fn seal_tree_version(
    src: &Path,
    out: &Path,
    mode: Mode,
    pass: Option<&str>,
    recipients: &[PublicIdentity],
    wards: &[(String, String)],
) -> Result<()> {
    if out.exists() {
        return Err(crate::Error::Msg(format!(
            "refusing to overwrite existing version seal {}",
            out.display()
        )));
    }
    let mut part = out.as_os_str().to_os_string();
    part.push(".part");
    let part = PathBuf::from(part);
    let res = inscribe_dir_to(
        src,
        &part,
        mode,
        pass,
        "",
        &[],
        DEFAULT_CHUNK,
        wards,
        recipients,
    );
    match res {
        Ok(_) => fs::rename(&part, out).map_err(|e| crate::Error::Msg(e.to_string())),
        Err(e) => {
            let _ = fs::remove_file(&part);
            Err(match e {
                crate::Error::Msg(m) if m == "folder is empty" => crate::Error::Msg(
                    "folder is empty — a folder version needs at least one (non-dot) file".into(),
                ),
                crate::Error::Msg(m) if m == crate::folder::WARD_ONLY_REFUSED => {
                    crate::Error::Msg(VAULT_WARD_ONLY_REFUSED.into())
                }
                other => other,
            })
        }
    }
}

/// Make `dst` mirror `src` (non-dot files): copy every file, delete files absent
/// from `src`, drop dirs left empty. Dotfiles in `dst` are never touched.
fn sync_tree(src: &Path, dst: &Path) -> Result<()> {
    fs::create_dir_all(dst).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let src_files = tree_files(src)?;
    let keep: std::collections::HashSet<&str> = src_files.iter().map(|(r, _)| r.as_str()).collect();
    for (rel, path) in &src_files {
        let out = dst.join(rel);
        if let Some(parent) = out.parent() {
            fs::create_dir_all(parent).map_err(|e| crate::Error::Msg(e.to_string()))?;
        }
        if out.exists() {
            let _ = fs::remove_file(&out);
        }
        fs::copy(path, &out).map_err(|e| crate::Error::Msg(format!("copy {rel}: {e}")))?;
    }
    for (rel, path) in tree_files(dst)? {
        if keep.contains(rel.as_str()) {
            continue;
        }
        fs::remove_file(&path).map_err(|e| crate::Error::Msg(format!("remove {rel}: {e}")))?;
        let mut cur = path.parent().map(|p| p.to_path_buf());
        while let Some(d) = cur {
            if d == dst || !d.starts_with(dst) || fs::remove_dir(&d).is_err() {
                break;
            }
            cur = d.parent().map(|p| p.to_path_buf());
        }
    }
    Ok(())
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
    let seal_path = seal_path_in(&chart.vault_dir, &tip_entry.seal);
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
    let live_present = match chart.kind {
        ChartKind::Single => live.is_file(),
        ChartKind::Folder => live.is_dir(),
    };
    if !live_present {
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
    let live_digest = match chart.kind {
        ChartKind::Single => sha256_path(&live)?,
        ChartKind::Folder => tree_digest(&live)?.0,
    };
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
    commit_ex(path, mode, pass, force, recipients, &[])
}

/// Like [`commit`], with per-file `wards` for folder vaults.
pub fn commit_ex(
    path: &Path,
    mode: Mode,
    pass: Option<&str>,
    force: bool,
    recipients: &[PublicIdentity],
    wards: &[(String, String)],
) -> Result<CommitReport> {
    let (live, vault_dir) = resolve_paths(path)?;
    if !vault_dir.join(CHART_NAME).is_file() {
        return Err(crate::Error::Msg(format!(
            "not tracked (no {}). Run `sigil vault track` first.",
            vault_dir.display()
        )));
    }
    if load_chart(&vault_dir)?.kind == ChartKind::Folder {
        if !live.is_dir() {
            return Err(crate::Error::Msg(format!(
                "live folder missing: {} (restore a version, or recreate the folder)",
                live.display()
            )));
        }
        return commit_tree(
            &live, &live, &vault_dir, mode, pass, force, recipients, wards,
        );
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
                note: None,
            });
        }
    }
    let recipients = effective_recipients(&chart, recipients)?;
    let next = chart.versions.iter().map(|v| v.n).max().unwrap_or(0) + 1;
    let name = payload_name(live);
    let sg1 = seal_version(data, mode, pass, &name, &recipients)?;
    if !recipients.is_empty() {
        chart.plain_ok = false;
    }
    chart.recipients = recipients;
    let seal_file = seal_name(next);
    fs::write(seal_path_in(vault_dir, &seal_file), &sg1)
        .map_err(|e| crate::Error::Msg(e.to_string()))?;
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
        note: None,
    })
}

/// Seal directory `src` as the next folder-vault version (SGDR); tip moves.
/// `src` is the live dir (ordinary commit) or a dirty export tree.
// Justification: each parameter is an independent user-facing seal option threaded
// straight from the CLI (mode, passphrase, covenant, geas, chunking, wards, recipients...).
// Bundling them into an options struct is a public-API refactor tracked separately;
// this PR keeps signatures stable.
#[allow(clippy::too_many_arguments)]
fn commit_tree(
    src: &Path,
    live: &Path,
    vault_dir: &Path,
    mode: Mode,
    pass: Option<&str>,
    force: bool,
    recipients: &[PublicIdentity],
    wards: &[(String, String)],
) -> Result<CommitReport> {
    let mut chart = load_chart(vault_dir)?;
    if chart.kind != ChartKind::Folder {
        return Err(crate::Error::Msg(
            "vault chart is a single-file vault, not a folder vault".into(),
        ));
    }
    chart.live = live.to_path_buf();
    let (digest, size, _n) = tree_digest(src)?;
    if let Ok(tip) = entry_by_n(&chart, chart.tip) {
        if tip.digest == digest && !force {
            return Ok(CommitReport {
                version: chart.tip,
                digest,
                size: tip.size,
                skipped: true,
                note: None,
            });
        }
    }
    let recipients = effective_recipients(&chart, recipients)?;
    let next = chart.versions.iter().map(|v| v.n).max().unwrap_or(0) + 1;
    let seal_file = seal_name(next);
    seal_tree_version(
        src,
        &seal_path_in(vault_dir, &seal_file),
        mode,
        pass,
        &recipients,
        wards,
    )?;
    if !recipients.is_empty() {
        chart.plain_ok = false;
    }
    chart.recipients = recipients;
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
        note: None,
    })
}

/// Re-seal cleartext from a writable `--export-dir` tree into the next vault version.
///
/// Requires `.sigil-dirty` sidecar (from `mount … --writable`).
///
/// - **Single-file** vault tip: on success the live file is updated to the committed bytes.
/// - **Folder** vault tip (SGDR): the export tree is sealed as a new SGDR version. The live
///   directory is synced (adds / edits / deletes) only when it was clean (matched a hot
///   version) or missing; otherwise it is left untouched and `note` says so.
///
/// Old seals stay immutable either way.
pub fn commit_from_export(
    export_dir: &Path,
    mode: Mode,
    pass: Option<&str>,
    force: bool,
    recipients: &[PublicIdentity],
) -> Result<CommitReport> {
    commit_from_export_ex(export_dir, mode, pass, force, recipients, &[])
}

/// Like [`commit_from_export`], with per-file `wards` for folder re-seal.
pub fn commit_from_export_ex(
    export_dir: &Path,
    mode: Mode,
    pass: Option<&str>,
    force: bool,
    recipients: &[PublicIdentity],
    wards: &[(String, String)],
) -> Result<CommitReport> {
    if !export_dir.is_dir() {
        return Err(crate::Error::Msg(format!(
            "export dir not found: {}",
            export_dir.display()
        )));
    }
    let meta = DirtyMeta::read(export_dir)?;
    if meta.kind == "folder" || is_dir_pack(&meta.seal) {
        return commit_folder_from_export(export_dir, &meta, mode, pass, force, recipients, wards);
    }
    if !meta.vault {
        return Err(crate::Error::Msg(
            "export is not vault-tracked; `sigil vault track` the live file first, then mount --vault --writable".into(),
        ));
    }
    let live = meta
        .live
        .clone()
        .ok_or_else(|| crate::Error::Msg("dirty sidecar missing live= for vault export".into()))?;
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

fn commit_folder_from_export(
    export_dir: &Path,
    meta: &DirtyMeta,
    mode: Mode,
    pass: Option<&str>,
    force: bool,
    recipients: &[PublicIdentity],
    wards: &[(String, String)],
) -> Result<CommitReport> {
    let not_vault = || {
        crate::Error::Msg(
            "folder export is not from a folder vault — `sigil vault track DIR` then \
             `mount DIR … --vault --export-dir … --writable`, or pack the edited tree as a new \
             mark with `sigil inscribe EXPORT -o new.sg1`"
                .into(),
        )
    };
    if !meta.vault {
        return Err(not_vault());
    }
    let live = meta.live.clone().ok_or_else(not_vault)?;
    let (_l, vault_dir) = resolve_paths(&live)?;
    if !vault_dir.join(CHART_NAME).is_file() {
        return Err(crate::Error::Msg(format!(
            "not tracked (no {}). Run `sigil vault track` first.",
            vault_dir.display()
        )));
    }
    let chart = load_chart(&vault_dir)?;
    if chart.kind != ChartKind::Folder {
        return Err(not_vault());
    }
    let export_abs = fs::canonicalize(export_dir).unwrap_or_else(|_| export_dir.to_path_buf());
    if export_abs.starts_with(&live) || live.starts_with(&export_abs) {
        return Err(crate::Error::Msg(
            "export dir must not be inside the live folder (or contain it)".into(),
        ));
    }
    // Was the live working copy clean (matches some hot version) before we commit?
    let live_clean = if live.is_dir() {
        let d = tree_digest(&live)?.0;
        chart.versions.iter().any(|v| v.digest == d)
    } else {
        !live.exists()
    };
    let mut report = commit_tree(
        export_dir, &live, &vault_dir, mode, pass, force, recipients, wards,
    )?;
    if !report.skipped {
        if live_clean {
            sync_tree(export_dir, &live)?;
        } else {
            report.note = Some(format!(
                "live folder {} has uncommitted edits — left untouched (tip v{} holds the export; \
                 `vault restore --force` to replace live)",
                live.display(),
                report.version
            ));
        }
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
            "single-file dirty export must contain exactly one cleartext file (found {} under {}); folder vault tips re-seal via commit --from-export / commit_folder_from_export",
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
    restore_ex(path, version, pass, identities, &[], false)
}

/// Like [`restore`], with per-file `wards` and `force` for folder vaults.
///
/// Folder restore mirrors the version into the live dir (adds / overwrites / deletes
/// non-dot files). It refuses when the live dir has edits that match no hot version
/// (they would be lost) unless `force`. Single-file restore ignores `force` (unchanged).
pub fn restore_ex(
    path: &Path,
    version: Option<u32>,
    pass: Option<&str>,
    identities: &[Identity],
    wards: &[(String, String)],
    force: bool,
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
    let seal_path = seal_path_in(&chart.vault_dir, &entry.seal);
    if !seal_path.is_file() {
        return Err(crate::Error::Msg(format!(
            "missing seal {} for v{n}",
            seal_path.display()
        )));
    }
    if chart.kind == ChartKind::Folder {
        return restore_tree(
            &chart, &entry, &seal_path, &live, pass, identities, wards, force,
        );
    }
    let raw = fs::read(&seal_path).map_err(|e| crate::Error::Msg(e.to_string()))?;
    let mut mended = false;
    // Unseal may still succeed within Seal budget while shards remain torn.
    // Mend + persist whenever unseal fails, or verify shows a damaged mark.
    let seal_bytes = match unseal_ex_keys(&raw, pass, &[], identities) {
        Ok(_) if !mark_torn(&raw) => raw,
        opened => match mend_bytes(&raw) {
            Ok(healed) => {
                // Persist only a healed mark that opens; atomic so a crash can't tear v{n}.
                unseal_ex_keys(&healed, pass, &[], identities)?;
                write_seal_atomic(&seal_path, &healed)?;
                mended = true;
                healed
            }
            // Opened within budget but couldn't be re-sealed clean: restore from it as-is.
            Err(_) if opened.is_ok() => raw,
            Err(e) => return Err(e),
        },
    };
    let (plain, meta) = crate::unseal_meta_keys(&seal_bytes, pass, &[], identities)?;
    let digest = sha256(&plain);
    if digest != entry.digest {
        // Prefer the seal's own true-name if chart drifted; still refuse a mismatch. A v3
        // encrypted seal keeps it inside the ciphertext (its label holds a keyed fingerprint).
        let (h, _, _) = locate_header(&seal_bytes)?;
        let true_name = meta.map(|m| m.digest).unwrap_or(h.digest);
        if digest != true_name {
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

// Justification: each parameter is an independent user-facing seal option threaded
// straight from the CLI (mode, passphrase, covenant, geas, chunking, wards, recipients...).
// Bundling them into an options struct is a public-API refactor tracked separately;
// this PR keeps signatures stable.
#[allow(clippy::too_many_arguments)]
fn restore_tree(
    chart: &Chart,
    entry: &VersionEntry,
    seal_path: &Path,
    live: &Path,
    pass: Option<&str>,
    identities: &[Identity],
    wards: &[(String, String)],
    force: bool,
) -> Result<RestoreReport> {
    if live.exists() && !live.is_dir() {
        return Err(crate::Error::Msg(format!(
            "folder vault live path is not a directory: {}",
            live.display()
        )));
    }
    if live.is_dir() && !force {
        let d = tree_digest(live)?.0;
        if !chart.versions.iter().any(|v| v.digest == d) {
            return Err(crate::Error::Msg(format!(
                "live folder {} has uncommitted edits (matches no hot version) — \
                 `vault commit` first, or pass --force to overwrite",
                live.display()
            )));
        }
    }
    let parent = live.parent().unwrap_or_else(|| Path::new("."));
    let stage = parent.join(format!(
        ".{}.sigil-restore-{}-{}",
        live.file_name().and_then(|n| n.to_str()).unwrap_or("live"),
        std::process::id(),
        SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .map(|d| d.as_nanos())
            .unwrap_or(0)
    ));
    let result = (|| -> Result<([u8; 32], u64, bool)> {
        // WORK/SGWK members heal chunk-by-chunk. Persist the healed pack only after
        // the restored tree matches the chart true-name, and atomically.
        let (_n, healed) =
            unseal_dir_mend_keys(seal_path, &stage, pass, &[], &[], wards, identities)?;
        let (digest, size, _n) = tree_digest(&stage)?;
        if digest != entry.digest {
            return Err(crate::Error::Msg(format!(
                "restored tree does not match CHART tree true-name for v{}",
                entry.n
            )));
        }
        let mended = if let Some(pack) = healed {
            write_seal_atomic(seal_path, &pack)?;
            true
        } else {
            false
        };
        sync_tree(&stage, live)?;
        Ok((digest, size, mended))
    })();
    let _ = fs::remove_dir_all(&stage);
    let (digest, size, mended) = result?;
    Ok(RestoreReport {
        version: entry.n,
        digest,
        size,
        path: live.to_path_buf(),
        mended,
    })
}

/// True when a classic `.sg1` still opens within mend budget but shards/Merkle
/// (or its primary header) are damaged.
fn mark_torn(raw: &[u8]) -> bool {
    crate::work::star_torn(raw)
}

/// Replace a version seal via temp file + rename (never a half-written v{n}).
fn write_seal_atomic(seal_path: &Path, bytes: &[u8]) -> Result<()> {
    let mut tmp = seal_path.as_os_str().to_os_string();
    tmp.push(".mend-part");
    let tmp = PathBuf::from(tmp);
    fs::write(&tmp, bytes).map_err(|e| crate::Error::Msg(e.to_string()))?;
    fs::rename(&tmp, seal_path).map_err(|e| {
        let _ = fs::remove_file(&tmp);
        crate::Error::Msg(e.to_string())
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
    let mut gone_files = Vec::new();
    for (i, v) in chart.versions.iter().enumerate() {
        if i < cutoff && v.n != tip {
            gone_files.push(seal_path_in(&chart.vault_dir, &v.seal));
            removed.push(v.n);
        } else {
            kept_entries.push(v.clone());
        }
    }
    chart.versions = kept_entries;
    // Chart first, files after: a crash leaves an orphan seal (`sigil gc` reclaims it),
    // never a chart entry whose seal is gone.
    write_chart(&chart)?;
    for p in gone_files {
        let _ = fs::remove_file(&p);
    }
    Ok(PruneReport {
        removed,
        kept: chart.versions.len() as u32,
        tip,
        cold_dir: cold_owned,
    })
}

#[derive(Clone, Debug)]
pub struct RemoveVersionReport {
    pub removed: u32,
    pub tip: u32,
    /// Versions still in the chart afterwards.
    pub remaining: u32,
    /// Where the seal was archived first (if it was).
    pub cold_dir: Option<PathBuf>,
    pub dry_run: bool,
}

/// `<container>/cold` for a vault that lives in a `name.sigil/` container.
pub fn cold_here(path: &Path) -> Result<PathBuf> {
    let (_live, vault_dir) = resolve_paths(path)?;
    if !is_container_vault_dir(&vault_dir) {
        return Err(crate::Error::Msg(
            "--cold-here needs a tidy container (run `sigil tidy` first) or pass --cold DIR".into(),
        ));
    }
    Ok(vault_dir.join(crate::container::COLD_DIR))
}

/// Remove one named version from the chart and delete its seal.
///
/// Policy: the **tip** can never be removed (commit a newer version first), nor the only
/// version. Under **light** retention the seal must go to a cold kit (`cold`) first, or be
/// discarded on purpose with `force_drop`; under **full** retention an explicit remove is
/// allowed (add `cold` to archive anyway). The chart is rewritten before the seal file is
/// deleted, so a crash leaves an orphan for `sigil gc`, never a dangling chart entry.
pub fn remove_version(
    path: &Path,
    n: u32,
    cold: Option<&Path>,
    force_drop: bool,
    dry_run: bool,
) -> Result<RemoveVersionReport> {
    let (_live, vault_dir) = resolve_paths(path)?;
    let mut chart = load_chart(&vault_dir)?;
    let entry = entry_by_n(&chart, n)?.clone();
    if n == chart.tip {
        return Err(crate::Error::Msg(format!(
            "v{n} is the tip and cannot be removed; commit a newer version first"
        )));
    }
    if chart.versions.len() <= 1 {
        return Err(crate::Error::Msg(
            "refusing to remove the only version".into(),
        ));
    }
    if matches!(chart.retention, RetentionPolicy::Light { .. }) && cold.is_none() && !force_drop {
        return Err(crate::Error::Msg(
            "light retention: removing a version needs --cold DIR (or --cold-here) to keep a cold kit, or --force-drop to discard it"
                .into(),
        ));
    }
    let report = RemoveVersionReport {
        removed: n,
        tip: chart.tip,
        remaining: chart.versions.len() as u32 - 1,
        cold_dir: cold.map(|p| p.to_path_buf()),
        dry_run,
    };
    if dry_run {
        return Ok(report);
    }
    if let Some(cold_root) = cold {
        fs::create_dir_all(cold_root).map_err(|e| crate::Error::Msg(e.to_string()))?;
        cold_archive_version(&chart.vault_dir, &entry, cold_root)?;
    }
    chart.versions.retain(|v| v.n != n);
    write_chart(&chart)?;
    let _ = fs::remove_file(seal_path_in(&chart.vault_dir, &entry.seal));
    Ok(report)
}

/// Place a version seal into `cold_root/vN/` via kit place when safe; else copy the `.sg1`.
fn cold_archive_version(vault_dir: &Path, entry: &VersionEntry, cold_root: &Path) -> Result<()> {
    let seal_path = seal_path_in(vault_dir, &entry.seal);
    let bytes = fs::read(&seal_path).map_err(|e| {
        crate::Error::Msg(format!(
            "read seal {} for cold archive: {e}",
            seal_path.display()
        ))
    })?;
    let dest = cold_root.join(format!("v{}", entry.n));
    fs::create_dir_all(&dest).map_err(|e| crate::Error::Msg(e.to_string()))?;
    // Kit place is single-star: on an SGDR folder pack `locate_header` would find only
    // the first inner star and archive that alone. Folder versions go cold as a plain copy.
    let placed = if bytes.starts_with(&crate::folder::DIR_MAGIC) {
        Err(crate::Error::Msg(
            "SGDR folder pack (kit place is single-star only)".into(),
        ))
    } else {
        crate::kit::place(&bytes, &dest, crate::kit::DEFAULT_DRIVES)
    };
    match placed {
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

/// Remembered encrypt-to recipients for a vault (public keys only).
pub fn get_recipients(path: &Path) -> Result<Vec<PublicIdentity>> {
    let (_live, vault_dir) = resolve_paths(path)?;
    if !vault_dir.join(CHART_NAME).is_file() {
        return Err(crate::Error::Msg(format!(
            "not tracked (no {}). Run `sigil vault track` first.",
            vault_dir.display()
        )));
    }
    Ok(load_chart(&vault_dir)?.recipients)
}

/// Replace remembered recipients (empty `recipients` = `--clear`: future versions go
/// plain on purpose). Existing version seals are never rewritten.
pub fn set_recipients(path: &Path, recipients: &[PublicIdentity]) -> Result<Vec<PublicIdentity>> {
    let (_live, vault_dir) = resolve_paths(path)?;
    if !vault_dir.join(CHART_NAME).is_file() {
        return Err(crate::Error::Msg(format!(
            "not tracked (no {}). Run `sigil vault track` first.",
            vault_dir.display()
        )));
    }
    let mut chart = load_chart(&vault_dir)?;
    chart.recipients = dedup_recipients(recipients);
    chart.plain_ok = chart.recipients.is_empty();
    write_chart(&chart)?;
    Ok(chart.recipients)
}

/// One line per recipient: short hint (as in SGTO) + X25519 public key.
pub fn format_recipients(rs: &[PublicIdentity]) -> String {
    if rs.is_empty() {
        return "encrypt-to: none remembered (new versions are not encrypt-to)\n".into();
    }
    let mut out = format!(
        "encrypt-to: {} remembered recipient{}\n",
        rs.len(),
        if rs.len() == 1 { "" } else { "s" }
    );
    for r in rs {
        out.push_str(&format!(
            "  hint={}  x25519={}\n",
            hex::encode(r.hint()),
            hex::encode(r.x25519_pk)
        ));
    }
    out
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
    let kind = if chart.kind == ChartKind::Folder {
        "  kind=folder"
    } else {
        ""
    };
    let mut out = format!(
        "vault {}  tip=v{}  versions={}  retention={}{}\n",
        chart.live.display(),
        chart.tip,
        chart.versions.len(),
        ret,
        kind
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
    use crate::folder::unseal_dir_only_keys;
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
        let seal_path = seal_path_in(&chart.vault_dir, &chart.versions[0].seal);
        let mut bytes = fs::read(&seal_path).unwrap();
        // Smash one shard past Keystone/header (byte 200 is still inside keystone copies).
        let (h, prefix, _) = locate_header(&bytes).unwrap();
        let stride = crate::header::shard_stride(&h);
        assert!(prefix + stride <= bytes.len());
        bytes[prefix..prefix + stride].fill(0);
        bytes[prefix] = 3;
        fs::write(&seal_path, &bytes).unwrap();
        assert!(mark_torn(&fs::read(&seal_path).unwrap()));
        fs::write(&live, b"garbage").unwrap();
        let r = restore(&live, Some(1), None, &[]).unwrap();
        assert_eq!(fs::read(&live).unwrap(), b"mend-me-please-0123456789abcdef");
        assert_eq!(r.digest, sha256(b"mend-me-please-0123456789abcdef"));
        assert!(r.mended, "single-file restore should mend a torn Seal mark");
        // On-disk seal healed (Merkle clean).
        let healed = fs::read(&seal_path).unwrap();
        let (_, merkle_ok, _, _, _) = crate::verify(&healed).unwrap();
        assert!(merkle_ok);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn folder_restore_mends_torn_inner_star() {
        let dir = tmpdir("fold-mend");
        let live = dir.join("photos");
        write_tree(
            &live,
            &[
                ("a.txt", b"mend-folder-a-0123456789abcdef-AAAAAAAA"),
                ("b.txt", b"mend-folder-b-0123456789abcdef-BBBBBBBB"),
                ("sub/c.txt", b"mend-folder-c-0123456789abcdef-CCCCCCCC"),
            ],
        );
        track(&live, Mode::Seal, None, &[]).unwrap();
        let v1 = version_seal_path(&live, 1).unwrap();
        let mut bytes = fs::read(&v1).unwrap();
        // Smash one shard inside the first classic inner star (past Keystone/header).
        assert!(bytes.len() >= 9 && &bytes[0..4] == b"SGDR");
        let mut off = 9usize;
        let nlen = u16::from_le_bytes(bytes[off..off + 2].try_into().unwrap()) as usize;
        off += 2 + nlen;
        let slen = u64::from_le_bytes(bytes[off..off + 8].try_into().unwrap()) as usize;
        off += 8; // start of first star
        let star = &bytes[off..off + slen];
        let (h, prefix, _) = locate_header(star).unwrap();
        let stride = crate::header::shard_stride(&h);
        assert!(
            prefix + stride <= slen,
            "inner star too short (slen={slen} prefix={prefix} stride={stride})"
        );
        let smash = off + prefix;
        bytes[smash..smash + stride].fill(0);
        bytes[smash] = 3;
        fs::write(&v1, &bytes).unwrap();
        let torn = fs::read(&v1).unwrap();

        // Trash live so restore must rebuild from the torn tip seal.
        fs::remove_dir_all(&live).unwrap();
        let r = restore(&live, Some(1), None, &[]).unwrap();
        assert!(r.mended, "folder restore should report mended");
        assert_eq!(
            tree_map(&live),
            vec![
                (
                    "a.txt".into(),
                    b"mend-folder-a-0123456789abcdef-AAAAAAAA".to_vec()
                ),
                (
                    "b.txt".into(),
                    b"mend-folder-b-0123456789abcdef-BBBBBBBB".to_vec()
                ),
                (
                    "sub/c.txt".into(),
                    b"mend-folder-c-0123456789abcdef-CCCCCCCC".to_vec()
                ),
            ]
        );
        // On-disk version seal is healed.
        let healed = fs::read(&v1).unwrap();
        assert_ne!(healed, torn);
        let open = dir.join("open-healed");
        unseal_dir_only_keys(&v1, &open, None, &[], &[], &[], &[]).unwrap();
        assert_eq!(
            tree_map(&open),
            vec![
                (
                    "a.txt".into(),
                    b"mend-folder-a-0123456789abcdef-AAAAAAAA".to_vec()
                ),
                (
                    "b.txt".into(),
                    b"mend-folder-b-0123456789abcdef-BBBBBBBB".to_vec()
                ),
                (
                    "sub/c.txt".into(),
                    b"mend-folder-c-0123456789abcdef-CCCCCCCC".to_vec()
                ),
            ]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    /// (rel, star_start, star_end) for each SGDR member.
    fn sgdr_members(pack: &[u8]) -> Vec<(String, usize, usize)> {
        assert_eq!(&pack[0..4], b"SGDR");
        let n = u32::from_le_bytes(pack[5..9].try_into().unwrap());
        let mut off = 9usize;
        let mut v = Vec::new();
        for _ in 0..n {
            let nlen = u16::from_le_bytes(pack[off..off + 2].try_into().unwrap()) as usize;
            off += 2;
            let name = String::from_utf8(pack[off..off + nlen].to_vec()).unwrap();
            off += nlen;
            let slen = u64::from_le_bytes(pack[off..off + 8].try_into().unwrap()) as usize;
            off += 8;
            v.push((name, off, off + slen));
            off += slen;
        }
        v
    }

    /// (start, end) of WORK chunk stars, absolute in `pack`, for a member at `m0..m1`.
    fn work_star_spans(pack: &[u8], m0: usize, m1: usize) -> Vec<(usize, usize)> {
        let member = &pack[m0..m1];
        assert_eq!(&member[0..4], b"SGWK");
        // head: magic4 ver1 chunk4 orig8 nlen1 name stars4 [overture4 if v2]
        let nlen = member[17] as usize;
        let mut off = 18 + nlen;
        let stars = u32::from_le_bytes(member[off..off + 4].try_into().unwrap());
        off += 4;
        if member[4] == 2 {
            off += 4;
        }
        let mut v = Vec::new();
        for _ in 0..stars {
            let len = u64::from_le_bytes(member[off..off + 8].try_into().unwrap()) as usize;
            off += 8;
            v.push((m0 + off, m0 + off + len));
            off += len;
        }
        v
    }

    fn smash(pack: &mut [u8], a: usize, b: usize, shard: usize) {
        let (h, prefix, _) = locate_header(&pack[a..b]).unwrap();
        let stride = crate::header::shard_stride(&h);
        let s = a + prefix + shard * stride;
        pack[s..s + stride].fill(0);
        pack[s] = 3;
    }

    fn pseudo(n: usize, seed: u64) -> Vec<u8> {
        let mut x = seed | 1;
        (0..n)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                (x >> 24) as u8
            })
            .collect()
    }

    #[test]
    fn folder_restore_mends_torn_work_member_chunks() {
        let dir = tmpdir("fold-work-mend");
        let live = dir.join("media");
        // > DEFAULT_CHUNK (4 MiB) → WORK/SGWK member with 2 chunk stars.
        let big = pseudo(DEFAULT_CHUNK as usize + 300 * 1024, 7);
        let small = b"small-classic-member-0123456789abcdef".to_vec();
        write_tree(&live, &[("big.bin", &big), ("notes/small.txt", &small)]);
        let id = Identity::generate().unwrap();
        track_ex(&live, Mode::Reflection, None, &[id.public()], &[]).unwrap();
        let v1 = version_seal_path(&live, 1).unwrap();
        let clean = fs::read(&v1).unwrap();
        // Encrypted folder versions are sealed directories (SGDR v2): one encrypted
        // body (here a WORK pack, the folder is > 4 MiB) carries the repair data.
        assert_eq!(
            &clean[0..5],
            b"SGDR\x02",
            "encrypt-to folder pack hides names"
        );
        assert!(!clean.windows(9).any(|w| w == b"small.txt"), "name leaked");
        let (b0, b1) = (17usize, clean.len());
        let stars = work_star_spans(&clean, b0, b1);
        assert!(stars.len() >= 2, "expected a multi-chunk WORK body");

        let mut torn = clean.clone();
        smash(&mut torn, stars[0].0, stars[0].1, 0); // chunk 0: one shard
        smash(&mut torn, stars[1].0, stars[1].1, 1); // chunk 1: another shard
        fs::write(&v1, &torn).unwrap();

        fs::remove_dir_all(&live).unwrap();
        let ids = [id.clone()];
        assert!(
            restore(&live, Some(1), None, &[]).is_err(),
            "encrypt-to needs the identity"
        );
        assert_eq!(
            fs::read(&v1).unwrap(),
            torn,
            "failed restore must not rewrite the seal"
        );
        let r = restore(&live, Some(1), None, &ids).unwrap();
        assert!(r.mended, "WORK chunk mend should report mended");
        assert_eq!(
            tree_map(&live),
            vec![
                ("big.bin".into(), big.clone()),
                ("notes/small.txt".into(), small.clone())
            ]
        );
        // Version seal healed in place: same size/layout, every star clean.
        let healed = fs::read(&v1).unwrap();
        assert_eq!(healed.len(), clean.len());
        for (a, b) in work_star_spans(&healed, b0, b1) {
            assert!(!crate::work::star_torn(&healed[a..b]));
        }
        assert!(!PathBuf::from(format!(
            "{}.mend-part",
            version_seal_path(&live, 1).unwrap().display()
        ))
        .exists());
        // Second restore is clean (no mend), and the healed pack opens directly.
        fs::remove_dir_all(&live).unwrap();
        let r2 = restore(&live, Some(1), None, &ids).unwrap();
        assert!(!r2.mended);
        let open = dir.join("open");
        unseal_dir_only_keys(&v1, &open, None, &[], &[], &[], &ids).unwrap();
        assert_eq!(fs::read(open.join("big.bin")).unwrap(), big);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn folder_restore_refuses_unmendable_work_member_without_rewrite() {
        let dir = tmpdir("fold-work-refuse");
        let live = dir.join("media");
        let big = pseudo(DEFAULT_CHUNK as usize + 100 * 1024, 11);
        write_tree(&live, &[("big.bin", &big)]);
        track(&live, Mode::Reflection, None, &[]).unwrap();
        let v1 = version_seal_path(&live, 1).unwrap();
        let mut torn = fs::read(&v1).unwrap();
        let (_, b0, b1) = sgdr_members(&torn)[0].clone();
        let stars = work_star_spans(&torn, b0, b1);
        let (h, _, _) = locate_header(&torn[stars[1].0..stars[1].1]).unwrap();
        for s in 0..=(h.n - h.k) as usize {
            smash(&mut torn, stars[1].0, stars[1].1, s);
        }
        fs::write(&v1, &torn).unwrap();
        fs::remove_dir_all(&live).unwrap();
        let e = restore(&live, Some(1), None, &[])
            .err()
            .unwrap()
            .to_string();
        assert!(e.contains("big.bin") && e.contains("star 1"), "{e}");
        assert_eq!(fs::read(&v1).unwrap(), torn);
        assert!(!live.exists() || tree_map(&live).is_empty());
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
            crate::unseal_ex_keys(&raw, None, &[], std::slice::from_ref(&alice)).unwrap(),
            b"vault-encrypt-v1"
        );

        fs::write(&live, b"vault-encrypt-v2").unwrap();
        let c = commit(&live, Mode::Glyph, None, false, &[alice.public()]).unwrap();
        assert_eq!(c.version, 2);
        let tip2 = tip_seal_path(&live).unwrap().0;
        assert_eq!(
            crate::unseal_ex_keys(
                &fs::read(&tip2).unwrap(),
                None,
                &[],
                std::slice::from_ref(&alice)
            )
            .unwrap(),
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
        assert!(dir.join("notes.txt.sigil/versions/v1.sg1").is_file());
        assert!(dir.join("notes.txt.sigil/versions/v2.sg1").is_file());
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn commit_from_export_bare_folder_needs_vault() {
        let dir = tmpdir("folder-bare");
        let export = dir.join("dirty");
        fs::create_dir_all(&export).unwrap();
        fs::write(export.join("a.txt"), b"a").unwrap();
        let meta = DirtyMeta {
            source: dir.join("tree.sg1"),
            seal: dir.join("tree.sg1"),
            live: None,
            vault: false,
            kind: "folder".into(),
        };
        meta.write(&export).unwrap();
        let err = commit_from_export(&export, Mode::Glyph, None, false, &[]).unwrap_err();
        assert!(err.to_string().contains("not from a folder vault"), "{err}");
        let _ = fs::remove_dir_all(&dir);
    }

    fn write_tree(root: &Path, files: &[(&str, &[u8])]) {
        for (rel, data) in files {
            let p = root.join(rel);
            fs::create_dir_all(p.parent().unwrap()).unwrap();
            fs::write(p, data).unwrap();
        }
    }

    fn tree_map(root: &Path) -> Vec<(String, Vec<u8>)> {
        tree_files(root)
            .unwrap()
            .into_iter()
            .map(|(r, p)| (r, fs::read(p).unwrap()))
            .collect()
    }

    fn export_writable(live: &Path, dest: &Path, identities: &[Identity]) {
        let vfs = crate::mount::VaultFs::open_keys(live, None, &[], true, identities).unwrap();
        let meta = dirty_meta_for(live, vfs.seal_path(), true).unwrap();
        assert!(meta.vault);
        assert_eq!(meta.kind, "folder");
        vfs.export_dir_ex(dest, true, Some(&meta)).unwrap();
    }

    #[test]
    fn vault_dir_for_ignores_trailing_slash() {
        assert_eq!(
            legacy_vault_dir_for(Path::new("photos/")),
            PathBuf::from("photos.sgv")
        );
        assert_eq!(
            vault_dir_for(Path::new("photos/")),
            PathBuf::from("photos.sigil")
        );
        assert_eq!(
            legacy_vault_dir_for(Path::new("/a/photos")),
            PathBuf::from("/a/photos.sgv")
        );
    }

    #[test]
    fn folder_vault_track_commit_restore() {
        let dir = tmpdir("fold-round");
        let live = dir.join("photos");
        write_tree(
            &live,
            &[
                ("a.txt", b"alpha"),
                ("b.txt", b"bravo"),
                ("sub/c.txt", b"charlie"),
            ],
        );
        let t = track(&live, Mode::Glyph, None, &[]).unwrap();
        assert_eq!(t.version, 1);
        let vdir = vault_dir_for(&live);
        let chart_txt = fs::read_to_string(vdir.join(CHART_NAME)).unwrap();
        assert!(chart_txt.contains("kind=folder"), "{chart_txt}");
        // v1 is an ordinary SGDR pack — plain folder unseal opens it.
        assert!(is_dir_pack(&seal_path_in(&vdir, "v1.sg1")));
        assert!(
            vdir.join("versions/v1.sg1").is_file()
                && vdir.join(crate::container::CONTAINER_FILE).is_file()
        );
        assert_eq!(status(&live).unwrap().drift, Drift::Match);

        // Dotfiles are not part of the tree (same rule as folder Inscribe).
        fs::write(live.join(".DS_Store"), b"junk").unwrap();
        assert_eq!(status(&live).unwrap().drift, Drift::Match);

        fs::write(live.join("a.txt"), b"alpha-2").unwrap();
        fs::remove_file(live.join("b.txt")).unwrap();
        assert_eq!(status(&live).unwrap().drift, Drift::Changed);
        let c = commit(&live, Mode::Glyph, None, false, &[]).unwrap();
        assert_eq!((c.version, c.skipped), (2, false));
        assert!(
            commit(&live, Mode::Glyph, None, false, &[])
                .unwrap()
                .skipped
        );

        // Restore v1: b.txt back, a.txt old bytes; dotfile untouched.
        let r = restore(&live, Some(1), None, &[]).unwrap();
        assert_eq!(r.version, 1);
        assert_eq!(
            tree_map(&live),
            vec![
                ("a.txt".into(), b"alpha".to_vec()),
                ("b.txt".into(), b"bravo".to_vec()),
                ("sub/c.txt".into(), b"charlie".to_vec()),
            ]
        );
        assert!(live.join(".DS_Store").is_file());
        // Back to tip v2: b.txt removed again.
        restore(&live, None, None, &[]).unwrap();
        assert!(!live.join("b.txt").exists());
        assert_eq!(status(&live).unwrap().drift, Drift::Match);

        // Missing live folder → restore recreates it.
        fs::remove_dir_all(&live).unwrap();
        assert_eq!(status(&live).unwrap().drift, Drift::MissingLive);
        restore(&live, None, None, &[]).unwrap();
        assert_eq!(status(&live).unwrap().drift, Drift::Match);
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn folder_export_reseal_edit_add_delete() {
        let dir = tmpdir("fold-export");
        let live = dir.join("docs");
        write_tree(
            &live,
            &[
                ("keep.txt", b"keep"),
                ("edit.txt", b"before"),
                ("gone/old.txt", b"old"),
            ],
        );
        track(&live, Mode::Reflection, None, &[]).unwrap();
        let v1 = version_seal_path(&live, 1).unwrap();
        let v1_sha = sha256_path(&v1).unwrap();

        let export = dir.join("dirty");
        export_writable(&live, &export, &[]);
        assert!(export.join(DIRTY_NAME).is_file());

        // Untouched export → skip (no new version).
        let skip = commit_from_export(&export, Mode::Reflection, None, false, &[]).unwrap();
        assert!(skip.skipped);

        fs::write(export.join("edit.txt"), b"after").unwrap();
        write_tree(&export, &[("new/added.txt", b"added")]);
        fs::remove_file(export.join("gone/old.txt")).unwrap();
        let c = commit_from_export(&export, Mode::Reflection, None, false, &[]).unwrap();
        assert_eq!((c.version, c.skipped), (2, false));
        assert!(c.note.is_none(), "{:?}", c.note);

        let want = vec![
            ("edit.txt".to_string(), b"after".to_vec()),
            ("keep.txt".to_string(), b"keep".to_vec()),
            ("new/added.txt".to_string(), b"added".to_vec()),
        ];
        // Live synced (clean before) and tip matches.
        assert_eq!(tree_map(&live), want);
        assert!(!live.join("gone").exists());
        assert_eq!(status(&live).unwrap().drift, Drift::Match);
        assert_eq!(list_versions(&live).unwrap().tip, 2);

        // New tip is a plain SGDR pack; open it with ordinary folder unseal.
        let out2 = dir.join("open-v2");
        unseal_dir_only_keys(
            &tip_seal_path(&live).unwrap().0,
            &out2,
            None,
            &[],
            &[],
            &[],
            &[],
        )
        .unwrap();
        assert_eq!(tree_map(&out2), want);
        // v1 immutable and still opens.
        assert_eq!(sha256_path(&v1).unwrap(), v1_sha);
        let out1 = dir.join("open-v1");
        unseal_dir_only_keys(&v1, &out1, None, &[], &[], &[], &[]).unwrap();
        assert_eq!(fs::read(out1.join("gone/old.txt")).unwrap(), b"old");
        assert_eq!(fs::read(out1.join("edit.txt")).unwrap(), b"before");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn folder_export_leaves_dirty_live_untouched() {
        let dir = tmpdir("fold-dirty-live");
        let live = dir.join("proj");
        write_tree(&live, &[("x.txt", b"x1")]);
        track(&live, Mode::Glyph, None, &[]).unwrap();
        let export = dir.join("dirty");
        export_writable(&live, &export, &[]);
        fs::write(export.join("x.txt"), b"x-from-export").unwrap();
        // Local uncommitted edit in live.
        fs::write(live.join("local.txt"), b"mine").unwrap();
        let c = commit_from_export(&export, Mode::Glyph, None, false, &[]).unwrap();
        assert_eq!(c.version, 2);
        assert!(c.note.as_deref().unwrap_or("").contains("left untouched"));
        assert_eq!(fs::read(live.join("x.txt")).unwrap(), b"x1");
        assert!(live.join("local.txt").is_file());
        assert_eq!(status(&live).unwrap().drift, Drift::Changed);

        // Restore refuses to eat local edits without --force.
        let err = restore(&live, None, None, &[]).unwrap_err();
        assert!(err.to_string().contains("uncommitted"), "{err}");
        restore_ex(&live, None, None, &[], &[], true).unwrap();
        assert_eq!(
            tree_map(&live),
            vec![("x.txt".into(), b"x-from-export".to_vec())]
        );
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn folder_reseal_keeps_encrypt_to_pass_and_ward() {
        let dir = tmpdir("fold-keys");
        let live = dir.join("sec");
        write_tree(&live, &[("a.txt", b"aaa"), ("p/b.txt", b"bbb")]);
        let alice = crate::Identity::generate().unwrap();
        track(&live, Mode::Glyph, None, &[alice.public()]).unwrap();
        let v1 = tip_seal_path(&live).unwrap().0;
        assert!(unseal_dir_only_keys(&v1, &dir.join("noid"), None, &[], &[], &[], &[]).is_err());

        let export = dir.join("dirty");
        export_writable(&live, &export, std::slice::from_ref(&alice));
        fs::write(export.join("a.txt"), b"aaa-2").unwrap();
        let wards = vec![("p/b.txt".to_string(), "room".to_string())];
        let c = commit_from_export_ex(
            &export,
            Mode::Glyph,
            Some("house"),
            false,
            &[alice.public()],
            &wards,
        )
        .unwrap();
        assert_eq!(c.version, 2);
        let v2 = tip_seal_path(&live).unwrap().0;
        // Identity alone opens a.txt (encrypt-to); p/b.txt needs its ward pass or identity.
        let o = dir.join("o-id");
        unseal_dir_only_keys(&v2, &o, None, &[], &[], &[], std::slice::from_ref(&alice)).unwrap();
        assert_eq!(fs::read(o.join("a.txt")).unwrap(), b"aaa-2");
        // Passphrase path: house for a.txt, room for p/b.txt.
        let o2 = dir.join("o-pass");
        unseal_dir_only_keys(&v2, &o2, Some("house"), &[], &[], &wards, &[]).unwrap();
        assert_eq!(fs::read(o2.join("p/b.txt")).unwrap(), b"bbb");
        // Wrong ward for p/b.txt fails.
        let o3 = dir.join("o-bad");
        assert!(unseal_dir_only_keys(&v2, &o3, Some("house"), &[], &[], &[], &[]).is_err());

        // Restore older v1 with identity (live synced from export, matches v2 → clean).
        restore_ex(&live, Some(1), None, &[alice], &[], false).unwrap();
        assert_eq!(fs::read(live.join("a.txt")).unwrap(), b"aaa");
        let _ = fs::remove_dir_all(&dir);
    }

    #[test]
    fn folder_light_retention_prunes_to_cold() {
        let dir = tmpdir("fold-light");
        let live = dir.join("t");
        write_tree(&live, &[("f.txt", b"1")]);
        track(&live, Mode::Seal, None, &[]).unwrap();
        let v1_sha = sha256_path(&version_seal_path(&live, 1).unwrap()).unwrap();
        set_retention(&live, RetentionPolicy::Light { keep: 1 }).unwrap();
        let export = dir.join("dirty");
        export_writable(&live, &export, &[]);
        fs::write(export.join("f.txt"), b"2").unwrap();
        commit_from_export(&export, Mode::Seal, None, false, &[]).unwrap();
        // Same retention hooks as ordinary commit.
        assert!(maybe_prune_after_commit(&live, None, None, false).is_err());
        let cold = dir.join("cold");
        let p = maybe_prune_after_commit(&live, None, Some(&cold), false)
            .unwrap()
            .unwrap();
        assert_eq!(p.removed, vec![1]);
        assert!(cold.join("v1").is_dir());
        assert!(!version_seal_path(&live, 1).unwrap().exists());
        // Whole SGDR version archived (not just its first inner star).
        let archived = cold.join("v1").join("v1.sg1");
        assert_eq!(sha256_path(&archived).unwrap(), v1_sha);
        assert!(cold.join("v1").join("ARCHIVE").is_file());
        assert!(!crate::kit::is_kit_dir(&cold.join("v1")));
        let o = dir.join("o-cold");
        unseal_dir_only_keys(&archived, &o, None, &[], &[], &[], &[]).unwrap();
        assert_eq!(fs::read(o.join("f.txt")).unwrap(), b"1");
        assert_eq!(list_versions(&live).unwrap().tip, 2);
        assert_eq!(fs::read(live.join("f.txt")).unwrap(), b"2");
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
            crate::kit::is_kit_dir(&cold.join("v1")) || cold.join("v1").join("v1.sg1").is_file(),
            "cold/v1 should be kit or plain archive"
        );
        assert!(!version_seal_path(&live, 1).unwrap().is_file());
        assert!(version_seal_path(&live, 3).unwrap().is_file());
        assert!(version_seal_path(&live, 4).unwrap().is_file());

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
        let any_plain = cold.read_dir().unwrap().filter_map(|e| e.ok()).any(|e| {
            let p = e.path();
            p.is_dir()
                && (p.join("ARCHIVE").is_file()
                    || p.join("v1.sg1").is_file()
                    || p.join(format!("{}.sg1", e.file_name().to_string_lossy()))
                        .is_file()
                    || fs::read_dir(&p)
                        .ok()
                        .map(|rd| {
                            rd.filter_map(|x| x.ok())
                                .any(|x| x.path().extension().map(|e| e == "sg1").unwrap_or(false))
                        })
                        .unwrap_or(false))
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
