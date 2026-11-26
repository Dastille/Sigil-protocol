//! `sigil doctor`: read-only health check of a vault or constellation.
//!
//! Looks for: CONTAINER manifest problems, old layouts, missing members, bit rot (ECC
//! verify; repairable damage points at `sigil mend`), orphans and temp files (shared with
//! `sigil gc`), and stale / broken cold kits. It never writes unless `fix` is set, and then
//! only the two safe, reversible-in-spirit operations: `sigil tidy` (old layout → Codex,
//! fingerprint-verified) and `sigil gc --apply`. Bit rot, missing members and cold kits are
//! never "fixed" automatically. See `docs/CODEX.md`.
//!
//! Exit codes (CLI): 0 healthy · 1 warnings only · 2 problems found · 3 could not check.

use std::collections::HashSet;
use std::fs;
use std::path::{Path, PathBuf};

use crate::container;
use crate::gc::{self, GcKind, GcOpts, Target};
use crate::keys::Identity;
use crate::Result;

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Severity {
    Info,
    Warn,
    Error,
}

impl Severity {
    pub fn label(self) -> &'static str {
        match self {
            Severity::Info => "info",
            Severity::Warn => "WARN",
            Severity::Error => "ERROR",
        }
    }
}

#[derive(Clone, Debug)]
pub struct Finding {
    pub severity: Severity,
    /// Stable machine-readable code (`star-missing`, `bit-rot`, `orphan-star`, …).
    pub code: &'static str,
    /// What it is about (relative path or list name).
    pub subject: String,
    pub message: String,
    /// What to do about it.
    pub hint: Option<String>,
}

#[derive(Clone, Debug, Default)]
pub struct DoctorReport {
    /// `vault` or `constellation`.
    pub kind: String,
    pub root: PathBuf,
    /// `container` or `old layout`.
    pub layout: String,
    pub container_version: Option<u32>,
    pub findings: Vec<Finding>,
    /// Stars / seals whose bytes were verified.
    pub verified: usize,
    /// Things `--fix` did (empty without `--fix`).
    pub fixed: Vec<String>,
}

/// A JSON string literal (quotes, backslashes and control characters escaped).
pub fn json_str(s: &str) -> String {
    let mut o = String::from("\"");
    for c in s.chars() {
        match c {
            '"' => o.push_str("\\\""),
            '\\' => o.push_str("\\\\"),
            '\n' => o.push_str("\\n"),
            '\r' => o.push_str("\\r"),
            '\t' => o.push_str("\\t"),
            c if (c as u32) < 0x20 => o.push_str(&format!("\\u{:04x}", c as u32)),
            c => o.push(c),
        }
    }
    o.push('"');
    o
}

impl DoctorReport {
    pub fn count(&self, s: Severity) -> usize {
        self.findings.iter().filter(|f| f.severity == s).count()
    }

    /// 0 healthy · 1 warnings only · 2 problems.
    pub fn exit_code(&self) -> i32 {
        if self.count(Severity::Error) > 0 {
            2
        } else if self.count(Severity::Warn) > 0 {
            1
        } else {
            0
        }
    }

    pub fn render(&self) -> String {
        self.render_as("doctor")
    }

    /// Same report under another command name (`sigil log verify`).
    pub fn render_as(&self, cmd: &str) -> String {
        let layout = crate::container::layout_label(self.layout.as_str());
        let mut s = format!(
            "{cmd} {} ({}, {}{})\n",
            self.root.display(),
            self.kind,
            layout,
            self.container_version
                .map(|v| format!(", format {v}"))
                .unwrap_or_default()
        );
        for f in &self.fixed {
            s.push_str(&format!("  fixed: {f}\n"));
        }
        for f in &self.findings {
            s.push_str(&format!(
                "  {:<5} {:<18} {}: {}\n",
                f.severity.label(),
                f.code,
                f.subject,
                f.message
            ));
            if let Some(h) = &f.hint {
                s.push_str(&format!("        → {h}\n"));
            }
        }
        let (e, w, i) = (
            self.count(Severity::Error),
            self.count(Severity::Warn),
            self.count(Severity::Info),
        );
        s.push_str(&format!("verified {} member(s)\n", self.verified));
        s.push_str(&match self.exit_code() {
            0 => format!(
                "result: healthy{}\n",
                if i > 0 {
                    format!(" ({i} note(s))")
                } else {
                    String::new()
                }
            ),
            1 => format!("result: warnings ({w} warning(s), {i} note(s)) — exit 1\n"),
            _ => format!("result: PROBLEMS ({e} error(s), {w} warning(s)) — exit 2\n"),
        });
        s
    }

    pub fn to_json(&self) -> String {
        let q = json_str;
        let status = match self.exit_code() {
            0 => "healthy",
            1 => "warnings",
            _ => "problems",
        };
        let findings: Vec<String> = self
            .findings
            .iter()
            .map(|f| {
                format!(
                    "{{\"severity\":{},\"code\":{},\"subject\":{},\"message\":{},\"hint\":{}}}",
                    q(match f.severity {
                        Severity::Info => "info",
                        Severity::Warn => "warn",
                        Severity::Error => "error",
                    }),
                    q(f.code),
                    q(&f.subject),
                    q(&f.message),
                    f.hint.as_deref().map(q).unwrap_or_else(|| "null".into())
                )
            })
            .collect();
        let fixed: Vec<String> = self.fixed.iter().map(|x| q(x)).collect();
        format!(
            "{{\"path\":{},\"kind\":{},\"layout\":{},\"container_version\":{},\"status\":{},\"exit_code\":{},\"verified\":{},\"errors\":{},\"warnings\":{},\"notes\":{},\"fixed\":[{}],\"findings\":[{}]}}\n",
            q(&self.root.display().to_string()),
            q(&self.kind),
            q(&self.layout),
            self.container_version.map(|v| v.to_string()).unwrap_or_else(|| "null".into()),
            q(status),
            self.exit_code(),
            self.verified,
            self.count(Severity::Error),
            self.count(Severity::Warn),
            self.count(Severity::Info),
            fixed.join(","),
            findings.join(",")
        )
    }
}

pub struct DoctorOpts<'a> {
    pub pass: Option<&'a str>,
    pub identities: &'a [Identity],
    /// Skip bit-level verification (existence / structure only).
    pub quick: bool,
    /// Apply the safe fixes (tidy an old layout, `gc --apply`).
    pub fix: bool,
    pub temp_age_secs: u64,
}

impl Default for DoctorOpts<'_> {
    fn default() -> Self {
        DoctorOpts {
            pass: None,
            identities: &[],
            quick: false,
            fix: false,
            temp_age_secs: gc::DEFAULT_TEMP_AGE_SECS,
        }
    }
}

fn f(
    sev: Severity,
    code: &'static str,
    subject: impl Into<String>,
    msg: impl Into<String>,
    hint: Option<String>,
) -> Finding {
    Finding {
        severity: sev,
        code,
        subject: subject.into(),
        message: msg.into(),
        hint,
    }
}

/// Outcome of verifying one seal / star.
#[derive(Debug)]
pub(crate) enum Health {
    Ok,
    /// Damaged but within the repair budget.
    Mendable(String),
    /// Beyond repair, or not readable as a Sigil.
    Damaged(String),
}

/// True when `healed` is `bytes` plus a trailing Keystone spare only (layout upgrade).
fn trailer_only_upgrade(bytes: &[u8], healed: &[u8]) -> bool {
    use crate::header::{keystone_trailer_len_at, KEYSTONE_TRAILER_SIZE};
    healed.len() == bytes.len() + KEYSTONE_TRAILER_SIZE
        && healed.starts_with(bytes)
        && keystone_trailer_len_at(healed, bytes.len()) > 0
}

pub(crate) fn health_bytes(bytes: &[u8]) -> Health {
    health_bytes_with(bytes, true)
}

/// [`health_bytes`]; `bounded` lets the last step (are the redundant copies intact?) use
/// [`crate::pieces::canonical_check`], which reaches the same verdict as mending a full copy
/// without holding several copies of the file in memory. `false` is the reference path.
pub(crate) fn health_bytes_with(bytes: &[u8], bounded: bool) -> Health {
    match crate::verify(bytes) {
        Err(e) => Health::Damaged(format!("not readable as a Sigil: {e}")),
        Ok((h, merkle_ok, live, k, recovered)) => {
            let n = h.n as usize;
            if live < k {
                Health::Damaged(format!("only {live}/{n} shards intact, need {k}"))
            } else if live < n || recovered {
                Health::Mendable(format!(
                    "{live}/{n} shards intact (need {k}){}",
                    if recovered {
                        ", header recovered from keystone"
                    } else {
                        ""
                    }
                ))
            } else if !merkle_ok {
                Health::Damaged(
                    "all shards present but Merkle root differs (corrupt shard data)".into(),
                )
            } else {
                // Every shard has one good copy, but Reflection / Seal keep redundant embers: if
                // the repaired form differs byte-for-byte, some copy has rotted (still safe today).
                // A healthy pre-trailer seal whose mend only appends an SGKT spare is not damage.
                if bounded {
                    use crate::pieces::Canon;
                    match crate::pieces::canonical_check(bytes) {
                        Some(Ok(Canon::Same | Canon::TrailerOnly)) => return Health::Ok,
                        Some(Ok(Canon::Differs)) => {
                            return Health::Mendable(
                                "redundant copies (shard or key-wrap spares) are damaged (data still intact)".into(),
                            )
                        }
                        Some(Err(e)) => return Health::Damaged(format!("repair pass failed: {e}")),
                        None => {}
                    }
                }
                match crate::mend_bytes(bytes) {
                    Ok(healed) if healed != bytes => {
                        if trailer_only_upgrade(bytes, &healed) {
                            Health::Ok
                        } else {
                            Health::Mendable(
                                "redundant copies (shard or key-wrap spares) are damaged (data still intact)".into(),
                            )
                        }
                    }
                    Ok(_) => Health::Ok,
                    Err(e) => Health::Damaged(format!("repair pass failed: {e}")),
                }
            }
        }
    }
}

/// Health of the star (a classic seal or a large-file pack) at `off..off + len` of
/// `path`: a pack is checked in place one part at a time; a classic seal (one AES-GCM
/// message, at most the `--chunk` it was sealed with) is read into memory.
fn health_window(path: &Path, off: u64, len: u64) -> Health {
    use crate::packhead::Src;
    let mut file = match crate::packhead::FileSrc::open(path) {
        Ok(f) => f,
        Err(e) => return Health::Damaged(format!("cannot read: {e}")),
    };
    let mut mag = [0u8; 4];
    if len >= 4 && file.read_at(off, &mut mag).is_err() {
        return Health::Damaged("cut off (incomplete copy)".into());
    }
    if mag == crate::work::WORK_MAGIC {
        return match crate::packhead::SubSrc::new(&mut file, off, len) {
            Ok(mut w) => health_pack_src(&mut w),
            Err(e) => Health::Damaged(e.to_string()),
        };
    }
    let mut star = vec![0u8; len as usize];
    match file.read_at(off, &mut star) {
        Ok(()) => health_bytes(&star),
        Err(e) => Health::Damaged(e.to_string()),
    }
}

fn health_work_pack(path: &Path) -> Health {
    match crate::packhead::FileSrc::open(path) {
        Ok(mut src) => health_pack_src(&mut src),
        Err(e) => Health::Damaged(e.to_string()),
    }
}

/// Health of a large-file pack: run the repair `sigil mend` would run, writing the
/// healed copy nowhere (one star in memory at a time; no scratch file).
fn health_pack_src<S: crate::packhead::Src>(src: &mut S) -> Health {
    let r = crate::work::mend_pack_src_to(src, &mut std::io::sink(), false);
    match r {
        Ok(rep) if rep.mended.is_empty() && rep.head == crate::HeadSource::Intact => Health::Ok,
        Ok(rep) if rep.head != crate::HeadSource::Intact => Health::Mendable(format!(
            "pack head damaged but rebuildable from the facet list; {} chunk star(s) torn",
            rep.mended.len()
        )),
        Ok(rep) => Health::Mendable(format!(
            "{} chunk star(s) torn but healable",
            rep.mended.len()
        )),
        Err(e) => Health::Damaged(e.to_string()),
    }
}

/// Verify a `.sg1` file of any shape: single mark, work pack, or SGDR folder pack.
pub(crate) fn health_file(path: &Path) -> Health {
    if crate::work::is_work_pack(path) {
        return health_work_pack(path);
    }
    if crate::is_sealed_dir_pack(path) {
        // Sealed directory: members are inside the encrypted body; check the body in
        // place (a large body one part at a time, never copied or held whole).
        return match crate::sealed_dir_body_loc(path) {
            Err(e) => Health::Damaged(format!("Tome body unreadable: {e}")),
            Ok(None) => Health::Damaged("Tome body unreadable".into()),
            Ok(Some((_, off, len))) => health_window(path, off, len),
        };
    }
    if crate::is_dir_pack(path) {
        let entries = match crate::folder::member_locs(path) {
            Ok(e) => e,
            Err(e) => return Health::Damaged(format!("Tome unreadable: {e}")),
        };
        let mut worst = Health::Ok;
        for (rel, off, len) in entries {
            let h = health_window(path, off, len);
            match (&h, &worst) {
                (Health::Damaged(m), _) => return Health::Damaged(format!("{rel}: {m}")),
                (Health::Mendable(m), Health::Ok) => {
                    worst = Health::Mendable(format!("{rel}: {m}"))
                }
                _ => {}
            }
        }
        return worst;
    }
    // A classic seal with intact framing is checked a window at a time.
    if let Ok(Some(h)) = crate::classic::health_path(path) {
        return h;
    }
    match fs::read(path) {
        Ok(b) => match health_bytes(&b) {
            Health::Ok => Health::Ok,
            // A pack whose SGWK magic is damaged reads as several seals in a row.
            other if crate::packhead::recover_bytes(&b).is_some() => {
                drop(b);
                match health_work_pack(path) {
                    Health::Ok => other,
                    h => h,
                }
            }
            other => other,
        },
        Err(e) => Health::Damaged(format!("cannot read: {e}")),
    }
}

fn rel(root: &Path, p: &Path) -> String {
    p.strip_prefix(root).unwrap_or(p).display().to_string()
}

fn push_health(rep: &mut DoctorReport, subject: &str, path: &Path, mend_target: &str) {
    rep.verified += 1;
    match health_file(path) {
        Health::Ok => {}
        Health::Mendable(m) => rep.findings.push(f(
            Severity::Warn,
            "bit-rot",
            subject,
            format!("{m} — repairable"),
            Some(format!(
                "{} (writes a repaired copy next to it; doctor does not rewrite your data)",
                crate::mend_out::mend_command(Path::new(mend_target))
            )),
        )),
        Health::Damaged(m) => rep.findings.push(f(
            Severity::Error,
            "bit-rot-unrecoverable",
            subject,
            m,
            Some("restore this file from another copy (backup, Frost Rune, atlas bag)".into()),
        )),
    }
}

fn add_gc_findings(rep: &mut DoctorReport, g: &gc::GcReport, root: &Path) {
    for i in &g.items {
        let (code, msg, hint): (&'static str, String, Option<String>) = match i.kind {
            GcKind::OrphanStar => (
                "orphan-star",
                format!("star no list entry uses ({} bytes)", i.bytes),
                Some("sigil gc --apply".into()),
            ),
            GcKind::OrphanVersion => (
                "orphan-version",
                format!("version seal the CHART does not list ({} bytes)", i.bytes),
                Some("sigil gc --apply".into()),
            ),
            GcKind::DuplicateStar => (
                "duplicate-star",
                format!("redundant copy of a star ({} bytes)", i.bytes),
                Some("sigil gc --apply".into()),
            ),
            GcKind::Temp => (
                "temp-file",
                "abandoned temp file".into(),
                Some("sigil gc --apply".into()),
            ),
            GcKind::StaleStaging => (
                "stale-staging",
                "interrupted `sigil tidy` staging folder".into(),
                Some("sigil gc --apply".into()),
            ),
            GcKind::OrphanSegment => (
                "orphan-segment",
                format!("segment no INDEX entry uses ({} bytes)", i.bytes),
                Some("sigil gc --apply".into()),
            ),
            GcKind::DeletedSegment => (
                "deleted-segment",
                format!(
                    "segment a tombstone deleted, still on disk ({} bytes)",
                    i.bytes
                ),
                Some("sigil log compact --apply (or sigil gc --apply)".into()),
            ),
            GcKind::SupersededSegment => (
                "superseded-segment",
                format!(
                    "segment merged into a compaction segment ({} bytes)",
                    i.bytes
                ),
                Some("sigil gc --apply".into()),
            ),
            GcKind::DeadKey => (
                "dead-key",
                "key ring record(s) of segments that are deleted, merged away or shredded".into(),
                Some("sigil gc --apply".into()),
            ),
            GcKind::EmptyDir => continue,
        };
        rep.findings
            .push(f(Severity::Warn, code, rel(root, &i.path), msg, hint));
    }
}

/// Check the vault or constellation at `path`.
pub fn doctor(path: &Path, opts: &DoctorOpts<'_>) -> Result<DoctorReport> {
    let mut fixed = Vec::new();
    let mut path = path.to_path_buf();
    if opts.fix {
        // Safe fix 1: old layout → Codex (fingerprint-verified copy, then remove old).
        let probe = analyze(&path, opts)?;
        if probe.layout == "old layout" {
            match container::tidy(
                &path,
                &container::TidyOpts {
                    dry_run: false,
                    pass: opts.pass,
                    identities: opts.identities,
                    fault: None,
                },
            ) {
                Ok(t) if !t.already => {
                    fixed.push(format!("tidied {} → {}", t.from.display(), t.to.display()));
                    path = t.to;
                }
                Ok(_) => {}
                Err(e) => fixed.push(format!("tidy skipped: {e}")),
            }
        }
        // Safe fix 2: gc --apply (orphans, duplicates, abandoned temp files).
        if let Ok(g) = gc::gc(
            &path,
            &GcOpts {
                apply: true,
                pass: opts.pass,
                identities: opts.identities,
                temp_age_secs: opts.temp_age_secs,
            },
        ) {
            let n = g.removed_count();
            if n > 0 {
                fixed.push(format!(
                    "gc removed {n} orphan/temp item(s) ({} bytes)",
                    g.items
                        .iter()
                        .filter(|i| i.removed)
                        .map(|i| i.bytes)
                        .sum::<u64>()
                ));
            }
        }
    }
    let mut rep = analyze(&path, opts)?;
    rep.fixed = fixed;
    Ok(rep)
}

fn manifest_findings(rep: &mut DoctorReport, dir: &Path, want_kind: &str) {
    if !container::is_container(dir) {
        return;
    }
    match container::read_manifest(dir) {
        Ok(m) => {
            rep.container_version = Some(m.version);
            if m.kind != want_kind {
                rep.findings.push(f(
                    Severity::Error,
                    "manifest-kind",
                    container::CONTAINER_FILE,
                    format!(
                        "manifest says kind={} but the folder holds a {want_kind}",
                        m.kind
                    ),
                    None,
                ));
            }
        }
        Err(e) => rep.findings.push(f(
            Severity::Error,
            "manifest",
            container::CONTAINER_FILE,
            e.to_string(),
            Some(
                "upgrade sigil if the `name.sigil/` layout is newer; otherwise restore the on-disk CONTAINER manifest from a copy"
                    .into(),
            ),
        )),
    }
}

fn old_layout_finding(rep: &mut DoctorReport) {
    rep.findings.push(f(
        Severity::Warn,
        "old-layout",
        rep.root.display().to_string(),
        "old layout still opens, but is not a Codex",
        Some("sigil tidy PATH (or doctor --fix)".into()),
    ));
}

fn analyze(path: &Path, opts: &DoctorOpts<'_>) -> Result<DoctorReport> {
    match gc::resolve_target(path)? {
        Target::Vault(v) => analyze_vault(&v, opts),
        Target::Sky(s) => analyze_sky(&s, opts),
        Target::Log(l) => analyze_log(&l, opts),
    }
}

fn analyze_log(dir: &Path, opts: &DoctorOpts<'_>) -> Result<DoctorReport> {
    let c = crate::seglog::check(
        dir,
        &crate::seglog::CheckOpts {
            pass: opts.pass,
            identities: opts.identities,
            quick: opts.quick,
            signer: None,
            anchors: &[],
            temp_age_secs: opts.temp_age_secs,
        },
    )?;
    Ok(DoctorReport {
        kind: "log".into(),
        root: dir.to_path_buf(),
        layout: "container".into(),
        container_version: c.container_version,
        findings: c.findings,
        verified: c.verified,
        fixed: Vec::new(),
    })
}

fn analyze_vault(vdir: &Path, opts: &DoctorOpts<'_>) -> Result<DoctorReport> {
    let is_container = crate::vault::is_container_vault_dir(vdir);
    let mut rep = DoctorReport {
        kind: "vault".into(),
        root: vdir.to_path_buf(),
        layout: if is_container {
            "container".into()
        } else {
            "old layout".into()
        },
        ..Default::default()
    };
    if is_container {
        manifest_findings(&mut rep, vdir, "vault");
    } else {
        old_layout_finding(&mut rep);
    }
    let chart = match crate::vault::load_chart(vdir) {
        Ok(c) => c,
        Err(e) => {
            rep.findings.push(f(
                Severity::Error,
                "chart",
                crate::vault::CHART_NAME,
                e.to_string(),
                Some("restore CHART from a copy; seals are still on disk".into()),
            ));
            return Ok(rep);
        }
    };
    if !chart.versions.iter().any(|v| v.n == chart.tip) {
        rep.findings.push(f(
            Severity::Error,
            "tip-missing",
            crate::vault::CHART_NAME,
            format!("tip v{} is not listed", chart.tip),
            None,
        ));
    }
    let hot: HashSet<u32> = chart.versions.iter().map(|v| v.n).collect();
    for v in &chart.versions {
        let p = crate::vault::seal_path_in(vdir, &v.seal);
        let subject = rel(vdir, &p);
        if !p.is_file() {
            rep.findings.push(f(
                Severity::Error,
                "seal-missing",
                subject,
                format!("CHART lists v{} but the seal file is gone", v.n),
                Some(if is_container {
                    "look in cold/ or a backup copy; `sigil vault restore` of other versions still works".into()
                } else {
                    "restore the seal from a backup copy".into()
                }),
            ));
            continue;
        }
        if !opts.quick {
            push_health(&mut rep, &subject, &p, &p.display().to_string());
        } else {
            rep.verified += 1;
        }
        if chart.kind == crate::vault::ChartKind::Single {
            if let Ok(bytes) = fs::read(&p) {
                if let Ok((h, _, _)) = crate::locate_header(&bytes) {
                    // A v3 encrypted seal shows no plaintext SHA-256 (only a keyed
                    // fingerprint), so the CHART cannot be compared without the key.
                    if !h.private_label() && h.digest != v.digest && !opts.quick {
                        rep.findings.push(f(
                            Severity::Warn,
                            "chart-digest",
                            rel(vdir, &p),
                            format!("seal's true-name differs from the CHART entry for v{}", v.n),
                            None,
                        ));
                    }
                }
            }
        }
    }
    // Live drift is a note, not a storage problem.
    if let Some(live) = crate::vault::resolve_paths(vdir).ok().map(|(l, _)| l) {
        if let Ok(st) = crate::vault::status(&live) {
            match st.drift {
                crate::vault::Drift::Changed => rep.findings.push(f(
                    Severity::Info,
                    "live-changed",
                    live.display().to_string(),
                    "live file differs from the tip (uncommitted edits)",
                    Some("sigil vault commit".into()),
                )),
                crate::vault::Drift::MissingLive => rep.findings.push(f(
                    Severity::Info,
                    "live-missing",
                    live.display().to_string(),
                    "live path is gone; the vault still holds every version",
                    Some("sigil vault restore".into()),
                )),
                _ => {}
            }
        }
    }
    // Cold kits.
    let cold = vdir.join(container::COLD_DIR);
    let mut cold_versions: HashSet<u32> = HashSet::new();
    if is_container && cold.is_dir() {
        let mut ents: Vec<PathBuf> = fs::read_dir(&cold)
            .map(|r| r.flatten().map(|e| e.path()).collect())
            .unwrap_or_default();
        ents.sort();
        for p in ents {
            let name = p
                .file_name()
                .and_then(|n| n.to_str())
                .unwrap_or("")
                .to_string();
            let Some(n) = name
                .strip_prefix('v')
                .and_then(|d| d.parse::<u32>().ok())
                .filter(|_| p.is_dir())
            else {
                rep.findings.push(f(
                    Severity::Info,
                    "cold-unknown",
                    rel(vdir, &p),
                    "not a Frost Rune cold folder (vN/); left alone",
                    None,
                ));
                continue;
            };
            cold_versions.insert(n);
            let subject = rel(vdir, &p);
            if hot.contains(&n) {
                rep.findings.push(f(
                    Severity::Info,
                    "cold-stale",
                    subject.clone(),
                    format!("v{n} is still hot in the chart; this cold copy is redundant"),
                    Some(format!(
                        "safe to delete {subject} by hand if you do not want the extra copy"
                    )),
                ));
            }
            check_cold_kit(&mut rep, &p, &subject, opts.quick);
        }
    }
    // History that left the chart without a cold kit.
    let max = chart.versions.iter().map(|v| v.n).max().unwrap_or(0);
    let light = matches!(chart.retention, crate::vault::RetentionPolicy::Light { .. });
    let gaps: Vec<u32> = (1..=max)
        .filter(|n| !hot.contains(n) && !cold_versions.contains(n))
        .collect();
    if !gaps.is_empty() && light {
        let list = gaps
            .iter()
            .map(|n| format!("v{n}"))
            .collect::<Vec<_>>()
            .join(", ");
        let uses_cold = !cold_versions.is_empty();
        rep.findings.push(f(
            if uses_cold { Severity::Warn } else { Severity::Info },
            "cold-missing",
            "cold/",
            format!("light retention: {list} left the chart and no Frost Rune (cold folder) for it is inside this Codex{}", if uses_cold { "" } else { " (fine if you used an external --cold DIR, which doctor cannot see)" }),
            Some("keep Frost Rune cold folders with `--cold-here` so they travel with the Codex".into()),
        ));
    }
    // Orphans / temp files, shared with gc.
    if let Ok(g) = gc::gc(
        vdir,
        &GcOpts {
            apply: false,
            pass: opts.pass,
            identities: opts.identities,
            temp_age_secs: opts.temp_age_secs,
        },
    ) {
        add_gc_findings(&mut rep, &g, vdir);
    }
    Ok(rep)
}

fn check_cold_kit(rep: &mut DoctorReport, dir: &Path, subject: &str, quick: bool) {
    if crate::kit::is_kit_dir(dir) {
        let usbs = fs::read_dir(dir)
            .map(|r| {
                r.flatten()
                    .filter(|e| {
                        e.file_name().to_string_lossy().starts_with("usb-") && e.path().is_dir()
                    })
                    .count()
            })
            .unwrap_or(0);
        let want = fs::read_to_string(dir.join(crate::kit::KIT_MANIFEST))
            .ok()
            .and_then(|t| {
                t.lines().find_map(|l| {
                    l.strip_prefix("drives=")
                        .and_then(|d| d.trim().parse::<usize>().ok())
                })
            })
            .unwrap_or(usbs);
        match crate::kit::mend(dir) {
            Err(e) => rep.findings.push(f(
                Severity::Error,
                "cold-broken",
                subject,
                format!("cold folder (Frost Rune) cannot be rebuilt: {e}"),
                Some("copy the missing usb-* folders back under the Frost Rune folder".into()),
            )),
            Ok(bytes) => {
                rep.verified += 1;
                if usbs < want {
                    rep.findings.push(f(Severity::Warn, "cold-degraded", subject, format!("cold folder (Frost Rune) has {usbs}/{want} usb folders; still mendable but one more loss may not be"), Some("re-place it (`sigil frost place`) after mending".into())));
                } else if !quick {
                    match health_bytes(&bytes) {
                        Health::Ok => {}
                        Health::Mendable(m) => rep.findings.push(f(
                            Severity::Warn,
                            "cold-degraded",
                            subject,
                            format!("rebuilt seal is damaged but repairable: {m}"),
                            None,
                        )),
                        Health::Damaged(m) => {
                            rep.findings
                                .push(f(Severity::Error, "cold-broken", subject, m, None))
                        }
                    }
                }
            }
        }
        return;
    }
    // Plain archive copy (+ ARCHIVE note).
    let seals: Vec<PathBuf> = fs::read_dir(dir)
        .map(|r| {
            r.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().map(|e| e == "sg1").unwrap_or(false))
                .collect()
        })
        .unwrap_or_default();
    if seals.is_empty() {
        rep.findings.push(f(
            Severity::Warn,
            "cold-broken",
            subject,
            "cold folder holds neither a Frost Rune (on-disk KIT manifest) nor a plain .sg1 archive",
            Some("the cold copy is empty; re-prune from a backup or delete the folder".into()),
        ));
        return;
    }
    for s in seals {
        if quick {
            rep.verified += 1;
        } else {
            push_health(
                rep,
                &format!(
                    "{subject}/{}",
                    s.file_name().and_then(|n| n.to_str()).unwrap_or("")
                ),
                &s,
                &s.display().to_string(),
            );
        }
    }
}

fn analyze_sky(sky: &Path, opts: &DoctorOpts<'_>) -> Result<DoctorReport> {
    let is_container = container::is_container(sky);
    let mut rep = DoctorReport {
        kind: "constellation".into(),
        root: sky.to_path_buf(),
        layout: if is_container {
            "container".into()
        } else {
            "old layout".into()
        },
        ..Default::default()
    };
    if is_container {
        manifest_findings(&mut rep, sky, "constellation");
    } else {
        old_layout_finding(&mut rep);
    }
    let Some(card) = crate::constellation::find_card(sky) else {
        rep.findings.push(f(
            Severity::Error,
            "card-missing",
            "card",
            "no constellation card (list) in this folder",
            None,
        ));
        return Ok(rep);
    };
    let chart = crate::constellation::load_chart_from_mark(&card, opts.pass, opts.identities);
    let by_digest = crate::constellation::index_stars(sky, Some(&card));
    let mut checked: HashSet<PathBuf> = HashSet::new();
    match chart {
        Ok(chart) => {
            let mut seen: HashSet<[u8; 32]> = HashSet::new();
            for m in chart.members.iter().filter(|m| m.bytes.is_empty()) {
                match crate::constellation::find_member_star(sky, m, &by_digest) {
                    None => rep.findings.push(f(
                        Severity::Error,
                        "star-missing",
                        m.name.clone(),
                        format!("list entry has no star on disk (fingerprint {})", crate::hex32(&m.digest)),
                        Some(format!("restore stars/{}/…sg1 from a copy or atlas bag, or `sigil constellation remove`", &crate::hex32(&m.digest)[..2])),
                    )),
                    Some(p) => {
                        if !seen.insert(m.digest) {
                            continue;
                        }
                        checked.insert(p.clone());
                        let subject = rel(sky, &p);
                        let key = crate::constellation::private_star_id(&p).unwrap_or(m.digest);
                        if is_container && p != container::star_path(sky, &key) && !subject.starts_with("stars/by-name") {
                            rep.findings.push(f(Severity::Info, "off-path-star", subject.clone(), "star is not at its fingerprint-sharded path", Some("sigil tidy normally files these".into())));
                        }
                        if !opts.quick {
                            push_health(&mut rep, &subject, &p, &p.display().to_string());
                        } else {
                            rep.verified += 1;
                        }
                    }
                }
            }
            if let Ok(g) = gc::gc(
                sky,
                &GcOpts {
                    apply: false,
                    pass: opts.pass,
                    identities: opts.identities,
                    temp_age_secs: opts.temp_age_secs,
                },
            ) {
                add_gc_findings(&mut rep, &g, sky);
            }
        }
        Err(e) => {
            rep.findings.push(f(
                Severity::Warn,
                "card-locked",
                rel(sky, &card),
                format!("list could not be opened ({e}); missing-member and orphan checks skipped"),
                Some("give --pass / --identity for the full check".into()),
            ));
        }
    }
    // Bit rot on stars not already checked (all of them when the card is locked; strays otherwise).
    if !opts.quick {
        let mut files: Vec<PathBuf> = Vec::new();
        let stars = sky.join(container::STARS_DIR);
        if stars.is_dir() {
            walk_sg1(&stars, &mut files);
        }
        files.retain(|p| !checked.contains(p));
        if rep.findings.iter().any(|x| x.code == "card-locked") {
            for p in files {
                let subject = rel(sky, &p);
                push_health(&mut rep, &subject, &p, &p.display().to_string());
            }
        }
    }
    Ok(rep)
}

fn walk_sg1(dir: &Path, out: &mut Vec<PathBuf>) {
    let mut ents: Vec<PathBuf> = fs::read_dir(dir)
        .map(|r| r.flatten().map(|e| e.path()).collect())
        .unwrap_or_default();
    ents.sort();
    for p in ents {
        if p.is_dir() {
            walk_sg1(&p, out);
        } else if p.extension().map(|e| e == "sg1").unwrap_or(false) {
            out.push(p);
        }
    }
}

#[cfg(test)]
mod tests {

    /// The bounded health check (borrowed shards, column-sliced re-encode, streamed true name,
    /// layout walk) reaches exactly the verdict of the reference path that mends a full copy.
    #[test]
    fn bounded_health_matches_reference() {
        use crate::Mode;
        fn same(a: &Health, b: &Health) -> bool {
            matches!(
                (a, b),
                (Health::Ok, Health::Ok)
                    | (Health::Mendable(_), Health::Mendable(_))
                    | (Health::Damaged(_), Health::Damaged(_))
            )
        }
        let mut cases: Vec<(String, Vec<u8>)> = Vec::new();
        let noise = |n: usize, seed: u32| -> Vec<u8> {
            (0..n as u32)
                .map(|i| (i.wrapping_add(seed).wrapping_mul(2654435761) >> 13) as u8)
                .collect()
        };
        for mode in [Mode::Glyph, Mode::Reflection, Mode::Seal] {
            for pass in [None, Some("pw")] {
                for (tag, data) in [
                    ("text", b"hello sigil ".repeat(5000)),
                    ("noise-odd", noise(123_457, 1)),
                    ("noise-big", noise(3 << 20, 2)),
                    ("tiny", b"x".to_vec()),
                    ("n2", noise(2, 3)),
                    ("n13", noise(13, 4)),
                    ("n25", noise(25, 5)),
                    ("n97", noise(97, 6)),
                    ("n1001", noise(1001, 7)),
                    ("t33", b"ab".repeat(33)),
                ] {
                    let Ok(b) = crate::seal(&data, mode, pass, "t.bin", false) else {
                        continue;
                    };
                    let name = format!("{mode:?}/{pass:?}/{tag}");
                    // damage one byte in the middle of every 7th KiB of the second half: hits
                    // redundant copies / shard bodies / CRCs depending on the layout
                    let mut torn = b.clone();
                    let mid = torn.len() / 2;
                    torn[mid] ^= 0x40;
                    cases.push((format!("{name}/flip-mid"), torn));
                    let mut tail = b.clone();
                    tail.truncate(b.len().saturating_sub(crate::header::KEYSTONE_TRAILER_SIZE));
                    cases.push((format!("{name}/no-trailer"), tail));
                    let mut extra = b.clone();
                    extra.extend_from_slice(b"junk");
                    cases.push((format!("{name}/trailing-junk"), extra));
                    cases.push((name, b));
                }
            }
        }
        let mut bounded_used = 0;
        for (name, b) in &cases {
            let fast = health_bytes_with(b, true);
            let slow = health_bytes_with(b, false);
            assert!(
                same(&fast, &slow),
                "{name}: bounded {fast:?} vs reference {slow:?}"
            );
            if crate::pieces::canonical_check(b).is_some() {
                bounded_used += 1;
            }
        }
        assert!(
            bounded_used > 20,
            "the bounded path ran on {bounded_used} cases"
        );
        assert!(
            matches!(health_bytes(&cases[3].1), Health::Ok),
            "{}",
            cases[3].0
        );
    }
    use super::*;

    #[test]
    fn damaged_pack_head_is_reported_as_mendable() {
        let fx = Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/pack-v0");
        let pack = fs::read(fx.join("pack-v2-reflection.sg1")).unwrap();
        let p = std::env::temp_dir().join(format!("sigil-doctor-ph-{}.sg1", std::process::id()));
        fs::write(&p, &pack).unwrap();
        assert!(matches!(health_file(&p), Health::Ok));
        for (lo, hi) in [(0, 4), (9, 17)] {
            let mut bad = pack.clone();
            bad[lo..hi].fill(0);
            fs::write(&p, &bad).unwrap();
            match health_file(&p) {
                Health::Mendable(m) => assert!(m.contains("pack head"), "{m}"),
                other => panic!("bytes {lo}..{hi}: {other:?}"),
            }
        }
        let mut gone = pack.clone();
        gone[..60].fill(0);
        fs::write(&p, &gone).unwrap();
        assert!(!matches!(health_file(&p), Health::Ok));
        let _ = fs::remove_file(&p);
    }
}
