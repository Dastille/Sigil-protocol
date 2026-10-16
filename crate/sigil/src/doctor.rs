//! `sigil doctor`: read-only health check of a vault or constellation.
//!
//! Looks for: container manifest problems, old layouts, missing members, bit rot (ECC
//! verify; repairable damage points at `sigil mend`), orphans and temp files (shared with
//! `sigil gc`), and stale / broken cold kits. It never writes unless `fix` is set, and then
//! only the two safe, reversible-in-spirit operations: `sigil tidy` (old layout → container,
//! fingerprint-verified) and `sigil gc --apply`. Bit rot, missing members and cold kits are
//! never "fixed" automatically. See `docs/CONTAINER.md`.
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
        let mut s = format!(
            "{cmd} {} ({}, {}{})\n",
            self.root.display(),
            self.kind,
            self.layout,
            self.container_version
                .map(|v| format!(" format {v}"))
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
        fn q(s: &str) -> String {
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
    /// Beyond repair, or not readable as a mark.
    Damaged(String),
}

pub(crate) fn health_bytes(bytes: &[u8]) -> Health {
    match crate::verify(bytes) {
        Err(e) => Health::Damaged(format!("not readable as a mark: {e}")),
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
                match crate::mend_bytes(bytes) {
                    Ok(healed) if healed != bytes => Health::Mendable(
                        "redundant shard copies are damaged (data still intact)".into(),
                    ),
                    Ok(_) => Health::Ok,
                    Err(e) => Health::Damaged(format!("repair pass failed: {e}")),
                }
            }
        }
    }
}

fn temp_path(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!("sigil-doctor-{}-{tag}", std::process::id()))
}

fn health_work_pack(path: &Path) -> Health {
    let tmp = temp_path("pack");
    let r = crate::work::mend_pack_path(path, &tmp, false);
    let _ = fs::remove_file(&tmp);
    match r {
        Ok(rep) if rep.mended.is_empty() => Health::Ok,
        Ok(rep) => Health::Mendable(format!(
            "{} chunk star(s) torn but healable",
            rep.mended.len()
        )),
        Err(e) => Health::Damaged(e.to_string()),
    }
}

/// Verify a `.sg1` file of any shape: single mark, work pack, or SGDR folder pack.
fn health_file(path: &Path) -> Health {
    if crate::work::is_work_pack(path) {
        return health_work_pack(path);
    }
    if crate::is_dir_pack(path) {
        let entries = match crate::list_dir_pack(path) {
            Ok(e) => e,
            Err(e) => return Health::Damaged(format!("folder pack unreadable: {e}")),
        };
        let mut worst = Health::Ok;
        for e in entries {
            let star = match crate::read_dir_entry_star(path, &e.path) {
                Ok(b) => b,
                Err(err) => return Health::Damaged(format!("{}: {err}", e.path)),
            };
            let h = if star.starts_with(&crate::work::WORK_MAGIC) {
                let tmp = temp_path("member");
                let ok = fs::write(&tmp, &star).is_ok();
                let h = if ok {
                    health_work_pack(&tmp)
                } else {
                    Health::Ok
                };
                let _ = fs::remove_file(&tmp);
                h
            } else {
                health_bytes(&star)
            };
            match (&h, &worst) {
                (Health::Damaged(m), _) => return Health::Damaged(format!("{}: {m}", e.path)),
                (Health::Mendable(m), Health::Ok) => {
                    worst = Health::Mendable(format!("{}: {m}", e.path))
                }
                _ => {}
            }
        }
        return worst;
    }
    match fs::read(path) {
        Ok(b) => health_bytes(&b),
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
            Some(format!("sigil mend {mend_target} -o healed.sg1, then replace the damaged file (doctor does not rewrite your data)")),
        )),
        Health::Damaged(m) => rep.findings.push(f(
            Severity::Error,
            "bit-rot-unrecoverable",
            subject,
            m,
            Some("restore this file from another copy (backup, cold kit, atlas bag)".into()),
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
        // Safe fix 1: old layout → container (fingerprint-verified copy, then remove old).
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
                "upgrade sigil if the container is newer; otherwise restore CONTAINER from a copy"
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
        "old layout still opens, but is not a tidy `name.sigil/` container",
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
                    if h.digest != v.digest && !opts.quick {
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
                    "not a cold kit folder (vN/); left alone",
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
            format!("light retention: {list} left the chart and no cold kit for it is inside this container{}", if uses_cold { "" } else { " (fine if you used an external --cold DIR, which doctor cannot see)" }),
            Some("keep cold kits with `--cold-here` so they travel with the container".into()),
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
                format!("cold kit cannot be rebuilt: {e}"),
                Some("copy the missing usb-* folders back under the kit".into()),
            )),
            Ok(bytes) => {
                rep.verified += 1;
                if usbs < want {
                    rep.findings.push(f(Severity::Warn, "cold-degraded", subject, format!("cold kit has {usbs}/{want} usb folders; still mendable but one more loss may not be"), Some("re-place the kit (`sigil kit place`) after mending".into())));
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
            "cold folder holds neither a kit (KIT) nor a plain .sg1 archive",
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
                        if is_container && p != container::star_path(sky, &m.digest) && !subject.starts_with("stars/by-name") {
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
