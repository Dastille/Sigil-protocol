//! Save what you can from a damaged Tome (`sigil unseal --salvage`).
//!
//! Plain `unseal` is all-or-nothing. Salvage restores every member that still passes its
//! own checks (length and SHA-256, merkle root, or AEAD tag, after the same repair `mend`
//! would do) and never writes one that does not. It finds each member's stored data
//! directly: it follows the folder list while the list reads cleanly and, where the list
//! is damaged, scans for the next star and the next intact member head.
//!
//! Names:
//! * a Warded (v2) or protected (v3) Tome: the list is inside the body and checked by its
//!   SHA-256 / AEAD, so list names are used as they are;
//! * a plain v1 Tome: a list name is used when its member head reads cleanly, it keeps
//!   the order and uniqueness Inscribe writes, and the member's own header confirms all
//!   of it (a header keeps the first 16 bytes of the name, so longer names cannot be
//!   confirmed). Every other member is written under `recovered-names/` with a name built
//!   from its header (`NNNN-<header prefix>`), and the report shows what the list said.
//!
//! Nothing is overwritten: a name that is already taken gets `.salvaged-N` and is
//! reported. A report file is written beside the output folder. Bounded: an optional
//! time limit, a cap on star magics tried per damaged stretch, and Ctrl-C; a limit stops
//! the run and reports what was not tried, it never guesses.

use std::fs::{self, OpenOptions};
use std::io::{BufWriter, Write};
use std::path::{Path, PathBuf};
use std::time::Instant;

use crate::folder::Scratch;
use crate::packhead::{self, Src};
use crate::{Identity, Result};

/// Folder (inside the output) for members whose names could not be confirmed.
pub const RECOVERED_DIR: &str = "recovered-names";
/// Star magics tried while scanning one damaged stretch before the scan stops.
const SCAN_HITS: usize = 1_000_000;
/// Longest member name a resync tries (Inscribe names are at most 65535 bytes; real
/// paths are far shorter, and a longer one is only found again by its star).
const SCAN_NAME: usize = 4096;
/// Classic stars larger than this are not read into memory for repair.
const MAX_CLASSIC_MEND: u64 = 1 << 30;
const STAR_MAGIC: [u8; 4] = *b"SGIL";

/// Keys and limits for [`salvage_tome`].
pub struct SalvageOpts<'a> {
    pub pass: Option<&'a str>,
    pub companions: &'a [Vec<u8>],
    pub identities: &'a [Identity],
    /// Per-member ward passphrases: `(path in the Tome, passphrase)`.
    pub wards: &'a [(String, String)],
    /// Stop after this many seconds (reported; never a guess). `None`: no time limit.
    pub max_secs: Option<u64>,
}

/// How a member came out.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Outcome {
    /// Written under its list name.
    Restored { path: String },
    /// Written, but not under its list name: `why` says if it was a taken name or an
    /// unconfirmed one (then `path` is under [`RECOVERED_DIR`]).
    Renamed {
        listed: Option<String>,
        path: String,
        why: String,
    },
    /// Not written.
    Lost { label: String, why: String },
}

/// What [`salvage_tome`] did.
#[derive(Debug, Default)]
pub struct SalvageReport {
    pub outcomes: Vec<Outcome>,
    /// The Tome's own member count (from its head), when readable.
    pub listed_count: Option<u32>,
    /// True when every name came from a list that was checked (v2/v3 body).
    pub list_checked: bool,
    /// Why the run stopped early (a limit or Ctrl-C), if it did.
    pub stopped: Option<String>,
    /// Problems noticed (damaged list stretches, a cut-off end, ...).
    pub notes: Vec<String>,
    /// Where the report file was written.
    pub report_path: Option<PathBuf>,
}

impl SalvageReport {
    pub fn restored(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| matches!(o, Outcome::Restored { .. }))
            .count()
    }
    pub fn renamed(&self) -> usize {
        self.outcomes
            .iter()
            .filter(|o| matches!(o, Outcome::Renamed { .. }))
            .count()
    }
    /// Members not written, counting members the head lists but no star was found for.
    pub fn lost(&self) -> usize {
        let lost = self
            .outcomes
            .iter()
            .filter(|o| matches!(o, Outcome::Lost { .. }))
            .count();
        let seen = self.outcomes.len();
        let missing = self
            .listed_count
            .map_or(0, |n| (n as usize).saturating_sub(seen));
        lost + missing
    }
    /// 0: everything restored under its list name. 7: something written, but something
    /// lost, renamed, or stopped. 2: nothing written.
    pub fn exit_code(&self) -> i32 {
        let written = self.restored() + self.renamed();
        if written == 0 {
            2
        } else if self.renamed() == 0 && self.lost() == 0 && self.stopped.is_none() {
            0
        } else {
            7
        }
    }

    /// Human report (also the report file's contents).
    pub fn text(&self, input: &Path, dest: &Path) -> String {
        let mut s = String::new();
        s.push_str(&format!(
            "sigil salvage of {} into {}\n",
            crate::shown::name(&input.display().to_string()),
            crate::shown::name(&dest.display().to_string())
        ));
        s.push_str(&format!(
            "restored {}, renamed {}, lost {}{}\n",
            self.restored(),
            self.renamed(),
            self.lost(),
            match self.listed_count {
                Some(n) => format!(" (the Tome lists {n})"),
                None => String::new(),
            }
        ));
        s.push_str(if self.list_checked {
            "names: from the Tome's checked folder list\n"
        } else {
            "names: from the folder list where each name could be confirmed; others under recovered-names/\n"
        });
        if let Some(w) = &self.stopped {
            s.push_str(&format!("STOPPED: {w}\n"));
        }
        for n in &self.notes {
            s.push_str(&format!("note: {n}\n"));
        }
        for o in &self.outcomes {
            match o {
                Outcome::Restored { path } => {
                    s.push_str(&format!("restored  {}\n", crate::shown::name(path)))
                }
                Outcome::Renamed { listed, path, why } => s.push_str(&format!(
                    "renamed   {} -> {} ({why})\n",
                    listed
                        .as_deref()
                        .map_or("(no name)".to_string(), crate::shown::name),
                    crate::shown::name(path)
                )),
                Outcome::Lost { label, why } => s.push_str(&format!(
                    "lost      {} ({})\n",
                    crate::shown::name(label),
                    crate::shown::name(why)
                )),
            }
        }
        let missing = self
            .listed_count
            .map_or(0, |n| (n as usize).saturating_sub(self.outcomes.len()));
        if missing > 0 {
            s.push_str(&format!(
                "lost      {missing} more member(s) the Tome lists: no data found for them\n"
            ));
        }
        s
    }
}

/// One member found in a v1 pack: where its star is and what the list said.
struct Found {
    /// Name from a cleanly read member head (`None` for a star found without one).
    listed: Option<String>,
    star_off: u64,
    star_len: u64,
    /// The list name may be used as is.
    trusted: bool,
    /// The star runs past the end of the file.
    cut: bool,
}

struct Ctx<'a, 'o> {
    opts: &'a SalvageOpts<'o>,
    t0: Instant,
    dest: PathBuf,
    report: SalvageReport,
    seq: usize,
    /// Damage was seen in the list's shape (a skipped stretch, a cut-off end).
    damage_seen: bool,
}

impl Ctx<'_, '_> {
    /// `Some(why)` when a limit or Ctrl-C says stop.
    fn limit(&self) -> Option<String> {
        if crate::repair_ctl::stop_requested() {
            return Some("stopped by Ctrl-C".into());
        }
        if let Some(s) = self.opts.max_secs {
            if self.t0.elapsed().as_secs() >= s {
                return Some(format!("time limit of {s} s reached (--max-secs)"));
            }
        }
        None
    }
}

/// Restore what can be saved from the Tome at `input` into the folder `dest` (created if
/// missing; existing files are never overwritten). Returns the report; it is also
/// written to `<dest>.salvage-report.txt` (or `-N` when that exists).
pub fn salvage_tome(input: &Path, dest: &Path, opts: &SalvageOpts<'_>) -> Result<SalvageReport> {
    crate::refuse_empty_open_pass(opts.pass)?;
    let existed = dest.exists();
    fs::create_dir_all(dest).map_err(io)?;
    let r = salvage_into(input, dest, opts);
    if r.is_err() && !existed {
        // Refused before anything was saved: leave no empty folder behind.
        let _ = fs::remove_dir(dest);
    }
    r
}

fn salvage_into(input: &Path, dest: &Path, opts: &SalvageOpts<'_>) -> Result<SalvageReport> {
    let mut cx = Ctx {
        opts,
        t0: Instant::now(),
        dest: dest.to_path_buf(),
        report: SalvageReport::default(),
        seq: 0,
        damage_seen: false,
    };
    let mut head = [0u8; 21];
    let size = fs::metadata(input).map_err(io)?.len();
    {
        let mut f = packhead::FileSrc::open(input)?;
        let n = head.len().min(size as usize);
        f.read_at(0, &mut head[..n])?;
    }
    let ver = (head[0..4] == crate::folder::DIR_MAGIC).then_some(head[4]);
    match ver {
        Some(1) => {
            cx.report.listed_count = Some(u32::from_le_bytes([head[5], head[6], head[7], head[8]]));
            salvage_v1(&mut cx, input, false, 9)?;
        }
        Some(2) | Some(3) => {
            cx.report.listed_count = Some(u32::from_le_bytes([head[5], head[6], head[7], head[8]]));
            salvage_body(&mut cx, input, ver == Some(2))?;
        }
        _ if body_after_damaged_head(&head, size) => {
            // The 17-byte head is outside the repair data; the body after it is intact
            // enough to try. Its own checks decide; with a key given it is read as Warded.
            cx.damage_seen = true;
            cx.report.notes.push(
                "the Tome's first bytes are damaged; its body is read with its own checks".into(),
            );
            let keyed = opts.pass.is_some() || !opts.identities.is_empty();
            salvage_body(&mut cx, input, keyed)?;
        }
        Some(v) => {
            return Err(crate::Error::Msg(format!(
                "unknown Tome version {v}: made by a newer sigil, or damaged; nothing was written"
            )))
        }
        None => {
            // A damaged `SGDR` head on a plain Tome: its members still follow at byte 9.
            if crate::tome_guard::damaged_tome_head(input).is_some()
                && crate::tome_guard::member_at(&mut packhead::FileSrc::open(input)?, 9)
            {
                cx.damage_seen = true;
                cx.report
                    .notes
                    .push("the Tome's first bytes are damaged; read as a plain Tome".into());
                salvage_v1(&mut cx, input, false, 9)?;
            } else {
                return Err(crate::Error::Msg(
                    "not a Tome (salvage works on a Tome: a .sg1 of a folder); nothing was written"
                        .into(),
                ));
            }
        }
    }
    let mut report = cx.report;
    report.report_path = Some(write_report_file(dest, &report.text(input, dest))?);
    Ok(report)
}

/// A Tome head (first 17 bytes) that is damaged while a body star follows it and the
/// stored body length still matches the file.
fn body_after_damaged_head(head: &[u8; 21], size: u64) -> bool {
    if head[0..4] == crate::folder::DIR_MAGIC && matches!(head[4], 1..=3) {
        return false;
    }
    if size < 21 {
        return false;
    }
    let blen = u64::from_le_bytes([
        head[9], head[10], head[11], head[12], head[13], head[14], head[15], head[16],
    ]);
    let mag = &head[17..21];
    blen == size - 17 && (mag == STAR_MAGIC || mag == crate::work::WORK_MAGIC)
}

/// Warded (v2) or protected (v3): restore the body (with repair if needed) to a private
/// scratch copy of its inner v1 pack, then salvage that with its names trusted.
fn salvage_body(cx: &mut Ctx<'_, '_>, input: &Path, keyed: bool) -> Result<()> {
    let mut src = packhead::FileSrc::open(input)?;
    let len = src.size().saturating_sub(17);
    let body = Scratch(crate::folder::scratch_beside(&cx.dest, "salvage-body"));
    {
        let mut w = BufWriter::new(crate::staging::create_private(&body.0)?);
        packhead::copy_range(&mut src, 17, len, &mut w)?;
        w.flush().map_err(io)?;
    }
    let inner = Scratch(crate::folder::scratch_beside(&cx.dest, "salvage-inner"));
    let o = cx.opts;
    // A protected plain body is not encrypted, whatever key was given.
    let body_pass = if keyed { o.pass } else { None };
    let open = |from: &Path| -> Result<()> {
        let _ = fs::remove_file(&inner.0);
        let mut w = BufWriter::new(crate::staging::create_private(&inner.0)?);
        crate::work::unseal_path_into(from, &mut w, body_pass, o.companions, o.identities)?;
        w.flush().map_err(io)
    };
    let opened = match open(&body.0) {
        Ok(()) => Ok(()),
        Err(first) => match heal(&body.0, &cx.dest)? {
            Some(h) => open(&h.0).map_err(|e| (e, true)),
            None => Err((first, false)),
        },
    };
    if let Err((e, healed)) = opened {
        let _ = fs::remove_file(&inner.0);
        let e = e.to_string();
        if keyed && crate::recovery::key_problem(&e).is_some() {
            return Err(crate::Error::Msg(format!(
                "{e} (a Warded Tome's folder list and files open only with its key)"
            )));
        }
        cx.report.notes.push(format!(
            "the Tome body {}: {e}",
            if healed {
                "was repaired but still does not open"
            } else {
                "cannot be repaired or opened"
            }
        ));
        if keyed {
            return Ok(());
        }
        // A protected plain body is not encrypted: look for member data in it directly.
        // Its folder list is not checked then, so names follow the plain-Tome rules.
        cx.damage_seen = true;
        cx.report
            .notes
            .push("looking for member data in the unrepaired body directly".into());
        // Start inside the body, past the body's own star marker.
        return salvage_v1(cx, input, false, 17);
    }
    // The inner list's own head (checked with the body) has the true member count.
    {
        let mut h = [0u8; 9];
        let mut isrc = packhead::FileSrc::open(&inner.0)?;
        if isrc.size() >= 9
            && isrc.read_at(0, &mut h).is_ok()
            && h[0..4] == crate::folder::DIR_MAGIC
        {
            cx.report.listed_count = Some(u32::from_le_bytes([h[5], h[6], h[7], h[8]]));
        }
    }
    salvage_v1(cx, &inner.0, true, 9)
}

/// Repair a star or pack file in scratch: `Some(healed)` when a repair was made. The
/// strict repair is tried first, then the soft one `mend --soft` uses (its result is
/// still checked: Merkle binding of every shard and the true name, or the AEAD tag);
/// whatever comes out is opened with the member's own checks before anything is kept.
fn heal(star: &Path, dest: &Path) -> Result<Option<Scratch>> {
    let out = Scratch(crate::folder::scratch_beside(dest, "salvage-heal"));
    if crate::work::is_work_pack(star) {
        for soft in [false, true] {
            let _ = fs::remove_file(&out.0);
            if crate::work::mend_pack_path(star, &out.0, soft).is_ok() {
                return Ok(Some(out));
            }
            if crate::repair_ctl::stop_requested() {
                break;
            }
        }
        return Ok(None);
    }
    let len = fs::metadata(star).map_err(io)?.len();
    if len > MAX_CLASSIC_MEND {
        return Ok(None);
    }
    let bytes = fs::read(star).map_err(io)?;
    for soft in [false, true] {
        if let Ok((h, _)) = crate::pieces::mend_bytes_ex(&bytes, soft) {
            let mut f = crate::staging::create_private(&out.0)?;
            f.write_all(&h).map_err(io)?;
            return Ok(Some(out));
        }
        if crate::repair_ctl::stop_requested() {
            break;
        }
    }
    Ok(None)
}

/// Walk a v1 pack (the Tome itself, or a body's inner pack when `checked`): open every
/// member found into a private part file, then decide names and place them.
///
/// Names in a plain v1 list are not checked by anything but the 16 bytes each member's
/// header keeps, the order Inscribe writes and the list's own shape, and one changed
/// byte past those 16 cannot be seen. So a v1 list name is used only when the member's
/// own header confirms all of it; every other member goes under `recovered-names/` and
/// the report shows the name the list gives it.
fn salvage_v1(cx: &mut Ctx<'_, '_>, path: &Path, checked: bool, start: u64) -> Result<()> {
    cx.report.list_checked = checked;
    let mut src = packhead::FileSrc::open(path)?;
    let size = src.size();
    let mut found = find_members(cx, &mut src, size, checked, start)?;
    if !checked {
        distrust_order(&mut found);
    }
    let mut opened = Vec::with_capacity(found.len());
    for f in found {
        if let Some(w) = cx.limit() {
            cx.report.stopped = Some(w);
            cx.damage_seen = true;
            break;
        }
        cx.seq += 1;
        let o = open_one(cx, &mut src, &f, cx.seq)?;
        opened.push((f, o));
    }
    let structure_ok = !cx.damage_seen
        && cx.report.listed_count == Some(opened.len() as u32)
        && opened
            .last()
            .map_or(true, |(f, _)| f.star_off + f.star_len == size)
        && opened
            .iter()
            .all(|(f, o)| f.trusted && !f.cut && o.part.is_some() && !o.healed);
    let trust_list = checked;
    if structure_ok && !checked {
        cx.report.notes.push(
            "no damage was found in this plain Tome: `sigil unseal` restores it with every name"
                .into(),
        );
    }
    for (f, o) in opened {
        place_one(cx, f, o, trust_list)?;
    }
    Ok(())
}

fn distrust_order(found: &mut [Found]) {
    let mut seen = std::collections::HashMap::<String, usize>::new();
    let mut prev: Option<usize> = None;
    for i in 0..found.len() {
        let Some(name) = found[i].listed.clone().filter(|_| found[i].trusted) else {
            continue;
        };
        if let Some(&j) = seen.get(&name) {
            found[i].trusted = false;
            found[j].trusted = false;
        }
        seen.insert(name.clone(), i);
        if name.contains('\u{fffd}') {
            prev = None;
            continue;
        }
        if let Some(j) = prev {
            if let Some(p) = &found[j].listed {
                if name.split('/').cmp(p.split('/')) != std::cmp::Ordering::Greater {
                    found[i].trusted = false;
                    found[j].trusted = false;
                }
            }
        }
        prev = Some(i);
    }
}

/// A member head at `off`: `(name bytes, star offset, star length)` when it reads
/// cleanly (the same test the list guards use), else `None`.
fn head_at<S: Src>(src: &mut S, off: u64) -> Option<(Vec<u8>, u64, u64)> {
    if !crate::tome_guard::member_at(src, off) {
        return None;
    }
    let mut lb = [0u8; 2];
    src.read_at(off, &mut lb).ok()?;
    let nlen = u64::from(u16::from_le_bytes(lb));
    let mut name = vec![0u8; nlen as usize];
    src.read_at(off + 2, &mut name).ok()?;
    let mut sl = [0u8; 8];
    src.read_at(off + 2 + nlen, &mut sl).ok()?;
    Some((name, off + 2 + nlen + 8, u64::from_le_bytes(sl)))
}

/// Walk the list from byte 9; on a damaged stretch, scan for the next star magic and
/// the next clean member head.
fn find_members<S: Src>(
    cx: &mut Ctx<'_, '_>,
    src: &mut S,
    size: u64,
    checked: bool,
    start: u64,
) -> Result<Vec<Found>> {
    let mut out = Vec::new();
    let mut pos = start;
    let mut damaged_stretches = 0usize;
    while pos < size {
        if let Some(w) = cx.limit() {
            cx.report.stopped = Some(format!("{w}; the list after byte {pos} was not read"));
            break;
        }
        if let Some((name, star_off, star_len)) = head_at(src, pos) {
            let listed = String::from_utf8(name).ok();
            let mut trusted = listed.is_some();
            if let (Some(n), false) = (&listed, checked) {
                trusted = header_agrees(src, n, star_off, star_len);
            }
            out.push(Found {
                listed,
                star_off,
                star_len,
                trusted,
                cut: false,
            });
            pos = star_off + star_len;
            continue;
        }
        // Not a clean member head here. A member whose star runs past the end of the
        // file (a cut-off copy)?
        if let Some((name, star_off)) = cut_head_at(src, pos, size) {
            cx.damage_seen = true;
            cx.report
                .notes
                .push("the Tome is cut off inside its last member".into());
            out.push(Found {
                listed: String::from_utf8(name).ok(),
                star_off,
                star_len: size - star_off,
                trusted: false,
                cut: true,
            });
            break;
        }
        damaged_stretches += 1;
        match resync(cx, src, pos, size)? {
            Resync::Member { orphan, next } => {
                if let Some(o) = orphan {
                    out.push(Found {
                        listed: None,
                        star_off: o,
                        star_len: next - o,
                        trusted: false,
                        cut: false,
                    });
                }
                pos = next;
            }
            Resync::OrphanToEnd(o) => {
                out.push(Found {
                    listed: None,
                    star_off: o,
                    star_len: size - o,
                    trusted: false,
                    cut: false,
                });
                break;
            }
            Resync::Nothing => break,
            Resync::Stopped(why) => {
                cx.report.stopped = Some(why);
                break;
            }
        }
    }
    if damaged_stretches > 0 {
        cx.damage_seen = true;
        cx.report.notes.push(format!(
            "{damaged_stretches} damaged stretch(es) of the folder list were skipped by finding the member data directly"
        ));
    }
    Ok(out)
}

/// A member head at `pos` whose name reads but whose star runs past the end of file.
fn cut_head_at<S: Src>(src: &mut S, pos: u64, size: u64) -> Option<(Vec<u8>, u64)> {
    let mut lb = [0u8; 2];
    src.read_at(pos, &mut lb).ok()?;
    let nlen = u64::from(u16::from_le_bytes(lb));
    if nlen == 0 || pos + 2 + nlen + 8 + 4 > size {
        return None;
    }
    let mut name = vec![0u8; nlen as usize];
    src.read_at(pos + 2, &mut name).ok()?;
    crate::tome_guard::bad_name(&name).is_none().then_some(())?;
    let mut sl = [0u8; 8];
    src.read_at(pos + 2 + nlen, &mut sl).ok()?;
    let star = pos + 2 + nlen + 8;
    let slen = u64::from_le_bytes(sl);
    let mut mag = [0u8; 4];
    src.read_at(star, &mut mag).ok()?;
    (slen > size - star && (mag == STAR_MAGIC || mag == crate::work::WORK_MAGIC))
        .then_some((name, star))
}

enum Resync {
    /// The next clean member head is at `next`; `orphan` is a star found before it.
    Member {
        orphan: Option<u64>,
        next: u64,
    },
    /// A star with no clean member head after it.
    OrphanToEnd(u64),
    Nothing,
    Stopped(String),
}

/// Scan forward from `pos` (a damaged list stretch) a window at a time.
fn resync<S: Src>(cx: &Ctx<'_, '_>, src: &mut S, pos: u64, size: u64) -> Result<Resync> {
    let window = packhead::COPY_WINDOW;
    let keep = SCAN_NAME + 2 + 8;
    let mut buf: Vec<u8> = Vec::new();
    let mut buf_off = pos;
    let mut next = pos;
    let mut hits = 0usize;
    let mut orphan: Option<u64> = None;
    while next < size {
        if let Some(w) = cx.limit() {
            return Ok(Resync::Stopped(format!(
                "{w}; scanning a damaged stretch at byte {next}"
            )));
        }
        let n = usize::try_from((size - next).min(window as u64)).unwrap_or(window);
        let mut chunk = vec![0u8; n];
        src.read_at(next, &mut chunk)?;
        let drop = buf.len().saturating_sub(keep + 3);
        buf.drain(..drop);
        buf_off += drop as u64;
        let scan_from = buf.len().saturating_sub(3);
        buf.extend_from_slice(&chunk);
        next += n as u64;
        let mut i = scan_from;
        while i + 4 <= buf.len() {
            let m = &buf[i..i + 4];
            let at = buf_off + i as u64;
            if (m == STAR_MAGIC || m == crate::work::WORK_MAGIC) && at > pos {
                hits += 1;
                if hits > SCAN_HITS {
                    return Ok(Resync::Stopped(format!(
                        "more than {SCAN_HITS} star markers in one damaged stretch at byte {pos}"
                    )));
                }
                // A clean member head that ends right before this star?
                for v in 1..=SCAN_NAME.min(i.saturating_sub(10)) {
                    let h = i - 10 - v;
                    if usize::from(u16::from_le_bytes([buf[h], buf[h + 1]])) == v {
                        let hat = buf_off + h as u64;
                        if hat > pos && head_at(src, hat).is_some() {
                            // A star that starts inside this head is not an orphan.
                            let orphan = orphan.filter(|&o| o < hat);
                            return Ok(Resync::Member { orphan, next: hat });
                        }
                    }
                }
                if orphan.is_none() && star_parses(src, at) {
                    orphan = Some(at);
                }
            }
            i += 1;
        }
    }
    Ok(match orphan {
        Some(o) => Resync::OrphanToEnd(o),
        None => Resync::Nothing,
    })
}

fn star_parses<S: Src>(src: &mut S, at: u64) -> bool {
    let size = src.size();
    let n = usize::try_from((size - at).min(crate::tome_guard::STAR_PEEK as u64)).unwrap_or(0);
    let mut head = vec![0u8; n];
    if src.read_at(at, &mut head).is_err() {
        return false;
    }
    if head.starts_with(&crate::work::WORK_MAGIC) {
        crate::work::read_head(&mut &head[..]).is_ok()
    } else {
        crate::locate_header(&head).is_ok()
    }
}

/// The list name agrees with the 16 bytes the member's own header keeps (a header with
/// no name, e.g. an encrypted star, cannot disagree).
fn header_agrees<S: Src>(src: &mut S, name: &str, star_off: u64, star_len: u64) -> bool {
    match SubSrc2::window(src, star_off, star_len) {
        Some(mut w) => {
            let mut peek = [0u8; 4];
            if w.read_at(0, &mut peek).is_err() {
                return false;
            }
            if peek == crate::work::WORK_MAGIC {
                crate::tome_guard::check_pack(name, &mut w).is_ok()
            } else {
                let n =
                    usize::try_from(star_len.min(crate::tome_guard::STAR_PEEK as u64)).unwrap_or(0);
                let mut head = vec![0u8; n];
                w.read_at(0, &mut head).is_ok()
                    && crate::tome_guard::check_classic(name, &head).is_ok()
            }
        }
        None => false,
    }
}

/// A bounded window of a source (like `packhead::SubSrc`, usable as `&mut dyn Src`).
struct SubSrc2<'a, S: Src> {
    inner: &'a mut S,
    base: u64,
    len: u64,
}

impl<'a, S: Src> SubSrc2<'a, S> {
    fn window(inner: &'a mut S, base: u64, len: u64) -> Option<Self> {
        (base.checked_add(len)? <= inner.size()).then_some(Self { inner, base, len })
    }
}

impl<S: Src> Src for SubSrc2<'_, S> {
    fn size(&self) -> u64 {
        self.len
    }
    fn read_at(&mut self, off: u64, buf: &mut [u8]) -> Result<()> {
        off.checked_add(buf.len() as u64)
            .filter(|&e| e <= self.len)
            .ok_or_else(|| crate::Error::Msg("read past a member window".into()))?;
        self.inner.read_at(self.base + off, buf)
    }
}

/// One member opened (or not) into a private part file.
struct Opened {
    seq: usize,
    part: Option<Scratch>,
    /// It opened only after a repair.
    healed: bool,
    /// The name its own header keeps (first 16 bytes), when it keeps one.
    prefix: Option<String>,
    /// The header confirms the whole list name (not only its first 16 bytes).
    whole_name: bool,
    /// A plain star named like one chunk of a large-file pack (`name.0003`).
    chunk_like: bool,
    last_err: String,
}

/// Unseal one member (repairing it in scratch first if needed) into a part file.
fn open_one<S: Src>(cx: &Ctx<'_, '_>, src: &mut S, f: &Found, seq: usize) -> Result<Opened> {
    let mut o = Opened {
        seq,
        part: None,
        healed: false,
        prefix: None,
        whole_name: false,
        chunk_like: false,
        last_err: String::from("no key opened it"),
    };
    if f.cut {
        return Ok(o);
    }
    let star = Scratch(crate::folder::scratch_beside(&cx.dest, "salvage-star"));
    {
        let mut w = BufWriter::new(crate::staging::create_private(&star.0)?);
        packhead::copy_range(src, f.star_off, f.star_len, &mut w)?;
        w.flush().map_err(io)?;
    }
    let (prefix, is_pack) = star_name_prefix(&star.0);
    o.chunk_like = !is_pack && prefix.as_deref().is_some_and(chunk_name);
    o.prefix = prefix;
    if let (Some(n), Some(p), true) = (&f.listed, &o.prefix, f.trusted) {
        // A plain star keeps its whole path when it fits in 16 bytes; a large-file pack
        // keeps only its file name (`name.0000`), never the folders above it.
        o.whole_name = if is_pack {
            !n.contains('/') && format!("{n}.0000").len() <= 16
        } else {
            n.len() <= 16 && p == n
        };
    }
    let keys = member_keys(cx.opts, f.listed.as_deref().filter(|_| f.trusted));
    let mut healed: Option<Scratch> = None;
    'outer: for attempt in 0..2 {
        if attempt == 1 {
            match heal(&star.0, &cx.dest)? {
                Some(h) => healed = Some(h),
                None => break,
            }
        }
        let from = healed.as_ref().map_or(&star.0, |h| &h.0);
        for k in &keys {
            match unseal_part(cx, from, *k) {
                Ok(p) => {
                    o.part = Some(p);
                    o.healed = attempt == 1;
                    break 'outer;
                }
                Err(e) => o.last_err = e.to_string(),
            }
        }
    }
    Ok(o)
}

/// Name an opened member and link it into place, or record why it is lost.
fn place_one(cx: &mut Ctx<'_, '_>, f: Found, o: Opened, trust_list: bool) -> Result<()> {
    let seq = o.seq;
    let label = f.listed.clone().unwrap_or_else(|| {
        format!(
            "member {seq} (no readable name, data at byte {})",
            f.star_off
        )
    });
    if f.cut {
        cx.report.outcomes.push(Outcome::Lost {
            label,
            why: "cut off: its data runs past the end of the file".into(),
        });
        return Ok(());
    }
    let Some(part) = o.part else {
        cx.report.outcomes.push(Outcome::Lost {
            label,
            why: format!("its data does not pass its own checks: {}", o.last_err),
        });
        return Ok(());
    };
    if o.chunk_like && !(f.trusted && f.listed.is_some()) {
        // Found without a list entry of its own: most likely one part of a large file
        // whose pack head is damaged. Written alone it would look like the whole file.
        cx.report.outcomes.push(Outcome::Lost {
            label,
            why: "it looks like one part of a large file whose pack head is damaged; a part is never written as if it were the file".into(),
        });
        return Ok(());
    }
    let listed_ok =
        f.trusted && (trust_list || o.whole_name) && f.listed.as_deref().is_some_and(safe_rel);
    let recovered = recovered_rel(seq, o.prefix.as_deref());
    let rel = match (&f.listed, listed_ok) {
        (Some(n), true) => n.clone(),
        _ => recovered.clone(),
    };
    // Its own name, or (if that folder path cannot be made) a recovered name.
    let mut blocked = None;
    let mut path = place(cx, &part.0, &rel);
    if let (Err(e), true) = (&path, listed_ok) {
        blocked = Some(e.to_string());
        path = place(cx, &part.0, &recovered);
    }
    let path = match path {
        Ok(p) => p,
        Err(e) => {
            cx.report.outcomes.push(Outcome::Lost {
                label,
                why: format!("it passed its checks but could not be written: {e}"),
            });
            return Ok(());
        }
    };
    let shown = path
        .strip_prefix(&cx.dest)
        .map(|p| p.to_string_lossy().into_owned())
        .unwrap_or_else(|_| path.display().to_string());
    let why = if let Some(e) = blocked {
        Some(format!("its own folder path could not be made: {e}"))
    } else if listed_ok && shown == rel {
        None
    } else if listed_ok {
        Some("that name was already taken in the output folder".into())
    } else if f.listed.is_none() {
        Some("the folder list has no readable name for it".into())
    } else if f.trusted {
        Some(
            "the Tome is damaged and this member's own header cannot confirm its whole name".into(),
        )
    } else {
        Some("the damaged folder list's name for it could not be confirmed".into())
    };
    cx.report.outcomes.push(match why {
        None => Outcome::Restored { path: shown },
        Some(why) => Outcome::Renamed {
            listed: f.listed.clone(),
            path: shown,
            why,
        },
    });
    Ok(())
}

/// Passphrases to try for one member: the Tome's key, then its own Ward (when its name
/// is confirmed) or every Ward given (when it is not).
fn member_keys<'a>(o: &'a SalvageOpts<'_>, name: Option<&str>) -> Vec<Option<&'a str>> {
    let mut keys = vec![o.pass];
    match name {
        Some(n) => keys.extend(
            o.wards
                .iter()
                .filter(|(p, _)| p == n)
                .map(|(_, w)| Some(w.as_str())),
        ),
        None => keys.extend(o.wards.iter().map(|(_, w)| Some(w.as_str()))),
    }
    // An unencrypted member opens with no passphrase at all.
    keys.push(None);
    let mut uniq: Vec<Option<&'a str>> = Vec::with_capacity(keys.len());
    for k in keys {
        if !uniq.contains(&k) {
            uniq.push(k);
        }
    }
    uniq
}

/// Unseal `from` into a private part file in the output folder; the part is removed
/// unless it is linked into place. Any check failure leaves nothing behind.
fn unseal_part(cx: &Ctx<'_, '_>, from: &Path, pass: Option<&str>) -> Result<Scratch> {
    let part = Scratch(crate::folder::scratch_beside(
        &cx.dest.join("member"),
        "salvage-part",
    ));
    let file = crate::staging::create_private(&part.0)?;
    let mut w = BufWriter::new(file);
    crate::work::unseal_path_into(from, &mut w, pass, cx.opts.companions, cx.opts.identities)?;
    w.flush().map_err(io)?;
    Ok(part)
}

/// Link a checked part file to `rel` under the output folder without overwriting
/// anything (a taken name gets `.salvaged-N`). Returns the path written.
fn place(cx: &Ctx<'_, '_>, part: &Path, rel: &str) -> Result<PathBuf> {
    let target = cx.dest.join(rel);
    let dir = target
        .parent()
        .map(Path::to_path_buf)
        .unwrap_or_else(|| cx.dest.clone());
    fs::create_dir_all(&dir).map_err(io)?;
    let name = target
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "member".into());
    for k in 0..10_000u32 {
        let p = if k == 0 {
            target.clone()
        } else {
            target.with_file_name(format!("{name}.salvaged-{k}"))
        };
        // A hard link never replaces an existing file (or folder).
        match fs::hard_link(part, &p) {
            Ok(()) => return Ok(p),
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(io(e)),
        }
    }
    Err(crate::Error::Msg(format!(
        "no free name for {} (10000 taken)",
        crate::shown::name(rel)
    )))
}

/// The first 16 bytes of the name the star's own header keeps, if it keeps one, and
/// whether the star is a large-file pack (whose first chunk star is named `name.0000`).
fn star_name_prefix(star: &Path) -> (Option<String>, bool) {
    let Ok(mut src) = packhead::FileSrc::open(star) else {
        return (None, false);
    };
    let n = usize::try_from(src.size().min(crate::tome_guard::STAR_PEEK as u64)).unwrap_or(0);
    let mut head = vec![0u8; n];
    if src.read_at(0, &mut head).is_err() {
        return (None, false);
    }
    if head.starts_with(&crate::work::WORK_MAGIC) {
        let name = (|| {
            let l = packhead::layout(&mut src).ok()?;
            let &(off, len) = l.stars.first()?;
            let peek = usize::try_from(len.min(crate::tome_guard::STAR_PEEK as u64)).ok()?;
            let mut h = vec![0u8; peek];
            src.read_at(off, &mut h).ok()?;
            let name = crate::tome_guard::header_name(&h)?;
            Some(
                name.strip_suffix(".0000")
                    .map_or(name.clone(), str::to_string),
            )
        })();
        return (name, true);
    }
    (crate::tome_guard::header_name(&head), false)
}

/// A header name ending in a large-file chunk number (`.0000` to `.9999`).
fn chunk_name(name: &str) -> bool {
    let b = name.as_bytes();
    b.len() >= 5 && b[b.len() - 5] == b'.' && b[b.len() - 4..].iter().all(u8::is_ascii_digit)
}

/// `recovered-names/NNNN-<prefix>` (or `NNNN-unnamed`), made safe as one file name.
fn recovered_rel(seq: usize, prefix: Option<&str>) -> String {
    let clean: String = prefix
        .unwrap_or("")
        .chars()
        .map(|c| if c == '/' { '_' } else { c })
        .filter(|c| !c.is_control())
        .collect();
    let clean = clean.trim_matches('.').to_string();
    let base = if clean.is_empty() {
        "unnamed".to_string()
    } else {
        clean
    };
    format!("{RECOVERED_DIR}/{seq:04}-{base}")
}

/// A Tome name that may be joined under the output folder.
fn safe_rel(rel: &str) -> bool {
    crate::tome_guard::bad_name(rel.as_bytes()).is_none()
        && !Path::new(rel).is_absolute()
        && rel
            .split('/')
            .all(|p| p != ".." && p != "." && !p.contains('\0') && !p.contains('\\'))
        && !rel.starts_with(&format!("{RECOVERED_DIR}/"))
}

/// Write the report beside `dest` (`<dest>.salvage-report.txt`, `-N` when taken).
fn write_report_file(dest: &Path, text: &str) -> Result<PathBuf> {
    let base = dest
        .file_name()
        .map(|n| n.to_string_lossy().into_owned())
        .unwrap_or_else(|| "salvage".into());
    for k in 0..10_000u32 {
        let name = if k == 0 {
            format!("{base}.salvage-report.txt")
        } else {
            format!("{base}.salvage-report-{k}.txt")
        };
        let p = dest.with_file_name(name);
        match OpenOptions::new().write(true).create_new(true).open(&p) {
            Ok(mut f) => {
                f.write_all(text.as_bytes()).map_err(io)?;
                return Ok(p);
            }
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => continue,
            Err(e) => return Err(io(e)),
        }
    }
    Err(crate::Error::Msg(
        "no free name for the salvage report".into(),
    ))
}

fn io(e: std::io::Error) -> crate::Error {
    crate::Error::Msg(e.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn chunk_names_and_recovered_names() {
        assert!(chunk_name("video.bin.0000"));
        assert!(chunk_name("a.0123"));
        assert!(!chunk_name("a.012"));
        assert!(!chunk_name("notes.txt"));
        assert_eq!(
            recovered_rel(7, Some("dir/sub/file.t")),
            "recovered-names/0007-dir_sub_file.t"
        );
        assert_eq!(recovered_rel(12, None), "recovered-names/0012-unnamed");
        assert_eq!(recovered_rel(3, Some("..")), "recovered-names/0003-unnamed");
        assert!(safe_rel("a/b.txt"));
        assert!(!safe_rel("../x"));
        assert!(!safe_rel("/etc/x"));
        assert!(!safe_rel("recovered-names/0001-x"));
    }

    #[test]
    fn exit_codes_never_hide_a_loss() {
        let mut r = SalvageReport {
            listed_count: Some(2),
            ..Default::default()
        };
        assert_eq!(r.exit_code(), 2, "nothing written");
        r.outcomes.push(Outcome::Restored { path: "a".into() });
        assert_eq!(r.exit_code(), 7, "one listed member has no data");
        r.outcomes.push(Outcome::Restored { path: "b".into() });
        assert_eq!(r.exit_code(), 0);
        r.stopped = Some("time".into());
        assert_eq!(r.exit_code(), 7, "a limit stopped it");
        r.stopped = None;
        r.outcomes[1] = Outcome::Renamed {
            listed: None,
            path: "recovered-names/0002-b".into(),
            why: "x".into(),
        };
        assert_eq!(r.exit_code(), 7, "renamed");
    }
}
