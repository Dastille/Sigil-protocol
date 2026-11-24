//! Hard repair for bad-sector damage (roadmap item (g)): neighbour guesses, joint windows
//! and a miscorrection hunt. Decoder only; no byte layout change.
//!
//! A bad disk sector or flash page ruins one run of bytes in one place. Sigil stores byte
//! `j` of every shard as one Reed–Solomon column, so that run lands on **the same shard
//! across thousands of neighbouring columns**. The per-column steps of the ratchet ignore
//! that; these steps use it:
//!
//! 1. **Neighbour guess.** A run of stuck columns is tried with the shards its nearest
//!    settled neighbours were changed on, confirmed on the whole run at once.
//! 2. **Joint windows** (collaborative decoding of interleaved Reed–Solomon codes:
//!    Bleichenbacher, Kiayias and Yung, ICALP 2003; Schmidt, Sidorenko and Bossert, IEEE
//!    Trans. Inf. Theory 55(7), 2009). Nearby stuck columns form a window. The smallest set
//!    of soft shards (at most `p − k − 1`) whose erasure makes **every** column of the
//!    window a codeword, with at least [`MIN_SPARE`] spare symbols across the window,
//!    settles it. If two different sets of that size fit, the window is refused; if none
//!    fits, it is halved (down to [`WMIN`] columns).
//! 3. **Miscorrection hunt** (anchor decoding: Häger and Pfister, IEEE Trans. Commun.
//!    66(7), 2018). Inside a damaged region a settled column that changed a shard neither
//!    neighbour changed was probably decoded to a wrong codeword. It is decided again with
//!    its neighbours' erasure set on the bytes as read, and the new fix replaces the old
//!    one only if it is confirmed by at least [`MIN_HUNT_CHECKS`] independent spare
//!    symbols and changes no CRC-verified shard.
//!
//! None of this is trusted on its own. Exactly like the rest of the ratchet, the caller
//! accepts the result only after re-encoding every shard and matching the header's Merkle
//! root (and the true name when not encrypted), so a wrong guess here can only make the
//! repair fail, never return wrong bytes. Work is capped by a budget and the window step
//! runs on [`super::par_map`] (stops on Ctrl-C; same answer for any thread count).

use std::collections::HashMap;

use super::{make_pattern, par_map, write_column, Pattern, Row};
use crate::rs;
use crate::Error;

/// Largest copy of the as-read bytes of the dirty columns (`p × dirty columns`) these steps
/// keep. Above it the steps are skipped and repair behaves as before.
pub(super) const MAX_READ_COPY: usize = 1 << 30;
/// Erasure guesses tried per window, at most.
const MAX_JOINT_PATTERNS: usize = 1 << 16;
/// Symbol steps (about `p·k²` per guess) allowed for building the window guesses, so wide
/// shard counts do not spend minutes before the search starts.
const PATTERN_BUILD_BUDGET: usize = 1 << 28;
/// Most columns in one window.
const WMAX: usize = 256;
/// Fewest columns in one window (smaller pieces stay stuck).
const WMIN: usize = 4;
/// Spare symbols, summed over the window, that must confirm a guess.
const MIN_SPARE: usize = 4;
/// Stuck columns at most this far apart go in the same window.
const MAX_GAP: usize = 8;
/// Independent spare symbols (rows outside the erased set and the rebuild basis) that
/// must confirm a hunt fix before it may replace a settled column. With one, a wrong
/// rebuild passes by chance about once in 256 columns.
pub(super) const MIN_HUNT_CHECKS: usize = 2;
/// Columns between Ctrl-C checks in the hunt.
const HUNT_CHECK_EVERY: usize = 4096;
/// Symbol steps one repair may spend building erasure guesses for the neighbour steps and
/// the hunt, together (about `k³ + p·k²` per guess). A 16-shard seal builds a guess in about
/// 4,000 steps, so this never binds there; at 254 shards it allows about 16 guesses.
pub(super) const BUILD_BUDGET: u64 = 1 << 28;
/// Build steps a neighbour step may spend before it must have settled something; with
/// nothing to show by then it stops (scattered damage, where neighbour sets never repeat).
/// About 4,000 guesses at 16 shards, one at 254.
pub(super) const DRY_BUILD_WORK: u64 = 1 << 24;
/// Most bytes one guess cache may hold (fixed memory, whatever the file size).
pub(super) const CACHE_BYTES: usize = 16 << 20;
/// Most erased sets one guess cache remembers (built or found unusable).
const MAX_CACHE_ENTRIES: usize = 1 << 16;

/// Symbol steps to build one erasure guess for `p` present shards and dimension `k`
/// (Vandermonde inverse plus the `p × k` generator).
pub(super) fn build_cost(p: usize, k: usize) -> u64 {
    let k = k as u64;
    k.saturating_mul(k)
        .saturating_mul(k)
        .saturating_add((p as u64).saturating_mul(k).saturating_mul(k))
        .max(1)
}

/// How many erasure guesses the window step builds for `p` present shards and dimension
/// `k`: [`MAX_JOINT_PATTERNS`], fewer for wide shard counts. Every default seal (16 shards)
/// gets the full number.
pub(super) fn pattern_cap(p: usize, k: usize) -> usize {
    let each = p.saturating_mul(k).saturating_mul(k).max(1);
    (PATTERN_BUILD_BUDGET / each).clamp(1, MAX_JOINT_PATTERNS)
}

/// A set of row positions (`0..256`; shard indexes stop at 254).
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq, Hash)]
pub(super) struct RowSet([u64; 4]);

impl RowSet {
    fn insert(&mut self, t: usize) {
        if let Some(w) = self.0.get_mut(t / 64) {
            *w |= 1 << (t % 64);
        }
    }

    fn contains(&self, t: usize) -> bool {
        self.0.get(t / 64).is_some_and(|w| (w >> (t % 64)) & 1 == 1)
    }

    fn is_empty(&self) -> bool {
        self.0.iter().all(|&w| w == 0)
    }

    fn union(self, o: RowSet) -> RowSet {
        let mut out = self;
        for (a, b) in out.0.iter_mut().zip(o.0) {
            *a |= b;
        }
        out
    }

    fn minus(self, o: RowSet) -> RowSet {
        let mut out = self;
        for (a, b) in out.0.iter_mut().zip(o.0) {
            *a &= !b;
        }
        out
    }

    fn rows(&self, p: usize) -> Vec<usize> {
        (0..p).filter(|&t| self.contains(t)).collect()
    }
}

/// The bytes of the dirty columns as they were read, before any fix. Only dirty columns
/// are ever changed by the ratchet, so every other column is unchanged by definition.
pub(super) struct ReadCols {
    /// Dirty column indexes, ascending.
    cols: Vec<usize>,
    p: usize,
    /// Column-major: `p` bytes per entry of `cols`.
    data: Vec<u8>,
}

impl ReadCols {
    /// Copy the dirty columns (`dirty` ascending). `None` when there are none or the copy
    /// would exceed [`MAX_READ_COPY`].
    pub(super) fn new(rows: &[Row], dirty: &[usize]) -> Option<Self> {
        let p = rows.len();
        let len = p.checked_mul(dirty.len())?;
        if dirty.is_empty() || len > MAX_READ_COPY {
            return None;
        }
        let mut data = Vec::with_capacity(len);
        for &j in dirty {
            data.extend(rows.iter().map(|r| r.body[j]));
        }
        Some(Self {
            cols: dirty.to_vec(),
            p,
            data,
        })
    }

    fn get(&self, j: usize) -> Option<&[u8]> {
        let i = self.cols.binary_search(&j).ok()?;
        self.data.get(i * self.p..(i + 1) * self.p)
    }

    /// Rows whose symbol in column `j` differs from what was read (soft rows only when
    /// `soft_only`).
    fn changed(&self, rows: &[Row], j: usize, soft_only: bool) -> RowSet {
        let mut m = RowSet::default();
        if let Some(read) = self.get(j) {
            for (t, (r, &v)) in rows.iter().zip(read).enumerate() {
                if r.body[j] != v && !(soft_only && r.hard) {
                    m.insert(t);
                }
            }
        }
        m
    }
}

/// Erasure patterns by erased set, built once each. Every build is charged to a shared
/// build budget and to the step's work count, and the cache holds at most [`CACHE_BYTES`]
/// and [`MAX_CACHE_ENTRIES`]; once either runs out, lookups of new sets say so
/// ([`Lookup::Spent`]) and the caller stops.
struct PatternCache {
    xs: Vec<u8>,
    power: Vec<u8>,
    k: usize,
    map: HashMap<RowSet, Option<Pattern>>,
    /// Bytes held by built guesses.
    bytes: usize,
    /// Guesses built.
    built: usize,
    /// Symbol steps spent building.
    work: u64,
}

/// The answer of [`PatternCache::get`].
enum Lookup<'a> {
    /// The guess erasing the set.
    Found(&'a Pattern),
    /// No usable guess: the set is empty or leaves no spare symbol.
    Unusable,
    /// Not built: the build budget or the cache cap is used up.
    Spent,
}

impl PatternCache {
    fn new(rows: &[Row], k: usize) -> Self {
        let xs: Vec<u8> = rows.iter().map(|r| r.x).collect();
        let power = rs::power_matrix(&xs, k);
        Self {
            xs,
            power,
            k,
            map: HashMap::new(),
            bytes: 0,
            built: 0,
            work: 0,
        }
    }

    /// The guess erasing `set`, building it (charged to `build_left`) when it is new.
    fn get(&mut self, set: RowSet, build_left: &mut u64) -> Result<Lookup<'_>, Error> {
        if !self.map.contains_key(&set) {
            let p = self.xs.len();
            let erased = set.rows(p);
            if erased.is_empty() || p < erased.len() + self.k + 1 {
                if self.map.len() < MAX_CACHE_ENTRIES {
                    self.map.insert(set, None);
                }
                return Ok(Lookup::Unusable);
            }
            let cost = build_cost(p, self.k);
            let size = p * self.k + 2 * p * std::mem::size_of::<usize>();
            if *build_left < cost
                || self.bytes.saturating_add(size) > CACHE_BYTES
                || self.map.len() >= MAX_CACHE_ENTRIES
            {
                return Ok(Lookup::Spent);
            }
            *build_left -= cost;
            self.work = self.work.saturating_add(cost);
            self.built += 1;
            self.bytes += size;
            let q = make_pattern(&self.xs, &self.power, &erased, self.k, 0.0)?;
            self.map.insert(set, Some(q));
        }
        Ok(match self.map.get(&set) {
            Some(Some(q)) => Lookup::Found(q),
            _ => Lookup::Unusable,
        })
    }
}

/// What a window step settled.
#[derive(Default)]
pub(super) struct Settled {
    /// Settled columns with their full codewords, ascending.
    pub fixed: Vec<(usize, Vec<u8>)>,
    /// Columns still stuck, ascending.
    pub still: Vec<usize>,
    /// Symbol multiply-compare steps spent (guess building included).
    pub work: u64,
    /// Stopped early at the work or build budget.
    pub budget_hit: bool,
    /// Erasure guesses built.
    pub built: usize,
    /// Bytes the guess cache held at the end (its peak).
    pub cache_bytes: usize,
}

/// Maximal runs of consecutive column indexes in an ascending list.
fn consecutive_runs(cols: &[usize]) -> Vec<&[usize]> {
    let mut out = Vec::new();
    let mut start = 0;
    for i in 1..=cols.len() {
        let breaks = match (cols.get(i), cols.get(i - 1)) {
            (Some(&a), Some(&b)) => a != b + 1,
            _ => true,
        };
        if breaks {
            if let Some(run) = cols.get(start..i) {
                if !run.is_empty() {
                    out.push(run);
                }
            }
            start = i;
        }
    }
    out
}

/// Step 1: each run of consecutive stuck columns tries the soft shards its two settled
/// neighbours were changed on, confirmed on every column of the run (at least
/// [`MIN_SPARE`] spare symbols in total).
pub(super) fn neighbour_windows(
    rows: &[Row],
    read: &ReadCols,
    stuck: &[usize],
    k: usize,
    build_left: &mut u64,
) -> Result<Settled, Error> {
    let shard_len = rows.first().map_or(0, |r| r.body.len());
    let mut stuck = stuck.to_vec();
    stuck.sort_unstable();
    stuck.dedup();
    let mut cache = PatternCache::new(rows, k);
    let mut out = Settled::default();
    let mut b = Vec::new();
    let mut spent = false;
    for run in consecutive_runs(&stuck) {
        let (Some(&first), Some(&last)) = (run.first(), run.last()) else {
            continue;
        };
        if spent {
            out.still.extend_from_slice(run);
            continue;
        }
        let left = first
            .checked_sub(1)
            .map(|c| read.changed(rows, c, true))
            .unwrap_or_default();
        let right = if last + 1 < shard_len {
            read.changed(rows, last + 1, true)
        } else {
            RowSet::default()
        };
        let mut done = false;
        let q = match cache.get(left.union(right), build_left)? {
            Lookup::Found(q) => Some(q),
            Lookup::Unusable => None,
            Lookup::Spent => {
                spent = true;
                None
            }
        };
        if let Some(q) = q {
            if q.checks.len() * run.len() >= MIN_SPARE {
                let mut all = true;
                for &j in run {
                    let (ok, w) = q.check(rows, j, &mut b);
                    out.work = out.work.saturating_add(w);
                    if !ok {
                        all = false;
                        break;
                    }
                }
                if all {
                    out.fixed.extend(run.iter().map(|&j| (j, q.fill(rows, j))));
                    done = true;
                }
            }
        }
        if !done {
            out.still.extend_from_slice(run);
        }
        if out.fixed.is_empty() && cache.work >= DRY_BUILD_WORK {
            spent = true;
        }
    }
    out.work = out.work.saturating_add(cache.work);
    out.budget_hit = spent;
    out.built = cache.built;
    out.cache_bytes = cache.bytes;
    Ok(out)
}

/// One window search, with its share of the work budget.
struct Window<'a> {
    rows: &'a [Row],
    pats: &'a [Pattern],
    budget: u64,
    work: u64,
    hit: bool,
}

impl Window<'_> {
    /// The one smallest erasure guess that makes every column in `cols` a codeword, as
    /// the full codewords; `None` when none fits, two disagree, or the budget ran out.
    fn explain(&mut self, cols: &[usize]) -> Option<Vec<Vec<u8>>> {
        let mut b = Vec::new();
        let mut level = None;
        let mut found: Option<Vec<Vec<u8>>> = None;
        for q in self.pats {
            if let Some(l) = level {
                if q.erased != l {
                    break;
                }
            }
            if q.checks.is_empty() || q.checks.len() * cols.len() < MIN_SPARE {
                continue;
            }
            if self.work >= self.budget {
                self.hit = true;
                return None;
            }
            let mut all = true;
            for &j in cols {
                let (ok, w) = q.check(self.rows, j, &mut b);
                self.work = self.work.saturating_add(w);
                if !ok {
                    all = false;
                    break;
                }
            }
            if !all {
                continue;
            }
            let fills: Vec<Vec<u8>> = cols.iter().map(|&j| q.fill(self.rows, j)).collect();
            match &found {
                None => {
                    found = Some(fills);
                    level = Some(q.erased);
                }
                Some(f) if *f == fills => {}
                Some(_) => return None,
            }
        }
        found
    }

    /// Settle `win` whole, or else each half (down to [`WMIN`] columns).
    fn split(&mut self, win: &[usize], out: &mut Vec<(usize, Option<Vec<u8>>)>) {
        if win.len() < WMIN || self.hit {
            out.extend(win.iter().map(|&j| (j, None)));
            return;
        }
        if let Some(f) = self.explain(win) {
            out.extend(win.iter().copied().zip(f.into_iter().map(Some)));
            return;
        }
        let (a, b) = win.split_at(win.len() / 2);
        self.split(a, out);
        self.split(b, out);
    }
}

/// Step 2: joint windows over the stuck columns. `pats` are erasure guesses over soft rows
/// in (size, likelihood) order; `budget` is shared evenly between windows, so the answer
/// does not depend on the thread count.
pub(super) fn joint_windows(
    rows: &[Row],
    pats: &[Pattern],
    stuck: &[usize],
    threads: usize,
    budget: u64,
) -> Result<Settled, Error> {
    let mut stuck = stuck.to_vec();
    stuck.sort_unstable();
    stuck.dedup();
    let mut runs: Vec<Vec<usize>> = Vec::new();
    for &j in &stuck {
        match runs.last_mut() {
            Some(r) if r.len() < WMAX && r.last().is_some_and(|&l| j - l <= MAX_GAP) => r.push(j),
            _ => runs.push(vec![j]),
        }
    }
    if runs.is_empty() {
        return Ok(Settled::default());
    }
    let share = (budget / runs.len() as u64).max(1);
    let ids: Vec<usize> = (0..runs.len()).collect();
    let per = par_map(&ids, threads, |i| {
        let mut w = Window {
            rows,
            pats,
            budget: share,
            work: 0,
            hit: false,
        };
        let mut out = Vec::new();
        if let Some(run) = runs.get(i) {
            w.split(run, &mut out);
        }
        (out, w.work, w.hit)
    })?;
    let mut res = Settled::default();
    for (cols, work, hit) in per {
        res.work = res.work.saturating_add(work);
        res.budget_hit |= hit;
        for (j, c) in cols {
            match c {
                Some(col) => res.fixed.push((j, col)),
                None => res.still.push(j),
            }
        }
    }
    Ok(res)
}

/// What the miscorrection hunt did.
#[derive(Default)]
pub(super) struct Hunt {
    /// Settled columns replaced by a confirmed neighbour-guided fix.
    pub replaced: usize,
    /// Symbol multiply-compare steps spent (guess building included).
    pub work: u64,
    /// Stopped early at the work or build budget.
    pub budget_hit: bool,
    /// Erasure guesses built.
    pub built: usize,
    /// Bytes the guess cache held at the end (its peak).
    pub cache_bytes: usize,
}

/// Step 3 (bounded: guesses are built from a shared build budget into a capped cache, and
/// the hunt stops once it has spent [`DRY_BUILD_WORK`] on builds without replacing
/// anything): re-decide settled columns that changed a shard neither neighbour changed, and
/// keep the new fix only if it checks on the bytes as read with at least `min_checks`
/// spare symbols, differs from the old one and changes no trusted (CRC-verified) shard.
#[allow(clippy::too_many_arguments)]
pub(super) fn hunt(
    rows: &mut [Row],
    read: &ReadCols,
    stuck: &[usize],
    k: usize,
    errs: &mut [u64],
    budget: u64,
    build_left: &mut u64,
    min_checks: usize,
) -> Result<Hunt, Error> {
    let p = rows.len();
    let mut stuck = stuck.to_vec();
    stuck.sort_unstable();
    let mut cache = PatternCache::new(rows, k);
    let mut out = Hunt::default();
    let cols = &read.cols;
    // Change masks as they were before the hunt touched anything: column `j` is only
    // written at its own turn, so its mask and its right neighbour's are read just before,
    // and the left neighbour's mask is carried over from the previous turn (constant
    // memory, same decisions as computing every mask first).
    let mut prev: Option<(usize, RowSet)> = None;
    let mut next: Option<(usize, RowSet)> =
        cols.first().map(|&c| (c, read.changed(rows, c, false)));
    for i in 0..cols.len() {
        if i % HUNT_CHECK_EVERY == 0 {
            crate::repair_ctl::check()?;
        }
        let Some((j, m)) = next else {
            break;
        };
        next = cols.get(i + 1).map(|&c| (c, read.changed(rows, c, false)));
        let left = match prev {
            Some((c, pm)) if c + 1 == j => pm,
            _ => RowSet::default(),
        };
        let right = match next {
            Some((c, nm)) if c == j + 1 => nm,
            _ => RowSet::default(),
        };
        prev = Some((j, m));
        if m.is_empty() || stuck.binary_search(&j).is_ok() {
            continue;
        }
        let around = left.union(right);
        if around.is_empty() || m.minus(around).is_empty() {
            continue;
        }
        // Too few rows left to confirm the fix independently: leave the column as settled
        // (decided before building anything, so it costs no budget).
        if around.rows(p).len() + k + min_checks.max(1) > p {
            continue;
        }
        if out.work.saturating_add(cache.work) >= budget
            || (out.replaced == 0 && cache.work >= DRY_BUILD_WORK)
        {
            out.budget_hit = true;
            break;
        }
        let Some(col) = read.get(j) else {
            continue;
        };
        let q = match cache.get(around, build_left)? {
            Lookup::Found(q) => q,
            Lookup::Unusable => continue,
            Lookup::Spent => {
                out.budget_hit = true;
                break;
            }
        };
        let (ok, w) = q.check_col(col);
        out.work = out.work.saturating_add(w);
        if !ok {
            continue;
        }
        let fill = q.fill_col(col);
        let mut differs = false;
        let mut touches_hard = false;
        for (r, &v) in rows.iter().zip(&fill) {
            if r.body[j] != v {
                differs = true;
                touches_hard |= r.hard;
            }
        }
        if differs && !touches_hard {
            write_column(rows, j, &fill, errs);
            out.replaced += 1;
        }
    }
    out.work = out.work.saturating_add(cache.work);
    out.built = cache.built;
    out.cache_bytes = cache.bytes;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn row_set_basics() {
        let mut a = RowSet::default();
        assert!(a.is_empty());
        for t in [0usize, 63, 64, 200, 255] {
            a.insert(t);
        }
        a.insert(300); // out of range: ignored, never a panic
        assert!(a.contains(64) && a.contains(255) && !a.contains(1) && !a.contains(300));
        assert_eq!(a.rows(256), vec![0, 63, 64, 200, 255]);
        let mut b = RowSet::default();
        b.insert(63);
        b.insert(7);
        assert_eq!(a.minus(b).rows(256), vec![0, 64, 200, 255]);
        assert_eq!(a.union(b).rows(70), vec![0, 7, 63, 64]);
        assert!(b.minus(a.union(b)).is_empty());
    }

    #[test]
    fn pattern_cap_keeps_default_seals_whole() {
        assert_eq!(pattern_cap(16, 12), MAX_JOINT_PATTERNS);
        assert_eq!(pattern_cap(16, 8), MAX_JOINT_PATTERNS);
        assert!(pattern_cap(70, 60) < 2000);
        assert_eq!(pattern_cap(255, 254), 16);
        assert_eq!(pattern_cap(0, 0), MAX_JOINT_PATTERNS);
    }

    /// Three columns of a 12-of-16 code: column 11 is "settled" with row 15 changed (a
    /// stand-in for a miscorrection), its neighbours changed `left` and `right`. The read
    /// bytes of column 11 are the truth with errors on the neighbours' rows, so erasing
    /// those rows rebuilds the truth. Returns (rows after the hunt, truth, replaced).
    fn hunt_case(
        left: &[usize],
        right: &[usize],
        tamper: impl Fn(&mut Vec<Row>, &[u8]),
        min_checks: usize,
    ) -> (Vec<Row>, Vec<Vec<u8>>, usize) {
        let payload: Vec<u8> = (0..12 * 32u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 9) as u8)
            .collect();
        let shards = rs::encode_shards(&payload, 12, 16).unwrap();
        let mk = |b: &Vec<Vec<u8>>| -> Vec<Row> {
            b.iter()
                .enumerate()
                .map(|(i, body)| Row {
                    x: rs::x_of(i),
                    hard: false,
                    crc: None,
                    body: body.clone(),
                })
                .collect()
        };
        let mut read_rows = mk(&shards);
        for &t in left {
            read_rows[t].body[10] ^= 0x11;
        }
        for &t in right {
            read_rows[t].body[12] ^= 0x22;
        }
        for &t in left.iter().chain(right) {
            read_rows[t].body[11] ^= 0x33;
        }
        let xs: Vec<u8> = read_rows.iter().map(|r| r.x).collect();
        tamper(&mut read_rows, &xs);
        let read = ReadCols::new(&read_rows, &[10, 11, 12]).unwrap();
        let mut rows = mk(&shards);
        rows[15].body[11] ^= 0x5a;
        let mut errs = vec![0u64; 16];
        let mut build_left = BUILD_BUDGET;
        let h = hunt(
            &mut rows,
            &read,
            &[],
            12,
            &mut errs,
            u64::MAX,
            &mut build_left,
            min_checks,
        )
        .unwrap();
        (rows, shards, h.replaced)
    }

    fn col(rows: &[Row], j: usize) -> Vec<u8> {
        rows.iter().map(|r| r.body[j]).collect()
    }

    fn truth_col(shards: &[Vec<u8>], j: usize) -> Vec<u8> {
        shards.iter().map(|s| s[j]).collect()
    }

    #[test]
    fn hunt_replaces_only_with_two_spare_confirmations() {
        // Two erased rows leave 16 - 12 - 2 = 2 spare symbols: the fix is confirmed twice
        // and replaces the wrong column with the truth.
        let (rows, truth, n) = hunt_case(&[3], &[7], |_, _| {}, MIN_HUNT_CHECKS);
        assert_eq!(n, 1);
        assert_eq!(col(&rows, 11), truth_col(&truth, 11));
        // Three erased rows leave one spare symbol: the old rule (one check) replaced it,
        // the two-check rule leaves the settled column alone.
        let (rows, truth, n) = hunt_case(&[3, 4], &[7], |_, _| {}, 1);
        assert_eq!(n, 1);
        assert_eq!(col(&rows, 11), truth_col(&truth, 11));
        let (rows, truth, n) = hunt_case(&[3, 4], &[7], |_, _| {}, MIN_HUNT_CHECKS);
        assert_eq!(n, 0);
        let mut want = truth_col(&truth, 11);
        want[15] ^= 0x5a;
        assert_eq!(col(&rows, 11), want, "column must stay exactly as settled");
    }

    /// A tampered read that fools a single check: a basis symbol is changed and the one
    /// spare row is forged to match the wrong rebuild. With one check the hunt writes that
    /// wrong column; with two it is never reached. With two spare rows and only one of
    /// them forged, the check fails and nothing is replaced.
    #[test]
    fn hunt_two_checks_resist_a_forged_spare_symbol() {
        let forge = |erased: Vec<usize>, forge_rows: usize| {
            move |rr: &mut Vec<Row>, xs: &[u8]| {
                let power = rs::power_matrix(xs, 12);
                let q = make_pattern(xs, &power, &erased, 12, 0.0).unwrap();
                rr[q.basis[0]].body[11] ^= 0x77;
                let c: Vec<u8> = rr.iter().map(|r| r.body[11]).collect();
                let w = q.fill_col(&c);
                for &t in q.checks.iter().take(forge_rows) {
                    rr[t].body[11] = w[t];
                }
            }
        };
        // One spare row, forged: one check is fooled.
        let (rows, truth, n) = hunt_case(&[3, 4], &[7], forge(vec![3, 4, 7], 1), 1);
        assert_eq!(n, 1);
        assert_ne!(
            col(&rows, 11),
            truth_col(&truth, 11),
            "one check accepts the forgery"
        );
        let (rows, truth, n) = hunt_case(&[3, 4], &[7], forge(vec![3, 4, 7], 1), MIN_HUNT_CHECKS);
        assert_eq!(n, 0);
        let mut want = truth_col(&truth, 11);
        want[15] ^= 0x5a;
        assert_eq!(col(&rows, 11), want);
        // Two spare rows, one forged: the other catches it.
        let (rows, truth, n) = hunt_case(&[3], &[7], forge(vec![3, 7], 1), MIN_HUNT_CHECKS);
        assert_eq!(n, 0);
        let mut want = truth_col(&truth, 11);
        want[15] ^= 0x5a;
        assert_eq!(col(&rows, 11), want);
    }

    #[test]
    fn consecutive_runs_split_on_gaps() {
        let cols = [1usize, 2, 3, 7, 9, 10];
        let runs = consecutive_runs(&cols);
        assert_eq!(runs, vec![&[1usize, 2, 3][..], &[7][..], &[9, 10][..]]);
        assert!(consecutive_runs(&[]).is_empty());
    }
}
