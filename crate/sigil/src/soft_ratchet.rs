//! Easy-first ("ratchet") soft repair of one Sigil's shards — the engine behind
//! `sigil mend --soft`.
//!
//! Decoder only: nothing on disk changes, old files open as before. Byte `j` of every shard
//! is one Reed–Solomon codeword (the evaluations at `x = index + 1` of a polynomial of
//! degree `< k`; v1 and v2 differ only in how the payload maps to that polynomial), so each
//! byte column can be settled on its own. Work goes from cheap and certain to expensive and
//! uncertain, and every settled column is locked in before the next step:
//!
//! 1. **Clean columns.** One matrix pass predicts every other shard from the first `k`;
//!    a column where every present symbol agrees is a codeword and is locked.
//! 2. **Berlekamp–Welch.** A dirty column is corrected when at most `(present − k) / 2`
//!    symbols disagree and no CRC-good ("hard") shard would change.
//! 3. **Erasure guesses with a check.** Still-stuck columns try erasing a few soft
//!    (CRC-failed) symbols, most likely culprits first. The order comes from which shards
//!    were wrong in already-fixed columns (and, when there are none, from a small sample of
//!    stuck columns). A guess locks only when at least two spare symbols agree with it.
//! 4. **Per-shard CRC.** For the few columns still stuck, each shard's stored CRC-32
//!    trailer is a check on that whole shard. CRC is linear, so the effect of each candidate
//!    fix on every shard's CRC is one table lookup — no re-hashing — and the combination
//!    that makes the stored CRCs match is chosen.
//! 5. **Best guess.** Anything left takes the most reliable `k` symbols.
//!
//! Between steps 3 and 4, runs of neighbouring stuck columns are settled together, because a
//! bad sector damages one shard over many neighbouring columns, and settled columns that
//! look miscorrected are decided again from their neighbours ([`joint`]).
//!
//! The result is **not** verified here. Exactly like before, the caller accepts it only
//! after re-encoding every shard once and matching the header's Merkle root (and the true
//! name when not encrypted); a wrong guess can only make the repair fail, never return
//! wrong bytes. Steps 2–3 race column blocks across several CPU threads (std only, no GPU;
//! [`crate::race`]); the answer is the same for any thread count.

use crate::gf;
use crate::rs;
use crate::Error;

mod joint;

#[cfg(test)]
thread_local! {
    static JOINT_OFF: std::cell::Cell<bool> = const { std::cell::Cell::new(false) };
}

/// Tests only: turn the [`joint`] steps off (or back on) for repairs on this thread, to
/// compare against the per-column ratchet alone.
#[cfg(test)]
pub(crate) fn set_joint_for_tests(on: bool) {
    JOINT_OFF.with(|c| c.set(!on));
}

#[cfg(test)]
fn joint_enabled() -> bool {
    !JOINT_OFF.with(|c| c.get())
}

#[cfg(not(test))]
fn joint_enabled() -> bool {
    true
}

/// One present shard for [`decode`].
#[derive(Clone, Copy, Debug)]
pub struct RatchetPart<'a> {
    /// Shard index (evaluation point `index + 1`).
    pub index: usize,
    /// Shard bytes as read.
    pub body: &'a [u8],
    /// The shard passed its stored CRC (trusted, never changed by repair).
    pub hard: bool,
    /// The CRC-32 trailer stored after a soft shard, if it was readable.
    pub stored_crc: Option<u32>,
}

/// What [`decode`] did, column by column (one column = byte `j` of every shard).
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct RatchetReport {
    /// Byte columns in the shard.
    pub columns: usize,
    /// Columns that were already one consistent codeword (or had no spare symbol to check).
    pub clean_columns: usize,
    /// Columns fixed by Berlekamp–Welch.
    pub bw_columns: usize,
    /// Columns fixed by an erasure guess confirmed by at least two spare symbols.
    pub erasure_columns: usize,
    /// Columns fixed by matching the stored per-shard CRC-32 trailers.
    pub crc_columns: usize,
    /// Columns left to an unconfirmed best guess (the final gate decides).
    pub guessed_columns: usize,
    /// Soft shards promoted to trusted because their stored CRC-32 matched after repair.
    pub promoted_shards: usize,
    /// Symbol multiply-compare steps spent on erasure guesses (a machine-independent work counter).
    pub guess_work: u64,
    /// The erasure-guess step stopped early because it reached its work budget.
    pub budget_hit: bool,
    /// Columns settled together with their neighbours (a neighbour guess or a joint window
    /// confirmed on every column of the run).
    pub joint_columns: usize,
    /// Settled columns that looked miscorrected and were replaced by a confirmed
    /// neighbour-guided fix.
    pub hunt_columns: usize,
    /// Symbol steps spent on the neighbour steps, building their erasure guesses included
    /// (own budget, the same size as the erasure-guess budget).
    pub joint_work: u64,
    /// Erasure guesses the neighbour steps built (window guesses included).
    pub joint_patterns: usize,
    /// Largest guess cache the neighbour guess or the hunt held, in bytes (fixed cap).
    pub joint_cache_peak: usize,
}

/// Erasure guesses tried per stuck column, at most.
const MAX_PATTERNS: usize = 4096;
/// Candidate fixes kept per column for the CRC step.
const MAX_CRC_CANDIDATES: usize = 256;
/// Most columns the CRC step will search jointly.
const MAX_CRC_COLUMNS: usize = 64;
/// Most combinations enumerated on each side of the CRC step's meet in the middle.
const MAX_CRC_HALF: u64 = 1 << 20;
/// Shards whose CRCs key the meet-in-the-middle table.
const KEY_ROWS: usize = 3;
/// How many more stored CRCs the chosen combination must match than any other.
const CRC_MARGIN: usize = 2;
/// Stuck columns sampled to learn which shards are bad when nothing else says so.
const LEARN_SAMPLE: usize = 64;
/// Fixed share of the erasure-guess budget, plus a part that grows with the file.
const GUESS_BUDGET_BASE: u64 = 1 << 30;
const GUESS_BUDGET_PER_SYMBOL: u64 = 256;

struct Row {
    x: u8,
    hard: bool,
    crc: Option<u32>,
    body: Vec<u8>,
}

/// Repair the shard columns and decode the folded payload. See the module docs.
///
/// Parts with indexes above 254, a body length other than `shard_len`, or a repeated index
/// are ignored. Fails only when fewer than `k` usable shards are present (or on bad
/// geometry); otherwise returns a candidate payload that the caller **must** gate.
/// (`mend` calls [`decode_threads`]; this all-threads form is for tests.)
#[cfg(test)]
pub fn decode(
    parts: &[RatchetPart<'_>],
    k: usize,
    shard_len: usize,
    payload_len: usize,
    systematic: bool,
) -> Result<(Vec<u8>, RatchetReport), Error> {
    decode_threads(
        parts,
        k,
        shard_len,
        payload_len,
        systematic,
        crate::race::MAX_THREADS,
    )
}

/// [`decode`] on at most `threads` CPU threads. The result is identical for every thread
/// count (columns are independent and put back in order); only the time changes.
pub(crate) fn decode_threads(
    parts: &[RatchetPart<'_>],
    k: usize,
    shard_len: usize,
    payload_len: usize,
    systematic: bool,
    threads: usize,
) -> Result<(Vec<u8>, RatchetReport), Error> {
    if k == 0 || shard_len == 0 {
        return Err(Error::Msg("soft repair: empty geometry".into()));
    }
    let mut seen = [false; 255];
    let mut rows: Vec<(usize, Row)> = Vec::new();
    for p in parts {
        if p.index > 254 || p.body.len() != shard_len || seen[p.index] {
            continue;
        }
        seen[p.index] = true;
        rows.push((
            p.index,
            Row {
                x: rs::x_of(p.index),
                hard: p.hard,
                crc: if p.hard { None } else { p.stored_crc },
                body: p.body.to_vec(),
            },
        ));
    }
    rows.sort_by_key(|r| r.0);
    let indexes: Vec<usize> = rows.iter().map(|r| r.0).collect();
    let mut rows: Vec<Row> = rows.into_iter().map(|r| r.1).collect();
    let p = rows.len();
    if p < k {
        return Err(Error::Msg(format!(
            "soft repair needs {k} shards with data, have {p}"
        )));
    }
    let mut rep = RatchetReport {
        columns: shard_len,
        ..RatchetReport::default()
    };
    let mut errs = vec![0u64; p];
    let mut observed = 0u64;

    // 1 + 2: clean columns, then Berlekamp–Welch on the dirty ones. Shards that are wrong
    // in most columns (a wiped or garbage shard) are found first from a sample and treated
    // as missing, so they do not use up the error budget of every column.
    let mut read: Option<joint::ReadCols> = None;
    let stuck = if p > k {
        let dirty = dirty_columns(&rows, k, shard_len)?;
        rep.clean_columns = shard_len - dirty.len();
        if joint_enabled() {
            // As-read bytes of the columns repair may change, so the neighbour steps can
            // see which shards each fix changed.
            read = joint::ReadCols::new(&rows, &dirty);
        }
        let step = dirty.len().div_ceil(LEARN_SAMPLE * 4).max(1);
        let sample: Vec<usize> = dirty.iter().step_by(step).copied().collect();
        let sfix = bw_columns(&rows, &sample, &[], k, threads)?;
        let mut serr = vec![0u64; p];
        let mut sobs = 0u64;
        for (&j, f) in sample.iter().zip(&sfix) {
            if let Some(col) = f {
                sobs += 1;
                for (t, &v) in col.iter().enumerate() {
                    if v != rows[t].body[j] {
                        serr[t] += 1;
                    }
                }
            }
        }
        let soft: Vec<usize> = (0..p).filter(|&t| !rows[t].hard).collect();
        let dead = dead_rows(&soft, &serr, sobs);
        let erase = if p - dead.len() >= k + 2 {
            dead
        } else {
            Vec::new()
        };
        let fixes = bw_columns(&rows, &dirty, &erase, k, threads)?;
        let mut stuck = Vec::new();
        for (&j, fix) in dirty.iter().zip(fixes) {
            match fix {
                Some(fixed) => {
                    write_column(&mut rows, j, &fixed, &mut errs);
                    rep.bw_columns += 1;
                    observed += 1;
                }
                None => stuck.push(j),
            }
        }
        stuck
    } else {
        rep.clean_columns = shard_len;
        Vec::new()
    };

    let mut stuck = stuck;
    let budget = GUESS_BUDGET_BASE
        .saturating_add(GUESS_BUDGET_PER_SYMBOL.saturating_mul((p * shard_len) as u64));
    let mut learned = false;
    // Shared by every guess the neighbour guess and the hunt build (see [`joint`]).
    let mut build_left = joint::BUILD_BUDGET;

    // 3 + 4: erasure guesses, then promote soft shards whose stored CRC now matches to
    // trusted, and go again with fewer unknowns — until nothing more settles.
    loop {
        crate::repair_ctl::check()?;
        if stuck.is_empty() {
            break;
        }
        let soft: Vec<usize> = (0..p).filter(|&t| !rows[t].hard).collect();
        let hard_n = p - soft.len();
        if hard_n >= k {
            // k trusted symbols in every column: interpolate, no guessing.
            let xs: Vec<u8> = rows.iter().map(|r| r.x).collect();
            let q = make_pattern(&xs, &rs::power_matrix(&xs, k), &soft, k, 0.0)?;
            for &j in &stuck {
                let col = q.fill(&rows, j);
                write_column(&mut rows, j, &col, &mut errs);
                rep.erasure_columns += 1;
            }
            stuck.clear();
            break;
        }
        // Shards wrong in most fixed columns (wiped or garbage) are treated as missing:
        // errors-and-erasures Berlekamp–Welch on the rest (2·errors + erasures ≤ n − k).
        let dead = dead_rows(&soft, &errs, observed);
        if !dead.is_empty() && p - dead.len() >= k + 2 {
            let found = bw_columns(&rows, &stuck, &dead, k, threads)?;
            let mut still = Vec::new();
            for (&j, f) in stuck.iter().zip(found) {
                match f {
                    Some(col) => {
                        write_column(&mut rows, j, &col, &mut errs);
                        rep.bw_columns += 1;
                    }
                    None => still.push(j),
                }
            }
            stuck = still;
        }
        if !stuck.is_empty() && p > k + 2 && !soft.is_empty() && rep.guess_work < budget {
            let max_erase = (p - k - 2).min(soft.len());
            if !learned && observed < 16 {
                // Nothing (or little) fixed yet: learn from a sample which shards are bad.
                let step = stuck.len().div_ceil(LEARN_SAMPLE).max(1);
                let sample: Vec<usize> = stuck.iter().step_by(step).copied().collect();
                let pats = patterns(
                    &rows,
                    &soft,
                    &dead,
                    &errs,
                    observed,
                    k,
                    1,
                    max_erase,
                    MAX_PATTERNS,
                    true,
                )?;
                let found = par_map(&sample, threads, |j| settle(&rows, &pats, j, 2))?;
                for (j, (f, w)) in sample.iter().zip(found) {
                    rep.guess_work = rep.guess_work.saturating_add(w);
                    if let [col] = f.as_slice() {
                        for (t, &v) in col.iter().enumerate() {
                            if v != rows[t].body[*j] {
                                errs[t] += 1;
                            }
                        }
                        observed += 1;
                    }
                }
            }
            learned = true;
            let pats = patterns(
                &rows,
                &soft,
                &dead,
                &errs,
                observed,
                k,
                1,
                max_erase,
                MAX_PATTERNS,
                true,
            )?;
            // Cap guesses per column so the step fits the budget (deterministic, whatever
            // the thread count).
            let per_col_cost = pats.iter().map(|q| q.cost).max().unwrap_or(1).max(1);
            let left = budget.saturating_sub(rep.guess_work);
            let cap = (left / (stuck.len() as u64).max(1) / per_col_cost).max(1) as usize;
            let use_n = pats.len().min(cap);
            rep.budget_hit |= use_n < pats.len();
            let found = par_map(&stuck, threads, |j| settle(&rows, &pats[..use_n], j, 2))?;
            let mut still = Vec::new();
            for (&j, (f, work)) in stuck.iter().zip(found) {
                rep.guess_work = rep.guess_work.saturating_add(work);
                match f.as_slice() {
                    [col] => {
                        write_column(&mut rows, j, col, &mut errs);
                        rep.erasure_columns += 1;
                    }
                    _ => still.push(j),
                }
            }
            stuck = still;
        }
        // 3b: neighbouring stuck columns together (see [`joint`]). Up to p − k − 1 bad
        // shards per region, one spare symbol per column, confirmed across the run.
        if let Some(read) = read.as_ref() {
            if !stuck.is_empty() && p > k + 1 && !soft.is_empty() && rep.joint_work < budget {
                crate::repair_ctl::check()?;
                let max_erase = (p - k - 1).min(soft.len());
                // Window guesses are built up front; their cost counts against the budget
                // and caps how many are built.
                let each = joint::build_cost(p, k);
                let afford = (budget.saturating_sub(rep.joint_work) / each) as usize;
                let cap = joint::pattern_cap(p, k).min(afford);
                rep.budget_hit |= cap < joint::pattern_cap(p, k);
                let pats = patterns(
                    &rows,
                    &soft,
                    &[],
                    &errs,
                    observed,
                    k,
                    1,
                    max_erase,
                    cap.max(1),
                    true,
                )?;
                rep.joint_work = rep
                    .joint_work
                    .saturating_add(each.saturating_mul(pats.len() as u64));
                rep.joint_patterns += pats.len();
                let near = joint::neighbour_windows(&rows, read, &stuck, k, &mut build_left)?;
                rep.joint_work = rep.joint_work.saturating_add(near.work);
                rep.budget_hit |= near.budget_hit;
                rep.joint_patterns += near.built;
                rep.joint_cache_peak = rep.joint_cache_peak.max(near.cache_bytes);
                for (j, col) in near.fixed {
                    write_column(&mut rows, j, &col, &mut errs);
                    rep.joint_columns += 1;
                    observed += 1;
                }
                let left = budget.saturating_sub(rep.joint_work);
                let win = joint::joint_windows(&rows, &pats, &near.still, threads, left)?;
                rep.joint_work = rep.joint_work.saturating_add(win.work);
                rep.budget_hit |= win.budget_hit;
                for (j, col) in win.fixed {
                    write_column(&mut rows, j, &col, &mut errs);
                    rep.joint_columns += 1;
                    observed += 1;
                }
                stuck = win.still;
            }
        }
        // Ratchet across shards: a soft shard whose stored CRC-32 now matches is right in
        // every column (including the stuck ones), so it becomes trusted.
        let mut promoted = false;
        for r in rows.iter_mut() {
            if !r.hard && r.crc == Some(crc32fast::hash(&r.body)) {
                r.hard = true;
                promoted = true;
                rep.promoted_shards += 1;
            }
        }
        if !promoted {
            break;
        }
    }

    // 3c: miscorrection hunt (see [`joint`]): a settled column that changed a shard
    // neither neighbour changed is decided again from its neighbours' guess.
    if let Some(read) = read.as_ref() {
        let left = budget.saturating_sub(rep.joint_work);
        let h = joint::hunt(&mut rows, read, &stuck, k, &mut errs, left, &mut build_left)?;
        rep.joint_work = rep.joint_work.saturating_add(h.work);
        rep.joint_patterns += h.built;
        rep.joint_cache_peak = rep.joint_cache_peak.max(h.cache_bytes);
        rep.hunt_columns += h.replaced;
        rep.budget_hit |= h.budget_hit;
    }
    drop(read);

    // 4b + 5: joint CRC match for the few columns still stuck, then best guesses.
    crate::repair_ctl::check()?;
    if !stuck.is_empty() {
        let soft: Vec<usize> = (0..p).filter(|&t| !rows[t].hard).collect();
        let dead = dead_rows(&soft, &errs, observed);
        let dead = if p - dead.len() >= k {
            dead
        } else {
            Vec::new()
        };
        let max_erase = (p - k).min(soft.len());
        let pats = patterns(
            &rows,
            &soft,
            &dead,
            &errs,
            observed,
            k,
            0,
            max_erase,
            MAX_PATTERNS,
            false,
        )?;
        if stuck.len() <= MAX_CRC_COLUMNS {
            let checked_pats = if max_erase >= 2 {
                patterns(
                    &rows,
                    &soft,
                    &dead,
                    &errs,
                    observed,
                    k,
                    1,
                    max_erase - 1,
                    MAX_PATTERNS,
                    true,
                )?
            } else {
                Vec::new()
            };
            if let Some(chosen) =
                crc_search(&rows, &checked_pats, &pats, &stuck, &errs, &dead, &mut rep)
            {
                for (j, col) in chosen {
                    write_column(&mut rows, j, &col, &mut errs);
                    rep.crc_columns += 1;
                }
                stuck.clear();
            }
        }
        // Most reliable k: the best-scoring pattern that erases exactly n−k soft rows.
        let guess = pats
            .iter()
            .find(|q| q.checks.is_empty())
            .or_else(|| pats.first());
        for &j in &stuck {
            if let Some(q) = guess {
                let col = q.fill(&rows, j);
                write_column(&mut rows, j, &col, &mut errs);
            }
            rep.guessed_columns += 1;
        }
    }

    let live: Vec<(usize, Vec<u8>)> = indexes
        .iter()
        .zip(rows)
        .map(|(&i, r)| (i, r.body))
        .collect();
    let payload = rs::decode_indexed(&live, k, payload_len, systematic)?;
    Ok((payload, rep))
}

/// Columns where the present symbols are not one codeword (one SIMD matrix pass).
fn dirty_columns(rows: &[Row], k: usize, shard_len: usize) -> Result<Vec<usize>, Error> {
    let p = rows.len();
    let basis: Vec<u8> = rows[..k].iter().map(|r| r.x).collect();
    let others: Vec<u8> = rows[k..].iter().map(|r| r.x).collect();
    let m = gf::matmul(
        &rs::power_matrix(&others, k),
        &rs::vandermonde_inverse(&basis)?,
        others.len(),
        k,
        k,
    );
    let ins: Vec<&[u8]> = rows[..k].iter().map(|r| r.body.as_slice()).collect();
    let mut pred = vec![vec![0u8; shard_len]; p - k];
    {
        let mut outs: Vec<&mut [u8]> = pred.iter_mut().map(|v| v.as_mut_slice()).collect();
        gf::matrix_apply(&m, &ins, &mut outs);
    }
    Ok((0..shard_len)
        .filter(|&j| (0..p - k).any(|o| pred[o][j] != rows[k + o].body[j]))
        .collect())
}

/// Errors-and-erasures Berlekamp–Welch on each column in `cols`, ignoring rows `erased`:
/// the full codeword when at most `(kept − k) / 2` kept symbols disagree and no trusted
/// (hard) symbol would change, else `None`.
fn bw_columns(
    rows: &[Row],
    cols: &[usize],
    erased: &[usize],
    k: usize,
    threads: usize,
) -> Result<Vec<Option<Vec<u8>>>, Error> {
    let keep: Vec<usize> = (0..rows.len()).filter(|t| !erased.contains(t)).collect();
    if keep.len() < k + 2 {
        return Ok(vec![None; cols.len()]);
    }
    let xs: Vec<u8> = rows.iter().map(|r| r.x).collect();
    let kx: Vec<u8> = keep.iter().map(|&t| xs[t]).collect();
    let e = (keep.len() - k) / 2;
    par_map(cols, threads, |j| {
        let ys: Vec<u8> = keep.iter().map(|&t| rows[t].body[j]).collect();
        let poly = rs::berlekamp_welch(&kx, &ys, k, e)?;
        let mut wrong = 0;
        for (&t, &y) in keep.iter().zip(&ys) {
            if gf::eval_poly(&poly, xs[t]) != y {
                if rows[t].hard {
                    return None;
                }
                wrong += 1;
            }
        }
        (wrong <= e).then(|| xs.iter().map(|&x| gf::eval_poly(&poly, x)).collect())
    })
}

/// Soft rows wrong in most of the (at least 16) fixed columns: wiped or garbage shards.
fn dead_rows(soft: &[usize], errs: &[u64], observed: u64) -> Vec<usize> {
    soft.iter()
        .copied()
        .filter(|&t| observed >= 16 && errs[t] * 2 > observed)
        .collect()
}

fn write_column(rows: &mut [Row], j: usize, col: &[u8], errs: &mut [u64]) {
    for (t, (r, &v)) in rows.iter_mut().zip(col).enumerate() {
        if r.body[j] != v {
            r.body[j] = v;
            errs[t] += 1;
        }
    }
}

/// One erasure guess: erase `erased` (soft rows), rebuild from `basis`, confirm on `checks`.
struct Pattern {
    /// Rows erased by this guess.
    erased: usize,
    basis: Vec<usize>,
    checks: Vec<usize>,
    /// `p × k`: every row's symbol as a combination of the basis symbols.
    gen: Vec<u8>,
    k: usize,
    cost: u64,
}

impl Pattern {
    fn symbol(&self, t: usize, b: &[u8]) -> u8 {
        let row = &self.gen[t * self.k..(t + 1) * self.k];
        row.iter()
            .zip(b)
            .fold(0u8, |acc, (&g, &v)| acc ^ gf::mul(g, v))
    }

    /// `(consistent, work)` for column `j`.
    fn check(&self, rows: &[Row], j: usize, b: &mut Vec<u8>) -> (bool, u64) {
        b.clear();
        b.extend(self.basis.iter().map(|&t| rows[t].body[j]));
        let mut work = 0u64;
        for &t in &self.checks {
            work += self.k as u64;
            if self.symbol(t, b) != rows[t].body[j] {
                return (false, work);
            }
        }
        (true, work)
    }

    /// The full codeword (all present rows) this guess gives for column `j`.
    fn fill(&self, rows: &[Row], j: usize) -> Vec<u8> {
        let b: Vec<u8> = self.basis.iter().map(|&t| rows[t].body[j]).collect();
        (0..rows.len()).map(|t| self.symbol(t, &b)).collect()
    }

    /// [`Pattern::check`] on a stand-alone column (one symbol per row).
    fn check_col(&self, col: &[u8]) -> (bool, u64) {
        let b: Vec<u8> = self.basis.iter().map(|&t| col[t]).collect();
        let mut work = 0u64;
        for &t in &self.checks {
            work += self.k as u64;
            if self.symbol(t, &b) != col[t] {
                return (false, work);
            }
        }
        (true, work)
    }

    /// [`Pattern::fill`] on a stand-alone column (one symbol per row).
    fn fill_col(&self, col: &[u8]) -> Vec<u8> {
        let b: Vec<u8> = self.basis.iter().map(|&t| col[t]).collect();
        (0..col.len()).map(|t| self.symbol(t, &b)).collect()
    }
}

/// Settle column `j` by the fewest erasures that work: patterns are in (size, likelihood)
/// order; the first size at which some guess is confirmed by at least `min_checks` spare
/// symbols is tried in full, and the column locks only if every confirmed guess of that
/// size gives the same codeword. Returns the codeword(s) found at that size (one = locked,
/// several = ambiguous) and the work spent.
fn settle(rows: &[Row], pats: &[Pattern], j: usize, min_checks: usize) -> (Vec<Vec<u8>>, u64) {
    let mut b = Vec::new();
    let mut work = 0u64;
    let mut found: Vec<Vec<u8>> = Vec::new();
    let mut level: Option<usize> = None;
    for q in pats {
        if let Some(l) = level {
            if q.erased != l {
                break;
            }
        }
        if q.checks.len() < min_checks {
            continue;
        }
        let (ok, w) = q.check(rows, j, &mut b);
        work += w;
        if !ok {
            continue;
        }
        level = Some(q.erased);
        let col = q.fill(rows, j);
        if !found.contains(&col) {
            found.push(col);
        }
    }
    (found, work)
}

/// Erasure patterns over soft rows, sizes `min_size..=max_size`, most likely first.
///
/// Each soft row gets a log-odds weight from how often it was wrong in fixed columns;
/// a pattern's score is the sum over the rows it erases. With no data every weight is
/// zero, so smaller patterns come first, then lower shard indexes (the old GMD order).
#[allow(clippy::too_many_arguments)]
fn patterns(
    rows: &[Row],
    soft: &[usize],
    dead: &[usize],
    errs: &[u64],
    observed: u64,
    k: usize,
    min_size: usize,
    max_size: usize,
    cap: usize,
    size_first: bool,
) -> Result<Vec<Pattern>, Error> {
    let p = rows.len();
    let weight = |t: usize| -> f64 {
        let q = (errs[t] as f64 + 0.5) / (observed as f64 + 1.0);
        let q = q.clamp(1e-6, 1.0 - 1e-6);
        (q / (1.0 - q)).ln()
    };
    // Most suspicious first; keep the enumeration small. Dead rows are always erased.
    let mut cand: Vec<usize> = soft.iter().copied().filter(|t| !dead.contains(t)).collect();
    let min_size = min_size.saturating_sub(dead.len());
    let max_size = max_size.saturating_sub(dead.len());
    cand.sort_by(|&a, &b| weight(b).total_cmp(&weight(a)).then(a.cmp(&b)));
    let mut m = cand.len();
    let max_size = max_size.min(m);
    while m > max_size && subsets_upto(m, max_size) > 200_000 {
        m -= 1;
    }
    cand.truncate(m);
    let mut sets: Vec<(f64, Vec<usize>)> = Vec::new();
    let mut cur = Vec::new();
    let min_size = if dead.is_empty() {
        min_size.max(1)
    } else {
        min_size
    };
    enumerate(&cand, 0, min_size, max_size, &mut cur, &mut |s| {
        let score: f64 = s.iter().map(|&t| weight(t)).sum();
        let mut v = s.to_vec();
        v.extend_from_slice(dead);
        v.sort_unstable();
        sets.push((score, v));
    });
    sets.sort_by(|a, b| {
        let by_score = b.0.total_cmp(&a.0);
        let by_size = a.1.len().cmp(&b.1.len());
        if size_first {
            by_size.then(by_score)
        } else {
            by_score.then(by_size)
        }
        .then(a.1.cmp(&b.1))
    });
    sets.truncate(cap);
    let xs: Vec<u8> = rows.iter().map(|r| r.x).collect();
    let all_power = rs::power_matrix(&xs, k);
    let mut out = Vec::with_capacity(sets.len());
    for (score, erased) in sets {
        if p - erased.len() < k {
            continue;
        }
        out.push(make_pattern(&xs, &all_power, &erased, k, score)?);
    }
    Ok(out)
}

/// The guess "erase rows `erased`, rebuild from the first `k` of the rest".
/// Callers keep at least `k` rows.
fn make_pattern(
    xs: &[u8],
    all_power: &[u8],
    erased: &[usize],
    k: usize,
    score: f64,
) -> Result<Pattern, Error> {
    let p = xs.len();
    let keep: Vec<usize> = (0..p).filter(|t| !erased.contains(t)).collect();
    if keep.len() < k {
        return Err(Error::Msg(
            "soft repair: guess keeps fewer than k shards".into(),
        ));
    }
    let basis = keep[..k].to_vec();
    let checks = keep[k..].to_vec();
    let bx: Vec<u8> = basis.iter().map(|&t| xs[t]).collect();
    let gen = gf::matmul(all_power, &rs::vandermonde_inverse(&bx)?, p, k, k);
    let cost = ((checks.len() + 1) * k) as u64;
    let _ = score;
    Ok(Pattern {
        erased: erased.len(),
        basis,
        checks,
        gen,
        k,
        cost,
    })
}

fn subsets_upto(m: usize, s: usize) -> u64 {
    let mut total = 0u64;
    let mut c = 1u64; // C(m, 0)
    for i in 0..s.min(m) {
        c = c.saturating_mul((m - i) as u64) / (i as u64 + 1);
        total = total.saturating_add(c);
    }
    total
}

fn enumerate(
    cand: &[usize],
    start: usize,
    min_size: usize,
    max_size: usize,
    cur: &mut Vec<usize>,
    f: &mut dyn FnMut(&[usize]),
) {
    if cur.len() >= min_size {
        f(cur);
    }
    if cur.len() == max_size {
        return;
    }
    for i in start..cand.len() {
        cur.push(cand[i]);
        enumerate(cand, i + 1, min_size, max_size, cur, f);
        cur.pop();
    }
}

/// Choose one candidate fix per stuck column so that the soft shards' stored CRC-32
/// trailers match. Returns the chosen columns, or `None` when no unique choice exists.
fn crc_search(
    rows: &[Row],
    checked_pats: &[Pattern],
    pats: &[Pattern],
    stuck: &[usize],
    errs: &[u64],
    dead: &[usize],
    rep: &mut RatchetReport,
) -> Option<Vec<(usize, Vec<u8>)>> {
    let checked: Vec<usize> = (0..rows.len()).filter(|&t| rows[t].crc.is_some()).collect();
    if checked.is_empty() {
        return None;
    }
    let residual: Vec<u32> = checked
        .iter()
        .map(|&t| crc32fast::hash(&rows[t].body) ^ rows[t].crc.unwrap_or(0))
        .collect();
    let shard_len = rows[0].body.len();
    let crc = Crc::new();
    // Candidate codewords per column, deduped, most likely first.
    let mut cols: Vec<CrcColumn> = Vec::new();
    let mut b = Vec::new();
    for &j in stuck {
        // Guesses one spare symbol confirms (usually one or two), else unconfirmed ones.
        let (mut cands, w) = settle(rows, checked_pats, j, 1);
        rep.guess_work = rep.guess_work.saturating_add(w);
        let confirmed = !cands.is_empty();
        for q in pats {
            if confirmed {
                break;
            }
            let (ok, w) = q.check(rows, j, &mut b);
            rep.guess_work = rep.guess_work.saturating_add(w);
            if !ok {
                continue;
            }
            let c = q.fill(rows, j);
            if !cands.contains(&c) {
                cands.push(c);
                if cands.len() == MAX_CRC_CANDIDATES {
                    break;
                }
            }
        }
        if cands.is_empty() {
            return None;
        }
        let table = crc.byte_effects(shard_len - 1 - j);
        let effects: Vec<Vec<u32>> = cands
            .iter()
            .map(|c| {
                checked
                    .iter()
                    .map(|&t| table[(c[t] ^ rows[t].body[j]) as usize])
                    .collect()
            })
            .collect();
        cols.push((j, cands, effects));
    }
    // Fewest choices first (the column nearest to settled).
    cols.sort_by_key(|c| c.1.len());
    // Meet in the middle on a few of the most reliable shards' CRCs (an exact 32-bit
    // match each), then score every hit on all shards. Two groups of key shards, in case
    // one key shard's own trailer is rotten.
    // Key on shards a fix can change (not trusted ones) and whose trailer can match (not
    // dead ones); otherwise every combination would be a "hit".
    let mut order: Vec<usize> = (0..checked.len())
        .filter(|&i| !rows[checked[i]].hard && !dead.contains(&checked[i]))
        .collect();
    order.sort_by_key(|&i| (errs[checked[i]], checked[i]));
    let mut hits = 0u64;
    let mut best: Option<(usize, Vec<usize>)> = None;
    let mut second = 0usize;
    let mut seen: std::collections::HashSet<Vec<usize>> = Default::default();
    for key in order.chunks(KEY_ROWS).take(2) {
        mitm(&cols, key, &residual, &mut |pick: Vec<usize>| {
            hits += 1;
            if hits > MAX_CRC_HALF || !seen.insert(pick.clone()) {
                return;
            }
            let mut acc = residual.clone();
            for (c, &i) in cols.iter().zip(&pick) {
                for (a, e) in acc.iter_mut().zip(&c.2[i]) {
                    *a ^= e;
                }
            }
            let score = acc.iter().filter(|&&v| v == 0).count();
            match &best {
                Some((s, _)) if score <= *s => second = second.max(score),
                _ => {
                    if let Some((s, _)) = &best {
                        second = second.max(*s);
                    }
                    best = Some((score, pick));
                }
            }
        })?;
    }
    if hits > MAX_CRC_HALF {
        return None;
    }
    let (score, pick) = best?;
    // Two different fixes of one column differ in at least n−k+1 shards, so the true
    // combination beats any other by several matching CRCs (a rotten or wiped trailer
    // only costs a match on both sides). Demand a clear win, never a near tie.
    // And it must explain (nearly) every shard that has a usable trailer: all checked
    // shards except dead ones (wiped stride, garbage trailer), minus one rotten trailer.
    let live_checked = checked.iter().filter(|&&t| !dead.contains(&t)).count();
    if score == 0 || score < second + CRC_MARGIN || score + 1 < live_checked {
        return None;
    }
    Some(
        cols.iter()
            .zip(pick)
            .map(|((j, cands, _), i)| (*j, cands[i].clone()))
            .collect(),
    )
}

type CrcColumn = (usize, Vec<Vec<u8>>, Vec<Vec<u32>>);

/// Every combination (one candidate per column) whose CRC effects on the `key` shards
/// exactly cancel the residual there; each is passed to `hit`. `None` if the search is
/// too big.
fn mitm(
    cols: &[CrcColumn],
    key: &[usize],
    residual: &[u32],
    hit: &mut dyn FnMut(Vec<usize>),
) -> Option<()> {
    let sizes: Vec<u64> = cols.iter().map(|c| c.1.len() as u64).collect();
    // Split so the two halves are about the same size.
    let total = sizes.iter().try_fold(1u64, |a, &s| a.checked_mul(s))?;
    let mut split = 0;
    let mut left = 1u64;
    while split < cols.len()
        && left
            .saturating_mul(sizes[split])
            .saturating_mul(left.saturating_mul(sizes[split]))
            <= total
    {
        left = left.saturating_mul(sizes[split]);
        split += 1;
    }
    let right = total / left.max(1);
    if left > MAX_CRC_HALF || right > MAX_CRC_HALF {
        return None;
    }
    let keyvec = |cs: &[CrcColumn], pick: &[usize]| -> Vec<u32> {
        key.iter()
            .map(|&r| cs.iter().zip(pick).fold(0u32, |a, (c, &i)| a ^ c.2[i][r]))
            .collect()
    };
    let (a_cols, b_cols) = cols.split_at(split);
    let mut table: std::collections::HashMap<Vec<u32>, Vec<Vec<usize>>> = Default::default();
    for_each_pick(a_cols, &mut |pick| {
        table
            .entry(keyvec(a_cols, pick))
            .or_default()
            .push(pick.to_vec());
    });
    let want: Vec<u32> = key.iter().map(|&r| residual[r]).collect();
    for_each_pick(b_cols, &mut |pick| {
        let need: Vec<u32> = keyvec(b_cols, pick)
            .iter()
            .zip(&want)
            .map(|(a, b)| a ^ b)
            .collect();
        if let Some(lefts) = table.get(&need) {
            for l in lefts {
                let mut full = l.clone();
                full.extend_from_slice(pick);
                hit(full);
            }
        }
    });
    Some(())
}

/// Call `f` with every mixed-radix pick (one candidate index per column).
fn for_each_pick(cols: &[CrcColumn], f: &mut dyn FnMut(&[usize])) {
    let mut pick = vec![0usize; cols.len()];
    loop {
        f(&pick);
        let mut d = 0;
        loop {
            if d == cols.len() {
                return;
            }
            pick[d] += 1;
            if pick[d] < cols[d].1.len() {
                break;
            }
            pick[d] = 0;
            d += 1;
        }
    }
}

/// CRC-32 (IEEE, reflected) as a linear map: how a byte change moves the CRC.
struct Crc {
    table: [u32; 256],
    /// `pow[b]` = the operator for 2^b zero bytes (bit `i`'s image at index `i`).
    pow: Vec<[u32; 32]>,
}

impl Crc {
    fn new() -> Self {
        let mut table = [0u32; 256];
        for (d, slot) in table.iter_mut().enumerate() {
            let mut c = d as u32;
            for _ in 0..8 {
                c = if c & 1 != 0 {
                    0xEDB8_8320 ^ (c >> 1)
                } else {
                    c >> 1
                };
            }
            *slot = c;
        }
        let mut one = [0u32; 32];
        for (i, slot) in one.iter_mut().enumerate() {
            let s = 1u32 << i;
            *slot = table[(s & 0xff) as usize] ^ (s >> 8);
        }
        let mut pow = vec![one];
        for b in 1..64 {
            let prev = pow[b - 1];
            pow.push(compose(&prev, &prev));
        }
        Crc { table, pow }
    }

    /// `out[d]` = change in the CRC of a message when byte `d` is XORed in with `zeros`
    /// bytes after it.
    fn byte_effects(&self, zeros: usize) -> Vec<u32> {
        let mut op: Option<[u32; 32]> = None;
        for (b, p) in self.pow.iter().enumerate() {
            if (zeros >> b) & 1 == 1 {
                op = Some(match op {
                    None => *p,
                    Some(o) => compose(p, &o),
                });
            }
            if zeros >> b == 0 {
                break;
            }
        }
        self.table
            .iter()
            .map(|&v| match &op {
                None => v,
                Some(o) => apply(o, v),
            })
            .collect()
    }
}

fn apply(m: &[u32; 32], v: u32) -> u32 {
    let mut out = 0u32;
    for (i, &col) in m.iter().enumerate() {
        if (v >> i) & 1 == 1 {
            out ^= col;
        }
    }
    out
}

/// `a ∘ b` (apply `b`, then `a`).
fn compose(a: &[u32; 32], b: &[u32; 32]) -> [u32; 32] {
    let mut out = [0u32; 32];
    for (o, &col) in out.iter_mut().zip(b) {
        *o = apply(a, col);
    }
    out
}

fn worker_count(items: usize) -> usize {
    if items < 256 {
        return 1;
    }
    std::thread::available_parallelism()
        .map(|n| n.get())
        .unwrap_or(1)
        .clamp(1, crate::race::MAX_THREADS)
        .min(items / 128)
        .max(1)
}

/// `items.map(f)` on up to `threads` (at most 8) std threads; same output, in order,
/// whatever the thread count. Workers take blocks of columns from a shared counter and all
/// stop at the next column on a stop request (Ctrl-C), which is an error, so a short result
/// is never used as a whole one (see [`crate::race`]).
fn par_map<T: Send, F: Fn(usize) -> T + Sync>(
    items: &[usize],
    threads: usize,
    f: F,
) -> Result<Vec<T>, Error> {
    let threads = worker_count(items.len()).min(threads.max(1));
    crate::race::map_ordered(items.len(), threads, |i| f(items[i]))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn crc_byte_effect_matches_crc32fast() {
        let crc = Crc::new();
        let msg: Vec<u8> = (0..5000u32)
            .map(|i| (i.wrapping_mul(2654435761) >> 7) as u8)
            .collect();
        let base = crc32fast::hash(&msg);
        for &j in &[0usize, 1, 7, 255, 4095, 4999] {
            let table = crc.byte_effects(msg.len() - 1 - j);
            for d in [1u8, 0x80, 0x5a, 0xff] {
                let mut m = msg.clone();
                m[j] ^= d;
                assert_eq!(crc32fast::hash(&m) ^ base, table[d as usize], "j={j} d={d}");
            }
        }
    }

    fn fixture() -> (Vec<u8>, Vec<Vec<u8>>) {
        let mut x = 0x0051_6711_u64;
        let payload: Vec<u8> = (0..12 * 3000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        let shards = rs::encode_shards(&payload, 12, 16).unwrap();
        (payload, shards)
    }

    fn parts<'a>(torn: &'a [Vec<u8>], truth: &[Vec<u8>], hard: &[usize]) -> Vec<RatchetPart<'a>> {
        torn.iter()
            .enumerate()
            .map(|(i, b)| RatchetPart {
                index: i,
                body: b,
                hard: hard.contains(&i),
                stored_crc: Some(crc32fast::hash(&truth[i])),
            })
            .collect()
    }

    #[test]
    fn wiped_shards_are_erasures_and_crc_settles_a_column_beyond_rs() {
        let (payload, shards) = fixture();
        let mut torn = shards.clone();
        // Two wiped shards (all zero, trailer zero) and single flips in a few columns...
        torn[0].fill(0);
        torn[1].fill(0);
        torn[3][200] ^= 0x10;
        torn[7][300] ^= 0x01;
        torn[12][2999] ^= 0x80;
        // ...and one column with two more wrong symbols: 4 errors in 16, past what
        // Reed–Solomon alone can place (2·2 + 2 erasures > n − k).
        torn[5][100] ^= 0x33;
        torn[9][100] ^= 0x05;
        let mut p = parts(&torn, &shards, &[]);
        p[0].stored_crc = Some(0);
        p[1].stored_crc = Some(0);
        let (got, rep) = decode(&p, 12, 3000, payload.len(), true).unwrap();
        assert_eq!(got, payload, "{rep:?}");
        // Every other shard's stored CRC matches once the easy columns are fixed, so 12
        // shards become trusted and column 100 is rebuilt from them.
        assert_eq!(rep.promoted_shards, 12, "{rep:?}");
        assert_eq!(rep.guessed_columns, 0, "{rep:?}");

        // Three such columns on different shard pairs: only 8 shards can be trusted, so
        // the stored CRCs pick the fix for all three at once.
        torn[6][400] ^= 0x44;
        torn[10][400] ^= 0x02;
        torn[8][500] ^= 0x21;
        torn[11][500] ^= 0x90;
        let mut p = parts(&torn, &shards, &[]);
        p[0].stored_crc = Some(0);
        p[1].stored_crc = Some(0);
        let (got, rep) = decode(&p, 12, 3000, payload.len(), true).unwrap();
        assert_eq!(got, payload, "{rep:?}");
        assert_eq!(rep.crc_columns, 3, "{rep:?}");
        assert_eq!(rep.guessed_columns, 0, "{rep:?}");
    }

    #[test]
    fn learned_bad_shards_settle_columns_by_erasure() {
        // Seal-like 8 of 16: six shards trashed everywhere (6 errors per column, past the
        // BW radius of 4). The sample learns which shards are bad; erasing them leaves two
        // spare symbols per column to confirm each fix.
        let mut x = 0xfeedu64;
        let payload: Vec<u8> = (0..8 * 2000)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        let shards = rs::encode_shards(&payload, 8, 16).unwrap();
        let mut torn = shards.clone();
        for (i, row) in torn.iter_mut().enumerate().skip(3).take(6) {
            for (j, b) in row.iter_mut().enumerate() {
                *b ^= (j as u8).wrapping_mul(31).wrapping_add(i as u8) | 1;
            }
        }
        let p = parts(&torn, &shards, &[]);
        let (got, rep) = decode(&p, 8, 2000, payload.len(), true).unwrap();
        assert_eq!(got, payload, "{rep:?}");
        assert_eq!(rep.guessed_columns, 0, "{rep:?}");
    }

    #[test]
    fn hard_shards_are_never_changed_and_short_input_is_refused() {
        let (payload, shards) = fixture();
        let p = parts(&shards[..11], &shards, &[]);
        assert!(decode(&p, 12, 3000, payload.len(), true).is_err());
        // A "hard" shard that is actually wrong is trusted, so the columns it breaks
        // cannot be fixed by changing it; the result is wrong and the caller's gate refuses.
        let mut torn = shards.clone();
        torn[4][10] ^= 1;
        let p = parts(&torn, &shards, &[4]);
        let (got, _) = decode(&p, 12, 3000, payload.len(), true).unwrap();
        let enc = rs::encode_shards(&got, 12, 16).unwrap();
        assert_eq!(enc[4][10], torn[4][10]);
        // Bad geometry is an error, not a panic.
        assert!(decode(&p, 0, 3000, payload.len(), true).is_err());
        assert!(decode(&p, 12, 0, payload.len(), true).is_err());
    }

    /// Bad-sector-like bursts: six regions of 400 columns, each on three shards, so every
    /// shard fails its CRC and each damaged column has one bad shard more than a single
    /// column can settle on Reflection 12/16 (two erasures plus two checks). Joint windows
    /// settle them from one spare symbol per column, confirmed across the window; the
    /// per-column ratchet alone cannot. Same answer on one thread.
    #[test]
    fn joint_window_settles_bursts_beyond_one_column() {
        let (payload, shards) = fixture();
        let mut torn = shards.clone();
        let regions: [(usize, [usize; 3]); 6] = [
            (0, [0, 1, 2]),
            (500, [3, 4, 5]),
            (1000, [6, 7, 8]),
            (1500, [9, 10, 11]),
            (2000, [12, 13, 14]),
            (2500, [15, 0, 1]),
        ];
        for (start, bad) in regions {
            for (n, &row) in bad.iter().enumerate() {
                for (j, b) in torn[row].iter_mut().enumerate().skip(start).take(400) {
                    *b ^= (j as u8).wrapping_mul(29).wrapping_add(n as u8 * 71) | 1;
                }
            }
        }
        let p = parts(&torn, &shards, &[]);
        set_joint_for_tests(false);
        let off = decode(&p, 12, 3000, payload.len(), true);
        set_joint_for_tests(true);
        let (off, off_rep) = off.unwrap();
        assert_ne!(
            off, payload,
            "per-column alone should not settle this: {off_rep:?}"
        );
        assert_eq!(off_rep.joint_columns + off_rep.hunt_columns, 0);
        let (got, rep) = decode(&p, 12, 3000, payload.len(), true).unwrap();
        assert_eq!(got, payload, "{rep:?}");
        assert!(rep.joint_columns > 0, "{rep:?}");
        let one = decode_threads(&p, 12, 3000, payload.len(), true, 1).unwrap();
        assert_eq!(one.0, got);
        assert_eq!(one.1, rep);
    }

    /// A trusted (CRC-good) shard is never changed by the neighbour steps either, even when
    /// it is in fact wrong inside a burst; the result is then wrong and the caller's gate
    /// refuses it.
    #[test]
    fn joint_steps_never_change_a_trusted_shard() {
        let (payload, shards) = fixture();
        let mut torn = shards.clone();
        for row in [2usize, 5, 9] {
            for (j, b) in torn[row].iter_mut().enumerate().skip(700).take(300) {
                *b ^= (j as u8) | 1;
            }
        }
        for (j, b) in torn[4].iter_mut().enumerate().skip(100).take(300) {
            *b ^= (j as u8) | 0x10;
        }
        let p = parts(&torn, &shards, &[5]);
        let (got, _) = decode(&p, 12, 3000, payload.len(), true).unwrap();
        let enc = rs::encode_shards(&got, 12, 16).unwrap();
        assert_eq!(enc[5], torn[5]);
        assert_ne!(got, payload);
    }

    /// More than 32 shards: shard sets are 256-bit, so bursts on shards past index 31
    /// settle as well (k = 30 of n = 36; five bad shards per burst, one more than a single
    /// column can settle; undamaged shards are CRC-good, as in a real file).
    #[test]
    fn joint_window_works_past_32_shards() {
        let mut x = 0x0036_1124_u64;
        let payload: Vec<u8> = (0..30 * 900)
            .map(|_| {
                x ^= x << 13;
                x ^= x >> 7;
                x ^= x << 17;
                x as u8
            })
            .collect();
        let shards = rs::encode_shards(&payload, 30, 36).unwrap();
        let mut torn = shards.clone();
        let regions: [(usize, [usize; 5]); 3] = [
            (0, [31, 32, 33, 34, 35]),
            (300, [0, 1, 2, 33, 34]),
            (600, [0, 1, 31, 32, 35]),
        ];
        for (start, bad) in regions {
            for (n, &row) in bad.iter().enumerate() {
                for (j, b) in torn[row].iter_mut().enumerate().skip(start).take(200) {
                    *b ^= (j as u8)
                        .wrapping_mul(13)
                        .wrapping_add((n as u8).wrapping_mul(37))
                        | 1;
                }
            }
        }
        let soft = [0usize, 1, 2, 31, 32, 33, 34, 35];
        let hard: Vec<usize> = (0..36).filter(|t| !soft.contains(t)).collect();
        let p = parts(&torn, &shards, &hard);
        set_joint_for_tests(false);
        let off = decode(&p, 30, 900, payload.len(), true);
        set_joint_for_tests(true);
        let (off, off_rep) = off.unwrap();
        assert_ne!(
            off, payload,
            "per-column alone should not settle this: {off_rep:?}"
        );
        let (got, rep) = decode(&p, 30, 900, payload.len(), true).unwrap();
        assert_eq!(got, payload, "{rep:?}");
        assert!(rep.joint_columns > 0, "{rep:?}");
    }

    /// Scattered symbol errors on a wide geometry: Berlekamp–Welch settles every column,
    /// each with different wrong rows, so neighbour sets almost never repeat. Returns the
    /// decode result with the (g) steps on or off, and the time taken.
    #[allow(clippy::needless_range_loop)] // rows vary per error; columns index them
    fn wide_scattered(
        n: usize,
        k: usize,
        sl: usize,
        errs: usize,
        joint: bool,
    ) -> (bool, RatchetReport, std::time::Duration) {
        let mut x = 0x5eed_u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let payload: Vec<u8> = (0..k * sl).map(|_| next() as u8).collect();
        let shards = rs::encode_shards(&payload, k, n).unwrap();
        let mut torn = shards.clone();
        for j in 0..sl {
            for _ in 0..errs {
                let t = (next() % n as u64) as usize;
                torn[t][j] ^= (next() as u8) | 1;
            }
        }
        let p = parts(&torn, &shards, &[]);
        set_joint_for_tests(joint);
        let t0 = std::time::Instant::now();
        let r = decode_threads(&p, k, sl, payload.len(), true, 8);
        let dt = t0.elapsed();
        set_joint_for_tests(true);
        let (got, rep) = r.unwrap();
        (got == payload, rep, dt)
    }

    /// Cost harness (not run by default): `cargo test --release -p sigil --lib
    /// wide_scattered_cost -- --ignored --nocapture`; geometry via `SIGIL_WIDE`
    /// (`n,k,columns,errors-per-column[,0|1]`, default `254,190,4000,2`).
    #[test]
    #[ignore]
    fn wide_scattered_cost() {
        let v: Vec<usize> = std::env::var("SIGIL_WIDE")
            .unwrap_or_else(|_| "254,190,4000,2".into())
            .split(',')
            .filter_map(|s| s.trim().parse().ok())
            .collect();
        let (n, k, sl, e) = (v[0], v[1], v[2], v[3]);
        // Optional fifth field: 0 = (g) off only, 1 = (g) on only.
        let modes: Vec<bool> = match v.get(4) {
            Some(&m) => vec![m == 1],
            None => vec![false, true],
        };
        for joint in modes {
            let (ok, rep, dt) = wide_scattered(n, k, sl, e, joint);
            eprintln!(
                "WIDE n={n} k={k} cols={sl} errs={e} joint={joint}: {dt:?} right={ok} {rep:?}"
            );
        }
    }

    /// Scattered damage on 254 and 64 shards: the neighbour steps stop after a fixed build
    /// spend with nothing to show, hold a fixed-size cache, return the same bytes as the
    /// per-column ratchet alone, and give the same report on 1 and 8 threads (deterministic
    /// measures; the timed check is `wide_scattered_time_ratio`).
    #[test]
    #[allow(clippy::needless_range_loop)] // rows vary per error; columns index them
    fn joint_steps_bounded_on_wide_scattered_damage() {
        for (n, k, sl, e) in [(254usize, 190usize, 400usize, 2usize), (64, 48, 3000, 4)] {
            let (off_ok, off, _) = wide_scattered(n, k, sl, e, false);
            let (on_ok, on, _) = wide_scattered(n, k, sl, e, true);
            assert!(off_ok && on_ok, "n={n}: {off:?} {on:?}");
            let each = joint::build_cost(n, k);
            // At most one guess past the dry-run spend.
            let most = (joint::DRY_BUILD_WORK / each) as usize + 1;
            assert!(
                on.joint_patterns <= most,
                "n={n}: {} > {most} {on:?}",
                on.joint_patterns
            );
            assert!(on.joint_cache_peak <= joint::CACHE_BYTES, "{on:?}");
            assert!(
                on.joint_work <= joint::DRY_BUILD_WORK + each + (n * sl) as u64 * 8,
                "{on:?}"
            );
            assert_eq!(on.hunt_columns, 0, "{on:?}");
        }
        // Same report on any thread count.
        let mut x = 0x5eed_u64;
        let mut next = || {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            x
        };
        let (n, k, sl) = (64usize, 48usize, 2000usize);
        let payload: Vec<u8> = (0..k * sl).map(|_| next() as u8).collect();
        let shards = rs::encode_shards(&payload, k, n).unwrap();
        let mut torn = shards.clone();
        for j in 0..sl {
            for _ in 0..4 {
                let t = (next() % n as u64) as usize;
                torn[t][j] ^= (next() as u8) | 1;
            }
        }
        let p = parts(&torn, &shards, &[]);
        let one = decode_threads(&p, k, sl, payload.len(), true, 1).unwrap();
        let eight = decode_threads(&p, k, sl, payload.len(), true, 8).unwrap();
        assert_eq!(one, eight);
    }

    /// Timed check (not run by default; release build): `cargo test --release -p sigil
    /// --lib wide_scattered_time_ratio -- --ignored --nocapture`. Scattered damage on 254
    /// and 64 shards takes at most 1.2× the time of the per-column ratchet alone (best of
    /// three runs each).
    #[test]
    #[ignore]
    fn wide_scattered_time_ratio() {
        for (n, k, sl, e) in [(254usize, 190usize, 4000usize, 2usize), (64, 48, 80_000, 4)] {
            let best = |joint: bool| {
                (0..3)
                    .map(|_| wide_scattered(n, k, sl, e, joint).2)
                    .min()
                    .unwrap()
            };
            let off = best(false);
            let on = best(true);
            let ratio = on.as_secs_f64() / off.as_secs_f64();
            eprintln!("TIME n={n} k={k} cols={sl}: off {off:?} on {on:?} ratio {ratio:.3}");
            assert!(ratio <= 1.2, "n={n}: {ratio:.3}");
        }
    }

    #[test]
    fn subsets_upto_counts() {
        assert_eq!(subsets_upto(16, 2), 16 + 120);
        assert_eq!(subsets_upto(4, 9), 15);
    }
}
