//! Decoders under test. All of them only *propose* bytes; the harness gate
//! (Merkle of re-encoded shards + SHA-256 true name) decides acceptance.

use crate::rs::{column_repair, Code, N};
use crate::sidecar::{self, Check, Mode, Sidecar};
use std::collections::HashMap;
use std::ops::Range;

pub struct Input<'a> {
    pub code: &'a Code,
    pub rx: &'a [Option<Vec<u8>>],
    /// Whole-shard CRC32 (the one in today's format) passes.
    pub crc_ok: &'a [bool],
    pub shard_len: usize,
    /// Original shards. STATISTICS ONLY (false-lock counting); never read for decisions.
    pub oracle: &'a [Vec<u8>],
}

#[derive(Default, Clone)]
pub struct Out {
    pub data: Option<Vec<Vec<u8>>>,
    pub budget_hit: bool,
    pub locks: u64,
    pub false_locks: u64,
    pub bit_locks: u64,
    pub ambiguous: u64,
}

/// Rough operation budget per decoder call (GF multiplies + hashed bytes).
pub const WORK_CAP: u64 = 1_500_000_000;

/// Largest per-column subset enumeration in the ratchet search.
pub const ENUM_CAP: usize = 1000;

fn n_choose(n: usize, r: usize) -> usize {
    if r > n {
        return 0;
    }
    let mut c: usize = 1;
    for t in 0..r {
        c = c.saturating_mul(n - t) / (t + 1);
    }
    c
}

fn present(inp: &Input) -> Vec<usize> {
    (0..N).filter(|&i| inp.rx[i].is_some()).collect()
}

/// Today's hard path: at least kk shards pass their whole-shard CRC.
fn hard_path(inp: &Input) -> Option<Vec<Vec<u8>>> {
    let kk = inp.code.k;
    let good: Vec<usize> = (0..N)
        .filter(|&i| inp.crc_ok[i] && inp.rx[i].is_some())
        .collect();
    if good.len() < kk {
        return None;
    }
    let rows: Vec<usize> = (0..kk).collect();
    inp.code
        .predict_rows(inp.rx, &good[..kk], &rows, 0..inp.shard_len)
}

/// (a) current `mend --soft` v1: hard path, else byte-column Berlekamp–Welch.
pub fn current(inp: &Input) -> Out {
    let kk = inp.code.k;
    if let Some(d) = hard_path(inp) {
        return Out {
            data: Some(d),
            ..Out::default()
        };
    }
    let live = present(inp);
    let data =
        column_repair(inp.code, inp.rx, &live, 0..inp.shard_len).and_then(|(full, failed)| {
            if failed.is_empty() {
                Some(full.into_iter().take(kk).collect())
            } else {
                None
            }
        });
    Out {
        data,
        ..Out::default()
    }
}

/// Independent-check verdict for cell (i, j): Some(true/false), None if no entry.
fn indep_ok(sc: &Sidecar, i: usize, j: usize, cell: &[u8]) -> Option<bool> {
    let e = sc.entry(i, j)?;
    let p = sidecar::prefix(&sc.spec, i, j as u32, None);
    Some(sidecar::hash(sc.spec.check, &p, cell) == e)
}

/// (b) hard marks: cells whose check fails are erased; BW on the rest.
/// (c) hints (`hint = true`): plain BW first per column, marks only for columns it can't fix.
pub fn marks(inp: &Input, sc: Option<&Sidecar>, hint: bool) -> Out {
    let kk = inp.code.k;
    let Some(sc) = sc else {
        return current(inp);
    };
    if let Some(d) = hard_path(inp) {
        return Out {
            data: Some(d),
            ..Out::default()
        };
    }
    let s = sc.spec.cell;
    let live_all = present(inp);
    let mut data = vec![vec![0u8; inp.shard_len]; kk];
    for j in 0..sc.blocks {
        let range = j * s..((j + 1) * s).min(inp.shard_len);
        let unmarked: Vec<usize> = live_all
            .iter()
            .copied()
            .filter(|&i| {
                inp.crc_ok[i]
                    || inp.rx[i]
                        .as_ref()
                        .and_then(|b| indep_ok(sc, i, j, &b[range.clone()]))
                        != Some(false)
            })
            .collect();
        let full = if hint {
            let Some((mut full, failed)) =
                column_repair(inp.code, inp.rx, &live_all, range.clone())
            else {
                return Out::default();
            };
            for abs in failed {
                let ys: Vec<u8> = unmarked
                    .iter()
                    .map(|&i| inp.rx[i].as_ref().map_or(0, |b| b[abs]))
                    .collect();
                let Some(cw) = crate::rs::bw_column(inp.code.k, &unmarked, &ys) else {
                    return Out::default();
                };
                for (r, row) in full.iter_mut().enumerate() {
                    row[abs - range.start] = cw[r];
                }
            }
            full
        } else {
            let Some((full, failed)) = column_repair(inp.code, inp.rx, &unmarked, range.clone())
            else {
                return Out::default();
            };
            if !failed.is_empty() {
                return Out::default();
            }
            full
        };
        for (r, row) in data.iter_mut().enumerate() {
            row[range.clone()].copy_from_slice(&full[r]);
        }
    }
    Out {
        data: Some(data),
        ..Out::default()
    }
}

#[derive(Clone, Copy, Debug)]
pub struct RatchetOpts {
    /// Repeat lock-in passes until nothing changes.
    pub iterate: bool,
    /// 0 = no bit guessing, 1 = single-bit flips, 2 = single + double flips.
    pub bits: u8,
    /// Chained sidecar: refuse stored predecessors (pure chain) if true.
    pub chain_pure: bool,
}

/// Bit-flip CRC deltas and their reverse index (delta -> bit positions).
type DeltaEntry = (Vec<u32>, HashMap<u32, Vec<u32>>);

#[derive(Default)]
pub struct DeltaCache {
    map: HashMap<(usize, usize), DeltaEntry>,
}

impl DeltaCache {
    fn get(&mut self, plen: usize, cell: usize) -> &DeltaEntry {
        self.map.entry((plen, cell)).or_insert_with(|| {
            let d = sidecar::crc_deltas(plen, cell);
            let mut m: HashMap<u32, Vec<u32>> = HashMap::with_capacity(d.len());
            for (p, &v) in d.iter().enumerate() {
                m.entry(v).or_default().push(p as u32);
            }
            (d, m)
        })
    }
}

enum Guess {
    None,
    Unique(Vec<u8>),
    Ambiguous,
}

fn flip(cell: &mut [u8], p: usize) {
    cell[p / 8] ^= 1 << (p % 8);
}

/// Ashlynn's "try 00/01/10/11": search bit flips of `cell` whose check matches `target`.
fn bit_guess(
    check: Check,
    prefix: &[u8],
    cell: &[u8],
    target: u64,
    bits: u8,
    dc: &mut DeltaCache,
    work: &mut u64,
) -> Guess {
    let m = cell.len() * 8;
    let mut found: Vec<(usize, Option<usize>)> = Vec::new();
    match check {
        Check::Crc32 => {
            let cur = sidecar::hash(check, prefix, cell) as u32;
            let need = cur ^ (target as u32);
            let (d, map) = dc.get(prefix.len(), cell.len());
            *work += (cell.len() + m) as u64;
            if let Some(ps) = map.get(&need) {
                for &p in ps {
                    found.push((p as usize, None));
                }
            }
            if bits >= 2 {
                for (p, &dp) in d.iter().enumerate() {
                    if let Some(qs) = map.get(&(need ^ dp)) {
                        for &q in qs {
                            if (q as usize) > p {
                                found.push((p, Some(q as usize)));
                            }
                        }
                    }
                    if found.len() > 1 {
                        break;
                    }
                }
            }
        }
        Check::Sha64 => {
            let mut c = cell.to_vec();
            for p in 0..m {
                flip(&mut c, p);
                if sidecar::hash(check, prefix, &c) == target {
                    found.push((p, None));
                }
                flip(&mut c, p);
            }
            *work += (m * cell.len()) as u64;
            if bits >= 2 && m <= 512 {
                'outer: for p in 0..m {
                    flip(&mut c, p);
                    for q in p + 1..m {
                        flip(&mut c, q);
                        if sidecar::hash(check, prefix, &c) == target {
                            found.push((p, Some(q)));
                        }
                        flip(&mut c, q);
                        if found.len() > 1 {
                            flip(&mut c, p);
                            break 'outer;
                        }
                    }
                    flip(&mut c, p);
                }
                *work += (m * m / 2 * cell.len()) as u64;
            }
        }
    }
    match found.len() {
        0 => Guess::None,
        1 => {
            let mut c = cell.to_vec();
            let (p, q) = found[0];
            flip(&mut c, p);
            if let Some(q) = q {
                flip(&mut c, q);
            }
            Guess::Unique(c)
        }
        _ => Guess::Ambiguous,
    }
}

fn combos(items: &[usize], r: usize) -> Vec<Vec<usize>> {
    let mut out = Vec::new();
    let mut cur = Vec::with_capacity(r);
    fn rec(
        items: &[usize],
        r: usize,
        start: usize,
        cur: &mut Vec<usize>,
        out: &mut Vec<Vec<usize>>,
    ) {
        if cur.len() == r {
            out.push(cur.clone());
            return;
        }
        for t in start..items.len() {
            if items.len() - t < r - cur.len() {
                break;
            }
            cur.push(items[t]);
            rec(items, r, t + 1, cur, out);
            cur.pop();
        }
    }
    rec(items, r, 0, &mut cur, &mut out);
    out
}

/// Per column: best codeword consistent with all `trusted` symbols, chosen by
/// agreement with `sus`. Returns per-sus candidate cells and ambiguous columns
/// (column, distinct alternatives as per-sus symbol vectors).
#[allow(clippy::type_complexity)]
fn trust_search(
    code: &Code,
    cells: &[Option<Vec<u8>>],
    trusted: &[usize],
    sus: &[usize],
    s: usize,
    work: &mut u64,
) -> Option<(Vec<Vec<u8>>, Vec<(usize, Vec<Vec<u8>>)>)> {
    let kk = code.k;
    let r = kk.checked_sub(trusted.len())?;
    let mut subsets = if n_choose(sus.len(), r) <= ENUM_CAP {
        combos(sus, r)
    } else {
        Vec::new()
    };
    let enumerate = !subsets.is_empty();
    if subsets.is_empty() {
        subsets.push(sus[..r].to_vec());
    }
    let mut pos: Vec<usize> = trusted.iter().chain(sus.iter()).copied().collect();
    pos.sort_unstable();
    let mut ys = vec![0u8; pos.len()];
    // (P, sorted base) per subset
    let mut mats: Vec<(&[u8], Vec<usize>)> = Vec::with_capacity(subsets.len());
    for sub in &subsets {
        let mut base: Vec<usize> = trusted.iter().chain(sub.iter()).copied().collect();
        base.sort_unstable();
        let mask = base.iter().fold(0u16, |m, &i| m | (1 << i));
        mats.push((code.pmat(mask)?, base));
    }
    let u = sus.len();
    let mut cand = vec![vec![0u8; s]; u];
    let mut amb = Vec::new();
    let mut v = vec![0u8; u];
    let mut best = vec![0u8; u];
    for x in 0..s {
        let mut best_agree = usize::MAX;
        let mut alts: Vec<Vec<u8>> = Vec::new();
        let mut bw_done = false;
        for (t, (p, base)) in mats.iter().enumerate() {
            if t == 1 && !bw_done {
                // Before enumerating: unique (Berlekamp–Welch) decode over all present
                // symbols; keep it if it agrees with every anchor.
                bw_done = true;
                for (q, &i) in pos.iter().enumerate() {
                    ys[q] = cells[i].as_ref().map_or(0, |cb| cb[x]);
                }
                *work += (pos.len() * pos.len() * kk) as u64;
                if let Some(cw) = crate::rs::bw_column(code.k, &pos, &ys) {
                    if trusted
                        .iter()
                        .all(|&i| cells[i].as_ref().map_or(0, |cb| cb[x]) == cw[i])
                    {
                        for (a, &i) in sus.iter().enumerate() {
                            best[a] = cw[i];
                        }
                        alts.clear();
                        break;
                    }
                }
                if !enumerate {
                    break;
                }
            }
            for (a, &pos) in sus.iter().enumerate() {
                let mut acc = 0u8;
                for (c, &b) in base.iter().enumerate() {
                    let y = cells[b].as_ref().map_or(0, |cb| cb[x]);
                    acc ^= crate::gf::mul(p[pos * kk + c], y);
                }
                v[a] = acc;
            }
            *work += (u * kk) as u64;
            let agree = sus
                .iter()
                .enumerate()
                .filter(|(a, &pos)| cells[pos].as_ref().map_or(0, |cb| cb[x]) == v[*a])
                .count();
            if t == 0 && agree == u {
                best.copy_from_slice(&v);
                alts.clear();
                break;
            }
            if best_agree == usize::MAX || agree > best_agree {
                best_agree = agree;
                best.copy_from_slice(&v);
                alts.clear();
                alts.push(v.clone());
            } else if agree == best_agree && !alts.iter().any(|w| w == &v) && alts.len() < 4 {
                alts.push(v.clone());
            }
        }
        if mats.len() == 1 && !bw_done && best_agree != usize::MAX && best_agree < u {
            for (q, &i) in pos.iter().enumerate() {
                ys[q] = cells[i].as_ref().map_or(0, |cb| cb[x]);
            }
            *work += (pos.len() * pos.len() * kk) as u64;
            if let Some(cw) = crate::rs::bw_column(code.k, &pos, &ys) {
                if trusted
                    .iter()
                    .all(|&i| cells[i].as_ref().map_or(0, |cb| cb[x]) == cw[i])
                {
                    for (a, &i) in sus.iter().enumerate() {
                        best[a] = cw[i];
                    }
                    alts.clear();
                }
            }
        }
        for a in 0..u {
            cand[a][x] = best[a];
        }
        if alts.len() > 1 {
            amb.push((x, alts));
        }
        if *work > WORK_CAP {
            return None;
        }
    }
    Some((cand, amb))
}

/// (d) Ratchet: per-cell checks; verified cells are anchors; search candidates
/// consistent with anchors, lock any cell whose check then matches, repeat;
/// bit-flip guessing on cells that RS alone cannot settle. Works block by block
/// (block j = byte range [j·cell, (j+1)·cell) of every shard; columns in a block
/// share one trust pattern). Chained sidecars are walked in block order.
pub fn ratchet(inp: &Input, sc: Option<&Sidecar>, o: RatchetOpts, dc: &mut DeltaCache) -> Out {
    let kk = inp.code.k;
    let Some(sc) = sc else {
        return current(inp);
    };
    let mut out = Out::default();
    if let Some(d) = hard_path(inp) {
        out.data = Some(d);
        return out;
    }
    let spec = sc.spec;
    let s = spec.cell;
    let chained = spec.mode == Mode::Chained;
    let mut chain_prev: Vec<Option<u64>> = (0..N)
        .map(|i| Some(sidecar::chain_init(&spec, i, &sc.root)))
        .collect();
    let mut data = vec![vec![0u8; inp.shard_len]; kk];
    let mut work = 0u64;
    let all: Vec<usize> = (0..N).collect();
    for j in 0..sc.blocks {
        let range: Range<usize> = j * s..((j + 1) * s).min(inp.shard_len);
        let s = range.len();
        let mut cells: Vec<Option<Vec<u8>>> = inp
            .rx
            .iter()
            .map(|b| b.as_ref().map(|b| b[range.clone()].to_vec()))
            .collect();
        // predecessor used to verify cell (i, j)
        let prev: Vec<Option<u64>> = (0..N)
            .map(|i| {
                if !chained {
                    return None;
                }
                if chain_prev[i].is_some() || o.chain_pure {
                    return chain_prev[i];
                }
                if j == 0 {
                    Some(sidecar::chain_init(&spec, i, &sc.root))
                } else {
                    sc.entry(i, j - 1)
                }
            })
            .collect();
        let pfx = |i: usize| -> Option<Vec<u8>> {
            if chained {
                prev[i].map(|p| sidecar::prefix(&spec, i, j as u32, Some(p)))
            } else {
                Some(sidecar::prefix(&spec, i, j as u32, None))
            }
        };
        // 0 missing, 1 trusted, 2 suspect lockable, 3 suspect not lockable
        let mut st = [0u8; N];
        for i in 0..N {
            let Some(c) = cells[i].as_ref() else { continue };
            if inp.crc_ok[i] {
                st[i] = 1;
                continue;
            }
            match (pfx(i), sc.entry(i, j)) {
                (Some(p), Some(e)) => {
                    work += c.len() as u64;
                    st[i] = if sidecar::hash(spec.check, &p, c) == e {
                        1
                    } else {
                        2
                    };
                }
                _ => st[i] = 3,
            }
        }
        let mut solved: Option<Vec<Vec<u8>>> = None;
        loop {
            let trusted: Vec<usize> = (0..N).filter(|&i| st[i] == 1).collect();
            if trusted.len() >= kk {
                solved = inp.code.predict_rows(&cells, &trusted[..kk], &all, 0..s);
                break;
            }
            let sus: Vec<usize> = (0..N).filter(|&i| st[i] >= 2).collect();
            let mut progress = false;
            let lock = |i: usize,
                        c: Vec<u8>,
                        st: &mut [u8; N],
                        cells: &mut Vec<Option<Vec<u8>>>,
                        out: &mut Out| {
                if inp.oracle[i][range.clone()] != c[..] {
                    out.false_locks += 1;
                }
                out.locks += 1;
                st[i] = 1;
                cells[i] = Some(c);
            };
            if trusted.len() + sus.len() > kk {
                let Some((cand, amb)) =
                    trust_search(inp.code, &cells, &trusted, &sus, s, &mut work)
                else {
                    out.budget_hit = true;
                    return out;
                };
                out.ambiguous += amb.len() as u64;
                for (a, &i) in sus.iter().enumerate() {
                    if st[i] != 2 {
                        continue;
                    }
                    let (Some(p), Some(e)) = (pfx(i), sc.entry(i, j)) else {
                        continue;
                    };
                    work += s as u64;
                    if sidecar::hash(spec.check, &p, &cand[a]) == e {
                        lock(i, cand[a].clone(), &mut st, &mut cells, &mut out);
                        progress = true;
                        continue;
                    }
                    // Chase-style: try tied alternatives on ambiguous columns.
                    if !amb.is_empty() && amb.len() <= 6 {
                        let mut tuples: Vec<Vec<u8>> = vec![Vec::new()];
                        for (_, alts) in &amb {
                            let mut nt = Vec::new();
                            for tpl in &tuples {
                                for alt in alts {
                                    let mut t2 = tpl.clone();
                                    t2.push(alt[a]);
                                    if !nt.contains(&t2) {
                                        nt.push(t2);
                                    }
                                }
                            }
                            tuples = nt;
                        }
                        let mut hit: Option<Vec<u8>> = None;
                        let mut hits = 0;
                        for tpl in &tuples {
                            let mut c = cand[a].clone();
                            for ((x, _), &val) in amb.iter().zip(tpl) {
                                c[*x] = val;
                            }
                            work += s as u64;
                            if sidecar::hash(spec.check, &p, &c) == e {
                                hits += 1;
                                hit = Some(c);
                            }
                        }
                        if hits == 1 {
                            if let Some(c) = hit {
                                lock(i, c, &mut st, &mut cells, &mut out);
                                progress = true;
                            }
                        }
                    }
                }
            }
            if !progress && o.bits > 0 {
                for &i in &sus {
                    if st[i] != 2 {
                        continue;
                    }
                    let (Some(p), Some(e), Some(c)) = (pfx(i), sc.entry(i, j), cells[i].as_ref())
                    else {
                        continue;
                    };
                    match bit_guess(spec.check, &p, c, e, o.bits, dc, &mut work) {
                        Guess::Unique(nc) => {
                            out.bit_locks += 1;
                            lock(i, nc, &mut st, &mut cells, &mut out);
                            progress = true;
                        }
                        Guess::Ambiguous => out.ambiguous += 1,
                        Guess::None => {}
                    }
                    if work > WORK_CAP {
                        out.budget_hit = true;
                        return out;
                    }
                }
            }
            if !progress || !o.iterate {
                if !o.iterate {
                    // single pass: one final solve attempt after the pass
                    let t2: Vec<usize> = (0..N).filter(|&i| st[i] == 1).collect();
                    if t2.len() >= kk {
                        solved = inp.code.predict_rows(&cells, &t2[..kk], &all, 0..s);
                    }
                }
                break;
            }
            if work > WORK_CAP {
                out.budget_hit = true;
                return out;
            }
        }
        let was_solved = solved.is_some();
        let full = match solved {
            Some(f) => f,
            None => {
                // Not settled: best effort (column BW over what we have); the gate decides.
                let live: Vec<usize> = (0..N).filter(|&i| cells[i].is_some()).collect();
                match column_repair(inp.code, &cells, &live, 0..s) {
                    Some((f, _)) => f,
                    None => return out,
                }
            }
        };
        if chained {
            // Advance each shard's chain from the decoded cell, but only when that
            // cell is known exact: block solved from >= kk anchors, or cell verified.
            for i in 0..N {
                let known = was_solved || st[i] == 1;
                chain_prev[i] = match prev[i] {
                    Some(p) if known => {
                        let pf = sidecar::prefix(&spec, i, j as u32, Some(p));
                        Some(sidecar::hash(spec.check, &pf, &full[i]))
                    }
                    _ => None,
                };
            }
        }
        for (r, row) in data.iter_mut().enumerate() {
            row[range.clone()].copy_from_slice(&full[r]);
        }
    }
    out.data = Some(data);
    out
}

/// (e) No sidecar: unique BW, then exhaustive list decoding of failed columns
/// (all kk-subsets of present shards = the complete list at any radius, a superset
/// of what Guruswami–Sudan returns), accept the unique nearest codeword if it is
/// within `radius` errors. Bounded at `max_cols` list-decoded columns.
pub fn list_decode(inp: &Input, radius: usize, max_cols: usize) -> Out {
    let kk = inp.code.k;
    if let Some(d) = hard_path(inp) {
        return Out {
            data: Some(d),
            ..Out::default()
        };
    }
    let live = present(inp);
    let Some((mut full, failed)) = column_repair(inp.code, inp.rx, &live, 0..inp.shard_len) else {
        return Out::default();
    };
    let mut out = Out::default();
    if failed.len() > max_cols {
        out.budget_hit = true;
        return out;
    }
    let subsets = combos(&live, kk);
    let mut mats = Vec::with_capacity(subsets.len());
    for sub in &subsets {
        let mask = sub.iter().fold(0u16, |m, &i| m | (1 << i));
        let Some(p) = inp.code.pmat(mask) else {
            return out;
        };
        mats.push((p, sub.clone()));
    }
    let p_len = live.len();
    for &x in &failed {
        let y: Vec<u8> = (0..N)
            .map(|i| inp.rx[i].as_ref().map_or(0, |b| b[x]))
            .collect();
        let mut best: Option<[u8; N]> = None;
        let mut best_agree = 0usize;
        let mut tie = false;
        for (p, base) in &mats {
            let mut cw = [0u8; N];
            for &pos in &live {
                let mut acc = 0u8;
                for (c, &b) in base.iter().enumerate() {
                    acc ^= crate::gf::mul(p[pos * kk + c], y[b]);
                }
                cw[pos] = acc;
            }
            let agree = live.iter().filter(|&&i| cw[i] == y[i]).count();
            match best {
                Some(b) if agree == best_agree && live.iter().any(|&i| b[i] != cw[i]) => tie = true,
                Some(_) if agree <= best_agree => {}
                _ => {
                    best_agree = agree;
                    best = Some(cw);
                    tie = false;
                }
            }
        }
        let Some(b) = best else { return out };
        if tie || best_agree + radius < p_len {
            if tie {
                out.ambiguous += 1;
            }
            return out;
        }
        // fill all rows: re-predict from kk agreeing positions
        let agree_pos: Vec<usize> = live
            .iter()
            .copied()
            .filter(|&i| b[i] == y[i])
            .take(kk)
            .collect();
        let mask = agree_pos.iter().fold(0u16, |m, &i| m | (1 << i));
        let Some(p) = inp.code.pmat(mask) else {
            return out;
        };
        for (r, row) in full.iter_mut().enumerate() {
            let mut acc = 0u8;
            for (c, &bpos) in agree_pos.iter().enumerate() {
                acc ^= crate::gf::mul(p[r * kk + c], y[bpos]);
            }
            row[x] = acc;
        }
    }
    out.data = Some(full.into_iter().take(kk).collect());
    out
}
