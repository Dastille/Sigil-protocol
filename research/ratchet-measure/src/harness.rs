//! Trial driver: damage models, sidecar file round trip, gate, aggregation.

use crate::decoders::{self, DeltaCache, Input, Out, RatchetOpts};
use crate::rs::{Code, K, N};
use crate::sidecar::{Check, Mode, Sidecar, Spec};
use sha2::{Digest, Sha256};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

pub const SHARD_LEN: usize = 131_072; // 1 MiB payload, Seal 8-of-16 => 2 MiB body
pub const GATE_STRIPE: usize = 4096;

/// xoshiro256** (simulation randomness only).
pub struct Rng([u64; 4]);
impl Rng {
    pub fn new(seed: u64) -> Self {
        let mut z = seed;
        let mut s = [0u64; 4];
        for v in s.iter_mut() {
            z = z.wrapping_add(0x9E37_79B9_7F4A_7C15);
            let mut x = z;
            x = (x ^ (x >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
            x = (x ^ (x >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
            *v = x ^ (x >> 31);
        }
        Rng(s)
    }
    pub fn next_u64(&mut self) -> u64 {
        let r = self.0[1].wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.0[1] << 17;
        self.0[2] ^= self.0[0];
        self.0[3] ^= self.0[1];
        self.0[1] ^= self.0[2];
        self.0[0] ^= self.0[3];
        self.0[2] ^= t;
        self.0[3] = self.0[3].rotate_left(45);
        r
    }
    pub fn below(&mut self, n: usize) -> usize {
        ((self.next_u64() >> 11) % n as u64) as usize
    }
    pub fn fill(&mut self, b: &mut [u8]) {
        for ch in b.chunks_mut(8) {
            let v = self.next_u64().to_le_bytes();
            ch.copy_from_slice(&v[..ch.len()]);
        }
    }
}

#[derive(Clone, Debug)]
pub struct Point {
    pub name: String,
    pub model: &'static str,
    pub loss: usize,
    pub flips: usize,
    pub bursts4k: usize,
    pub sectors512: usize,
    pub sidecar_rot: bool,
}

fn pt(model: &'static str, loss: usize, flips: usize, b: usize, s: usize, rot: bool) -> Point {
    let mut name = String::new();
    if loss > 0 {
        let _ = write!(name, "L{loss}+");
    }
    if b > 0 {
        let _ = write!(name, "B{b}x4K+");
    }
    if s > 0 {
        let _ = write!(name, "S{s}x512+");
    }
    if flips > 0 {
        let _ = write!(name, "F{flips}+");
    }
    if rot {
        name.push_str("rot+");
    }
    name.pop();
    Point {
        name,
        model,
        loss,
        flips,
        bursts4k: b,
        sectors512: s,
        sidecar_rot: rot,
    }
}

pub fn points() -> Vec<Point> {
    vec![
        pt("M1 scattered", 0, 1024, 0, 0, false),
        pt("M1 scattered", 0, 16384, 0, 0, false),
        pt("M1 scattered", 0, 32768, 0, 0, false),
        pt("M1 scattered", 0, 65536, 0, 0, false),
        pt("M1 scattered", 0, 98304, 0, 0, false),
        pt("M1 scattered", 0, 131072, 0, 0, false),
        pt("M2 burst 4K", 0, 0, 32, 0, false),
        pt("M2 burst 4K", 0, 0, 64, 0, false),
        pt("M2 burst 4K", 0, 0, 96, 0, false),
        pt("M2 burst 512", 0, 0, 0, 256, false),
        pt("M2 burst 512", 0, 0, 0, 512, false),
        pt("M2 burst 512", 0, 0, 0, 768, false),
        pt("M3 loss+flips", 8, 16, 0, 0, false),
        pt("M3 loss+flips", 8, 128, 0, 0, false),
        pt("M3 loss+flips", 8, 1024, 0, 0, false),
        pt("M3 loss+flips", 6, 4096, 0, 0, false),
        pt("M3 loss+flips", 4, 16384, 0, 0, false),
        pt("M4 mixed", 4, 1024, 32, 0, false),
        pt("M4 mixed", 2, 4096, 0, 256, false),
        pt("M5 sidecar rot", 0, 65536, 0, 0, true),
        pt("M5 sidecar rot", 8, 128, 0, 0, true),
    ]
}

#[derive(Clone, Copy, Debug)]
pub enum Kind {
    Current,
    Hard,
    Hint,
    Ratchet(RatchetOpts),
    List(usize),
}

#[derive(Clone, Debug)]
pub struct Dec {
    pub name: String,
    pub kind: Kind,
    pub spec: Option<Spec>,
}

const fn sp(cell: usize, check: Check, mode: Mode) -> Spec {
    Spec { cell, check, mode }
}

pub fn decoders() -> Vec<Dec> {
    use Check::*;
    use Mode::*;
    let r = |iterate, bits, pure| RatchetOpts {
        iterate,
        bits,
        chain_pure: pure,
    };
    let d = |name: &str, kind, spec| Dec {
        name: name.to_string(),
        kind,
        spec,
    };
    vec![
        d("a current mend --soft", Kind::Current, None),
        d(
            "b hard marks 4096/crc32",
            Kind::Hard,
            Some(sp(4096, Crc32, Independent)),
        ),
        d(
            "b hard marks 64/crc32",
            Kind::Hard,
            Some(sp(64, Crc32, Independent)),
        ),
        d(
            "c hint marks 4096/crc32",
            Kind::Hint,
            Some(sp(4096, Crc32, Independent)),
        ),
        d(
            "c hint marks 64/crc32",
            Kind::Hint,
            Some(sp(64, Crc32, Independent)),
        ),
        d(
            "d ratchet 64/crc32 +2bit",
            Kind::Ratchet(r(true, 2, false)),
            Some(sp(64, Crc32, Independent)),
        ),
        d(
            "d ratchet 512/crc32 +2bit",
            Kind::Ratchet(r(true, 2, false)),
            Some(sp(512, Crc32, Independent)),
        ),
        d(
            "d ratchet 4096/crc32 +2bit",
            Kind::Ratchet(r(true, 2, false)),
            Some(sp(4096, Crc32, Independent)),
        ),
        d(
            "d ratchet 64/sha64 +2bit",
            Kind::Ratchet(r(true, 2, false)),
            Some(sp(64, Sha64, Independent)),
        ),
        d(
            "d ratchet 512/sha64 +1bit",
            Kind::Ratchet(r(true, 1, false)),
            Some(sp(512, Sha64, Independent)),
        ),
        d(
            "d ratchet 4096/sha64 nobits",
            Kind::Ratchet(r(true, 0, false)),
            Some(sp(4096, Sha64, Independent)),
        ),
        d(
            "d ratchet 512/crc32 1-pass nobits",
            Kind::Ratchet(r(false, 0, false)),
            Some(sp(512, Crc32, Independent)),
        ),
        d(
            "d ratchet 512/crc32 iter nobits",
            Kind::Ratchet(r(true, 0, false)),
            Some(sp(512, Crc32, Independent)),
        ),
        d(
            "d chain-pure 64/crc32 +2bit",
            Kind::Ratchet(r(true, 2, true)),
            Some(sp(64, Crc32, Chained)),
        ),
        d(
            "d chain-hybrid 64/crc32 +2bit",
            Kind::Ratchet(r(true, 2, false)),
            Some(sp(64, Crc32, Chained)),
        ),
        d(
            "d chain-pure 512/crc32 +2bit",
            Kind::Ratchet(r(true, 2, true)),
            Some(sp(512, Crc32, Chained)),
        ),
        d(
            "d chain-hybrid 512/crc32 +2bit",
            Kind::Ratchet(r(true, 2, false)),
            Some(sp(512, Crc32, Chained)),
        ),
        d("e list r<=5 (GS radius)", Kind::List(5), None),
        d("e list r<=7", Kind::List(7), None),
    ]
}

pub fn merkle(leaves: &[[u8; 32]]) -> [u8; 32] {
    let mut lvl: Vec<[u8; 32]> = leaves.to_vec();
    while lvl.len() > 1 {
        let mut nx = Vec::with_capacity(lvl.len().div_ceil(2));
        for p in lvl.chunks(2) {
            if p.len() == 2 {
                let mut h = Sha256::new();
                h.update(p[0]);
                h.update(p[1]);
                nx.push(h.finalize().into());
            } else {
                nx.push(p[0]);
            }
        }
        lvl = nx;
    }
    lvl.first().copied().unwrap_or([0u8; 32])
}

fn sha(b: &[u8]) -> [u8; 32] {
    Sha256::digest(b).into()
}

pub fn root_of(shards: &[Vec<u8>]) -> [u8; 32] {
    let leaves: Vec<[u8; 32]> = shards.iter().map(|s| sha(s)).collect();
    merkle(&leaves)
}

#[derive(Default, Clone)]
pub struct Agg {
    pub trials: u64,
    pub ok: u64,
    pub false_accept: u64,
    pub gate_rejected: u64,
    pub budget: u64,
    pub locks: u64,
    pub false_locks: u64,
    pub bit_locks: u64,
    pub ambiguous: u64,
    pub ns: u128,
    pub max_ns: u128,
    pub salvage: f64,
    pub sidecar_bytes: u64,
}

impl Agg {
    fn add(&mut self, o: &Agg) {
        self.trials += o.trials;
        self.ok += o.ok;
        self.false_accept += o.false_accept;
        self.gate_rejected += o.gate_rejected;
        self.budget += o.budget;
        self.locks += o.locks;
        self.false_locks += o.false_locks;
        self.bit_locks += o.bit_locks;
        self.ambiguous += o.ambiguous;
        self.ns += o.ns;
        self.max_ns = self.max_ns.max(o.max_ns);
        self.salvage += o.salvage;
        self.sidecar_bytes = self.sidecar_bytes.max(o.sidecar_bytes);
    }
}

/// Write the sidecar as a real file next to a stand-in Sigil name, read it back, parse.
fn sidecar_roundtrip(
    dir: &Path,
    bytes: &[u8],
    root: &[u8; 32],
    name: &[u8; 32],
) -> Result<(Option<Sidecar>, u64), String> {
    let path = dir.join("sample.sg1.stripes");
    std::fs::write(&path, bytes).map_err(|e| format!("write {}: {e}", path.display()))?;
    let back = std::fs::read(&path).map_err(|e| format!("read {}: {e}", path.display()))?;
    let len = back.len() as u64;
    Ok((Sidecar::parse(&back, root, name).ok(), len))
}

pub fn run_trial(
    code: &Code,
    p: &Point,
    decs: &[Dec],
    seed: u64,
    dir: &Path,
    dc: &mut DeltaCache,
) -> Result<Vec<Agg>, String> {
    let mut rng = Rng::new(seed);
    let mut payload = vec![0u8; SHARD_LEN * K];
    rng.fill(&mut payload);
    let data: Vec<Vec<u8>> = payload.chunks(SHARD_LEN).map(|c| c.to_vec()).collect();
    let shards = code.encode(&data);
    let root = root_of(&shards);
    let name = sha(&payload);
    let crcs: Vec<u32> = shards.iter().map(|s| crc32fast::hash(s)).collect();

    // ---- damage ----
    let mut rx: Vec<Option<Vec<u8>>> = shards.iter().cloned().map(Some).collect();
    let mut order: Vec<usize> = (0..N).collect();
    for i in (1..N).rev() {
        order.swap(i, rng.below(i + 1));
    }
    for &i in order.iter().take(p.loss) {
        rx[i] = None;
    }
    let live: Vec<usize> = (0..N).filter(|&i| rx[i].is_some()).collect();
    let pick_cells = |rng: &mut Rng, size: usize, count: usize| -> Vec<(usize, usize)> {
        let per = SHARD_LEN / size;
        let total = live.len() * per;
        let mut chosen = std::collections::HashSet::new();
        while chosen.len() < count.min(total) {
            chosen.insert(rng.below(total));
        }
        let mut v: Vec<usize> = chosen.into_iter().collect();
        v.sort_unstable();
        v.into_iter().map(|c| (live[c / per], c % per)).collect()
    };
    for (i, b) in pick_cells(&mut rng, 4096, p.bursts4k) {
        if let Some(s) = rx[i].as_mut() {
            rng.fill(&mut s[b * 4096..(b + 1) * 4096]);
        }
    }
    for (i, b) in pick_cells(&mut rng, 512, p.sectors512) {
        if let Some(s) = rx[i].as_mut() {
            rng.fill(&mut s[b * 512..(b + 1) * 512]);
        }
    }
    let body_bits = live.len() * SHARD_LEN * 8;
    for _ in 0..p.flips {
        let bit = rng.below(body_bits);
        let (i, off) = (live[bit / (SHARD_LEN * 8)], bit % (SHARD_LEN * 8));
        if let Some(s) = rx[i].as_mut() {
            s[off / 8] ^= 1 << (off % 8);
        }
    }
    let crc_ok: Vec<bool> = (0..N)
        .map(|i| {
            rx[i]
                .as_ref()
                .is_some_and(|s| crc32fast::hash(s) == crcs[i])
        })
        .collect();

    // ---- sidecars (built from the intact Sigil at seal time, stored as files) ----
    let mut cache: HashMap<Spec, (Option<Sidecar>, u64)> = HashMap::new();
    for d in decs {
        let Some(spec) = d.spec else { continue };
        if cache.contains_key(&spec) {
            continue;
        }
        let sc = Sidecar::build(spec, &shards, root, name).ok_or("sidecar build")?;
        let mut bytes = sc.to_bytes();
        if p.sidecar_rot && p.flips > 0 {
            let nflip =
                ((p.flips as u128 * bytes.len() as u128 * 8) / body_bits as u128).max(1) as usize;
            for _ in 0..nflip {
                let bit = rng.below(bytes.len() * 8);
                bytes[bit / 8] ^= 1 << (bit % 8);
            }
        }
        cache.insert(spec, sidecar_roundtrip(dir, &bytes, &root, &name)?);
    }

    let inp = Input {
        code,
        rx: &rx,
        crc_ok: &crc_ok,
        shard_len: SHARD_LEN,
        oracle: &shards,
    };
    let mut res = Vec::with_capacity(decs.len());
    for d in decs {
        let (sc, sc_len) = match d.spec {
            Some(s) => cache.get(&s).map_or((None, 0), |(a, l)| (a.as_ref(), *l)),
            None => (None, 0),
        };
        let t0 = Instant::now();
        let o: Out = match d.kind {
            Kind::Current => decoders::current(&inp),
            Kind::Hard => decoders::marks(&inp, sc, false),
            Kind::Hint => decoders::marks(&inp, sc, true),
            Kind::Ratchet(opts) => decoders::ratchet(&inp, sc, opts, dc),
            Kind::List(r) => decoders::list_decode(&inp, r, 256),
        };
        let mut a = Agg {
            trials: 1,
            sidecar_bytes: sc_len,
            ..Agg::default()
        };
        if let Some(out) = &o.data {
            // ---- the gate: Merkle of re-encoded shards + true name ----
            let mut pl = Vec::with_capacity(SHARD_LEN * K);
            for r in out {
                pl.extend_from_slice(r);
            }
            let accept = sha(&pl) == name && root_of(&code.encode(out)) == root;
            let correct = out == &data;
            if accept {
                a.ok = 1;
                if !correct {
                    a.false_accept = 1;
                }
            } else {
                a.gate_rejected = 1;
            }
            let mut good = 0usize;
            let mut tot = 0usize;
            for (r, row) in out.iter().enumerate() {
                for (x, ch) in row.chunks(GATE_STRIPE).enumerate() {
                    tot += 1;
                    if ch == &data[r][x * GATE_STRIPE..x * GATE_STRIPE + ch.len()] {
                        good += 1;
                    }
                }
            }
            a.salvage = good as f64 / tot.max(1) as f64;
        }
        let ns = t0.elapsed().as_nanos();
        a.ns = ns;
        a.max_ns = ns;
        a.budget = o.budget_hit as u64;
        a.locks = o.locks;
        a.false_locks = o.false_locks;
        a.bit_locks = o.bit_locks;
        a.ambiguous = o.ambiguous;
        res.push(a);
    }
    Ok(res)
}

fn wilson(ok: u64, n: u64) -> (f64, f64) {
    if n == 0 {
        return (0.0, 0.0);
    }
    let z = 1.96f64;
    let p = ok as f64 / n as f64;
    let nf = n as f64;
    let den = 1.0 + z * z / nf;
    let c = (p + z * z / (2.0 * nf)) / den;
    let h = z * ((p * (1.0 - p) / nf + z * z / (4.0 * nf * nf)).sqrt()) / den;
    ((c - h).max(0.0), (c + h).min(1.0))
}

pub fn run_cli(args: Vec<String>) -> Result<(), String> {
    let mut trials = 20usize;
    let mut threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let mut max_secs = 2400u64;
    let mut filter: Option<String> = None;
    let mut dfilter: Option<String> = None;
    let mut out_dir = PathBuf::from(".");
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().ok_or(format!("{a} needs a value"));
        match a.as_str() {
            "--trials" => trials = val()?.parse().map_err(|e| format!("{e}"))?,
            "--threads" => threads = val()?.parse().map_err(|e| format!("{e}"))?,
            "--max-secs" => max_secs = val()?.parse().map_err(|e| format!("{e}"))?,
            "--points" => filter = Some(val()?),
            "--decoders" => dfilter = Some(val()?),
            "--out-dir" => out_dir = PathBuf::from(val()?),
            "--help" | "-h" => {
                println!("ratchet-measure [--trials N] [--threads T] [--max-secs S] [--points substr,..] [--decoders substr,..] [--out-dir D]");
                return Ok(());
            }
            _ => return Err(format!("unknown argument {a}")),
        }
    }
    let code = Code::new().ok_or("RS tables")?;
    let pts: Vec<Point> = points()
        .into_iter()
        .filter(|p| {
            filter.as_ref().is_none_or(|f| {
                f.split(',')
                    .any(|s| p.name.contains(s) || p.model.contains(s))
            })
        })
        .collect();
    let decs: Vec<Dec> = decoders()
        .into_iter()
        .filter(|d| {
            dfilter
                .as_ref()
                .is_none_or(|f| f.split(',').any(|s| d.name.contains(s)))
        })
        .collect();
    let jobs: Vec<(usize, usize)> = (0..trials)
        .flat_map(|t| (0..pts.len()).map(move |p| (p, t)))
        .collect();
    let next = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let start = Instant::now();
    let results: Mutex<Vec<Vec<Agg>>> =
        Mutex::new(vec![vec![Agg::default(); decs.len()]; pts.len()]);
    let errors: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let base_tmp = std::env::temp_dir().join(format!("ratchet-measure-{}", std::process::id()));
    std::thread::scope(|s| {
        for tid in 0..threads.max(1) {
            let (code, pts, decs, jobs) = (&code, &pts, &decs, &jobs);
            let (next, stop, results, errors, base_tmp) =
                (&next, &stop, &results, &errors, &base_tmp);
            s.spawn(move || {
                let dir = base_tmp.join(format!("t{tid}"));
                if let Err(e) = std::fs::create_dir_all(&dir) {
                    if let Ok(mut g) = errors.lock() {
                        g.push(format!("mkdir: {e}"));
                    }
                    return;
                }
                let mut dc = DeltaCache::default();
                loop {
                    if stop.load(Ordering::Relaxed) || start.elapsed().as_secs() >= max_secs {
                        stop.store(true, Ordering::Relaxed);
                        break;
                    }
                    let j = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&(pi, t)) = jobs.get(j) else { break };
                    let seed = 0x0051_6711_u64 ^ ((pi as u64) << 32) ^ t as u64;
                    match run_trial(code, &pts[pi], decs, seed, &dir, &mut dc) {
                        Ok(r) => {
                            if let Ok(mut g) = results.lock() {
                                for (a, b) in g[pi].iter_mut().zip(&r) {
                                    a.add(b);
                                }
                            }
                        }
                        Err(e) => {
                            if let Ok(mut g) = errors.lock() {
                                g.push(e);
                            }
                        }
                    }
                    if j % 50 == 0 {
                        eprintln!(
                            "[{:>6.1}s] job {j}/{}",
                            start.elapsed().as_secs_f64(),
                            jobs.len()
                        );
                    }
                }
            });
        }
    });
    let _ = std::fs::remove_dir_all(&base_tmp);
    let errs = errors.into_inner().map_err(|_| "poisoned")?;
    if !errs.is_empty() {
        return Err(format!("{} trial errors, first: {}", errs.len(), errs[0]));
    }
    let res = results.into_inner().map_err(|_| "poisoned")?;
    let wall = start.elapsed().as_secs_f64();
    let body = (N * SHARD_LEN) as f64;
    let payload = (K * SHARD_LEN) as f64;
    let mut md = String::new();
    let mut csv = String::from("model,point,decoder,trials,ok,ok_lo95,ok_hi95,false_accept,gate_rejected,budget,locks,false_locks,bit_locks,ambiguous,mean_ms,max_ms,salvage_4k,sidecar_bytes,overhead_body_pct,overhead_payload_pct\n");
    let _ = writeln!(md, "# ratchet-measure results\n\nthreads={threads} trials/point={trials} wall={wall:.1}s stopped_early={} host={}\n", stop.load(Ordering::Relaxed), hostname());
    for (pi, p) in pts.iter().enumerate() {
        let _ = writeln!(md, "## {} — {}\n", p.model, p.name);
        let _ = writeln!(md, "| decoder | ok/trials | 95% CI | false accept | gate rejected | budget | locks (false) | bit locks | mean ms | max ms | salvage 4K | sidecar % body |");
        let _ = writeln!(md, "|---|---|---|---|---|---|---|---|---|---|---|---|");
        for (di, d) in decs.iter().enumerate() {
            let a = &res[pi][di];
            let (lo, hi) = wilson(a.ok, a.trials);
            let mean = a.ns as f64 / a.trials.max(1) as f64 / 1e6;
            let ovb = a.sidecar_bytes as f64 / body * 100.0;
            let ovp = a.sidecar_bytes as f64 / payload * 100.0;
            let salv = a.salvage / a.trials.max(1) as f64;
            let _ = writeln!(
                md,
                "| {} | {}/{} | {:.3}–{:.3} | {} | {} | {} | {} ({}) | {} | {:.1} | {:.1} | {:.3} | {:.2} |",
                d.name, a.ok, a.trials, lo, hi, a.false_accept, a.gate_rejected, a.budget, a.locks, a.false_locks,
                a.bit_locks, mean, a.max_ns as f64 / 1e6, salv, ovb
            );
            let _ = writeln!(
                csv,
                "{},{},{},{},{},{:.4},{:.4},{},{},{},{},{},{},{},{:.2},{:.2},{:.4},{},{:.3},{:.3}",
                p.model,
                p.name,
                d.name,
                a.trials,
                a.ok,
                lo,
                hi,
                a.false_accept,
                a.gate_rejected,
                a.budget,
                a.locks,
                a.false_locks,
                a.bit_locks,
                a.ambiguous,
                mean,
                a.max_ns as f64 / 1e6,
                salv,
                a.sidecar_bytes,
                ovb,
                ovp
            );
        }
        md.push('\n');
    }
    std::fs::create_dir_all(&out_dir).map_err(|e| format!("{e}"))?;
    std::fs::write(out_dir.join("results.md"), &md).map_err(|e| format!("{e}"))?;
    std::fs::write(out_dir.join("results.csv"), &csv).map_err(|e| format!("{e}"))?;
    print!("{md}");
    Ok(())
}

fn hostname() -> String {
    std::fs::read_to_string("/etc/hostname").map_or_else(|_| "?".into(), |s| s.trim().to_string())
}
