//! Real-data mode: real `.sg1` stars (read from a scratch COPY), real Sigil gate.
//!
//! - Shards are located by their Ember maps (merkle + shard length must match the
//!   header) and checked against their stored CRC32 and the header's Merkle root.
//! - The harness RS twin must reproduce every stored parity shard byte for byte.
//! - Today's repair is the real library path `sigil::mend_bytes_ex(_, soft = true)`
//!   (what `sigil mend --soft` calls), run on the damaged file bytes.
//! - Every other decoder's proposal is accepted only if the real Merkle binding of the
//!   re-encoded shards matches the header AND `sigil::unseal` of the patched file
//!   succeeds (true-name check inside Sigil). Truth for false accepts: the original
//!   unsealed bytes' SHA-256 and the original shard bytes.

use crate::decoders::{self, DeltaCache, Input, Out, RatchetOpts};
use crate::harness::{Agg, Rng};
use crate::rs::{Code, N};
use crate::sidecar::{Check, Mode, Sidecar, Spec};
use std::collections::HashMap;
use std::fmt::Write as _;
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicUsize, Ordering};
use std::sync::Mutex;
use std::time::Instant;

pub struct RealSigil {
    pub label: String,
    pub bytes: Vec<u8>,
    pub k: usize,
    pub shard_len: usize,
    pub merkle: [u8; 32],
    /// Shard body offset in `bytes`, by slot.
    pub offs: Vec<usize>,
    /// Whole stride (Ember .. CRC) start and length, by slot.
    pub strides: Vec<(usize, usize)>,
    pub shards: Vec<Vec<u8>>,
    pub plain_sha: [u8; 32],
    pub plain_len: usize,
}

fn sha(b: &[u8]) -> [u8; 32] {
    sigil::sha256(b)
}

pub fn parse(
    label: &str,
    bytes: Vec<u8>,
    code_for: &dyn Fn(usize) -> Option<&'static Code>,
) -> Result<RealSigil, String> {
    let (h, _prefix, _) =
        sigil::locate_header(&bytes).map_err(|e| format!("{label}: header: {e}"))?;
    if h.n as usize != N || h.encrypted() || h.vow() || !h.ember() {
        return Err(format!(
            "{label}: unsupported geometry/flags (k={} n={} flags={:#x})",
            h.k, h.n, h.flags
        ));
    }
    let k = h.k as usize;
    let sl = h.shard_len as usize;
    let lead = sigil::HEADER_SIZE;
    let mut offs = vec![usize::MAX; N];
    let mut strides = vec![(0usize, 0usize); N];
    let mut i = 0usize;
    while i + lead <= bytes.len() {
        if &bytes[i..i + 4] != b"SGEM" {
            i += 1;
            continue;
        }
        let ok_m = bytes.get(i + 128..i + 160) == Some(&h.merkle[..]);
        let ok_l = bytes.get(i + 100..i + 104) == Some(&h.shard_len.to_le_bytes()[..]);
        if ok_m && ok_l {
            let slot = bytes[i + 107] as usize;
            let off = i + lead;
            if slot < N && off + sl + 4 <= bytes.len() && offs[slot] == usize::MAX {
                offs[slot] = off;
                strides[slot] = (i, lead + sl + 4);
            }
            i += lead;
        } else {
            i += 1;
        }
    }
    if offs.contains(&usize::MAX) {
        return Err(format!("{label}: not all {N} Embers found"));
    }
    let mut shards = Vec::with_capacity(N);
    for &o in &offs {
        let s = bytes[o..o + sl].to_vec();
        let crc = u32::from_le_bytes([
            bytes[o + sl],
            bytes[o + sl + 1],
            bytes[o + sl + 2],
            bytes[o + sl + 3],
        ]);
        if crc32fast::hash(&s) != crc {
            return Err(format!("{label}: stored shard CRC mismatch in the copy"));
        }
        shards.push(s);
    }
    let leaves: Vec<[u8; 32]> = shards.iter().map(|s| sha(s)).collect();
    if sigil::merkle_root(&leaves) != h.merkle {
        return Err(format!("{label}: Merkle root mismatch"));
    }
    let code = code_for(k).ok_or(format!("{label}: no code for k={k}"))?;
    if code.encode(&shards[..k]) != shards {
        return Err(format!(
            "{label}: harness RS does not reproduce stored parity"
        ));
    }
    let plain = sigil::unseal(&bytes, None).map_err(|e| format!("{label}: unseal: {e}"))?;
    Ok(RealSigil {
        label: label.to_string(),
        k,
        shard_len: sl,
        merkle: h.merkle,
        offs,
        strides,
        shards,
        plain_sha: sha(&plain),
        plain_len: plain.len(),
        bytes,
    })
}

#[derive(Clone, Debug)]
pub struct RPoint {
    pub name: String,
    pub loss: usize,
    pub ber: f64,
    pub sector_frac: f64,
    pub burst4k_frac: f64,
    pub rot: bool,
}

fn rp(loss: usize, ber: f64, sector_frac: f64, burst4k_frac: f64, rot: bool) -> RPoint {
    let mut name = String::new();
    if loss > 0 {
        let _ = write!(name, "L{loss}+");
    }
    if burst4k_frac > 0.0 {
        let _ = write!(name, "B4K {:.2}%+", burst4k_frac * 100.0);
    }
    if sector_frac > 0.0 {
        let _ = write!(name, "S512 {:.2}%+", sector_frac * 100.0);
    }
    if ber > 0.0 {
        let _ = write!(name, "BER {ber:.1e}+");
    }
    if rot {
        name.push_str("rot+");
    }
    name.pop();
    RPoint {
        name,
        loss,
        ber,
        sector_frac,
        burst4k_frac,
        rot,
    }
}

/// Damage settings. BERs are chosen to match the synthetic run's flip counts on its
/// 2 MiB body (1 024 flips = 6.1e-5, 16 384 = 9.8e-4, 65 536 = 3.9e-3, ...).
pub fn points_for(k: usize) -> Vec<RPoint> {
    if k == 8 {
        vec![
            rp(0, 6.1e-5, 0.0, 0.0, false),
            rp(0, 9.8e-4, 0.0, 0.0, false),
            rp(0, 1.95e-3, 0.0, 0.0, false),
            rp(0, 3.9e-3, 0.0, 0.0, false),
            rp(0, 5.9e-3, 0.0, 0.0, false),
            rp(0, 0.0, 0.0625, 0.0, false),
            rp(0, 0.0, 0.125, 0.0, false),
            rp(0, 0.0, 0.0, 0.125, false),
            rp(8, 1.9e-6, 0.0, 0.0, false),
            rp(8, 1.5e-5, 0.0, 0.0, false),
            rp(8, 1.2e-4, 0.0, 0.0, false),
            rp(4, 1.3e-3, 0.0, 0.0, false),
            rp(0, 3.9e-3, 0.0, 0.0, true),
            rp(8, 1.5e-5, 0.0, 0.0, true),
        ]
    } else {
        vec![
            rp(0, 6.1e-5, 0.0, 0.0, false),
            rp(0, 2.4e-4, 0.0, 0.0, false),
            rp(0, 9.8e-4, 0.0, 0.0, false),
            rp(0, 1.95e-3, 0.0, 0.0, false),
            rp(0, 3.9e-3, 0.0, 0.0, false),
            rp(0, 0.0, 0.02, 0.0, false),
            rp(0, 0.0, 0.0625, 0.0, false),
            rp(0, 0.0, 0.0, 0.0625, false),
            rp(4, 1.9e-6, 0.0, 0.0, false),
            rp(4, 1.5e-5, 0.0, 0.0, false),
            rp(4, 1.2e-4, 0.0, 0.0, false),
            rp(2, 9.8e-4, 0.0, 0.0, false),
            rp(0, 1.95e-3, 0.0, 0.0, true),
            rp(4, 1.5e-5, 0.0, 0.0, true),
        ]
    }
}

#[derive(Clone, Copy, Debug)]
enum RKind {
    RealMend,
    Model,
    Hard,
    Hint,
    Ratchet(RatchetOpts),
}

struct RDec {
    name: &'static str,
    kind: RKind,
    spec: Option<Spec>,
}

fn rdecoders() -> Vec<RDec> {
    use Check::Crc32;
    use Mode::*;
    let sp = |cell, mode| {
        Some(Spec {
            cell,
            check: Crc32,
            mode,
        })
    };
    let r = |bits, pure| RatchetOpts {
        iterate: true,
        bits,
        chain_pure: pure,
    };
    vec![
        RDec {
            name: "a REAL sigil mend --soft (library)",
            kind: RKind::RealMend,
            spec: None,
        },
        RDec {
            name: "a' harness model of today",
            kind: RKind::Model,
            spec: None,
        },
        RDec {
            name: "b hard marks 4096/crc32",
            kind: RKind::Hard,
            spec: sp(4096, Independent),
        },
        RDec {
            name: "b hard marks 64/crc32",
            kind: RKind::Hard,
            spec: sp(64, Independent),
        },
        RDec {
            name: "c hint marks 64/crc32",
            kind: RKind::Hint,
            spec: sp(64, Independent),
        },
        RDec {
            name: "d ratchet 64/crc32 +2bit",
            kind: RKind::Ratchet(r(2, false)),
            spec: sp(64, Independent),
        },
        RDec {
            name: "d ratchet 512/crc32 +2bit",
            kind: RKind::Ratchet(r(2, false)),
            spec: sp(512, Independent),
        },
        RDec {
            name: "d chain-hybrid 64/crc32 +2bit",
            kind: RKind::Ratchet(r(2, false)),
            spec: sp(64, Chained),
        },
        RDec {
            name: "d chain-pure 64/crc32 +2bit",
            kind: RKind::Ratchet(r(2, true)),
            spec: sp(64, Chained),
        },
    ]
}

fn sround(rng: &mut Rng, x: f64) -> usize {
    let f = x.floor();
    let frac = x - f;
    let extra = ((rng.next_u64() >> 11) as f64 / (1u64 << 53) as f64) < frac;
    f as usize + extra as usize
}

/// Patch decoded data shards into the file (all n shards re-encoded, CRCs rewritten,
/// wiped Embers restored from the intact header copy) and run the real gate.
fn real_gate(s: &RealSigil, code: &Code, damaged: &[u8], data: &[Vec<u8>]) -> (bool, bool) {
    let all = code.encode(data);
    let leaves: Vec<[u8; 32]> = all.iter().map(|x| sha(x)).collect();
    let merkle_ok = sigil::merkle_root(&leaves) == s.merkle;
    let correct = all == s.shards;
    if !merkle_ok {
        return (false, correct);
    }
    let mut f = damaged.to_vec();
    for (slot, sh) in all.iter().enumerate() {
        let (st, _) = s.strides[slot];
        f[st..st + sigil::HEADER_SIZE].copy_from_slice(&s.bytes[st..st + sigil::HEADER_SIZE]);
        let o = s.offs[slot];
        f[o..o + s.shard_len].copy_from_slice(sh);
        f[o + s.shard_len..o + s.shard_len + 4].copy_from_slice(&crc32fast::hash(sh).to_le_bytes());
    }
    let ok =
        sigil::unseal(&f, None).is_ok_and(|p| p.len() == s.plain_len && sha(&p) == s.plain_sha);
    (ok, correct)
}

#[allow(clippy::too_many_arguments)]
fn run_one(
    s: &RealSigil,
    code: &Code,
    p: &RPoint,
    decs: &[RDec],
    seed: u64,
    dir: &Path,
    dc: &mut DeltaCache,
    mend_secs: u64,
) -> Result<Vec<Agg>, String> {
    let mut rng = Rng::new(seed);
    let sl = s.shard_len;
    let mut file = s.bytes.clone();
    let mut order: Vec<usize> = (0..N).collect();
    for i in (1..N).rev() {
        order.swap(i, rng.below(i + 1));
    }
    let lost: Vec<usize> = order.iter().copied().take(p.loss).collect();
    for &i in &lost {
        let (st, len) = s.strides[i];
        file[st..st + len].fill(0);
    }
    let live: Vec<usize> = (0..N).filter(|i| !lost.contains(i)).collect();
    let cells = |rng: &mut Rng, file: &mut Vec<u8>, size: usize, frac: f64| {
        let per = sl.div_ceil(size);
        let total = live.len() * per;
        let want = sround(rng, frac * total as f64).min(total);
        let mut chosen = std::collections::HashSet::new();
        while chosen.len() < want {
            chosen.insert(rng.below(total));
        }
        for c in chosen {
            let (slot, b) = (live[c / per], c % per);
            let a = s.offs[slot] + b * size;
            let e = s.offs[slot] + ((b + 1) * size).min(sl);
            rng.fill(&mut file[a..e]);
        }
    };
    cells(&mut rng, &mut file, 4096, p.burst4k_frac);
    cells(&mut rng, &mut file, 512, p.sector_frac);
    let body_bits = live.len() * sl * 8;
    let flips = sround(&mut rng, p.ber * body_bits as f64);
    for _ in 0..flips {
        let bit = rng.below(body_bits.max(1));
        let (slot, off) = (live[bit / (sl * 8)], bit % (sl * 8));
        file[s.offs[slot] + off / 8] ^= 1 << (off % 8);
    }
    let rx: Vec<Option<Vec<u8>>> = (0..N)
        .map(|i| {
            if lost.contains(&i) {
                None
            } else {
                Some(file[s.offs[i]..s.offs[i] + sl].to_vec())
            }
        })
        .collect();
    let crc_ok: Vec<bool> = (0..N)
        .map(|i| rx[i].as_ref().is_some_and(|b| b == &s.shards[i]))
        .collect();

    let mut cache: HashMap<Spec, (Option<Sidecar>, u64)> = HashMap::new();
    for d in decs {
        let Some(spec) = d.spec else { continue };
        if cache.contains_key(&spec) {
            continue;
        }
        let sc =
            Sidecar::build(spec, s.k, &s.shards, s.merkle, s.plain_sha).ok_or("sidecar build")?;
        let mut bytes = sc.to_bytes();
        if p.rot && p.ber > 0.0 {
            let nflip = sround(&mut rng, p.ber * bytes.len() as f64 * 8.0);
            for _ in 0..nflip {
                let bit = rng.below(bytes.len() * 8);
                bytes[bit / 8] ^= 1 << (bit % 8);
            }
        }
        let path = dir.join("star.sg1.stripes");
        std::fs::write(&path, &bytes).map_err(|e| format!("{e}"))?;
        let back = std::fs::read(&path).map_err(|e| format!("{e}"))?;
        let len = back.len() as u64;
        cache.insert(
            spec,
            (Sidecar::parse(&back, &s.merkle, &s.plain_sha).ok(), len),
        );
    }
    let inp = Input {
        code,
        rx: &rx,
        crc_ok: &crc_ok,
        shard_len: sl,
        oracle: &s.shards,
    };
    let mut res = Vec::with_capacity(decs.len());
    for d in decs {
        let (sc, sc_len) = match d.spec {
            Some(sp) => cache.get(&sp).map_or((None, 0), |(a, l)| (a.as_ref(), *l)),
            None => (None, 0),
        };
        let mut a = Agg {
            trials: 1,
            sidecar_bytes: sc_len,
            ..Agg::default()
        };
        let t0 = Instant::now();
        match d.kind {
            RKind::RealMend => match real_mend_bounded(&file, dir, mend_secs) {
                MendResult::Healed(healed) => {
                    let good = sigil::unseal(&healed, None)
                        .is_ok_and(|pl| pl.len() == s.plain_len && sha(&pl) == s.plain_sha);
                    if good {
                        a.ok = 1;
                    } else {
                        a.false_accept = 1; // mend said OK but bytes differ
                    }
                }
                MendResult::Refused => {}
                MendResult::Timeout => a.budget = 1,
            },
            _ => {
                let o: Out = match d.kind {
                    RKind::Model => decoders::current(&inp),
                    RKind::Hard => decoders::marks(&inp, sc, false),
                    RKind::Hint => decoders::marks(&inp, sc, true),
                    RKind::Ratchet(opts) => decoders::ratchet(&inp, sc, opts, dc),
                    RKind::RealMend => Out::default(),
                };
                if let Some(data) = &o.data {
                    let (accept, correct) = real_gate(s, code, &file, data);
                    if accept {
                        a.ok = 1;
                        if !correct {
                            a.false_accept = 1;
                        }
                    } else {
                        a.gate_rejected = 1;
                    }
                }
                a.budget = o.budget_hit as u64;
                a.locks = o.locks;
                a.false_locks = o.false_locks;
                a.bit_locks = o.bit_locks;
            }
        }
        let ns = t0.elapsed().as_nanos();
        a.ns = ns;
        a.max_ns = ns;
        res.push(a);
    }
    Ok(res)
}

enum MendResult {
    Healed(Vec<u8>),
    Refused,
    Timeout,
}

/// Run the real library mend (`sigil::mend_bytes_ex`, soft) in a child process of this
/// binary so a slow soft search can be stopped at `secs` (counted as a failure).
fn real_mend_bounded(file: &[u8], dir: &Path, secs: u64) -> MendResult {
    let inp = dir.join("damaged.sg1");
    let outp = dir.join("healed.sg1");
    let _ = std::fs::remove_file(&outp);
    if std::fs::write(&inp, file).is_err() {
        return MendResult::Refused;
    }
    let Ok(exe) = std::env::current_exe() else {
        return MendResult::Refused;
    };
    let Ok(mut child) = std::process::Command::new(exe)
        .arg("mend-one")
        .arg(&inp)
        .arg(&outp)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
    else {
        return MendResult::Refused;
    };
    let t0 = Instant::now();
    loop {
        match child.try_wait() {
            Ok(Some(st)) => {
                return if st.success() {
                    std::fs::read(&outp).map_or(MendResult::Refused, MendResult::Healed)
                } else {
                    MendResult::Refused
                };
            }
            Ok(None) if t0.elapsed().as_secs() >= secs => {
                let _ = child.kill();
                let _ = child.wait();
                return MendResult::Timeout;
            }
            Ok(None) => std::thread::sleep(std::time::Duration::from_millis(5)),
            Err(_) => return MendResult::Refused,
        }
    }
}

/// `mend-one IN OUT`: the real library soft mend on one file (child-process helper).
pub fn mend_one(args: Vec<String>) -> Result<(), String> {
    let (Some(i), Some(o)) = (args.first(), args.get(1)) else {
        return Err("mend-one IN OUT".into());
    };
    let b = std::fs::read(i).map_err(|e| format!("{e}"))?;
    let (healed, _) = sigil::mend_bytes_ex(&b, true).map_err(|e| format!("{e}"))?;
    std::fs::write(o, healed).map_err(|e| format!("{e}"))
}

fn code_for(k: usize) -> Option<&'static Code> {
    static C8: std::sync::OnceLock<Option<Code>> = std::sync::OnceLock::new();
    static C12: std::sync::OnceLock<Option<Code>> = std::sync::OnceLock::new();
    match k {
        8 => C8.get_or_init(|| Code::new(8)).as_ref(),
        12 => C12.get_or_init(|| Code::new(12)).as_ref(),
        _ => None,
    }
}

/// `real --list FILE` : one scratch-copy path per line (tab-separated, path in last column).
pub fn run_real(args: Vec<String>) -> Result<(), String> {
    let mut list: Option<PathBuf> = None;
    let mut trials = 72usize;
    let mut threads = std::thread::available_parallelism().map_or(1, |n| n.get());
    let mut max_secs = 2400u64;
    let mut out_dir = PathBuf::from(".");
    let mut tracks = "reflection,seal".to_string();
    let mut mend_secs = 20u64;
    let mut it = args.into_iter();
    while let Some(a) = it.next() {
        let mut val = || it.next().ok_or(format!("{a} needs a value"));
        match a.as_str() {
            "--list" => list = Some(PathBuf::from(val()?)),
            "--trials" => trials = val()?.parse().map_err(|e| format!("{e}"))?,
            "--threads" => threads = val()?.parse().map_err(|e| format!("{e}"))?,
            "--max-secs" => max_secs = val()?.parse().map_err(|e| format!("{e}"))?,
            "--out-dir" => out_dir = PathBuf::from(val()?),
            "--tracks" => tracks = val()?,
            "--mend-secs" => mend_secs = val()?.parse().map_err(|e| format!("{e}"))?,
            _ => return Err(format!("unknown argument {a}")),
        }
    }
    let list = list.ok_or("--list required")?;
    let text = std::fs::read_to_string(&list).map_err(|e| format!("{e}"))?;
    let mut stars: Vec<RealSigil> = Vec::new();
    let mut seals: Vec<RealSigil> = Vec::new();
    let mut log = String::new();
    for line in text.lines().filter(|l| !l.trim().is_empty()) {
        let path = line.split('\t').next_back().unwrap_or(line).trim();
        let label = Path::new(path)
            .file_name()
            .map_or(path.to_string(), |f| f.to_string_lossy().to_string());
        let bytes = std::fs::read(path).map_err(|e| format!("{path}: {e}"))?;
        match parse(&label, bytes, &code_for) {
            Ok(s) => {
                let _ = writeln!(log, "loaded {label}: k={} shard_len={} file={} plain={} parity reproduced, merkle ok", s.k, s.shard_len, s.bytes.len(), s.plain_len);
                if tracks.contains("seal") {
                    // Same real payload, re-sealed as Seal 8-of-16 (in memory; scratch only).
                    let plain = sigil::unseal(&s.bytes, None).map_err(|e| format!("{e}"))?;
                    let sb = sigil::seal(&plain, sigil::Mode::Seal, None, &label, false)
                        .map_err(|e| format!("{e}"))?;
                    match parse(&format!("{label} [as Seal]"), sb, &code_for) {
                        Ok(x) if x.k == 8 => seals.push(x),
                        Ok(x) => {
                            let _ = writeln!(log, "skip seal of {label}: k={}", x.k);
                        }
                        Err(e) => {
                            let _ = writeln!(log, "skip seal of {label}: {e}");
                        }
                    }
                }
                stars.push(s);
            }
            Err(e) => {
                let _ = writeln!(log, "SKIP {e}");
            }
        }
    }
    eprint!("{log}");
    let mut groups: Vec<(&str, &Vec<RealSigil>)> = Vec::new();
    if tracks.contains("reflection") {
        groups.push(("Reflection 12-of-16 (as stored)", &stars));
    }
    if tracks.contains("seal") {
        groups.push(("Seal 8-of-16 (same payloads re-sealed)", &seals));
    }
    let decs = rdecoders();
    // jobs: (group, point, trial) — trial-major so a time stop stays balanced
    let mut jobs: Vec<(usize, usize, usize)> = Vec::new();
    let gpoints: Vec<Vec<RPoint>> = groups
        .iter()
        .map(|(_, g)| points_for(g.first().map_or(12, |s| s.k)))
        .collect();
    for t in 0..trials {
        for (gi, pts) in gpoints.iter().enumerate() {
            for pi in 0..pts.len() {
                jobs.push((gi, pi, t));
            }
        }
    }
    let next = AtomicUsize::new(0);
    let stop = AtomicBool::new(false);
    let start = Instant::now();
    let results: Mutex<HashMap<(usize, usize), Vec<Agg>>> = Mutex::new(HashMap::new());
    let errors: Mutex<Vec<String>> = Mutex::new(Vec::new());
    let base_tmp = out_dir.join("tmp-sidecars");
    std::fs::create_dir_all(&out_dir).map_err(|e| format!("{e}"))?;
    let raw = Mutex::new(
        std::fs::File::create(out_dir.join("real-trials.csv")).map_err(|e| format!("{e}"))?,
    );
    if let Ok(mut f) = raw.lock() {
        use std::io::Write as _;
        let _ = writeln!(
            f,
            "track,point,trial,star,decoder,ok,false_accept,gate_rejected,budget_or_timeout,ms"
        );
    }
    std::thread::scope(|sc| {
        for tid in 0..threads.max(1) {
            let (groups, gpoints, decs, jobs) = (&groups, &gpoints, &decs, &jobs);
            let (next, stop, results, errors, base_tmp) =
                (&next, &stop, &results, &errors, &base_tmp);
            let raw = &raw;
            sc.spawn(move || {
                let dir = base_tmp.join(format!("t{tid}"));
                if std::fs::create_dir_all(&dir).is_err() {
                    return;
                }
                let mut dc = DeltaCache::default();
                loop {
                    if stop.load(Ordering::Relaxed) || start.elapsed().as_secs() >= max_secs {
                        stop.store(true, Ordering::Relaxed);
                        break;
                    }
                    let j = next.fetch_add(1, Ordering::Relaxed);
                    let Some(&(gi, pi, t)) = jobs.get(j) else {
                        break;
                    };
                    let g = groups[gi].1;
                    if g.is_empty() {
                        continue;
                    }
                    let s = &g[(t * 5) % g.len()]; // stride 5: sizes mixed early, all stars by t = len
                    let Some(code) = code_for(s.k) else { continue };
                    let seed =
                        0x5245_414c_u64 ^ ((gi as u64) << 48) ^ ((pi as u64) << 32) ^ t as u64;
                    match run_one(
                        s,
                        code,
                        &gpoints[gi][pi],
                        decs,
                        seed,
                        &dir,
                        &mut dc,
                        mend_secs,
                    ) {
                        Ok(r) => {
                            if let Ok(mut f) = raw.lock() {
                                use std::io::Write as _;
                                for (d, a) in decs.iter().zip(&r) {
                                    let _ = writeln!(
                                        f,
                                        "{},{},{t},{},{},{},{},{},{},{:.2}",
                                        groups[gi].0,
                                        gpoints[gi][pi].name,
                                        s.label,
                                        d.name,
                                        a.ok,
                                        a.false_accept,
                                        a.gate_rejected,
                                        a.budget,
                                        a.ns as f64 / 1e6
                                    );
                                }
                                let _ = f.flush();
                            }
                            if let Ok(mut m) = results.lock() {
                                let e = m
                                    .entry((gi, pi))
                                    .or_insert_with(|| vec![Agg::default(); decs.len()]);
                                for (a, b) in e.iter_mut().zip(&r) {
                                    a.add(b);
                                }
                            }
                        }
                        Err(e) => {
                            if let Ok(mut m) = errors.lock() {
                                m.push(e);
                            }
                        }
                    }
                    if j % 100 == 0 {
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
    let res = results.into_inner().map_err(|_| "poisoned")?;
    let wall = start.elapsed().as_secs_f64();
    let mut md = String::new();
    let mut csv = String::from("track,point,decoder,trials,ok,false_accept,gate_rejected,budget,locks,false_locks,bit_locks,mean_ms,max_ms,sidecar_bytes_sum,file_bytes_sum\n");
    let _ = writeln!(md, "# ratchet-measure REAL data (Instagram Sigil sample copy)\n\nthreads={threads} trials/point<={trials} wall={wall:.1}s stopped_early={} errors={}\n", stop.load(Ordering::Relaxed), errs.len());
    for e in errs.iter().take(5) {
        let _ = writeln!(md, "- error: {e}");
    }
    md.push_str("\n```\n");
    md.push_str(&log);
    md.push_str("```\n");
    for (gi, (gname, g)) in groups.iter().enumerate() {
        let fbytes: u64 = g.iter().map(|s| s.bytes.len() as u64).sum();
        let _ = writeln!(md, "\n## {gname}: {} stars, {} bytes\n", g.len(), fbytes);
        for (pi, p) in gpoints[gi].iter().enumerate() {
            let Some(row) = res.get(&(gi, pi)) else {
                continue;
            };
            let _ = writeln!(md, "### {}\n\n| decoder | ok/trials | false accept | gate rejected | budget | locks (false) | mean ms | max ms |\n|---|---|---|---|---|---|---|---|", p.name);
            for (di, d) in decs.iter().enumerate() {
                let a = &row[di];
                let mean = a.ns as f64 / a.trials.max(1) as f64 / 1e6;
                let _ = writeln!(
                    md,
                    "| {} | {}/{} | {} | {} | {} | {} ({}) | {:.1} | {:.1} |",
                    d.name,
                    a.ok,
                    a.trials,
                    a.false_accept,
                    a.gate_rejected,
                    a.budget,
                    a.locks,
                    a.false_locks,
                    mean,
                    a.max_ns as f64 / 1e6
                );
                let _ = writeln!(
                    csv,
                    "{},{},{},{},{},{},{},{},{},{},{},{:.2},{:.2},{},{}",
                    gname,
                    p.name,
                    d.name,
                    a.trials,
                    a.ok,
                    a.false_accept,
                    a.gate_rejected,
                    a.budget,
                    a.locks,
                    a.false_locks,
                    a.bit_locks,
                    mean,
                    a.max_ns as f64 / 1e6,
                    a.sidecar_bytes,
                    fbytes
                );
            }
            md.push('\n');
        }
        // overhead per sidecar type over this group's files
        let _ = writeln!(md, "Sidecar overhead (sum over the {} stars):\n", g.len());
        for spec in [
            (64usize, Mode::Independent),
            (512, Mode::Independent),
            (4096, Mode::Independent),
        ] {
            let sp = Spec {
                cell: spec.0,
                check: Check::Crc32,
                mode: spec.1,
            };
            let mut tot = 0u64;
            for s in g.iter() {
                if let Some(sc) = Sidecar::build(sp, s.k, &s.shards, s.merkle, s.plain_sha) {
                    tot += sc.to_bytes().len() as u64;
                }
            }
            let _ = writeln!(
                md,
                "- {}/crc32: {} bytes = {:.2}% of the stars' bytes",
                spec.0,
                tot,
                tot as f64 / fbytes.max(1) as f64 * 100.0
            );
        }
    }
    std::fs::create_dir_all(&out_dir).map_err(|e| format!("{e}"))?;
    std::fs::write(out_dir.join("real-results.md"), &md).map_err(|e| format!("{e}"))?;
    std::fs::write(out_dir.join("real-results.csv"), &csv).map_err(|e| format!("{e}"))?;
    print!("{md}");
    Ok(())
}
