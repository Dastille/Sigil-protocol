#!/usr/bin/env python3
"""Deep-space damage benchmark for the real `sigil` CLI (docs/research/DEEP-SPACE.md).

Usage:
  python3 docs/research/deep-space-bench.py path/to/sigil [trials] [size_bytes]

Seals one random file (fixed seed) in Reflection and Seal mode, then for each
damage case runs `sigil unseal` on a damaged copy; if that refuses, runs
`sigil mend --soft` and unseals the mended copy. Every output is compared with
the original bytes, so a wrong answer is counted as WRONG, never as success.

Cases:
  bits N     flip N random bits anywhere in the .sg1 (scattered, independent)
  run F      zero one contiguous run of F x file size at a random offset
  trunc F    cut the last F x file size bytes off
  fountain   `deluge --fountain --extra E`, delete K% of the .rq packets at
             random, `gather`, unseal (fountain only, no .sg1 damage)

Outcome columns per case (out of `trials`):
  direct   unseal succeeded on the damaged file, bytes exact
  mended   unseal refused, `mend --soft` + unseal gave exact bytes
  refused  both refused (fail closed)
  WRONG    a command exited 0 with bytes that differ from the original
Time is the median wall time of the successful path (ms), whole commands.
Seeds are fixed (trial index), so reruns give the same damage.
"""
import os, random, shutil, statistics, subprocess, sys, tempfile, time

S = os.path.abspath(sys.argv[1])
T = int(sys.argv[2]) if len(sys.argv) > 2 else 10
SIZE = int(sys.argv[3]) if len(sys.argv) > 3 else 1_000_000
d = tempfile.mkdtemp(prefix="sigil-deepspace-")
orig = random.Random(2026_10_25).randbytes(SIZE)
open(f"{d}/orig.bin", "wb").write(orig)


def sh(*args):
    t = time.perf_counter()
    p = subprocess.run([S, *args], capture_output=True)
    return p.returncode, (time.perf_counter() - t) * 1000


def unseal(path):
    out = f"{d}/out.bin"
    if os.path.exists(out):
        os.remove(out)
    rc, ms = sh("unseal", "-o", out, path)
    if rc != 0:
        return "refused", ms
    return ("exact" if open(out, "rb").read() == orig else "WRONG"), ms


def attempt(damaged):
    open(f"{d}/t.sg1", "wb").write(damaged)
    r, ms = unseal(f"{d}/t.sg1")
    if r != "refused":
        return ("direct" if r == "exact" else "WRONG"), ms
    m = f"{d}/m.sg1"
    if os.path.exists(m):
        os.remove(m)
    rc, ms2 = sh("mend", "--soft", "-o", m, f"{d}/t.sg1")
    if rc != 0:
        return "refused", ms + ms2
    r, ms3 = unseal(m)
    if r == "exact":
        return "mended", ms + ms2 + ms3
    return ("WRONG" if r == "WRONG" else "refused"), ms + ms2 + ms3


def flips(base, count, r):
    b = bytearray(base)
    for pos in r.sample(range(len(b) * 8), count):
        b[pos // 8] ^= 1 << (pos % 8)
    return bytes(b)


def run_zero(base, frac, r):
    b = bytearray(base)
    n = int(len(b) * frac)
    s = r.randrange(0, len(b) - n)
    b[s:s + n] = bytes(n)
    return bytes(b)


def trunc(base, frac, r):
    return base[: len(base) - int(len(base) * frac)]


def row(mode, label, res, times):
    c = {k: res.count(k) for k in ["direct", "mended", "refused", "WRONG"]}
    t = f"{statistics.median(times):.0f}" if times else "-"
    print(f"| {mode} | {label} | {c['direct']} | {c['mended']} | {c['refused']} | {c['WRONG']} | {t} |",
          flush=True)


print(f"sigil: {subprocess.run([S, '--version'], capture_output=True, text=True).stdout.strip()}")
print(f"file: {SIZE} random bytes, trials per case: {T}\n")
print("| mode | damage | direct | mended | refused | WRONG | median ms (ok path) |")
print("|---|---|---|---|---|---|---|")
for mode in ["reflection", "seal"]:
    sh("seal", "--mode", mode, "-o", f"{d}/{mode}.sg1", f"{d}/orig.bin")
    base = open(f"{d}/{mode}.sg1", "rb").read()
    cases = [("bits", v) for v in [1, 4, 16, 64, 256, 1024, 4096, 16384]]
    cases += [("run", v) for v in [0.01, 0.10, 0.20, 0.30, 0.45]]
    cases += [("trunc", v) for v in [0.001, 0.10, 0.20, 0.30, 0.45]]
    for kind, v in cases:
        res, times = [], []
        for s in range(T):
            r = random.Random(s)
            dmg = {"bits": flips, "run": run_zero, "trunc": trunc}[kind](base, v, r)
            out, ms = attempt(dmg)
            res.append(out)
            if out in ("direct", "mended"):
                times.append(ms)
        label = {"bits": f"{v} scattered bit flips",
                 "run": f"zeroed run {v:.0%} of .sg1",
                 "trunc": f"truncate {v:.1%} of .sg1"}[kind]
        row(f"{mode} ({len(base)} B)", label, res, times)

# Fountain: drop K% of RaptorQ packets.
print("\n| fountain (.rq of a reflection .sg1) | extra | packets written | dropped | rebuilt exact | refused | WRONG | median gather+unseal ms |")
print("|---|---|---|---|---|---|---|---|")
for extra in [4, 16, 64]:
    for drop in [0.0, 0.05, 0.10, 0.25, 0.50]:
        res, times, written = [], [], 0
        for s in range(T):
            rain = f"{d}/rain"
            shutil.rmtree(rain, ignore_errors=True)
            sh("deluge", "--fountain", "--extra", str(extra), "-o", rain, f"{d}/reflection.sg1")
            pk = sorted(p for p in os.listdir(rain) if p.endswith(".rq"))
            written = len(pk)
            r = random.Random(1000 + s)
            for p in r.sample(pk, int(len(pk) * drop)):
                os.remove(f"{rain}/{p}")
            g = f"{d}/g.sg1"
            if os.path.exists(g):
                os.remove(g)
            rc, ms = sh("gather", "-o", g, rain)
            if rc != 0:
                res.append("refused")
                continue
            u, ms2 = unseal(g)
            res.append(u)
            if u == "exact":
                times.append(ms + ms2)
        t = f"{statistics.median(times):.0f}" if times else "-"
        print(f"| reflection | {extra} | {written} | {drop:.0%} | {res.count('exact')} | "
              f"{res.count('refused')} | {res.count('WRONG')} | {t} |", flush=True)
shutil.rmtree(d, ignore_errors=True)
