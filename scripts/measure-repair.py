#!/usr/bin/env python3
"""Measure .sg1 repair against scattered bit flips and contiguous bursts.

Usage: python3 scripts/measure-repair.py path/to/sigil [trials]
Makes a 1 MB random file, inscribes it in Reflection and Seal (default settings),
damages copies with fixed seeds, De-scribes each, and counts exact / refused / WRONG.
"""
import os, random, subprocess, sys, tempfile

S = sys.argv[1]
N = int(sys.argv[2]) if len(sys.argv) > 2 else 20
d = tempfile.mkdtemp(prefix="sigil-repair-")
orig = os.urandom(1_000_000)
open(f"{d}/orig.bin", "wb").write(orig)

def run(b):
    open(f"{d}/t.sg1", "wb").write(b)
    out = f"{d}/out.bin"
    if os.path.exists(out):
        os.remove(out)
    p = subprocess.run([S, "de-scribe", "-o", out, f"{d}/t.sg1"], capture_output=True, text=True)
    if p.returncode == 0:
        return "exact" if open(out, "rb").read() == orig else "WRONG"
    return "refused"

def flips(base, count, r):
    b = bytearray(base)
    for i in r.sample(range(len(b)), count):
        b[i] ^= 1 << r.randrange(8)
    return b

def burst(base, frac, r):
    b = bytearray(base); n = int(len(b) * frac); s = r.randrange(4096, len(b) - n)
    b[s:s + n] = bytes(n)
    return b

for mode in ["reflection", "seal"]:
    subprocess.run([S, "inscribe", "--mode", mode, "-o", f"{d}/{mode}.sg1", f"{d}/orig.bin"],
                   check=True, capture_output=True)
    base = open(f"{d}/{mode}.sg1", "rb").read()
    print(f"# {mode}: mark {len(base)} bytes")
    cases = [("bits", c) for c in [1, 4, 5, 6, 8, 9, 12, 16]]
    cases += [("bits", int(len(base) * f)) for f in [1e-4, 1e-3, 0.01, 0.10]]
    cases += [("burst", f) for f in [0.10, 0.20, 0.25, 0.40, 0.45, 0.50]]
    for kind, v in cases:
        res = [run(flips(base, v, random.Random(s)) if kind == "bits" else burst(base, v, random.Random(s)))
               for s in range(N)]
        label = f"{v} flipped bits" if kind == "bits" else f"{v:.0%} zeroed burst"
        print(f"{mode:10s} {label:24s} exact {res.count('exact')}/{N}  "
              f"refused {res.count('refused')}  WRONG {res.count('WRONG')}", flush=True)
