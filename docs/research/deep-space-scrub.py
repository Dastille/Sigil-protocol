#!/usr/bin/env python3
"""Scrubbing experiment: errors that pile up vs errors cleaned every epoch.

Usage: python3 docs/research/deep-space-scrub.py path/to/sigil [trials] [flips_per_epoch] [epochs]

One 1 MB random file, Reflection. Each epoch flips `flips_per_epoch` random
bits in the stored copy (a stand-in for upsets between scrub passes).
  scrubbed:   after every epoch run `mend --soft` and keep the mended copy
  unscrubbed: let all epochs pile up, then one `mend --soft` at the end
Then unseal and compare with the original. Counts exact / refused / WRONG.
"""
import os, random, subprocess, sys, tempfile

S = os.path.abspath(sys.argv[1])
T = int(sys.argv[2]) if len(sys.argv) > 2 else 10
F = int(sys.argv[3]) if len(sys.argv) > 3 else 1024
E = int(sys.argv[4]) if len(sys.argv) > 4 else 8
d = tempfile.mkdtemp(prefix="sigil-scrub-")
orig = random.Random(2026_10_25).randbytes(1_000_000)
open(f"{d}/o.bin", "wb").write(orig)
subprocess.run([S, "seal", "-o", f"{d}/a.sg1", f"{d}/o.bin"], check=True, capture_output=True)
base = open(f"{d}/a.sg1", "rb").read()


def hit(b, r):
    b = bytearray(b)
    for p in r.sample(range(len(b) * 8), F):
        b[p // 8] ^= 1 << (p % 8)
    return bytes(b)


def mend(b):
    open(f"{d}/t.sg1", "wb").write(b)
    if os.path.exists(f"{d}/m.sg1"):
        os.remove(f"{d}/m.sg1")
    p = subprocess.run([S, "mend", "--soft", "-o", f"{d}/m.sg1", f"{d}/t.sg1"], capture_output=True)
    return open(f"{d}/m.sg1", "rb").read() if p.returncode == 0 else None


def outcome(b):
    if b is None:
        return "refused"
    open(f"{d}/u.sg1", "wb").write(b)
    p = subprocess.run([S, "unseal", "-o", f"{d}/u.bin", f"{d}/u.sg1"], capture_output=True)
    if p.returncode != 0:
        return "refused"
    return "exact" if open(f"{d}/u.bin", "rb").read() == orig else "WRONG"


res = {"scrubbed": [], "unscrubbed": []}
for s in range(T):
    r = random.Random(s)
    cur = base
    for _ in range(E):
        cur = mend(hit(cur, r))
        if cur is None:
            break
    res["scrubbed"].append(outcome(cur))
    r = random.Random(s)
    cur = base
    for _ in range(E):
        cur = hit(cur, r)
    res["unscrubbed"].append(outcome(mend(cur)))
print(f"{F} flips per epoch x {E} epochs = {F * E} flips total, {len(base)} B mark, {T} trials\n")
print("| policy | exact | refused | WRONG |\n|---|---|---|---|")
for k, v in res.items():
    print(f"| {k} | {v.count('exact')} | {v.count('refused')} | {v.count('WRONG')} |")
