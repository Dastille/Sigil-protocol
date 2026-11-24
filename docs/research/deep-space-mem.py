#!/usr/bin/env python3
"""Peak memory and time of seal / unseal / mend / mend --soft for one file size.

Usage: python3 docs/research/deep-space-mem.py path/to/sigil [size_MiB]
Each command runs in its own child process; peak RSS is that child's
ru_maxrss (Linux: KiB). Random input, so deflate does not shrink it.
For --soft the copy has 1 flipped bit per 64 KiB (scattered).
"""
import os, random, resource, subprocess, sys, tempfile, time

S = os.path.abspath(sys.argv[1])
MB = int(sys.argv[2]) if len(sys.argv) > 2 else 64
d = tempfile.mkdtemp(prefix="sigil-mem-")
open(f"{d}/in.bin", "wb").write(random.Random(7).randbytes(MB << 20))


# The measuring parent must be small: on Linux a child's ru_maxrss keeps the
# high-water mark of the process image it exec'd from. So a fresh, tiny Python
# helper forks and execs sigil, and reports that child's peak RSS (floor ~10 MiB).
HELPER = """
import os, sys, time
t = time.perf_counter()
pid = os.fork()
if pid == 0:
    fd = os.open(os.devnull, os.O_WRONLY)
    os.dup2(fd, 1); os.dup2(fd, 2)
    os.execv(sys.argv[1], sys.argv[1:])
_, st, ru = os.wait4(pid, 0)
print(os.waitstatus_to_exitcode(st), time.perf_counter() - t, ru.ru_maxrss)
"""


def run(args):
    out = subprocess.run([sys.executable, "-c", HELPER, S, *args], capture_output=True, text=True)
    rc, secs, rss = out.stdout.split()
    return int(rc), float(secs), int(rss)


print(f"| step ({MB} MiB random input) | exit | seconds | peak RSS MiB |")
print("|---|---|---|---|")
for label, args in [
    ("seal (reflection)", ["seal", "-o", f"{d}/a.sg1", f"{d}/in.bin"]),
    ("unseal", ["unseal", "-o", f"{d}/b.bin", f"{d}/a.sg1"]),
    ("mend (healthy input)", ["mend", "-o", f"{d}/m.sg1", f"{d}/a.sg1"]),
]:
    rc, s, rss = run(args)
    print(f"| {label} | {rc} | {s:.2f} | {rss / 1024:.0f} |", flush=True)
b = bytearray(open(f"{d}/a.sg1", "rb").read())
r = random.Random(8)
for _ in range(len(b) // 65536):
    p = r.randrange(len(b) * 8)
    b[p // 8] ^= 1 << (p % 8)
open(f"{d}/t.sg1", "wb").write(b)
rc, s, rss = run(["mend", "--soft", "-o", f"{d}/s.sg1", f"{d}/t.sg1"])
print(f"| mend --soft (1 bit flip / 64 KiB) | {rc} | {s:.2f} | {rss / 1024:.0f} |")
rc, s, rss = run(["unseal", "-o", f"{d}/c.bin", f"{d}/s.sg1"])
ok = rc == 0 and subprocess.run(["cmp", "-s", f"{d}/in.bin", f"{d}/c.bin"]).returncode == 0
print(f"| unseal of mended copy | {rc} | {s:.2f} | {rss / 1024:.0f} |")
print(f"\nexact after mend --soft: {ok}")
subprocess.run(["rm", "-rf", d])
