# Repair scan: `sigil mend --scan` and `--max-secs`

Status: first half of R1 step 2 ("wait screen"), 18 November 2026. Code:
`crate/sigil/src/repair_scan.rs`; CLI wiring in `crate/sigil/src/main.rs` (mend arm).
Tests: `repair_scan::tests` (8) and `crate/sigil/tests/cli_mend_scan.rs` (5).
No file-format change: the scan only reads what `mend` already reads.

## Problem

A person running `sigil mend` cannot tell, before it starts, whether the repair will take
a moment or a long time, or whether it can work at all. Scheduled jobs need a way to skip
a repair that would run for hours. The 11 November 2026 wait-UX notes
(`/workspace/receipts/sigil-repair-wait-ux-20261111.md`, not in this repo) set the order:
scan, estimate, then decide; tell from about 10 seconds; ask only past about 2 minutes;
unattended jobs never ask.

## What the scan does

It grades every shard exactly as `mend` does: CRC-good, present but CRC-failed, or
missing. Large-file packs (SGWK) are scanned one chunk star at a time (one star in memory).

**Damage kind** (a hint for choosing a repair method later; it never accepts a result):

| kind | rule |
|------|------|
| clean | every shard passes its CRC |
| truncated | only missing shards, and they are the last ones |
| one-region | the bad shards are one contiguous run, and either all look wiped or missing, or the run is at least 2 and fewer than all shards |
| scattered | CRC-failed shards that still hold data, none missing or wiped-looking |
| mixed | anything else |

A CRC-failed shard "looks wiped" when it contains a run of 64 or more copies of one byte.
Random or compressed data almost never has one; plain data can, so this is only a hint.

**Repair path**, using the Reed–Solomon limits of the deeper repair (per column: 2·errors +
erasures ≤ n − k):

| path | rule |
|------|------|
| none | nothing damaged |
| quick | at least k shards pass their CRC |
| deeper | missing + wiped + 2·(other damaged) ≤ n − k: every column is in range even if every damaged shard is wrong in the same column |
| deeper-hard | past that worst case: it may still work (scattered flips rarely line up) but can fail |
| not-enough | fewer than k usable shards (wiped-looking counted as gone); Glyph with any damage |

`mend` always makes the final call. "not-enough" is worded "probably too damaged" for
that reason, and `--scan` exits 0 whenever the scan ran (1 if the file could not be
scanned). The tests check that a "not-enough" file is still refused by `mend`, and that a
"deeper-hard" file with one flip per shard is still repaired to the original bytes.

## Time estimate

`est = PAD × Σ over seals of bytes / rate(path)`, with these rates (bytes per second):

| work | rate used | measured (box, 18 Nov 2026, release build, 8 cores) |
|------|-----------|------------------------------------------------------|
| check clean data | 50 MB/s | `verify` of a 4.2 MB seal 0.072 s (58 MB/s); of an 89.5 MB pack 0.47 s (190 MB/s) |
| quick repair | 30 MB/s | 4.2 MB seal, ~1/14 wiped, `--hard-only`: 0.084 s (50 MB/s) |
| deeper repair | 20 MB/s (plus the quick pass) | 4.2 MB seal, bit-error rates 1e-6 to 1e-4: 0.084–0.093 s; 89.5 MB pack at 1e-5: 1.94 s (46 MB/s) |
| deeper-hard | 5 MB/s (plus the quick pass) | 10 MB worst refused case 0.84 s on 16 Nov 2026 (12 MB/s) |

`PAD` = 1.5. Rates are the measurements rounded down, so on this machine the estimate is
high; on slower machines (laptops on battery, phones, network drives) it is **unverified**.
Times are spoken in one coarse unit ("under 10 seconds", "about 3 minutes"), as the
wait-UX notes ask. Measurement script: `/workspace/sigil-1118-scan/rates.py` and
`measure.py` on the box (not in this repo).

## Decisions

- `sigil mend --scan FILE`: print the scan, write nothing, exit 0 (1 if unscannable).
  Refuses several copies. `--json` adds a `scan` object
  (`kind`, `path`, `seals`, `torn`, `clean`, `damaged`, `missing`, `est_secs`).
- Plain `sigil mend` on a single Sigil: scan first; if the estimate is 10 s or more, print
  it and say that nothing is written until the check passes and Ctrl-C stops safely. The
  `--json` result of a single-Sigil mend also carries `scan`.
- `--max-secs SECS` (single Sigil or large-file pack): if the estimate is over SECS, write
  nothing and exit 4 with "repair skipped"; `--json` adds `"skipped":true`. Several copies,
  folder packs and atlas bags are refused with `--max-secs` (exit 1).

## Limitations

- No progress bar, no question before long repairs, no Stop besides Ctrl-C, no live
  re-estimate yet (second half of step 2).
- Large-file packs are scanned only with `--scan` / `--max-secs`; plain `mend` does not
  scan them first (it would read the pack twice). Merging the scan into the repair pass
  with progress is part of the second half.
- A pack whose framing (head or length fields, which are not Reed–Solomon coded) is
  damaged cannot be scanned; plain `mend` still tries its head rebuild.
- Folder packs and atlas bags are not scanned.
- The time model is from one machine.
