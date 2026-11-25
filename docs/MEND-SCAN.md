# Repair scan: `sigil mend --scan` and `--max-secs`

Status: R1 step 2 ("wait screen") done: first half 18 November 2026 (this scan), second half
19 November 2026 (progress, ask, Stop; below). Code:
`crate/sigil/src/repair_scan.rs`; CLI wiring in `crate/sigil/src/main.rs` (mend arm).
Tests: `repair_scan::tests` (8) and `crate/sigil/tests/cli_mend_scan.rs` (5).
No file-format change: the scan only reads what `mend` already reads.

## Problem

A person running `sigil mend` cannot tell, before it starts, whether the repair will take
a moment or a long time, or whether it can work at all. Scheduled jobs need a way to skip
a repair that would run for hours. The 11 November 2026 wait-UX notes
(maintainers' notes, not in this repo) set the order:
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

`PAD` = 1.5. Rates are the measurements rounded down, so on the measuring machine the estimate is
high; on slower machines (laptops on battery, phones, network drives) it is **unverified**.
Times are spoken in one coarse unit ("under 10 seconds", "about 3 minutes"), as the
wait-UX notes ask. Measurement scripts: `rates.py` and
`measure.py` (maintainers' tooling, not in this repo).

## Decisions

- `sigil mend --scan FILE`: print the scan, write nothing, exit 0 (1 if unscannable).
  Refuses several copies. `--json` adds a `scan` object
  (`kind`, `path`, `seals`, `torn`, `clean`, `damaged`, `missing`, `est_secs`).
- Plain `sigil mend` on a single Sigil: scan first; if the estimate is 10 s or more, print
  it and say that nothing is written until the check passes and Ctrl-C stops safely. The
  `--json` result of a single-Sigil mend also carries `scan`.
- `--max-secs SECS` (single Sigil or large-file pack): if the estimate is over SECS, write
  nothing and exit 4 with "repair skipped"; `--json` adds `"skipped":true`. Several copies,
  Tomes and atlas bags are refused with `--max-secs` (exit 1).

## Second half (19 November 2026): progress, ask, Stop

Code: `crate/sigil/src/repair_ctl.rs` (stop flag, progress counters, the ask/skip rule,
the question, the progress line); CLI wiring in `main.rs` (`mend_wait_gate`,
`mend_stop_gate`, `RepairWatch`, `install_stop_handler`). Tests: `repair_ctl::tests` (3),
`crate/sigil/tests/cli_mend_wait.rs` (4, two on a pseudo-terminal via util-linux `script`)
and `crate/sigil/tests/lib_repair_stop.rs` (1). No file-format change.

Rule, single Sigil, no `--max-secs` (with `--max-secs` the old rule stays: over SECS → exit 4):

| who is there | estimate | what happens |
|---|---|---|
| terminal (stdin and stderr), not `--json` | ≤ 120 s | just run (scan shown from 10 s) |
| terminal | > 120 s | scan shown, then `Keep going? [y/N]`; only `y`/`yes` starts; anything else, Enter or end of input: exit 4, nothing written |
| nobody (no terminal, or `--json`) | ≤ 900 s | just run, never ask |
| nobody | > 900 s | exit 4 ("repair skipped"), nothing written, `--json` adds `"skipped":true` |
| `--yes` / `-y` | any | run without asking |

The 120 s ask point and the 900 s unattended budget are the wait-UX notes' defaults (§2.1 E
and G; reasoned defaults, not lab results). They can be changed with
`SIGIL_MEND_ASK_SECS` and `SIGIL_MEND_UNATTENDED_SECS` (the "Settings" in §4 of the notes);
a value that is not a whole number is refused (exit 1, nothing written). Scans that say
"no damage" or "probably too damaged" never ask: there is no slow work to start.

Progress: when stderr is a terminal, a thread redraws one line on stderr every second once
the repair has run 5 seconds ("Repairing… 40 seconds so far, about 2 minutes left. Ctrl-C
stops safely."; a large-file pack adds "3 of 40 parts done"). Past the estimate it says
"Taking longer than first thought; still working" instead of a wrong number. The line is
cleared before the result is printed. Not shown when stderr is not a terminal.

Stop: on Unix a SIGINT handler (via `libc`, already in the dependency tree through `fuser`;
no new crate in `Cargo.lock`, `cargo audit` unchanged) sets a flag and prints "Stopping
safely…". The deeper repair checks it before every column it works on (`par_map`), every
ratchet round and the fallback search; the pack repair checks it before every chunk star and
before the rename. After the repair returns, the CLI checks the flag before writing, so a
stop always ends with "repair stopped: … Nothing was written", exit 130, and no output or
`.mend-part` file. A second Ctrl-C quits at once (`_exit(130)`). The handler is installed
only after any question, so Ctrl-C at the question still quits straight away.

## Routing by damage kind (measured 22–23 November 2026, parked)

R1 step (f) asked whether the damage kind should pick the repair. Measured on the
60-case corpus and 1 MiB stars: for truncated, one-region and scattered damage the
current order (quick RS when at least k shards are whole, else column repair, then the
shard-order fallback) is already the routed order; racing two methods on mixed damage
was 24% slower on the corpus and 34–64% slower on 1 MiB, with the same 36 of 60
repaired (a second try with the column repair on all threads was still 3% slower on the
corpus and up to 21% slower on 1 MiB). So the kind is **not** used to choose a method; it stays a hint for the
time estimate and the plain-English scan. Details: docs/SOFT-RS.md, step 3f.

## Limitations

- No live re-estimate; the question comes before the repair starts (the notes ask for it
  after the quick part) and has no "finish tonight" option; the relative "4× a normal read"
  test from the notes is not used (so it asks at least as often as the notes would).
- Ctrl-C does not interrupt the quick repair or the final full check (they are short and
  run to the end; nothing is written afterwards). On Windows there is no handler: Ctrl-C
  ends the process (nothing is written before the check; a `.mend-part` may stay if it
  lands during the final write).
- Large-file packs are scanned only with `--scan` / `--max-secs`; plain `mend` does not
  scan them first (it would read the pack twice). Merging the scan into the repair pass
  is not done yet (the second half added progress and Stop, not this).
- A pack whose head or length framing will not parse cannot be scanned; plain `mend`
  still tries to rebuild the head and, when the facet list can confirm them, the
  length prefixes (decoder-only; the `.sg1` layout is unchanged).
- Tomes and atlas bags are not scanned.
- The time model is from one machine.
