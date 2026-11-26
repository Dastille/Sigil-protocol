# Changelog

## Unreleased

### Naming

- User-facing text (CLI `--help`, messages, README, docs, wiki, and the desktop lab) uses the
  approved names: **Sigil Archive**, **Tome**, **Ward**, **Channel** / **mana**, **Inscribe**,
  **Mend**, **Scry**, **Frost Rune**. **Fire Rune** is reserved (not built). On-disk names
  (`CONTAINER`, `KIT`, `name.sigil/`) and machine-readable JSON keys (`kind`, `layout`, `cmd`)
  are unchanged. Hidden aliases `kit` and `cold-usb` still run `sigil frost`.
- The `name.sigil/` folder is called a **Codex** in user-facing text. A Codex holds a Vault, a
  Constellation, or a signed log. It is not a Sigil Archive (a `.sg1` file) and not a Tome
  (a `.sg1` of a whole folder). The on-disk `CONTAINER` manifest and the JSON value
  `"layout":"container"` are unchanged.

### Repair

- `mend` and `unseal` rebuild damaged length prefixes in a large-file pack
  (the 8-byte length in front of each chunk star) when every star confirms
  against the facet list and any intact pack-head guard. Decoder-only: the
  `.sg1` layout is unchanged. A successful mend writes the same prefixes a
  clean pack already had.
- A rebuilt length is accepted only after that confirmation. Swapped stars, a
  forged length that points at a different valid-looking star, a truncated pack,
  and a wrong passphrase on a Warded large-file pack are still refused.
- When the prefixes are damaged but the facet list is intact, the refusal no
  longer blames the facet list. The facet list itself is still not
  Reed–Solomon coded; if it is damaged too, `mend` still refuses.
- Measured (same damage model as the 25 November 2026 GPU park, three seeds per
  case): 256 MiB Seal packs with 1–4% scattered bad sectors, previously often
  refused at once, were repaired in 12 of 12 sector-damage runs (about 12–20 s,
  about 105 MiB peak RSS). No run wrote a wrong file. Scans of untrusted input
  are capped (24 MiB per star, 64 MiB per rebuild, 3 seconds of CPU time
  excluding disk I/O wait, 64 magic hits, a reused 1 MiB window, Ctrl-C checks).
- `sigil mend` prints `length framing rebuilt` from one shared summary helper
  when that is what it did.
- Whole-file pack-head guard (`SGHG`) recovery runs in one linear pass bounded
  by file size (no 256 MiB scan cutoff), with a size-scaled `SGHG` hit cap
  (`max(size / 1024, 64)`), `(head, placed)` candidate deduplication, at most
  8 distinct candidate heads, a shared 3-second CPU-only budget (excluding disk
  I/O wait), Ctrl-C checks, and a reused 1 MiB read window, running streaming
  before `fs::read` in `mend`, `unseal`, `scry`, and recovery diagnostics.
  - Measured on a 2.52 GB (`450`-star) guarded pack with the head and first
    272.2 MiB of guards wiped: `mend` recovers all 50 missing guards and the
    head in 15.05 s at 13.2 MiB RSS, and `unseal` recovers byte-exact in
    44.59 s at 39.0 MiB RSS (exit 0).
  - Measured on a throttled 30 MB/s source: both guard scanning past 3 s wall
    clock and framing rebuild succeed without false refusal.
  - Measured on a 2.00 GiB crafted `SGHG`-flooded pack: `mend` dropped from
    194.5 s / 2.0 GiB RSS to 0.069 s / 12.0 MiB RSS (exit 2 with hints), and
    `unseal` dropped from 211.0 s / 2.0 GiB RSS (exit 1) to 0.199 s / 12.0 MiB
    RSS (exit 2 with hints).
- Additional bounds on untrusted input: `header::locate_from_ember` caps
  raw `SGEM` scans (4,096), valid Ember headers (512), and deduplicated prefix
  probes (1,024), cutting a 32 MiB dense-`SGEM` worst case from ~5 min
  (9.83 s per 1 MiB) to 0.03 s while preserving damaged-seal recovery;
  `work::index_pack` stops immediately on zero/short star lengths when `stars`
  is huge; `fountain::answer_with` enforces `ESI_MISS_LIMIT`; and `show::handle`
  caps HTTP request headers at 16 KiB and 64 lines (431 on excess).

### Recovery guidance

- When an archive will not open or cannot be repaired, `scry`, `verify`, `unseal`, `open`,
  `mend`, `gather` and `frost mend` print a short **What you can try:** list. Every line is
  a command that works for that kind of archive (placeholders are written `<like-this>`);
  with `--json` the same lines are in an optional `hints` array. Existing JSON fields are
  unchanged.
- `scry` / `verify` no longer call bit rot that `sigil mend` repairs `NOT recoverable`. When
  too few pieces are intact, they run the repair `sigil mend` would run, in memory: nothing
  is written, at most 2 CPU threads, seals over 32 MiB are skipped, and the check stops after
  3 seconds per command (`SIGIL_SCRY_PROBE_SECS=N`; `0` turns it off). Measured worst case
  on a crafted 32 MiB seal: 3.2 s, 290 MiB (it was 24 s, 764 MiB, 20 threads).
- Wording uses the approved names: Sigil Archive, Tome, Warded Tome, Channel / mana,
  Frost Rune. A wrong key now says `Wrong passphrase or key — this Sigil Archive is Warded
  (…)` instead of `could not unwrap CEK — need matching --identity or passphrase`.
- A Warded Tome never shows its member names in any of this guidance.

### Breaking changes

Scripts that branch on exit codes or match error text should check these (measured
against the previous release build):

| Command | Case | Before | Now |
|---|---|---:|---:|
| `scry`, `verify` | too few intact pieces, but `sigil mend` repairs it | 2 | **5** |
| `scry`, `verify` | too few intact pieces, repair not checked (time limit, `SIGIL_SCRY_PROBE_SECS=0`, over 32 MiB) | 2 | **6** |
| `unseal`, `open` | damaged, `sigil mend` repairs it | 1 | **5** |
| `unseal`, `open` | damaged, repair not checked | 1 | **6** |
| `unseal`, `open` | damaged beyond repair, or a cut-off Tome | 1 | **2** |
| `scry`, `verify` | a cut-off Tome | 1 | **2** |
| `frost mend` | not enough Frost Rune drives / pieces | 1 | **2** |
| `gather` | not enough `.sgp` pieces or Channel mana (without `--partial`) | 1 | **2** |

- New exit code **6** (damaged; whether `sigil mend` can repair it was not found out).
  Exit **5** is given only after the repair was checked in memory.
- `SIGIL_SCRY_PROBE_SECS` must be a whole number of seconds; anything else is an error
  (exit 1), never a silent default.
- Placeholders in the printed next steps are now in angle brackets, e.g.
  `sigil mend photo.sg1 <other-copy.sg1>` (was `other-copy.sg1`).
