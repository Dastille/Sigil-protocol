# Changelog

## Unreleased

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
