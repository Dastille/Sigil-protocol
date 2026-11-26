# Changelog

## Unreleased

The first release will be **v0.9.0**. This tree is not 1.0.

### Security

- Salts, nonces and content keys for new seals, and new identity keys, now come from the
  operating system's secure random number generator through the `getrandom` crate (the
  `getrandom` system call on Linux, `BCryptGenRandom` on Windows, `getentropy` on macOS).
  Earlier builds read `/dev/urandom` and, if it could not be opened or read, silently kept
  all-zero bytes. `/dev/urandom` does not exist on Windows, so an encrypted seal made by a
  Windows build of earlier code had an all-zero content key and gave no protection. No
  Windows build was ever published. Now a failing random source refuses the seal, key or
  log append with a clear error, and nothing is written.
- `scry` warns when a seal (or a large-file pack's first star) has an all-zero salt or
  nonce, the mark of a seal made while the random source was failing. No format change.
- A large-file pack and a plain Tome are written through a hidden part file renamed into
  place at the end, so a seal that fails part way leaves no partial output.
- A padded log refuses an append when the random source fails, instead of padding with
  zeros (zeros would compress and show the entry's size).
- Library: `rain_lane()` returns `Result<u8>` (it fails when the random source fails).

### Version

- The crate and `sigil --version` now report `0.9.0`. The `.sg1` format version is unchanged.

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

### Tomes

- A folder Inscribe lists every path it leaves out of the Tome on stderr: names starting
  with `.` (a dot-folder is not entered), special files, links whose target is missing, and
  folders with nothing stored under them. The summary line counts them and `--json` adds
  `"not_packed": N`. At most 50 paths are printed by name, then a count. A note says how many
  executable files will restore without their executable bit (permissions are not stored).
  What is packed is unchanged, and the exit code stays 0.
- New `seal --fail-on-skip` (folders only): when any path would be left out, list them,
  write nothing and exit 1.
- `scry` and `path` list a member larger than `--chunk` (stored as a large-file pack inside
  the Tome) as `file`, not `nest`. A member is a `nest` when its name ends in `.sg1` or
  `.sgwk`, whatever its size. `path --json` reports `"nest": false` for such members.

### Mount

- `mount` (FUSE and `--export-dir`) reads a large-file member one chunk star at a time
  instead of decoding it whole into memory. This covers a large member of a plain Tome (read
  in place), of a Warded Tome with a large locked body (the body is decrypted a star at a
  time, never whole), a single large-file pack, and a Constellation star. The first read of
  a member checks every star once, as `unseal` does (each star, its facet position, the
  total), holding one star; later reads open only the stars they cover and check each again,
  so a pack changed after it was opened is refused, never served. At most three decoded
  stars are kept. `--export-dir` writes each file through a hidden part file renamed into
  place only after its checks pass.
- Classic members (one AES-GCM message, at most the Tome's `--chunk`) and log segments are
  still decoded whole; at most 256 MiB of them stay cached, oldest dropped first, and the
  member being read is always kept. A single file sealed whole with a large `--chunk` is
  still decoded whole by `mount`.
- Measured peak RSS of `mount --export-dir` with one 1 GiB member at the default `--chunk`
  (before -> after): plain Tome 2.37 GiB -> 43 MiB, Warded Tome 3.04 GiB -> 86 MiB, single
  large-file pack 1.04 GiB -> 43 MiB; every export byte-identical. Plain Tome and single pack
  exports took about the same time (33 s -> 30 s). A large Warded Tome export was slower
  (78 s -> 206 s): each member star is read through the locked body, and is checked when the
  member is opened and again when it is copied.
- Library: `VaultFs::read_range` and `VaultFs::copy_file_to` read part of a file, or copy
  it, without holding the whole file.

### Memory

- Tomes and Warded Tomes no longer load a member or the locked body into memory whole.
  `seal`, `unseal`, `list`, `scry`, `mend`, `status`, `doctor` and the repair assessment read
  large members in place or one chunk star at a time, and copy them 1 MiB at a time. The
  `.sg1` and Tome layouts are unchanged. With a fixed random source, seals of files and
  unencrypted Tomes are byte-identical to the previous build, and mend output is
  byte-identical for all Tomes.
- Measured peak RSS on a Tome holding one 2 GiB file and 20 small files (before -> after):
  plain Tome seal 2.7 GiB -> 32 MiB, scry 2.7 GiB -> 15 MiB, unseal 2.7 GiB -> 39 MiB,
  mend 5.4 GiB -> 42 MiB; Warded Tome seal 5.4 GiB -> 43 MiB, scry 2.7 GiB -> 13 MiB,
  unseal 6.7 GiB -> 66 MiB, mend 8.0 GiB -> 35 MiB. Wall times stayed within about 10%
  (most steps slightly faster). A plain 2 GiB file (large-file pack) was already bounded and
  is unchanged (15-43 MiB).
- `doctor` no longer writes a full mended copy of a large-file pack to the temp folder.
- Inflating a classic seal stops at the length its header states, so a small seal whose
  deflate stream would grow far larger is refused without first using that memory.
- `scrub` skips a large-file pack without reading it; `attest`, attestation checks and
  `--bind` hash files in a stream.
- A classic single seal (a file at or below `--chunk`, or forced with a larger `--chunk`,
  `--mds` or `--pad`) is now sealed, opened, scried and mended a window at a time. The
  `.sg1` format is unchanged: with a fixed random source, seals are byte-identical to the
  previous build, and each build opens the other's seals. The AES-GCM tag is checked over
  the whole ciphertext before anything is decrypted, and every later pass re-checks each
  1 MiB window against that pass, so no byte the tag did not cover is ever decrypted into
  the output. Plain seals sent to stdout are checked in full before the first byte is
  written. Scratch files are owner-only and removed afterwards; the deflate scratch is
  encrypted with a throwaway key.
- Measured peak RSS for one 2 GiB file sealed whole (before -> after): seal 12 GiB ->
  39 MiB, scry 2.7 GiB -> 40 MiB, unseal 15 GiB -> 12 MiB, mend 18 GiB -> 39 MiB; Warded:
  seal 13 GiB -> 39 MiB, scry 2.7 GiB -> 40 MiB, unseal 15 GiB -> 39 MiB, mend 13 GiB ->
  39 MiB. Wall times were within 10% except Warded unseal, about 25% slower (65 s -> 82 s)
  because of the window re-check.
- Still whole-file for a classic seal: the deeper (soft) repair, repair of the framing
  itself (a header recovered from its copies, shifted or extra bytes), version 1 seals,
  `unseal --repair`, opening a `--mds cauchy` seal, and mending several copies together.

### Repair

- `sigil mend` on a Warded Tome now runs the deeper bit-rot repair on its locked body when the
  quick repair fails, as it already did for a single `.sg1` and for the members of a plain Tome.
  Scattered bit flips that touch every part of the body used to leave a Warded Tome
  unrepairable even at one flipped bit in 100,000; with Reflection or Seal, copies with up to
  about one flipped bit in 10,000 are now healed (measured on three test folders). `--hard-only`
  keeps the quick repair only. `scry` assesses the body with the same repair, so it reports
  exit 5 (repairable) instead of 2 for such copies. The format is unchanged.

- A plain Tome's folder list (member count, names and lengths) has no repair data of its own,
  so one damaged byte there could give wrong output that still exited 0: a member restored
  under another name, two members sharing a name (one overwriting the other), or members
  silently dropped by a lowered count. `scry`, `verify`, `unseal` and `mend` now refuse
  such a copy with exit 2 and `folder list damaged: …`, and write nothing. They check each
  name against the path kept in that member's own protected header (its first 16 bytes; for
  a large-file member, its first chunk's name), refuse a name used twice or one that is not
  valid UTF-8, refuse a name out of the order Inscribe has always written names in (sorted,
  folder by folder), and refuse when a complete member follows the last counted one. A length that
  runs past the end while later members are still there is reported as list damage, not as
  "this copy is cut short"; a copy that really is cut short is still reported as cut short.
  Encrypted member headers keep no name, so names in those Tomes are checked for uniqueness,
  order and form only. Limit: a damaged name that keeps its first 16 bytes, stays valid and
  still sorts between its neighbours (for example `.dat` turned into `.dau`) cannot be told
  from the real name without protecting the list itself, which would change the format.
  The format is unchanged.
- `scry` / `verify` no longer report a Tome whose first bytes (`SGDR` and the version) are
  damaged as a healthy or repairable single archive; they exit 2 with `Tome head damaged`.

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
- Stored names are printed with control characters and invisible layout characters escaped
  (for example `\u{1b}`), so a crafted name in a Tome or `.sg1` cannot drive the terminal.
  This covers `scry`, `ls`, `unseal`, `mend` and every error and hint line. Files are still
  restored under their real names.

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
