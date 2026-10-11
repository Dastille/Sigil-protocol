# Tidy container (`name.sigil/`)

Status: container format **1**, shipped. Approved 2026-10-10 as the "tidy container" track,
ahead of the segment-log mode.

Goal: after years of use a folder holds **one `name.sigil/` per thing** — not a pile of
loose `.sg1` stars, `.sgv/` sidecars and orphans. This is purely a *folder* layout:
the `.sg1` byte layout is unchanged, plain `.sg1` marks and every old layout still open
forever, and Vandermonde stays the default (Cauchy opt-in) exactly as before.

## Layout

```text
notes.txt                      the live file (vault) stays where it is
notes.txt.sigil/               vault container
  CONTAINER                    manifest (below)
  CHART                        vault chart, same format as before (sigil-vault=1)
  versions/v1.sg1 v2.sg1 …     version stack (byte-identical seals)
  cold/                        reserved: suggested `--cold` target for light retention

Sky.sigil/                     constellation container
  CONTAINER
  Sky.sg1                      the card (index / list), same format as before
  stars/ab/ab12…ef.sg1         stars, sharded by fingerprint (SHA-256 of the plain file)
  stars/by-name/<old>.sg1      only for migrated stars with no readable fingerprint
  Sky.sga                      optional atlas (bag)
```

### `CONTAINER` manifest

Plain `key=value` lines, UTF-8:

```text
sigil-container=1
kind=vault            # or constellation
name=notes.txt        # human name of the thing
```

* First key `sigil-container=N` is required. `N` greater than this sigil understands →
  clear refusal ("upgrade sigil"); never a silent misread.
* Unknown keys are tolerated and preserved on rewrite (additive evolution).
* `#` comments and blank lines are ignored.

### Fingerprints

The star fingerprint is the SHA-256 true-name of the plain bytes (the same digest the
card lists and the star header carries). `stars/<first 2 hex>/<64 hex>.sg1`. The file
name is only a hint: readers still read each star's header digest, so a renamed star
is still found; work packs (large chunked stars) are found by their sharded path.

## Mapping old layouts

| Old                                     | Container                         |
|-----------------------------------------|-----------------------------------|
| `<live>.sgv/CHART`                      | `<live>.sigil/CHART` (verbatim)   |
| `<live>.sgv/vN.sg1`                     | `<live>.sigil/versions/vN.sg1`    |
| other files in `.sgv/` (e.g. leftovers) | same relative path in container   |
| `Sky/<title>.sg1` (card)                | `Sky.sigil/<title>.sg1`           |
| `Sky/<name>.sg1` flat stars             | `Sky.sigil/stars/ab/<fp>.sg1`     |
| `Sky/*.sga` atlas                       | `Sky.sigil/*.sga`                 |
| non-sigil files / sub-folders in `Sky/` | left alone (reported)             |

The CHART keeps storing bare seal names (`v3.sg1`); the `versions/` folder is implied by
the `.sigil` container, so the CHART text is identical in both layouts.

## Defaults (new writes)

* `sigil vault track notes.txt` → `notes.txt.sigil/`. A path that already has an old
  `notes.txt.sgv/` keeps committing there until you `sigil tidy` it.
* `sigil constellation add Sky …` → `Sky.sigil/` when neither `Sky/` nor `Sky.sigil/`
  exists (or `Sky/` is empty). An existing non-empty flat folder stays flat.
* Reading: `Sky` falls back to `Sky.sigil/` when `Sky` does not exist; `notes.txt`
  finds `notes.txt.sigil/` first, then `notes.txt.sgv/`.
* Atlas bags built from a container carry stars under their old flat names, so any
  sigil — old or new — opens them.

## `sigil tidy PATH`

```sh
sigil tidy notes.txt --dry-run      # show the plan, change nothing
sigil tidy notes.txt                # or notes.txt.sgv
sigil tidy Sky [--pass … | --identity key.sgk]
```

1. Plan every file (above table). Refuse if the target `name.sigil` already exists.
2. Copy into a hidden staging folder `.tidy-name.sigil/` beside it (fsync each file).
3. Verify: SHA-256 of every copy equals the original. Vaults: the CHART loads and every
   version seal is present. Constellations: when the card opens (clear, or with the
   given `--pass` / `--identity`), the container must not miss any star the old folder
   had ("list checked"). A locked card without keys gets byte-level verification only —
   still safe because nothing is re-encoded.
4. Atomic rename staging → `name.sigil/`. Only then remove the moved old files (and the
   old folder if it is empty).

Any failure before step 4 deletes the staging folder and leaves the original untouched.
A crash mid-copy leaves only a `.tidy-*` folder that no reader looks at; the next `tidy`
clears it and starts over. After the rename, readers prefer the container, so a crash
during cleanup is harmless (leftover old files are just redundant). `.sg1` bytes are
never rewritten: encrypt-to and passphrase stars / cards migrate without any key.

## Real remove

```sh
sigil constellation remove Sky docs/a.txt [more names…]   # alias: rm
sigil constellation remove Sky docs/ --dry-run            # trailing / = everything under docs/
sigil vault remove notes.txt --version 2 [--cold DIR | --cold-here] [--force-drop] [--dry-run]
sigil vault prune  notes.txt --keep 3 --cold-here         # cold/ inside the container
```

* **Constellation remove** takes names off the list. The card is rewritten atomically
  *first*; star files go after, so a crash leaves at worst an orphan star (`sigil gc`
  reclaims it), never a list entry without its star. A star another name still uses (same
  bytes) is kept. `--keep-stars` leaves star files for `gc`. An encrypt-to card needs the
  same `--to` (and `--identity` to open it) as `add`; a warded card needs `--pass`.
  Removing the last name is refused (delete the folder instead).
* **Vault remove** drops one version. The **tip** and the only version can never be removed.
  Retention rules from [VAULT-RETENTION.md](VAULT-RETENTION.md) hold: under **light**
  retention the seal must go to a cold kit (`--cold DIR` or `--cold-here`) or be discarded on
  purpose (`--force-drop`); under **full** an explicit remove is allowed. The CHART is
  rewritten before the seal file is deleted (same order now used by `prune`).
* `--cold-here` = `<name>.sigil/cold/` (containers only). Cold kits land in `cold/vN/` exactly
  as with an external `--cold DIR`.

## `sigil gc PATH`

```sh
sigil gc notes.txt                  # report only (the default)
sigil gc Sky --dry-run              # same, spelled out
sigil gc Sky.sigil --apply          # actually delete
sigil gc Sky --pass …|--identity key.sgk   # card must be readable (see below)
```

**Report-only unless `--apply`.** The report lists each orphan with its size, what was kept,
what was left alone, and ends with "dry run: nothing was changed" or "reclaimed N …".

Reclaims (containers):

| What                         | Rule |
|------------------------------|------|
| orphan star                  | `stars/…` file whose fingerprint no list entry uses |
| duplicate star               | referenced star at a non-canonical path (e.g. `stars/by-name/`) **and** a byte-identical sharded copy exists |
| orphan version               | `versions/vN.sg1` the CHART does not list (e.g. crashed commit) |
| temp file                    | `*.part` older than `--temp-age` seconds (default 3600) |
| stale staging                | sibling `.tidy-<name>.sigil/` from an interrupted tidy, same age rule |
| empty shard folder           | `stars/ab/` left with nothing in it |

Never touched: anything the card / CHART references, **`cold/`** (cold kits are history you
chose to keep), the atlas `.sga`, `CONTAINER`, and any file gc does not recognise (listed as
"left alone"). A constellation card that cannot be opened (no `--pass` / `--identity`) stops
gc — it will not guess what is referenced. Old flat constellation folders are reported but
never reclaimed (run `sigil tidy` first); old `.sgv/` vaults only lose unlisted `vN.sg1` and
old temp files.

## `sigil doctor PATH`

```sh
sigil doctor notes.txt              # vault (live path, .sigil or .sgv) or constellation
sigil doctor Sky --pass … | --identity key.sgk   # needed to open a warded / encrypt-to card
sigil doctor Sky --json             # machine-readable report on stdout
sigil doctor Sky --quick            # skip bit-level verification (existence / structure only)
sigil doctor notes.txt --fix        # safe fixes only (below)
```

**Read-only** unless `--fix`. Prints one line per finding (`info` / `WARN` / `ERROR`, a stable
code, the subject, and a hint of what to do), then `result: healthy | warnings | PROBLEMS`.

**Exit codes:** `0` healthy (notes allowed) · `1` warnings only · `2` problems · `3` could not
check (not a vault / constellation). Handy for a cron job.

| Code | Sev. | Meaning |
|------|------|---------|
| `manifest`, `manifest-kind` | ERROR | `CONTAINER` unreadable, newer than this sigil ("upgrade sigil"), or wrong kind |
| `old-layout` | WARN | `.sgv/` or flat folder; `sigil tidy` (or `--fix`) |
| `chart`, `tip-missing`, `card-missing` | ERROR | the index itself is unreadable |
| `seal-missing`, `star-missing` | ERROR | CHART / card lists a member whose file is gone |
| `bit-rot` | WARN | damage within the repair budget (incl. rotted *redundant* shard copies while the data is still intact); hint: `sigil mend` |
| `bit-rot-unrecoverable` | ERROR | not enough intact shards; restore from another copy |
| `chart-digest` | WARN | a single-file seal's true-name differs from its CHART entry |
| `orphan-star`, `orphan-version`, `duplicate-star`, `temp-file`, `stale-staging` | WARN | what `sigil gc` would reclaim |
| `card-locked` | WARN | card needs `--pass` / `--identity`; list-based checks skipped (bit rot on stars is still checked) |
| `cold-broken` | ERROR | cold kit cannot be rebuilt, or its seal is beyond repair / empty |
| `cold-degraded` | WARN | cold kit lost some `usb-*` folders (still mendable) or holds a repairable seal |
| `cold-missing` | WARN / info | light retention: a departed version has no kit in `cold/`. Only a warning when `cold/` is in use; otherwise a note, since an external `--cold DIR` cannot be seen |
| `cold-stale` | info | `cold/vN/` for a version that is still hot (redundant copy; delete by hand if unwanted) |
| `live-changed`, `live-missing` | info | vault drift notes |

Bit rot is checked with the same ECC machinery as `sigil verify` / `sigil mend` — single marks,
large-file work packs, and folder (SGDR) packs member by member — and nothing is decrypted, so
warded and encrypt-to data checks without keys.

**`--fix` is deliberately narrow:** it runs `sigil tidy` on an old layout (copy → verify →
atomic rename) and `sigil gc --apply` (orphans, duplicates, abandoned temp files). It never
touches bit rot, missing members or cold kits — those need a human (`sigil mend`, a backup, a
decision). The report is recomputed after the fixes and lists them as `fixed:` lines.

## Names, not hashes (`ls`, `mount`)

On disk a star is `stars/ab/<sha256>.sg1` and a version is `versions/vN.sg1`; that layout is
unchanged. What *you* see goes by the names in the card / CHART:

```sh
sigil ls Sky                    # every list name, size, short fingerprint (MISSING star flagged)
sigil ls Sky docs/              # only names under docs/
sigil ls Sky docs/a.txt         # walk into that member (nest / breadcrumb), trail starts at docs/a.txt
sigil ls notes.txt.sigil        # versions as  notes.txt@v1  notes.txt@v2 (tip) …
sigil ls notes.txt.sigil v2     # walk into a version (v2, @2, 2 or notes.txt@v2)
sigil ls Sky.sigil/stars/ab/ab12….sg1   # raw path: the breadcrumb says  docs/a.txt, not the hash
sigil mount Sky mnt             # FUSE (read-only): the tree is the list names; stars decode on read
sigil mount Sky mnt --export-dir out  [--pass … | --identity key.sgk]
```

* `ls` / `mount` accept the short name (`Sky`), the container (`Sky.sigil`), an old flat folder,
  and for vaults the container, `.sgv`, or the live path once the live file is gone. A live file
  that still exists keeps its old `ls` meaning (it walks the file itself).
* A warded / encrypt-to card needs `--pass` / `--identity` to show names; without the key the
  breadcrumb falls back to the file name and listing says so.
* Constellation mount is read-only (`--writable` is refused — a constellation is a list of separate
  stars; use `constellation add` / `remove`). Vault mounts already carry the payload name.
* Nothing is written into the container by `ls` or `mount` (the tests compare fingerprints).

## Segment logs (`kind=log`)

A third container kind: `events.sigil/` with `CONTAINER` (`kind=log`, `log=1`, `log-id=…`),
`INDEX`, `HEAD` and `segments/NNNN/<seq>.sg1`. Same container format 1 (extra manifest keys only).
`sigil gc` and `sigil doctor` understand it: gc removes only unindexed leftovers of a crashed
append and temp files, never a segment the INDEX lists. Full design in
[SEGMENT-LOG.md](SEGMENT-LOG.md).

## Status

Tidy-container track complete: container format 1, tidy, real remove, gc, doctor, names.
Segment-log mode: slice 1 shipped (see SEGMENT-LOG.md). A later container-format bump (if ever needed) is
handled by `sigil tidy` migrating forward; format 1 readers refuse newer manifests clearly.
