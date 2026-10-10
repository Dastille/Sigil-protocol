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

## Later slices (not in format 1 yet)

Real remove + `sigil gc`; `sigil doctor`; human-readable names in `ls` / mount; a
default `cold/` wiring for light-retention prune.
