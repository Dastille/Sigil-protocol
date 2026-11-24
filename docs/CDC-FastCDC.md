# FastCDC for Sigil Inscribe (ship plan)

Opt-in content-defined chunking for work packs / constellation stars.
Product: smarter slicing so big files and re-seals after small edits do less re-work.

## Why

Fixed 4 MiB slices shift every boundary after a middle insert or delete. FastCDC
(gear-hash, normalized) keeps unchanged regions on the same cut points, so most
star true-names stay put and only the edited neighborhood re-seals.

## Profiles (no overlap)

| Profile | min | avg | max | Use |
|---------|-----|-----|-----|-----|
| **media** | 1 MiB | 4 MiB | 8 MiB | Movies, dumps, large binaries |
| **dedup** | 256 KiB | 1 MiB | 4 MiB | Mixed / backup-style locality |
| Floor | 64 KiB | — | — | Hard lower bound for any custom size |

Default Inscribe stays **fixed 4 MiB** (unchanged). CDC is opt-in only.

## CLI

```bash
sigil inscribe big.bin -o big.sgwk --cdc media
sigil inscribe tree.tar -o tree.sgwk --cdc dedup
# omit --cdc → fixed 4 MiB chunks as today
```

Each CDC chunk is sealed as one `.sg1` star inside the SGWK work pack (same
machinery as fixed chunks). De-scribe / scry / overture reuse existing paths;
facet offsets use each star’s true payload length (variable).

## Non-goals (this ship)

- No overlapping chunks
- No change to Keystone / Ember / Ward / RS layout
- No soft-RS (see `docs/SOFT-RS.md`)
- No mandatory CDC — fixed chunking remains the default

## Implementation

- `crate/sigil/src/cdc.rs` — gear-hash FastCDC, profiles, range / owned APIs
- `work.rs` — `inscribe_path` / stars-dir accept optional CDC profile
- Tests: determinism, media max ≤ 8 MiB, roundtrip, edit-locality

## Citations

- Xia et al., FastCDC, USENIX ATC 2016
- Xia et al., FastCDC improvements, 2020
