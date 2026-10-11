# Vault retention (full vs light)

A **vault** tracks one live file (or one folder — see [VAULT-MOUNT-NEST.md](VAULT-MOUNT-NEST.md#folder-vaults--sgdr-dirty-re-seal)) with a sidecar chart dir `<live>.sgv/`. Inside: a `CHART` index and immutable version seals `v1.sg1`, `v2.sg1`, …. New commit = new seal; tip moves. History inside one seal is never rewritten.

Think Bitcoin: **full** node vs **light/pruned** node.

| Policy | Hot chart | Older versions |
|--------|-----------|----------------|
| **full** (default) | Keep every `vN.sg1` | Stay in `.sgv` forever |
| **light keep=N** | Newest N only | Must go to a **cold kit** (`--cold DIR`) before leaving the chart — or `--force-drop` to discard |

## Everyday commands

```
# Start tracking (creates notes.txt.sgv/ with v1; retention=full)
./sigil vault track ./notes.txt
# optional: --mode seal  --pass house  --to alice.pub

./sigil vault status ./notes.txt
# drift: match | changed | missing-seal | missing-live | missing-vault

# Edit the live file, then seal a new version (tip moves)
./sigil vault commit ./notes.txt

# List the version stack
./sigil vault versions ./notes.txt

# Restore tip (or an older hot version) over the live path
./sigil vault restore ./notes.txt
./sigil vault restore ./notes.txt --version 2
# encrypt-to: --identity alice.sgk
```

Dirty write path (export tree → new version): see [VAULT-MOUNT-NEST.md](VAULT-MOUNT-NEST.md) and the Mount section in `crate/sigil/README.md` (`mount … --writable` then `vault commit --from-export`).

## Retention policy

```
# Show current policy (default full when CHART has no retention= line)
./sigil vault retention ./notes.txt

# Full node — keep all seals in the chart
./sigil vault retention ./notes.txt --full

# Light / pruned — keep only newest 3 hot
./sigil vault retention ./notes.txt --light --keep 3
```

Chart fields (backward compatible): `retention=full` or `retention=light` plus `keep=N` (N≥1). Unknown keys are tolerated.

## Prune + cold kit

```
# Full retention: explicit prune may drop without cold (legacy). Prefer --cold anyway.
./sigil vault prune ./notes.txt --keep 5 --cold ./vault-cold/

# Light retention: --cold is required when seals would leave the chart
./sigil vault prune ./notes.txt --keep 3 --cold ./vault-cold/
# escape hatch (discards history):
./sigil vault prune ./notes.txt --keep 3 --force-drop
```

`--cold-here` is shorthand for the container's own `<name>.sigil/cold/` (tidy containers only; see [CONTAINER.md](CONTAINER.md)). To drop one specific old version rather than the oldest N: `sigil vault remove ./notes.txt --version 2` (never the tip; light retention needs `--cold`/`--cold-here` or `--force-drop`). `sigil gc` never touches cold kits.

Each pruned seal lands under `DIR/vN/`:

- **Seal** (and Reflection when the drive budget fits): `sigil kit place` layout (`usb-*` + `KIT`) so one lost USB is still mendable.
- **Glyph** (or kit place rejected): plain `vN.sg1` copy plus an `ARCHIVE` note — still better than a silent delete.
- **Folder vault** versions (SGDR packs): always the plain `vN.sg1` copy + `ARCHIVE` (kit place is single-star only).

After a successful (non-skipped) **commit**, light policy auto-prunes to `keep`. Explicit `--keep` on commit overrides for that commit. Pass `--cold` (or `--force-drop`) the same way:

```
./sigil vault commit ./notes.txt --cold ./vault-cold/
./sigil vault commit ./notes.txt --keep 2 --cold ./vault-cold/
```

## Restore after prune

Only versions still listed in `CHART` (hot set) restore via `vault restore`. Cold kit folders are ordinary kits / archives — use `sigil kit mend` (or copy the plain `.sg1` back) if you need an older seal again; re-track / re-commit is a separate story.

Passkeys and PGP import live in key files (see PASSKEY.md, PGP-IMPORT.md), not in retention.
