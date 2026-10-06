# Vault + mount + nest (composed model)

How the **version tip**, **read/edit views**, and **nested seals** fit together. Retention policy (full vs light, cold kit) lives in [VAULT-RETENTION.md](VAULT-RETENTION.md) — this page does not repeat that deep-dive.

Seals stay **immutable**. Edits never rewrite an existing `vN.sg1` or a bare mark in place. A new tip is always a new seal.

## Pieces

| Piece | What it is | Durable store |
|-------|------------|---------------|
| **Vault** | Live file + sidecar chart `<live>.sgv/` (`CHART` + `v1.sg1`, `v2.sg1`, …) | Version stack; tip moves on commit |
| **Mount** | Apps see normal paths over a tip / bare `.sg1` / SGDR pack | Seal untouched; cleartext in RAM (FUSE) or an export tree |
| **Path / nest** | Breadcrumb walk into nested `.sg1` layers inside a pack or mark | Outer mark unchanged; optional extract to a temp path |

`vault track` takes a **regular file** (single-file vault) or a **directory** (folder vault: each `vN.sg1` is an ordinary SGDR folder pack). Bare SGDR packs outside a vault stay mountable and walkable as plain `.sg1` marks.

## When to use which

| Goal | Use |
|------|-----|
| Keep history of one live file | `vault track` → edit live → `vault commit` |
| Browse tip / pack like a filesystem (read-only) | `mount` FUSE, or `mount … --export-dir` |
| Edit cleartext, then re-seal a **new** vault tip | `mount … --vault --export-dir DIR --writable` → edit → `vault commit --from-export DIR` |
| Peek / extract a nested mark without unpacking the whole store | `sigil path` / `path --into … -o …` |
| Restore an older hot version over the live path | `vault restore` (see retention doc for prune / cold) |

Quick rule: **vault** owns versions; **mount** owns the OS view; **path** owns nest breadcrumbs. Combine them — do not fork the `.sg1` layout.

## Immutable seals + version stacks

```
./sigil vault track ./notes.txt
# → notes.txt.sgv/CHART  +  v1.sg1  (tip=1)

# edit notes.txt …
./sigil vault commit ./notes.txt
# → v2.sg1; tip moves; v1 untouched

./sigil vault versions ./notes.txt
./sigil vault status ./notes.txt
# drift: match | changed | missing-seal | missing-live | missing-vault
```

Optional on track/commit: `--mode seal`, `--pass …`, `--to alice.pub`. Encrypt-to and passphrase Ward are additive (see below). Light retention / prune / cold: [VAULT-RETENTION.md](VAULT-RETENTION.md).

## Mount: FUSE vs export-dir vs writable dirty

FUSE is read-only. Writable cleartext requires `--export-dir --writable` (writes a `.sigil-dirty` sidecar; never stores passphrases). Re-seal only through `vault commit --from-export`.

```
# FUSE read-only (Linux/Parrot: /dev/fuse + fusermount3)
mkdir -p ./view
./sigil mount tree.sg1 ./view
# vault tip:
./sigil mount ./notes.txt ./view --vault
ls ./view
./sigil umount ./view

# No FUSE: materialize a read-only tree (seal still intact)
mkdir -p /tmp/sigil-view
./sigil mount tree.sg1 ./view --export-dir /tmp/sigil-view

# Dirty write path (vault-tracked single-file live)
./sigil vault track ./notes.txt
mkdir -p /tmp/sigil-dirty
./sigil mount ./notes.txt ./view --vault --export-dir /tmp/sigil-dirty --writable
# edit under /tmp/sigil-dirty …
./sigil vault commit --from-export /tmp/sigil-dirty
# optional: --mode seal  --pass house  --to alice.pub  --force
# light retention: --keep N  --cold DIR  (same hooks as ordinary commit)
```

`--writable` without `--export-dir` is refused (FUSE stays read-only). Export without `--writable` is a read-only tree (no `.sigil-dirty`, no commit-from-export).

### Folder vaults + SGDR dirty re-seal

```
./sigil vault track ./photos            # photos.sgv/CHART (kind=folder) + v1.sg1 (SGDR)
./sigil mount ./photos ./view --vault --export-dir /tmp/photos-dirty --writable
# edit / add / delete files under /tmp/photos-dirty …
./sigil vault commit --from-export /tmp/photos-dirty
# → v2.sg1 (new SGDR pack); tip moves; v1 untouched
./sigil vault versions ./photos         # … kind=folder
./sigil vault restore ./photos --version 1
# options as single-file: --mode seal  --pass house  --ward photos/cat.jpg=room  --to alice.pub
#                         --keep N  --cold DIR  --force-drop  (restore: --identity, --force)
```

**Tip model.** The chart's tip seal (an SGDR `vN.sg1`) is the durable source of truth; the live directory and any `--writable` export tree are working copies. That is the same rule as single-file vaults (commit reads a working copy, restore writes one), so no second "live dir is the truth" model exists.

- **Version digest** = tree true-name: SHA-256 over `sigil-tree=1` + sorted `rel\0size\0sha256` lines (dotfiles skipped — the same set folder Inscribe packs). It lives only in `CHART`; the SGDR layout is unchanged, so every folder version opens with plain `de-scribe` / `mount` / `path`.
- **Chart** gains one additive line, `kind=folder`. Single-file charts are written byte-for-byte as before; a missing `kind=` means single.
- `vault commit ./photos` seals the live dir; `--from-export DIR` seals the export tree (the `.sigil-dirty` sidecar is ignored). Unchanged tree → skipped unless `--force`.
- After a from-export commit the live dir is **synced** (adds / edits / deletes) only if it was clean (matched a hot version) or missing. If it had its own uncommitted edits it is left untouched and commit prints a `note:`; use `vault restore --force` to take the tip.
- `vault restore` mirrors a version into the live dir (unpacks to a staging dir, verifies the tree true-name, then syncs). It refuses to drop edits that match no hot version unless `--force`. Dotfiles in the live dir are never touched.
- Secrets are not remembered: pass the same `--pass` / `--ward` / `--to` on commit as on track (the sidecar never stores them). Mount the export with `--identity` / `--pass` / `--ward` to read protected entries.
- Light retention archives pruned folder versions as a plain `vN.sg1` copy + `ARCHIVE` note (kit place is single-star only).
- A bare SGDR (not vault-tracked) `--writable` export cannot `--from-export`; `vault track` the folder, or pack the edited tree with `sigil inscribe EXPORT -o new.sg1`.

## Nested `.sg1` / SGDR: path vs mount

An SGDR pack is one `.sg1` whose payload is a directory of per-file stars. A star may itself be a nested seal (name ends in `.sg1`, or payload peeks as a mark).

**Mount** flattens one layer for apps:

- Directory entries appear as normal paths.
- A nested `.sg1` entry appears as a **file** whose bytes are the unsealed payload of that star (often still an inner `.sg1`). Mount does not auto-descend further nest layers into a second virtual tree.
- Further nest-walk is optional — use `sigil path`.

**Path** walks breadcrumbs without rewriting the outer mark:

```
# List outer pack (aliases: walk, ls)
./sigil path tree.sg1

# Descend into a nested entry (repeatable --into, or positional segments)
./sigil path tree.sg1 --into photos --into secret.sg1
./sigil path tree.sg1 photos secret.sg1

# Single-file nest: unwrap one layer with "."
./sigil path nested-payload.sg1 --into .

# Extract current view to a path (temp-friendly; outer .sg1 unchanged)
./sigil path tree.sg1 --into photos --into cat.jpg -o /tmp/cat.jpg
./sigil path tree.sg1 --into inner.sg1 -o /tmp/inner.sg1

# Encrypt-to / Ward
./sigil path secret.sg1 --identity alice.sgk --into .
./sigil path tree.sg1 --pass house --ward photos/secret.jpg=room --into photos
```

Hard nest depth cap is 32 (`--depth` may lower it). Cycles are refused. Work packs are not nested folder seals — De-scribe the work pack instead of path-walking it as SGDR.

What is **not** rewritten: the durable outer `.sg1`, vault tip seals, or chart history. Path extract and mount export only write cleartext (or nested mark bytes) to the destination you named.

## Encrypt-to through vault, mount, path, open

`--to` / `--identity` (SGTO recipient envelopes) and passphrase Ward (`--pass` / `--talisman` / `--ward`) are independent and additive.

```
# Track / commit with recipients (and optional passphrase)
./sigil vault track ./notes.txt --to alice.pub
./sigil vault commit ./notes.txt --pass house --to alice.pub --to bob.pub
# either passphrase OR any matching identity unwraps the CEK

# Restore / mount / path / open with identity
./sigil vault restore ./notes.txt --identity alice.sgk
./sigil mount ./notes.txt ./view --vault --identity alice.sgk
./sigil mount secret.sg1 ./view --export-dir /tmp/view --identity alice.sgk
./sigil path secret.sg1 --identity alice.sgk --into .
./sigil open --identity alice.sgk secret.sg1
./sigil de-scribe --identity alice.sgk -o notes.txt secret.sg1
```

Dirty re-seal: pass `--to` / `--pass` on `vault commit --from-export` the same way as ordinary commit. The `.sigil-dirty` sidecar never stores secrets.

**Deferred:** `--identity` on **constellation** packs is not wired yet — de-scribe member `.sg1`s directly. PGP import is on main (`sigil import-pgp`, see [PGP-IMPORT.md](PGP-IMPORT.md)); any imported `.sgk` / `.pub` works with every `--identity` / `--to` shown here. Passkeys/WebAuthn remain a roadmap follow-on.

## Limits (current)

- Vault track/commit live tip: a regular file, or a directory (folder vault, SGDR versions).
- Dirty `--from-export` re-seal: single-file and folder vault tips; bare (non-vault) SGDR exports must be tracked or re-inscribed.
- Folder vault restore mends torn classic (non-WORK) inner stars in an SGDR version, persists the healed pack, and sets `mended` — same spirit as single-file restore (outer SGDR is not RS-coded; WORK/SGWK members are not mended yet).
- FUSE: read-only; writable needs `--export-dir`.
- Nested seals: mount shows one layer; `sigil path` walks deeper.
- Constellation `--identity`: deferred.
- Format policy: new `.sg1` features stay additive/opt-in at Inscribe; plain seals stay readable forever — no layout fork.

## Related

- Retention full/light, prune, cold kit: [VAULT-RETENTION.md](VAULT-RETENTION.md)
- CLI Mount / Vault / Keys sections: [crate/sigil/README.md](../crate/sigil/README.md)
