# Vault + mount + nest (composed model)

How the **version tip**, **read/edit views**, and **nested seals** fit together. Retention policy (full vs light, cold kit) lives in [VAULT-RETENTION.md](VAULT-RETENTION.md) — this page does not repeat that deep-dive.

Seals stay **immutable**. Edits never rewrite an existing `vN.sg1` or a bare mark in place. A new tip is always a new seal.

## Pieces

| Piece | What it is | Durable store |
|-------|------------|---------------|
| **Vault** | Live file + sidecar chart `<live>.sgv/` (`CHART` + `v1.sg1`, `v2.sg1`, …) | Version stack; tip moves on commit |
| **Mount** | Apps see normal paths over a tip / bare `.sg1` / SGDR pack | Seal untouched; cleartext in RAM (FUSE) or an export tree |
| **Path / nest** | Breadcrumb walk into nested `.sg1` layers inside a pack or mark | Outer mark unchanged; optional extract to a temp path |

`vault track` needs a **regular file** (not a directory). Folder packs (SGDR) are still mountable and walkable as bare `.sg1` marks; versioning a folder as a vault live tip is not the track path today.

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

### Folder / SGDR dirty re-seal (stub)

Mount and export of SGDR folder packs work (including nested `.sg1` entries as files). **`vault commit --from-export` for folder/SGDR dirty trees is not implemented yet** — it errors with `folder dirty re-seal not in this slice (single-file vault tip only)`. Single-file vault tip dirty → re-seal works. Until folder re-seal lands, version a folder by packing with `inscribe` to a new mark, or keep the live tip as a single file.

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

**Deferred:** `--identity` on **constellation** packs is not wired yet — de-scribe member `.sg1`s directly. Passkeys/WebAuthn and PGP import remain roadmap follow-ons (not part of this glue).

## Limits (current)

- Vault track/commit live tip: **single regular file** only.
- Dirty `--from-export` re-seal: **single-file** vault tip only; folder/SGDR stubbed (clear error).
- FUSE: read-only; writable needs `--export-dir`.
- Nested seals: mount shows one layer; `sigil path` walks deeper.
- Constellation `--identity`: deferred.
- Format policy: new `.sg1` features stay additive/opt-in at Inscribe; plain seals stay readable forever — no layout fork.

## Related

- Retention full/light, prune, cold kit: [VAULT-RETENTION.md](VAULT-RETENTION.md)
- CLI Mount / Vault / Keys sections: [crate/sigil/README.md](../crate/sigil/README.md)
