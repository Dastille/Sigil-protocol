# Vault remembered recipients

An encrypt-to vault remembers who its versions are sealed to, so a later
`vault commit` can't silently produce a version that isn't encrypt-to.

## What changes

- `sigil vault track PATH --to alice.pub [--to bob.pub]` writes one additive
  `to=<x25519 hex>.<ed25519 hex>` line per recipient into the vault's `CHART`.
  Only **public** keys are stored. Passphrases, `--ward` passwords, identities
  and key-file paths are never written.
- `sigil vault commit PATH` with no `--to` seals the new version to the
  remembered set. This also covers `vault commit --from-export DIR` (the
  writable-export write path) and folder vaults.
- `--to` on `vault commit` **replaces** the remembered set for that version and
  every later one. The commit line says `(remembered)` or `(now remembered)`.
- Older version seals are never rewritten; each keeps the recipients it was
  minted with.

```
./sigil vault track ./notes.txt --to alice.pub
./sigil vault commit ./notes.txt                 # still encrypt-to alice
./sigil vault commit ./notes.txt --to bob.pub    # bob from now on
./sigil vault recipients ./notes.txt             # list (hint + X25519 key)
./sigil vault recipients ./notes.txt --to alice.pub --to bob.pub   # replace
./sigil vault recipients ./notes.txt --clear     # go plain on purpose
```

`--clear` writes `to=-`: an explicit "future versions are not encrypt-to".
Passphrase Ward (`--pass` / `--talisman`) is unaffected and still has to be
given on each commit; it is never remembered.

## Charts made before this feature

A chart with no `to=` lines whose single-file tip seal **is** encrypt-to refuses
a commit without `--to` (instead of writing a plain version next to encrypted
ones). Pass `--to` once and it is remembered from then on, or run
`vault recipients PATH --clear` to choose plain deliberately. Folder vaults
made before this feature aren't probed; pass `--to` once on the next commit.

An older `sigil` binary ignores `to=` lines when reading, but drops them if it
rewrites the `CHART` (commit / prune / retention). The guard above catches that
on single-file vaults the next time a current binary commits.

## Format

Additive and opt-in, per the Sigil format policy: plain vaults write no `to=`
lines, so their `CHART` stays byte-for-byte what it was, and `.sg1` / SGDR /
SGTO layouts are unchanged. Recipient specs accept everything `--to` does
(`.pub`, `.sgk`, OpenPGP cv25519 export, 32-byte hex). A hex-only recipient is
stored with an all-zero Ed25519 half, exactly as `--to` already treats it.

## Private label (v3)

Version seals are v3 private-label marks; restore checks the inner SHA-256. The CHART sidecar still records plaintext SHA-256 and size per version (keyed fingerprints for the CHART are a follow-up).
