# Private label (header v3)

New encrypted `.sg1` files no longer carry the plaintext's identity in the clear.
Spec and threat model: `docs/sigil-v1.txt` (HEADER, THREAT MODEL). Code: `crate/sigil/src/privacy.rs`.

## What changed (on by default for every encrypted write)

| Field | v2 encrypted (old) | v3 private label (new) |
|---|---|---|
| true-name slot | plaintext SHA-256 | keyed fingerprint (HMAC-SHA256, per file) |
| original length | exact | 0 (inside the lock) |
| file name (16 B) | clear | empty (full name inside the lock) |
| entropy, deflate flag | clear | 0 (inside the lock) |
| label integrity | CRC32 only | GCM associated data + Merkle binding |
| pack front / guards | full name, total | empty name, total 0 |
| pack facets | per-chunk plaintext SHA-256 | per-star keyed fingerprint |
| constellation star file | `star_path(sha256)` | ciphertext id (Merkle root) |

Inner block `SGIN` v1 (72 bytes + name) sits before the folded body inside the
AES-256-GCM plaintext. Keyed fingerprint key: HKDF-SHA256 (RFC 5869), ikm = content
key, salt = file salt, info `sigil v3 keyed fingerprint`; fingerprint = HMAC-SHA256
(RFC 2104) of the plaintext. `FingerprintKey::Shared` (library, opt-in) derives the
key from a vault-wide secret instead so equal files dedupe for its holder.
`sigil::keyed_fingerprint_matches` lets the key holder test a live file without decrypting the body.

## Tomes (sealed directory, SGDR v2)

Every encrypted Tome (`--pass` and/or `--to`) is written as a sealed
directory. There is no opt-out flag. Layout (code: `crate/sigil/src/folder.rs`):

    "SGDR" | ver=2 | file count u32 LE | body length u64 LE | body

`body` is one ordinary encrypted `.sg1` (a v3 private-label Sigil, or an SGWK work
pack when the folder is over the chunk size, 4 MiB by default) sealed with the same
mode and keys. Its plaintext is the complete v1 Tome, so the member names,
the folder tree and the per-member star lengths are all inside AES-256-GCM.
Members inside the body are still sealed with the same keys (per-file `--ward`s keep
working), in Glyph mode because the body already carries the Reed-Solomon parity.

- Keyless: `scry` / `verify` print `folder  N files (names hidden)` plus the body's
  health line; `mend` heals the body; `doctor` checks it.
- With the key: `scry --pass/--identity` lists members, `unseal --only` and `mount`
  work as for v1. Readers reject a body whose inner pack does not match the outer
  file count, trailing bytes, a truncated body, and any GCM / Merkle failure.
- Still visible: the file count and the total ciphertext length.
- Plain Tomes (no key) show their names to anyone. A new one is written as
  a protected plain Tome (v3, below); `--old-tome-layout` still writes v1. A pack whose
  only keys are `--ward`s is refused unless `--ward-names-visible` is given (names
  readable without a key, with a warning); add `--pass` / `--to` to get v2. Every v1
  pack, including encrypted and ward-only ones written earlier, opens and lists as before.

## Protected plain Tomes (SGDR v3)

A Tome made without `--pass` / `--to` uses the v2 layout without encryption:

    "SGDR" | ver=3 | file count u32 LE | body length u64 LE | body

`body` is one ordinary unencrypted `.sg1` (or an SGWK work pack when the folder list
and members together are over the chunk size) sealed with the chosen mode. Its plaintext
is the complete v1 Tome. So the folder list (count, names, star lengths) sits inside
Reed-Solomon parity and is checked by the body's SHA-256 (and per-chunk SHA-256 and
merkle root for a work pack) before anything is written. In a v1 Tome the list has no
repair data. Members inside the body are sealed in Glyph mode, as in v2.

- **Accidental damage only.** No key is involved, so nothing here stops a deliberate
  forger: anyone can write a new, valid v3 Tome with other contents. Use a Ward
  (`--pass` / `--to`) when edits by someone else matter.
- Names, sizes and the tree are readable by anyone (`scry`, `ls`, `mount` need no key).
- Readers reject a body whose inner pack does not match the outer count, trailing bytes,
  a truncated body, and any SHA-256 / merkle failure. `mend` heals the body and rebuilds
  a damaged body length or file count in the head from the file size and the healed body.
- Size: on the three measured folder shapes, v3 was 8% to 48% smaller than v1 for many
  small or deeply nested files (the list is compressed with the body) and at most 0.08%
  larger for a few big files.
- Older sigil builds refuse a v3 Tome without reading it ("unknown Tome version 3" from
  `unseal` / `ls`; `scry` and `mend` report the Tome as too damaged); they never return
  a wrong tree. Update sigil to open it, or write `--old-tome-layout` for an old reader.

### Sealing the names of an old pack (`sigil seal-folder-names`)

```sh
sigil seal-folder-names old.sg1 -o new.sg1 --pass-file pw.txt          # or --to me.pub [--identity me.sgk]
sigil seal-folder-names wards.sg1 -o new.sg1 --pass-file pw.txt --allow-new-key   # ward-only pack
```

Turns a v1 pack (names in the clear) into a v2 sealed directory without re-inscribing the
folder: the v1 pack becomes the encrypted body, as `inscribe` builds it. Encrypted members are
copied byte-for-byte (not decrypted; wards keep working); clear members are sealed under the new
key (Glyph mode). INPUT is never changed and an existing OUTPUT is refused.

- Fails closed: when the pack has encrypted members, the given `--pass-file` / `--identity` must
  open at least one of them (a typo would otherwise seal the names under a key that opens none of
  the files). A ward-only pack's members open only with their wards: `--allow-new-key` accepts that.
  No key, a literal `--pass`, or an already-sealed pack is refused; nothing is written.
- **Honest limits:** the old file and every copy or backup of it still show the names; delete them
  yourself. Members encrypted with a passphrase different from the new key still need that old
  passphrase (only one is checked). Large unencrypted members (work packs) are refused: re-inscribe
  that folder with `--pass-file` / `--to`.

## Keyless operations

`mend`, `scry`, `verify`, `doctor`, `log verify`/`mend` use shard CRCs and the
Merkle binding of the ciphertext; they never need the key. Name and size appear only
after unlock.

## Compatibility

Plain Sigils stay v2. Every existing file (v0–v2, packs, Tomes,
constellations, logs) opens as before; fixtures in `tests/fixtures/enc-v2/`.
Readers refuse a v3 label on an unencrypted Sigil, a v3 Sigil without SGTO, a
nonzero outer entropy slot, and any label edit. Since 17 November 2026 the SGTO block of a
new v3 Sigil is stored twice (SGTO v3 + `SGTS` spare at the end; docs/KEYWRAP-SPARE.md);
builds before that refuse those files.

## Still leaks

Ciphertext length (padding is a follow-up, opt-in only), the file count of an
encrypted Tome (names are sealed: see above), member names of Tomes
written before sealed directories (until converted with `sigil seal-folder-names`; old copies still show them), ward-only packs (made before wards needed a folder key, or with `--ward-names-visible`), vault CHART digests/sizes, segment-log INDEX size/SHA-256/path in a log created
with no key or with `--public-index` (a private INDEX, the default for a keyed log, seals them: docs/SEGMENT-LOG.md "Private INDEX").
See the threat model.
