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

## Folder packs (sealed directory, SGDR v2)

Every encrypted folder pack (`--pass` and/or `--to`) is written as a sealed
directory. There is no opt-out flag. Layout (code: `crate/sigil/src/folder.rs`):

    "SGDR" | ver=2 | file count u32 LE | body length u64 LE | body

`body` is one ordinary encrypted `.sg1` (a v3 private-label mark, or an SGWK work
pack when the folder is over the chunk size, 4 MiB by default) sealed with the same
mode and keys. Its plaintext is the complete v1 folder pack, so the member names,
the folder tree and the per-member star lengths are all inside AES-256-GCM.
Members inside the body are still sealed with the same keys (per-file `--ward`s keep
working), in Glyph mode because the body already carries the Reed-Solomon parity.

- Keyless: `scry` / `verify` print `folder  N files (names hidden)` plus the body's
  health line; `mend` heals the body; `doctor` checks it.
- With the key: `scry --pass/--identity` lists members, `unseal --only` and `mount`
  work as for v1. Readers reject a body whose inner pack does not match the outer
  file count, trailing bytes, a truncated body, and any GCM / Merkle failure.
- Still visible: the file count and the total ciphertext length.
- Plain folder packs (no key) stay v1 with names in the clear. A pack whose only keys
  are `--ward`s is refused unless `--ward-names-visible` is given (then it is v1, names
  in the clear, with a warning); add `--pass` / `--to` to get v2. Every v1 pack,
  including encrypted and ward-only ones written earlier, opens and lists as before.

## Keyless operations

`mend`, `scry`, `verify`, `doctor`, `log verify`/`mend` use shard CRCs and the
Merkle binding of the ciphertext; they never need the key. Name and size appear only
after unlock.

## Compatibility

Plain marks stay v2. Every existing file (v0–v2, packs, folder packs,
constellations, logs) opens as before; fixtures in `tests/fixtures/enc-v2/`.
Readers refuse a v3 label on an unencrypted mark, a v3 mark without SGTO, a
nonzero outer entropy slot, and any label edit.

## Still leaks

Ciphertext length (padding is a follow-up, opt-in only), the file count of an
encrypted folder pack (names are sealed: see above), member names of folder packs
written before sealed directories, ward-only packs (made before wards needed a folder key, or with `--ward-names-visible`), vault CHART digests/sizes, segment-log INDEX size/SHA-256/path in a log created
with no key or with `--public-index` (a private INDEX, the default for a keyed log, seals them: docs/SEGMENT-LOG.md "Private INDEX").
See the threat model.
