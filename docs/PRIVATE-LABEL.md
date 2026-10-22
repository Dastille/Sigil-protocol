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

Ciphertext length (padding is a follow-up, opt-in only), folder-pack (SGDR) member
names, vault CHART digests/sizes, segment-log INDEX size/SHA-256/path in a log created
without `--private-index` (a private INDEX seals them: docs/SEGMENT-LOG.md "Private INDEX").
See the threat model.
