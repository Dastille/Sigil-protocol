# OpenPGP import (minimal)

`sigil import-pgp` turns an existing OpenPGP **Curve25519** key into Sigil key files, so a friend's GnuPG key can be an encrypt-to recipient and your own GnuPG key can open those seals. It only touches key files. `.sg1` bytes and the `SGTO` recipient block are unchanged, and nothing about plain seals changes.

```bash
# friend's public key → recipient
./sigil import-pgp friend.asc --pub-out friend.pub
./sigil inscribe --to friend.pub -o gift.sg1 movie.mkv
./sigil inscribe --to friend.asc -o gift.sg1 movie.mkv   # .asc works directly with --to too

# your own key → identity (protected exports prompt for the passphrase, see below)
./sigil import-pgp my-secret.asc -o me.sgk               # also writes me.pub
./sigil de-scribe --identity me.sgk -o movie.mkv gift.sg1
./sigil sign gift.sg1 --key me.sgk                       # attest with your PGP primary key
```

## What is accepted

- OpenPGP **v4** keys, armored (`.asc`) or binary, with an **Ed25519 primary** (legacy EdDSA algo 22 or RFC 9580 algo 27) and at least one **cv25519 / X25519 encryption subkey** (algo 18 with the Curve25519 OID, or algo 25).
- RFC 9580 **v6** keys (e.g. `sq key generate --profile rfc9580`, OpenPGP.js 6 with `v6Keys`), with a native **Ed25519 primary (algo 27)** and an **X25519 subkey (algo 25)**. v6 fingerprints are the full 32-byte SHA-256 value and are printed in full, tagged `(OpenPGP v6)`. Self-signatures must be v6 (salted) signatures; primary expiry is taken from the direct-key signature as well as user-ID signatures. v6 keys without a user ID (like the RFC sample key) are fine.
- The Ed25519 primary becomes the attest half, so `sigil sign --key me.sgk` produces signatures under the same public key as your PGP primary.
- The **newest valid** encryption subkey becomes the X25519 encrypt-to half.

Refused, with a clear message: RSA, DSA, ElGamal, NIST/Brainpool curves, ML-KEM/ML-DSA (post-quantum) keys, v3/v5 keys, v6 keys using legacy algo 22/18 (forbidden by RFC 9580), revoked or expired primaries, and armor whose CRC24 does not match. Subkeys whose packet version differs from the primary's are skipped.

## Checks

- Each candidate subkey needs a **subkey binding signature (0x18)** that verifies against the primary (SHA-224/256/384/512 only). A file where someone swapped in a different cv25519 subkey under the same primary fails here, so the printed primary fingerprint really vouches for the encrypt subkey.
- Verified **subkey revocations (0x28)** and **key revocations (0x20)** are honored; key expiration (from the binding or newest user-ID self-signature) is checked against the clock.
- For secret import, the secret checksum must match, and the recovered scalars are re-derived to the public points before anything is written. Legacy cv25519 secrets are stored byte-reversed in OpenPGP; the importer handles that and proves the result.
- Output prints the primary and subkey fingerprints. Compare them with `gpg --list-keys --with-subkey-fingerprints` (or with your friend) before trusting a recipient.

## Secret keys and passphrases

Passphrase-protected secret exports import directly. This is what `gpg --export-secret-keys` writes for a key that has a passphrase:

```bash
gpg --export-secret-keys --armor <FPR> > me-sec.asc        # stays encrypted; no temp plaintext
./sigil import-pgp me-sec.asc -o me.sgk                    # prompts (no echo)
./sigil import-pgp me-sec.asc -o me.sgk --passphrase-file ~/.secrets/pgp-pass   # first line of the file
SIGIL_PGP_PASSPHRASE=… ./sigil import-pgp me-sec.asc -o me.sgk                 # scripts / CI
./sigil import-pgp me-sec.asc -o me.sgk --passkey          # straight into a passkey-locked .sgk
```

How it decrypts (standard OpenPGP, no custom crypto):

| S2K usage | Key versions | Passphrase → key | Secret encryption | Integrity |
|---|---|---|---|---|
| **254** (CFB) | v4, v6 | simple / salted / iterated+salted over SHA-1, SHA-224/256/384/512 | AES-128/192/256 OpenPGP **CFB** (RustCrypto `aes` + `cfb-mode`) | SHA-1 of the plaintext |
| **255** (legacy) | v4 only | same | same | 16-bit checksum |
| **253** (AEAD, RFC 9580) | v4, v6 | **Argon2id** (S2K type 4) or iterated+salted | KEK = **HKDF-SHA256**(S2K key, info = packet type ‖ version ‖ cipher ‖ AEAD mode), then AES-128/192/256 in **OCB** (`ocb3`), **GCM** (`aes-gcm`) or **EAX** (`eax`) | AEAD tag; associated data = packet type ‖ public key packet |

After decryption the recovered scalars must re-derive the exact public points before anything is written. A wrong passphrase is an error, never a silent public-only import; for AEAD keys a wrong passphrase and a damaged/tampered key both fail the tag check (`wrong passphrase (or damaged secret key): AEAD authentication failed`) and nothing is written. The passphrase is never printed or logged; passphrase, S2K output, KEK, decrypted material and the in-memory identity are held in zeroizing buffers and wiped on drop (Argon2's working memory is wiped too).

**Argon2 resource caps.** RFC 9580 lets a key ask for up to 2^31 KiB (2 TiB) of Argon2 memory, so a hostile key file could otherwise exhaust RAM. `import-pgp` checks the parameters *before* allocating and refuses, with a clear message:

- memory exponent `encoded_m` above **22** (2^22 KiB = **4 GiB**). RFC 9106's first recommended setting (t=1, p=4, m=2^21 = 2 GiB, which the RFC 9580 sample key uses) is accepted; budget that much free RAM for such a key;
- more than **64 passes**, or passes × memory above 2^26 KiB-passes (e.g. 16 passes at 4 GiB, 1024 passes at 64 MiB);
- RFC-invalid parameters (t or p of 0, memory below 8·p KiB, `encoded_m` > 31), and Argon2 under anything but AEAD protection (RFC 9580 §3.7.2 calls that malformed).

The Argon2 buffer is reserved fallibly, so a machine without that much memory gets an error instead of an abort. To import a key above the cap, re-protect it with less memory first (e.g. `sq key password`).

Tested against: a GnuPG 2.4 export (AES-128, iterated SHA-1); an independent PGPy export (AES-256, iterated SHA-512) that GnuPG imports; the **RFC 9580 Appendix A.3–A.5** sample v6 certificate, unlocked secret, and locked secret (Argon2id + AES-256-OCB, passphrase `correct horse battery staple`), including its published HKDF key and associated-data intermediates; **OpenPGP.js 6** v4 keys protected with Argon2id + AES-256-OCB, -GCM, -EAX, and iterated SHA-256 + OCB (all also unlocked by Sequoia `sq` 1.3 as a cross-check); and a **Sequoia `sq` 1.3** v6 key (`--profile rfc9580`, CFB). An in-test encoder additionally covers every AEAD mode × AES-128/192/256, and tests check that wrong passphrases, flipped tag/ciphertext bytes, changed public-key bytes (associated data), and a primary/subkey packet-type swap all fail closed.

Not decrypted (clear refusal): non-AES ciphers (CAST5/3DES/Camellia/…), unknown AEAD modes, v6 keys with MalleableCFB (usage 255) or a raw cipher id (both forbidden for v6), pre-RFC 2440 protection, and GnuPG stubs (`--export-secret-subkeys` / smartcard keys have no secret to import).

## File format

Imported identities are written as **`.sgk` v2** (`SGIK`, version 2, flag bit 0 = from OpenPGP): the raw X25519 scalar, the Ed25519 seed, and the 20-byte v4 primary fingerprint, 92 bytes total, created owner-only (0600). The layout is unchanged for v6 imports: RFC 9580 §14.1 forbids storing part of a 32-byte v6 fingerprint in a 20-byte field, so a v6 import leaves that slot **all-zero** (never a real SHA-1 fingerprint) and the full v6 fingerprint is printed at import time and can be recomputed from the key. Native `sigil keygen` identities stay `.sgk` v1 (HKDF master), and builds from before this change refuse v2 with "unsupported .sgk version 2" instead of misreading it. Public halves are ordinary `.pub` v1 files, readable by every build.

To keep the imported secret off disk in the clear, lock it to a security key right after import: `sigil identity protect me.sgk --in-place --passkey` (see [PASSKEY.md](PASSKEY.md)).

## Not in this slice

Producing OpenPGP messages (Sigil still uses its own `SGTO` envelope; GnuPG cannot open a `.sg1`), exporting Sigil keys as OpenPGP, post-quantum (ML-KEM / ML-DSA) and X448/Ed448 keys, and non-AES secret-key ciphers.
