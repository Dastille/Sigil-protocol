# OpenPGP import (minimal)

`sigil import-pgp` turns an existing OpenPGP **Curve25519** key into Sigil key files, so a friend's GnuPG key can be an encrypt-to recipient and your own GnuPG key can open those seals. It only touches key files. `.sg1` bytes and the `SGTO` recipient block are unchanged, and nothing about plain seals changes.

```bash
# friend's public key → recipient
./sigil import-pgp friend.asc --pub-out friend.pub
./sigil inscribe --to friend.pub -o gift.sg1 movie.mkv
./sigil inscribe --to friend.asc -o gift.sg1 movie.mkv   # .asc works directly with --to too

# your own key → identity (needs an unprotected secret export, see below)
./sigil import-pgp my-secret.asc -o me.sgk               # also writes me.pub
./sigil de-scribe --identity me.sgk -o movie.mkv gift.sg1
./sigil sign gift.sg1 --key me.sgk                       # attest with your PGP primary key
```

## What is accepted

- OpenPGP **v4** keys, armored (`.asc`) or binary, with an **Ed25519 primary** (legacy EdDSA algo 22 or RFC 9580 algo 27) and at least one **cv25519 / X25519 encryption subkey** (algo 18 with the Curve25519 OID, or algo 25).
- The Ed25519 primary becomes the attest half, so `sigil sign --key me.sgk` produces signatures under the same public key as your PGP primary.
- The **newest valid** encryption subkey becomes the X25519 encrypt-to half.

Refused, with a clear message: RSA, DSA, ElGamal, NIST/Brainpool curves, v6 keys, revoked or expired primaries, and armor whose CRC24 does not match.

## Checks

- Each candidate subkey needs a **subkey binding signature (0x18)** that verifies against the primary (SHA-224/256/384/512 only). A file where someone swapped in a different cv25519 subkey under the same primary fails here, so the printed primary fingerprint really vouches for the encrypt subkey.
- Verified **subkey revocations (0x28)** and **key revocations (0x20)** are honored; key expiration (from the binding or newest user-ID self-signature) is checked against the clock.
- For secret import, the secret checksum must match, and the recovered scalars are re-derived to the public points before anything is written. Legacy cv25519 secrets are stored byte-reversed in OpenPGP; the importer handles that and proves the result.
- Output prints the primary and subkey fingerprints. Compare them with `gpg --list-keys --with-subkey-fingerprints` (or with your friend) before trusting a recipient.

## Secret keys and passphrases

Passphrase-protected secret exports are **not decrypted** by Sigil (no S2K/CFB code in this slice). If the export is protected, `import-pgp -o` refuses and says so; with no `-o`, it just imports the public half. To import your own key, export it unprotected into a private temp directory, import, then delete the export:

```bash
umask 077; d=$(mktemp -d)
gpg --export-secret-keys --armor <FPR> > "$d/k.asc"   # only unprotected if the key has no passphrase
./sigil import-pgp "$d/k.asc" -o me.sgk
shred -u "$d/k.asc"; rmdir "$d"
```

## File format

Imported identities are written as **`.sgk` v2** (`SGIK`, version 2, flag bit 0 = from OpenPGP): the raw X25519 scalar, the Ed25519 seed, and the 20-byte v4 primary fingerprint, 92 bytes total, created owner-only (0600). Native `sigil keygen` identities stay `.sgk` v1 (HKDF master), and builds from before this change refuse v2 with "unsupported .sgk version 2" instead of misreading it. Public halves are ordinary `.pub` v1 files, readable by every build.

To keep the imported secret off disk in the clear, lock it to a security key right after import: `sigil identity protect me.sgk --in-place --passkey` (see [PASSKEY.md](PASSKEY.md)).

## Not in this slice

Decrypting passphrase-protected PGP secrets, v6 keys, and producing OpenPGP messages (Sigil still uses its own `SGTO` envelope; GnuPG cannot open a `.sg1`).
