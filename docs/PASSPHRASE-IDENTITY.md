# Passphrase-protected identities (`keygen --pass`)

Your identity file (`me.sgk`) is the key that opens everything sent to you with
`--to me.sgk.pub`, and it signs as you. A plain `me.sgk` is that key in plain bytes:
anyone who gets a copy of the file (a backup, a synced folder, a stolen laptop) can use
it. A **passphrase-protected** identity is the same key locked with a passphrase you
choose, so a copied file alone is not enough.

```
./sigil keygen --pass - -o me.sgk            # asks twice, hidden; writes me.sgk + me.sgk.pub
./sigil keygen --pass-file ~/.id-pass -o me.sgk   # scripts: first line of a file only you can read

./sigil inscribe --to me.sgk.pub -o gift.sg1 movie.mkv      # no passphrase needed (public half)
./sigil de-scribe --identity me.sgk -o movie.mkv gift.sg1   # asks for the passphrase (hidden)
./sigil de-scribe --identity me.sgk --identity-pass-file ~/.id-pass -o movie.mkv gift.sg1
./sigil sign gift.sg1 --key me.sgk                          # asks too

./sigil identity protect --pass - me.sgk --in-place    # lock an existing plain identity
./sigil identity unprotect me.sgk -o plain.sgk         # back to plain (asks for the passphrase)
./sigil identity info me.sgk                           # kind + public keys, no passphrase needed
```

What you can count on (each checked by `tests/cli_keygen_pass.rs` and the unit tests in
`crate/sigil/src/passid.rs`):

- **The plain secret is never written to disk.** The file is created owner-only (0600).
- **Opening asks for the passphrase on the terminal**, without showing it. In a script (no
  terminal) Sigil does not wait or guess: it stops with a message pointing to
  `--identity-pass-file PATH`. That flag works wherever an identity is opened
  (`--identity`, `--unlock`, `--sign`, `sign --key`, `identity unprotect`) and follows the
  same rules as `--pass-file`: first line of the file, refused if other users can read or
  change it, refused if empty. There is **no** environment-variable way to give it.
- **It fails closed.** A wrong passphrase, a file that was cut short, any changed byte, or
  a file that demands an unreasonable amount of memory or time to unlock is refused with an
  error, and no key is used. A wrong passphrase and a damaged file give the same message
  (the check cannot tell them apart).
- **Empty passphrases are refused**, and so is `--pass VALUE` typed on the command line
  (other programs can see it, and your shell may save it).
- **The public half needs no passphrase.** `--to me.sgk`, `--signer me.sgk` and
  `identity info` read the public keys from the file's clear header.
- **Plain and passkey identities keep working** exactly as before.
- **There is no reset.** Forget the passphrase and the identity is gone. Keep a backup of
  the passphrase (or a second identity) somewhere you trust.

Plain `sigil keygen -o me.sgk` (no `--pass`, no `--passkey`) still writes an unprotected
file so existing scripts keep working, and now prints a one-line warning on stderr.

## How it works (standard primitives only)

- **Passphrase → key:** Argon2id, version 0x13 ([RFC 9106](https://www.rfc-editor.org/rfc/rfc9106)),
  with a random 16-byte salt. New files use m = 19456 KiB (19 MiB), t = 2, p = 1 (the OWASP
  Password Storage Cheat Sheet minimum, the same defaults as passphrase seals). The parameters
  are stored in the file; before doing any work, readers refuse values below RFC 9106's
  minimums or above Sigil's caps (1 GiB, 16 passes, 8 lanes, passes × memory ≤ 2^22 KiB).
- **Lock:** AES-256-GCM ([NIST SP 800-38D](https://csrc.nist.gov/pubs/sp/800/38/d/final)) with a
  random 96-bit nonce over the exact bytes of the plain `.sgk` (native v1 or OpenPGP-imported v2).
  The whole clear header is the associated data, so editing any header byte (parameters, salt,
  public keys, nonce, length) makes unlocking fail.
- **Self-check:** after unlocking, the inner identity's public keys must equal the header copy.
  Writing checks that the new file opens before it is saved.
- **Hygiene:** the derived key, Argon2 working memory and the plain identity bytes are wiped
  (zeroized) after use.

## File layout (`SGKP` v1)

All integers little-endian. Bytes 0–115 are the clear header and the AES-GCM associated data.

```
  0  4  "SGKP"
  4  1  version = 1
  5  1  KDF id = 1 (Argon2id v0x13)
  6  2  reserved, must be 0
  8  4  Argon2id memory (KiB)
 12  4  Argon2id passes (t)
 16  4  Argon2id lanes (p)
 20 16  salt
 36 32  X25519 public key
 68 32  Ed25519 public key
100 12  AES-GCM nonce
112  4  sealed length N (= inner .sgk length + 16)
116  N  AES-256-GCM(key, nonce, plain .sgk, AAD = bytes 0..116) incl. 16-byte tag
```

The file must be exactly `116 + N` bytes. Older Sigil builds refuse an `SGKP` file when it
is used as `--identity` ("not a Sigil identity (.sgk)") or `--to` ("not a recipient public
key"). One exception: builds from before this format treat an unknown file given to
`sign --key` as a raw 32-byte signing seed, so an old build "signs" with a meaningless key
made from public header bytes (the signature does not verify as you). Use a current build
with protected identities.

## Limits

- Offline guessing: anyone with a copy of the file can try passphrases at the cost of one
  Argon2id run each. A long passphrase (several random words) is what makes that hopeless.
- One passphrase per file (no second passphrase or passkey slot on the same file yet).
- The default is still plain `keygen` (see the warning); choose `--pass -` or `--passkey`.
