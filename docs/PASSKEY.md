# Passkey unlock for identities (FIDO2 hmac-secret / WebAuthn PRF)

A `.sgk` identity can be locked to a FIDO2 security key (YubiKey 5, SoloKey, Nitrokey 3, Google Titan v2, Feitian…). The secret key never sits on disk in the clear; opening a seal with `--identity me.sgk` asks you to touch the key (and enter its PIN). This changes **key files only**: `.sg1` bytes, the `SGTO` recipient block, passphrase Wards, and plain `.sgk` v1/v2 files are all unchanged.

```bash
# new identity, protected from the start (plain secret is never written)
sigil keygen --passkey -o me.sgk            # writes me.sgk (protected) + me.sgk.pub
sigil identity add-passkey me.sgk           # register a BACKUP key — do this now

# protect an existing identity (native v1 or PGP-imported v2)
sigil identity protect me-plain.sgk -o me.sgk --passkey
shred -u me-plain.sgk                       # after you've tested me.sgk

# use it exactly like before — unlock is transparent
sigil inscribe --to friend.pub --to me.sgk -o gift.sg1 movie.mkv   # public half needs no touch
sigil de-scribe --identity me.sgk -o movie.mkv gift.sg1            # touch + PIN
sigil sign gift.sg1 --key me.sgk
sigil vault restore --identity me.sgk ./photos

sigil identity info me.sgk                  # slots, rp id, PIN/touch — no unlock
sigil identity remove-passkey me.sgk --slot 0
sigil identity unprotect me.sgk -o me-plain.sgk   # escape hatch
```

`--no-uv` makes a slot touch-only (no PIN). Default is PIN / user verification, so a stolen key plus a stolen file isn't enough. `--rp-id` sets the relying-party id (default `sigil.sg1`).

## Build it with security-key support

Hardware support is a cargo feature so the default build stays dependency-light:

```bash
# Debian / Ubuntu / Parrot
sudo apt install libudev-dev pkg-config
cd crate/sigil && cargo build --release --features passkey
```

Linux also needs permission to open the key's hidraw device: install your distro's FIDO udev rules (`libfido2-1` / `libu2f-udev` on Debian-family) and replug. Exactly one key should be plugged in at a time. PIN comes from a no-echo prompt, or `SIGIL_PASSKEY_PIN` for scripts. macOS and Windows build the same way (no extra packages); on Windows, raw HID access to FIDO devices needs an elevated prompt.

A build **without** the feature still reads `identity info` and `--to me.sgk`, and tells you to rebuild if asked to unlock.

## How it works (standard primitives only)

- **Authenticator PRF.** At setup Sigil registers a non-discoverable credential with the CTAP2 `hmac-secret` extension, picks a random 32-byte `prf_input`, and asks the key for `hmac-secret` with `salt = SHA-256("WebAuthn PRF" ‖ 0x00 ‖ prf_input)`. That is exactly the salt a browser sends for the WebAuthn `prf` extension with `eval.first = prf_input`, so the same credential gives the same output from either path.
- **KEK.** `KEK = HKDF-SHA256(salt = prf_input, ikm = prf_output, info = "sigil-sgkw-kek-v1")`.
- **Envelope.** A random 32-byte data key encrypts the exact bytes of the plain `.sgk` with AES-256-GCM (AAD = the clear header). Each slot wraps that data key under its KEK with AES-256-GCM (AAD = header ‖ slot kind, flags, rp id, credential id, prf_input). So editing any slot field, flipping PIN-required to touch-only, or swapping the public key in the header fails authentication.
- **Self-check.** After unwrap the inner identity is re-derived and its public keys must equal the clear header.
- **Hygiene.** Key files are written owner-only (0600) via temp-file + rename; secrets are held in zeroizing buffers.
- The PIN/UV choice selects a different hmac-secret secret on the authenticator (CTAP2 `CredRandomWithUV` vs `WithoutUV`), so it's recorded per slot and enforced by the AAD.

## File layout (`SGKW` v1)

```
"SGKW" | ver=1 | 0 | slot_count | 0 | x25519_pk[32] | ed25519_pk[32]      (72-byte clear header)
body_nonce[12] | body_len u32le | AES-GCM(DEK, plain .sgk bytes)
slot × slot_count:  kind u8 | len u16le | body
  kind 1 (FIDO2 hmac-secret / PRF): flags u8 (bit0 UV) | rp_len u8 | rp_id |
         cred_len u16le | cred_id | prf_input[32] | nonce[12] | AES-GCM(KEK, DEK)[48]
crc32 (casual-damage check; security comes from the GCM tags)
```

Unknown slot kinds are length-prefixed and kept verbatim, so later unlock methods (e.g. a passphrase slot) can be added without breaking these files. Older Sigil builds refuse an `SGKW` file as "not a Sigil identity" — they never misread it.

## Tests and the software authenticator

Tests use `SoftAuthenticator`, a model of CTAP2 hmac-secret (`HMAC-SHA-256(CredRandom, salt)` with separate UV / non-UV secrets). Setting `SIGIL_SOFT_AUTHENTICATOR=/path/state.bin` makes the CLI use it — **testing only**: its state file is effectively a plain key. CI runs these; the real CTAP backend is compiled in CI but needs a physical key to exercise.

## Limits

- Lose every registered key → the identity is gone (that's the point). Register a backup with `identity add-passkey`, or keep an offline plain copy somewhere you trust.
- CTAP2 HID only (USB, or NFC readers that expose HID). Phone/hybrid (caBLE) passkeys and platform authenticators (Windows Hello, Touch ID) need the WebAuthn browser/OS APIs; the PRF salt construction is already compatible, but that bridge isn't built.
- Assertion signatures/attestation aren't verified — they aren't needed for key derivation (a fake device just produces a wrong key and unlock fails), but Sigil does not prove *which* authenticator model you used.
- Each unlock takes one touch per `--identity` file per command.
