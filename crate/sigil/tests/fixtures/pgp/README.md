Throwaway GnuPG test keys generated for unit tests (2026-10-06). Not anyone's real key; the unprotected
secret in `test-sec.asc` is public on purpose. `locked-sec.asc` passphrase: `hunter2`.
`rotated-pub.asc`: two cv25519 subkeys, the newest revoked (import must pick the older one).
`pgpy256-sec.asc` / `pgpy256-pub.asc`: throwaway key made with PGPy (Ed25519 + cv25519), protected with AES-256 + iterated SHA-512 S2K; passphrase `pgpy pass 256`. Cross-checked by importing into GnuPG 2.4.
`rfc9580-a3-pub.asc`, `rfc9580-a4-sec.asc`, `rfc9580-a5-locked-sec.asc`: the RFC 9580 Appendix A.3–A.5 sample v6 Ed25519 + X25519 key (public, unlocked, and locked with Argon2id t=1 p=4 m=2^21 + AES-256-OCB; passphrase `correct horse battery staple`), copied verbatim from the RFC.
`sq-v6-sec.asc`: throwaway v6 key from Sequoia `sq` 1.3.1 (`sq key generate --profile rfc9580 --cipher-suite cv25519`, 2026-10-08), CFB + iterated SHA-256 (usage 254); passphrase `sq v6 pass`.
`opjs-{ocb,gcm,eax,ocb-iter}-sec.asc`: throwaway v4 keys from OpenPGP.js 6.x (2026-10-08) with `aeadProtect` (usage 253): Argon2id (t=1, p=4, m=2^15) + AES-256-OCB / -GCM / -EAX, and iterated SHA-256 + OCB. `ocb`/`eax` use legacy EdDSA/cv25519 (22/18), `gcm`/`ocb-iter` RFC 9580 Ed25519/X25519 (27/25). Passphrases `ocb pass`, `gcm pass`, `eax pass`, `iter pass`. Sequoia `sq` 1.3.1 unlocks all four (cross-check).
