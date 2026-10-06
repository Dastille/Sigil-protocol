Throwaway GnuPG test keys generated for unit tests (2026-10-06). Not anyone's real key; the unprotected
secret in `test-sec.asc` is public on purpose. `locked-sec.asc` passphrase: `hunter2`.
`rotated-pub.asc`: two cv25519 subkeys, the newest revoked (import must pick the older one).
`pgpy256-sec.asc` / `pgpy256-pub.asc`: throwaway key made with PGPy (Ed25519 + cv25519), protected with AES-256 + iterated SHA-512 S2K; passphrase `pgpy pass 256`. Cross-checked by importing into GnuPG 2.4.
