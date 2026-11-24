# kdf-v2 fixtures (Argon2id passphrase wraps, SGTO version 2)

Written by the Rust CLI on `main` as of 19 October 2026 (`cargo build --release`), from `plain.txt`.
Passphrase for every file: `correct horse battery`. Used by the web lab tests
(`src/lib/sigil/sgto.test.ts`) to prove the lab opens what Rust writes.

| File | Command |
|---|---|
| `pass-reflection.sg1` | `sigil seal --pass-file F plain.txt` |
| `pass-seal-vow.sg1` | `sigil seal --mode seal --covenant "lab fixture" --pass-file F plain.txt` (Vow after SGTO) |
| `pass-and-to.sg1` | `sigil seal --pass-file F --to id.pub plain.txt` (X25519 record + Argon2id record) |
| `to-only.sg1` | `sigil seal --to id.pub plain.txt` (no passphrase record; the lab must refuse) |
