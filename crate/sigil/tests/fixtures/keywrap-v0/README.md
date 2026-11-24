# keywrap-v0 fixtures (one key-wrap copy: private label v3 + SGTO v1/v2, no `SGTS` spare)

Written by the Rust CLI on `main` @ `13eee34` (PR #107, `cargo build --release`), from
`../kdf-v2/plain.txt`, before the key wrap got a tail spare (SGTO v3). Used by
`src/keywrap_spare_tests.rs` to prove that files written before the change open and mend
exactly as before (no spare is added to them).

| File | Command |
|---|---|
| `pass-reflection.sg1` | `sigil seal --pass-file F plain.txt` (passphrase `correct horse battery`; SGTO v2) |
| `to-seal.sg1` | `sigil seal --mode seal --to ../enc-v2/id.sgk.pub plain.txt` (SGTO v1; open with `../enc-v2/id.sgk`) |
