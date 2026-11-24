# keywrap-v1 fixtures (key wrap stored twice: SGTO v3 at the front + `SGTS` tail spare)

Written by the Rust CLI on branch `fix/keywrap-spare-1117` (the change that added the spare;
`cargo build --release`), from `../kdf-v2/plain.txt`. Passphrase: `correct horse battery`.
Used by the web lab tests (`src/lib/sigil/sgto.test.ts`) to prove the lab opens the new layout,
including when the front key wrap is wiped. Builds before this change refuse this file
(fail closed: they do not know SGTO v3).

| File | Command |
|---|---|
| `pass-reflection.sg1` | `sigil seal --pass-file F plain.txt` |
