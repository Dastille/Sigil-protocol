# Glossary

*Version 1.1, 26 November 2026. Sigil's own names first, then the general terms they rest on.*

| Word | Meaning |
|---|---|
| **Sigil** | One `.sg1` file: your file or folder plus its repair data and fingerprints. Also called a Sigil Archive. |
| **Tome** | A Sigil Archive of a whole folder: one `.sg1` file that holds every file in that folder. |
| **Codex** | A `name.sigil/` folder that keeps one thing together (a Vault, a Constellation, or a signed log), including its manifest and related files. Not a `.sg1` file, and not a Tome. The on-disk manifest is still named `CONTAINER`. |
| **Inscribe / seal** | Make a Sigil from a file or folder (`sigil seal`). |
| **De-scribe / unseal** | Get the original back from a Sigil (`sigil unseal`). |
| **Scry / verify** | Check a Sigil's health without changing it. |
| **Mend** | Repair a damaged Sigil into a new copy. |
| **Quick repair** | Rebuilds the file from the pieces that are still entirely intact. |
| **Deeper repair** | Fixes small errors inside each piece, byte by byte; used automatically when the quick repair is not enough. Also called soft repair. |
| **Scan** | A look before repairing: kind of damage, which repair, rough time (`mend --scan`). |
| **Reflection** | The default mode: about 1.3 times the size; any 12 of 16 pieces rebuild it. |
| **Seal (mode)** | The stronger mode: about 2 times the size; any 8 of 16 pieces rebuild it. |
| **Glyph** | A mode with no repair data (any damage is fatal). |
| **Shard / piece** | One of the (usually 16) parts a Sigil is split into. A shard saved as its own file has the extension `.sgp`. |
| **Keystone / Ember** | Spare copies of a Sigil's header (its label), so damage at the front of the file does not lose it. |
| **Ward** | The lock on a Sigil (a passphrase or key). |
| **Encrypt-to** | Locking a Sigil so that only the holder of a certain key file can open it (`--to`). |
| **Identity (`.sgk`)** | Your secret key file; its public half ends in `.pub`. |
| **Key wrap** | The small block inside a locked Sigil that unlocks it with your passphrase or key. Stored twice since 17 November 2026. |
| **Private label** | For locked Sigils, the file name and size are kept inside the lock. |
| **Frost Rune** | Cold storage: one Sigil spread over several unplugged drives. |
| **Fire Rune** | Reserved name for future hot (always-online) storage; does nothing yet. |
| **Channel / mana** | A way to send a Sigil as many small packets (`.mana` files) over an unreliable link; any large enough set rebuilds it. |
| **Scatter / gather** | Split a Sigil into piece files, and rebuild it from enough of them. |
| **Segment log** | An append-only archive: each backed-up file is a Sigil ("segment") listed in the INDEX. |
| **INDEX / root** | The log's list of entries, and the single fingerprint of the whole list at one moment. |
| **Signed** | A key you hold vouches for each change to a log, so tampering is detectable. |
| **Vault / constellation** | Versions of one live file; a named list of Sigils. |
| **Checksum (CRC-32)** | A small check number per piece that shows whether that piece changed. |
| **Hash / fingerprint (SHA-256)** | A 32-byte value computed from data; any change to the data changes it. |
| **True name** | The SHA-256 fingerprint of the original file. |
| **Merkle tree / hash tree** | Fingerprints of all the pieces combined into one value, so one check covers every piece. |
| **Reed–Solomon** | The well-established mathematics (1960) that lets missing or wrong pieces be rebuilt from spare ones. |
| **AES-256-GCM** | The standard encryption method used for locked Sigils; it also detects any change to the locked data. |
| **Argon2id** | A method that turns a passphrase into a key slowly, so guessing passphrases is expensive. |
| **Bit rot** | Slow, scattered damage to stored data, often single flipped bits. |
| **Hexadecimal (hex)** | Writing numbers with 0–9 and a–f; Sigil shows keys and fingerprints this way. You never need to type them. |
| **Result code (exit code)** | The number a command leaves for scripts: 0 done, 1 error, 2 too damaged, 3 nothing checked, 4 skipped, 5 damaged but `sigil mend` repairs it, 6 damaged, repair not checked, 130 stopped. |
