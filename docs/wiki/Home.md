# Sigil wiki

*Plain-English guide for people who are not developers. Version 1.0, 23 November 2026.
Every example on these pages is real output, captured on 23 November 2026 from Sigil
built from the main branch on a Linux desktop.*

Sigil keeps your files safe from damage. It wraps a file or folder into one `.sg1` file
(called a **Sigil**) that carries its own spare repair data. If part of that file is
damaged later (a failing disk, a cut-off download, slow "bit rot" over the years), Sigil
can usually rebuild the original exactly, and it tells you plainly when it cannot. It can
also lock a file with a passphrase or a key.

## Start here

| Page | What you will learn |
|---|---|
| [Getting started](Getting-started.md) | Install Sigil, wrap a file, check it, get it back |
| [Repairing a damaged file](Repairing-a-damaged-file.md) | What to do when a Sigil is damaged; the scan; long repairs; what the result codes mean |
| [Encryption and keys](Encryption-and-keys.md) | Locking a Sigil with a passphrase or a key file, and why a lost key cannot be reset |
| [Frost Rune: cold storage](Frost-Rune-cold-storage.md) | Spreading one Sigil across several USB drives so losing some drives is fine |
| [Archives and the signed log](Archives-and-signed-log.md) | Backing up a folder over time into a log that proves nothing was changed |
| [FAQ](FAQ.md) | Short answers to common questions |
| [Glossary](Glossary.md) | What each Sigil word means |

## Three things to remember

1. **Sigil never writes over your damaged file.** A repair makes a new copy next to it.
2. **A result is kept only if it checks out.** Sigil compares the rebuilt file against
   fingerprints stored when it was made. If they do not match, nothing is written.
3. **Sigil is not a backup schedule.** It makes one copy much harder to lose, but you still
   need a second copy somewhere else.

More detail for technical readers: the [white paper](../WHITEPAPER.md), the
[README](../../README.md) and the [format specification](../sigil-v1.txt).
