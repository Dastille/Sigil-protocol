# Start here

Friendly map of Sigil. Pick what you want to do, run the short command, then open the guide if you need more.

**Defaults that keep things simple**

- Everyday marks use **Reflection** (default). Use **Seal** when the copy might take heavy damage (about half the pieces can die).
- A **passphrase Ward** (`--pass`) is still fine for a personal lock.
- **Encrypt-to** (`--to`) is opt-in — only when you want a recipient’s public key to open the mark.
- **Cauchy** MDS is opt-in lab math; leave the default alone unless you know you need it.

Workshop names still work: `seal` / `unseal` / `scry` mean the same as inscribe / de-scribe / scry.

---

## What do I want to do?

### Wrap a file, check it, get it back

```
./sigil inscribe -o out.sg1 file.bin          # Reflection by default
./sigil inscribe --mode seal -o out.sg1 file.bin   # harder damage, bigger mark
./sigil scry out.sg1
./sigil de-scribe -o file.bin out.sg1
```

De-scribe is all-or-nothing: it writes to `file.bin.sigil-part` and renames it
to `file.bin` only after the whole file checks out (length and SHA-256 of every
chunk, plus the pack's chunk list for big files). If it can't restore the whole
file it exits nonzero, removes the part file and leaves any existing `file.bin`
alone. A big file whose front (the pack head) is damaged is refused with
"this file holds more than one seal" instead of quietly returning the first 4 MiB.
Folder packs and constellations work the same way for the whole folder: if any
file in it can't be restored, none are written and existing files stay as they were.

Folder:

```
./sigil inscribe -o tree.sg1 ./myfolder
./sigil de-scribe -o ./restored tree.sg1
```

### Keep versions of a live file (vault tip + dirty edit → re-seal)

```
./sigil vault track ./notes.txt
# edit notes.txt …
./sigil vault commit ./notes.txt
./sigil vault status ./notes.txt
./sigil vault versions ./notes.txt
```

Edit through an export tree, then seal a **new** tip (old seals stay untouched):

```
./sigil mount ./notes.txt ./view --vault --export-dir /tmp/sigil-dirty --writable
# edit files under /tmp/sigil-dirty …
./sigil vault commit --from-export /tmp/sigil-dirty
```

Full story: [VAULT-MOUNT-NEST.md](VAULT-MOUNT-NEST.md) · retention (full vs light + cold kit): [VAULT-RETENTION.md](VAULT-RETENTION.md) · remembered encrypt-to people: [VAULT-RECIPIENTS.md](VAULT-RECIPIENTS.md)

### Browse a mark like a folder (mount / export)

```
./sigil mount ./notes.txt ./view --vault --export-dir /tmp/view
# or FUSE when available:
./sigil mount ./notes.txt ./view --vault
./sigil umount ./view
```

### Peek inside a nested mark (breadcrumb path)

```
./sigil path tree.sg1 --into photos
./sigil path tree.sg1 --into photos -o ./extracted
```

### One tidy folder per thing (`name.sigil/`)

```
./sigil tidy ./notes.txt --dry-run    # preview: old .sgv/ → notes.txt.sigil/
./sigil tidy ./notes.txt
./sigil doctor ./notes.txt.sigil
./sigil gc ./notes.txt.sigil
```

Guide: [CONTAINER.md](CONTAINER.md)

### Append-only segment log (batches you can prove later)

```
./sigil log init events --identity me.sgk
./sigil log append events batch.json --identity me.sgk
./sigil log ls events
./sigil log verify events --signer me.pub
./sigil log prove events --seq 3 -o r.proof
./sigil log check-proof r.proof --file batch.json --signer me.pub
```

Guide: [SEGMENT-LOG.md](SEGMENT-LOG.md)

### Back up a folder into a log (only new or changed files)

```
./sigil log init photos --identity me.sgk
./sigil log add photos ./Photos --mode seal --to me.pub --identity me.sgk --dry-run   # preview
./sigil log add photos ./Photos --mode seal --to me.pub --identity me.sgk
./sigil log ls photos                                    # every file with its seq and path
./sigil log read photos --seq 12 -o beach.jpg --identity me.sgk   # one file back
```

Run the same `log add` again whenever you like. It seals only files that are new or changed (it
compares SHA-256, so it needs no key for that); unchanged files are skipped, and with nothing to do
it writes nothing. A changed file becomes a new version and the old one stays. A file you deleted
from the folder is listed as `missing from source (kept)` and is **never** removed from the log.
Symlinks and special files are skipped and listed.
To leave something out (say a Python `.tools-venv/` folder inside an export), put one pattern per
line in a `.sigilignore` file at the top of the folder (`#` starts a comment), or pass
`--exclude '.tools-venv/'` (repeatable). A skipped folder is skipped with everything inside it;
`--dry-run` lists what would be skipped, and files already in the log are never removed by this.

To keep the file names, sizes and fingerprints themselves private (for example a family photo
backup on a drive someone else could pick up), create the log with a key (`--to` and/or `--pass`);
the INDEX is then private by default. A log created with no key keeps names in the clear.

```
./sigil log init photos --identity me.sgk --to me.pub
./sigil log add photos ./Photos --mode seal --to me.pub --identity me.sgk
./sigil log ls photos --identity me.sgk                  # names and sizes need the key
```

Without the key the log's list shows only "sealed" rows; verify, mend and gc still work.

Guide: [SEGMENT-LOG.md](SEGMENT-LOG.md) ("Backing up a folder", "Private INDEX")

### Lock a mark to someone’s public key (encrypt-to)

```
./sigil keygen -o me.sgk                 # also writes me.pub
./sigil inscribe --to alice.pub -o gift.sg1 movie.mkv
./sigil de-scribe --identity me.sgk -o movie.mkv gift.sg1
```

A fingerprint printed by Sigil is just a **long ID number in code form** — you do not need to edit it by hand; copy-paste or compare with a friend.

### Unlock with a hardware passkey

```
./sigil keygen --passkey -o me.sgk       # needs a build with --features passkey
./sigil de-scribe --identity me.sgk -o movie.mkv gift.sg1   # touch + PIN
```

Guide: [PASSKEY.md](PASSKEY.md)

### Use an existing GnuPG / OpenPGP key

```
./sigil import-pgp friend.asc --pub-out friend.pub
./sigil import-pgp my-secret.asc -o me.sgk
```

Guide: [PGP-IMPORT.md](PGP-IMPORT.md)

### Cold USB kit (split a Seal across sticks)

```
./sigil kit place out.sg1 --drives 4 -o ./kit/
./sigil kit mend ./kit -o healed.sg1
```

Short note: [LRC-COLD-USB.md](LRC-COLD-USB.md)

---

## Guides (one line each)

| Guide | What it is |
|-------|------------|
| [VAULT-MOUNT-NEST.md](VAULT-MOUNT-NEST.md) | Version tip + mount/export views + nested path walk |
| [VAULT-RETENTION.md](VAULT-RETENTION.md) | Full vs light history, prune, cold kit |
| [VAULT-RECIPIENTS.md](VAULT-RECIPIENTS.md) | Remember who a vault seals to on later commits |
| [CONTAINER.md](CONTAINER.md) | One `name.sigil/` folder per thing; tidy / doctor / gc |
| [SEGMENT-LOG.md](SEGMENT-LOG.md) | Append-only sealed batches, verify, prove, shred, rotate signer |
| [PASSKEY.md](PASSKEY.md) | Lock a `.sgk` identity to a FIDO2 security key |
| [PGP-IMPORT.md](PGP-IMPORT.md) | Turn a Curve25519 OpenPGP key into Sigil key files |
| [LRC-COLD-USB.md](LRC-COLD-USB.md) | Cold kit across USB sticks |

Frozen layout: [`docs/sigil-v1.txt`](sigil-v1.txt). CLI dump: `sigil --help`.

### Advanced / lab (skip unless you need them)

| Note | What it is |
|------|------------|
| [CAUCHY-BAKEOFF.md](CAUCHY-BAKEOFF.md) | Opt-in Cauchy MDS bake-off notes |
| [FOUNTAIN-v2.md](FOUNTAIN-v2.md) | Fountain / Deluge piece experiments |
| [SOFT-RS.md](SOFT-RS.md) | Soft Reed–Solomon lab notes |
| [RS-FAST.md](RS-FAST.md) | How Reed–Solomon got fast without changing a byte |
| [FAIL-CLOSED.md](FAIL-CLOSED.md) | Unseal/mend never return part of a file silently |
| [CDC-FastCDC.md](CDC-FastCDC.md) | Opt-in FastCDC chunking profiles |
| [BREAKTHROUGHS.md](BREAKTHROUGHS.md) | Internal research log |

---

## Still deferred (later)

Not in this Friday slice — come back later:

- Nested hierarchical cards (a card of cards / roll-ups)
- Consistency proofs between anchors without the full INDEX
- Adding a signer to an unsigned log after init
- Key-ring rewrap / rotating encrypt-to recipients on an existing segment-key log
- Monthly doctor + compact dry-run routine
- INDEX roll-up of very old history

Day-to-day use does not need those.
