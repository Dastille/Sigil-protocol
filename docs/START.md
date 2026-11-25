# Start here

Friendly map of Sigil. Pick what you want to do, run the short command, then open the guide if you need more.

Plain-English walk-throughs with real output: the wiki pages in [wiki/](wiki/Home.md).
Design, threat model and measured results: the [white paper](WHITEPAPER.md).

**Defaults that keep things simple**

- Everyday Sigils use **Reflection** (default). Use **Seal** when the copy might take heavy damage (about half the pieces can die).
- A **passphrase Ward** (`--pass`) is still fine for a personal lock. Type it with `--pass -`, or in scripts read it from a private file with `--pass-file PATH` (see [Passphrases in scripts](#passphrases-in-scripts)).
- **Encrypt-to** (`--to`) is opt-in — only when you want a recipient’s public key to open the Sigil.
- **Cauchy** MDS is opt-in lab math; leave the default alone unless you know you need it.

Workshop names still work: `seal` / `unseal` / `scry` mean the same as inscribe / de-scribe / scry.

---

## What do I want to do?

### Wrap a file, check it, get it back

```
./sigil inscribe -o out.sg1 file.bin          # Reflection by default
./sigil inscribe --mode seal -o out.sg1 file.bin   # harder damage, bigger Sigil
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

### Repair a damaged file

```
./sigil mend --scan damaged.sg1      # look only: kind of damage, which repair, rough time
./sigil mend damaged.sg1             # writes damaged.mended.sg1 next to it
./sigil verify damaged.mended.sg1
./sigil mend copy1.sg1 copy2.sg1 -o fixed.sg1   # two damaged copies pooled
```

Plain `mend` tries the quick repair, then the deeper repair for bit rot, on its own. It
never writes over the damaged file or any existing file, and keeps a result only if it
passes the full check (hash tree, and the file's own hash when not encrypted). No
passphrase is needed, even for encrypted Sigils. Long repairs show a progress line, ask
first when the estimate is over about 2 minutes (`--yes` skips the question), and stop
safely on Ctrl-C. For scheduled jobs: `--max-secs SECS` skips (exit 4) a repair estimated
longer than that.

When scattered bit rot hits every piece (`live < need`), `scry` and `unseal` check whether
`mend`'s deeper repair can heal it: if so, they report `damaged — run sigil mend` (exit 5)
instead of `NOT recoverable`, and every failure prints a tailored `What you can try:` list.

Exit codes: 0 done, 1 error or key problem, 2 not recoverable / too damaged (nothing written),
3 nothing checked, 4 repair skipped, 5 damaged but repairable with `sigil mend`, 130 stopped with Ctrl-C. Guides: [MEND-SCAN.md](MEND-SCAN.md),
[SOFT-RS.md](SOFT-RS.md); walk-through: [wiki/Repairing-a-damaged-file.md](wiki/Repairing-a-damaged-file.md).

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

Full story: [VAULT-MOUNT-NEST.md](VAULT-MOUNT-NEST.md) · retention (full vs light + Frost Rune): [VAULT-RETENTION.md](VAULT-RETENTION.md) · remembered encrypt-to people: [VAULT-RECIPIENTS.md](VAULT-RECIPIENTS.md)

### Browse a Sigil like a folder (mount / export)

```
./sigil mount ./notes.txt ./view --vault --export-dir /tmp/view
# or FUSE when available:
./sigil mount ./notes.txt ./view --vault
./sigil umount ./view
```

### Peek inside a nested Sigil (breadcrumb path)

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
./sigil log prove photos --path 2024/beach.jpg -o beach.proof   # by path, after `log add`
./sigil log check-proof beach.proof --path 2024/beach.jpg --signer me.pub
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

### Lock a Sigil to someone’s public key (encrypt-to)

```
./sigil keygen --pass - -o me.sgk        # asks for a passphrase twice; also writes me.sgk.pub
./sigil inscribe --to alice.pub -o gift.sg1 movie.mkv
./sigil de-scribe --identity me.sgk -o movie.mkv gift.sg1   # asks for your passphrase
```

`--pass -` locks your identity file with a passphrase, so a copy of the file alone
opens nothing. In scripts use `--pass-file F` when making it and
`--identity-pass-file F` when using it. Plain `./sigil keygen -o me.sgk` (no
passphrase) still works but warns: anyone who copies that file can open what is
sent to you. Guide: [PASSPHRASE-IDENTITY.md](PASSPHRASE-IDENTITY.md)

A fingerprint printed by Sigil is just a **long ID number in code form** — you do not need to edit it by hand; copy-paste or compare with a friend.

### Passphrases in scripts

**In plain words:** anything you type after a command is not secret. While the
command runs, every other program on the computer can read it (that is what `ps`
shows), and your shell usually saves it in its history file. So
`--pass 'my secret'` hands your passphrase to anyone else on the machine. Put the
passphrase in a small file that only you can read, and point Sigil at the file.

```
printf '%s\n' 'my secret' > ~/.sigil-pass
chmod 600 ~/.sigil-pass                       # only you can read or change it
./sigil seal --pass-file ~/.sigil-pass -o out.sg1 file.bin
./sigil log add backup.sigil ~/Photos --pass-file ~/.sigil-pass
```

What Sigil promises (each checked by `tests/cli_pass_file.rs`):

- `--pass-file PATH` works everywhere `--pass` does (seal, unseal, scry, log, vault,
  constellation, boot, frost, …) and opens the same files: the passphrase is the
  file's **first line**, with one trailing newline or CRLF dropped.
- **It fails closed.** A missing file, an empty file (or empty first line), or the
  wrong passphrase stops with an error and writes nothing.
- **It refuses a file other people can read or change** (any group/other permission,
  like 644). The fix is `chmod 600 FILE`. Pipes are fine:
  `--pass-file <(pass show sigil)` or `--pass-file /dev/stdin`.
- `--pass` and `--pass-file` together are refused. Pick one.
- `--pass VALUE` (and `--seal-pass VALUE`) is **refused**: the command stops before
  reading or writing anything and tells you to use `--pass-file` or `--pass -`. The
  error does not repeat your passphrase. Older scripts need `--pass-file`.
- Damaged or cut-off files still fail closed (or come back byte-exact after repair)
  when the key comes from a file.
- `import-pgp --passphrase-file` follows the same rules (private file, first line).

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

### Frost Rune (split a Seal across sticks)

```
./sigil frost place out.sg1 --drives 4 -o ./frost/
./sigil frost mend ./frost -o healed.sg1
```

Short note: [LRC-COLD-USB.md](LRC-COLD-USB.md)

---

## Guides (one line each)

| Guide | What it is |
|-------|------------|
| [VAULT-MOUNT-NEST.md](VAULT-MOUNT-NEST.md) | Version tip + mount/export views + nested path walk |
| [VAULT-RETENTION.md](VAULT-RETENTION.md) | Full vs light history, prune, Frost Rune cold folder |
| [VAULT-RECIPIENTS.md](VAULT-RECIPIENTS.md) | Remember who a vault seals to on later commits |
| [CONTAINER.md](CONTAINER.md) | One `name.sigil/` folder per thing; tidy / doctor / gc |
| [SEGMENT-LOG.md](SEGMENT-LOG.md) | Append-only sealed batches, verify, prove, shred, rotate signer |
| [SFX-DESIGN.md](SFX-DESIGN.md) | Self-extracting archives with repair: recovery folder (Option 0) shipped as the script `scripts/make-recovery-kit.sh`; stubs pending |
| [INDEX-PRUNE-DESIGN.md](INDEX-PRUNE-DESIGN.md) | Design note: options for bounding INDEX growth (Option A epoch rollover chosen 2026-11-02, shipped 2026-11-08 as `sigil log epoch`) |
| [STREAMING-DESIGN.md](STREAMING-DESIGN.md) | Design note: segments above memory size (`log=9`, chunked segments); deferred 2026-11-02, not implemented |
| [RELEASE-SIGNING-DESIGN.md](RELEASE-SIGNING-DESIGN.md) | Design note: signing releases and recovery folders (minisign + SSH-signed tags, locked 2026-11-02); public key id 6AA9D817CBAC87FA is in [keys/sigil-release.pub](../keys/sigil-release.pub); no release signed yet |
| [PASSKEY.md](PASSKEY.md) | Lock a `.sgk` identity to a FIDO2 security key |
| [PGP-IMPORT.md](PGP-IMPORT.md) | Turn a Curve25519 OpenPGP key into Sigil key files |
| [LRC-COLD-USB.md](LRC-COLD-USB.md) | Frost Rune: one Seal spread across cold USB sticks |
| [MEND-SCAN.md](MEND-SCAN.md) | Repair scan, time estimate, ask-first, unattended skip, Ctrl-C stop |
| [SOFT-RS.md](SOFT-RS.md) | The deeper repair for bit rot (default inside plain `mend` since 17 Nov 2026) and its measurements |
| [KEYWRAP-SPARE.md](KEYWRAP-SPARE.md) | Encrypted files keep their key wrap twice (since 17 Nov 2026); before/after numbers |
| [PRIVATE-LABEL.md](PRIVATE-LABEL.md) | What an encrypted Sigil still shows without the key |
| [PASSPHRASE-IDENTITY.md](PASSPHRASE-IDENTITY.md) | Passphrase-protected identity files (`keygen --pass`) |
| [PACK-HEAD-REPAIR.md](PACK-HEAD-REPAIR.md) | How a damaged large-file pack head is rebuilt |
| [WHITEPAPER.md](WHITEPAPER.md) | White paper: design, threat model, measured results, limitations |

Frozen layout: [`docs/sigil-v1.txt`](sigil-v1.txt). CLI dump: `sigil --help`.

### Advanced / lab (skip unless you need them)

| Note | What it is |
|------|------------|
| [CAUCHY-BAKEOFF.md](CAUCHY-BAKEOFF.md) | Opt-in Cauchy MDS bake-off notes |
| [FOUNTAIN-v2.md](FOUNTAIN-v2.md) | Channel / Deluge piece experiments |
| [RS-FAST.md](RS-FAST.md) | How Reed–Solomon got fast without changing a byte |
| [FAIL-CLOSED.md](FAIL-CLOSED.md) | Unseal/mend never return part of a file silently |
| [CDC-FastCDC.md](CDC-FastCDC.md) | Opt-in FastCDC chunking profiles |
| [BREAKTHROUGHS.md](BREAKTHROUGHS.md) | Internal research log |

Consistency proofs between anchors now ship without the full INDEX: `sigil log prove-consistency LOG OLD:ROOT -o p` then `sigil log check-consistency p --old OLD:ROOT --signer me.pub` (see SEGMENT-LOG.md, "Consistency proofs").

Re-wrapping a segment-key log's keys to new recipients now ships: `sigil log rewrap LOG --identity me.sgk --add-to bob.pub` (or `--remove-to`, `--replace`, `--new-pass-file`); see SEGMENT-LOG.md, "rewrap".

Roll-up cards (a card of logs, a card of cards) ship as an MVP: `sigil log card day-01 day-02 --name 2026-10 --identity me.sgk -o 2026-10.card`, `sigil log check-card 2026-10.card --child day-01 --child day-02 --all --signer me.pub` One child can be proved alone (`sigil log card-prove` / `check-card-child`), and a newer card checked against an older one (`sigil log check-card-consistency`) (see SEGMENT-LOG.md, "Cards"). A log that has grown large can be rolled over into a new epoch (`sigil log epoch OLD NEW --identity me.sgk`, checked with `sigil log check-epoch NEW --archive OLD`); the old log is kept as the archive (SEGMENT-LOG.md, "Epoch rollover"; [INDEX-PRUNE-DESIGN.md](INDEX-PRUNE-DESIGN.md)).

---

## Still deferred (later)

Not built yet:

- INDEX roll-up of very old history
- Self-extracting archives with repair: options and open questions in
  [SFX-DESIGN.md](SFX-DESIGN.md) (stubs pending; the recovery folder below is shipped)

To leave a way back next to an archive (program, checksums, spec, plain-English `RECOVER.txt`; no secrets): `scripts/make-recovery-kit.sh --check photos.sg1 --bin sigil-macos --bin sigil.exe` (see SFX-DESIGN.md, Option 0).

Day-to-day use does not need those. A monthly read-only health + compaction-plan check ships as `scripts/monthly-log-retention.sh` (see SEGMENT-LOG.md, "Monthly retention check"); add `--apply --older-than 90d --seal-pass-file F` to let it compact when the log is healthy.

## Verify a download

Each GitHub release includes a `SHA256SUMS` file. `sha256sum -c SHA256SUMS --ignore-missing`
(macOS: `shasum -a 256 -c SHA256SUMS --ignore-missing`) catches accidental damage. It does not
catch a swapped file, because whoever can replace a binary can also rewrite the checksum list.

Official releases are signed with [minisign](https://jedisct1.github.io/minisign/). The public
key (id `6AA9D817CBAC87FA`) lives in [`keys/sigil-release.pub`](../keys/sigil-release.pub):

```
untrusted comment: minisign public key 6AA9D817CBAC87FA
RWT6h6zLF9ipahFYaGkWD1OdEeGyIVK4SDRi+0XIJmirk/4cSsdOqUNi
```

Compare that key in more than one place before you trust a download: this page, the README, the
file above, the white paper, and a paper copy you already have. A page that was swapped can also
swap the key printed next to it.

When a release includes `SHA256SUMS.minisig` (none has been signed yet), check the signature
first, then the checksums:

```
minisign -Vm SHA256SUMS -P RWT6h6zLF9ipahFYaGkWD1OdEeGyIVK4SDRi+0XIJmirk/4cSsdOqUNi
sha256sum -c SHA256SUMS --ignore-missing
```

(`minisign -Vm SHA256SUMS -p keys/sigil-release.pub` is the same check with the key file.)
See [RELEASE-SIGNING-DESIGN.md](RELEASE-SIGNING-DESIGN.md).
