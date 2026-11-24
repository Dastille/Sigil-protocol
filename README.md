<p align="center"><img src="assets/brand/original/og.jpg" alt="Sigil logo: gold tree of life in a circle over the SIGIL wordmark" width="600"></p>

# Sigil

Sigil wraps a file or folder into a `.sg1` file that carries its own repair data.
If part of the copy gets damaged (bad disk sectors, a cut-off download, bit rot),
`sigil` can usually rebuild the original from what is left. It also checks a hash
tree (Merkle root) over the pieces, so a swapped or altered copy is detected
instead of silently opened.

It is a file format plus a command-line tool. It is not a sync tool, network,
or key server.

New here? Read the plain-English wiki pages in [docs/wiki/](docs/wiki/Home.md)
(getting started, repairing a damaged file, keys, Frost Rune, archives, FAQ, glossary).
For the design, threat model and measured results, read the white paper:
[docs/WHITEPAPER.md](docs/WHITEPAPER.md) ([PDF](docs/WHITEPAPER.pdf)).

- Program (CLI, crate, web-lab code): [AGPL-3.0-or-later](LICENSE) ([notice](LICENSE.app))
- Byte layout ([docs/sigil-v1.txt](docs/sigil-v1.txt)): [Apache-2.0](LICENSE.SPEC), so others can write compatible readers and writers without the AGPL.

## Repository layout

| Path | What it is |
|---|---|
| `crate/sigil/` | Rust crate: the `sigil` CLI, library, integration tests, fixtures, boot hooks |
| `Cargo.toml` | Workspace root (one member, `crate/sigil`) |
| `docs/` | Format spec (`sigil-v1.txt`), everyday guide (`START.md`), feature notes |
| `src/lib/sigil/` | TypeScript codec used by the web lab, with tests against the Rust CLI |
| `scripts/` | `sigil-selftest.mjs` (standalone math self-test), `measure-repair.py` |
| `.github/workflows/` | CI and release workflows (see "CI" below) |

## Build

Needs Rust (stable, via [rustup](https://rustup.rs)). From the repository root:

```
cargo build --release
# binary: target/release/sigil
```

`cargo install --path crate/sigil` puts `sigil` in `~/.cargo/bin`.
Optional features: `--features passkey` (FIDO2 keys; Linux needs `libudev-dev` and
`pkg-config`, see [docs/PASSKEY.md](docs/PASSKEY.md)) and `--features lab` (desktop GUI `sigil-lab`).

## Everyday use

Every command and output below was run against this tree on Linux
(output trimmed). `sigil --help` and `sigil <command> --help` list all options.

### Seal and unseal

```
$ sigil seal -o photo.sg1 photo.jpg
inscribed 3000000 bytes → photo.sg1

$ sigil unseal -o photo-back.jpg photo.sg1
de-scribed 3000000 bytes → photo-back.jpg
```

The default mode, `reflection`, makes the file about 1.3× larger and survives
losing about a quarter of it (a 3 MB file became 4.0 MB: 16 pieces, any 12 rebuild it).
`--mode seal` uses about 2× space for about half. Old command names still work
(`inscribe` = `seal`, `de-scribe` = `unseal`).

### Check: scry / verify

```
$ sigil scry photo.sg1
ok  v2  live=16/16 need=12 merkle=closed keystone=intact orig=3000000 entropy=8000 name=photo.jpg
```

`live` is how many pieces are intact, `need` how many are required. Neither
command needs a passphrase. When too few pieces are left (`live` below `need`),
the line starts with `NOT recoverable` instead of `ok` and the command exits
with code 2:

```
$ sigil scry dead.sg1
NOT recoverable  v2  live=5/16 need=12 merkle=open keystone=intact ...
NOT recoverable (live=5/16 need=12): too damaged to restore from this copy; find another copy or more pieces (sigil gather), then try again
```

A constellation (`sigil constellation scry Sky` or `sigil scry Sky.sigil`) gets
the same verdict: if any listed file's star is missing or damaged beyond repair,
the report ends with a `NOT recoverable: ...` line naming those files and the
command exits with code 2. A star that is damaged but still repairable does not
count; `sigil doctor` lists it so you can mend it.

```
$ sigil constellation scry Sky
constellation  title=Sky  stars=2  unique=2
star  star  a.txt  17 bytes  d7db...
star  MISSING  sub/big.bin  200000 bytes  6705...
missing  sub/big.bin (6705...)
NOT recoverable: 1 star(s) missing: sub/big.bin
NOT recoverable (1 star(s) missing: sub/big.bin): too damaged to restore from this copy; find another copy or more pieces (sigil gather), then try again
```

`scry` counts only pieces that pass their own checksum. Bit rot spread over every piece
makes all of them fail it, so `scry` can say `NOT recoverable` (exit 2) for a file that
`sigil mend` can still repair with its deeper repair. Before giving up on a copy, run
`sigil mend --scan FILE` (it writes nothing). Captured on 23 November 2026 (build `8f03b46`)
on a 2.2 MB photo with 2 000 random bits flipped:

```
$ sigil scry rot.sg1
NOT recoverable  v2  live=0/16 need=12 merkle=open keystone=intact orig=2270725 entropy=7988 name=photo.jpg
attestation: none (no .sig beside this file)
NOT recoverable (live=0/16 need=12): too damaged to restore from this copy; find another copy or more pieces (sigil gather), then try again
$ sigil mend rot.sg1
mended rot.sg1 → rot.mended.sg1 (live 16/16, need 12, merkle ok, soft salvage)
The quick repair was not enough, so Sigil used the deeper repair for bit rot. The result passed the full check (Merkle root and true name).
Your repaired copy is rot.mended.sg1 (no -o given, so Sigil picked a new name next to the original). The damaged file was left as it is.
To double-check the repaired copy: sigil verify rot.mended.sg1
```

`sigil --version` prints the version and the git commit it was built from, e.g.
`sigil 1.0.0 (commit 76d0639)` (`-dirty` after the SHA if the checkout had
uncommitted changes, `unknown` when built without git, e.g. from a source tarball).

### Repair: mend

After overwriting 200 KB in the middle of `photo.sg1`:

```
$ sigil scry torn.sg1
ok  v2  live=14/16 need=12 merkle=open keystone=intact ...
$ sigil mend torn.sg1
mended torn.sg1 → torn.mended.sg1 (live 16/16, need 12, merkle ok)
Your repaired copy is torn.mended.sg1 (no -o given, so Sigil picked a new name next to the original). The damaged file was left as it is.
To double-check the repaired copy: sigil verify torn.mended.sg1
```

Without `-o`, the repaired copy goes next to the original as `<name>.mended.<ext>`
(`torn.mended.sg1`); if that name is taken, `torn.mended-2.sg1`, `-3`, and so on. It never
writes over the original or over a file that already exists. `-o fixed.sg1` still picks
the name yourself.

To look before repairing, `sigil mend --scan` says what kind of damage it found, which
repair it needs and a rough time, and writes nothing:

```
$ sigil mend --scan torn.sg1
Scan: one damaged stretch (a wiped or unreadable area). Shards: 14 good, 2 damaged, 0 missing.
Repair: the quick repair should be enough.
Estimated time: under 10 seconds on a computer like the one this was measured on (a rough guess, padded high).
Nothing was written. To repair it: sigil mend torn.sg1
```

The scan is a hint, not a verdict: `mend` still makes the final call and still keeps a
result only if it passes the full check. Scripts and scheduled jobs can add
`--max-secs SECS`: when the padded estimate is longer, `mend` writes nothing and exits 4
("repair skipped") so the job can report it instead of running for hours. Plain `mend`
prints the scan before it starts when the estimate is 10 seconds or more. The time model
and its measurements are in [docs/MEND-SCAN.md](docs/MEND-SCAN.md).

Long repairs (since 19 November 2026):

- On a terminal, after 5 seconds a one-line progress note shows on stderr (time so far,
  rough time left, chunks done for a large-file pack). Short repairs stay quiet.
- On a terminal, if the estimate is over about 2 minutes, `mend` asks first. Only `y`
  starts; Enter or anything else writes nothing and exits 4. `--yes` (`-y`) skips the
  question.
- With nobody to ask (no terminal, or `--json`) and no `--max-secs`, a repair estimated
  over 15 minutes is skipped (exit 4, nothing written); `--yes` runs it anyway.
- Ctrl-C stops a running repair safely: nothing is written, the original is unchanged,
  exit 130. Ctrl-C twice quits at once.

Captured on 23 November 2026 (build `8f03b46`, 20-thread desktop). A 150 MB Sigil with
150 000 flipped bits: the scan, the progress line after 5 seconds, then the result (the
padded estimate said about 80 seconds; the repair took about 6):

```
$ sigil mend one.sg1
Scan: scattered small errors (bit rot). Shards: 0 good, 44 damaged, 0 missing.
Repair: needs the deeper repair, and the damage is heavy: it may take longer and may not succeed.
Estimated time: about 80 seconds on a computer like the one this was measured on (a rough guess, padded high).
Working on it now. Nothing is written until the result passes the full check, and Ctrl-C stops without touching the original.
Repairing… 5 seconds so far, about 70 seconds left. Ctrl-C stops safely.
mended one.sg1 → one.mended.sg1 (live 44/44, need 33, merkle ok, soft salvage)
```

The same file, stopped with one Ctrl-C after about 3 seconds (exit 130, no output file):

```
Stopping safely... nothing will be written. (Ctrl-C again quits at once.)
repair stopped: you pressed Ctrl-C. Nothing was written; one.sg1 is unchanged. Run the same command again to start over.
```

The question, shown on a small file by lowering the ask point with
`SIGIL_MEND_ASK_SECS=0` and answering `n` (exit 4):

```
This repair may take under 10 seconds (a rough guess, padded high).
Your file is safe either way: nothing is written until the result passes the full check.
Keep going? [y/N] repair skipped: you chose not to start it now. Nothing was written; rot.sg1 is unchanged. To repair it later without this question:
  sigil mend --yes rot.sg1
```

The 2-minute and 15-minute points can be changed with `SIGIL_MEND_ASK_SECS` and
`SIGIL_MEND_UNATTENDED_SECS` (whole seconds). See [docs/MEND-SCAN.md](docs/MEND-SCAN.md).

Plain `mend` tries the quick repair first (rebuild from the pieces whose checksums still
pass). If that is not enough it moves on, by itself, to the deeper repair for bit rot below
and says so. Either way the result is kept only if the hash tree (and, when not encrypted,
the file hash) match; otherwise it writes nothing, exits 2 and prints the next command to
try. `--hard-only` skips the deeper repair; `--soft` still works as before.

Scattered bit flips (radiation, bit rot) spread over many pieces break every
piece's checksum, so plain `unseal` and the quick repair refuse. The deeper repair (plain
`sigil mend`, or `sigil mend --soft`) repairs
them byte column by byte column (up to 2 wrong bytes per column in Reflection, 4
in Seal, fewer when pieces are missing; a wiped piece counts as missing, and a piece's
own checksum can settle a few columns past that) and keeps the result only if the hash
tree and file hash match. It checks the whole file once, not once per guess, so a 10 MB
file that is too damaged is refused in about a second instead of after many minutes. Measured on a 1 MB file: 1 024 flipped bits repaired in
10 of 10 trials (Reflection). Details and limits: [docs/research/DEEP-SPACE.md](docs/research/DEEP-SPACE.md).

Two or more damaged copies of the same Sigil can be mended together: `mend`
pools the good pieces from every copy. Here each copy lost 45 KB (one at the front,
one at the end) and neither can be mended alone:

```
$ sigil mend copy1.sg1 -o fixed.sg1
could not repair copy1.sg1: too damaged to rebuild from this copy (soft mend could not reconstruct a true-name match). Nothing was written.
If you have another copy of this Sigil (a backup, a USB stick), give both and Sigil will combine their good parts:
  sigil mend copy1.sg1 other-copy.sg1
$ sigil mend copy1.sg1 copy2.sg1 -o fixed.sg1
mended 2 copies → fixed.sg1 (good shards per copy: copy1.sg1 (11/16), copy2.sg1 (11/16); pooled 16/16, need 12; now live 16/16, merkle ok)
```

This works for single-file Sigils (plain or encrypted; no passphrase needed). It
refuses, and writes nothing, when the copies are of different Sigils, when two
copies hold different contents for the same piece, or when the rebuilt file does
not match its hash tree. `--soft` works on one copy at a time. Large-file work
packs and folder packs are mended one copy at a time.

Folder wraps mend too: `sigil mend folder.sg1 -o fixed.sg1` heals each damaged file
inside (small files and large ones) and says which. If any file inside is beyond
repair, nothing is written. The folder's own index (file names and sizes) has no
spare copy — if that is hit, mend says so; restore from another copy.
`sigil verify folder.sg1` prints `needs mend: <files>` when files inside are damaged
but still repairable (exit 0, like `merkle=open` on one file), and `NOT recoverable`
(exit 2) when they are not.

Two opt-in shortcuts use the same repair (plain `unseal` stays strict by default):

- `sigil unseal --repair -o out.jpg flipped.sg1` repairs in memory and opens, without
  writing a mended copy. It prints a warning that the file on disk is still damaged,
  and writes nothing at all if the repair or the checks fail (wrong passphrase too).
- `sigil doctor --scrub DIR` checks every `.sg1` in a folder, repairs flipped bits, and
  rewrites a Sigil only when the hash tree and file hash match. A Sigil it cannot fix is
  listed as UNCORRECTABLE and left byte-for-byte as it was (exit code 2). Run it on a
  schedule so small damage is fixed before it piles up. It cannot check piece files
  (`.sgp` from `sigil frost place` or `sigil scatter`): it lists them as NOT CHECKED, says
  what to run instead, and exits 3 so a scheduled scrub of cold drives never looks clean.
  A wrong path, a file instead of a folder, or a folder with no `.sg1` Sigils in it also
  exits 3 with a plain message (`no Sigil files found in DIR, nothing was checked`), so a
  scrub that checked nothing never reports success.
  `--scrub` cannot be combined with `--json` (refused with an error).

```
$ sigil doctor --scrub frost
scrub: 0 Sigil(s), 0 repaired, 0 uncorrectable, 0 clean
NOT CHECKED: 4 piece file(s) (.sgp). Scrub only checks .sg1 files, so these were not checked at all and may be damaged or missing.
  frost: Frost Rune folder, 4 piece(s). Check it with: sigil frost mend frost -o check.sg1 && sigil verify check.sg1
```

`unseal` also works directly on a damaged file while enough pieces are live.
When too many are gone it refuses rather than guessing:

```
$ sigil unseal -o out.jpg dead.sg1
need 12 pieces, have 5
```

### Exit codes

Every command ends with one of these codes, so scripts and scheduled jobs can tell what
happened (source: `classify_exit` in `crate/sigil/src/main.rs`; scrub and doctor reports in
`scrub.rs` / `doctor.rs`):

| Code | Meaning | Examples |
|---:|---|---|
| 0 | Done; or checked and fine | `seal`, `unseal`, `mend` succeeded; `scry` / `verify` ok (also when a `needs repair` line is printed); `mend --scan` ran |
| 1 | Error, or a key problem | wrong or missing passphrase or identity; unreadable input; `unseal` or `frost mend` with too few pieces (`need 12 pieces, have 5`); `doctor` warnings |
| 2 | Too damaged (nothing written), or a usage error | `scry` / `verify` `NOT recoverable`; `mend` could not repair; `doctor --scrub` found an uncorrectable Sigil; a refused option such as `--pass VALUE` |
| 3 | Nothing could be checked | `doctor --scrub` on Frost Rune pieces or a folder with no `.sg1`; `boot` found no Sigil |
| 4 | Repair skipped, nothing written | `mend --max-secs` estimate too long; "no" at the `Keep going?` question; unattended repair estimated over 15 minutes |
| 130 | Stopped with Ctrl-C, nothing written | `mend` stopped safely |

A failed `mend` leaves the damaged file exactly as it was and writes no output file.

### Encryption with a passphrase

The passphrase never goes on the command line (`--pass VALUE` is refused): put it in
a file only you can read, or type it with `--pass -`.

```
$ printf '%s\n' 'correct horse' > pw.txt && chmod 600 pw.txt
$ sigil seal --pass-file pw.txt -o secret.sg1 photo.jpg
$ sigil unseal -o out.jpg secret.sg1 < /dev/null
passphrase or --identity required
$ sigil unseal --pass-file wrong.txt -o out.jpg secret.sg1
could not unwrap CEK — need matching --identity or passphrase
$ sigil unseal --pass-file pw.txt -o out.jpg secret.sg1
de-scribed 3000000 bytes → out.jpg
```

Encryption is AES-256-GCM. To type the passphrase without it showing (and
without it landing in shell history), use `--pass -`; `seal` asks twice:

```
$ sigil seal --pass - -o secret.sg1 photo.jpg
Passphrase:
Same passphrase again:
inscribed 3000000 bytes → secret.sg1
$ sigil unseal -o out.jpg secret.sg1
Passphrase:
de-scribed 3000000 bytes → out.jpg
```

`unseal` of an encrypted file with no key asks on its own when run in a
terminal. An empty passphrase (`--pass ""`) is refused everywhere. The Rust
library does the same: passing `Some("")` to `seal`, `unseal`, folder or
large-file pack functions is an error, never "no passphrase" (pass `None` for an
unencrypted file). In plain words: an empty password is treated as a mistake, so
it can never quietly open or write a file without protection.

A password made only of spaces (or tabs) counts as empty too: refused when sealing
and when opening. Spaces *around* a real password are kept exactly as typed on new
files (` pw ` and `pw` are different passwords). Very old Ward-locked files always
ignored surrounding spaces, and still do, so they keep opening. If you ever sealed a
file with a spaces-only password on an older Sigil, open it with that older version
and seal it again with a real password.

For scripts, put the passphrase in a file only you can read and use
`--pass-file` (accepted everywhere `--pass` is; `log compact` also has
`--seal-pass-file`):

```
$ printf '%s\n' 'correct horse' > ~/.sigil-pass && chmod 600 ~/.sigil-pass
$ sigil seal --pass-file ~/.sigil-pass -o secret.sg1 photo.jpg
$ sigil unseal --pass-file ~/.sigil-pass -o out.jpg secret.sg1
```

Sigil uses the file's first line (a trailing newline or CRLF is dropped) and
refuses, writing nothing, if the file is missing, empty, or readable or writable
by other users (`chmod 600` fixes that). A pipe works too:
`--pass-file <(pass show sigil)` or `--pass-file /dev/stdin`.
`--pass VALUE` is refused (nothing is read or written; the error does not repeat
the value): while `sigil` runs, any program on the computer can see the command
line (`ps`), and your shell may save it in history. See "Passphrases in scripts" in [docs/START.md](docs/START.md). Other key options (`--to` a
public key, `--identity`, `--talisman` key file, passkeys) are described in
`sigil seal --help` and [docs/START.md](docs/START.md); they are not shown here.

Your identity key can be locked with a passphrase (Argon2id + AES-256-GCM; the plain secret
is never written to disk):

```
$ sigil keygen --pass - -o me.sgk
Passphrase:
Same passphrase again:
identity → me.sgk  (passphrase-protected)  x25519 …
public → me.sgk.pub  (encrypt-to: --to me.sgk.pub)
attest seed is inside .sgk; sign with --key me.sgk
keep the passphrase safe: without it this identity cannot be opened (there is no reset)
$ sigil unseal --identity me.sgk -o out.jpg secret.sg1        # asks for it (hidden)
$ sigil unseal --identity me.sgk --identity-pass-file ~/.id-pass -o out.jpg secret.sg1
```

`--identity-pass-file PATH` follows the `--pass-file` rules and works wherever an identity is
opened. `sigil identity protect --pass - me.sgk --in-place` locks an existing plain identity.
Details and file layout: [docs/PASSPHRASE-IDENTITY.md](docs/PASSPHRASE-IDENTITY.md).

### Private labels

Encrypted single files are written with a private label (header v3): the file
name, size and entropy are stored inside the encryption, and the outer
"true-name" slot holds a keyed HMAC-SHA256 fingerprint instead of the
plaintext SHA-256:

```
$ sigil scry secret.sg1
ok  v3  live=16/16 need=12 merkle=closed keystone=intact label=private (name, size and fingerprint inside the lock)
```

Repair and checking still work without the key. Ciphertext length is still
visible. Details: [docs/PRIVATE-LABEL.md](docs/PRIVATE-LABEL.md).

### Folder packs

```
$ sigil seal -o album.sg1 album
folder 2 files, 4 bytes → album.sg1
$ sigil scry album.sg1
folder  files=2 dirs=1
dir   sub/
file  a.txt  2 bytes
file  sub/b.txt  2 bytes
$ sigil unseal -o album-out album.sg1
de-scribed 2 files → album-out
$ sigil unseal --only sub/b.txt -o just-b album.sg1
de-scribed 1 files → just-b
```

An **encrypted** folder pack (`--pass` or `--to`) hides its file names, folder
layout and per-file sizes. There is no flag for this; it is always on. Without the
key, `scry` shows only how many files there are and whether the pack is healthy:

```
$ sigil seal --pass-file pw.txt -o secret-album.sg1 album
folder 2 files, 4 bytes → secret-album.sg1
$ sigil scry secret-album.sg1
folder  2 files (names hidden)
body  ok  v3  live=16/16 need=12 merkle=closed keystone=intact label=private (name, size and fingerprint inside the lock)
$ sigil scry --pass-file pw.txt secret-album.sg1
folder  files=2 dirs=1
dir   sub/
file  a.txt
file  sub/b.txt
$ sigil unseal --pass-file pw.txt --only sub/b.txt -o just-b secret-album.sg1
de-scribed 1 files → just-b
```

Per-file passwords (`--ward-file PATH=PWFILE`) lock single files inside the pack, on
top of the folder key. A ward needs `--pass` or `--to` as well, so the names stay
hidden; to open, give both:

```
$ printf '%s\n' room-key > room.txt && chmod 600 room.txt
$ sigil seal --pass-file pw.txt --ward-file sub/b.txt=room.txt -o secret-album.sg1 album
folder 2 files, 4 bytes → secret-album.sg1
$ sigil unseal --pass-file pw.txt --ward-file sub/b.txt=room.txt -o album-out secret-album.sg1
de-scribed 2 files → album-out
$ sigil seal --ward-file sub/b.txt=room.txt -o w.sg1 album
a folder pack locked only with --ward would show every file name and size to anyone: add --pass (or --to) to hide them (the wards still lock their files), or add --ward-names-visible to accept visible names
```

`--ward-names-visible` is the opt-in for a ward-only pack (the old layout): it
warns, then writes a pack whose names, sizes and unwarded files anyone can read;
only the warded files' contents are locked. `vault track` refuses ward-only folder
vaults the same way. Ward-only packs made before this change still open.

A ward password typed as `--ward PATH=PASSWORD` would show in the process list and
your shell history, so Sigil **refuses** it (nothing is read or written, and the error
does not repeat it), like a literal `--pass VALUE`. Keep it off the command line with
`--ward-file PATH=PWFILE` (same rules as `--pass-file`: the first line of a file only
you can read) or `--ward PATH=-` (type it, hidden; asked twice when sealing). Both
work everywhere `--ward` does; `--ward PATH=-` needs a terminal and never reads piped
input. Giving one path two passwords is refused.

```
$ sigil seal --pass-file ~/.sigil-pass --ward-file sub/b.txt=$HOME/.room-pass -o secret-album.sg1 album
folder 2 files, 4 bytes → secret-album.sg1
```

`mend`, `scry`, `verify` and `doctor` still work without the key. Encrypted
folder packs written before this change still open (and still show their names);
seal the folder again to hide them. Details: "Folder packs" in
[docs/PRIVATE-LABEL.md](docs/PRIVATE-LABEL.md).

### Segment log (append-only backups)

A log is a `name.sigil/` folder of sealed segments chained by a hash INDEX.
`log add` backs up a folder, sealing each new or changed file as a segment;
unchanged files are skipped and deleted files are reported, never removed.

```
$ sigil log init backup
log backup.sigil  created (unsigned: ...)
$ sigil log add backup proj --exclude build/
  + .sigilignore  13 bytes  new → segment 1
  + src/main.c  2 bytes  new → segment 2
  x build/  excluded by "build/" (--exclude)
  x notes.tmp  excluded by "*.tmp" (.sigilignore line 2)
log add backup.sigil from proj: added 2, changed 0, unchanged 0, missing 0, skipped-special 0, excluded 2 ...
$ sigil log add backup proj --exclude build/
log add backup.sigil from proj: added 0, ... unchanged 2, ... (nothing to do: log unchanged)
$ sigil log add backup proj --exclude build/ --cache   # opt-in: skip re-hashing files whose size+times are unchanged
$ sigil log verify backup
result: healthy
```

- `--exclude PATTERN` (repeatable): `*`, `?`, `[a-z]` stay in one folder, `**` crosses
  folders, a name without `/` matches at any depth, a leading `/` anchors at the
  folder root, a trailing `/` means folders only.
- `DIR/.sigilignore`: same patterns, one per line, `#` comments. Here it held `*.tmp`.
- `--no-ignore-file`: ignore `.sigilignore`; only `--exclude` applies
  (with it, `notes.tmp` showed up as new).
- `--dry-run`: show what would happen, write nothing.

`log ls`, `log read`, `log prove`, `log tombstone`, `log compact` and more:
`sigil log --help` and [docs/SEGMENT-LOG.md](docs/SEGMENT-LOG.md).

**See what a log holds at a glance** (`log ls --pretty`, also `sigil path LOG --pretty`):
identity, condition, extent, live files by folder (big folders on one line), current root.
The default condition is a fast check (INDEX chain, signed HEAD, every segment file present;
no segment bytes read) and the page says so; `--deep` runs the full `log verify`.

```
$ sigil log ls backup --pretty --exclude .tools-venv/
  /home/me/backup.sigil
  ──────────────────────────────────────────────────────────────────────────
  LOG       backup.sigil
  FORMAT    segment log, format 1
  SIGNED    yes, by key b9d4186edf156b96
  STATUS    healthy
            fast check: chain, HEAD, 6,765 segments present
            deep check NOT run (add --deep, or sigil log verify)
  FILES     4,240 live files · 0 tombstoned · 2,423 excluded-kept
  ...
  posts/                                              3,952 files  12.1 GiB
  ROOT      fed422e8ae762c028bc2c95fa6870bc907766799200a1908f7dae743a19c8d25
$ sigil log ls backup --pretty --expand posts --recent 5   # list one folder; newest 5 files
$ sigil log read backup --name posts/photo.jpg -o photo.jpg  # one file by its stored name
```

`--exclude` counts live files that `log add --exclude` would keep without updating
("excluded-kept"). `log read --name` takes the path inside the backed-up folder (or a bare
file name when only one folder has it) and reads its newest live version; an unknown,
ambiguous or deleted name is refused. Color only on a terminal; `NO_COLOR` turns it off,
`SIGIL_ASCII=1` gives plain ASCII rules.

`log verify` checks a big segment without copying it into memory (it is memory-mapped, and the
redundancy check runs a megabyte at a time): private memory stays a few MiB whatever the
segment size. Measured numbers: [docs/SEGMENT-LOG.md](docs/SEGMENT-LOG.md#verify-memory).
The log INDEX records each entry's path, size and SHA-256. A log created with
no key (as above) keeps them in the clear, and `log init` says so.

**Private INDEX (default with a key).** Create the log with `--pass` and/or
`--to` and those three are sealed (AES-256-GCM) under an index key wrapped to
them; no extra flag is needed. Every segment must then be encrypted. Without the
key, `log ls` shows `sealed`:

```
$ sigil log init photos --identity me.sgk --to me.pub
$ sigil log add photos Photos --to me.pub --identity me.sgk
  + 2024/beach.jpg  3 bytes  new → segment 1
$ sigil log ls photos
  1    2026-10-22T13:14:30Z  sealed      sealed             ok
$ sigil log ls photos --identity me.sgk
  1    2026-10-22T13:14:30Z  3           98ea6e4f216f2fb4…  ok  2024/beach.jpg
$ sigil log prove photos --seq 1 --identity me.sgk -o beach.proof
$ sigil log check-proof beach.proof --file Photos/2024/beach.jpg --signer me.pub
  file matches the entry's bytes (SHA-256 and size)
$ sigil log prove photos --path 2024/beach.jpg --identity me.sgk -o beach.proof   # or by path
$ sigil log check-proof beach.proof --path 2024/beach.jpg --signer me.pub
```

Get a file or a whole folder back by its path (checked, never overwrites):

```
$ sigil log restore photos 2024 -o Photos-2024 --identity me.sgk
  + beach.jpg  3 bytes  (segment 1)
log restore: 1 file(s), 3 byte(s) → Photos-2024
$ sigil log restore photos 2024 --at 2026-10-01 -o Photos-Oct1 --identity me.sgk   # as it was then
```

Change who can open a key-wrapped log (segment keys or private INDEX) without
re-sealing anything:

```
$ sigil log rewrap photos --identity me.sgk --add-to partner.pub
log rewrap photos.sigil: the index key
```

Roll daily logs up into a signed monthly card (and cards into a yearly card),
then check any level against its children:

```
$ sigil log card day-01 day-02 --name 2026-10 --identity me.sgk -o 2026-10.card
$ sigil log check-card 2026-10.card --child day-01 --child day-02 --all --signer me.pub
card OK: 2026-10 (2 children) root …, signed by …
$ sigil log card-prove 2026-10.card 2 -o day02.cardproof     # receipt for one child only
$ sigil log check-card-child day02.cardproof --signer me.pub --child day-02
$ sigil log check-card-consistency 2026-10.v1.card 2026-10.card --child day-01   # v2 extends v1
```

Later, prove that an anchor you pinned (`SEQ:ROOT` from `log ls`) is a prefix of
today's log, checkable without the INDEX:

```
$ sigil log prove-consistency photos 1:<ROOT> -o since1.proof
$ sigil log check-consistency since1.proof --old 1:<ROOT> --signer me.pub
consistency proof OK: 1:… is a prefix of 4:…
```

`sigil mount photos mnt --identity me.sgk` (or `--export-dir DIR`) shows one
file per live segment; without the key the mount is refused.

Keyless `log verify`, `mend` and `gc` still work. Entry count, times and
on-disk segment sizes stay visible. `--private-index` is still accepted.
`--public-index` opts out (names, sizes and hashes in the clear) and prints a
warning. Logs created before this change keep the INDEX they were made with; `sigil log privatize OLD NEW --pass-file pw.txt` copies one into a new private log (the old folder and its backups still show the names until you delete them). Details: "Private INDEX" in
[docs/SEGMENT-LOG.md](docs/SEGMENT-LOG.md).

A log that has grown large can be rolled over into a new epoch:
`sigil log epoch events events-2027 --identity me.sgk` closes `events` at its
HEAD, signs a card over it, and starts `events-2027` with a first line that
names the old log and copies the live data across. `sigil log check-epoch
events-2027 --archive events` checks the link. The old log is only read and
stays as the archive (sigil never deletes it); restoring a version from before
the cut needs it. Details: "Epoch rollover" in
[docs/SEGMENT-LOG.md](docs/SEGMENT-LOG.md).

### Other commands

**Channel** (`sigil deluge --channel`; old `--fountain` still accepted) pours a Sigil out as
**mana**: `.mana` files (`mana-<block>-<id>.mana`, RaptorQ codec) with random symbol IDs, so
several people can rain the same file into one folder without coordinating
(`--sequential` = the old 0, 1, 2, ... order). `--extra N` is a target, not an
increment: running deluge again into the same folder tops it up to N spare packets
beyond what the file needs (only valid packets of that file count; damaged, forged or
other files' packets are reported and left alone), and writes nothing if it is already
there. `--loss P` (for example `--loss 10%`) replaces `--extra`: Sigil works out
how many spare packets to send so the chance the far side cannot rebuild without a
resend is at most 1 in 10 000, assuming each packet is lost independently (no long
outages); the math and its limits are in `crate/sigil/src/fountain_loss.rs`. `sigil gather` skips damaged or
stray packet files and, when short, says `have 4 of 10 needed, need 6 more`
([docs/FOUNTAIN-v2.md](docs/FOUNTAIN-v2.md)).

On a slow or one-way link the receiver can ask for just what is missing:
`sigil gather --report rx/` prints one short line (`SGNAK1 <id> <blocks> <have>/<need>
<list>`, under 1 KiB even for 100 blocks). Send that line back; the sender runs
`sigil deluge --channel --answer "<line>" -o out/ file.sg1`, which writes exactly the
missing number of fresh packets per block. A report for a different file is refused.
RaptorQ occasionally needs one or two packets beyond the exact count; report again if so.
The numbered-piece options `--from`, `--only-rain` and `--watch` do not apply to a channel and
are refused with `--channel` (they used to be silently ignored); use `--report` / `--answer` instead.

**`gather --partial` (for scripts).** If there are not enough packets yet, gather still
fails (exit 2) and still writes **no** Sigil — it never leaves a pretend-complete archive.
With `--partial` it also writes `OUT.partial.json` (or, with `--json`, one JSON line on
stdout) saying how far it got: `packets_accepted`, `packets_needed`, `packets_more`,
damaged and foreign packet files (never counted as progress), the `--report` line and
the reason. When there are enough packets, `--partial` changes nothing.

`sigil --help` lists the rest (pieces/`deluge`/`gather`, `dispatch`, `boot` for
live USBs, `vault`, `mount`, `frost`, `sign`, `import-pgp`, ...). They are not
covered by the examples here; see [docs/START.md](docs/START.md) and
[crate/sigil/README.md](crate/sigil/README.md).

## Play a sealed film or song (`sigil show`)

`sigil show film.sg1 --plex ~/Media/Movies` serves ONE sealed file over plain HTTP at
`http://127.0.0.1:7845/play` and writes `Film.strm` (a one-line file with that URL) into
your library folder.

- **Works with anything that plays a URL and seeks with HTTP Range:** Plex and
  Jellyfin (and Kodi/Emby) through the `.strm`, VLC "Open Network Stream", mpv, a browser.
  There is no codec plugin — the player just sees an ordinary web video.
- **Want it in every app (Finder, Explorer, editors)?** Use `sigil mount` (FUSE) instead.
- **Large-file packs** unlock only the 4 MiB slices the player reads (seeking jumps
  straight there; at most 8 slices are kept in RAM). A plain small `.sg1` is unsealed
  once to a temp file, deleted after `--idle` seconds of no reads.
- Several connections at once are fine (players probe, play and seek in parallel).
  Seeking near the end (`Range: bytes=-N`) works.
- If part of a large pack is not copied yet, the player gets "416" with
  `X-Sigil: overture-incomplete` instead of wrong bytes.
- Folder wraps and constellations are refused: `show` plays one file.
- Local only by default (`--bind 127.0.0.1:7845`). If the player is on another PC, set
  `--bind 0.0.0.0:7845 --public http://THIS-PC:7845` — anyone on the network who can
  reach that port can then watch it (no password on the HTTP side).

## Scripts and pipes

**Seal straight from a pipe.** Use `-` as the input and Sigil reads stdin:

```sh
pg_dump mydb | sigil seal - --pass-file ~/.sigil-pass -o dump.sg1 --stdin-name mydb.sql
```

- The pipe is copied into a private temp folder next to `-o` (so big dumps take the
  normal large-file path) and that folder is removed when the seal ends.
- **Empty stdin is refused** (exit 1, no Sigil written): if `pg_dump` failed you get an
  error, not an empty backup. A terminal on stdin is refused too.
- Passphrase rules are the same as always: use `--pass-file` or `--to` in scripts
  (stdin is busy carrying the data). `--stdin-name` sets the name stored inside.

**Unseal to stdout.** `sigil unseal dump.sg1 --pass-file ~/.sigil-pass -o - | psql mydb`.
Works for one file (plain `.sg1` or a large-file pack, also with `--star` / `--from-mb` /
`--to-mb`). Not for folder wraps or constellations. A large pack streams part by part;
if a later part fails, the exit code is not 0 — treat that output as incomplete.

**`--json`** on `seal`, `unseal`, `verify`, `scry`, `mend`, `scatter`, `gather`, `frost place`,
`frost mend`, `path`, `vault` (all subcommands), `constellation`, `gc`, `tidy`, `sign`, `deluge`,
`keygen`, `seal-folder-names` (and `doctor`, which already had it) prints
exactly one JSON line on stdout; the friendly lines move to stderr.

```json
{"ok":true,"cmd":"seal","exit":0,"output":"dump.sg1","output_bytes":12345}
{"ok":false,"cmd":"unseal","exit":1,"error":"..."}
```

`verify --json` adds `"report"` (the normal text) and, with a deep read, `"read_data"`.
`scry --json` adds the same `"report"`. Both (and `constellation scry --json`) also add a structured
`"status"` object (`"schema":1`, additive — `report` stays) built from library data, not
the text: `kind` (`mark` = a single Sigil, `work-pack`, `folder-pack`, `constellation`; JSON values are stable), `health`
(`healthy`, `needs-repair`, `not-recoverable`), `reason` (why not recoverable, else null),
`repair` (what needs `sigil mend`, else null). A Sigil adds `version`, `shards` (`live`,
`total`, `need`, `len`), `merkle_closed`, `header_recovered`, `encrypted`, `compressed`,
`private_label`, `orig_len` (null when private); a large-file pack adds `parts` (`total`,
`present`), `chunk_size`, `overture`, `orig_len`; a folder pack adds `members` and
`encrypted`; a constellation adds `stars` (`members`, `packed`, `present`, `missing`,
`needs_repair`, `beyond_repair`). A not-recoverable copy is `ok:false`, exit 2, and still
carries `status`. New fields may be added within schema 1; a rename or removal bumps it. `mend --json` adds `"kind"` (`mark`, `folder-pack`,
`sealed-folder-pack`, `work-pack`) and, for one Sigil (`kind` `mark`), `"live"`, `"n"`, `"need"`, `"merkle"`,
`"soft_salvage"` (counted on the mended copy); a work pack adds `"stars"`, `"facets_checked"`.
`scatter --json` adds `"pieces"`; `frost place --json` adds `"drives"`, `"pieces"`, `"per_drive"`,
`"star"`; `frost mend --json` has `"output"` / `"output_bytes"`. For script stability their
`"cmd"` field still reads `"kit place"` / `"kit mend"` (the deprecated alias names). A copy too damaged to mend is
`"ok":false` with the error, exit 1, and no output file.

More `--json` (same one-line shape): `path --json` adds `"view"` (`trail`, `kind`, `name`,
`nest_payload`, `entries` with `path` / `size` / `nest` / `sha256`; an encrypted pack lists names
only with its key, otherwise `ok:false`; `-o` adds `"output"`; not with `--pretty`; a log,
constellation or vault folder is refused with a pointer to `log ls --json` / `doctor --json` /
`vault versions --json`). `vault status --json` adds `"status"` (`drift`, `tip`, live and tip
SHA-256, `tip_size`); `vault versions --json` adds `"chart"` (`versions` with `n`, `seal`,
`sha256`, `size`, `time`; `recipients` is a count). `gc --json` and `tidy --json` add
`"report"` (items / moved files, bytes, `apply` / `dry_run`); `sign --json` adds
`"attestation"` (the `.sig` path).

Also with `--json`: `constellation add` (`added`, `linked`, `skipped`, `replaced`,
`new_bytes`), `constellation scry` (`report`; not recoverable is `ok:false`, exit 2),
`constellation atlas` (`files`, `output`), `constellation remove` (`dry_run`, `removed` names,
`stars_freed`, `remaining`); `vault track` / `commit` / `restore` (`version`, `size`, `sha256`;
commit adds `skipped`, restore adds `mended`), `vault prune` (`kept`, `tip`, `removed`),
`vault remove` (`removed`, `tip`, `remaining`, `dry_run`), `vault recipients` / `retention`
(`ok` only; their text goes to stderr); `deluge` (`output`; not with `--watch`); `keygen`
(`output`, `output_bytes`; never key material); `seal-folder-names` (`output`, `files`,
`out_bytes`). Output of helper programs started with `--rsync` / `--rclone` / `--wormhole` is
not captured and may reach stdout.

`keygen --json` also adds `public` (the `.pub` path), `x25519` (public hex) and `passkey`
(and `passphrase:true` with `--pass` / `--pass-file`).
`identity info --json` adds `kind` plus public `x25519` / `ed25519` hex, or for a
passkey-protected key `kind:"passkey-protected"` and `report` (slots; no wrapped bytes), or for
a passphrase-protected key `kind:"passphrase-protected"`, `report` and the public hex;
`identity protect` / `add-passkey` / `remove-passkey` / `unprotect` and `boot prepare` /
`mend` / `install` print `ok` only. `import-pgp --json` adds `fingerprint`, `encrypt_subkey`,
`user_id`, `key_version`, `public`, `x25519` and `identity` (the written path, or null) — never
secret key bytes. `overture --json` adds `report`; `umount --json` adds `mountpoint`;
`dispatch --json` prints `ok` (helper output is not captured). `mount --json` works only with
`--export-dir` (the FUSE mount blocks until unmounted). No `--json` on `show`, `circle` or
`open`: they are interactive / long-running. `boot` and `dispatch` success paths are not covered
by tests (they need a boot medium and rsync/rclone/wormhole).

**Exit codes** (seal / unseal / verify):

| code | meaning |
|------|---------|
| 0 | it worked / the Sigil is healthy |
| 1 | error or refused (bad key, missing file, empty stdin, wrong option combo) |
| 2 | too damaged to restore, or a deep read found a part that will not open. (Also clap's code for a mistyped command line — check `--json` `ok`.) |
| 3 | no boot Sigil found |
| 4 | `mend`: repair skipped — the estimate was over `--max-secs`, over the 15-minute unattended limit with nobody to ask, or you answered no; nothing written |
| 130 | `mend`: stopped with Ctrl-C; nothing written |

`doctor` keeps its own documented codes.

**Deep read: `verify --read-data` / `--read-data-subset 10%`.** Plain `verify` is
cheap: it checks structure and repair checksums and needs no key. Add `--read-data` to
open every part all the way back to the original bytes (decrypt + true-name check), or
`--read-data-subset 10%` to open an evenly spaced tenth. The sample moves each day, so
a daily 10% check covers the whole file in about ten days (like restic). Encrypted Sigils
need `--pass-file` / `--identity`. Nothing is written to disk. Pin the sample with
`--subset-offset N`. Works on one `.sg1`, a large-file pack, a folder pack or a
constellation (each member's star is a part; a locked card takes the same `--pass-file` /
`--identity`). An atlas bag (`.sga`) is unpacked to a scratch folder and read the same way
(`kind: atlas`). Plain `verify` / `scry` of a bag also unpacks it and checks every star. On a folder pack each sampled member is a part; an encrypted pack
needs its key, a member locked with its own `--ward` opens with `--ward-file PATH=PWFILE`
(without it, it fails as a key problem), and a nested folder pack is listed under `skipped`, never counted as opened. Each
failure carries a `cause`: `key-needed` or `wrong-key` (exit 1, a key problem, nothing shown
damaged) or `damaged` (exit 2, NOT recoverable). Unknown errors count as `damaged`.

```sh
sigil verify dump.sg1 --pass-file ~/.sigil-pass --read-data-subset 10% --json
# ... "read_data":{"kind":"work","percent":10,"offset":20752,"total_parts":40,"checked":[...],"bytes_read":...,"failed":[],"skipped":[]}
```

## Web lab

The browser lab (a TypeScript implementation that seals and opens the same `.sg1`
bytes in the page) has its codec here in `src/lib/sigil/`. The tests open
fixtures written by the Rust CLI and, with `SIGIL_BIN` set, cross-check both
directions against the binary:

```
npm ci
npm run typecheck
cargo build --release
SIGIL_BIN="$PWD/target/release/sigil" npm run test:lab
npm run selftest
```

The lab's web UI (pages, components, hosting) is still in
[dove-bloom-star-island](https://github.com/Dastille/dove-bloom-star-island) and
was not moved here.

## Tests and CI

```
cargo fmt --all -- --check
cargo clippy --all-targets -- -D warnings
cargo audit
cargo test
```

`.github/workflows/ci.yml` and `release.yml` are manual-only (`workflow_dispatch`):
they do not run on push, pull requests, tags, or a schedule (free plan billing), so
no CI results appear on commits or PRs. The merge gate is the local fmt / clippy /
audit / test checks above.

`cargo test` includes a privacy check (`crate/sigil/tests/privacy_check.rs`): it scans every
text file in the repository and fails on the generic rules in `scripts/privacy-denylist.txt`
(real home-folder and build-machine paths, machine ids), including the text of PDFs (needs
`pdftotext` from poppler-utils; without it the check fails unless `SIGIL_PRIVACY_SKIP_PDF=1`)
and image metadata. Rebuild `docs/WHITEPAPER.pdf` with `scripts/build-whitepaper-pdf.py` after
editing `docs/WHITEPAPER.md`. Public docs use neutral wording such as "Debian-based Linux" or
"maintainer decision". Project-specific terms go in an untracked
local file named by `SIGIL_PRIVACY_DENY_EXTRA`; `SIGIL_PRIVACY_SCAN_EXTRA` adds outside files
or folders (a PR body, a wiki checkout) to the scan.

## Verify a download

Each GitHub release includes a `SHA256SUMS` file listing the SHA-256 checksum of every artefact.
`sha256sum -c SHA256SUMS --ignore-missing` (macOS: `shasum -a 256 -c SHA256SUMS --ignore-missing`)
catches accidental damage. It does not catch a swapped file, because whoever can replace a binary
can also rewrite the checksum list.

Official releases are signed with [minisign](https://jedisct1.github.io/minisign/) (Ed25519).
The public key (id `6AA9D817CBAC87FA`) lives in [`keys/sigil-release.pub`](keys/sigil-release.pub):

```
untrusted comment: minisign public key 6AA9D817CBAC87FA
RWT6h6zLF9ipahFYaGkWD1OdEeGyIVK4SDRi+0XIJmirk/4cSsdOqUNi
```

Compare that key in more than one place before you trust a download: this README, the file
above, [docs/START.md](docs/START.md), the white paper, and a paper copy you already have. A
page that was swapped can also swap the key printed next to it.

When a release includes `SHA256SUMS.minisig` (none has been signed yet), check the signature
first, then the checksums:

```
minisign -Vm SHA256SUMS -P RWT6h6zLF9ipahFYaGkWD1OdEeGyIVK4SDRi+0XIJmirk/4cSsdOqUNi
sha256sum -c SHA256SUMS --ignore-missing
```

(`minisign -Vm SHA256SUMS -p keys/sigil-release.pub` is the same check with the key file.)
See [docs/RELEASE-SIGNING-DESIGN.md](docs/RELEASE-SIGNING-DESIGN.md).

## Known limitations

- `sigil keygen -o me.sgk` with no `--pass` / `--passkey` still writes the secret identity
  unprotected (owner-only file, but plain bytes) so existing scripts keep working; it prints a
  warning. Use `--pass -` or `--passkey`. A passphrase-protected identity asks for its
  passphrase on a terminal; in scripts give `--identity-pass-file PATH` (there is no
  environment-variable option).

- Unencrypted Seal pieces on Frost Rune (cold) drives are readable by anyone holding one drive.
  Each `.sgp` piece carries the header, and data pieces are slices of the payload under the fold,
  which is not a cipher; with the default 4 drives, one drive holds 2 of the 8 data pieces of a
  Seal (8,16). The plain header and the `KIT` manifest also show the file name and true name.
  Use `--to` (encrypt-to) or a passphrase when sealing anything that goes on cold drives.
  `sigil frost place` does not warn about this yet. Tested in `crate/sigil/src/kit.rs`
  (`unencrypted_seal_piece_on_one_frost_drive_is_readable_without_key`,
  `passphrase_seal_piece_on_one_frost_drive_shows_no_plaintext`).
- `sigil doctor --scrub DIR` checks only `.sg1` files. Frost Rune / scatter pieces (`.sgp`)
  are not checked; scrub lists them as NOT CHECKED and exits 3 (fails closed). Check cold
  drives with `sigil frost mend KIT -o check.sg1 && sigil verify check.sg1`. `--scrub`
  cannot be combined with `--json` (refused). See
  [docs/research/COLD-HOT-BOX.md](docs/research/COLD-HOT-BOX.md).
- `--pass -` needs a terminal: it never reads a piped stdin (use
  `--pass-file /dev/stdin` for that). Only `unseal` asks on its own when a key is
  missing. (`--pass VALUE`, `--seal-pass VALUE` and `--ward PATH=PASSWORD` on the command line are refused.)
- `sigil mend` scans first (since 18 November 2026) and, since 19 November 2026, shows a
  progress line on a terminal, asks before repairs estimated over about 2 minutes, skips
  (exit 4) unattended repairs estimated over 15 minutes, and stops cleanly on Ctrl-C (exit
  130, nothing written). Limits: the ask and the unattended skip work only on a single
  Sigil (a large-file pack is not scanned by plain `mend`, so it is never asked about or
  skipped unless `--max-secs` is given; folder packs, atlas bags and several copies are not
  scanned at all). The question comes before any repair starts (not after the quick part)
  and offers only yes/no (no "finish tonight" option yet). The progress line is time-based
  for a single Sigil (no percentage) and the estimate is not re-measured while it runs.
  Ctrl-C is checked between columns and chunks of the deeper repair; the quick repair and the
  final check are not interruptible (a stop waits for them, then writes nothing). On Windows,
  Ctrl-C ends the process the default way (still nothing written before the full check).
  A second Ctrl-C during the last instant of writing can leave a `*.mend-part` temp file
  (never the output name). A pack whose framing is damaged cannot be scanned (plain `mend`
  still tries). Time estimates are a throughput model measured on one 8-core machine and are
  unverified elsewhere. The rest of
  the planned order is in [docs/SOFT-RS.md](docs/SOFT-RS.md): a GPU option, and joint solving for more stuck columns (racing across CPU threads with a shared stop is done; it makes repair faster, not able to fix more). An explicit `-o` that names
  an existing file still replaces it (after the repair has passed its check), as before.
  When several copies are given, the deeper repair is not used (one copy at a time). Soft repair is bounded (a work cap plus at most
  2(n−k)+2 whole-file checks), so it finishes in seconds on files of tens of MB, but scattered
  damage past the per-column Reed–Solomon limit is still refused.
- Damage near the start of a file still costs more: the header region is used to
  find everything else. New seals also keep one spare header copy at the end
  (`SGKT` trailer) so a wiped front can still locate when Embers are gone too;
  if the front header, every Keystone copy and the trailer are all wiped, the
  header is still found from any surviving per-shard Ember copy, and the file
  opens and mends as long as enough shards are intact. Only when every header
  copy (front, Keystone, trailer and all Embers) is gone does it refuse; a second
  copy can then still heal it with `sigil mend A.sg1 B.sg1`.
- Encrypted files written before 17 November 2026 keep their key wrap (the ~100-byte `SGTO`
  block that unlocks the content key) in one copy: one damaged byte there makes the file
  unopenable even when all data is intact, and `sigil mend` refuses it. New encrypted files
  store it twice, far apart (SGTO v3 + `SGTS` spare, 109–121 bytes more per file), and open
  and mend when either copy survives or the two can be merged; re-seal older encrypted files
  to get this. Builds from before that date cannot open the new encrypted files (they refuse
  them; nothing wrong is written). The web lab still writes the one-copy layout. Numbers and
  tests: [docs/KEYWRAP-SPARE.md](docs/KEYWRAP-SPARE.md) (`crate/sigil/src/keywrap_spare_tests.rs`).
- Encrypted files still reveal their ciphertext length **unless** sealed with
  `--pad bucket` or `--pad max` (then only the bucket or power-of-two size
  shows). Default is `--pad off` (no silent size growth). `--pad` needs
  encryption and is single-file for now (folder / work packs not yet). Encrypted
  folder packs still reveal how many files they hold and their total encrypted
  size (not names or per-file sizes).
- Some folder packs still show member names: encrypted packs made before October
  2026, ward-only packs made before wards needed `--pass` / `--to`, and packs sealed
  with `--ward-names-visible`. Convert them with `sigil seal-folder-names OLD -o NEW
  --pass-file F` (or seal the folder again with `--pass` / `--to`); old copies keep the names.
- `sigil path` / `ls` / `walk` open an encrypted folder pack only with its key
  (`--pass-file`, `--pass -`, `--identity`); without it they refuse and show no names.
- With the key, `scry` and `path` of an encrypted folder pack show names and
  per-file sizes; this opens each member once (one decrypt per file), so a pack
  with very many files takes longer to list than a plain one. Without the key
  only the file count shows.

- There is no self-extracting archive: opening or repairing a `.sg1` needs the
  `sigil` CLI (or the web lab codec). Options are in
  [docs/SFX-DESIGN.md](docs/SFX-DESIGN.md) (stubs on hold, locked 2026-11-02). What ships instead is a
  recovery folder: `scripts/make-recovery-kit.sh ARCHIVE...` puts the program, checksums, the spec
  and a plain-English `RECOVER.txt` next to the archive (no passphrases or keys).

- `scry` and `verify` judge a file by the pieces whose own checksum still passes. Scattered
  bit rot can fail every piece's checksum, so they report `NOT recoverable` (exit 2) and
  suggest finding another copy even when `sigil mend` can repair the file with its deeper
  repair (captured 23 November 2026, see "Check: scry / verify" above). Run
  `sigil mend --scan FILE` before giving up on a copy.
- `unseal` and `frost mend` with too few pieces exit 1 (`need 12 pieces, have 0`), not 2
  like `scry` and `mend`. Scripts should treat any non-zero code as "not restored".
- The release public key is published (minisign id `6AA9D817CBAC87FA`,
  [`keys/sigil-release.pub`](keys/sigil-release.pub)), but no release has been signed yet.
  `SHA256SUMS` alone still only catches accidental damage, not a swapped file. Once a release
  includes `SHA256SUMS.minisig`, follow [Verify a download](#verify-a-download). A recovery
  folder copies the public key as `SIGNING-KEY.pub` and will copy `SHA256SUMS.minisig` when
  one is supplied; compare the key with this README and a paper copy, never only the copy in
  the folder.
- A segment-log batch is sealed and read in memory in one piece, so batches above RAM size do
  not work; split them or keep huge files as separate `sigil seal` packs. Options:
  [docs/STREAMING-DESIGN.md](docs/STREAMING-DESIGN.md) (deferred, locked 2026-11-02).
- In `scry --json` / `verify --json`, `health` combines Scry's recoverability check with
  `doctor`'s repair check; `needs-repair` errs on the cautious side. When it is `needs-repair`,
  the `scry` / `verify` text (and the JSON `report`) ends with a `needs repair: …` line pointing to `sigil mend`.

## History

Code before October 2026 is kept on branch `archive/pre-2026-10` and tag
`pre-2026-10-import`. The current code and its commit history were imported from
`crate/sigil` and related paths of dove-bloom-star-island (main at `40e649a`).
