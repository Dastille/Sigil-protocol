<p align="center"><img src="assets/brand/original/og.jpg" alt="Sigil logo: gold tree of life in a circle over the SIGIL wordmark" width="600"></p>

# Sigil

Sigil wraps a file or folder into a `.sg1` file that carries its own repair data.
If part of the copy gets damaged (bad disk sectors, a cut-off download, bit rot),
`sigil` can usually rebuild the original from what is left. It also checks a hash
tree (Merkle root) over the pieces, so a swapped or altered copy is detected
instead of silently opened.

It is a file format plus a command-line tool. It is not a sync tool, network,
or key server.

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

`sigil --version` prints the version and the git commit it was built from, e.g.
`sigil 1.0.0 (commit 76d0639)` (`-dirty` after the SHA if the checkout had
uncommitted changes, `unknown` when built without git, e.g. from a source tarball).

### Repair: mend

After overwriting 200 KB in the middle of `photo.sg1`:

```
$ sigil scry torn.sg1
ok  v2  live=14/16 need=12 merkle=open keystone=intact ...
$ sigil mend torn.sg1 -o fixed.sg1
mended torn.sg1 → fixed.sg1 (live 16/16, need 12, merkle ok)
```

Scattered bit flips (radiation, bit rot) spread over many pieces break every
piece's checksum, so plain `unseal` and `mend` refuse. `sigil mend --soft` repairs
them byte column by byte column (up to 2 wrong bytes per column in Reflection, 4
in Seal, fewer when pieces are missing) and keeps the result only if the hash
tree and file hash match. Measured on a 1 MB file: 1 024 flipped bits repaired in
10 of 10 trials (Reflection). Details and limits: [docs/research/DEEP-SPACE.md](docs/research/DEEP-SPACE.md).

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
  rewrites a mark only when the hash tree and file hash match. A mark it cannot fix is
  listed as UNCORRECTABLE and left byte-for-byte as it was (exit code 2). Run it on a
  schedule so small damage is fixed before it piles up.

`unseal` also works directly on a damaged file while enough pieces are live.
When too many are gone it refuses rather than guessing:

```
$ sigil unseal -o out.jpg dead.sg1
need 12 pieces, have 5
```

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
warning. Logs created before this change keep the INDEX they were made with. Details: "Private INDEX" in
[docs/SEGMENT-LOG.md](docs/SEGMENT-LOG.md).

### Other commands

`sigil deluge --fountain` writes RaptorQ packets with random symbol IDs, so
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
`sigil deluge --fountain --answer "<line>" -o out/ file.sg1`, which writes exactly the
missing number of fresh packets per block. A report for a different file is refused.
RaptorQ occasionally needs one or two packets beyond the exact count; report again if so.

**`gather --partial` (for scripts).** If there are not enough packets yet, gather still
fails (exit 2) and still writes **no** mark — it never leaves a pretend-complete archive.
With `--partial` it also writes `OUT.partial.json` (or, with `--json`, one JSON line on
stdout) saying how far it got: `packets_accepted`, `packets_needed`, `packets_more`,
damaged and foreign packet files (never counted as progress), the `--report` line and
the reason. When there are enough packets, `--partial` changes nothing.

`sigil --help` lists the rest (pieces/`deluge`/`gather`, `dispatch`, `boot` for
live USBs, `vault`, `mount`, `kit`, `sign`, `import-pgp`, ...). They are not
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
- **Empty stdin is refused** (exit 1, no mark written): if `pg_dump` failed you get an
  error, not an empty backup. A terminal on stdin is refused too.
- Passphrase rules are the same as always: use `--pass-file` or `--to` in scripts
  (stdin is busy carrying the data). `--stdin-name` sets the name stored inside.

**Unseal to stdout.** `sigil unseal dump.sg1 --pass-file ~/.sigil-pass -o - | psql mydb`.
Works for one file (plain `.sg1` or a large-file pack, also with `--star` / `--from-mb` /
`--to-mb`). Not for folder wraps or constellations. A large pack streams part by part;
if a later part fails, the exit code is not 0 — treat that output as incomplete.

**`--json`** on `seal`, `unseal`, `verify` (and `doctor`, which already had it) prints
exactly one JSON line on stdout; the friendly lines move to stderr.

```json
{"ok":true,"cmd":"seal","exit":0,"output":"dump.sg1","output_bytes":12345}
{"ok":false,"cmd":"unseal","exit":1,"error":"..."}
```

`verify --json` adds `"report"` (the normal text) and, with a deep read, `"read_data"`.

**Exit codes** (seal / unseal / verify):

| code | meaning |
|------|---------|
| 0 | it worked / the mark is healthy |
| 1 | error or refused (bad key, missing file, empty stdin, wrong option combo) |
| 2 | too damaged to restore, or a deep read found a part that will not open. (Also clap's code for a mistyped command line — check `--json` `ok`.) |
| 3 | no boot mark found |

`doctor` keeps its own documented codes.

**Deep read: `verify --read-data` / `--read-data-subset 10%`.** Plain `verify` is
cheap: it checks structure and repair checksums and needs no key. Add `--read-data` to
open every part all the way back to the original bytes (decrypt + true-name check), or
`--read-data-subset 10%` to open an evenly spaced tenth. The sample moves each day, so
a daily 10% check covers the whole file in about ten days (like restic). Encrypted marks
need `--pass-file` / `--identity`. Nothing is written to disk. Pin the sample with
`--subset-offset N`. Works on one `.sg1` or a large-file pack (not folder wraps yet).

```sh
sigil verify dump.sg1 --pass-file ~/.sigil-pass --read-data-subset 10% --json
# ... "read_data":{"kind":"work","percent":10,"offset":20752,"total_parts":40,"checked":[...],"bytes_read":...,"failed":[]}
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

## Known limitations

- `--pass -` needs a terminal: it never reads a piped stdin (use
  `--pass-file /dev/stdin` for that). Only `unseal` asks on its own when a key is
  missing. (`--pass VALUE`, `--seal-pass VALUE` and `--ward PATH=PASSWORD` on the command line are refused.)
- Damage near the start of a file costs more: the header region is used to find
  everything else, so recovery there leans on the spare header copies (Keystone)
  and loses more margin than the same damage in the middle.
- Encrypted files still reveal their ciphertext length. Encrypted folder packs
  reveal how many files they hold and their total encrypted size (not names or
  per-file sizes).
- Some folder packs still show member names: encrypted packs made before October
  2026, ward-only packs made before wards needed `--pass` / `--to`, and packs sealed
  with `--ward-names-visible`. Seal them again with `--pass` / `--to` to hide them.
- `sigil path` / `ls` / `walk` open an encrypted folder pack only with its key
  (`--pass-file`, `--pass -`, `--identity`); without it they refuse and show no names.
- With the key, `scry` and `path` of an encrypted folder pack show names and
  per-file sizes; this opens each member once (one decrypt per file), so a pack
  with very many files takes longer to list than a plain one. Without the key
  only the file count shows.

## History

Code before October 2026 is kept on branch `archive/pre-2026-10` and tag
`pre-2026-10-import`. The current code and its commit history were imported from
`crate/sigil` and related paths of dove-bloom-star-island (main at `40e649a`).
