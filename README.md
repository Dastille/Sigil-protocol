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
command needs a passphrase. See "Known limitations": read `live`/`need`, not just `ok`.

### Repair: mend

After overwriting 200 KB in the middle of `photo.sg1`:

```
$ sigil scry torn.sg1
ok  v2  live=14/16 need=12 merkle=open keystone=intact ...
$ sigil mend torn.sg1 -o fixed.sg1
mended torn.sg1 → fixed.sg1 (live 16/16, need 12, merkle ok)
```

`unseal` also works directly on a damaged file while enough pieces are live.
When too many are gone it refuses rather than guessing:

```
$ sigil unseal -o out.jpg dead.sg1
need 12 pieces, have 5
```

### Encryption with --pass

```
$ sigil seal --pass 'correct horse' -o secret.sg1 photo.jpg
$ sigil unseal -o out.jpg secret.sg1
passphrase or --identity required
$ sigil unseal --pass wrong -o out.jpg secret.sg1
could not unwrap CEK — need matching --identity or passphrase
$ sigil unseal --pass 'correct horse' -o out.jpg secret.sg1
de-scribed 3000000 bytes → out.jpg
```

Encryption is AES-256-GCM. The passphrase is given on the command line (there is
no prompt yet), so it can land in shell history. Other key options (`--to` a
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
visible, and so are member names in an encrypted folder pack (confirmed: the
name `b.txt` appears in the clear in an encrypted folder pack). Details:
[docs/PRIVATE-LABEL.md](docs/PRIVATE-LABEL.md).

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
The log INDEX records each entry's path, size and SHA-256 in the clear.

### Other commands

`sigil --help` lists the rest (pieces/`deluge`/`gather`, `dispatch`, `boot` for
live USBs, `vault`, `mount`, `kit`, `sign`, `import-pgp`, ...). They are not
covered by the examples here; see [docs/START.md](docs/START.md) and
[crate/sigil/README.md](crate/sigil/README.md).

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

`.github/workflows/ci.yml` and `release.yml` are kept for reference, but GitHub
Actions do not run on this account (free plan billing), so no CI results appear on
commits or PRs. Run the checks above locally.

## Known limitations

- `scry` and `verify` print `ok` and exit 0 even when a file can no longer be
  recovered (for example `live=5/16 need=12`). Compare `live` with `need`, or try `unseal`.
- `--pass ''` (empty passphrase) writes an unencrypted file without warning.
- There is no `--version` flag.
- There is no interactive passphrase prompt; `--pass` takes the value on the command line.
- Damage near the start of a file costs more: the header region is used to find
  everything else, so recovery there leans on the spare header copies (Keystone)
  and loses more margin than the same damage in the middle.
- Encrypted files still reveal their ciphertext length; encrypted folder packs reveal member names.

## History

Code before October 2026 is kept on branch `archive/pre-2026-10` and tag
`pre-2026-10-import`. The current code and its commit history were imported from
`crate/sigil` and related paths of dove-bloom-star-island (main at `40e649a`).
