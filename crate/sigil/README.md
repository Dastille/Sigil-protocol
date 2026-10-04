# sigil

Rust command for Sigil. Same `.sg1` bytes as the lab. **No size cap** on this command. v1.0.

**Build (Linux or Windows — same source)**

```
# in crate/sigil
cargo build --release
# Linux:  target/release/sigil
# Windows (from Windows, or Linux with mingw):
cargo build --release --target x86_64-pc-windows-gnu
# → target/x86_64-pc-windows-gnu/release/sigil.exe
```

```
./sigil inscribe --mode reflection --piece-mb 4 -o out.sg1 file.bin
# default mode is Reflection. Seal: --mode seal
# or force 64 parts:  --shards 64

./sigil scry out.sg1
./sigil de-scribe -o file.bin out.sg1
```

Large files become a **work pack** (many marks in one file, 4 MiB chunks). Same commands.

**Boot disk (live USB)**

Firmware cannot boot a `.sg1`. The stick stays a normal live USB (GRUB + kernel + initrd). Wrap `live/filesystem.squashfs` (Debian/Parrot) or `casper/filesystem.squashfs` (Ubuntu) as a Seal. Initrd Scrys it; if the squashfs was chewed it De-scribes, then the live image mounts. If too damaged, it stops — Sigil will not guess.

```
# mount the USB, then:
./sigil boot prepare /media/usb
# default is Seal. Copies this `sigil` onto live/sigil and tries to inject the initrd hook.

./sigil boot mend /media/usb
# exit 0 = intact or repaired, 2 = too damaged, 3 = no mark

# Debian/dracut hooks onto this machine (then rebuild the live initrd):
sudo ./sigil boot install
```

`--only-mark` deletes the original squashfs after wrapping (saves space; stick must be writable, or initrd De-scribes into RAM). Ward: `--pass` / `--talisman` / `SIGIL_WARD`. Attest `.sg1.sig` that fails refuses boot. Stub swap is Secure Boot, not Sigil.

**Tape / rsync / Gather (one real path)**

```
# PC A — wrap and send boot first, then the rest
./sigil inscribe -o dump.sg1 ./big.bin
./sigil dispatch dump.sg1 --rsync tape@nas:/backup/ --overture
rsync -av --partial dump.sg1 tape@nas:/backup/

# or pieces + watch
./sigil inscribe --pieces ./rain ./big.bin
# other PC:
./sigil gather --watch -o dump.sg1 ./rain
# this PC:
./sigil deluge dump.sg1 --watch --only-rain --rsync other:~/rain/
```


```
./sigil inscribe -o tree.sg1 ./myfolder
./sigil de-scribe -o ./restored tree.sg1
./sigil de-scribe --only photos/cat.jpg -o ./out tree.sg1
./sigil inscribe --pass house --ward photos/secret.jpg=room -o tree.sg1 ./album
./sigil open photo.sg1

```

**Constellation (add unique files without rewriting the pile)**

A star is one `.sg1`. A constellation is a named list of stars, kept as a folder: the card (`Taxes.sg1`) plus one star per unique true name. Same bytes under a second name join the list without a second star. An atlas (`.sga`) is the bag when they must travel together. De-scribe refuses if a named star is missing.

```
./sigil constellation add ./Taxes ./tax-2025.pdf --name Taxes
./sigil constellation add ./Taxes ./notes.txt
# same bytes, new name: listed twice, one star on disk
./sigil constellation add ./Taxes ./copy.pdf --as dup.pdf

./sigil scry ./Taxes
./sigil de-scribe -o ./restored ./Taxes

# one bag for a USB / email (refuses if a star is already missing)
./sigil constellation atlas ./Taxes
./sigil de-scribe -o ./restored ./Taxes/Taxes.sga

# rsync only sends new stars
./sigil constellation add ./Taxes ./receipt.jpg --rsync user@nas:/backup/Taxes/
```

```

**One file vs pieces**

```
# default: one file
./sigil inscribe -o out.sg1 file.bin

# 16 piece files (small file) or star-NNNN.sg1 (large file)
./sigil inscribe --pieces ./pieces file.bin

# split an existing .sg1
./sigil scatter mark.sg1 -o ./pieces
./sigil kit place mark.sg1 --drives 4 -o ./kit/
./sigil kit mend ./kit -o healed.sg1
./sigil gather ./pieces -o mark.sg1

# rain extra pieces (Seal/Reflection). Far side needs any k, not all 16.
./sigil deluge dump.sg1 --extra 16 -o ./rain
./sigil gather --watch ./rain -o dump.sg1
./sigil deluge dump.sg1 --watch --only-rain --extra 32 -o ./rain --rsync user@other:~/rain/

# unlimited extra packets (RaptorQ), not stuck at 255
./sigil deluge dump.sg1 --fountain --extra 32 -o ./rain
./sigil gather ./rain -o dump.sg1


# Plex/Jellyfin: one movie. Stub in the library, unpack on Play, delete temp after idle.
./sigil show movie.sg1 --plex ~/Plex/Movies
./sigil overture movie.sg1
# first 64 MiB is boot (change with --overture-mb on Inscribe)


```

Shrink still runs **before** the Ward. Encrypted bytes do not shrink.

**Dispatch (copy the mark)** — calls tools you already have. Does not replace them.

```
# one shot: pack and rsync (usual for you)
./sigil inscribe --mode seal --rsync user@other:/backup/ -o dump.sg1 dump.sql

# already packed
./sigil dispatch dump.sg1 --rsync user@other:/backup/

# cloud (only if you use rclone remotes)
./sigil dispatch dump.sg1 --rclone backup:sigil

# one person, no SSH (needs magic-wormhole)
./sigil dispatch dump.sg1 --wormhole
```

On the far computer: `sha256sum dump.sg1` then `./sigil scry dump.sg1` then `./sigil de-scribe -o dump.sql dump.sg1`.





**Keys + encrypt-to (ECC Ward)**

Modern identity (default `sigil keygen`): `.sgk` holds a 32-byte master; X25519 (encrypt-to) and Ed25519 (attest) are HKDF-split. Public half is written to `<out>.pub` (or `--pub-out`).

```
# modern identity (X25519 + Ed25519)
./sigil keygen -o me.sgk
# → me.sgk + me.sgk.pub

# legacy raw 32-byte attest/Talisman seed (old behaviour)
./sigil keygen --legacy -o attest.bin

# encrypt-to one or more recipients (implies encrypted; passphrase optional)
./sigil inscribe --to alice.pub --to bob.pub -o secret.sg1 file.bin
# also works on folders, work packs, --cdc, and --pieces stars
./sigil inscribe --to alice.pub -o tree.sg1 ./myfolder

# open with matching identity (or passphrase if also sealed with --pass)
./sigil de-scribe --identity alice.sgk -o file.bin secret.sg1
./sigil open --identity alice.sgk secret.sg1
./sigil path --identity alice.sgk secret.sg1 --into .
./sigil mount --identity alice.sgk secret.sg1 ./view --export-dir /tmp/view

# both --pass and --to: either passphrase OR any matching identity unwraps the CEK
./sigil inscribe --pass house --to alice.pub -o secret.sg1 file.bin
./sigil de-scribe --pass house -o file.bin secret.sg1
./sigil de-scribe --identity alice.sgk -o file.bin secret.sg1
```

Recipient envelopes live in an `SGTO` companion block after the Keystone maps (no header flag bit). Passphrase-only seals (`--pass` / `--talisman` / `--ward`) are unchanged. `--identity` / `--to` are wired through mount, path, open, folder packs, CDC, pieces, and vault track/commit/restore. Passkeys/WebAuthn and PGP import are roadmap follow-ups.

**Mount (FUSE read-only / export-dir)**

Apps see normal paths; cleartext stays in RAM (FUSE) or an export tree (`--export-dir`). The durable `.sg1` is never rewritten in place. FUSE stays read-only; use `--export-dir --writable` for a dirty cleartext tree, then `sigil vault commit --from-export` to re-seal as a new vault version.

```
# FUSE (Linux/Parrot: needs /dev/fuse + fusermount3; usually in the `fuse3` package)
mkdir -p ./view
./sigil mount tree.sg1 ./view
# Warded: --pass house --ward photos/secret.jpg=room
# Encrypt-to: --identity alice.sgk
# Vault tip: ./sigil mount ./notes.txt ./view --vault
ls ./view
./sigil umount ./view
# or: fusermount3 -u ./view

# No FUSE / containers: materialize a read-only tree (seal stays intact)
mkdir -p /tmp/sigil-view
./sigil mount tree.sg1 ./view --export-dir /tmp/sigil-view

# Dirty write path (vault-tracked single-file live; no /dev/fuse needed)
./sigil vault track ./notes.txt
mkdir -p /tmp/sigil-dirty
./sigil mount ./notes.txt ./view --vault --export-dir /tmp/sigil-dirty --writable
# edit files under /tmp/sigil-dirty …
./sigil vault commit --from-export /tmp/sigil-dirty
# optional: --to alice.pub  --keep 5  --force

# Folder vault: same flow, each version is an SGDR pack
./sigil vault track ./photos
./sigil mount ./photos ./view --vault --export-dir /tmp/photos-dirty --writable
# edit / add / delete under /tmp/photos-dirty …
./sigil vault commit --from-export /tmp/photos-dirty
```

Nested `.sg1` entries in an SGDR pack appear as files (further nest-walk is optional; use `sigil path`). Folder vault tip model, sync rules, and `--ward` / `--force`: [docs/VAULT-MOUNT-NEST.md](../../docs/VAULT-MOUNT-NEST.md#folder-vaults--sgdr-dirty-re-seal).

Composed vault + mount + nest recipes: [docs/VAULT-MOUNT-NEST.md](../../docs/VAULT-MOUNT-NEST.md).

**Vault (version tip + retention)**

Track a live file or folder; each commit adds an immutable `vN.sg1` under `<live>.sgv/` (folder vaults: SGDR packs, CHART `kind=folder`). Retention is full (keep all) or light (newest N hot; older seals go to a cold kit before leaving the chart).

```
./sigil vault track ./notes.txt
./sigil vault status ./notes.txt
./sigil vault commit ./notes.txt
./sigil vault versions ./notes.txt
./sigil vault restore ./notes.txt --version 2
./sigil vault retention ./notes.txt --light --keep 3
./sigil vault prune ./notes.txt --keep 3 --cold ./vault-cold/
```

Details: [docs/VAULT-RETENTION.md](../../docs/VAULT-RETENTION.md). Mount / nest / dirty export glue: [docs/VAULT-MOUNT-NEST.md](../../docs/VAULT-MOUNT-NEST.md).

AGPL-3.0.

