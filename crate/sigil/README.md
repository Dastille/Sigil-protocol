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


AGPL-3.0.

