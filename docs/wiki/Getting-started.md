# Getting started

*Version 1.0, 23 November 2026. Output captured from Sigil built from the main branch on 23 November 2026.*

## 1. Install

There is no download page yet, so Sigil is built from its source code. You need the Rust
tools from [rustup.rs](https://rustup.rs) (one command on Linux and macOS). Then, in a
terminal:

```
git clone https://github.com/Dastille/Sigil-protocol.git
cd Sigil-protocol
cargo install --path crate/sigil
```

This puts the `sigil` program in your personal program folder (`~/.cargo/bin`). Check it:

```
$ sigil --version
sigil 1.0.0 (commit 1a2b3c4)
```

The part in brackets says exactly which version of the code you have.

## 2. Wrap a file (seal)

Here a 2.2 MB photo, `photo.jpg`, is wrapped into `photo.sg1`:

```
$ sigil seal -o photo.sg1 photo.jpg
inscribed 2270725 bytes → photo.sg1
```

"Inscribed" is Sigil's word for "wrapped". The Sigil is about a third bigger than the photo
(3 019 109 bytes against 2 270 725; sizes are listed below). That extra third is the repair data. This default
setting is called **Reflection**: the file is split into 16 pieces and any 12 of them are
enough to rebuild it, so about a quarter of the file can be lost.

For files that may take heavier damage, use **Seal** mode. It doubles the size and survives
losing about half:

```
$ sigil seal --mode seal -o photo-strong.sg1 photo.jpg
inscribed 2270725 bytes → photo-strong.sg1

$ stat -c '%s bytes  %n' photo.jpg photo.sg1 photo-strong.sg1
2270725 bytes  photo.jpg
3019109 bytes  photo.sg1
4526933 bytes  photo-strong.sg1
```

## 3. Check it (scry)

```
$ sigil scry photo.sg1
ok  v2  live=16/16 need=12 merkle=closed keystone=intact orig=2270725 entropy=7988 name=photo.jpg
attestation: none (no .sig beside this file)
```

How to read it:

- `ok` — the file is healthy.
- `live=16/16 need=12` — all 16 pieces are intact, and 12 are needed.
- `merkle=closed` — the overall fingerprint of the pieces matches.
- `keystone=intact` — the spare copies of the file's header (its label) are fine.
- `attestation: none` — nobody has signed this Sigil (signing is optional).

`sigil verify photo.sg1` does the same check. Neither needs a passphrase, and neither
changes anything.

## 4. Get the original back (unseal)

```
$ sigil unseal -o photo-back.jpg photo.sg1
de-scribed 2270725 bytes → photo-back.jpg

$ cmp photo.jpg photo-back.jpg && echo same bytes
same bytes
```

"De-scribed" means "unwrapped". The `cmp` line shows the copy is identical to the original,
byte for byte.

Folders work the same way: `sigil seal -o tree.sg1 myfolder` and
`sigil unseal -o restored tree.sg1`. That folder Sigil is a **Tome**: one `.sg1`
file, not a Codex (`name.sigil/` folder).

Next: [Repairing a damaged file](Repairing-a-damaged-file.md).
