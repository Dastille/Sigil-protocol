# Frost Rune: cold storage

*Version 1.0, 23 November 2026. Output captured from Sigil built from commit `8f03b46`.*

**Frost Rune** spreads one Sigil across several USB drives (or disks) that you store
unplugged ("cold"). With the default four drives, any two are enough to get your file
back. Losing or breaking two drives is fine.

## Lock first

Anyone holding one drive of an **unlocked** Sigil can read part of the file from it. Always
lock a Sigil before spreading it (see [Encryption and keys](Encryption-and-keys.md)), and
use **Seal** mode, which survives losing half the pieces:

```
$ sigil seal --mode seal --pass-file my-pass.txt -o cold.sg1 photo.jpg
inscribed 2270725 bytes → cold.sg1
```

## Spread it over four drives

```
$ sigil frost place cold.sg1 --drives 4 -o frost
Frost Rune → frost  drives=4 pieces=16 (4/4/4/4 each) star=74cd2d14
copy each usb-* folder to its own stick. Lose one stick → sigil frost mend

$ ls frost frost/usb-0
frost:
KIT
usb-0
usb-1
usb-2
usb-3

frost/usb-0:
piece-000.sgp
piece-004.sgp
piece-008.sgp
piece-012.sgp
```

Copy each `usb-` folder to its own drive. The small `KIT` file lists which piece is on
which drive; a copy on each drive is handy, but `frost mend` needs only the `usb-` folders. Each `.sgp` file is one **shard**: one piece of
the Sigil. The first line above was captured with the build that includes this page (commit
`8f03b46` plus the 23 November 2026 documentation update); earlier builds print
`cold-USB kit Option A` instead of `Frost Rune` (same result).

## Get the file back after losing drives

Here drives 1 and 3 are gone. Put the surviving folders together and rebuild:

```
$ sigil frost mend frost -o back.sg1
frost mend 4527319 bytes → back.sg1

$ sigil verify back.sg1
ok  v3  live=16/16 need=8 merkle=closed keystone=intact label=private (name, size and fingerprint inside the lock)
attestation: none (no .sig beside this file)

$ sigil unseal --pass-file my-pass.txt -o cold-back.jpg back.sg1
de-scribed 2270725 bytes → cold-back.jpg

$ cmp photo.jpg cold-back.jpg && echo same bytes
same bytes
```

With three of four drives gone, only 4 of the 8 needed pieces are left, and Sigil says so
(result code 1, nothing written):

```
$ sigil frost mend frost -o back2.sg1
need 8 pieces, have 4
```

## Checking cold drives

The folder check `sigil doctor --scrub` only checks whole `.sg1` files, so it refuses to call
a Frost Rune folder healthy and tells you the right check (result code 3, "not checked"):

```
$ sigil doctor --scrub frost
scrub: 0 Sigil(s), 0 repaired, 0 uncorrectable, 0 clean
NOT CHECKED: 4 piece file(s) (.sgp). Scrub only checks .sg1 files, so these were not checked at all and may be damaged or missing.
  frost: Frost Rune folder, 4 piece(s). Check it with: sigil frost mend frost -o check.sg1 && sigil verify check.sg1
```

Check your cold drives about once a year: plug them in, run `frost mend` into a scratch
file and `verify` it.

**Fire Rune** (hot, always-online storage) is a reserved name for a later feature. It does
nothing yet.
