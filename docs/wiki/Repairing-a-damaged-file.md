# Repairing a damaged file

*Version 1.0, 23 November 2026. Output captured from Sigil built from the main branch on 23 November 2026.
The damaged files below were made on purpose from the 2.2 MB `photo.sg1` of
[Getting started](Getting-started.md), by overwriting part of it or flipping random bits.*

## The short version

```
sigil mend --scan damaged.sg1     # look first; writes nothing
sigil mend damaged.sg1            # repair into damaged.mended.sg1
sigil verify damaged.mended.sg1   # double-check the repaired copy
```

- `mend` never writes over the damaged file or any file that already exists.
- It keeps the repaired copy only if it passes the full check. Otherwise it writes nothing.
- It needs no passphrase, even for a locked (encrypted) Sigil.

## Example 1: a damaged stretch

Here 200 KB in the middle of the file was overwritten with zeros, as a failing disk might do.

```
$ sigil scry torn.sg1
ok  v2  live=14/16 need=12 merkle=open keystone=intact orig=2270725 entropy=7988 name=photo.jpg
attestation: none (no .sig beside this file)
needs repair: 14/16 shards intact (need 12) (run: sigil mend torn.sg1)
```

Two of the 16 pieces are damaged. 12 are needed and 14 are fine, so it can be repaired.
`merkle=open` means the overall fingerprint no longer matches until it is repaired.

Look before repairing (optional):

```
$ sigil mend --scan torn.sg1
Scan: one damaged stretch (a wiped or unreadable area). Shards: 14 good, 2 damaged, 0 missing.
Repair: the quick repair should be enough.
Estimated time: under 10 seconds on a computer like the one this was measured on (a rough guess, padded high).
Nothing was written. To repair it: sigil mend torn.sg1
```

Repair:

```
$ sigil mend torn.sg1
mended torn.sg1 → torn.mended.sg1 (live 16/16, need 12, merkle ok)
Your repaired copy is torn.mended.sg1 (no -o given, so Sigil picked a new name next to the original). The damaged file was left as it is.
To double-check the repaired copy: sigil verify torn.mended.sg1

$ sigil verify torn.mended.sg1
ok  v2  live=16/16 need=12 merkle=closed keystone=intact orig=2270725 entropy=7988 name=photo.jpg
attestation: none (no .sig beside this file)
```

Run it again and Sigil picks the next free name rather than overwrite anything:

```
$ sigil mend torn.sg1
mended torn.sg1 → torn.mended-2.sg1 (live 16/16, need 12, merkle ok)
```

To choose the name yourself, add `-o fixed.sg1`.

## Example 2: bit rot everywhere

Here 2 000 single bits were flipped at random across the whole file. Every piece now fails
its own small checksum, so the simple check gives up:

```
$ sigil scry rot.sg1
NOT recoverable  v2  live=0/16 need=12 merkle=open keystone=intact orig=2270725 entropy=7988 name=photo.jpg
attestation: none (no .sig beside this file)
NOT recoverable (live=0/16 need=12): too damaged to restore from this copy; find another copy or more pieces (sigil gather), then try again
```

**Do not give up on the copy yet.** `scry` only counts pieces that are entirely intact.
The scan looks closer:

```
$ sigil mend --scan rot.sg1
Scan: scattered small errors (bit rot). Shards: 0 good, 16 damaged, 0 missing.
Repair: needs the deeper repair, and the damage is heavy: it may take longer and may not succeed.
Estimated time: under 10 seconds on a computer like the one this was measured on (a rough guess, padded high).
Nothing was written. To repair it: sigil mend rot.sg1

$ sigil mend rot.sg1
mended rot.sg1 → rot.mended.sg1 (live 16/16, need 12, merkle ok, soft salvage)
The quick repair was not enough, so Sigil used the deeper repair for bit rot. The result passed the full check (Merkle root and true name).
Your repaired copy is rot.mended.sg1 (no -o given, so Sigil picked a new name next to the original). The damaged file was left as it is.
To double-check the repaired copy: sigil verify rot.mended.sg1

$ sigil unseal -o rot-back.jpg rot.mended.sg1
de-scribed 2270725 bytes → rot-back.jpg

$ cmp photo.jpg rot-back.jpg && echo same bytes
same bytes
```

Plain `mend` tried the quick repair, saw it was not enough, and moved on to the deeper
repair by itself. The deeper repair fixes the small errors inside each piece instead of
throwing whole pieces away.

## Example 3: too damaged

Here about 40% of the file (1.2 MB) was overwritten. That is more than Reflection can
survive:

```
$ sigil mend --scan dead.sg1
Scan: one damaged stretch (a wiped or unreadable area). Shards: 9 good, 7 damaged, 0 missing.
Repair: probably too damaged to rebuild from this copy alone (another copy of the same Sigil can be combined with it).
Nothing was written. To repair it: sigil mend dead.sg1

$ sigil mend dead.sg1
could not repair dead.sg1: too damaged to rebuild from this copy (soft mend could not reconstruct a true-name match). Nothing was written.
If you have another copy of this Sigil (a backup, a USB stick), give both and Sigil will combine their good parts:
  sigil mend dead.sg1 other-copy.sg1
```

The result code was 2 and no file was written. Sigil does not guess.

## Two damaged copies can rescue each other

If you have two damaged copies of the same Sigil, give both. Here one copy lost 800 KB near
the front and the other 800 KB near the end. Neither can be repaired alone:

```
$ sigil mend copyA.sg1
could not repair copyA.sg1: too damaged to rebuild from this copy (soft mend could not reconstruct a true-name match). Nothing was written.
If you have another copy of this Sigil (a backup, a USB stick), give both and Sigil will combine their good parts:
  sigil mend copyA.sg1 other-copy.sg1

$ sigil mend copyA.sg1 copyB.sg1 -o fixed.sg1
mended 2 copies → fixed.sg1 (good shards per copy: copyA.sg1 (11/16), copyB.sg1 (10/16); pooled 16/16, need 12; now live 16/16, merkle ok)

$ sigil verify fixed.sg1
ok  v2  live=16/16 need=12 merkle=closed keystone=intact orig=2270725 entropy=7988 name=photo.jpg
attestation: none (no .sig beside this file)
```

## Long repairs: the wait screen

Most repairs take seconds. For a big file with heavy damage, Sigil:

- **tells you the estimate** before it starts, when it is 10 seconds or more;
- **shows a progress line** once the repair has run for 5 seconds;
- **asks first** when the estimate is over about 2 minutes (only `y` starts it; add `--yes`
  to skip the question);
- **stops safely on Ctrl-C**: nothing is written and the damaged file is unchanged.

A 150 MB Sigil with 150 000 flipped bits on a 20-thread desktop. The estimate is padded
high on purpose; this repair took about 6 seconds:

```
$ sigil mend one.sg1
Scan: scattered small errors (bit rot). Shards: 0 good, 44 damaged, 0 missing.
Repair: needs the deeper repair, and the damage is heavy: it may take longer and may not succeed.
Estimated time: about 80 seconds on a computer like the one this was measured on (a rough guess, padded high).
Working on it now. Nothing is written until the result passes the full check, and Ctrl-C stops without touching the original.
Repairing… 5 seconds so far, about 70 seconds left. Ctrl-C stops safely.
mended one.sg1 → one.mended.sg1 (live 44/44, need 33, merkle ok, soft salvage)
The quick repair was not enough, so Sigil used the deeper repair for bit rot. The result passed the full check (Merkle root and true name).
```

The same repair stopped with Ctrl-C after about 3 seconds:

```
Stopping safely... nothing will be written. (Ctrl-C again quits at once.)
repair stopped: you pressed Ctrl-C. Nothing was written; one.sg1 is unchanged. Run the same command again to start over.
```

What the question looks like (shown here on a small file by setting
`SIGIL_MEND_ASK_SECS=0`, which makes Sigil ask about every repair, and answering `n`):

```
This repair may take under 10 seconds (a rough guess, padded high).
Your file is safe either way: nothing is written until the result passes the full check.
Keep going? [y/N] repair skipped: you chose not to start it now. Nothing was written; rot.sg1 is unchanged. To repair it later without this question:
  sigil mend --yes rot.sg1
```

## Scheduled jobs (no one at the screen)

When nobody can be asked, a repair estimated at over 15 minutes is skipped, and
`--max-secs` sets your own limit. Both write nothing and end with code 4:

```
$ sigil mend --max-secs 0 rot.sg1
Scan: scattered small errors (bit rot). Shards: 0 good, 16 damaged, 0 missing.
Repair: needs the deeper repair, and the damage is heavy: it may take longer and may not succeed.
Estimated time: under 10 seconds on a computer like the one this was measured on (a rough guess, padded high).
repair skipped: the padded estimate (1.1 seconds) is over --max-secs 0. Nothing was written. To repair it anyway:
  sigil mend rot.sg1
```

## What the result codes mean

Programs and scripts see a number when Sigil finishes (`echo $?` shows it in a terminal):

| Code | Meaning |
|---:|---|
| 0 | Done (repaired, or the scan ran) |
| 1 | Some other error (for example a file that is not a Sigil) |
| 2 | Too damaged: nothing was written |
| 4 | Repair skipped: too long, or you said no; nothing was written |
| 130 | Stopped with Ctrl-C: nothing was written |

## Limits

- The time estimate was measured on one 8-core computer. On slower machines it may be off.
- The question comes before the repair starts; there is no "finish later" option yet.
- Folder packs and several copies at once are not scanned first.
- Damage past the repair budget is refused. Keep a second copy somewhere else.
