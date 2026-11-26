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
its own small checksum, so `unseal` cannot open it directly—yet `sigil mend` can still heal
it. `scry` runs the same repair in memory (nothing is written; at most 3 seconds), sees that it
works, exits **5** (`damaged — run sigil mend`), and prints the next steps. (If that check runs
out of time, `scry` exits **6** and says to run `sigil mend` to find out.)

```
$ sigil scry rot.sg1
damaged  v2  live=0/16 need=12 merkle=open keystone=intact orig=2270725 entropy=7988 name=photo.jpg
attestation: none (no .sig beside this file)
damaged — run sigil mend rot.sg1 (0 of 16 shards intact, 12 needed; the deeper repair restores it)

What you can try:
  - See what is damaged and how long a repair takes: sigil mend --scan rot.sg1
  - Repair it into a new file (the original is kept): sigil mend rot.sg1
  - Or open it with a one-off repair in memory: sigil unseal --repair -o <out-file> rot.sg1
  - If you have another copy (backup, cloud, USB stick), combine them: sigil mend rot.sg1 <other-copy.sg1>
```

Running `sigil mend --scan` inspects the damage and estimates the repair time:

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

What you can try:
  - If you have another copy (backup, cloud, USB stick), combine them: sigil mend dead.sg1 <other-copy.sg1>
  - If you kept .sgp pieces or Channel mana for it, rebuild from them: sigil gather <folder> -o <rebuilt.sg1>
  - If it is on Frost Rune drives, rebuild from them: sigil frost mend <frost-folder> -o <rebuilt.sg1>
  - If it is kept in a Vault, restore an earlier version: sigil vault versions <vault>, then sigil vault restore --version <N> <vault>
```

The result code was 2 and no file was written. Sigil does not guess.

### A damaged Tome: save what you can

When a Tome (a Sigil of a folder) is too damaged to open as a whole, you can still ask for
every file that is intact:

```
$ sigil unseal --salvage -o rescued photos.sg1
```

Each file is checked on its own and written only if it passes; a file that fails is listed
as lost and nothing of it is written. Nothing already in `rescued` is overwritten (a taken
name gets `.salvaged-1`). The list of what was restored, renamed and lost is written to
`rescued.salvage-report.txt`. If a file's name cannot be confirmed (a damaged list in a Tome
made by an older version), the file goes into `rescued/recovered-names/` with the start of
its name, and the report shows the name the list gave it. Result code 0 means every file
came back under its own name, 7 means some did and some did not, 2 means nothing could be
saved.

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
Stopping safely... nothing half-done will be written. (Ctrl-C again quits at once.)
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
| 1 | Some other error (for example a file that is not a Sigil, or a wrong or missing key) |
| 2 | Too damaged: nothing was written (or a cut-off Tome) |
| 3 | Nothing could be checked |
| 4 | Repair skipped: too long, or you said no; nothing was written |
| 5 | Damaged, and `sigil mend` repairs it (checked in memory; the file cannot be opened as-is). `scry`, `verify`, `unseal` and `open` use this code |
| 6 | Damaged; whether `sigil mend` can repair it was not found out (time limit `SIGIL_SCRY_PROBE_SECS`, default 3 seconds, or a seal over 32 MiB). Run `sigil mend` |
| 7 | `unseal --salvage` saved some files but not all (or saved some under another name); see its report file |
| 130 | Stopped with Ctrl-C: nothing was written (`unseal --salvage`: files already saved stay) |

Exit 5 is given only after the repair was checked in memory (nothing is written by that check; at most 2 CPU threads). Exit 6 is not a guess that repair will fail. These codes and the `What you can try:` lines are tested in `crate/sigil/tests/cli_recovery_hints.rs`.

## Large-file packs: length framing

In a large-file pack (SGWK, a big file sealed as a row of chunk stars), each chunk star is preceded by an 8-byte length. Those prefixes and the facet list at the end are not Reed–Solomon coded. `sigil mend` rebuilds damaged length prefixes when every chunk star confirms against the facet list and any intact pack-head guard. It prints `length framing rebuilt`. The `.sg1` layout is unchanged. If the facet list is damaged too, `mend` refuses.

This is tested in `crate/sigil/tests/cli_pack_head.rs` (`new_pack_with_wiped_length_prefix_mends_and_prints_framing_rebuilt`) and the packhead unit test `framing_rebuild_heals_zeroed_flipped_and_sector_wiped_lengths_and_stays_fail_closed`.

## Limits

- The time estimate was measured on one 8-core computer. On slower machines it may be off.
- The question comes before the repair starts; there is no "finish later" option yet.
- Tomes and several copies at once are not scanned first. A pack whose head or length framing will not parse cannot be scanned either (plain `mend` still tries to rebuild both).
- Damage past the repair budget is refused. Keep a second copy somewhere else.
