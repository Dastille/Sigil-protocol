# Frequently asked questions

*Version 1.0, 25 November 2026.*

**How much bigger does Sigil make my files?**
About a third bigger in the default Reflection mode (a 2 270 725-byte photo became
3 019 109 bytes) and about twice as big in Seal mode (4 526 933 bytes). See
[Getting started](Getting-started.md).

**How much damage can it survive?**
Reflection: any 4 of its 16 pieces can be lost or ruined; Seal: any 8 of 16. Scattered bit
rot inside the pieces can often be repaired past that, because the deeper repair fixes small
errors inside each piece instead of throwing the piece away; in a test on a 2.2 MB photo,
2 000 flipped bits spread over every piece were repaired exactly. Heavy damage is refused,
never guessed.

**How much memory does Sigil need for a big file?**
Not the size of the file. Sealing, opening, `scry` and the usual `mend` read a big file a
piece at a time: a 2 GiB file sealed as one Sigil peaked at about 40 MiB in each of these
steps (it used to take 12 to 18 GiB). Opening a Warded file reads it twice, once to check it
and once to decrypt, so it takes a little longer. The deeper repair for scattered bit rot
(the step `mend` tries when the quick repair is not enough) still loads the whole file.
`sigil mount` also reads a big file inside a Tome a piece at a time: exporting a Tome with
one 1 GiB file peaked at 43 MiB (86 MiB when the Tome is locked), where it used to take
more than twice the file's size. Exporting a large file from a locked Tome takes longer
than before (about 2.5 times as long), because each piece is checked twice.

**Why are some files missing from my Tome?**
A Tome stores regular files only. Files and folders whose names start with `.`, special
files such as named pipes, links that point nowhere, and empty folders are left out. Sigil
lists every one of them when it makes the Tome, and the last line says how many. File
permissions are not stored either, so a script comes back without its executable bit. To
stop instead of packing without them, add `--fail-on-skip`: nothing is written and the exit
code is 1.

**Can damage to a Tome's list of file names be repaired?**
For a Tome made with this version or later, yes. The list of names and sizes is kept inside
the repair data, so `sigil mend` fixes it, and if it cannot, nothing is restored. A Tome made
by an older version keeps its list outside the repair data: a damaged list there is refused,
and a small change to one name may not be noticed. Seal the folder again to get the new
layout. Older versions of sigil cannot open the new layout (they stop with an error and write
nothing); `sigil seal --old-tome-layout` makes a Tome they can read. Without a Ward this
protects against accidental damage, not against someone changing the file on purpose.

**Can a repair ever give me a wrong file?**
Sigil keeps a repaired file only if it matches the fingerprints stored when the Sigil was
made (a hash tree over the pieces, and for an unlocked Sigil a SHA-256 fingerprint of the
original). If it does not match, nothing is written.

**`scry` says `damaged — run sigil mend` (exit 5 or 6) or `NOT recoverable` (exit 2). Is my file gone?**
If `scry` says `damaged — run sigil mend` (exit 5), scattered bit rot touched too many pieces
for direct `unseal`, but `sigil mend` repairs it (`scry` checked by running the repair in
memory). Exit 6 means `scry` could not finish that check in its time limit (3 seconds, or
`SIGIL_SCRY_PROBE_SECS`): run `sigil mend` to find out. If `scry` says `NOT recoverable` (exit 2),
this single copy cannot be rebuilt alone — follow the `What you can try:` options printed below
the verdict (pool a second copy with `sigil mend A.sg1 B.sg1`, `sigil gather`, `sigil frost mend`,
`sigil vault versions`, or for a partially damaged Tome rescue intact files with
`sigil unseal --only <path>`). See [Repairing a damaged file](Repairing-a-damaged-file.md).

**A large file will not open, but `mend` says `length framing rebuilt`. What was wrong?**
In a large-file pack, an 8-byte length sits in front of each chunk. Those prefixes are not
Reed–Solomon coded, so a bad sector there used to make `mend` refuse (sometimes blaming the
facet list). `mend` now rebuilds the prefixes when every chunk confirms against the facet list,
and prints `length framing rebuilt`. If the facet list is damaged too, `mend` still refuses.
Tested in `crate/sigil/tests/cli_pack_head.rs`.

**Will `mend` overwrite my damaged file?**
No. Without `-o` it writes `name.mended.sg1` next to it (or `-2`, `-3` if that is taken). If
you name an output with `-o` and that file exists, it is replaced, but only after the repair
has passed its check.

**Do I need my passphrase to repair a locked Sigil?**
No. Checking and repairing work without it.

**I forgot my passphrase. Can it be reset?**
No. Nobody can open a locked Sigil without its passphrase or key file. See
[Encryption and keys](Encryption-and-keys.md).

**Is Sigil a backup program?**
No. It makes each copy far more resistant to damage and can prove an archive was not
altered, but you still need copies in more than one place. [Frost Rune](Frost-Rune-cold-storage.md)
helps spread one Sigil over several drives.

**A repair is taking long. Can I stop it?**
Yes. Press Ctrl-C once. Sigil stops at the next safe point, writes nothing, and leaves your
file unchanged. Pressing Ctrl-C twice quits immediately.

**Can I run repairs from a scheduled job?**
Yes. With nobody at the screen, repairs estimated at over 15 minutes are skipped (result
code 4) so a job never runs for hours unnoticed. `--max-secs SECS` sets your own limit and
`--yes` runs it regardless.

**Can older versions of Sigil open new files?**
Not always. Locked Sigils made since 17 November 2026 (which keep two copies of their key
wrap) are refused by older builds; nothing wrong is written. Upgrade Sigil to open them.
When in doubt, open a file with a build at least as new as the one that made it.

**Does Sigil work on Windows and macOS?**
It is built and tested on Linux. It is written in Rust and is expected to build elsewhere,
but those systems are not part of the regular checks. On Windows, Ctrl-C ends a repair at
once instead of stopping at a safe point (still nothing is written before the final check).
