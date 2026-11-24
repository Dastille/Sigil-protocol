# Frequently asked questions

*Version 1.0, 23 November 2026.*

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

**Can a repair ever give me a wrong file?**
Sigil keeps a repaired file only if it matches the fingerprints stored when the Sigil was
made (a hash tree over the pieces, and for an unlocked Sigil a SHA-256 fingerprint of the
original). If it does not match, nothing is written.

**`scry` says NOT recoverable. Is my file gone?**
Not always. `scry` counts only pieces that are completely intact. If bit rot touched every
piece, run `sigil mend --scan FILE`; if it says "deeper repair", try `sigil mend FILE`. See
[Repairing a damaged file](Repairing-a-damaged-file.md).

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
