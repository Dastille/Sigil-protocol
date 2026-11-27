# Unseal and mend never return part of a file silently

## The bug (fixed 2026-10)
A large file (over 4 MiB) is stored as a *work pack*: a small pack head
(magic `SGWK`, total size, chunk count), then one complete seal per 4 MiB chunk,
then a list of each chunk's fingerprint (the SGFC facets). The pack head is not
Reed–Solomon protected.

When the pack head was damaged, the tool no longer recognised the file as a pack
and treated it as a single seal. The single-seal reader searches a few KB in for
a header, found the **first chunk's** seal, and that seal is valid on its own:
its length and SHA-256 matched *its own* header. So `unseal` wrote 4,194,304
bytes and exited 0, and `mend` "healed" the file into a healthy-looking
one-chunk seal and dropped the rest. Separately, an unseal that failed partway
through a pack left a half-written output file behind.

## The rules now
- **One seal means one seal.** `header::ensure_single_seal` runs in every
  single-seal unseal and mend. If another Sigil header, ember or a facet trailer
  sits after the end of the seal that was found, it refuses with
  "this file holds more than one seal ...". Random trailing junk is still allowed.
- **All-or-nothing output.** `work::write_atomic` writes `<output>.sigil-part`,
  syncs it, and renames it over `<output>` only on success. On any error the part
  file is removed and an existing output is left untouched. Used by plain unseal,
  pack unseal and `--star` / `--from-mb` range unseal. Pack mend and single mend
  already used temp + rename.
- **Tomes and constellations restore all-or-nothing too.** Every member
  is written in full to a hidden part file beside its destination
  (`.<name>.<pid>-<n>.sigil-part`) and synced. Only after every wanted member has
  unsealed and verified are the part files renamed into place. If any member
  fails (damage beyond repair, wrong key or ward, missing star), every part file
  and every folder the restore created is removed and existing files are left
  untouched. This covers Tome De-scribe (with and without mend),
  constellation folders, cards and atlases (`staging::Staging`). Limit: the
  final renames are one per file. If a rename itself fails during that last step,
  files already renamed stay; each is complete and verified. A crash before the
  renames can leave `.sigil-part` files, never a file under a restored name.
- **A damaged Tome folder list is refused, not guessed.** A plain Tome's list
  (count, names, lengths) has no repair data. Before anything is written, each name
  is checked against the path prefix in that member's own protected header, a name
  used twice, not valid UTF-8, or out of the order Inscribe writes names in is
  refused, and a complete member after the last counted one means the count was
  lowered. A damaged name that keeps its header prefix and its place in the order
  is not caught in a v1 Tome. Any of these stops `scry`, `verify`,
  `unseal` and `mend` with exit 2 (`folder list damaged: …`) and no output.
  `sigil ls` and `sigil mount` run the same name checks on a v1 list.
- **New plain Tomes protect their folder list (Tome v3).** The list is inside the
  repair-protected body, so damage to it, including a name changed by one bit
  (`.dat` to `.dau`), fails the body's SHA-256 and is repaired by `mend` or refused;
  it is never read as a different name. This guards against accidental damage only: with
  no key there is no authentication, so a deliberate forger can write a valid Tome (use a
  Ward for that). A damaged body length or file count in the v3 head stops readers;
  `mend` rebuilds both. An unknown Tome version (from a newer sigil, or a damaged
  version byte) is refused by every command with nothing written.
- **File details never widen access by default (Tome v4 and v5).** Restored permissions
  are limited by the umask and never include set-user-ID, set-group-ID or sticky bits
  unless `unseal --exact-modes` is given. The mode is set on the private part file before
  the rename, so a file stored as private is never visible to others. Empty-folder names
  are checked like member names (`..`, `.` parts, absolute names refuse the restore), and
  restore refuses to write through a link inside the output folder. A details block this
  build cannot read is skipped with a note; it never stops the files from restoring.
- **Salvage is opt-in and never writes an unchecked file.** `unseal --salvage`
  (`salvage.rs`) is the one restore that is not all-or-nothing, and only when asked
  for. Each file is unsealed into a private part file and kept only if it passes its
  own checks (length and SHA-256 or AEAD tag, Merkle binding after a repair); a file
  that fails is reported lost and nothing of it stays. Each name is first claimed
  with a new empty file (`create_new`, which never takes an existing file or folder),
  then the checked part is moved over that claim: a taken name gets `.salvaged-N`.
  A v1 list name is used only when the file's own header confirms all of it;
  otherwise the file goes under `recovered-names/` and the report gives the list's
  name. A stored part of a large file found without its pack head is never
  written as if it were the whole file. Exit 0 only when every listed file came back
  under its own name; 7 when anything was lost, renamed or not tried; 2 when nothing
  was saved. The scan of a damaged list stops at 1,000,000 star markers per damaged
  stretch, at `--max-secs`, or at Ctrl-C, and reports what was not tried.
- **Whole-file checks before success.** Every chunk is checked against the length
  and SHA-256 in its own header. Pack unseal and in-memory pack mend also check
  every chunk against the facet list (catches swapped or reordered chunks) and the
  total against the pack head's size.
- If only the facet trailer itself is cut off, every chunk is still verified on
  its own, so the file comes back whole and exact.
- **A damaged pack head is now rebuilt when the evidence is unambiguous** (facet
  list + each star's own header; in new packs, a guard copy after each star), see
  `PACK-HEAD-REPAIR.md`. Damaged length prefixes between stars are rebuilt the
  same way, decoder-only, and only when every star confirms against the facet
  list. When either cannot be rebuilt, the refusal above still applies. A lone
  first star still behind its pack framing is refused too ("one part of a
  large-file pack").

Tests: `tests/cli_unseal_failclosed.rs` (the original 6 MB `--mode seal
--shards 254` case, truncations, existing output preserved, mend refuses) and
`work::tests` (swapped stars, damaged head in memory, two concatenated seals,
range all-or-nothing), `folder::tests::failed_folder_restore_writes_nothing_and_keeps_existing_files`,
`folder::tests::wrong_key_folder_restore_writes_nothing`,
`constellation::tests::failed_constellation_restore_writes_nothing_and_keeps_existing_files`,
`staging::tests`, and `tests/cli_salvage.rs` plus `salvage::tests` for salvage.

## Private label (v3)

New encrypted Sigils authenticate their label as AES-GCM associated data. A rewritten name, size, fingerprint, salt, nonce, version or binding, a swapped label, or an outer entropy score makes unseal refuse. See docs/PRIVATE-LABEL.md.

## Passphrase files (`--pass-file`)

`--pass-file PATH` (and `log compact --seal-pass-file`, `import-pgp --passphrase-file`)
refuses before doing any work, and writes nothing, when the file is missing or
unreadable, empty, not UTF-8, over 64 KiB, or (unix) a regular file with any
group/other permission bit (`chmod 600` fixes it). A wrong passphrase from a file
fails exactly like a wrong `--pass`. A literal `--pass VALUE` is still accepted but
warns on stderr that the command line is visible to other programs. Tests:
`tests/cli_pass_file.rs`.
