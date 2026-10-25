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
- **Folder packs and constellations restore all-or-nothing too.** Every member
  is written in full to a hidden part file beside its destination
  (`.<name>.<pid>-<n>.sigil-part`) and synced. Only after every wanted member has
  unsealed and verified are the part files renamed into place. If any member
  fails (damage beyond repair, wrong key or ward, missing star), every part file
  and every folder the restore created is removed and existing files are left
  untouched. This covers folder-pack De-scribe (with and without mend),
  constellation folders, cards and atlases (`staging::Staging`). Limit: the
  final renames are one per file. If a rename itself fails during that last step,
  files already renamed stay; each is complete and verified. A crash before the
  renames can leave `.sigil-part` files, never a file under a restored name.
- **Whole-file checks before success.** Every chunk is checked against the length
  and SHA-256 in its own header. Pack unseal and in-memory pack mend also check
  every chunk against the facet list (catches swapped or reordered chunks) and the
  total against the pack head's size.
- If only the facet trailer itself is cut off, every chunk is still verified on
  its own, so the file comes back whole and exact.
- **A damaged pack head is now rebuilt when the evidence is unambiguous** (facet
  list + each star's own header; in new packs, a guard copy after each star), see
  `PACK-HEAD-REPAIR.md`. When it cannot be
  rebuilt, the refusal above still applies. A lone first star still behind its
  pack framing is refused too ("one part of a large-file pack").

Tests: `tests/cli_unseal_failclosed.rs` (the original 6 MB `--mode seal
--shards 254` case, truncations, existing output preserved, mend refuses) and
`work::tests` (swapped stars, damaged head in memory, two concatenated seals,
range all-or-nothing), `folder::tests::failed_folder_restore_writes_nothing_and_keeps_existing_files`,
`folder::tests::wrong_key_folder_restore_writes_nothing`,
`constellation::tests::failed_constellation_restore_writes_nothing_and_keeps_existing_files`
and `staging::tests`.

## Private label (v3)

New encrypted marks authenticate their label as AES-GCM associated data. A rewritten name, size, fingerprint, salt, nonce, version or binding, a swapped label, or an outer entropy score makes unseal refuse. See docs/PRIVATE-LABEL.md.

## Passphrase files (`--pass-file`)

`--pass-file PATH` (and `log compact --seal-pass-file`, `import-pgp --passphrase-file`)
refuses before doing any work, and writes nothing, when the file is missing or
unreadable, empty, not UTF-8, over 64 KiB, or (unix) a regular file with any
group/other permission bit (`chmod 600` fixes it). A wrong passphrase from a file
fails exactly like a wrong `--pass`. A literal `--pass VALUE` is still accepted but
warns on stderr that the command line is visible to other programs. Tests:
`tests/cli_pass_file.rs`.
