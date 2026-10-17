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
range all-or-nothing).
