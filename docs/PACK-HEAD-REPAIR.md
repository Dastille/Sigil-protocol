# Repairing a damaged pack head

A file over 4 MiB is stored as a *work pack*: a small pack head (magic `SGWK`,
version, chunk size, total size, name, star count, overture), then one complete
seal ("star") per 4 MiB chunk, each behind an 8-byte length, then the facet list
(`SGFC`, the SHA-256 of every chunk in order). Each star is Reed–Solomon
protected on its own. The pack head is not. See `FAIL-CLOSED.md` for why a
damaged head used to mean a clean refusal.

## Rebuilding the head from what every pack already holds

Nothing new is written for this; it works on every pack ever made, including
files written before this change (`crate/sigil/tests/fixtures/pack-v0`).

When the head does not parse, or does not fit the rest of the file, the reader
(`unseal`, range unseal, `mend`, folder-pack mend, `doctor`, the pack index)
rebuilds it from:

- **the facet list** at the end of the file, which gives the star count and the
  SHA-256 of each chunk, in order;
- **the length framing**, which must tile the file exactly from one head length
  (22 to 281 bytes) up to the facet list;
- **each star's own header** (protected by its keystone copies and embers), which
  must carry the listed SHA-256, star by star, in order;
- **the stars' own lengths**, which add up to the total size.

The rebuild is accepted only if exactly one head length makes every star match
the list. Then each star is still opened and checked against its own length and
SHA-256 as always, and the total is checked at the end. Damage that cannot be
rebuilt keeps the old clean refusal and the old error message.

A head that parses but carries a wrong **total size** or **name** (both checkable
against the stars) is corrected the same way. The name is recovered when star 0's
header name (`name.0000`, kept to 16 bytes) holds all of it, which is true for
names up to 11 bytes; a longer name cannot be recovered from the stars, and a
rebuilt head then records no name (`unseal` suggests `payload.bin`).

`sigil mend` writes the repaired head into its output and says
`pack head rebuilt from the facet list`. For the old-format fixture, every single
byte of the head was damaged three ways (set to 0, all bits flipped, low bit
flipped): every case opens byte-exact, and `mend` restores the original head byte
for byte except for the two advisory fields below.

### What this cannot do

- **Chunk size and overture** (8 of the head's bytes) are advisory: nothing in the
  stars checks them, so damage there is carried along, not detected. They only
  affect `--from-mb` / `--to-mb` range arithmetic and the overture report; data is
  still verified chunk by chunk. A head rebuilt from scratch sets chunk size to the
  largest chunk and overture to the default.
- **Head and facet list both damaged:** there is no record of the star count or
  order left, so the pack is refused.
- **A damaged 8-byte length in front of a star:** refused, as before.
- **Swapped or reordered stars:** never match the facet list, so they are refused
  with or without a damaged head.
- **A truncated pack:** the head and the facet list both say how many stars there
  should be, so a short pack is refused, never returned short.

## One more fail-closed rule

A file that is just one star still behind its 8-byte pack framing (the head is
damaged and every other star is missing) used to open as if that one 4 MiB chunk
were the whole file, because a single seal may have a few bytes of leading junk.
Now any seal whose header is preceded, within the first 289 bytes, by a length
that equals the seal's own size is refused with "this file holds one part of a
large-file pack". Tests: `packhead::tests::old_format_refuses_when_the_evidence_is_gone`.

## Tests

- `crate/sigil/src/packhead.rs` tests: old fixtures open exactly and `mend` leaves
  them byte-identical; a version 1 head still opens; every head byte damaged three
  ways; whole head wiped (plain and passphrase packs, in-memory mend, index, range
  unseal, suggested name); wrong or missing key after a rebuild; swapped stars with
  the head wiped; head plus facet list damaged, truncations at many points, damaged
  star framing; facet list alone damaged; a single seal is never taken for a pack.
- `crate/sigil/tests/cli_pack_head.rs`: `sigil unseal` / `sigil mend` on an old pack
  with its magic wiped (mend output is byte-identical to the original), a wrong
  total mended in place, and an unrebuildable head still refused with no output.
- `doctor::tests::damaged_pack_head_is_reported_as_mendable`.
