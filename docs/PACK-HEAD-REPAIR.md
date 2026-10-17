# Repairing a damaged pack head

A file over 4 MiB is stored as a *work pack*: a small pack head (magic `SGWK`,
version, chunk size, total size, name, star count, overture), then one complete
seal ("star") per 4 MiB chunk, each behind an 8-byte length, then the facet list
(`SGFC`, the SHA-256 of every chunk in order). Each star is Reed–Solomon
protected on its own. The pack head is not. See `FAIL-CLOSED.md` for why a
damaged head used to mean a clean refusal.

There are two layers:

1. **Every pack, old or new:** the head is rebuilt from the facet list and the
   stars' own headers (below). Nothing new is written for this.
2. **New packs:** each star also carries a *guard*, a checked copy of the whole
   head plus the star's index. Any one intact guard restores the head byte for
   byte, and the guards prove the star order even when the facet list is gone too.

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

## Guards in new packs

Every pack written from now on puts a guard right after each star's seal, inside
that star's 8-byte length:

| Field | Bytes |
|---|---|
| magic `SGHG` | 4 |
| version (1) | 1 |
| star index | 4 |
| star's file offset when written (informational) | 8 |
| seal length (bytes before the guard) | 8 |
| pack id (random, the same in every star of one pack) | 16 |
| head length + a copy of the whole pack head | 2 + head |
| SHA-256 of everything above | 32 |
| guard length, tail magic `GHGS` | 4 + 4 |

**Additive, same layout.** The pack head, the framing and the facet list are
exactly as before; only each star's framed length grows by the guard. A single
seal tolerates trailing bytes, so binaries from before guards open, verify,
range-read and mend new packs unchanged (checked with the `d2f5307` binary on a
64 MiB pack: unseal, `--from-mb`/`--to-mb`, scry, mend of a clean pack
(byte-identical) and of a pack with 3 torn stars). An old binary's mend drops
the guard of each star it heals; the new reader still opens that file (it checks
guard *indexes*, not offsets) and a new `mend` writes the missing guards back.
Undamaged old packs never get guards added by `mend`.

**What the guards add**
- Head damaged anywhere, including the advisory fields and long names: restored
  byte for byte from any intact guard (`mend` reports
  `pack head restored from a guard copy`).
- Head **and** facet list damaged, or the facet list cut off: the guards prove
  each star's place, so the list is rebuilt from the stars' own headers
  (`facet list rebuilt`).
- A star whose guard names another index (swapped or reordered stars) is refused.
  Stars whose guards carry a different pack id or head (spliced in from another
  pack, even one with the same name and size) are refused.
- Any one intact guard is enough; damaged guards are rewritten by `mend`. If
  every guard is damaged, the facet-list rebuild above still applies.

The SHA-256 only detects accidental damage; like the rest of an unsigned pack it
is not a MAC. A guard repeats only what the head already holds in the clear (name,
sizes, star count) plus a random pack id; it adds no chunk fingerprints. If the
pending metadata-leak change moves the pack name out of the head, the guard's
head copy must follow it.

### Space cost (measured)

Per star: 83 bytes + one copy of the head (26 bytes + the name). With the default
4 MiB chunks (`seal`, `--mode reflection` and `--mode seal`, random data), old
`d2f5307` binary vs this one:

| File | Mode | Before | After | Added | Overhead |
|---|---|---:|---:|---:|---:|
| 8 MiB (2 stars) | reflection | 11,191,480 | 11,191,710 | 230 | 0.0021% |
| 8 MiB | seal | 16,783,864 | 16,784,094 | 230 | 0.0014% |
| 64 MiB (16 stars) | reflection | 89,531,561 | 89,533,417 | 1,856 | 0.0021% |
| 64 MiB | seal | 134,270,633 | 134,272,489 | 1,856 | 0.0014% |
| 256 MiB (64 stars) | reflection | 358,126,122 | 358,133,610 | 7,488 | 0.0021% |
| 256 MiB | seal | 537,082,410 | 537,089,898 | 7,488 | 0.0014% |
| 64 MiB of zeros (compresses to ~140 KB) | reflection | 139,945 | 141,801 | 1,856 | 1.33% |

So about 116 bytes per 4 MiB star for a short name (0.002%), at most 364 bytes per
star with a 255-byte name. Only packs whose chunks compress to almost nothing see
a visible percentage, and there the absolute cost is still ~116 bytes per chunk.

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
- `crate/sigil/src/packhead.rs` guard tests: guard shape and space per star, what a
  pre-guard reader does with a guarded star, stripping guards gives the old layout;
  every head byte of a new pack (long name) damaged three ways is restored byte for
  byte; head and facet list both damaged (plain and passphrase, file and in-memory
  mend, list cut off); any one intact guard is enough, a pre-guard mend's shifted
  stars still open and are re-guarded; star bit flips and head damage heal together;
  swapped, spliced (including a same-name, same-size twin with the facet list
  damaged) and truncated packs refused; wrong key fails closed, keyless mend works;
  CDC packs are guarded too.
- `crate/sigil/tests/cli_pack_head.rs`: `sigil unseal` / `sigil mend` on an old pack
  with its magic wiped (mend output is byte-identical to the original), a wrong
  total mended in place, an unrebuildable head still refused with no output, and a
  new pack with head and facet list wiped coming back byte-exact.
- `doctor::tests::damaged_pack_head_is_reported_as_mendable`.
