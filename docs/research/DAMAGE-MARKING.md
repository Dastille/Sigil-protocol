# Damage marking for Sigil repair: per-stripe checks, iterative passes, bad-holder detection

Status: design note, 2026-11-10. No code, no format change. Every gain figure
below is a calculation or a model simulation, not a measurement of Sigil, and is
marked **UNVERIFIED** until the measurement plan in §7 has been run. Line numbers
refer to this branch. On base `main` (`e07e50f`) lines of `docs/sigil-v1.txt`
after the Frost Rune section were 7 lower, and lines after claim P 11 lower
(e.g. claim F `:183–197` here was `:176–190`; the A "NOT claimed" text
`:208–212` here was `:197–201`).

## 1. Source

A. Chvanov and N. Malkovsky, "Anchored Iterative Decoding of Reed–Solomon
Product Codes for High-Rate Magnetic Tape Storage", arXiv:2611.09366 (v1),
https://arxiv.org/abs/2611.09366 (abstract and HTML full text read 2026-11-10).

Abstract as published (quoted): "We present a decoding algorithm for a
Reed–Solomon product code targeted at the demanding reliability requirements of
modern magnetic tape storage. For a code RS(256,224)×RS(175,173) in a BSC we
achieve post-decoding bit error rate (BER) of 10⁻²⁰ at ≈5.3×10⁻³ raw BER while
maintaining the common requirement to detect and correct 4 out of 32 dead
tracks. We resolve two common problems of miscorrections and stall patterns that
arise under such a high raw BER via simplified versions of anchor decoding and
binary image analysis. The highest efficiency is achieved by performing an
unlimited iterative decoder, which performs decoding iterations until no changes
are made. [...] We provide a CPU implementation achieving 100-200 megabytes/s
single-core throughput on a regular laptop and a design of a potential hybrid
FPGA-CPU implementation of our decoder."

The authors state their proof "is not complete but follows common simulation
principles". None of their numbers were reproduced here.

What the paper does that matters for Sigil (from §II-B, §III-A, §III-B):

1. **Rows as detectors.** Each row codeword sits on one tape track. Rows that
   fail tell the column decoder which positions are bad, so the column decoder
   runs in error-and-erasure mode instead of error-only mode (§II-B).
2. **Error-and-erasure budget.** An RS(n,k) code corrects t errors and e
   erasures when 2t + e < d = n − k + 1, i.e. 2t + e ≤ n − k (§II-A).
   Known-bad positions cost 1, unknown-bad positions cost 2.
3. **Anchors.** Columns that decode with no syndromes left are "anchored" and may
   not be changed by later row corrections; this stops miscorrections from
   spreading and stops oscillation (Algorithm 2, after Häger and Pfister 2018).
4. **Iterate until nothing changes.** An unlimited loop beats a fixed 4
   half-iterations at the same average cost, because the rare hard cases are
   the ones that need more passes (§IV, Fig. 5 and 7).
5. **Dead-track detection by statistics.** Count codewords that are already
   correct; a dead track looks like random data (§III-A).

## 2. The problem in Sigil today

Verified in this repository:

- **One CRC32 per whole shard.** Layout: `n × (Ember SGEM 160 [+ Vow] + shard +
  CRC32 of shard)` (`docs/sigil-v1.txt:81`). Threat model: "Repair is SHARD
  ERASURE. A shard whose CRC32 fails is dropped whole, so one flipped bit costs
  a whole shard" (`docs/sigil-v1.txt:186–187`). Piece files use the same stride
  (`crate/sigil/src/pieces.rs`, `pack_stride` / `shard_from_stride`).
- **Column repair treats unflagged bad bytes as errors.** `mend --soft` v1
  decodes each byte column as its own RS codeword; "Missing shards count as
  erasures (2·errors + erasures ≤ n − k per column). Any column past that budget
  fails the call" (`docs/SOFT-RS.md`, section "v1: column repair").
- **Consequence.** For Seal (k = 8, n = 16) a column survives 8 *marked* holes
  (erasures) but only 4 *hidden* wrong bytes. Present-but-bad shards are hidden
  errors, because the whole-shard CRC only says "something in these 125 000
  bytes is wrong", not where. Reflection (12,16): 4 erasures or 2 hidden errors.
- **Soft v0 already guesses stripes.** GMD-lite "flips ≤ (n−k) lowest-reliability
  soft shards (then soft stripes) to erasure" using 4096-byte stripes
  (`rs::SOFT_STRIPE`, `docs/SOFT-RS.md` v0) but "has no way to locate which bytes
  are wrong" (`docs/research/DEEP-SPACE.md` §4). The missing piece is
  localization, not the stripe size.

Where the gap shows: damage that touches **more than n − k shards** (so
whole-shard erasure fails) but puts **more than (n−k)/2 and at most n − k** bad
shards into some columns (so error-only column repair fails). Bad sectors,
partial overwrites and flash page failures spread across many shards are this
case. Scattered single-bit flips at low density are not: column repair already
handles them (DEEP-SPACE §5.2: Seal 16 384 flips, 10/10).

## 3. Option 1: per-4096-byte-stripe checks (optional sidecar first)

**What.** For every shard i and stripe j (4096 bytes, same as
`rs::SOFT_STRIPE`), store a check value c(i, j). On repair, a stripe whose check
fails becomes a known erasure for its 4096 columns; a stripe whose check passes
is trusted (an anchor in the paper's sense).

**Where it lives (in order of preference).**

1. **Sidecar file, no `.sg1` change** (proposed first): e.g. `NAME.sg1.stripes`,
   or one per Frost Rune drive next to the pieces. Contents: magic, version,
   binding to the Sigil (Merkle root + true name from the header), stripe size,
   n, shard length, the table of c(i, j), and a CRC32 over the table. A missing
   or damaged sidecar means today's behavior, nothing worse.
2. **Additive format block** later, only if measurements justify it and
   **Ashlynn picks the format**. Not part of this note.

**Check value choices (Ashlynn's pick):**

| choice | bytes per 4 KiB | overhead (Seal, 1 MB file, 496 stripes) | detects | against a lying holder |
|---|---|---|---|---|
| CRC32 | 4 | ~2 KiB, ~0.1% | faults (F) | no: recomputable |
| SHA-256 (full) | 32 | ~15.5 KiB, ~0.8% | faults (F) | no on its own: recomputable |
| SHA-256 table + Ed25519 signature over it (`sigil sign` key) | 32 + 64 once | ~15.6 KiB | faults (F) | yes, if the verifier trusts the signer key (A) |

Overhead figures are arithmetic on the DEEP-SPACE Seal geometry (16 shards ×
125 000 B, 31 stripes each), **UNVERIFIED** against a real sidecar.

**Important trade-off found while writing this note.** Stripe flags are not
free: a flagged stripe erases all 4096 symbols of that shard in those columns,
including the good ones. For uniformly scattered flips this is worse than
error-only column repair. Model (independent flips over the 2 MB Seal body,
**UNVERIFIED**, calculation only):

| scattered flips | P(stripe has ≥1 flip) | error-only column repair, P(ok) | flags as pure erasures, P(ok) |
|---|---|---|---|
| 64 | 0.12 | ≈1.000 | ≈0.999 |
| 1 024 | 0.88 | ≈1.000 | ≈0.000 |
| 16 384 | ≈1.00 | ≈0.98 (measured 10/10, DEEP-SPACE §5.2) | ≈0.000 |

So flags must be **hints**, not orders. The decoder keeps today's error-only
pass and adds an erasure pass per stripe row; whichever succeeds still goes
through the same acceptance gate (§4).

For stripe-shaped damage the model goes the other way. Model: B whole 4 KiB
stripes replaced by garbage, uniformly over the 16 × 31 stripe cells of the 1 MB
Seal; 20 000 model trials each; **UNVERIFIED**, not Sigil code:

| bad stripes B | whole-shard erasure (today's unseal) | error-only columns (today's `mend --soft`) | stripe flags as erasures |
|---|---|---|---|
| 16 | 0.06 | 1.00 | 1.00 |
| 32 | 0.00 | 0.93 | 1.00 |
| 48 | 0.00 | 0.65 | 1.00 |
| 64 | 0.00 | 0.21 | 1.00 |
| 96 | 0.00 | 0.00 | 0.97 |
| 128 | 0.00 | 0.00 | 0.77 |

Deterministic example for a test: shards 0–5 garbage in stripe row 3 and shards
6–11 garbage in stripe row 7. Twelve shards fail CRC (> 8, unseal refuses); row 3
columns have 6 hidden errors (> 4, column repair refuses); with flags, each row
has 6 erasures (≤ 8) and should decode. Expected, **UNVERIFIED** until run.

## 4. Option 2: iterative row/column repair passes (fail closed)

Sigil has a 1-D code: columns are RS codewords, there is no row code. The stripe
check is a detection-only "row". The paper's loop still carries over:

1. Pass 0: verify every stripe check. Passing stripes are anchors (never
   changed). Failing stripes are candidates.
2. Column pass: for each stripe row, if candidates ≤ n − k, decode its columns
   with candidates as erasures. Otherwise decode each column in error mode
   (today's Berlekamp–Welch), but **never change an anchored symbol**: a column
   whose solution would change an anchor is rejected (miscorrection filter, cf.
   Algorithm 2 anchors).
3. Row re-check: recompute the checks of candidate stripes. A stripe that now
   verifies becomes an anchor. A stripe that error-mode columns proved wrong
   stays a candidate.
4. Repeat 2–3 until a pass changes nothing (the paper's "unlimited" loop; it
   ends because each pass either adds an anchor or stops, bounded by n × stripes).
5. **Gate, unchanged:** re-encode, Merkle binding must match the header, and on
   unencrypted Sigils the true name and length must match
   (`docs/sigil-v1.txt:183–197`, `pieces::accept_folded`). Anything else
   refuses. No partial output. This is the same fail-closed rule as
   `mend --soft` today (`docs/FAIL-CLOSED.md`).

What iteration adds over one pass: a stripe row with more than n − k candidates
can still finish if error-mode columns fix enough bytes that some candidate
stripes re-verify, shrinking the erasure set for the remaining columns. How often
that happens is **UNVERIFIED**.

Cost: one extra hash per stripe per pass. The hostile-input bound noted in
DEEP-SPACE §9 (minutes at n = 254) gets a pass-count factor; the loop needs a
hard cap on passes and on total work so a crafted sidecar cannot extend it.

## 5. Option 3: bad-holder detection

The paper detects dead tracks; Sigil's analogue is a **holder** that keeps
returning bad stripes: a Frost Rune drive (`usb-i` in the KIT manifest maps
shard → drive), a network share, a cloud bucket, a server.

- **Faults (F).** With stripe checks, a repair or `doctor --scrub` run can report
  per holder: stripes checked, stripes bad, shards missing. A drive whose bad
  fraction rises between scrubs is failing. This needs only plain checks.
- **Lying holder (A).** A holder that serves consistent but wrong bytes passes
  any check it can recompute: CRC32 and unsigned SHA-256 tables detect faults
  only. Detecting a lying holder needs checks the holder cannot forge: a signed
  stripe table (Ed25519 via the existing `sigil sign` key) or a table obtained
  out of band. On encrypted Sigils the GCM tag already rejects a changed payload
  after decode (`docs/sigil-v1.txt:204`), but it does not say which holder lied;
  a signed table does, per stripe. Unencrypted Sigils have no authenticity at all
  today (`docs/sigil-v1.txt:208–212`).
- **Denial.** A lying holder can always make its own shards useless; the budget
  (n − k bad shards, or per stripe row) is the only defense. Detection lets the
  owner stop trusting that holder; it does not restore data beyond the budget.

## 6. Threat model

Lines in `docs/sigil-v1.txt` this note touches:

| line | where | effect of this note |
|---|---|---|
| F adversary | `:172–174` | in scope: options 1–3 aim at F |
| F claim | `:183–197` | would gain "stripe-level erasure with a sidecar"; the never-wrong-bytes gate is unchanged |
| P adversary / claim | `:174–175`, `:198–203` | sidecar hashes of an **unencrypted** Sigil are hashes of folded plaintext stripes: a holder can confirm a guessed 4 KiB stripe. The true name already allows this for the whole file. For encrypted Sigils the table covers ciphertext and reveals nothing new beyond lengths |
| A adversary / claim | `:176–178`, `:204–212` | CRC and unsigned hash tables give nothing against A. Only a signed table (option 3) touches A, and only for locating bad stripes, not for authenticity of the plaintext |
| destruction beyond budget | THREAT MODEL, out of scope | unchanged: more than n − k bad shards in a stripe row is still loss |

A sidecar is new attack surface: a crafted table can flag every stripe (denial,
falls back to today's path because flags are hints) or mark bad stripes good
(the gate catches the wrong result). Parsers must treat it as hostile input,
with bounded sizes, like every other Sigil structure.

## 7. Measurement plan (DEEP-SPACE harness)

Use `docs/research/deep-space-bench.py` conventions: 1 000 000-byte random file,
fixed seeds, `sigil unseal` then `sigil mend --soft`, byte-for-byte comparison,
columns ok / refused / WRONG, median times. Add a script (planned name
`docs/research/deep-space-stripes.py`) with these damage models, all spread
across many shards:

| id | damage | why |
|---|---|---|
| M1 | uniform scattered flips, 64 … 65 536 | check flags-as-hints do not lose today's results (§3 first table) |
| M2 | B random 4 KiB-aligned stripes replaced by random bytes, B = 16 … 128 | the gap case (§3 second table) |
| M3 | random runs of 512 B, 4 KiB, 64 KiB zeroed at random offsets in random shards | unaligned bursts; flags cover 1–2 stripes per run |
| M4 | M2 plus one holder whose shards are consistently replaced | option 3 report and gate |
| M5 | the deterministic 12-shard example in §3 | one-row regression test |
| M6 | sidecar itself damaged or crafted (all-bad, all-good, truncated) | must fall back, never WRONG |

Report for each: before (main) vs prototype, 100 trials for rows near a budget
edge (10 is not enough there, DEEP-SPACE §9), time and peak memory, number of
iterative passes. Pass criteria: 0 WRONG everywhere; M1 no worse than main; a
measured gain on M2/M3 before any format proposal.

## 8. Perspectives

Each item: as-is / modified / different angle, and the threat-model line.

- **Frost Rune (cold drives).** As-is: one sidecar copy per drive, describing all
  n shards, so any surviving drive has the table. Modified: per-drive tables
  plus a signed whole table, so a scrub can name the failing `usb-i` (option 3).
  Different angle: the KIT manifest already maps shard → drive and is not
  authenticated (`docs/sigil-v1.txt:145`); a signed table could cover it too.
  Lines: F; A for the signed table; P (see the readable-pieces warning below).
- **Fire Rune (hot storage).** Reserved name, no behavior
  (`docs/sigil-v1.txt`, after Frost Rune). As-is: nothing to change. Different
  angle: hot data is rewritten often, so a sidecar must be rewritten with the
  Sigil; the stripe table fits a scrub schedule better than per-write repair.
  Line: F.
- **Servers vs personal PCs.** Servers usually have RAID or ZFS/btrfs checksums
  below Sigil; stripe checks mostly duplicate those, except where Sigil pieces
  sit on different servers (then option 3 is the useful part). Personal PCs with
  one disk get the most from stripe flags, since one bad disk region can hit
  several shards of one `.sg1` (layout risk, **UNVERIFIED**). Line: F.
- **Cloud vs non-cloud.** Cloud object stores check their own integrity; what
  they do not give is proof that the bucket returned what was written. Different
  angle: signed tables let a client test a provider without downloading k
  shards. Lines: A (signed), P (unencrypted tables allow guess confirmation).
- **Sigil installed vs not installed.** A sidecar is optional: a reader without
  this feature ignores it and opens the `.sg1` as today. A decades-later
  re-implementer needs no sidecar to decode; the table only helps repair. Keeping
  it out of `.sg1` keeps the long-term decoder small. Line: F.
- **Linux servers.** As-is via `doctor --scrub` from cron. Modified: per-holder
  health in `--json` for monitoring. Line: F.
- **Windows servers.** Same as Linux; the sidecar must use the same name rules
  as other Sigil sidecars (no new path handling). Line: F.
- **Databases.** Dumps sealed as Sigils: stripe flags help when storage returns
  torn pages (4 KiB / 8 KiB pages match the stripe size). Different angle: a DB
  page size could be a reason to pick 4096 as fixed. Line: F.
- **AWS.** S3 checks objects; EBS/instance disks can return bad blocks. Pieces in
  several buckets or regions: option 3 names the bad bucket. Lines: F; A signed.
- **Mainframe / tape.** The paper's own home. As-is: Sigil rides on top of the
  drive's product code; Frost Rune placement across cartridges works without
  change. Different angle: a cartridge that fails is a "dead track" at a higher
  level, the per-holder report is the analogue of the paper's detector. Product
  codes inside `.sg1`: not proposed (format change, heavier decoder). Line: F.
- **Paper carrier.** 2-D by nature. Different angle: a row/column product code
  with interleaving across pages is the direct use of this paper, as a carrier
  around an unchanged `.sg1` (research only, no approved paper product;
  `/workspace/receipts/sigil-assess-math-finds-1109b.md` item 3). Line: F.

## 9. Related finding: unencrypted Seal pieces are readable (tested)

Checked against the code while writing this note. `seal_plain` folds the body
(`chaos::fold`, a keyless mask keyed only by the salt in the header) and encodes
with **systematic** RS, so data shards 0..k−1 are contiguous slices of the folded
body (`crate/sigil/src/lib.rs` `seal_plain`, `rs::encode_shards_ex`). Every piece
file carries the header (map and Ember) with the salt (`pieces::write_piece`).
Frost Rune places piece i on drive i mod D (`kit::place`), so with D = 4 one
drive holds data pieces 0 and 4 of a Seal (8,16).

Tests added in this branch (`crate/sigil/src/kit.rs`):

- `unencrypted_seal_piece_on_one_frost_drive_is_readable_without_key`: a grep of
  the raw piece does not find the marker, but unfolding with the salt from the
  same piece recovers the exact bytes of its slice; drive `usb-0` alone yields
  data pieces 0 and 4.
- `unencrypted_compressed_text_piece_is_readable_without_key`: for deflated text,
  piece 0 is a prefix of the deflate stream and inflates to readable text.
- `passphrase_seal_piece_on_one_frost_drive_shows_no_plaintext`: with a
  passphrase, no piece on any drive shows the markers or the file name, raw or
  unfolded.

Not tested: encrypt-to (`--to`) seals; the same code path wraps the content key
differently but encrypts the same way, so the result is expected to match the
passphrase case (**UNVERIFIED**). Warnings added to `README.md` (Known
limitations) and `docs/sigil-v1.txt` (Frost Rune and claim P).

## 10. Limitations

- All gain figures are calculations or model simulations, **UNVERIFIED**. The
  models assume uniform placement and ignore header bytes, Embers and the
  Keystone.
- The paper's numbers (BER 10⁻²⁰, 4 of 32 dead tracks, 100–200 MB/s) are for a
  2-D tape product code and were not reproduced; they do not transfer to Sigil's
  1-D 16-shard code.
- Stripe flags hurt scattered-flip repair if used as orders (§3); the hint design
  is not prototyped.
- A sidecar that rots with the data helps less; how often both rot together on
  one disk is **UNVERIFIED**.
- Plain checks never detect a deliberate rewrite. Only a signed table does, and
  only if the verifier trusts the key.
- Nothing here changes `.sg1`, the decoder, or any CLI output.

## 11. Recommendation

ADOPT (no approval needed, docs and tests only, this PR):

1. This note, and the readable-unencrypted-pieces warning with its tests.

PROPOSE TO ASHLYNN:

1. Build the measurement script (§7, M1–M6) and a decoder-side prototype that
   reads an optional sidecar, flags as hints, gate unchanged. No format change.
2. **Sidecar format choice is hers:** CRC32, SHA-256, or SHA-256 + Ed25519
   signature (§3 table); one table per Sigil or per Frost Rune drive.
3. Iterative passes with anchors (§4) only after (1) shows a measured gain on
   M2/M3 and no loss on M1.
4. Per-holder health in `doctor --scrub` / `frost` reports (§5), plain checks
   first; signed tables if she wants lying-holder detection.
5. Separately from this note: should `sigil frost place` warn (or refuse without
   `--allow-plain`) when the input Sigil is unencrypted? That changes CLI output,
   so it was not done here.
6. Additive in-format stripe block: not before measurements, and only with her
   pick.

## Citations

- A. Chvanov, N. Malkovsky, arXiv:2611.09366, 2026 (read).
- C. Häger, H. D. Pfister, "Approaching miscorrection-free performance of
  product codes with anchor decoding", IEEE Trans. Commun. 66(7), 2018 (cited by
  the paper; not read for this note).
- Repository: `docs/sigil-v1.txt`, `docs/SOFT-RS.md`,
  `docs/research/DEEP-SPACE.md`, `docs/FAIL-CLOSED.md`, `docs/LRC-COLD-USB.md`,
  `crate/sigil/src/{lib.rs,rs.rs,pieces.rs,kit.rs,chaos.rs}`.
