# Sigil for deep space: one-way links and onboard corruption

Status: research note, 2026-10-25. Measurements are from the reference
implementation in this repository (`crate/sigil`) on an 8-core x86_64 Linux box
(Intel Xeon, AVX2), rustc 1.99.1, release build. Nothing here was run on flight
hardware or under radiation. Claims that were not measured or read in a source
are marked **UNVERIFIED**.

## Abstract

Sigil stores a file as `n` Reed–Solomon (RS) shards over GF(256), any `k` of
which rebuild it, plus SHA-256 identity checks (true name, Merkle binding).
Two deep-space uses were examined: (1) sending a file over a link where the
round trip is many minutes, so lost data cannot cheaply be asked for again;
(2) keeping files intact in spacecraft storage that collects scattered bit
flips. Measurements on the current code confirm that scattered bit flips were
the weak point: 16 flipped bits in a 1 MB file made every trial refuse to open
(0 of 10 recovered, both modes), because each shard is checked as a whole and
one flipped bit discards a whole shard. Long zeroed runs and truncations within
the budget repair as documented. This branch adds a decoder-only repair,
`mend --soft` column repair, that treats every byte column as its own RS
codeword and corrects up to (present − k)/2 wrong bytes per column, with
the result kept only if the Merkle binding and true name match. With it,
1 024 scattered flips (bit error rate 9.6·10⁻⁵) are repaired in 10 of 10 trials
in Reflection mode and 16 384 flips (1.0·10⁻³) in 10 of 10 trials in Seal mode,
with no wrong output in any trial and no change to the file format. The
RaptorQ fountain mode (`deluge --fountain`) already fits a one-way link.
What it lacks is a way to size its extra packets from an expected loss rate.

## 1. Problem statement

**P1: one-way delivery.** A sender (ground station or spacecraft) must deliver
a file of `F` bytes to a receiver when the one-way light time is minutes (RFC
5325 §2.2 uses 4 minutes one-way for Mars at closest approach). Packets are lost
whole (frames that the link layer could not decode are discarded, see §3).
Asking for the missing ones costs at least one round trip plus the wait for the
next contact. The question: given loss fraction `p`, how much redundancy must
be sent up front so the receiver can rebuild the file without asking, and does
the receiver detect a wrong or incomplete rebuild?

**P2: onboard storage corruption.** A `.sg1` file sits in onboard memory
(SDRAM or flash solid-state recorder) that collects single-event upsets
(scattered single bit flips), multi-bit upsets and block errors (runs), and may
lose the end of a file (torn write). The question: which damage patterns does
Sigil repair, which does it refuse, does it ever return wrong bytes, and how
much CPU time and memory does repair need?

Out of scope: physical-layer coding, link scheduling, ranging, and anything
needing a key exchange during flight.

## 2. Threat model

Sigil's own threat model is in `docs/sigil-v1.txt` ("THREAT MODEL"). The parts
that matter here:

| Adversary | Deep-space example | What Sigil does |
|---|---|---|
| F (faults) | SEU/MBU bit flips, SDRAM/flash block errors, torn writes, lost packets | Repairs within the RS budget; otherwise refuses. Output must match the true name (SHA-256 of plaintext) and length. Never returns different bytes (tested, §5). |
| P (passive reader) | Anyone who records the downlink or reads a recorder dump | Payload confidentiality only with a Ward (`--pass`, `--to`): AES-256-GCM. Without one, the bytes are readable. The fold is not a cipher. |
| A (active tamperer) | Forged uplink file, tampered relay | Encrypted marks: the GCM tag rejects changes. Plain marks: only CRC32 and SHA-256 values in the header, which a tamperer can recompute. Authenticity needs `sigil sign` (Ed25519) or a true name learned another way. |

Two points:

- **Integrity against accidents is not authenticity.** CRC32, the Merkle root
  and the true name catch radiation damage with high probability (SHA-256 for
  the final check). They do not stop someone who rewrites the payload and
  header together. That holds for the new column repair too: a consistent
  forgery is "clean" to the RS decoder, and only the Merkle/true-name check, or
  a signature, rejects it (test
  `mend_soft_column_repair_fails_closed_when_flooded`, forged part).
- **Column repair needs no key.** It works on the stored bytes (ciphertext if
  encrypted) and checks the Merkle binding of the ciphertext. An encrypted mark
  is repaired without its passphrase and still needs the passphrase to open
  (test `mend_soft_column_repair_encrypted_and_wrong_key`).

## 3. Prior work (read for this note)

Only documents that were fetched and read for this note are cited. Section
numbers are the ones printed in those documents.

**CCSDS File Delivery Protocol (CFDP)**, CCSDS 727.0-B-5, Blue Book, July 2020,
https://ccsds.org/Pubs/727x0b5e1.pdf
- §2.3.1: in unacknowledged mode "data delivery failures are not reported to the
  sender and therefore cannot be repaired"; in acknowledged mode the receiver
  reports missing segments, which are retransmitted.
- §2.3.4: NAK release ranges "from immediate release to deferred release
  (whereby any NAKs are stored until the assumed end of the transmission)".
- §3.3 (notes): CFDP assumes the underlying service may deliver errors and miss
  data, and "is not intended to compensate for networks in which these effects
  are prevalent". It "includes no security mechanisms of any kind".
- §4.2.2: the modular checksum (type 0) and null checksum (type 15) are
  mandatory. A NOTE recommends implementing a stronger algorithm "for improved
  protection of the integrity of large files".

**Licklider Transmission Protocol (LTP)**: RFC 5325 (motivation),
https://www.rfc-editor.org/rfc/rfc5325.txt; RFC 5326 (specification),
https://www.rfc-editor.org/rfc/rfc5326.txt; RFC 5327 (security extensions,
including LTP authentication), https://www.rfc-editor.org/rfc/rfc5327.txt;
CCSDS 734.1-B-1, LTP for CCSDS, Blue Book, May 2015,
https://ccsds.org/Pubs/734x1b1.pdf
- RFC 5326 §2 (Terminology; repeated in CCSDS 734.1-B-1 §1.4.1.3): a block is split into
  a **red-part** "to be transmitted reliably, i.e., subject to acknowledgment and
  retransmission" and a **green-part** "not subject to acknowledgments or
  retransmissions".
- RFC 5325 §2.1: Earth to Europa round trips "run between 66 and 100 minutes".
  §2.2 works through why TCP is unsuitable, assuming a minimum Mars RTT of 8
  minutes.

**Bundle Protocol v7**: RFC 9171, https://www.rfc-editor.org/rfc/rfc9171.txt
- §4.2.1: per-block CRC type 0 (none), 1 (X-25 CRC-16), 2 (CRC32C). The
  text points to Block Integrity Blocks of BPSec for stronger integrity. Bundles
  carry a Lifetime field (§4.3.1) after which nodes may discard them.
- CCSDS Bundle Protocol Specification, CCSDS 734.2-B-1, Blue Book, Sept. 2015,
  https://ccsds.org/Pubs/734x2b1.pdf (CCSDS profile of BP; downloaded and
  identified, not studied further).

**TM Synchronization and Channel Coding**, CCSDS 131.0-B-5, Blue Book, Sept.
2023, https://ccsds.org/Pubs/131x0b5.pdf
- §4.1: the RS codes "can correct 16 R-S symbols in error per codeword" (E=16)
  or 8 (E=8). §4.3.2: n = 255, k = n − 2E. Note 1 of §4.3.4 names them
  (255,223) and (255,239). §4.3.5.1: interleaving depth I = 1, 2, 3, 4, 5 or 8.
  §4.2.2 note: the E=16 code "has an extremely low undetected error rate", so
  the RS decoder may be used alone to validate a frame.
- §7.1: LDPC codes, a rate-223/255 code (7.3) and nine codes with rates 1/2,
  2/3, 4/5 (7.4). Section 6: turbo codes.
- What this means here: the link layer corrects bit errors and passes
  undecodable frames up as losses (erasures). A file-level code such as Sigil's
  sees **erasures** on a link, but **errors** (unknown positions) in storage.

**Erasure Correcting Codes for Use in Near-Earth and Deep-Space
Communications**, CCSDS 131.5-O-1 (Experimental, Orange Book, Nov. 2014,
incl. Technical Corrigendum 1, Dec. 2024), https://ccsds.org/Pubs/131x5o1c1.pdf
- §1.2: aimed at cases "where implementation of ARQ schemes is either
  problematic or impossible because of specific service delay constraints".
- Section 2 (p. 2-11): assumes lower layers mark frames correct or erased. It
  lists four strategies (pure FEC, Type-I hybrid ARQ, Type-II hybrid ARQ, "Weather
  Genie") and advises keeping retransmission out of the erasure-coding core and
  leaving it to upper layers (CFDP acknowledged mode, LTP red-part). The codes
  are LDPC/IRA erasure codes in a shim layer.

**RaptorQ**: RFC 6330, https://www.rfc-editor.org/rfc/rfc6330.txt
- Systematic fountain code. §5.8: a compliant decoder given K' symbols with
  random ESIs fails at most 1 in 100 times on average, at K'+1 at most 1 in 10 000,
  at K'+2 at most 1 in 1 000 000. §5.1.2: K'_max = 56 403 symbols per source
  block. Sigil's `deluge --fountain` uses the `raptorq` crate 2.0.0
  (`docs/FOUNTAIN-v2.md`).

**Onboard memory scrubbing and EDAC**
- Ladbury, Poivey, Gee, Barth, LaBel, Safren, *Lessons Learned from Radiation
  Induced Effects on Solid State Recorders (SSR) and Memories*, NASA GSFC/NEPP,
  2002, updated March 2013,
  https://nepp.nasa.gov/files/24662/Ladbury_2013_n224_SSR%20Update.pdf. §1.2.1.2.1:
  since 2002 single-event functional interrupts (SEFI) and block errors have
  become more important relative to SEU. For an Elpida 512 Mbit SDRAM, block
  errors occur at more than 1% of the SEU rate and each upsets hundreds of
  addresses, so they "will dominate the data errors". §5.3.1: "Hamming codes will
  fail in cases of SMU" (multiple upsets in one word). LEO SEUs come in bursts in
  the South Atlantic Anomaly, and "the scrubbing rate needs to be calculated for
  this high SEU rate".
- Swift and Guertin, *In-Flight Observations of Multiple-Bit Upset in DRAMs*,
  IEEE Trans. Nucl. Sci. 47(6) (JPL preprint marked "© 2001 IEEE ... in press"),
  https://nepp.nasa.gov/docuploads/5C83952E-CB29-424E-97BA449CF8181E7C/CassDRAM-00.pdf.
  Abstract: the Cassini solid-state recorder saw "the predicted number of
  upsets, but a very high rate of uncorrectable errors", explained by a high
  MBU rate "in combination with an architectural flaw in the error correction
  circuitry".
- Maurer and Goldsten, *The Van Allen Probes Engineering Radiation Monitor:
  Mission Radiation Environment and Effects*, JHU APL Technical Digest 33(3),
  2016,
  https://secwww.jhuapl.edu/techdigest/Content/techdigest/pdf/V33-N03/33-03-Maurer.pdf.
  Raising the SSR scrub rate "appeared to exponentially increase the corrected
  error counts". The cause was an SDRAM read/write timing issue visible only with
  multiple burst errors. A software scrub with SDRAM mode-register resets,
  uploaded October 2012, "significantly decreased the corrected error counts".
- NASA IV&V, *Lessons Learned From a Memory-Scrub Anomaly* (slides),
  https://www.nasa.gov/wp-content/uploads/2016/10/ivv_mirfakhraie_ivv_lessons_learned_from_a_memory-scrub_anomaly_090114.pdf.
  Hardware SECDED scrubbing "took ~4.7 seconds to scrub all of system memory".
  On an uncorrectable error the handler rewrote the location so its check bits
  matched again: "the contents of the memory would still be ... (most likely bad)
  ... but the scrub routine would not flag an error".
- Mars Science Laboratory (Curiosity), JPL news release "Computer Swap on
  Curiosity Rover", 28 Feb 2013,
  https://www.jpl.nasa.gov/news/computer-swap-on-curiosity-rover/: the problem
  "involved corrupted memory at an A-side memory location used for addressing
  memory files", and the rover was switched to its B-side computer. NASA Lessons
  Learned entry 11201 (https://llis.nasa.gov/lesson/11201) describes
  uncorrectable NAND flash errors and a single failing flash chip. **UNVERIFIED**:
  that page is script-rendered and could not be fetched. Only a search-engine
  excerpt was seen.
- Mars Reconnaissance Orbiter: no documented solid-state-recorder corruption
  incident was found. Nothing about MRO is claimed here.

## 4. Sigil as implemented (read from the code)

| Piece | Code | Behavior relevant here |
|---|---|---|
| Seal / Reflection | `rs.rs`, `lib.rs` | Systematic (v2) Vandermonde RS over GF(256), point x = index+1. Defaults n=16: Reflection k=12, Seal k=8. Max index 254. |
| Shard check | `header.rs` `gather_live_shards` | Each shard has its own CRC32. A CRC failure drops the whole shard (erasure). |
| Header copies | Keystone (3 copies), Ember (one per shard) | Header found even with the front destroyed. |
| Final check | `pieces::accept_folded`, unseal | Re-encode, compare Merkle root of all n shards with the header. Plain marks: SHA-256 of plaintext = true name. |
| Soft mend (before this branch) | `rs::decode_soft` | Keeps CRC-failed bodies and tries erasing up to n−k "soft" shards or 4 KiB stripes in index order. Has no way to locate which bytes are wrong. Measured: it fixed none of the scattered-flip cases (§5) and took about 9 s per refusal on a 1 MB file. |
| Large files | `work.rs` (SGWK) | 4 MiB chunks, each a complete seal (per-chunk recovery exists). Peak memory stays below file size (§5.4). |
| Fountain | `fountain.rs`, `deluge --fountain`, `gather` | RaptorQ over the whole `.sg1`; packets carry per-packet SHA-256 and the object SHA-256. Damaged packets are skipped (erasures). The rebuilt `.sg1` is checked against the object SHA-256. |
| Scatter / deluge | `pieces.rs` | Extra RS evaluations up to index 254 as `.sgp` files. |

## 5. Measurements

### 5.1 How to reproduce

```
cargo build --locked --release --bin sigil
python3 docs/research/deep-space-bench.py target/release/sigil 10 1000000
python3 docs/research/deep-space-scrub.py target/release/sigil 10 1024 8
python3 docs/research/deep-space-mem.py   target/release/sigil 64
```

`deep-space-bench.py` seals one 1 000 000-byte random file (fixed seed) and
damages copies with fixed seeds (trial index). Each case runs `sigil unseal`.
If that refuses, it runs `sigil mend --soft` and unseals the result. Every output
is compared byte for byte with the original. "Before" is `origin/main` at
`7b6aab6`, "after" is this branch. Both were run with the same script and seeds.
Times are wall-clock medians of whole CLI calls (process start included) on the
successful path. They include contention from the other benchmark that ran at
the same time, so treat them as rough.

### 5.2 Storage damage (1 MB file, 10 trials per row)

Reflection mark = 1 336 608 B (16 shards of 83 334 B, any 12). Seal mark =
2 003 264 B (16 of 125 000 B, any 8). "ok" = exact bytes, either directly or
after `mend --soft`. No row in either build had a WRONG result.

| mode | damage | before: ok / refused | after: ok / refused | after: how | after: median ms |
|---|---|---|---|---|---|
| Reflection | 1 flipped bit | 10 / 0 | 10 / 0 | direct | 25 |
| Reflection | 4 flipped bits | 10 / 0 | 10 / 0 | direct | 24 |
| Reflection | 16 flipped bits | 0 / 10 | 10 / 0 | mend --soft | 62 |
| Reflection | 64 | 0 / 10 | 10 / 0 | mend --soft | 64 |
| Reflection | 256 | 0 / 10 | 10 / 0 | mend --soft | 64 |
| Reflection | 1 024 (BER 9.6e-5) | 0 / 10 | 10 / 0 | mend --soft | 64 |
| Reflection | 4 096 (BER 3.8e-4) | 0 / 10 | 3 / 7 | mend --soft | 81 |
| Reflection | 16 384 | 0 / 10 | 0 / 10 | none | - |
| Reflection | zeroed run 1% / 10% of mark | 10 / 0 each | 10 / 0 each | direct | 26-27 |
| Reflection | zeroed run 20% | 8 / 2 | 8 / 2 | direct | 26 |
| Reflection | zeroed run 30% / 45% | 0 / 10 each | 0 / 10 each | - | - |
| Reflection | truncate 0.1% / 10% / 20% | 10 / 0 each | 10 / 0 each | direct | 24-25 |
| Reflection | truncate 30% / 45% | 0 / 10 each | 0 / 10 each | - | - |
| Seal | 1 / 4 flipped bits | 10 / 0 each | 10 / 0 each | direct | 25-26 |
| Seal | 16 / 64 / 256 / 1 024 | 0 / 10 each | 10 / 0 each | mend --soft | 72-79 |
| Seal | 4 096 | 0 / 10 | 10 / 0 | mend --soft | 92 |
| Seal | 16 384 (BER 1.0e-3) | 0 / 10 | 10 / 0 | mend --soft | 141 |
| Seal | zeroed run 1% … 30% | 10 / 0 each | 10 / 0 each | direct | 25-26 |
| Seal | zeroed run 45% | 7 / 3 | 7 / 3 | direct | 31 |
| Seal | truncate 0.1% … 45% | 10 / 0 each | 10 / 0 each | direct | 24-27 |

Raw outputs of both runs are in the Appendix.

Readings:
- The prior result "scattered bit flips currently fail; long damaged runs mend"
  is confirmed for `origin/main`. Up to n−k damaged shards are fine, so 1–4 flips
  pass. At 16 flips, more than 4 (Reflection) or 8 (Seal) of the 16 shards are
  hit with high probability, and every trial refused.
- The 20% zeroed run in Reflection fails 2 of 10 times. That is the budget
  edge: a run of 20% of the mark can overlap 5 of 16 shards depending on where
  it starts. Seal at 45% behaves the same way.
- Column repair changed none of the run or truncation rows. That is expected:
  those cases are erasures and were already handled.

**Model check (calculation, not a measurement):** with `B` flips spread over
`M` bytes, each byte is hit with probability `q ≈ B/M`. A column (16 bytes)
fails when more than `t = (n−k)/2` of its bytes are hit. With `L` columns, the
expected number of failing columns is `L·P[Bin(16,q) > t]`. Reflection
(t=2, L=83 334): 1 024 flips gives 0.021, so success ≈ 98%; 4 096 gives 1.3, so
success ≈ e^−1.3 ≈ 27% (measured 3/10); 16 384 gives 76, so ≈ 0%. Seal (t=4,
L=125 000): 16 384 flips gives 0.019, so success ≈ 98% (measured 10/10). The
model ignores header bytes and assumes independent flips. Real upsets are often
bursty or block-shaped (Ladbury 2013), so this is a lower bound on the trouble.

**What the benchmark found besides scattered flips.** In the first "after" run,
Seal at 16 384 flips failed 5 of 10 times. Every failure was a trial in which
all four front header copies had been hit (seen by checking each trial). The
header was then taken from an Ember, and the body offset was chosen by "most
CRC-good shards at this offset". With nearly every CRC broken, that was a tie,
and the first candidate (offset 0, which was wrong) won. Fixed on this branch:
`header::score_prefix` breaks ties by counting Embers that sit where the offset
puts them. CRC count still comes first, so earlier choices are unchanged.
After the fix, 10/10 (table above). A second small defect: a header rebuilt from
an Ember kept that Ember's slot number in the top byte of the entropy word, so
the mended file differed from the original in 5 header bytes per copy (the file
still opened). Fixed too. Tests:
`mend_soft_finds_body_offset_when_front_header_and_all_crcs_are_gone` (fails on
`origin/main`, passes here) and `mend_from_ember_header_restores_exact_front_header`.

### 5.3 Scrubbing: errors that pile up (1 MB, Reflection, 10 trials)

`deep-space-scrub.py`: 8 epochs of 1 024 random flips each (8 192 total).

| policy | exact | refused | WRONG |
|---|---|---|---|
| `mend --soft` after every epoch (scrubbed) | 9 | 1 | 0 |
| one `mend --soft` after all 8 epochs | 0 | 10 | 0 |

The one scrubbed failure is consistent with the model in §5.2 (about 2% chance
of a failing column per epoch, so ≈ 16% over 8 epochs). Its cause was not
inspected. Rewriting a clean copy before damage accumulates
is what turns "dead" into "repaired". This matches the reason missions scrub
memory at all. Unlike the hardware scrub in the IV&V anomaly, Sigil refuses to
write a "repaired" copy unless the SHA-256 checks pass, so it cannot hide an
uncorrectable error.

### 5.4 Memory and time (64 MiB random file, single run each)

`deep-space-mem.py` (peak RSS of the `sigil` child; floor ≈ 10 MiB is the helper):

| step | exit | seconds | peak RSS MiB |
|---|---|---|---|
| seal (Reflection; 16 × 4 MiB chunk stars) | 0 | 3.05 | 30 |
| unseal | 0 | 1.49 | 38 |
| mend (healthy) | 0 | 0.32 | 16 |
| mend --soft (1 flip per 64 KiB of mark, ≈ 1 370 flips) | 0 | 2.15 | 52 |
| unseal of the mended copy | 0 | 1.42 | 38 |

The mended copy unsealed to the exact input. Large files are processed one
4 MiB chunk at a time, so peak memory is set by the chunk size, not the file
size. This was measured at one size only; scaling with `--chunk` is **UNVERIFIED**.

Column repair cost with many shards (`seal --mode seal --shards 254`, 1 MB,
single runs): 2 000 flips took 14.0 s and 8 000 flips took 39.8 s to mend, both
exact. The Berlekamp–Welch solve is O(p·(k+2t)²) per damaged column, so large `n`
is slow. At the default n = 16 it is not noticeable (the table above).

### 5.5 Fountain over a lossy one-way link (1 MB Reflection mark, 10 trials)

`deluge --fountain --extra E` on the 1 336 608-byte mark gives 82 source
packets plus E. Random packets are then deleted, and the rest is run through
`gather` + `unseal`.

| extra E (overhead) | packets | 0% lost | 5% | 10% | 25% | 50% |
|---|---|---|---|---|---|---|
| 4 (4.9%) | 86 | 10/10 | 10/10 | 0/10 | 0/10 | 0/10 |
| 16 (19.5%) | 98 | 10/10 | 10/10 | 10/10 | 0/10 | 0/10 |
| 64 (78%) | 146 | 10/10 | 10/10 | 10/10 | 10/10 | 0/10 |

Same results before and after this branch (fountain code unchanged). All
refusals were "not enough packets". None produced wrong bytes. Median
gather + unseal ≈ 32–35 ms. Each outcome follows from the count: the rebuild
works when the packets that survive are ≥ 82 (RaptorQ may need K'+1 or K'+2
in rare cases, RFC 6330 §5.8).

## 6. Standards compared with Sigil

| Need | Standards approach | Sigil today | Gap |
|---|---|---|---|
| Bit errors on the link | CCSDS 131.0: RS(255,223) corrects 16 symbol errors; LDPC/turbo | Not Sigil's layer | None (use the link codes) |
| Lost frames/packets, no time to re-ask | CCSDS 131.5-O-1 LDPC erasure codes; LTP green-part; CFDP unacknowledged | `deluge --fountain` (RaptorQ, rateless, random ESIs) | No rule for how many extras to send for a given loss rate |
| Re-ask when there is time | CFDP acknowledged (deferred NAK); LTP red-part | `gather` prints "need N more"; `deluge --extra` tops up | No compact "what I have" summary to send back |
| End-to-end file integrity | CFDP checksum (modular checksum mandatory; stronger recommended); BP CRC16/CRC32C; BPSec | SHA-256 true name + Merkle; per-packet SHA-256 | Sigil's check is stronger than the CFDP default |
| Authenticity | LTP authentication (RFC 5327); BPSec | Ed25519 `sigil sign`; AES-GCM tag when encrypted | Plain marks unauthenticated unless signed |
| Memory upsets | EDAC (SECDED, multi-bit codes) + periodic scrubbing | Shard-level erasure, and now column repair in `mend --soft` | No built-in scrub schedule; repair only on request |

## 7. Proposed changes, each with a test that would verify it

1. **Column repair in `mend --soft`.** PROTOTYPED on this branch (§8).
   Verify: §5.2 table rows for 16–16 384 flips. Tests in `rs::tests::column_errors_*`,
   `tests::mend_soft_column_repair_*`, `cli_mend::mend_soft_cli_repairs_scattered_bit_flips`.
2. **Opt-in `unseal --repair`** (column repair in memory, then open, without
   writing a mended file). It must stay opt-in under the "safest by default"
   rule until it has more field time. Test: for each §5.2 bit-flip row,
   `unseal --repair` gives the same ok/refused counts as `mend --soft` + `unseal`,
   with no output file on refusal.
3. **Fountain sizing from a loss estimate: `deluge --fountain --loss P`.** BUILT
   (`crate/sigil/src/fountain_loss.rs`, `cli_fountain::loss_picks_the_packet_count_and_bad_values_are_refused`;
   seeded trials at P ∈ {0.05, 0.10, 0.25, 0.5} rebuild 100 of 100, and the packets written equal
   the formula exactly). Pick
   extras so that P[surviving packets < K'+2] stays below a target, using the
   binomial tail. Test: for P ∈ {0.05, 0.10, 0.25}, 100 trials of random
   deletion at rate P each rebuild in ≥ 99. A second test checks that the
   overhead written is within one packet of the formula.
4. **Fountain-first sends with per-chunk blocks for large files.** Raining
   each 4 MiB chunk star separately would let the receiver verify and keep each
   chunk as soon as its packets suffice. Today the whole `.sg1` is one object.
   Test: drop every packet of one chunk. `gather --partial` (opt-in) writes the
   other chunks verified into a part file plus a map of the missing ranges,
   and never writes the final name. A normal `gather` still refuses.
5. **Compact receiver report (deferred-NAK style).** `gather --report` prints a
   short line per source block, "have / need", that fits in one uplink packet,
   for the CFDP-acknowledged style follow-up. Test: the report size for a
   100-block object is ≤ 1 KiB. Feeding it to `deluge --extra` on the sender
   produces exactly the missing count per block.
6. **Scrub command: `sigil doctor --scrub DIR`.** Periodically run column repair
   on every mark and rewrite only when the Merkle/true-name check passes, then
   log what changed. Test: the §5.3 experiment run through the command, with
   9/10 or better scrubbed vs 0/10 unscrubbed. A mark with an uncorrectable
   column is reported and left byte-identical.
7. **Faster column decoder for large n and low-power CPUs.** Syndrome decoding
   (Berlekamp–Massey + Chien search + Forney) is O(t²) + O(n·t) per dirty
   column instead of the O(n³) solve. Test: property test that its output
   equals `decode_column_errors` on random patterns up to the budget, and the
   n=254, 8 000-flip case under 2 s on this box.
8. **Interleaving across shards for burst damage.** Block errors of hundreds of
   addresses (Ladbury 2013) land in one or two shards, which erasure decoding
   already absorbs, so no change is proposed. Test to confirm: zero 1 KiB runs at
   100 random offsets in a Seal mark, and all trials recover.

## 8. Prototype: column repair (additive, decoder only)

- `rs::decode_column_errors(parts, k, shard_len, payload_len, systematic)`. Every
  present shard body (CRC-good or not) is used. Missing shards are erasures. The
  first k shards predict the others through one matrix pass
  (`gf::matrix_apply`). Columns where every prediction matches are clean. Each
  other column runs Berlekamp–Welch with e = ⌊(p−k)/2⌋, solved by Gaussian
  elimination over GF(256), then an exact polynomial division. The column is
  corrected only if ≤ e symbols disagree. Any column beyond that fails the whole
  call (no partial result).
- Wired into `pieces::mend_bytes_ex` as the first step of the `--soft` path.
  Its output goes through the same `accept_folded` gate (Merkle of all n
  re-encoded shards, plus the true name when not encrypted) as every other path.
  The old GMD-lite path still runs if it fails. Work packs inherit it through
  `mend_pack_path`.
- **Format:** unchanged. No new block, no header change. Every existing `.sg1`
  benefits as it is. Plain `unseal` and plain `mend` behave exactly as before.
  `--soft` was already an opt-in flag.
- **Primitives:** GF(256) arithmetic already in `gf.rs`, SHA-256 and CRC32 already
  used. No new dependencies, no `unsafe`, no `unwrap`/`expect` in library code.
- **Tests added (11):**
  `rs::tests::column_errors_fix_scattered_symbols_and_erasures` (v1 and v2, five
  shapes, mixed erasures + errors at the budget),
  `column_errors_clean_input_matches_erasure_decode`,
  `column_errors_beyond_budget_never_return_the_original_unchecked`,
  `column_errors_without_spare_shards_refuse` (budget 0, fewer than k, wrong
  lengths, k = 0, duplicate/out-of-range indexes);
  `tests::mend_soft_column_repair_fixes_scattered_bit_flips` (mended mark is
  byte-identical to the original), `..._encrypted_and_wrong_key`,
  `..._with_truncation_and_flips`, `..._fails_closed_when_flooded` (5% of bits
  flipped, and a consistent forgery: refused),
  `mend_soft_finds_body_offset_when_front_header_and_all_crcs_are_gone`,
  `mend_from_ember_header_restores_exact_front_header`;
  `cli_mend::mend_soft_cli_repairs_scattered_bit_flips` (plain unseal and plain
  mend refuse, no output file left; `mend --soft` + unseal exact).

## 9. Limitations

- All numbers come from one x86_64 box, 10 trials per row (single runs for §5.4
  and the n = 254 timings). Ten trials cannot show rare failures. A 0/10 WRONG count
  is not a proof. The proof that wrong bytes are not returned is the SHA-256
  acceptance gate, not these trials.
- Flips are uniform and independent. Real upsets include multi-bit upsets, SEFI
  and stuck bits (Ladbury 2013; Swift and Guertin 2000). Performance on those
  patterns was not measured except as contiguous zeroed runs.
- Column repair runs only in `mend --soft`. A plain `unseal` of a bit-flipped file
  still refuses (by design; proposal 2).
- Damage outside shard bodies is handled separately: the front header (four
  copies plus the Embers), the SGTO key block of encrypted marks, and work-pack
  heads. Heavy damage to the SGTO block of an encrypted mark makes it unopenable
  even when every shard is repaired. **UNVERIFIED** at what rate this happens; not
  measured.
- Glyph mode has no parity and gains nothing.
- At large n (254 shards) column repair is slow (§5.4). A hostile file can make
  `mend --soft` spend roughly (shard length × per-column solve) time before it
  refuses. It is bounded but can take minutes at n = 254.
- The fountain results assume packets are either intact or detected as damaged
  (the per-packet SHA-256 does that). They say nothing about packet sizes that fit
  CCSDS frames or BP bundles. Matching those is **UNVERIFIED**.
- No flight software, real-time OS, radiation-hardened CPU or power budget was
  tested. "Low-power decode" here means the algorithmic cost only.
- Mars one-way light time beyond the 4-minute minimum in RFC 5325 is not cited;
  the often-quoted maximum near 22 minutes is **UNVERIFIED** here.

## 10. In plain language (for an audience)

Sigil packs a file into 16 pieces with extra repair data built in. Before this
work, Sigil treated each piece as either fine or broken, and even one wrong
bit made a whole piece count as broken. That works well when a chunk of the
file is destroyed, like a bad patch of disk or a download cut off at the end.
It worked badly for radiation in space, which flips single bits here and there
across everything: sixteen flipped bits were enough to make a 1 MB file
unrecoverable in every test. The new repair looks at the file in thin
slices across all 16 pieces, so a flipped bit only damages one small slice of
one piece, and the built-in math can find and fix it. In tests it fixed a
thousand scattered flips every time in the normal mode, and sixteen thousand in
the heavy-protection mode. It never handed back a wrong file, because the result
is kept only if its digital fingerprint matches the original exactly. Repairing
the file regularly, before damage piles up, matters as much as the repair
itself: eight rounds of damage were survived 9 times out of 10 with regular
repair and 0 times out of 10 without it. For sending files to Mars, Sigil can
already send extra "spare" packets so the far side can rebuild the file without
asking again, which can take most of an hour, and with `--loss 10%` it now
works out how many spares to send for a given amount of expected loss.

## Appendix: raw benchmark output

`origin/main` (7b6aab6) and this branch, same script, 10 trials, 1 000 000-byte file.

`origin/main` (binary reports `7b6aab6`):

```
sigil: sigil 1.0.0 (commit 7b6aab6)
file: 1000000 random bytes, trials per case: 10

| mode | damage | direct | mended | refused | WRONG | median ms (ok path) |
|---|---|---|---|---|---|---|
| reflection (1336608 B) | 1 scattered bit flips | 10 | 0 | 0 | 0 | 24 |
| reflection (1336608 B) | 4 scattered bit flips | 10 | 0 | 0 | 0 | 24 |
| reflection (1336608 B) | 16 scattered bit flips | 0 | 0 | 10 | 0 | - |
| reflection (1336608 B) | 64 scattered bit flips | 0 | 0 | 10 | 0 | - |
| reflection (1336608 B) | 256 scattered bit flips | 0 | 0 | 10 | 0 | - |
| reflection (1336608 B) | 1024 scattered bit flips | 0 | 0 | 10 | 0 | - |
| reflection (1336608 B) | 4096 scattered bit flips | 0 | 0 | 10 | 0 | - |
| reflection (1336608 B) | 16384 scattered bit flips | 0 | 0 | 10 | 0 | - |
| reflection (1336608 B) | zeroed run 1% of .sg1 | 10 | 0 | 0 | 0 | 25 |
| reflection (1336608 B) | zeroed run 10% of .sg1 | 10 | 0 | 0 | 0 | 23 |
| reflection (1336608 B) | zeroed run 20% of .sg1 | 8 | 0 | 2 | 0 | 23 |
| reflection (1336608 B) | zeroed run 30% of .sg1 | 0 | 0 | 10 | 0 | - |
| reflection (1336608 B) | zeroed run 45% of .sg1 | 0 | 0 | 10 | 0 | - |
| reflection (1336608 B) | truncate 0.1% of .sg1 | 10 | 0 | 0 | 0 | 25 |
| reflection (1336608 B) | truncate 10.0% of .sg1 | 10 | 0 | 0 | 0 | 22 |
| reflection (1336608 B) | truncate 20.0% of .sg1 | 10 | 0 | 0 | 0 | 22 |
| reflection (1336608 B) | truncate 30.0% of .sg1 | 0 | 0 | 10 | 0 | - |
| reflection (1336608 B) | truncate 45.0% of .sg1 | 0 | 0 | 10 | 0 | - |
| seal (2003264 B) | 1 scattered bit flips | 10 | 0 | 0 | 0 | 24 |
| seal (2003264 B) | 4 scattered bit flips | 10 | 0 | 0 | 0 | 24 |
| seal (2003264 B) | 16 scattered bit flips | 0 | 0 | 10 | 0 | - |
| seal (2003264 B) | 64 scattered bit flips | 0 | 0 | 10 | 0 | - |
| seal (2003264 B) | 256 scattered bit flips | 0 | 0 | 10 | 0 | - |
| seal (2003264 B) | 1024 scattered bit flips | 0 | 0 | 10 | 0 | - |
| seal (2003264 B) | 4096 scattered bit flips | 0 | 0 | 10 | 0 | - |
| seal (2003264 B) | 16384 scattered bit flips | 0 | 0 | 10 | 0 | - |
| seal (2003264 B) | zeroed run 1% of .sg1 | 10 | 0 | 0 | 0 | 25 |
| seal (2003264 B) | zeroed run 10% of .sg1 | 10 | 0 | 0 | 0 | 25 |
| seal (2003264 B) | zeroed run 20% of .sg1 | 10 | 0 | 0 | 0 | 24 |
| seal (2003264 B) | zeroed run 30% of .sg1 | 10 | 0 | 0 | 0 | 25 |
| seal (2003264 B) | zeroed run 45% of .sg1 | 7 | 0 | 3 | 0 | 26 |
| seal (2003264 B) | truncate 0.1% of .sg1 | 10 | 0 | 0 | 0 | 25 |
| seal (2003264 B) | truncate 10.0% of .sg1 | 10 | 0 | 0 | 0 | 25 |
| seal (2003264 B) | truncate 20.0% of .sg1 | 10 | 0 | 0 | 0 | 24 |
| seal (2003264 B) | truncate 30.0% of .sg1 | 10 | 0 | 0 | 0 | 24 |
| seal (2003264 B) | truncate 45.0% of .sg1 | 10 | 0 | 0 | 0 | 22 |

| fountain (.rq of a reflection .sg1) | extra | packets written | dropped | rebuilt exact | refused | WRONG | median gather+unseal ms |
|---|---|---|---|---|---|---|---|
| reflection | 4 | 86 | 0% | 10 | 0 | 0 | 32 |
| reflection | 4 | 86 | 5% | 10 | 0 | 0 | 30 |
| reflection | 4 | 86 | 10% | 0 | 10 | 0 | - |
| reflection | 4 | 86 | 25% | 0 | 10 | 0 | - |
| reflection | 4 | 86 | 50% | 0 | 10 | 0 | - |
| reflection | 16 | 98 | 0% | 10 | 0 | 0 | 33 |
| reflection | 16 | 98 | 5% | 10 | 0 | 0 | 31 |
| reflection | 16 | 98 | 10% | 10 | 0 | 0 | 32 |
| reflection | 16 | 98 | 25% | 0 | 10 | 0 | - |
| reflection | 16 | 98 | 50% | 0 | 10 | 0 | - |
| reflection | 64 | 146 | 0% | 10 | 0 | 0 | 33 |
| reflection | 64 | 146 | 5% | 10 | 0 | 0 | 32 |
| reflection | 64 | 146 | 10% | 10 | 0 | 0 | 34 |
| reflection | 64 | 146 | 25% | 10 | 0 | 0 | 32 |
| reflection | 64 | 146 | 50% | 0 | 10 | 0 | - |
```

This branch (built from the uncommitted working tree on top of 7b6aab6, so it reports `7b6aab6-dirty`; same code as the PR commit):

```
sigil: sigil 1.0.0 (commit 7b6aab6-dirty)
file: 1000000 random bytes, trials per case: 10

| mode | damage | direct | mended | refused | WRONG | median ms (ok path) |
|---|---|---|---|---|---|---|
| reflection (1336608 B) | 1 scattered bit flips | 10 | 0 | 0 | 0 | 25 |
| reflection (1336608 B) | 4 scattered bit flips | 10 | 0 | 0 | 0 | 24 |
| reflection (1336608 B) | 16 scattered bit flips | 0 | 10 | 0 | 0 | 62 |
| reflection (1336608 B) | 64 scattered bit flips | 0 | 10 | 0 | 0 | 64 |
| reflection (1336608 B) | 256 scattered bit flips | 0 | 10 | 0 | 0 | 64 |
| reflection (1336608 B) | 1024 scattered bit flips | 0 | 10 | 0 | 0 | 64 |
| reflection (1336608 B) | 4096 scattered bit flips | 0 | 3 | 7 | 0 | 81 |
| reflection (1336608 B) | 16384 scattered bit flips | 0 | 0 | 10 | 0 | - |
| reflection (1336608 B) | zeroed run 1% of .sg1 | 10 | 0 | 0 | 0 | 27 |
| reflection (1336608 B) | zeroed run 10% of .sg1 | 10 | 0 | 0 | 0 | 26 |
| reflection (1336608 B) | zeroed run 20% of .sg1 | 8 | 0 | 2 | 0 | 26 |
| reflection (1336608 B) | zeroed run 30% of .sg1 | 0 | 0 | 10 | 0 | - |
| reflection (1336608 B) | zeroed run 45% of .sg1 | 0 | 0 | 10 | 0 | - |
| reflection (1336608 B) | truncate 0.1% of .sg1 | 10 | 0 | 0 | 0 | 24 |
| reflection (1336608 B) | truncate 10.0% of .sg1 | 10 | 0 | 0 | 0 | 24 |
| reflection (1336608 B) | truncate 20.0% of .sg1 | 10 | 0 | 0 | 0 | 25 |
| reflection (1336608 B) | truncate 30.0% of .sg1 | 0 | 0 | 10 | 0 | - |
| reflection (1336608 B) | truncate 45.0% of .sg1 | 0 | 0 | 10 | 0 | - |
| seal (2003264 B) | 1 scattered bit flips | 10 | 0 | 0 | 0 | 26 |
| seal (2003264 B) | 4 scattered bit flips | 10 | 0 | 0 | 0 | 25 |
| seal (2003264 B) | 16 scattered bit flips | 0 | 10 | 0 | 0 | 74 |
| seal (2003264 B) | 64 scattered bit flips | 0 | 10 | 0 | 0 | 72 |
| seal (2003264 B) | 256 scattered bit flips | 0 | 10 | 0 | 0 | 75 |
| seal (2003264 B) | 1024 scattered bit flips | 0 | 10 | 0 | 0 | 79 |
| seal (2003264 B) | 4096 scattered bit flips | 0 | 10 | 0 | 0 | 92 |
| seal (2003264 B) | 16384 scattered bit flips | 0 | 10 | 0 | 0 | 141 |
| seal (2003264 B) | zeroed run 1% of .sg1 | 10 | 0 | 0 | 0 | 26 |
| seal (2003264 B) | zeroed run 10% of .sg1 | 10 | 0 | 0 | 0 | 25 |
| seal (2003264 B) | zeroed run 20% of .sg1 | 10 | 0 | 0 | 0 | 25 |
| seal (2003264 B) | zeroed run 30% of .sg1 | 10 | 0 | 0 | 0 | 25 |
| seal (2003264 B) | zeroed run 45% of .sg1 | 7 | 0 | 3 | 0 | 31 |
| seal (2003264 B) | truncate 0.1% of .sg1 | 10 | 0 | 0 | 0 | 27 |
| seal (2003264 B) | truncate 10.0% of .sg1 | 10 | 0 | 0 | 0 | 25 |
| seal (2003264 B) | truncate 20.0% of .sg1 | 10 | 0 | 0 | 0 | 25 |
| seal (2003264 B) | truncate 30.0% of .sg1 | 10 | 0 | 0 | 0 | 26 |
| seal (2003264 B) | truncate 45.0% of .sg1 | 10 | 0 | 0 | 0 | 24 |

| fountain (.rq of a reflection .sg1) | extra | packets written | dropped | rebuilt exact | refused | WRONG | median gather+unseal ms |
|---|---|---|---|---|---|---|---|
| reflection | 4 | 86 | 0% | 10 | 0 | 0 | 33 |
| reflection | 4 | 86 | 5% | 10 | 0 | 0 | 32 |
| reflection | 4 | 86 | 10% | 0 | 10 | 0 | - |
| reflection | 4 | 86 | 25% | 0 | 10 | 0 | - |
| reflection | 4 | 86 | 50% | 0 | 10 | 0 | - |
| reflection | 16 | 98 | 0% | 10 | 0 | 0 | 34 |
| reflection | 16 | 98 | 5% | 10 | 0 | 0 | 32 |
| reflection | 16 | 98 | 10% | 10 | 0 | 0 | 33 |
| reflection | 16 | 98 | 25% | 0 | 10 | 0 | - |
| reflection | 16 | 98 | 50% | 0 | 10 | 0 | - |
| reflection | 64 | 146 | 0% | 10 | 0 | 0 | 35 |
| reflection | 64 | 146 | 5% | 10 | 0 | 0 | 34 |
| reflection | 64 | 146 | 10% | 10 | 0 | 0 | 34 |
| reflection | 64 | 146 | 25% | 10 | 0 | 0 | 33 |
| reflection | 64 | 146 | 50% | 0 | 10 | 0 | - |
```

Scrub experiment (this branch):

```
1024 flips per epoch x 8 epochs = 8192 flips total, 1336608 B mark, 10 trials

| policy | exact | refused | WRONG |
|---|---|---|---|
| scrubbed | 9 | 1 | 0 |
| unscrubbed | 0 | 10 | 0 |
```

Memory (this branch):

```
| step (64 MiB random input) | exit | seconds | peak RSS MiB |
|---|---|---|---|
| seal (reflection) | 0 | 3.05 | 30 |
| unseal | 0 | 1.49 | 38 |
| mend (healthy input) | 0 | 0.32 | 16 |
| mend --soft (1 bit flip / 64 KiB) | 0 | 2.15 | 52 |
| unseal of mended copy | 0 | 1.42 | 38 |

exact after mend --soft: True
```
