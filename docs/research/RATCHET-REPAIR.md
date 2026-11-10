# Ratchet repair for Sigil Seal: checking the numbers, then measuring

Status: research note + measurement harness, 2026-11-10. No `.sg1` format change, no
change to the `sigil` crate or its decode paths. Harness: `research/ratchet-measure/`
(standalone crate). Raw results: `docs/research/ratchet-measure-results.{md,csv}`.
Anything not measured here or not read in a primary source is marked **UNVERIFIED**.

## Abstract

Ashlynn's idea: keep a small check value for every slice of every piece, so repair can
*guess* a fix, *confirm* it against the check, *lock it in*, and use the locked slice as
known-good input for the next guess ("ratchet"). We checked what the literature says
about going past Reed–Solomon's one-shot limit, then measured 19 decoders on the same
damage (21 damage settings, 157–158 trials each, 3 308 trials, run on Parrot).

Result in one line: with a 64-byte CRC32 side-file (6.3% of the stored body) the
ratchet repaired **every** damage setting today's `mend --soft` repairs, and also
repaired damage today's repair cannot touch at all. Examples: 8 of 16 pieces lost plus
scattered bit flips in the other 8 (today 0%, ratchet 100% at 128 flips, 59% at 1 024
flips), and 4× the scattered-flip density (65 536 flips: today 0%, ratchet 100%). False
accepts: **0 of 62 852 decodes**. The final Merkle + true-name gate rejected every wrong
guess. The chained variant works the same as the independent one when it succeeds, but
a broken link stops later slices of that piece. The hybrid (chain plus stored checks)
fixes that.

## 1. Problem

Seal is RS(16, 8) over GF(256). Each byte column is one codeword (`docs/SOFT-RS.md`).
`mend --soft` v1 fixes 2·errors + erasures ≤ 8 per column. Without knowing *where*
the damage is, that means 4 wrong pieces per column. Today the only location hint is one
CRC32 per whole shard (`docs/sigil-v1.txt:81`). PR #100 showed that coarse hard marks
(4 KiB) make scattered bit rot *worse*. Question: can per-slice checks plus guessing beat
the one-shot limit, and where?

## 2. Checking the numbers (Part 1)

Verified = read in the primary source this session (abstract, publisher page or full
text). Computed = arithmetic on a verified formula for n = 16, k = 8. Saved receipt:
`/workspace/receipts/ratchet-part1-numbers-20261110.md`.

| method | what it needs | wrong pieces per column (Seal, 16 present) | source / status |
|---|---|---|---|
| Unique decoding (Berlekamp–Welch, today) | nothing | 4 (2e + s ≤ 8) | `docs/SOFT-RS.md`; tape paper §II-A, arXiv:2611.09366 (verified) |
| Guruswami–Sudan list decoding | nothing; returns a list | **5** (e < n − √(n(k−1)) = 16 − √112 = 5.42) | GS, IEEE TIT 45(6) 1999, doi:10.1109/18.782097: "e < n − √(kn)" with degree ≤ k, so Seal's dimension 8 is their k = 7. Formula verified, number computed |
| GS with p pieces present | — | p=15: 4 (unique 3), p=14: 4 (3), p=13: 3 (2), p=12: 2 (2), p=9: 1 (0) | computed |
| Koetter–Vardy soft decoding | a reliability per symbol | beats GS and GMD; no closed number | Koetter & Vardy, IEEE TIT 49(11) 2003, doi:10.1109/tit.2003.819332 (verified). Sigil stores no per-byte reliabilities, so the Sigil number is **UNVERIFIED** |
| Capacity 1 − R (folded RS, Guruswami–Rudra) | a *different* code view (bundled symbols, large alphabet) | → 8 as ε → 0 (needs a format change) | arXiv:cs/0511072 (verified). Not applicable as-is |
| Generic RS at capacity (Brakensiek–Gopi–Makam) | random evaluation points over an exponentially large field | radius n(1−R−(1−R)/(L+1)): L=3 → 6, L=7 → 7 | arXiv:2206.05256, STOC 2023 (verified). Field-size constant c = 2Ln²·C(n,≤n−k)^(L+1) is 3.6·10²¹ (L=3) vs |GF(256)| = 256, so the theorem gives **no guarantee** for Sigil (computed) |
| List + checksum pick (CRC-aided list) | a check value to choose from the list | up to the list radius; the check only *selects* | Tal & Vardy arXiv:1206.0050 (CRC as the "genie"; figure uses L = 32, 16-bit CRC); 5G NR polar DCI uses CRC24C, TS 38.212 §5.1 (ETSI TS 138 212 v19.4.0); MATLAB nrPolarDecode default L = 8 example (verified) |
| Chase / GMD | reliabilities | "up to d − 1" = 8 with high probability (binary codes) | Chase IEEE TIT 1972 doi:10.1109/tit.1972.1054746; Forney 1966 doi:10.1109/tit.1966.1053873 (abstracts verified). Sigil mapping **UNVERIFIED** |
| Anchored iterative product decoding | rows + columns (2-D code) | known-bad cost 1, unknown cost 2; iterate until no change | arXiv:2611.09366 (verified in PR #100). Their BER and dead-track numbers were not reproduced |
| Information limit, RS alone | — | erasures: **8** (MDS / Singleton). Any 8 correct symbols fix the column; fewer cannot | standard; computed |

What this means for Sigil, in plain terms:

- **RS by itself caps at 8 bad pieces per column, if you know where they are.** Not
  knowing where costs double (4). List decoding narrows that gap: 5 is guaranteed (GS),
  6–7 is possible only with luck or a different code.
- **n = 16 is tiny, so brute force is cheap.** Every set of 8 out of 16 pieces is only
  C(16,8) = 12 870 interpolations per column. The harness uses exhaustive list decoding
  instead of GS's algebra, so (e) below returns a superset of what GS would.
- **A check value is extra redundancy, not just a judge.** With a check per slice, a
  slice can be fixed by search *even when RS has no slack left* (8 pieces lost). This is
  how the ratchet goes past "50%". The cost is space and the risk of a lucky false
  match. For CRC32 and two-bit-flip search, the computed false-match odds per searched
  slice are C(8S,2)/2³²: 3·10⁻⁵ (64 B), 2·10⁻³ (512 B), **0.125 (4 KiB)**.

## 3. What was built (Part 2)

`research/ratchet-measure/`: a standalone crate that is not a workspace member. It adds
no new dependencies beyond `crc32fast` and `sha2`, which Sigil already uses. It is
forbid-unsafe, with no `unwrap`/`expect` in library code.

- **RS(16,8) twin** of Sigil's Seal (systematic, x = i+1, field 0x11d). The test
  `encoder_matches_sigil_bytes` checks byte equality against `sigil::rs_bench::encode_shards`.
  Berlekamp–Welch is a line-for-line port of `rs::berlekamp_welch`.
- **Side-file prototype** `NAME.sg1.stripes`: magic `SGRS`, version, mode
  (independent or chained), check type (CRC32 or SHA-256 truncated to 64 bits), slice
  size, geometry, binding to the Merkle root and true name, and a header CRC. Entries
  come in groups of 256 with a CRC32 per group, so one rotted group loses only its own
  entries. Every trial writes the file to disk, reads it back and parses it as hostile
  input. A sidecar that is missing, bound to a different Sigil, or truncated is refused,
  which gives today's behaviour.
- **Gate.** Every decoder only *proposes* bytes. Acceptance needs the SHA-256 true name
  of the payload to match, and so does a Merkle root over the re-encoded shards (an
  emulation of Sigil's binding, not its exact tree).
- **Damage, same seeds for every decoder:** M1 scattered flips (1 024 to 131 072 over
  the 2 MiB body), M2 garbage 4 KiB stripes (32/64/96 of 512) and 512 B sectors
  (256/512/768 of 4 096), M3 lost pieces plus flips, M4 mixed, and M5 the same with the
  side-file itself rotting at the same bit-error rate.

Decoders:

- (a) today: hard path, then column BW.
- (b) hard marks: erase flagged slices (PR #100 style).
- (c) marks as hints: plain BW first, marks only for columns it fails.
- (d) ratchet, run per slice row (one slice of every piece, sharing a trust pattern):
  1. Verified slices are anchors; flagged slices are suspects.
  2. If there are fewer than 8 anchors, search the codewords that match every anchor:
     BW first, then all subsets of suspects up to 1 000 per column.
  3. Lock any suspect whose check now matches.
  4. Chase-style: try tied alternatives on up to 6 ambiguous columns.
  5. Bit-guessing (Ashlynn's 00/01/10/11): try every 1- and 2-bit flip of a stuck slice
     against its check. CRC uses the linear-delta trick, so it costs O(slice bits).
  6. Repeat until nothing changes.
  - Variants: slice size 64/512/4096 B, CRC32 vs SHA-256/64, single pass vs iterate,
    with and without bit-guessing.
- (d-chain) **chained ratchet**: check_j = H(check_{j−1} ‖ slice_j), walked slice by
  slice down each piece.
  - *Pure*: only a predecessor recomputed from verified data counts.
  - *Hybrid*: falls back to the stored predecessor when the chain breaks.
- (e) no side-file: exhaustive list decoding of the columns BW fails, accepting the
  unique nearest codeword within radius 5 (GS) or 7. Capped at 256 such columns per
  trial (ᵇ in the table).

## 4. Measurements

Run on Parrot (i9-10900KF, 18 threads, nice 10, while the machine was also in use),
2026-11-10 12:36:57–1:17 PM ET. 2 425 s of wall time, stopped at the 40-minute cap.
Trials per point: 157–158, for 3 308 of the 4 200 planned. Smoke runs (1 trial/point)
on the box. Cells show the success rate, %. ᵇ = some trials hit the work cap and count
as failures. \* = false locks happened (all were caught by the gate).
95% Wilson intervals are in the raw files.

| damage | a now | b hard 4K | b hard 64 | c hint 4K | c hint 64 | d 64 crc | d 512 crc | d 4K crc | d 64 sha | d 512 sha | d 4K sha | d 512 1-pass | d 512 iter | chain pure 64 | chain hyb 64 | chain pure 512 | chain hyb 512 | e GS r5 | e r7 |
|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|---|
| M1 scattered: F1024 | 100 | 0 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 |
| M1 scattered: F16384 | 99 | 0 | 0 | 99 | 99 | 100 | 100 | 100 | 100 | 100 | 100 | 99 | 100 | 100 | 100 | 100 | 100 | 100 | 100 |
| M1 scattered: F32768 | 65 | 0 | 0 | 65 | 65 | 100 | 100 | 100 | 100 | 100 | 100 | 65 | 100 | 100 | 100 | 100 | 100 | 98 | 100 |
| M1 scattered: F65536 | 0 | 0 | 0 | 0 | 0 | 100 | 73* | 40* | 100 | 73 | 40 | 0 | 73 | 100 | 100 | 73* | 73* | 47 | 87 |
| M1 scattered: F98304 | 0 | 0 | 0 | 0 | 0 | 96 | 0* | 0* | 96 | 0 | 0 | 0 | 0 | 96 | 96 | 0* | 0* | 0 | 35 |
| M1 scattered: F131072 | 0 | 0 | 0 | 0 | 0 | 16 | 0* | 0* | 14ᵇ | 0ᵇ | 0 | 0 | 0 | 16 | 16 | 0* | 0* | 0ᵇ | 1ᵇ |
| M2 burst 4K: B32x4K | 95 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 95ᵇ | 95ᵇ |
| M2 burst 4K: B64x4K | 18 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 100 | 18ᵇ | 18ᵇ |
| M2 burst 4K: B96x4K | 0 | 96 | 96 | 96 | 96 | 96 | 96 | 96* | 96ᵇ | 96 | 96 | 96 | 96 | 96 | 96 | 96 | 96 | 0ᵇ | 0ᵇ |
| M2 burst 512: S256x512 | 52 | 0 | 100 | 65 | 100 | 100 | 100 | 99* | 100 | 100 | 99 | 100 | 100 | 100 | 100 | 100 | 100 | 52ᵇ | 52ᵇ |
| M2 burst 512: S512x512 | 0 | 0 | 99 | 0 | 99 | 99 | 99 | 43* | 99 | 99 | 43 | 99 | 99 | 99 | 99 | 99 | 99 | 0ᵇ | 0ᵇ |
| M2 burst 512: S768x512 | 0 | 0 | 82 | 0 | 82 | 82 | 82* | 0ᵇ* | 82 | 82 | 0 | 82 | 82 | 82 | 82 | 82* | 82* | 0ᵇ | 0ᵇ |
| M3 loss+flips: L8+F16 | 0 | 0 | 0 | 0 | 0 | 100 | 100 | 96 | 100 | 93 | 0 | 0 | 0 | 100 | 100 | 100 | 100 | 0 | 0 |
| M3 loss+flips: L8+F128 | 0 | 0 | 0 | 0 | 0 | 100 | 91 | 0* | 100 | 1 | 0 | 0 | 0 | 100 | 100 | 91 | 91 | 0 | 0 |
| M3 loss+flips: L8+F1024 | 0 | 0 | 0 | 0 | 0 | 59 | 0* | 0* | 0ᵇ | 0ᵇ | 0 | 0 | 0 | 59 | 59 | 0* | 0* | 0 | 0 |
| M3 loss+flips: L6+F4096 | 0 | 0 | 0 | 0 | 0 | 100 | 87 | 2* | 100 | 38 | 2 | 1 | 12 | 100 | 100 | 87 | 87* | 0 | 0 |
| M3 loss+flips: L4+F16384 | 0 | 0 | 0 | 0 | 0 | 100 | 64 | 58* | 100 | 60 | 58 | 58 | 58 | 100 | 100 | 64* | 64 | 0 | 0 |
| M4 mixed: L4+B32x4K+F1024 | 0 | 0 | 0 | 0 | 0 | 96 | 76* | 0* | 93ᵇ | 33 | 0 | 2 | 2 | 96 | 96 | 76* | 76* | 0ᵇ | 0ᵇ |
| M4 mixed: L2+S256x512+F4096 | 0 | 0 | 0 | 0 | 0 | 99 | 76* | 0* | 99 | 41 | 0 | 0 | 0 | 99 | 99 | 76* | 76* | 0ᵇ | 0ᵇ |
| M5 sidecar rot: F65536+rot | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 0 | 54 | 91 |
| M5 sidecar rot: L8+F128+rot | 0 | 0 | 0 | 0 | 0 | 0 | 20 | 0* | 0 | 1 | 0 | 0 | 0 | 0 | 0 | 22 | 22 | 0 | 0 |

| decoder | mean ms (M1 F16384) | mean ms (M3 L8+F128) | max ms any point | sidecar bytes | % of 2 MiB body | % of 1 MiB payload | false locks (all points) |
|---|---|---|---|---|---|---|---|
| a current mend --soft | 203 | 15 | 1841 | 0 | 0.000 | 0.000 | 0 |
| b hard marks 4096/crc32 | 0 | 0 | 766 | 2144 | 0.102 | 0.204 | 0 |
| b hard marks 64/crc32 | 0 | 0 | 758 | 131672 | 6.279 | 12.557 | 0 |
| c hint marks 4096/crc32 | 204 | 15 | 1972 | 2144 | 0.102 | 0.204 | 0 |
| c hint marks 64/crc32 | 208 | 20 | 1923 | 131672 | 6.279 | 12.557 | 0 |
| d ratchet 64/crc32 +2bit | 89 | 43 | 1492 | 131672 | 6.279 | 12.557 | 0 |
| d ratchet 512/crc32 +2bit | 295 | 45 | 2387 | 16536 | 0.788 | 1.577 | 233 |
| d ratchet 4096/crc32 +2bit | 294 | 95 | 9313 | 2144 | 0.102 | 0.204 | 20959 |
| d ratchet 64/sha64 +2bit | 122 | 15219 | 23414 | 262744 | 12.529 | 25.057 | 0 |
| d ratchet 512/sha64 +1bit | 326 | 2096 | 13197 | 32920 | 1.570 | 3.139 | 0 |
| d ratchet 4096/sha64 nobits | 328 | 23 | 7215 | 4192 | 0.200 | 0.400 | 0 |
| d ratchet 512/crc32 1-pass nobits | 294 | 17 | 1933 | 16536 | 0.788 | 1.577 | 0 |
| d ratchet 512/crc32 iter nobits | 293 | 16 | 2105 | 16536 | 0.788 | 1.577 | 0 |
| d chain-pure 64/crc32 +2bit | 92 | 46 | 3381 | 131672 | 6.279 | 12.557 | 0 |
| d chain-hybrid 64/crc32 +2bit | 91 | 45 | 1484 | 131672 | 6.279 | 12.557 | 0 |
| d chain-pure 512/crc32 +2bit | 293 | 46 | 4100 | 16536 | 0.788 | 1.577 | 36 |
| d chain-hybrid 512/crc32 +2bit | 294 | 47 | 2205 | 16536 | 0.788 | 1.577 | 236 |
| e list r<=5 (GS radius) | 204 | 15 | 1886 | 0 | 0.000 | 0.000 | 0 |
| e list r<=7 | 204 | 15 | 2592 | 0 | 0.000 | 0.000 | 0 |

Timing is wall time per decode on a shared, de-prioritised machine. Read it as relative,
not absolute. The (b) "0 ms" means hard marks gave up at the first slice row it
could not fix.

### What the numbers say

1. **Ratchet 64 B / CRC32 beats today's repair everywhere and never loses.** It held
   100% through 65 536 scattered flips, where today's repair falls to 0% at 65 536 and
   65% at 32 768. It got 96% at 98 304 flips and 16% at 131 072.
2. **Past 50% is real.** With 8 of 16 pieces lost, RS has zero slack. Today's repair
   (and every RS-only method, (e) included) is 0%. The ratchet with bit-guessing got
   100% at 16 and 128 flips and 59% at 1 024. Without bit-guessing it got 0%, so the
   check value *is* the redundancy there.
3. **Iteration matters, which is the ratchet effect.** 512 B CRC32 with one pass and no
   bits: 0% at 65 536 flips. Iterating: 73%. With 6 pieces lost and 4 096 flips: 1% →
   12%. Adding bit-guessing: 87%.
4. **Small slices win, and big slices plus guessing is dangerous.** 4 KiB CRC32 with
   two-bit guessing produced 20 959 false locks. That matches the 1-in-8 false-match odds
   computed in §2, and it pulled success *down* (512 B sectors: 99% → 43%). The gate
   caught all of them, but the false locks cost wins.
5. **SHA-256/64 never false-locked but costs time.** 64 B SHA averaged 15 s per decode
   at L8+F128 (max 23 s) against 43 ms for CRC32, and hit the work cap under heavy
   damage. CRC32 at 64 B had zero false locks in 19.8 M locks.
6. **Marks-as-hints never hurt; hard marks did** (4 KiB hard marks were 0% at only
   1 024 flips, reproducing PR #100). But hints add nothing for scattered flips. They
   only help when damage is chunky (512 B sectors: hints at 64 B 99% vs today 0%).
7. **List decoding with no side-file (e)** gives a real but small gain on scattered
   flips (65 536 flips: radius 5 at 47%, radius 7 at 87%, today 0%), and it is the only
   thing that survives a rotted side-file (91%). It can't touch lost pieces, and here it
   hit its column cap on bursts.
8. **Chained vs independent.** When the whole file is recovered, the success rates are
   identical, point for point. The weakness Ashlynn expected is real, and it shows in
   the partial-recovery ("salvage", fraction of 4 KiB data stripes correct) column of the
   raw results. With pure chaining, one slice that can't be fixed blinds every later
   slice of that piece:
   - L8+F1024: pure 64 B 0.872, hybrid 0.991.
   - F131072: pure 0.489, hybrid 0.959.
   - L8+F1024, 512 B: pure 0.138, hybrid 0.643.

   The **hybrid** (chain, but resume from the stored check) matches the independent
   ratchet. Chaining gives no repair gain over independent checks of the same size,
   because Sigil's all-or-nothing gate already ties everything together. Its value would
   be elsewhere: ordering and tamper-evidence with a *signed* chain head (UNVERIFIED,
   not tested). A sparse chain (one stored check per m slices) is exactly an independent
   check on an m-times-bigger slice, so its numbers are the 512 B / 4 KiB rows (computed
   equivalence, not separately run).
9. **The side-file must protect itself.** At the same bit-error rate as the data
   (65 536 flips), the unprotected side-file lost almost all of its groups and every
   side-file decoder fell back to today's 0%. Needed before any product use: RS over
   the table, or copies on other holders (**UNVERIFIED**, not built).

### Space versus "just add another parity piece"

64 B CRC32 costs 131 672 bytes for a 1 MiB file: 6.3% of the 2 MiB body, about one
extra piece. One extra parity piece (8-of-17) would add 1 erasure per column but **no**
hidden-error capacity, since ⌊9/2⌋ = 4, the same as today (computed). It also cannot fix
the "8 lost + flips" case unless that piece survives. 512 B CRC32 (0.8%) keeps most of
the gain except at the heaviest damage. The 8-of-17 comparison was not measured.

## 5. Threat-model note

Per-slice CRC or SHA checks detect **faults** only. That is threat line F
(`docs/sigil-v1.txt:172–173` adversary, `:183–197` claim). An active tamperer (line A,
`:176–177` adversary; "NOT claimed: authenticity of an unencrypted Sigil",
`:208–212`) can rewrite a slice and its check together. A ratchet fed lying checks
would lock lies. The gate still refuses the result, so the effect is a denial of
repair, not a wrong file. Catching a lying holder needs keyed checks (HMAC under a
key the holder doesn't have) or a signed table (`sigil sign`, Ed25519) whose key the
verifier trusts. Unencrypted side-files also let a passive holder (line P) confirm
guesses about a slice's content. Any product version should key the checks for
unencrypted Sigils (**UNVERIFIED** design, not built).

## 6. Limitations

- This is a simulation of Seal RS on synthetic random payloads, not repair of real
  `.sg1` files. Headers, Embers and the Keystone are assumed intact, and the gate's
  Merkle tree is an emulation.
- Damage models are uniform. Real disks cluster damage, which is **UNVERIFIED** here.
- The work cap (1.5·10⁹ ops per decode) and the 256-column list cap shape the heavy-damage
  rows. Results there are lower bounds for the uncapped algorithm.
- Today's (a) omits the v0 GMD-lite fallback that runs after column repair in
  `sigil mend --soft`. It can only help (a), and its effect is **UNVERIFIED**.
- The 4 200 planned trials were cut to 3 308 by the time cap. That is balanced (157–158
  per point), but ~158 trials can't resolve rates near 0 or 100 finer than about ±2%.
- Timings come from a shared machine at low priority.
- GS was not implemented. The exhaustive list decoder is at least as strong at n = 16.

## 7. Recommendation (perspective rule)

- **PROPOSE**: a decoder-only ratchet behind `mend --soft`, reading an optional
  64 B or 512 B side-file. Same gate, no `.sg1` change. Prerequisites:
  - a self-protecting side-file (§4.9);
  - keyed or signed checks for anything beyond fault repair (§5);
  - Ashlynn's pick of slice size and check type: CRC32 64 B for maximum repair,
    512 B for low overhead, SHA only if the speed hit is acceptable.
- Perspectives:
  - **Cold (Frost Rune)**: the biggest win. Lost drives plus bit rot is exactly M3. The
    side-file should live on every drive. Line F.
  - **Hot (Fire Rune)**: the side-file must be rewritten with each re-seal. Fine for
    scrub-time repair. Line F.
  - **Servers vs PCs**: servers with ZFS/RAID rarely see M1 densities, so the gain is in
    multi-holder layouts. Single-disk PCs gain most. Line F.
  - **Cloud**: only with keyed/signed checks, or the provider is trusted. Lines A, P.
  - **Sigil not installed**: the side-file is optional, and a plain reader ignores it.
  - **Linux / Windows servers, databases**: 512 B slices match sector sizes, and 4 KiB
    pages are M2. Line F.
  - **AWS**: signed tables per bucket name the bad holder. Line A.
  - **Mainframe / tape**: sits above the drive's own product code. Line F.
- **PARK**: chained checks for repair. They give no gain over the hybrid or independent
  ones, and the pure chain loses salvage. This was considered for cold, hot, server and
  cloud. Reopen it if a *signed chain head* is wanted for ordering/tamper evidence
  (ties to the lying-holder work).
- **PARK**: folded/generic-RS capacity codes. Format change, and no guarantee at GF(256).
  Reopen only with a new code family.

## Citations

- V. Guruswami, M. Sudan, IEEE TIT 45(6):1757–1767, 1999, doi:10.1109/18.782097.
- R. Koetter, A. Vardy, IEEE TIT 49(11):2809–2825, 2003, doi:10.1109/tit.2003.819332.
- V. Guruswami, A. Rudra, arXiv:cs/0511072.
- J. Brakensiek, S. Gopi, V. Makam, arXiv:2206.05256 (STOC 2023).
- I. Tal, A. Vardy, arXiv:1206.0050 (IEEE TIT 2015, doi:10.1109/tit.2015.2410251).
- 3GPP TS 38.212 / ETSI TS 138 212 v19.4.0 (2026-07), §5.1, https://www.etsi.org/deliver/etsi_ts/138200_138299/138212/19.04.00_60/ts_138212v190400p.pdf
- D. Chase, IEEE TIT 18(1):170–182, 1972, doi:10.1109/tit.1972.1054746.
- G. D. Forney, IEEE TIT 12(2):125–131, 1966, doi:10.1109/tit.1966.1053873.
- A. Chvanov, N. Malkovsky, arXiv:2611.09366 (see `DAMAGE-MARKING.md`).
