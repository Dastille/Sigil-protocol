# Fast Reed–Solomon (same bytes, ~100–5000× faster)

**What changed:** only *how* Sigil computes its Reed–Solomon parts. The parts
themselves, and so every `.sg1` on disk, are **byte-for-byte the same** as before.
Old files open with the new code and new files open with the old code.

## Why it was slow
The old code (`rs.rs`, `gf.rs`) treated every byte position of a part as a new
puzzle. For each byte column it set up and solved a k×k Vandermonde system from
scratch (`gf::solve_vandermonde`), about 72% of all time. At k = 189 that is
hours per GB.

## What it does now
Every step is a fixed linear map over GF(256) that depends only on
(k, n, which parts are present). So:

1. **Build the matrix once** per shape and erasure pattern:
   - encode (v2, systematic): `E(parity points) · V(1..k)⁻¹`
   - encode (v1): `E(all points)`
   - decode: `V(live points)⁻¹`, times `E(1..k)` for v2
   - the matrix inverse is unique, so a one-shot Gauss–Jordan gives exactly the
     numbers the old per-column solve produced.
2. **Run whole part slices** through it (`gf::matrix_apply`): out_row ^= c · in_slice,
   cache-blocked in 16 KiB strips.
3. **Multiply-accumulate kernel** (`gf::mul_acc`), picked at runtime:
   AVX2 → SSSE3 (x86_64, `std::arch`, split-nibble `pshufb`), NEON (aarch64,
   `vqtbl1q_u8`), else a scalar 64 KiB product table. No new dependencies.
4. **Soft mend** (`decode_graded_with_mask`): the chosen symbols are the same for a
   whole 4 KiB stripe, so each stripe is one matrix pass (matrices cached per
   pattern).
5. **Cauchy** (`--mds cauchy`) uses the same slice kernel for encode and decode.

## Safety net
- `src/rs_ref.rs` is the **frozen old code**, kept only as a test oracle and
  benchmark baseline.
- Property tests (`rs::tests::prop_*`) compare new vs old on hundreds of random
  k / n / sizes / erasure orders, duplicates, short, long and bit-flipped parts,
  and soft-mend stripe masks. `gf` tests check every SIMD kernel against the
  scalar table for all 256 coefficients; Cauchy is checked against its per-byte
  formula.
- `lib::tests::rs_fast_path_fails_closed`: wrong passphrase, truncation and
  damage beyond the parity budget are refused (never wrong bytes); damage within
  budget repairs exactly.

## Numbers (one core, x86_64 AVX2, MB/s encode / decode, n−k data parts erased)
`cargo run --release --example rsbench -- <MB> <k> <n> [ref|fast|both]`

| size, k/n | before | after |
|---|---|---|
| 1 MB 12/16 | 5.4 / 29 | 846 / 883 |
| 1 MB 8/16 | 8.5 / 41 | 533 / 889 |
| 64 MB 15/20 | 3.9 / 21 | 775 / 1002 |
| 64 MB 16/32 | 3.4 / 14 | 431 / 695 |
| 1 GB 15/20 | 4.0 / 22 | 606 / 909 |
| 1 GB 189/252 | 0.05 / 0.74 (2 MB sample; ~6 h/GB) | 265 / 256 |
| 1 GB 127/254 | ~0.1 / 1.5 (eval sample) | 152 / 171 |

Large k is still O(k·(n−k)) per byte; an FFT-style code would be the next step
there, but that would change the bytes and is out of scope.
