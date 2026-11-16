# Soft-decision RS for Sigil (Mathamatico #2)

## Problem
CRC-kill whole shards → pure erasures. Bit-rot in a live shard fails late (Merkle/true-name),
or a chewed CRC trailer discards an otherwise intact body.

## v0 (this crate)
- Keep GF(256) Vandermonde RS; Seal (8,16) / Reflection (12,16)
- Graded gather: CRC pass → Hard; present but CRC fail → Soft; else Missing
- Stripe size 4096 B within shard payload (`rs::SOFT_STRIPE`)
- Soft symbols fill gaps when Hard < k; GMD-lite flips ≤ (n−k) lowest-reliability
  soft shards (then soft stripes) to erasure and retries
- Accept only if Merkle of re-encoded shards matches the header; when not Warded,
  plaintext SHA-256 (true-name) must match too
- Opt-in: `sigil mend --soft torn.sg1 -o healed.sg1` (hard path first, soft fallback)
- Glyph unchanged (all-or-nothing; `--soft` does not relax it)
- Non-goals: Keystone/Ember byte change; replace RaptorQ; Ward substitute

## v1: column repair (October 2026, decoder only)
- `sigil mend --soft` now first decodes every **byte column** on its own
  (`rs::decode_column_errors`): byte j of each shard is one Reed–Solomon codeword
  (evaluations at x = index + 1 of a degree < k polynomial), so a flipped bit is one
  wrong symbol in one column, not a lost shard.
- Clean columns are found with one matrix pass (predict the other shards from the first k
  and compare). Each dirty column is decoded with Berlekamp–Welch; it is corrected only if
  at most (present − k) / 2 symbols disagree. Missing shards count as erasures
  (2·errors + erasures ≤ n − k per column). Any column past that budget fails the call.
- Accepted only through the same gate: Merkle binding of the re-encoded shards, plus the
  true name when not encrypted. Then the old GMD-lite path runs as before.
- No byte layout change. Old Sigils benefit as-is. Plain `unseal` and plain `mend` are unchanged.
- Measured numbers and limits: `docs/research/DEEP-SPACE.md`.
- Also fixed while measuring: when every front header copy is gone and bit rot leaves no
  CRC-good shard, the body offset is chosen by where surviving Embers sit (tie-break after
  CRC count), and a header rebuilt from an Ember no longer keeps that Ember's slot number
  in the entropy word.

## v2: easy-first column repair (November 2026, decoder only)
`sigil mend --soft` used to try candidate after candidate (every soft-shard pair × every
4 KiB stripe) and re-encode, re-hash and Merkle-check the **whole file for each one**. On a
10 MB star with heavy damage that ran for 16+ minutes (box) and 40+ minutes (Parrot, shared
with other trials), then failed anyway. It now works column by column, easiest first, and
locks in each settled column (`crate/sigil/src/soft_ratchet.rs`):

1. **Clean columns**: one matrix pass; a column where every present byte agrees is locked.
2. **Wiped / garbage shards**: a sample of dirty columns shows which soft shards are wrong
   almost everywhere; those are treated as missing (erasures), so they do not use up every
   column's error budget.
3. **Berlekamp–Welch** (errors-and-erasures) on each dirty column; CRC-good shards are
   trusted and never changed.
4. **Erasure guesses** for still-stuck columns, fewest erasures first and most suspicious
   shards first. A guess locks only when **two** spare bytes confirm it and no other guess
   of the same size gives a different answer.
5. **Per-shard CRC ratchet**: a soft shard whose stored CRC-32 now matches is right
   everywhere, so it becomes trusted; repeat 4 with fewer unknowns.
6. **CRC match for the last few columns** (up to 64): CRC-32 is linear, so each candidate
   fix's effect on every shard's CRC is one table lookup; a meet-in-the-middle search keyed
   on three reliable shards picks the combination that makes the stored CRCs match. It must
   win clearly (2+ more matching shards than any other) and explain every shard except wiped
   ones and at most one rotten trailer.
7. Anything left gets a best guess (most reliable `k` bytes).

Then the result is checked **once** (re-encode all shards, Merkle root, and the true name
when not encrypted). Only if that fails are the old shard-order GMD-lite candidates tried
(at most 2(n−k)+1 more checks; the old stripe×pair search is gone). Steps 3–4 run on up to
8 CPU threads (std only; no GPU). Same acceptance gate as before: a wrong guess can only make
the repair fail, never return wrong bytes. No byte layout change.

Measured (box, release build; harness `mend_soft_timing` in `crate/sigil/src/mend_soft_tests.rs`,
numbers in the PR): Reflection 12/16, 10 MB, 2 wiped shards + BER 1e-3 (the R1 hang class):
old 963 s then refused, new under 1 s (0.6–0.8 s) then refused (10 full checks). Where the old search
finished with a result, the new path returns the same bytes (test
`mend_soft_matches_old_path_on_damage_corpus`).

Still open (R1 slices, in this order; none of this is in the tool yet):

1. Easy repair by default (Tuesday 17 November 2026 weekday slice). Plain `sigil mend` will
   try the fast hard repair first, then fall back to soft repair on its own. Soft repair will
   still only keep a result that passes the Merkle and true-name check. The `--soft` flag will
   keep working. If `-o` is omitted, the tool will pick a path next to the input and will never
   overwrite the input. Messages will be plain English and will suggest full, copyable commands.
   The doctor hint will include the full command too.
2. Wait screen (Wednesday–Thursday 18–19 November 2026; one roadmap item, estimated at two
   weekday slices — that size is a guess). After a short scan, the tool will estimate how long
   the repair will take. Short repairs will just run. Long repairs will ask first, then show
   progress and a way to Stop. The time cut-offs come from the 11 November 2026 wait-UX notes.
3. Then: racing regions across threads, with a way to cancel.
4. Then: a GPU option, with a CPU path that must still work.
5. Then: joint solving for more than 64 stuck columns. Heavy scattered damage past the
   per-column Reed–Solomon limit will still need the stripe sidecar (PR #101).

## Damage-adaptive preview
- Missing clean: hard RS erasure
- Present dirty: soft RS/GMD (`--soft`)
- Rateless rain: RaptorQ

## Citations
- Koetter & Vardy, IEEE TIT 2003
- Forney GMD
- Xia et al., HACFS, USENIX FAST 2015
