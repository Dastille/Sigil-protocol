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
- No byte layout change. Old marks benefit as-is. Plain `unseal` and plain `mend` are unchanged.
- Measured numbers and limits: `docs/research/DEEP-SPACE.md`.
- Also fixed while measuring: when every front header copy is gone and bit rot leaves no
  CRC-good shard, the body offset is chosen by where surviving Embers sit (tie-break after
  CRC count), and a header rebuilt from an Ember no longer keeps that Ember's slot number
  in the entropy word.

## Damage-adaptive preview
- Missing clean: hard RS erasure
- Present dirty: soft RS/GMD (`--soft`)
- Rateless rain: RaptorQ

## Citations
- Koetter & Vardy, IEEE TIT 2003
- Forney GMD
- Xia et al., HACFS, USENIX FAST 2015
