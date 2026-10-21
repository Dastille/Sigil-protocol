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

## Damage-adaptive preview
- Missing clean: hard RS erasure
- Present dirty: soft RS/GMD (`--soft`)
- Rateless rain: RaptorQ

## Citations
- Koetter & Vardy, IEEE TIT 2003
- Forney GMD
- Xia et al., HACFS, USENIX FAST 2015
