# Soft-decision RS for Sigil (Mathamatico #2)

Parked until FastCDC ships.

## Problem
CRC-kill whole shards → pure erasures. Bit-rot in a live shard fails late (Merkle/true-name).

## v0 spike
- Keep GF(256) Vandermonde RS; Seal (8,16) / Reflection (12,16)
- Stripe CRC (e.g. 4 KiB): fail → erase symbols; pass → hard symbols
- Erasure decode first; if fail, GMD flipping ≤ (n-k) lowest-reliability stripes to erasure
- Accept only if true-name matches
- Gate soft path to: shards present but hard mend/Merkle fail
- Non-goals: Keystone/Ember byte change; replace RaptorQ; Ward substitute

## Damage-adaptive preview
- Missing clean: hard RS erasure
- Present dirty: soft RS/GMD
- Rateless rain: RaptorQ

## Citations
- Koetter & Vardy, IEEE TIT 2003
- Forney GMD
- Xia et al., HACFS, USENIX FAST 2015
