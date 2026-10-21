# Fountain & regeneration — current crate state

This note tracks what the tree **already does**. It does not claim this branch invented fountain codes.

## What is already here

| Mechanism | Command / API | Notes |
|-----------|---------------|--------|
| Classic RS Seal/Reflection | `seal` / `unseal` | Fixed `k` of `n`; systematic v2 |
| Scatter / Gather | `sigil scatter` / `sigil gather` | `.sgp` pieces; any `k` rebuilds `.sg1` |
| Deluge (indexed RS rain) | `sigil deluge` / `rain` | Extra indices up to 254; `--from` lanes |
| RaptorQ fountain | `sigil deluge --fountain` | `.rq` packets; `gather_fountain` |
| In-place mend | `sigil mend` / `repair` | Torn single `.sg1` → healthy rewrite |

Ward passphrase is **not** required for scatter, deluge, fountain gather, or mend. Work stays on the folded (possibly ciphertext) payload.

## Mend (new on this branch)

```text
sigil mend torn.sg1 -o healed.sg1
```

1. `locate_header` on the file (Keystone / Ember / hunt).
2. `gather_live_shards` for live classic slots.
3. **Glyph**: error if any shard missing.
4. Need ≥`k` live → `decode_indexed` → `encode_shard_index` for `0..n-1` → assemble mark the same way seal/gather finish (keystone, ember, vow, CRCs).

`pieces::mend_bytes` is the shared rebuild primitive; `gather` for Seal/Reflection also finishes through the same assemble path.

## Deluge vs RaptorQ

- **Deluge** extends the **same** Vandermonde RS: evaluate at new points. Hard ceiling index 254.
- **RaptorQ** (`raptorq` crate, pinned `=2.0.0` for rustc 1.85) encodes the whole `.sg1` as rateless packets — no RS index ceiling.

Classic `.sg1` layout stays interoperable; rain lives in piece folders or `.rq` sidecars.

## Not claimed here

- Inventing fountain codes.
- Changing `docs/sigil-v1.txt`.
- Replacing Seal’s on-mark 50% budget (extras are outside the classic `n` slots).

## Next leaps after mend

1. Streaming / chunked Inscribe (whole-file RAM).
2. zstd + codec flag (v2).
3. Constellation / Geas productization (cold USB, atlas kits).
4. Optional cross-star heal and Argon2id Ward.

## Success checks (regression)

- [x] Seal → smash half shards → `mend` → verify merkle closed → unseal equals original.
- [x] Glyph → missing shard → `mend` errors.
- [x] Seal → deluge rain-only ≥`k` → gather → unseal.
- [x] Seal → RaptorQ fountain → drop some `.rq` → gather_fountain → unseal.
- [x] Scatter → drop within budget → gather → unseal.
