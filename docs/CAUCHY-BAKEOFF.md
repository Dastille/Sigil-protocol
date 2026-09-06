# Cauchy MDS bake-off (track #3)

Vandermonde stays **default**. Cauchy is opt-in (`--mds cauchy` / `SIGIL_MDS=cauchy` / `MdsBackend`) after a measured win.

## Spec

- Trait `MdsBackend`: `VandermondeRs` default, `CauchyRs` opt-in
- Systematic Seal (8,16) / Reflection (12,16); stars 1 / 4 / 8 MiB
- Keep Cauchy only if ≥15–20% faster on encode **or** multi-erasure decode
- True-name (plaintext SHA-256) bitexact after repair for both backends (parity shards differ)

Sources: Plank CS-05-569; Ceph jerasure benches.

## Machine result (this PR)

Release, scalar GF(256) tables, no SIMD. `sigil bench-mds --iters 1` on the bake-off host:

| backend     | k/n  | size | encode MiB/s | decode MiB/s | erasures |
|-------------|------|------|-------------:|-------------:|---------:|
| vandermonde | 8/16 | 1–8 MiB | ~8–9 | ~55–57 | 8 |
| cauchy      | 8/16 | 1–8 MiB | ~53–57 | ~90–92 | 8 |
| vandermonde | 12/16 | 1–8 MiB | ~5 | ~28–30 | 4 |
| cauchy      | 12/16 | 1–8 MiB | ~117–120 | ~81–85 | 4 |

Best Cauchy vs Vandermonde: **encode ≫ +15%** (order-of-magnitude; Vandermonde encode still solves per column), multi-erasure decode **~+60–190%**.

**Recommendation: KEEP** Cauchy as opt-in. Vandermonde remains the production default (wire-compatible with existing `.sg1`). No free header flag for an MDS marker yet — Cauchy marks are experimental: Inscribe and De-scribe must both pass `--mds cauchy` (single-star `.sg1` only).

## How to remasure

```bash
cargo build --release -p sigil
./target/release/sigil bench-mds --iters 3
# or
cargo test -p sigil --release ignored_full_bakeoff -- --ignored --nocapture
```

## API / CLI

- `sigil bench-mds` — always available
- `sigil seal … --mds cauchy` / `sigil unseal … --mds cauchy` (or `SIGIL_MDS=cauchy`)
- Feature `mds-cauchy` in `Cargo.toml` documents the opt-in (disabled by default as a *default backend*; code path is present for benches + CLI)
- Library: `seal_kn_mds` / `unseal_ex_mds` / `CauchyRs` / `VandermondeRs`

## Non-goals (this PR)

- Making Cauchy the seal default
- Header layout change / MDS flag bit
- Work-pack / folder / CDC Cauchy path
- SIMD bitmatrix schedule (future speed-up on top of this table impl)
