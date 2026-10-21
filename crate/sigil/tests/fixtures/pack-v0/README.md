# Large-file pack fixtures written before pack-head repair

Written by the `sigil` binary built from `main` at `d2f5307` (2026-10-17), before
any pack-head repair code existed. They pin the on-disk SGWK layout: every
reader change must keep these opening byte-exact, and `mend` must leave an
undamaged one byte-identical.

| File | Command |
|---|---|
| `pack-v2-reflection.sg1` | `sigil seal --chunk 65536 -o pack-v2-reflection.sg1 plain.bin` |
| `pack-v2-pass.sg1` | `sigil seal --chunk 65536 --pass "fixture pass" -o pack-v2-pass.sg1 plain.bin` |

`plain.bin` (200,000 bytes, SHA-256
`cfbeeed4da2dee64b1042ee3af314220eedab7c2bae804647b9d961e6fb388bf`) is not
stored; the tests regenerate it with xorshift64 (seed `0x2545f4914f6cdd1d`,
`x ^= x << 13; x ^= x >> 7; x ^= x << 17`, low byte of each step). Each pack is
4 chunk stars (3 x 64 KiB + 3,392 bytes), SGWK head version 2, name `plain.bin`.
