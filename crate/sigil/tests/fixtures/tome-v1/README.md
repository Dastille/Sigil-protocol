# Tome fixtures in the older layouts (before the protected plain Tome, v3)

Written by the `sigil` binary built from `main` at `80347aa` (2026-11-26), the last
build before Tome v3. They pin the plain v1 layout (folder list outside any repair
data) and the Warded v2 layout: every reader must keep opening them exactly, and
`mend` must leave an undamaged one byte-identical.

| File | Command |
|---|---|
| `tome-v1-glyph.sg1` | `sigil seal --chunk 65536 --mode glyph -o tome-v1-glyph.sg1 src` |
| `tome-v1-reflection.sg1` | `sigil seal --chunk 65536 --mode reflection -o tome-v1-reflection.sg1 src` |
| `tome-v1-seal.sg1` | `sigil seal --chunk 65536 --mode seal -o tome-v1-seal.sg1 src` |
| `tome-v2-pass.sg1` | `sigil seal --chunk 65536 --pass "fixture pass" -o tome-v2-pass.sg1 src` |

`src` is not stored; the tests rebuild it:

- `a.txt`: the 6 bytes `alpha\n`;
- `sub/large.bin`: 100,000 bytes of xorshift64 (seed `0x2545f4914f6cdd1d`,
  `x ^= x << 13; x ^= x >> 7; x ^= x << 17`, low byte of each step), SHA-256
  `f7e7127e4a1bcf28c1f82e5901b689a9199f030efa8f0399c9cf3b1439245aab`. With
  `--chunk 65536` it is a large-file member (two chunk stars);
- `sub/b.bin`: the first 3,000 bytes of the same stream, SHA-256
  `deec71ae69dbf89ef55db67db46b2693b934dfc15c99dd3660ba7fe2141cdaf4`.

SHA-256 of the fixtures:

```
19716be18576b31a8b6435ec2cb7c42ebe459d0c046f49f346bd47ad65b85ef1  tome-v1-glyph.sg1
1ccf9c1d65e9d57b471f6417f3092544a520ca564678c679f3f530240d33197f  tome-v1-reflection.sg1
26844217e92b8d9ebccaedfb11c7e37c5fb1cdb820bde86868d5715ce03dba75  tome-v1-seal.sg1
494dd2e4fba0dcb929c9bd3998e071a7b80513a0e82f52f23051b2921fda7b9d  tome-v2-pass.sg1
```
