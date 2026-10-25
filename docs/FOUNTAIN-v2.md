# Fountain & regeneration — current crate state

This note tracks what the tree **already does**. It does not claim this branch invented fountain codes.

## What is already here

| Mechanism | Command / API | Notes |
|-----------|---------------|--------|
| Classic RS Seal/Reflection | `seal` / `unseal` | Fixed `k` of `n`; systematic v2 |
| Scatter / Gather | `sigil scatter` / `sigil gather` | `.sgp` pieces; any `k` rebuilds `.sg1` |
| Deluge (indexed RS rain) | `sigil deluge` / `rain` | Extra indices up to 254; `--from` lanes |
| RaptorQ fountain | `sigil deluge --fountain` | `.rq` packets, random 24-bit ESIs (`--sequential` = old order); `gather_fountain` |
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

## RaptorQ packet numbering and checks

RFC 6330 section 3.2 (FEC Payload ID) gives each encoding symbol an 8-bit source block number
and a **24-bit Encoding Symbol ID (ESI)**: 0 to 2^24 - 1 = 16 777 215 (`fountain::MAX_ESI`).
ESIs 0..K-1 of a block are its source symbols, K and up are repair symbols (section 4.4.2).

- **Default:** `deluge --fountain` gives each packet a random ESI from the whole 24-bit space
  (K + `--extra` distinct ones per block, files `rain-<block>-<esi>.rq`). People raining the same
  file without coordinating almost never send the same packet, so partial shares pooled in one
  folder add up.
- **`--extra N` is a target, not an increment** (both modes): each source block ends up with
  K + N valid packets of this file. Running deluge again into the same folder counts the packets
  already there (v1 or v2, any file name) that are byte-for-byte this file's packet for their ESI,
  and writes only the missing number with fresh random ESIs that collide with none already there;
  at or above the target it writes nothing and says so. Damaged packets, packets that claim this
  file but do not match it (forged), and other files' packets are reported (`not counted ...` on
  stderr), never counted, and never overwritten. A smaller `--extra` never deletes packets.
- **`--loss P` instead of `--extra`:** P is the expected fraction of packets lost (`0.1` or `10%`;
  a bare `10` is refused with a hint). Sigil picks the smallest extra count per block so the chance
  that the far side cannot rebuild without a resend is at most 1e-4, from the exact binomial tail and
  the RFC 6330 section 5.8 decoder bound (1e-2 / 1e-4 / 1e-6 at K', K'+1, K'+2), with a union bound
  across source blocks. Example: one 82-symbol block at 10% loss gets 23 extra (105 packets).
  Assumes independent losses; bursts, outages, or more loss than stated are not covered, and then
  gather refuses rather than writing wrong bytes. With `--sequential` the ESIs are not random, so
  the bound is only measured, not claimed. Model and tests: `crate/sigil/src/fountain_loss.rs`.
- **`--sequential`:** the old order, ESIs 0..K+extra-1 (`rain-00000.rq` ...). Two senders using it
  send identical packets.
- **Packet file v2:** `"SGFT" | 2 | OTI (12) | object SHA-256 (32) | payload id (4) | symbol |
  SHA-256 of all preceding bytes (32)`. Old v1 packets (`"SGFT" | 1 | OTI | payload id | symbol`)
  still gather, alone or mixed with v2 packets of the same file.
- **Gather** skips (and names on stderr) packet files that are damaged, cut off, from another file,
  or have impossible headers; ignores duplicate ESIs; checks the rebuilt bytes against the object
  SHA-256 (a forged packet with a recomputed checksum fails closed, nothing is written); and when
  short prints `have 4 of 10 needed, need 6 more`. RaptorQ sometimes needs 1-2 symbols beyond K;
  gather says so when that is the case.
- The per-packet SHA-256 is not keyed: it catches damage, not an attacker. The object SHA-256
  inside each packet is what makes a forgery fail, and it also reveals the fountain'd file's
  SHA-256 to anyone holding a packet (the file is a `.sg1`; seal it encrypted if that matters).

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
