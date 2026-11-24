# Key-wrap spare (SGTO v3 + `SGTS`)

Status: shipped 17 November 2026. Code: `crate/sigil/src/header.rs` (`sgto_slice`,
`write_sgto_spare`, `merge_sgto_copies`), `crate/sigil/src/keys.rs` (`SGTO_VERSION_SPARED`,
`mark_spared`), writers in `lib.rs` (`assemble`) and `pieces.rs` (`assemble_mark`).
Tests: `crate/sigil/src/keywrap_spare_tests.rs`, `src/lib/sigil/sgto.test.ts`.
Measurement: `crate/sigil/src/keywrap_measure.rs` (ignored test, see below).

## Problem

Every encrypted Sigil keeps its content key wrapped in one `SGTO` block (about 100 bytes) right
after the Keystone. Before this change that block existed **once** and sat outside the shards, so
Reflection/Seal repair never covered it. One flipped bit there failed its CRC32; `unseal` then
said "no key wrap (SGTO) left; past repair" and `mend` refused (since PR #107), even with all 16
shards intact. Shown by `keywrap_measure::keywrap_single_hit_repro` on `main` @ `13eee34`:
one flipped bit, or 16 zeroed bytes, in the wrap → intact data shards 16/16, unseal and
mend both refuse (passphrase and encrypt-to).

## Layout

```
front   SGTO | version=3 | count | flags | 0 | records | CRC32      (after the Keystone, as before)
...     Vow, n × (Ember + shard + CRC32)                              (unchanged)
spare   SGTS | 1 | 0 0 0 | the exact front SGTO block                 (new; right after the shards)
tail    SGKT Keystone trailer                                         (unchanged, still last)
```

SGTO v3 records are laid out exactly as v1/v2 (no new crypto: the same X25519 + HKDF +
AES-256-GCM and Argon2id records). Version 3 only says "a spare exists". Segment-log key wraps
(outside `.sg1`) keep v1/v2.

## Reading rules (fail closed)

1. Front copy, if its CRC32 checks. A wrong key costs one KDF run, not two.
2. Else the last CRC-good `SGTS` spare within the final ~26 KiB (largest wrap + trailer + 1 KiB), and its SGTO must be v3.
3. Else a byte-by-byte merge: line the two copies up (length from either copy's record
   count and kinds; the spare ends right before the trailer, or at end of file), and where they
   differ (at most 12 bytes) try each mix until the block CRC32 checks and the block is v3.
4. Whatever is used must still open its AES-GCM wrap record and then the body's AES-GCM tag
   and inner SHA-256. A forged or mis-merged block can only fail, never return other bytes
   (tests `forged_spare_with_front_damaged_fails_closed`, `wrong_key_fails_closed_with_either_copy`,
   `truncation_never_returns_wrong_plaintext`, `both_copies_damaged_fails_closed`).

`mend` writes both copies back, so a repaired file is byte-identical to the original
(`either_copy_alone_opens_and_mend_restores_the_exact_original`,
`mend_with_keywrap_and_data_damage_is_byte_identical`). Only spares of v3 blocks are ever
searched or written, and only on private-label (v3 header) seals.

## Compatibility

- Old files (SGTO v1/v2, one copy) open and mend exactly as before; mend does not add a spare
  (`old_single_copy_files_open_and_mend_unchanged`, fixtures `tests/fixtures/keywrap-v0/`
  written by `13eee34`, plus `kdf-v2/`). They keep the one-copy weakness until re-sealed.
- New encrypted files open only with this build or later. `13eee34` refuses them cleanly
  ("v3 seal has no key wrap (SGTO) left"; exit 1 for unseal, exit 2 and nothing written for
  mend). That refusal is deliberate: a tool that does not know the spare must not rewrite the
  front wrap and leave an old spare behind.
- Plain (unencrypted) seals are unchanged.
- The web lab reads the new layout (front or spare) but still writes the one-copy layout.

## Cost

Spare = wrap length + 8 bytes: 109 B (passphrase only), 121 B (one recipient), 101 B more per
extra recipient (`spare_costs_wrap_length_plus_eight_bytes`). Large files are work packs of
4 MiB stars; each encrypted star carries its own spare (`work_pack_stars_carry_spares`).

## Measurement

Method: `cargo test --release -p sigil --lib keywrap_loss_table -- --ignored --nocapture`.
Random plaintext, sealed encrypt-to one X25519 recipient (CLI default part size 4 MiB),
Reflection and Seal, one single seal per size (the CLI turns files over 4 MiB into work packs
of 4 MiB stars, each with its own wrap, so a 10 MiB CLI file has three wraps to lose). Damage anywhere in the file (like `scripts/measure-repair.py`, not just
shard bodies): random bit flips at the given bit-error rate, or one zeroed run at a random
offset. Open = `unseal`, else `mend` (quick, then soft) + `unseal`. "Lost only to key wrap" =
refused, but opens once the key-wrap bytes are put back. Same seeds before and after; the
new file is 121 bytes longer, so the same seed lands flips on slightly different bytes. WRONG
(returned bytes that differ) was 0 in every row. Before = `main` @ `13eee34`; after = this
change. "4 KiB" etc. is the plaintext size.

Totals: lost only to the key wrap **908 of 7 200 → 9**; from one burst **156 → 0**.

| plaintext | mode | damage | trials | before: file B | before: refused | before: lost ONLY to key wrap | after: file B | after: refused | after: lost ONLY to key wrap | WRONG (before/after) |
|---|---|---|---|---|---|---|---|---|---|---|
| 4 KiB | Reflection | bits BER 1e-5 | 400 | 9,110 | 4 | **4** | 9,231 | 0 | **0** | 0/0 |
| 4 KiB | Reflection | bits BER 1e-4 | 400 | 9,110 | 32 | **32** | 9,231 | 0 | **0** | 0/0 |
| 4 KiB | Reflection | bits BER 1e-3 | 400 | 9,110 | 241 | **236** | 9,231 | 8 | **4** | 0/0 |
| 4 KiB | Reflection | 512 B burst | 400 | 9,110 | 25 | **25** | 9,231 | 0 | **0** | 0/0 |
| 4 KiB | Reflection | 4 KiB burst | 400 | 9,110 | 400 | **0** | 9,231 | 400 | **0** | 0/0 |
| 4 KiB | Reflection | 10% burst | 400 | 9,110 | 44 | **44** | 9,231 | 0 | **0** | 0/0 |
| 4 KiB | Seal | bits BER 1e-5 | 400 | 11,894 | 7 | **7** | 12,015 | 0 | **0** | 0/0 |
| 4 KiB | Seal | bits BER 1e-4 | 400 | 11,894 | 45 | **45** | 12,015 | 0 | **0** | 0/0 |
| 4 KiB | Seal | bits BER 1e-3 | 400 | 11,894 | 242 | **241** | 12,015 | 5 | **5** | 0/0 |
| 4 KiB | Seal | 512 B burst | 400 | 11,894 | 20 | **20** | 12,015 | 0 | **0** | 0/0 |
| 4 KiB | Seal | 4 KiB burst | 400 | 11,894 | 32 | **32** | 12,015 | 0 | **0** | 0/0 |
| 4 KiB | Seal | 10% burst | 400 | 11,894 | 34 | **34** | 12,015 | 0 | **0** | 0/0 |
| 1 MiB | Reflection | bits BER 1e-5 | 100 | 1,401,750 | 1 | **1** | 1,401,871 | 0 | **0** | 0/0 |
| 1 MiB | Reflection | bits BER 1e-4 | 100 | 1,401,750 | 10 | **10** | 1,401,871 | 0 | **0** | 0/0 |
| 1 MiB | Reflection | bits BER 1e-3 | 100 | 1,401,750 | 87 | **25** | 1,401,871 | 68 | **0** | 0/0 |
| 1 MiB | Reflection | 512 B burst | 100 | 1,401,750 | 0 | **0** | 1,401,871 | 0 | **0** | 0/0 |
| 1 MiB | Reflection | 4 KiB burst | 100 | 1,401,750 | 0 | **0** | 1,401,871 | 0 | **0** | 0/0 |
| 1 MiB | Reflection | 10% burst | 100 | 1,401,750 | 1 | **1** | 1,401,871 | 0 | **0** | 0/0 |
| 1 MiB | Seal | bits BER 1e-5 | 100 | 2,100,854 | 1 | **1** | 2,100,975 | 0 | **0** | 0/0 |
| 1 MiB | Seal | bits BER 1e-4 | 100 | 2,100,854 | 9 | **9** | 2,100,975 | 0 | **0** | 0/0 |
| 1 MiB | Seal | bits BER 1e-3 | 100 | 2,100,854 | 63 | **63** | 2,100,975 | 0 | **0** | 0/0 |
| 1 MiB | Seal | 512 B burst | 100 | 2,100,854 | 0 | **0** | 2,100,975 | 0 | **0** | 0/0 |
| 1 MiB | Seal | 4 KiB burst | 100 | 2,100,854 | 0 | **0** | 2,100,975 | 0 | **0** | 0/0 |
| 1 MiB | Seal | 10% burst | 100 | 2,100,854 | 0 | **0** | 2,100,975 | 0 | **0** | 0/0 |
| 10 MiB | Reflection | bits BER 1e-5 | 100 | 13,984,662 | 0 | **0** | 13,984,783 | 0 | **0** | 0/0 |
| 10 MiB | Reflection | bits BER 1e-4 | 100 | 13,984,662 | 9 | **9** | 13,984,783 | 0 | **0** | 0/0 |
| 10 MiB | Reflection | bits BER 1e-3 | 100 | 13,984,662 | 100 | **0** | 13,984,783 | 100 | **0** | 0/0 |
| 10 MiB | Reflection | 512 B burst | 100 | 13,984,662 | 0 | **0** | 13,984,783 | 0 | **0** | 0/0 |
| 10 MiB | Reflection | 4 KiB burst | 100 | 13,984,662 | 0 | **0** | 13,984,783 | 0 | **0** | 0/0 |
| 10 MiB | Reflection | 10% burst | 100 | 13,984,662 | 0 | **0** | 13,984,783 | 0 | **0** | 0/0 |
| 10 MiB | Seal | bits BER 1e-5 | 100 | 20,975,222 | 0 | **0** | 20,975,343 | 0 | **0** | 0/0 |
| 10 MiB | Seal | bits BER 1e-4 | 100 | 20,975,222 | 6 | **6** | 20,975,343 | 0 | **0** | 0/0 |
| 10 MiB | Seal | bits BER 1e-3 | 100 | 20,975,222 | 63 | **63** | 20,975,343 | 0 | **0** | 0/0 |
| 10 MiB | Seal | 512 B burst | 100 | 20,975,222 | 0 | **0** | 20,975,343 | 0 | **0** | 0/0 |
| 10 MiB | Seal | 4 KiB burst | 100 | 20,975,222 | 0 | **0** | 20,975,343 | 0 | **0** | 0/0 |
| 10 MiB | Seal | 10% burst | 100 | 20,975,222 | 0 | **0** | 20,975,343 | 0 | **0** | 0/0 |

The 9 left are 4 KiB files at a bit-error rate of 1e-3 (about 1 flip per 125 bytes), where both
~113-byte copies were too damaged to merge (hit in the same byte, or more than 12 differing
bytes). A spare alone (no merge; an intermediate run with the same seeds) left 400, nearly all
at 1e-3; the merge took that to 9 at no size cost.

## Alternatives considered

- **Reed–Solomon-protect the wrap inside the shards.** Stronger in theory, but the wrap must
  be read before the shards can be decrypted, the shard layout and Merkle binding would change,
  and old readers would misread the body. Rejected: bigger change, same practical result.
- **Three copies.** One more ~110 bytes for little gain once two copies are merged; bursts
  already cannot hit both copies (they are a whole file apart).
- **Spare without a version bump.** Old builds would open new files, but could also rewrite
  the front wrap (re-wrap, mend) and leave a stale spare that still opens for a removed
  recipient. Rejected; the bump makes old builds fail closed instead.

## Not covered

- Encrypted files written before this change: re-seal to upgrade.
- Scatter pieces (`.sgp`) already carry the front block in every piece; unchanged.
- Segment-log key rings and index keys (files beside the segments, outside `.sg1`) are separate
  single-copy key wraps; not changed here.
