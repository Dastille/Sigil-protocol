# Sigil breakthrough map

Frozen v1 layout: `public/sigil-v1.txt`. Tooling below is **v1.x** (no byte-layout break) unless marked **v2**.

Lab: https://dove-bloom-star-island.grok.me

## Already shipped in this crate

- **Keystone + Ember** — smashed or wiped front header still locates; live shards stay findable.
- **Honest repair budget** — Reflection ~25%, Seal ~50%; Glyph is all-or-nothing.
- **Ward** — AES-256-GCM; chaos fold is obfuscation only.
- **True name + Merkle** — SHA-256 of plaintext; Merkle binds the classic `n` shards.
- **Scatter / Gather** — piece folders (`.sgp`); any `k` distinct pieces rebuild a healthy `.sg1`.
- **Deluge** — extra indexed RS rain past `n` (index ≤ 254); mixed lanes for coupon collection.
- **RaptorQ fountain** — `--fountain` / `.rq` packets via `deluge_fountain` / `gather_fountain` (no 255 ceiling).
- **In-place mend** — `sigil mend torn.sg1 -o healed.sg1` (alias `repair`): locate header → gather live shards → decode ≥`k` → re-encode classic `0..n-1` → rewrite full mark (keystone / ember / vow). No passphrase; stays in the folded domain. Glyph errors if any shard is missing.

## Gaps still open

1. **Whole-file RAM** — seal/unseal/mend still load the mark; multi-GB media needs streaming.
2. **Deflate-only** — already-compressed video barely shrinks; entropy flag unused for codec choice.
3. **Constellation productization** — card / atlas / Geas exist in code paths but are not the archive product yet.
4. **Show / range serve** — work-pack `show` exists; Jellyfin-grade streaming UX still maturing.

## Next leaps (recommended order)

1. ~~Scatter / gather / deluge / RaptorQ~~ — done.
2. ~~In-place `mend`~~ — done (this branch).
3. **Streaming / chunked Inscribe** — unblocks movie libraries without whole-file RAM.
4. **zstd + passthrough codec flag (v2)** — media → none; dumps → zstd; keep deflate for v1.
5. **Constellation index + Geas productization** — cold USB kits, `.sga` atlas workflows.
6. Optional: cross-star heal, Argon2id Ward, CDC stars.

## Math notes

- Vandermonde RS over GF(256) is in `rs.rs` / `gf.rs` (systematic v2).
- Indexed RS rain and RaptorQ are **already** the fountain/regeneration tools — not a future invention on this branch.
- Order must stay: compress → fold → Ward (never encrypt then compress).
- Prove same true name from: full `.sg1` | any `k` shards + Ember | piece folder gather | fountain gather | mend rewrite.
