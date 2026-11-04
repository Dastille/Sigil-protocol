# Frost Rune — cold multi-drive Seal split (track #4)

**Frost Rune** is the people-facing name for spreading one Seal `.sg1` across several cold
drives so one lost drive does not lose the Sigil. Command: `sigil frost place` / `sigil frost mend`
(alias `frost-rune`). The old names `sigil kit …` and `sigil cold-usb …` are **deprecated hidden aliases**:
they still run for old scripts but should not be used in new ones.
Folder names on disk (`usb-0` …, `KIT` manifest) are unchanged, and `--json` output still reports
`"cmd":"kit place"` / `"cmd":"kit mend"` so existing scripts keep parsing it.

Hot storage name reserved: **Fire Rune** — not built; no behavior exists yet.

## Ship first — Option A (placement only)

Keep Seal (8,16). Round-robin 16 shards across 4 USBs (4/USB). One USB lost = 4 shards gone = within Seal budget. Atlas/`KIT` records star/shard/usb.

```
sigil inscribe --mode seal -o archive.sg1 file.bin
sigil frost place archive.sg1 --drives 4 -o ./frost/
# copy frost/usb-0 … usb-3 onto four sticks
# if usb-2 dies, bring the other three back under ./frost/
sigil frost mend ./frost -o healed.sg1
sigil de-scribe -o file.bin healed.sg1
```

`KIT` at the recovery folder root lists `star_id` (true-name hex), `shard=i usb=j` rows, and `n`/`k`. No new erasure codec — same Seal RS as a single `.sg1`.

Deprecated aliases (old scripts only): `sigil kit place|mend …`, `sigil cold-usb place|mend …`.

## Later — Option B (true LRC)

Azure-style local + global parities only if Option A repair I/O/UX is insufficient. **Not in this PR.**

Same true-name proof. Not a RaptorQ replacement.

Sources: Huang et al. ATC 2012 Azure LRC; Dimakis allocation papers.
