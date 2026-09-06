# LRC cold-USB kits (track #4)

## Ship first — Option A (placement only)

Keep Seal (8,16). Round-robin 16 shards across 4 USBs (4/USB). One USB lost = 4 shards gone = within Seal budget. Atlas/`KIT` records star/shard/usb.

```
sigil inscribe --mode seal -o mark.sg1 file.bin
sigil kit place mark.sg1 --drives 4 -o ./kit/
# copy kit/usb-0 … usb-3 onto four sticks
# if usb-2 dies, bring the other three back under ./kit/
sigil kit mend ./kit -o healed.sg1
sigil de-scribe -o file.bin healed.sg1
```

`KIT` at the kit root lists `star_id` (true-name hex), `shard=i usb=j` rows, and `n`/`k`. No new erasure codec — same Seal RS as a single `.sg1`.

CLI alias: `sigil cold-usb place …` / `sigil cold-usb mend …`.

## Later — Option B (true LRC)

Azure-style local + global parities only if Option A repair I/O/UX is insufficient. **Not in this PR.**

Same true-name proof. Not a RaptorQ replacement.

Sources: Huang et al. ATC 2012 Azure LRC; Dimakis allocation papers.
