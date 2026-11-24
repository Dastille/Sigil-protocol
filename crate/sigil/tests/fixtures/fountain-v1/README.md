# fountain-v1 fixtures (Channel mana, SGFT packet version 1)

Written by the Rust CLI on `main` @ `bc96b5a` (before random symbol IDs and
per-packet checksums), so the reader for version-1 packets stays tested. The
packet bytes are unchanged; the files were renamed from the original
`rain-NNNNN.rq` to `mana-NNNNN.mana` when Channel moved to the `.mana`
extension (`.rq` is no longer read).

```
sigil seal --mode seal -o mark.sg1 plain.bin
sigil deluge mark.sg1 --channel --extra 2 -o mana     # mana-00000.mana .. mana-00007.mana
```

`plain.bin` is 40 000 pseudo-random bytes (Python `random.seed(6330)`).
