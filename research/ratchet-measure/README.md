# ratchet-measure

Research harness for `docs/research/RATCHET-REPAIR.md`. Standalone crate (not a
workspace member). Does not touch the `sigil` crate or the `.sg1` format.

    cargo test --release                       # 7 checks, incl. byte-equality with Sigil's Seal RS
    cargo run --release -- --trials 200 --threads 18 --max-secs 2400 --out-dir out
    cargo run --release -- --points L8 --decoders "ratchet 64" --trials 20

Writes `results.md` and `results.csv`. Side-files are written to and read back from a temp dir.

## Real-data mode

```
ratchet-measure real --list FILES.txt [--trials 72] [--threads N] [--max-secs 900] \
    [--mend-secs 20] [--tracks reflection,seal] --out-dir DIR
```

`FILES.txt` lists scratch **copies** of real n=16 `.sg1` stars (one path per line, or a
tab-separated line whose last column is the path). Never point it at an original archive.
Every star is checked before use: the Ember maps are located, each shard CRC is checked,
the real Merkle root must match, the stored parity must be reproduced, and the star must
unseal. Today's repair is the real `sigil::mend_bytes_ex(_, soft)`, run in a child process
(`ratchet-measure mend-one IN OUT`) and stopped after `--mend-secs`. Every other decoder
must pass the real Merkle + `sigil::unseal` gate. Each trial's result is appended to
`DIR/real-trials.csv` as it finishes, and the summary goes to `DIR/real-results.{md,csv}`.
