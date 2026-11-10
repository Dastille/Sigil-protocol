# ratchet-measure

Research harness for `docs/research/RATCHET-REPAIR.md`. Standalone crate (not a
workspace member). Does not touch the `sigil` crate or the `.sg1` format.

    cargo test --release                       # 7 checks, incl. byte-equality with Sigil's Seal RS
    cargo run --release -- --trials 200 --threads 18 --max-secs 2400 --out-dir out
    cargo run --release -- --points L8 --decoders "ratchet 64" --trials 20

Writes `results.md` and `results.csv`. Side-files are written to and read back from a temp dir.
