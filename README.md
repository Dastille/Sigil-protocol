# Sigil

Wrap a file so a **damaged copy can still be restored**, and so you can tell if it was **swapped**.

v1.0. Writers emit **version 2** bytes; old v1 files still De-scribe. This is a **file format**, not a network, identity provider, or replacement for rsync / PGP / IPFS.

- **This program** (CLI): [AGPL-3.0](LICENSE)
- **Byte layout** (so others can implement `.sg1` without AGPL): [Apache 2.0](LICENSE.SPEC)

## Build

Rust 1.70+ ([rustup](https://rustup.rs)). Same source on Linux, Windows, and macOS.

```
cargo build --release
# Linux / macOS:  target/release/sigil
# Windows:        target\release\sigil.exe
```

## Use

```
./sigil inscribe -o out.sg1 file.bin          # Reflection: ~1.3× size, ~25% repair
./sigil scry out.sg1
./sigil de-scribe -o file.bin out.sg1

./sigil inscribe --mode seal -o dump.sg1 db.sql   # ~2× size, ~50% repair
./sigil open photo.sg1
```

Also in the command: Keystone (spare headers), Ember (header on each piece), Deluge (extra pieces), folders, Plex `show`, Overture (copy the start first), Talisman (key file), Attest (`.sg1.sig`).

```
./sigil --help
```

Layout: [docs/sigil-v1.txt](docs/sigil-v1.txt).

## Related

Earlier sketches: [Sigil-protocol](https://github.com/Dastille/Sigil-protocol), [ChaosRegenerationFlow](https://github.com/Dastille/ChaosRegenerationFlow).
