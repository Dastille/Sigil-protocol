# Build Sigil from source

Same crate on Linux, Windows, and macOS. Rust 1.70+ (`rustup`).

```
cd crate/sigil
cargo build --release
```

| You are on | Output |
|---|---|
| Linux | `target/release/sigil` |
| Windows (PowerShell) | `target\release\sigil.exe` |
| macOS | `target/release/sigil` (same `cargo build --release`) |
| Linux → Windows | needs MinGW (`x86_64-w64-mingw32-gcc`). This app sandbox cannot produce `.exe`. |

No extra libraries. AGPL-3.0 for this program. Apache-2.0 for the `.sg1` layout (`LICENSE.SPEC` at the repo root).

Tag **v1.0** on GitHub when you push `Dastille/Sigil-protocol` (this sandbox cannot log into your GitHub).
