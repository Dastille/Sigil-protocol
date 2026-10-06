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

No extra libraries for the default build. Optional `--features passkey` (FIDO2 security keys) needs `libudev-dev` + `pkg-config` on Linux — see `docs/PASSKEY.md`. AGPL-3.0 for this program. Apache-2.0 for the `.sg1` layout (`LICENSE.SPEC` at the repo root).

Tag **v1.0** on GitHub when you push `Dastille/Sigil-protocol` (this sandbox cannot log into your GitHub).

**CI**

Every push and PR to `main` runs `.github/workflows/ci.yml`: `cargo build --locked --all-targets` + `cargo test --locked` (lib + integration tests), plus a second job that builds `--features passkey` headless (libudev-dev) and runs the passkey tests against the software authenticator. Cargo deps and `target/` are cached. Tagged releases still use `release.yml`.

**Mount / FUSE (Linux)**

`sigil mount` links `fuser` on Unix. Runtime needs `/dev/fuse` and `fusermount3` (`fuse3` package). If the environment forbids FUSE (common in containers), use `--export-dir` instead — same read-only view, seal untouched.

