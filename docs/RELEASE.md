# Building and verifying Sigil releases

This document covers local and manual Docker image builds, per-OS release
binaries, checksum generation, and offline release signing.

All release workflows in `.github/workflows/` are manual-only
(`workflow_dispatch`) so nothing runs automatically on push, pull request,
tag, or schedule.

## 1. Docker / OCI image (`Dockerfile`)

The root `Dockerfile` is a multi-stage, multi-arch (`linux/amd64`,
`linux/arm64`) build:

- **Builder stage:** `docker.io/library/rust@sha256:bb875b0f8ce726053e259034848c471840e96bfe591fd52556178ae9a05e6126`
  (`rust:1-slim-bookworm` multi-arch OCI index). Cross-compiles static musl
  binaries with `rust-lld` using `cargo build --release --locked`,
  `CARGO_INCREMENTAL=0`, `SOURCE_DATE_EPOCH`, `--remap-path-prefix`, and
  `-C strip=symbols`.
- **Runtime stage:** `gcr.io/distroless/static-debian12@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab`
  (`static-debian12:nonroot` multi-arch OCI index). Distroless static is chosen
  over `debian:bookworm-slim` because the musl binary is statically linked and
  requires no shell, libc, or package manager at runtime (~9.8 MB on `amd64`,
  ~8.5 MB on `arm64`, `USER 65532:65532`, minimal attack surface).
- **Version stamp:** Pass `--build-arg SIGIL_GIT_COMMIT=$(git rev-parse --short=7 HEAD)`
  so `sigil --version` records the commit even though `.dockerignore` omits `.git`.

### Build locally (`amd64`)

```sh
docker build \
  --build-arg SIGIL_VERSION=0.9.0 \
  --build-arg SIGIL_GIT_COMMIT="$(git rev-parse --short=7 HEAD)" \
  --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct HEAD)" \
  -t sigil:local .
```

### Multi-arch build (`linux/amd64` and `linux/arm64`)

```sh
docker buildx build \
  --platform linux/amd64,linux/arm64 \
  --build-arg SIGIL_VERSION=0.9.0 \
  --build-arg SIGIL_GIT_COMMIT="$(git rev-parse --short=7 HEAD)" \
  --build-arg SOURCE_DATE_EPOCH="$(git log -1 --format=%ct HEAD)" \
  -t ghcr.io/dastille/sigil:0.9.0 \
  .
```

Add `--push` when publishing to a registry, or `--load` with a single
`--platform` to load into the local Docker daemon.

### Running without FUSE (`--export-dir`)

Docker environments normally lack `/dev/fuse` and `fusermount3`. Plain `sigil mount`
exits non-zero with a clear error pointing to `--export-dir`. Use
`--export-dir` for a read-only exported view without modifying the `.sg1`
Sigil Archive (a positional `<MOUNTPOINT>` argument is still required):

```sh
docker run --rm -v "$PWD:/work" -w /work sigil:local --version
docker run --rm -v "$PWD:/work" -w /work sigil:local seal -o /work/data.sg1 /work/data.bin
docker run --rm -v "$PWD:/work" -w /work sigil:local unseal -o /work/out.bin /work/data.sg1
docker run --rm -v "$PWD:/work" -w /work sigil:local mount /work/data.sg1 /work/mnt --export-dir /work/view
```

## 2. Per-OS release binaries (`scripts/release-build.sh`)

Run without `sudo` from the repository root:

```sh
bash scripts/release-build.sh ./dist
```

Default targets built on a Linux `x86_64` host:

| Artifact | Target | Toolchain | Notes |
|---|---|---|---|
| `sigil-linux-x86_64` (+ `.tar.gz`) | `x86_64-unknown-linux-musl` | `rustup` musl target | Statically linked (`static-pie`), stripped |
| `sigil-windows-x86_64.exe` (+ `.zip`) | `x86_64-pc-windows-gnu` | `x86_64-w64-mingw32-gcc` | Cross-compiled without `sudo` |

Optional targets via `SIGIL_RELEASE_TARGETS` (space-separated):

- `linux-arm64` (`aarch64-unknown-linux-musl`, statically linked via `rust-lld`)
- `macos-arm64` / `macos-x86_64` (built only when running natively on macOS;
  no Linux-to-macOS cross SDK is assumed, and paid Apple notarization is not
  used; `sigil mount` may be omitted or require macFUSE, with `--export-dir` as
  the mount-less path)

`scripts/release-build.sh` finishes by running `scripts/make-sha256sums.sh` to
write a sorted `SHA256SUMS` file in the output directory.

### Reproducibility notes

Both `Dockerfile` and `scripts/release-build.sh` set:

- `--locked` (`Cargo.lock` pinned)
- `CARGO_INCREMENTAL=0` and `ZERO_AR_DATE=1`
- `SOURCE_DATE_EPOCH` (defaults to `HEAD` commit timestamp)
- `--remap-path-prefix` for the repository root and Cargo home, plus `-C strip=symbols`
- `-Wl,--no-insert-timestamp` on Windows MinGW link to avoid PE COFF timestamp drift
- Deterministic `tar` (`--sort=name --mtime=... --numeric-owner`) + `gzip -n`, and
  fixed-timestamp `.zip` creation

## 3. Signing `SHA256SUMS` offline (release key holder)

Private signing keys and passphrases never run in CI or automation. After
verifying the built artefacts and `SHA256SUMS`, the key holder signs
`SHA256SUMS` offline with [minisign](https://jedisct1.github.io/minisign/)
(see `docs/RELEASE-SIGNING-DESIGN.md`):

```sh
minisign -Sm SHA256SUMS -s sigil-release.key -t "sigil vX.Y.Z"
```

Official public key (id `6AA9D817CBAC87FA`, stored in `keys/sigil-release.pub`):

```text
untrusted comment: minisign public key 6AA9D817CBAC87FA
RWT6h6zLF9ipahFYaGkWD1OdEeGyIVK4SDRi+0XIJmirk/4cSsdOqUNi
```

To verify a release download:

```sh
minisign -Vm SHA256SUMS -P RWT6h6zLF9ipahFYaGkWD1OdEeGyIVK4SDRi+0XIJmirk/4cSsdOqUNi
sha256sum -c SHA256SUMS --ignore-missing
```
