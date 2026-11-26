# syntax=docker/dockerfile:1
# Multi-stage, multi-arch (linux/amd64, linux/arm64) Dockerfile for the Sigil CLI.
# Runtime choice: gcr.io/distroless/static-debian12:nonroot over debian-slim because
# sigil links statically against musl and needs no shell, libc, or package manager
# at runtime (smaller attack surface, ~2.5 MiB base + ~4 MiB static binary).

FROM --platform=$BUILDPLATFORM docker.io/library/rust@sha256:bb875b0f8ce726053e259034848c471840e96bfe591fd52556178ae9a05e6126 AS builder

ARG TARGETARCH
ARG SIGIL_GIT_COMMIT=unknown
ARG SOURCE_DATE_EPOCH=0

ENV CARGO_INCREMENTAL=0 \
    CARGO_NET_RETRY=3 \
    SOURCE_DATE_EPOCH=${SOURCE_DATE_EPOCH}

WORKDIR /src
COPY Cargo.toml Cargo.lock ./
COPY crate/sigil ./crate/sigil

RUN set -eu; \
    arch="${TARGETARCH:-$(uname -m)}"; \
    case "$arch" in \
      amd64|x86_64)  target="x86_64-unknown-linux-musl";  triple_env="X86_64_UNKNOWN_LINUX_MUSL" ;; \
      arm64|aarch64) target="aarch64-unknown-linux-musl"; triple_env="AARCH64_UNKNOWN_LINUX_MUSL" ;; \
      *) echo "unsupported arch: $arch" >&2; exit 1 ;; \
    esac; \
    rustup target add "$target"; \
    host_triple="$(rustc -vV | sed -n 's/^host: //p')"; \
    lld="$(rustc --print sysroot)/lib/rustlib/${host_triple}/bin/rust-lld"; \
    test -x "$lld"; \
    export "CARGO_TARGET_${triple_env}_LINKER=${lld}"; \
    export "CARGO_TARGET_${triple_env}_RUSTFLAGS=--remap-path-prefix=/src=/build --remap-path-prefix=/usr/local/cargo=/cargo -C strip=symbols -C linker-flavor=ld.lld"; \
    export SIGIL_GIT_COMMIT; \
    cargo build --release --locked --target "$target" --bin sigil; \
    mkdir -p /out; \
    cp "target/${target}/release/sigil" /out/sigil; \
    chmod 0755 /out/sigil; \
    touch -d "@${SOURCE_DATE_EPOCH}" /out/sigil

FROM gcr.io/distroless/static-debian12@sha256:afa5c872c891853ca7fcf1f12c3edb23f7eeef36189728842dd51042ff57f7ab AS runtime

ARG SIGIL_VERSION=0.9.0
ARG SIGIL_GIT_COMMIT=unknown

LABEL org.opencontainers.image.title="sigil" \
      org.opencontainers.image.description="Sigil CLI for regenerative .sg1 Sigil Archives" \
      org.opencontainers.image.url="https://github.com/Dastille/Sigil-protocol" \
      org.opencontainers.image.source="https://github.com/Dastille/Sigil-protocol" \
      org.opencontainers.image.licenses="AGPL-3.0-or-later" \
      org.opencontainers.image.version="${SIGIL_VERSION}" \
      org.opencontainers.image.revision="${SIGIL_GIT_COMMIT}"

COPY --from=builder /out/sigil /usr/local/bin/sigil

USER 65532:65532

ENTRYPOINT ["/usr/local/bin/sigil"]
CMD ["--help"]
