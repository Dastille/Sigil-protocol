#!/usr/bin/env bash
# Build per-OS Sigil release binaries locally without sudo and generate SHA256SUMS.
#
# Usage:
#   scripts/release-build.sh [OUT_DIR]
#
# Defaults:
#   OUT_DIR=./dist
#
# Built on Linux x86_64:
#   - sigil-linux-x86_64 (+ .tar.gz)        static musl (x86_64-unknown-linux-musl)
#   - sigil-windows-x86_64.exe (+ .zip)     MinGW GNU cross-build (x86_64-pc-windows-gnu)
#
# Optional targets via SIGIL_RELEASE_TARGETS (space-separated):
#   linux-x86_64 windows-x86_64 linux-arm64
#
# macOS is only built when running natively on Darwin; no zero-cost Linux->macOS
# cross-compilation SDK is assumed. Signing SHA256SUMS with minisign remains a
# manual offline step by the release key holder (see docs/RELEASE.md).

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
OUT_DIR="${1:-$REPO_ROOT/dist}"

if [ "${EUID:-$(id -u)}" -eq 0 ]; then
  echo "release-build: refusing to run as root (no sudo needed)." >&2
  exit 1
fi

if [ -f "$HOME/.cargo/env" ]; then
  # shellcheck disable=SC1091
  source "$HOME/.cargo/env"
fi

for cmd in cargo rustc rustup sha256sum tar gzip; do
  command -v "$cmd" >/dev/null 2>&1 || {
    echo "release-build: missing required command: $cmd" >&2
    exit 1
  }
done

[ -f "$REPO_ROOT/Cargo.lock" ] || {
  echo "release-build: Cargo.lock missing (--locked required)" >&2
  exit 1
}

mkdir -p "$OUT_DIR"
OUT_DIR="$(cd "$OUT_DIR" && pwd)"

export LC_ALL=C
export TZ=UTC
export CARGO_INCREMENTAL=0
export ZERO_AR_DATE=1

if [ -z "${SOURCE_DATE_EPOCH:-}" ]; then
  if command -v git >/dev/null 2>&1 && git -C "$REPO_ROOT" rev-parse --git-dir >/dev/null 2>&1; then
    SOURCE_DATE_EPOCH="$(git -C "$REPO_ROOT" log -1 --format=%ct HEAD)"
  else
    SOURCE_DATE_EPOCH=0
  fi
fi
export SOURCE_DATE_EPOCH

CARGO_HOME_DIR="${CARGO_HOME:-$HOME/.cargo}"
REMAP_FLAGS="--remap-path-prefix=${REPO_ROOT}=/build --remap-path-prefix=${CARGO_HOME_DIR}=/cargo -C strip=symbols"

HOST_TRIPLE="$(rustc -vV | sed -n 's/^host: //p')"
SYSROOT="$(rustc --print sysroot)"
RUST_LLD="${SYSROOT}/lib/rustlib/${HOST_TRIPLE}/bin/rust-lld"

TARGETS="${SIGIL_RELEASE_TARGETS:-linux-x86_64 windows-x86_64}"

pack_tar_gz() {
  local dir="$1" bin="$2" out_tgz="$3"
  chmod 0755 "$dir/$bin"
  touch -d "@${SOURCE_DATE_EPOCH}" "$dir/$bin"
  tar --sort=name --mtime="@${SOURCE_DATE_EPOCH}" --owner=0 --group=0 --numeric-owner \
    -C "$dir" -cf - "$bin" | gzip -n > "$out_tgz"
}

pack_zip() {
  local dir="$1" bin="$2" out_zip="$3"
  chmod 0755 "$dir/$bin"
  touch -d "@${SOURCE_DATE_EPOCH}" "$dir/$bin"
  if command -v python3 >/dev/null 2>&1; then
    python3 - "$dir/$bin" "$bin" "$out_zip" "$SOURCE_DATE_EPOCH" <<'PY'
import datetime, pathlib, sys, zipfile

src_path = pathlib.Path(sys.argv[1])
arcname = sys.argv[2]
out_zip = pathlib.Path(sys.argv[3])
epoch = int(sys.argv[4])

dt = datetime.datetime.fromtimestamp(epoch, tz=datetime.timezone.utc)
if dt.year < 1980:
    dt = datetime.datetime(1980, 1, 1, 0, 0, 0, tzinfo=datetime.timezone.utc)
zdt = (dt.year, dt.month, dt.day, dt.hour, dt.minute, dt.second)

zi = zipfile.ZipInfo(filename=arcname, date_time=zdt)
zi.create_system = 3  # Unix permissions
zi.external_attr = 0o100755 << 16
zi.compress_type = zipfile.ZIP_DEFLATED

data = src_path.read_bytes()
with zipfile.ZipFile(out_zip, "w") as zf:
    zf.writestr(zi, data)
PY
  elif command -v zip >/dev/null 2>&1; then
    (cd "$dir" && zip -q -X "$out_zip" "$bin")
  else
    echo "release-build: need python3 or zip to pack $out_zip" >&2
    exit 1
  fi
}

ensure_target() {
  local target="$1"
  if ! rustup target list --installed | grep -qx "$target"; then
    rustup target add "$target"
  fi
}

cd "$REPO_ROOT"

for item in $TARGETS; do
  case "$item" in
    linux-x86_64)
      target="x86_64-unknown-linux-musl"
      ensure_target "$target"
      echo "=== Building $item ($target, static musl) ==="
      CARGO_TARGET_X86_64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="$REMAP_FLAGS" \
        cargo build --release --locked --target "$target" --bin sigil
      cp "$REPO_ROOT/target/$target/release/sigil" "$OUT_DIR/sigil-linux-x86_64"
      pack_tar_gz "$OUT_DIR" "sigil-linux-x86_64" "$OUT_DIR/sigil-linux-x86_64.tar.gz"
      ;;
    linux-arm64)
      target="aarch64-unknown-linux-musl"
      ensure_target "$target"
      [ -x "$RUST_LLD" ] || {
        echo "release-build: missing rust-lld at $RUST_LLD for $target" >&2
        exit 1
      }
      echo "=== Building $item ($target, static musl via rust-lld) ==="
      CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER="$RUST_LLD" \
      CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_RUSTFLAGS="$REMAP_FLAGS -C linker-flavor=ld.lld" \
        cargo build --release --locked --target "$target" --bin sigil
      cp "$REPO_ROOT/target/$target/release/sigil" "$OUT_DIR/sigil-linux-arm64"
      pack_tar_gz "$OUT_DIR" "sigil-linux-arm64" "$OUT_DIR/sigil-linux-arm64.tar.gz"
      ;;
    windows-x86_64)
      target="x86_64-pc-windows-gnu"
      command -v x86_64-w64-mingw32-gcc >/dev/null 2>&1 || {
        echo "release-build: missing x86_64-w64-mingw32-gcc for $target" >&2
        exit 1
      }
      ensure_target "$target"
      echo "=== Building $item ($target, MinGW GNU) ==="
      CARGO_TARGET_X86_64_PC_WINDOWS_GNU_LINKER="x86_64-w64-mingw32-gcc" \
      CARGO_TARGET_X86_64_PC_WINDOWS_GNU_RUSTFLAGS="$REMAP_FLAGS -C link-arg=-Wl,--no-insert-timestamp" \
        cargo build --release --locked --target "$target" --bin sigil
      cp "$REPO_ROOT/target/$target/release/sigil.exe" "$OUT_DIR/sigil-windows-x86_64.exe"
      pack_zip "$OUT_DIR" "sigil-windows-x86_64.exe" "$OUT_DIR/sigil-windows-x86_64.exe.zip"
      ;;
    macos-arm64|macos-x86_64)
      if [ "$(uname -s)" != "Darwin" ]; then
        echo "=== Skipping $item (not on macOS; no zero-cost cross SDK available) ==="
        continue
      fi
      if [ "$item" = "macos-arm64" ]; then
        target="aarch64-apple-darwin"
        env_prefix="AARCH64_APPLE_DARWIN"
      else
        target="x86_64-apple-darwin"
        env_prefix="X86_64_APPLE_DARWIN"
      fi
      ensure_target "$target"
      echo "=== Building $item ($target) ==="
      env "CARGO_TARGET_${env_prefix}_RUSTFLAGS=$REMAP_FLAGS" \
        cargo build --release --locked --target "$target" --bin sigil
      cp "$REPO_ROOT/target/$target/release/sigil" "$OUT_DIR/sigil-$item"
      pack_tar_gz "$OUT_DIR" "sigil-$item" "$OUT_DIR/sigil-$item.tar.gz"
      ;;
    *)
      echo "release-build: unknown target '$item'" >&2
      exit 2
      ;;
  esac
done

echo "=== Writing SHA256SUMS ==="
bash "$REPO_ROOT/scripts/make-sha256sums.sh" "$OUT_DIR"
cat "$OUT_DIR/SHA256SUMS"
