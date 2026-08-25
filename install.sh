#!/bin/sh
# Sigil v1.0 — copy the Linux binary into /usr/local/bin (or $PREFIX)
set -e
PREFIX="${PREFIX:-/usr/local}"
DIR="$(cd "$(dirname "$0")" && pwd)"
BIN="$DIR/sigil-linux-x86_64"
if [ ! -f "$BIN" ]; then
  echo "sigil-linux-x86_64 missing. Unpack the tarball next to this script." >&2
  exit 1
fi
mkdir -p "$PREFIX/bin"
cp "$BIN" "$PREFIX/bin/sigil"
chmod +x "$PREFIX/bin/sigil"
echo "installed $PREFIX/bin/sigil"
echo "Windows/macOS: cargo build --release in crate/sigil"
