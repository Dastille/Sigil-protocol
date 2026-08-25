#!/bin/sh
# Run on YOUR machine (needs ~10 GB free). Not for the tiny lab.
set -e
SIGIL="${SIGIL:-./sigil-linux-x86_64}"
DIR="${TMPDIR:-/tmp}/sigil-5g-$$"
mkdir -p "$DIR"
echo "writing 5 GiB test file…"
dd if=/dev/urandom of="$DIR/in.bin" bs=1M count=5120 status=progress
echo "inscribe…"
"$SIGIL" inscribe -o "$DIR/out.sg1" "$DIR/in.bin"
"$SIGIL" scry "$DIR/out.sg1"
echo "de-scribe…"
"$SIGIL" de-scribe -o "$DIR/back.bin" "$DIR/out.sg1"
cmp "$DIR/in.bin" "$DIR/back.bin"
echo "OK — 5 GiB round-trip. rm -rf $DIR when done."
