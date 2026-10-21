#!/usr/bin/env bash
# Thin wrapper around: sigil inscribe … [--rsync|--rclone|--wormhole]
set -euo pipefail

usage() {
  echo "Usage: $0 [-m seal|reflection|glyph] [-p passphrase] [--rsync dest] [--rclone dest] [--wormhole] INPUT OUTPUT.sg1"
  echo "  Default truck is rsync when you pass --rsync user@host:/path/"
  exit 1
}

MODE=seal
PASS=()
RSYNC=()
RCLONE=()
WORM=()
while [[ $# -gt 0 ]]; do
  case "$1" in
    -m|--mode) MODE="${2:-}"; shift 2 ;;
    -p|--pass) PASS=(--pass "$2"); shift 2 ;;
    --rsync) RSYNC=(--rsync "$2"); shift 2 ;;
    --rclone) RCLONE=(--rclone "$2"); shift 2 ;;
    --wormhole) WORM=(--wormhole); shift ;;
    -h|--help) usage ;;
    *) break ;;
  esac
done
[[ $# -eq 2 ]] || usage

ROOT=$(cd "$(dirname "$0")" && pwd)
if command -v sigil >/dev/null 2>&1; then SIGIL=sigil
elif [[ -x "$ROOT/sigil" ]]; then SIGIL="$ROOT/sigil"
elif [[ -x "$ROOT/target/release/sigil" ]]; then SIGIL="$ROOT/target/release/sigil"
else echo "sigil not found"; exit 1
fi

exec "$SIGIL" inscribe --mode "$MODE" "${PASS[@]}" "${RSYNC[@]}" "${RCLONE[@]}" "${WORM[@]}" -o "$2" "$1"
