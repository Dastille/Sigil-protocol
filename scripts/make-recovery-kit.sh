#!/usr/bin/env bash
# Build a Sigil recovery kit (SFX-DESIGN.md Option 0): everything needed to open or repair the
# given archives later, without assuming anything is installed. Writes DEST/sigil-recovery/.
#
#   scripts/make-recovery-kit.sh [--dest DIR] [--bin FILE]... [--spec FILE] [--dry-run] [--force]
#                                ARCHIVE...
#
# ARCHIVE  .sg1 files or segment log folders (NAME.sigil). Hashed into SHA256SUMS, never copied.
# --dest   where to create sigil-recovery/ (default: the folder of the first ARCHIVE)
# --bin    a sigil binary to include (repeatable; e.g. release builds for other platforms).
#          Default: the one being run ($SIGIL or `sigil` on PATH), named for this platform.
# --spec   format spec to include (default: docs/sigil-v1.txt next to this script's repo)
# --dry-run  list what would be written; write nothing.   --force  replace an existing kit.
# Never includes passphrases or keys: .sgk, .key, .pem and pass-file-like names are refused.
# Exit: 0 kit written (or planned), 2 bad input, 3 could not write.
set -u
SIGIL="${SIGIL:-sigil}"
here="$(cd "$(dirname "$0")" && pwd)"
usage() { sed -n '2,15p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
die() { echo "make-recovery-kit: $*" >&2; exit "${2:-2}"; }
secretish() {
  case "$(basename "$1" | tr 'A-Z' 'a-z')" in
    *.sgk|*.key|*.pem|*pass*|*pw|*pw.txt|*secret*|*.asc) return 0 ;;
  esac
  return 1
}
dest=""; spec="$here/../docs/sigil-v1.txt"; bins=(); archives=(); dry=0; force=0
while [ $# -gt 0 ]; do
  case "$1" in
    --dest) [ $# -ge 2 ] || usage; dest="$2"; shift 2 ;;
    --bin) [ $# -ge 2 ] || usage; bins+=("$2"); shift 2 ;;
    --spec) [ $# -ge 2 ] || usage; spec="$2"; shift 2 ;;
    --dry-run) dry=1; shift ;;
    --force) force=1; shift ;;
    -h|--help) usage ;;
    --pass|--pass-file|--identity|--ward|--ward-file) die "$1: a recovery kit never holds secrets" ;;
    -*) die "unknown option $1" ;;
    *) archives+=("$1"); shift ;;
  esac
done
[ ${#archives[@]} -ge 1 ] || die "no ARCHIVE given (a .sg1 file or a NAME.sigil log folder)"
for a in "${archives[@]}"; do
  [ -e "$a" ] || die "archive not found: $a"
  case "$a" in *.sgk|*.key|*.pem|*.asc) die "refusing a key file as an archive: $a" ;; esac
done
if [ ${#bins[@]} -eq 0 ]; then
  b="$(command -v "$SIGIL" 2>/dev/null)" || die "sigil not found (set SIGIL= or pass --bin)"
  bins=("$b")
  default_name="sigil-$(uname -s | tr 'A-Z' 'a-z')-$(uname -m)"
fi
for b in "${bins[@]}"; do
  [ -f "$b" ] || die "binary not found: $b"
  secretish "$b" && die "refusing a secret-looking file as a binary: $b"
done
[ -f "$spec" ] || die "spec not found: $spec (pass --spec)"
[ -n "$dest" ] || dest="$(dirname "${archives[0]}")"
[ -d "$dest" ] || die "destination folder not found: $dest"
kit="$dest/sigil-recovery"
if [ -e "$kit" ] && [ $force -eq 0 ]; then die "$kit exists (use --force to replace)"; fi
if command -v sha256sum >/dev/null; then sha() { sha256sum "$@"; }
elif command -v shasum >/dev/null; then sha() { shasum -a 256 "$@"; }
else die "need sha256sum or shasum" 3; fi
version="$("${bins[0]}" --version 2>/dev/null | head -1)"; [ -n "$version" ] || version="sigil (version unknown)"

names=()
for b in "${bins[@]}"; do
  if [ -n "${default_name:-}" ]; then names+=("$default_name"); else names+=("$(basename "$b")"); fi
done
if [ $dry -eq 1 ]; then
  echo "would write $kit/"
  echo "  RECOVER.txt"; echo "  SHA256SUMS"; echo "  spec/sigil-v1.txt"
  for n in "${names[@]}"; do echo "  bin/$n"; done
  for a in "${archives[@]}"; do echo "  (hash only) $a"; done
  exit 0
fi

tmp="$dest/.sigil-recovery.tmp.$$"
rm -rf "$tmp"; mkdir -p "$tmp/bin" "$tmp/spec" || die "cannot create $tmp" 3
trap 'rm -rf "$tmp"' EXIT
i=0
for b in "${bins[@]}"; do
  cp "$b" "$tmp/bin/${names[$i]}" && chmod 755 "$tmp/bin/${names[$i]}" || die "copy $b failed" 3
  i=$((i+1))
done
cp "$spec" "$tmp/spec/sigil-v1.txt" || die "copy spec failed" 3

alist=""
for a in "${archives[@]}"; do
  if [ -d "$a" ]; then alist+="   $(basename "$a")/   (segment log folder)"$'\n'
  else alist+="   $(basename "$a")   sha256 $(sha "$a" | cut -d' ' -f1)"$'\n'; fi
done
blist=""
for n in "${names[@]}"; do blist+="   bin/$n"$'\n'; done
awk -v d="$(date -u +%Y-%m-%dT%H:%MZ)" -v v="$version" -v A="$alist" -v B="$blist" '
  /^@ARCHIVES@$/ { printf "%s", A; next }
  /^@BINARIES@$/ { printf "%s", B; next }
  { gsub(/@DATE@/, d); gsub(/@VERSION@/, v); print }' "$here/RECOVER.txt.in" > "$tmp/RECOVER.txt" \
  || die "write RECOVER.txt failed" 3
(cd "$tmp" && sha RECOVER.txt spec/sigil-v1.txt bin/* > SHA256SUMS) || die "checksums failed" 3

rm -rf "$kit" && mv "$tmp" "$kit" || die "cannot move kit into $kit" 3
trap - EXIT
echo "recovery kit: $kit (${#names[@]} binary, spec, RECOVER.txt, SHA256SUMS)"
echo "copy it next to the archives; check with: (cd $kit && sha256sum -c SHA256SUMS)"
