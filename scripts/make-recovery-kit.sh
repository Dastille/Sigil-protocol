#!/usr/bin/env bash
# Build a Sigil recovery kit (SFX-DESIGN.md Option 0): everything needed to open or repair the
# given archives later, without assuming anything is installed. Writes DEST/sigil-recovery/.
#
#   scripts/make-recovery-kit.sh [--dest DIR] [--bin FILE]... [--spec FILE] [--minisig FILE]
#                                [--check] [--dry-run] [--force] ARCHIVE...
#
# ARCHIVE  .sg1 files or segment log folders (NAME.sigil). Hashed into ARCHIVES.sha256 (every
#          file of a log folder), never copied.
# --check  first run `sigil scry` (.sg1) / `sigil log verify` (log folder) on each ARCHIVE with
#          the kit's binary; refuse to make the kit if one is damaged or unreadable (no keys used).
# --dest   where to create sigil-recovery/ (default: the folder of the first ARCHIVE)
# --bin    a sigil binary to include (repeatable; e.g. release builds for other platforms).
#          Default: the one being run ($SIGIL or `sigil` on PATH), named for this platform.
# --spec   format spec to include (default: docs/sigil-v1.txt next to this script's repo)
# --minisig  official release signature of SHA256SUMS (SHA256SUMS.minisig). Copied into the kit
#          when given, or when SHA256SUMS.minisig sits next to the first ARCHIVE or in --dest
#          (not inside an old sigil-recovery/ folder). This is the release signature, not a
#          signature of this folder's own SHA256SUMS.
# --dry-run  list what would be written; write nothing.   --force  replace an existing kit.
# Always copies the project minisign public key as SIGNING-KEY.pub (keys/sigil-release.pub).
# Never includes passphrases or keys: .sgk, .key, .pem and pass-file-like names are refused,
# and any file whose first line is "untrusted comment: minisign encrypted secret key" is refused.
# Exit: 0 kit written (or planned), 2 bad input, 3 could not write.
set -u
SIGIL="${SIGIL:-sigil}"
here="$(cd "$(dirname "$0")" && pwd)"
usage() { sed -n '2,24p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 2; }
die() { echo "make-recovery-kit: $*" >&2; exit "${2:-2}"; }
secretish() {
  case "$(basename "$1" | tr 'A-Z' 'a-z')" in
    *.sgk|*.key|*.pem|*pass*|*pw|*pw.txt|*secret*|*.asc) return 0 ;;
  esac
  return 1
}
# A minisign secret key starts with this exact comment, even if the file name is harmless.
minisign_secret() {
  [ -f "$1" ] || return 1
  local first=""
  IFS= read -r -n 200 first < "$1" || true
  [ "$first" = "untrusted comment: minisign encrypted secret key" ]
}
refuse_secret() {
  local path="$1" what="$2"
  secretish "$path" && die "refusing a secret-looking file as a $what: $path"
  minisign_secret "$path" && die "refusing a minisign secret key as a $what: $path"
}
pubkey="$here/../keys/sigil-release.pub"
dest=""; spec="$here/../docs/sigil-v1.txt"; bins=(); archives=(); dry=0; force=0; check=0
minisig=""
while [ $# -gt 0 ]; do
  case "$1" in
    --dest) [ $# -ge 2 ] || usage; dest="$2"; shift 2 ;;
    --bin) [ $# -ge 2 ] || usage; bins+=("$2"); shift 2 ;;
    --spec) [ $# -ge 2 ] || usage; spec="$2"; shift 2 ;;
    --minisig) [ $# -ge 2 ] || usage; minisig="$2"; shift 2 ;;
    --dry-run) dry=1; shift ;;
    --check) check=1; shift ;;
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
  if [ -f "$a" ]; then
    minisign_secret "$a" && die "refusing a minisign secret key as an archive: $a"
  fi
done
if [ ${#bins[@]} -eq 0 ]; then
  b="$(command -v "$SIGIL" 2>/dev/null)" || die "sigil not found (set SIGIL= or pass --bin)"
  bins=("$b")
  default_name="sigil-$(uname -s | tr 'A-Z' 'a-z')-$(uname -m)"
fi
for b in "${bins[@]}"; do
  [ -f "$b" ] || die "binary not found: $b"
  refuse_secret "$b" "binary"
done
[ -f "$spec" ] || die "spec not found: $spec (pass --spec)"
refuse_secret "$spec" "spec"
[ -f "$pubkey" ] || die "release public key not found: $pubkey"
if minisign_secret "$pubkey"; then
  die "refusing a minisign secret key as the release public key: $pubkey"
fi
# Public key file must be the two-line minisign format (comment + base64 key).
pk_first=""; pk_second=""; pk_third=""
{ IFS= read -r pk_first; IFS= read -r pk_second; IFS= read -r pk_third || true; } < "$pubkey"
case "$pk_first" in
  "untrusted comment: minisign public key "*) ;;
  *) die "release public key is not a minisign public key file: $pubkey" ;;
esac
[ -n "$pk_second" ] || die "release public key is missing the key line: $pubkey"
[ -z "$pk_third" ] || die "release public key must be exactly two lines: $pubkey"
[ -n "$dest" ] || dest="$(dirname "${archives[0]}")"
[ -d "$dest" ] || die "destination folder not found: $dest"

# Resolve an optional release SHA256SUMS.minisig. Never pick one out of an existing kit.
if [ -n "$minisig" ]; then
  [ -f "$minisig" ] || die "signature not found: $minisig"
  refuse_secret "$minisig" "signature"
else
  cand=""
  if [ -f "$dest/SHA256SUMS.minisig" ]; then cand="$dest/SHA256SUMS.minisig"; fi
  first_dir="$(cd "$(dirname "${archives[0]}")" && pwd)"
  if [ -z "$cand" ] && [ -f "$first_dir/SHA256SUMS.minisig" ]; then
    cand="$first_dir/SHA256SUMS.minisig"
  fi
  if [ -n "$cand" ]; then
    # Skip if that path is inside a sigil-recovery folder (an old kit's copy).
    case "$(cd "$(dirname "$cand")" && pwd)" in
      */sigil-recovery) cand="" ;;
    esac
  fi
  if [ -n "$cand" ]; then
    refuse_secret "$cand" "signature"
    minisig="$cand"
  fi
fi

kit="$dest/sigil-recovery"
if [ -e "$kit" ] && [ $force -eq 0 ]; then die "$kit exists (use --force to replace)"; fi
if command -v sha256sum >/dev/null; then sha() { sha256sum "$@"; }
elif command -v shasum >/dev/null; then sha() { shasum -a 256 "$@"; }
else die "need sha256sum or shasum" 3; fi
version="$("${bins[0]}" --version 2>/dev/null | head -1)"; [ -n "$version" ] || version="sigil (version unknown)"

if [ $check -eq 1 ]; then
  for a in "${archives[@]}"; do
    if [ -d "$a" ]; then out="$("${bins[0]}" log verify "$a" 2>&1)"; rc=$?
    else out="$("${bins[0]}" scry "$a" 2>&1)"; rc=$?; fi
    # log verify: 1 = warnings only (still readable); anything else non-zero is damage
    if [ $rc -ne 0 ] && { [ ! -d "$a" ] || [ $rc -ne 1 ]; }; then
      printf '%s\n' "$out" >&2
      die "check failed for $a (exit $rc): repair it first (sigil mend / sigil log mend), then make the kit"
    fi
    echo "checked: $a"
  done
fi

names=()
for b in "${bins[@]}"; do
  if [ -n "${default_name:-}" ]; then names+=("$default_name"); else names+=("$(basename "$b")"); fi
done
if [ $dry -eq 1 ]; then
  echo "would write $kit/"
  echo "  RECOVER.txt"; echo "  SHA256SUMS"; echo "  ARCHIVES.sha256"
  echo "  SIGNING-KEY.pub"; echo "  spec/sigil-v1.txt"
  [ -n "$minisig" ] && echo "  SHA256SUMS.minisig"
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
cp "$pubkey" "$tmp/SIGNING-KEY.pub" || die "copy signing public key failed" 3
chmod 644 "$tmp/SIGNING-KEY.pub" || true
if [ -n "$minisig" ]; then
  cp "$minisig" "$tmp/SHA256SUMS.minisig" || die "copy $minisig failed" 3
  chmod 644 "$tmp/SHA256SUMS.minisig" || true
fi

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
: > "$tmp/ARCHIVES.sha256" || die "write ARCHIVES.sha256 failed" 3
for a in "${archives[@]}"; do
  (cd "$(dirname "$a")" && b="$(basename "$a")" &&
    if [ -d "$b" ]; then find "$b" -type f ! -name '*.part' ! -name '*.tmp*' | LC_ALL=C sort |
      while IFS= read -r f; do sha "$f"; done
    else sha "$b"; fi) >> "$tmp/ARCHIVES.sha256" || die "hashing $a failed" 3
done
# Kit SHA256SUMS covers the folder's own files (including SIGNING-KEY.pub). It does not
# include SHA256SUMS itself or a release SHA256SUMS.minisig (that signature is of the
# official release checksums, not of this list).
(cd "$tmp" && sha RECOVER.txt ARCHIVES.sha256 SIGNING-KEY.pub spec/sigil-v1.txt bin/* > SHA256SUMS) || die "checksums failed" 3

rm -rf "$kit" && mv "$tmp" "$kit" || die "cannot move kit into $kit" 3
trap - EXIT
extra=""
[ -n "$minisig" ] && extra=", SHA256SUMS.minisig"
echo "recovery kit: $kit (${#names[@]} binary, spec, SIGNING-KEY.pub, RECOVER.txt, SHA256SUMS, ARCHIVES.sha256${extra})"
echo "copy it next to the archives; check with: (cd $kit && sha256sum -c SHA256SUMS)"
echo "compare SIGNING-KEY.pub with the README and a paper copy before trusting it"
