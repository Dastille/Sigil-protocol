#!/usr/bin/env bash
# Write SHA256SUMS for release artefacts (RELEASE-SIGNING-DESIGN.md §6 step 1).
#
#   scripts/make-sha256sums.sh DIR
#
# Hashes every regular file directly in DIR (sorted, basenames only) into DIR/SHA256SUMS.
# Skips SHA256SUMS itself and any *.minisig. No key is used: this catches accidental damage
# only. Signing SHA256SUMS (minisign) is a separate, manual, offline step by the key holder.
# Exit: 0 written, 2 bad input, 3 could not write.
set -u
die() { echo "make-sha256sums: $*" >&2; exit "${2:-2}"; }
[ $# -eq 1 ] || die "usage: make-sha256sums.sh DIR"
dir="$1"; [ -d "$dir" ] || die "not a folder: $dir"
if command -v sha256sum >/dev/null; then sha() { sha256sum "$@"; }
elif command -v shasum >/dev/null; then sha() { shasum -a 256 "$@"; }
else die "need sha256sum or shasum" 3; fi
cd "$dir" || die "cannot enter $dir" 3
files=()
while IFS= read -r f; do files+=("$f"); done < <(
  find . -maxdepth 1 -type f ! -name SHA256SUMS ! -name '*.minisig' ! -name '.*' \
    | sed 's|^\./||' | LC_ALL=C sort)
[ ${#files[@]} -ge 1 ] || die "no files to hash in $dir"
sha "${files[@]}" > SHA256SUMS.tmp.$$ && mv SHA256SUMS.tmp.$$ SHA256SUMS || {
  rm -f SHA256SUMS.tmp.$$; die "write SHA256SUMS failed" 3; }
sha -c SHA256SUMS >/dev/null || die "self-check of SHA256SUMS failed" 3
echo "SHA256SUMS: ${#files[@]} files in $dir"
