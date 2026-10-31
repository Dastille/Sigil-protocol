#!/usr/bin/env bash
# Monthly retention check for a sigil segment log: health (`sigil log verify`) + a compaction
# PLAN (`sigil log compact` without --apply). Read-only: it never changes the log.
#
#   scripts/monthly-log-retention.sh LOG [--pass-file F] [--identity K.sgk] [--signer KEY]
#                                        [--keep-last N] [--older-than 30d] [--quick] [--strict]
#
# Exit: 0 healthy (warnings allowed unless --strict), 1 warnings with --strict,
#       2 problems found by verify, 3 could not run (bad arguments, missing sigil, compact error).
# Env:  SIGIL=path/to/sigil (default: `sigil` on PATH).
# Cron (1st of the month, 06:00; mail the output):
#   0 6 1 * *  /path/to/monthly-log-retention.sh ~/logs/photos --pass-file ~/.sigil/pw --older-than 30d
set -u
SIGIL="${SIGIL:-sigil}"
usage() { sed -n '2,13p' "$0" | sed 's/^# \{0,1\}//' >&2; exit 3; }
[ $# -ge 1 ] || usage
LOG="$1"; shift
keys=(); verify_only=(); compact_only=(); strict=0
while [ $# -gt 0 ]; do
  case "$1" in
    --pass-file|--identity) [ $# -ge 2 ] || usage; keys+=("$1" "$2"); shift 2 ;;
    --signer) [ $# -ge 2 ] || usage; verify_only+=("$1" "$2"); shift 2 ;;
    --quick) verify_only+=("$1"); shift ;;
    --keep-last|--older-than|--range) [ $# -ge 2 ] || usage; compact_only+=("$1" "$2"); shift 2 ;;
    --strict) strict=1; shift ;;
    -h|--help) usage ;;
    *) echo "unknown option: $1" >&2; usage ;;
  esac
done
command -v "$SIGIL" >/dev/null 2>&1 || [ -x "$SIGIL" ] || { echo "sigil not found (set SIGIL=)" >&2; exit 3; }

echo "== sigil monthly retention check: $LOG  ($(date -u +%Y-%m-%dT%H:%M:%SZ))"
echo
echo "== 1/2 health: sigil log verify"
"$SIGIL" log verify "$LOG" ${keys[@]+"${keys[@]}"} ${verify_only[@]+"${verify_only[@]}"}
vrc=$?
echo
echo "== 2/2 retention plan: sigil log compact (dry run, nothing is changed)"
"$SIGIL" log compact "$LOG" ${keys[@]+"${keys[@]}"} ${compact_only[@]+"${compact_only[@]}"}
crc=$?
echo
case $vrc in
  0) health="healthy" ;;
  1) health="warnings" ;;
  2) health="PROBLEMS" ;;
  *) health="could not check (exit $vrc)" ;;
esac
plan="ok"; [ $crc -eq 0 ] || plan="FAILED (exit $crc)"
echo "== summary: health=$health  compaction-plan=$plan  (apply with: sigil log compact $LOG --apply …)"
if [ $vrc -ge 2 ]; then [ $vrc -eq 2 ] && exit 2; exit 3; fi
[ $crc -eq 0 ] || exit 3
if [ $vrc -eq 1 ] && [ $strict -eq 1 ]; then exit 1; fi
exit 0
