#!/usr/bin/env bash
# Monthly retention check for a sigil segment log: health (`sigil log verify`) + a compaction
# PLAN (`sigil log compact` without --apply). Read-only unless --apply is given.
#
#   scripts/monthly-log-retention.sh LOG [--pass-file F] [--identity K.sgk] [--signer KEY]
#                                        [--keep-last N] [--older-than 30d] [--quick] [--strict]
#                                        [--apply --seal-pass-file F | --to K.pub]
#
# --apply: only when the health check passed (no problems; no warnings with --strict) and the
#       plan worked, run `sigil log compact --apply` with the same rule, then verify again.
#       Needs a rule (--older-than / --keep-last / --range) so fresh batches are never merged.
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
keys=(); verify_only=(); compact_only=(); seal=(); strict=0; apply=0
while [ $# -gt 0 ]; do
  case "$1" in
    --pass-file|--identity) [ $# -ge 2 ] || usage; keys+=("$1" "$2"); shift 2 ;;
    --signer) [ $# -ge 2 ] || usage; verify_only+=("$1" "$2"); shift 2 ;;
    --quick) verify_only+=("$1"); shift ;;
    --keep-last|--older-than|--range) [ $# -ge 2 ] || usage; compact_only+=("$1" "$2"); shift 2 ;;
    --strict) strict=1; shift ;;
    --apply) apply=1; shift ;;
    --seal-pass-file|--to) [ $# -ge 2 ] || usage; seal+=("$1" "$2"); shift 2 ;;
    --pass|--seal-pass) echo "$1 is not accepted here; use a file (--pass-file / --seal-pass-file)" >&2; exit 3 ;;
    -h|--help) usage ;;
    *) echo "unknown option: $1" >&2; usage ;;
  esac
done
if [ $apply -eq 1 ] && [ ${#compact_only[@]} -eq 0 ]; then
  echo "--apply needs a rule (--older-than / --keep-last / --range)" >&2; exit 3
fi
if [ $apply -eq 0 ] && [ ${#seal[@]} -gt 0 ]; then echo "--seal-pass-file / --to need --apply" >&2; exit 3; fi
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
applied="no (dry run)"; arc=0; v2=0
if [ $apply -eq 1 ]; then
  if [ $vrc -ge 2 ] || [ $crc -ne 0 ] || { [ $vrc -eq 1 ] && [ $strict -eq 1 ]; }; then
    applied="SKIPPED (health or plan not ok)"
  else
    echo "== 3/3 apply: sigil log compact --apply, then verify again"
    "$SIGIL" log compact "$LOG" --apply ${keys[@]+"${keys[@]}"} ${compact_only[@]+"${compact_only[@]}"} ${seal[@]+"${seal[@]}"}
    arc=$?
    if [ $arc -eq 0 ]; then
      "$SIGIL" log verify "$LOG" ${keys[@]+"${keys[@]}"} ${verify_only[@]+"${verify_only[@]}"}
      v2=$?
      applied="yes"; [ $v2 -ge 2 ] && applied="yes, but verify after it found PROBLEMS"
    else
      applied="FAILED (exit $arc)"
    fi
    echo
  fi
fi
if [ $apply -eq 1 ]; then
  echo "== summary: health=$health  compaction-plan=$plan  applied=$applied"
else
  echo "== summary: health=$health  compaction-plan=$plan  (apply with: sigil log compact $LOG --apply …)"
fi
if [ $vrc -ge 2 ]; then [ $vrc -eq 2 ] && exit 2; exit 3; fi
[ $crc -eq 0 ] || exit 3
[ $arc -eq 0 ] || exit 3
[ $v2 -ge 2 ] && exit 2
if [ $vrc -eq 1 ] && [ $strict -eq 1 ]; then exit 1; fi
exit 0
