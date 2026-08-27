#!/bin/sh
# Fallback if live-boot is not in use: scan disks for a boot mark and mend.

PREREQ=""
prereqs() { echo "$PREREQ"; }
case $1 in
prereqs) prereqs; exit 0 ;;
esac

if [ -f /scripts/functions ]; then
    . /scripts/functions
fi

SIGIL=
if command -v sigil >/dev/null 2>&1; then
    SIGIL=$(command -v sigil)
elif [ -x /bin/sigil ]; then
    SIGIL=/bin/sigil
fi
[ -n "$SIGIL" ] || exit 0

mkdir -p /run/sigil
"$SIGIL" boot mend --scan --stage /run/sigil
st=$?
case $st in
    0|3) exit 0 ;;
    2)
        echo "Sigil: mark is too damaged to boot." >&2
        if command -v panic >/dev/null 2>&1; then panic "Sigil: too damaged"; fi
        exec /bin/sh
        ;;
    *)
        exit 0
        ;;
esac
