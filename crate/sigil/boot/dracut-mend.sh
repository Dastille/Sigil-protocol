#!/bin/sh
# dracut pre-mount: Scry + De-scribe the live squashfs if a boot mark is present.

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
if [ "$st" = 2 ]; then
    echo "Sigil: mark is too damaged to boot. Sigil will not guess."
    emergency_shell
fi
exit 0
