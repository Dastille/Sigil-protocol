#!/bin/sh
# After the live medium is mounted: Scry the mark, mend the squashfs if chewed, then continue.

PREREQ=""
prereqs() { echo "$PREREQ"; }
case $1 in
prereqs) prereqs; exit 0 ;;
esac

if [ -f /scripts/functions ]; then
    . /scripts/functions
fi

sigil_fail() {
    msg=$1
    echo "Sigil: $msg" >&2
    if command -v panic >/dev/null 2>&1; then
        panic "Sigil: $msg"
    fi
    exec /bin/sh
}

find_sigil() {
    if command -v sigil >/dev/null 2>&1; then
        command -v sigil
        return 0
    fi
    for p in /bin/sigil /usr/bin/sigil /usr/local/bin/sigil \
        /lib/live/mount/medium/live/sigil \
        /lib/live/mount/medium/casper/sigil \
        /run/live/medium/live/sigil \
        /run/live/medium/casper/sigil \
        /run/initramfs/live/live/sigil \
        /run/initramfs/live/casper/sigil \
        /cdrom/live/sigil /cdrom/casper/sigil; do
        if [ -x "$p" ]; then
            echo "$p"
            return 0
        fi
    done
    if [ -n "$SIGIL_MEDIUM" ]; then
        for p in "$SIGIL_MEDIUM/live/sigil" "$SIGIL_MEDIUM/casper/sigil" "$SIGIL_MEDIUM/sigil"; do
            if [ -x "$p" ]; then
                echo "$p"
                return 0
            fi
        done
    fi
    return 1
}

SIGIL=$(find_sigil) || exit 0

stage=/run/sigil
mkdir -p "$stage"

found=
for d in /lib/live/mount/medium /run/live/medium /run/initramfs/live /cdrom "$SIGIL_MEDIUM"; do
    [ -n "$d" ] || continue
    [ -d "$d" ] || continue
    if ls "$d"/live/*.sg1 "$d"/casper/*.sg1 "$d"/*.sg1 >/dev/null 2>&1; then
        found=$d
        break
    fi
done

if [ -z "$found" ]; then
    "$SIGIL" boot mend --scan --stage "$stage"
    st=$?
else
    "$SIGIL" boot mend "$found" --stage "$stage"
    st=$?
fi

case $st in
    0) exit 0 ;;
    3) exit 0 ;; # no mark on this medium — not a Sigil stick
    2) sigil_fail "mark is too damaged to boot. Sigil will not guess." ;;
    *) sigil_fail "could not mend the image (exit $st). Check Ward / Attest." ;;
esac
