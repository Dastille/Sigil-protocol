#!/bin/sh
# Copy sigil into the initramfs so live-premount can Scry/De-scribe before pivot.

PREREQ=""
prereqs() { echo "$PREREQ"; }
case $1 in
prereqs) prereqs; exit 0 ;;
esac

. /usr/share/initramfs-tools/hook-functions

for p in /usr/local/bin/sigil /usr/bin/sigil /bin/sigil; do
    if [ -x "$p" ]; then
        copy_exec "$p" /bin
        break
    fi
done
