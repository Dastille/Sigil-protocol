#!/bin/bash
# dracut module: put sigil in the initramfs and mend before sysroot mount.

check() {
    require_binaries sigil || return 1
    return 0
}

depends() {
    return 0
}

install() {
    inst_multiple sigil mkdir mount umount
    inst_hook pre-mount 90 "$moddir/mend.sh"
}
