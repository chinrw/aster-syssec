#!/usr/bin/env bash
set -euo pipefail

packer="${SYSSEC_INITRAMFS_PACKER:?set SYSSEC_INITRAMFS_PACKER}"
work_root="$(mktemp -d)"
cleanup() {
    chmod -R u+w "$work_root" 2>/dev/null || true
    rm -rf -- "$work_root"
}
trap cleanup EXIT

mkdir -p "$work_root/base/bin" "$work_root/base/nix/store/fixture/bin"
printf '#!/bin/sh\nprintf "base init\\n"\n' > "$work_root/base/init"
chmod 0755 "$work_root/base/init"
printf 'busybox fixture\n' > "$work_root/base/bin/busybox"
chmod 0755 "$work_root/base/bin/busybox"
printf 'read-only closure fixture\n' \
    > "$work_root/base/nix/store/fixture/bin/tool"
chmod 0555 \
    "$work_root/base/nix/store" \
    "$work_root/base/nix/store/fixture" \
    "$work_root/base/nix/store/fixture/bin" \
    "$work_root/base/nix/store/fixture/bin/tool"

(
    cd "$work_root/base"
    find . -print0 \
        | sort -z \
        | cpio --quiet --null --reproducible --owner=0:0 -o -H newc \
        | gzip -n -9 > "$work_root/base.cpio.gz"
)

printf 'exact static binary fixture\n' > "$work_root/case"
chmod 0755 "$work_root/case"

"$packer" --version | grep -Fx 'syssec-initramfs-packer 1.0.0'
"$packer" \
    --base-rootfs "$work_root/base.cpio.gz" \
    --binary "$work_root/case" \
    --output "$work_root/derived-a.cpio.gz"
"$packer" \
    --base-rootfs "$work_root/base.cpio.gz" \
    --binary "$work_root/case" \
    --output "$work_root/derived-b.cpio.gz"

cmp "$work_root/derived-a.cpio.gz" "$work_root/derived-b.cpio.gz"
mkdir "$work_root/unpacked"
(
    cd "$work_root/unpacked"
    gzip -dc "$work_root/derived-a.cpio.gz" \
        | cpio --quiet --extract --make-directories --no-absolute-filenames
)
cmp "$work_root/base/init" "$work_root/unpacked/init"
cmp "$work_root/case" "$work_root/unpacked/syssec-case"
test -x "$work_root/unpacked/syssec-case"
