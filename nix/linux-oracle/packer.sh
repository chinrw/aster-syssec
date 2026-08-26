if [[ "$#" -eq 1 && "$1" == "--version" ]]; then
    printf '%s\n' 'syssec-initramfs-packer 1.0.0'
    exit 0
fi

if [[ "$#" -ne 6 \
    || "$1" != "--base-rootfs" \
    || "$3" != "--binary" \
    || "$5" != "--output" ]]; then
    printf '%s\n' \
        'usage: syssec-initramfs-packer --base-rootfs PATH --binary PATH --output PATH' \
        >&2
    exit 2
fi

base_rootfs="$2"
binary="$4"
output="$6"

if [[ -L "$base_rootfs" || ! -f "$base_rootfs" ]]; then
    printf 'base rootfs is not a regular file: %s\n' "$base_rootfs" >&2
    exit 2
fi
if [[ -L "$binary" || ! -f "$binary" || ! -x "$binary" ]]; then
    printf 'binary is not an executable regular file: %s\n' "$binary" >&2
    exit 2
fi
if [[ -e "$output" || -L "$output" ]]; then
    printf 'output already exists: %s\n' "$output" >&2
    exit 2
fi
if [[ ! -d "$(dirname -- "$output")" ]]; then
    printf 'output directory does not exist: %s\n' "$output" >&2
    exit 2
fi

pack_root=""
archive_tmp=""
cleanup() {
    if [[ -n "$pack_root" ]]; then
        chmod -R u+w "$pack_root" 2>/dev/null || true
        rm -rf -- "$pack_root"
    fi
    if [[ -n "$archive_tmp" ]]; then
        rm -f -- "$archive_tmp"
    fi
}
trap cleanup EXIT

pack_root="$(mktemp -d "${TMPDIR:-/tmp}/syssec-initramfs.XXXXXX")"
archive_tmp="$(mktemp "$(dirname -- "$output")/.syssec-initramfs.XXXXXX")"
gzip -dc -- "$base_rootfs" \
    | (
        cd "$pack_root"
        cpio --quiet \
            --extract \
            --make-directories \
            --no-absolute-filenames \
            --no-preserve-owner
    )

install -m 0755 -- "$binary" "$pack_root/syssec-case"
find "$pack_root" -exec touch -h -d @1 {} +
(
    cd "$pack_root"
    find . -print0 \
        | LC_ALL=C sort -z \
        | cpio --quiet --null --reproducible --owner=0:0 -o -H newc \
        | gzip -n -9 > "$archive_tmp"
)
chmod 0644 "$archive_tmp"
mv -- "$archive_tmp" "$output"
archive_tmp=""
