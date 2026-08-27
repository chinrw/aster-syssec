#!/bin/sh

set -eu

: "${SYSSEC_ASTERINAS_DEV_IMAGE:?set an immutable Asterinas dev image}"
: "${SYSSEC_CARGO_OSDK_HOST:?set the host path to pinned cargo-osdk}"
: "${SYSSEC_ASTERINAS_CARGO_VENDOR:?set the pinned Asterinas Cargo vendor}"
: "${CARGO_TARGET_DIR:?the Runtime adapter must isolate Cargo output}"
: "${TMPDIR:?the Runtime adapter must isolate temporary output}"
: "${CARGO_NET_OFFLINE:?the Runtime adapter must disable Cargo networking}"
: "${QEMU_HOSTFWD:?the Runtime adapter must disable host forwarding}"
: "${RUSTUP_TOOLCHAIN:?the Runtime adapter must pin the Rust toolchain}"

image_digest=${SYSSEC_ASTERINAS_DEV_IMAGE##*@sha256:}
case "$SYSSEC_ASTERINAS_DEV_IMAGE" in
    *@sha256:*) ;;
    *) echo "Asterinas dev image must use an immutable sha256 digest" >&2; exit 2 ;;
esac
case "$image_digest" in
    *[!0-9a-f]*) echo "Asterinas dev image has an invalid sha256 digest" >&2; exit 2 ;;
esac
if [ "${#image_digest}" -ne 64 ]; then
    echo "Asterinas dev image has an invalid sha256 digest" >&2
    exit 2
fi
if [ "$CARGO_NET_OFFLINE" != true ] || [ "$QEMU_HOSTFWD" != off ]; then
    echo "Runtime container requires offline Cargo and disabled host forwarding" >&2
    exit 2
fi
if [ -L "$SYSSEC_CARGO_OSDK_HOST" ] || [ ! -f "$SYSSEC_CARGO_OSDK_HOST" ] || [ ! -x "$SYSSEC_CARGO_OSDK_HOST" ]; then
    echo "pinned cargo-osdk must be a regular executable" >&2
    exit 2
fi
case "$SYSSEC_ASTERINAS_CARGO_VENDOR" in
    /nix/store/*-asterinas-cargo-vendor-*-vendor) ;;
    *) echo "Asterinas Cargo vendor must be a pinned Nix store path" >&2; exit 2 ;;
esac
if [ ! -f "$SYSSEC_ASTERINAS_CARGO_VENDOR/.cargo/config.toml" ]; then
    echo "Asterinas Cargo vendor lacks its source replacement config" >&2
    exit 2
fi

interpreter=$(readelf -l "$SYSSEC_CARGO_OSDK_HOST" | sed -n 's/.*Requesting program interpreter: \([^]]*\)].*/\1/p')
case "$interpreter" in
    /nix/store/*-glibc-*/lib/ld-linux-x86-64.so.2) ;;
    *) echo "pinned cargo-osdk has an unexpected ELF interpreter" >&2; exit 2 ;;
esac
glibc_root=${interpreter%/lib/ld-linux-x86-64.so.2}

runpath=$(readelf -d "$SYSSEC_CARGO_OSDK_HOST" | sed -n 's/.*Library runpath: \[\(.*\)\].*/\1/p')
gcc_lib_root=
remaining=$runpath
while [ -n "$remaining" ]; do
    case "$remaining" in
        *:*) directory=${remaining%%:*}; remaining=${remaining#*:} ;;
        *) directory=$remaining; remaining= ;;
    esac
    case "$directory" in
        /nix/store/*-gcc-*-lib/lib) gcc_lib_root=${directory%/lib} ;;
    esac
done
if [ -z "$gcc_lib_root" ] || [ ! -d "$gcc_lib_root" ]; then
    echo "pinned cargo-osdk lacks its Nix gcc-lib runpath" >&2
    exit 2
fi
libgcc_binary=$(readlink -f "$gcc_lib_root/lib/libgcc_s.so.1")
libgcc_root=${libgcc_binary%/lib/libgcc_s.so.1}
case "$libgcc_root" in
    /nix/store/*-gcc-*-libgcc) ;;
    *) echo "pinned cargo-osdk has an unexpected libgcc target" >&2; exit 2 ;;
esac

checkout=$(pwd -P)
stage_root=$(dirname -- "$checkout")
if [ "$(basename -- "$checkout")" != checkout ]; then
    echo "Runtime make wrapper must run from the adapter checkout" >&2
    exit 2
fi
case "$CARGO_TARGET_DIR" in
    "$stage_root"/*) ;;
    *) echo "Cargo target directory escapes the Runtime stage" >&2; exit 2 ;;
esac
case "$TMPDIR" in
    "$stage_root"/*) ;;
    *) echo "temporary directory escapes the Runtime stage" >&2; exit 2 ;;
esac

cargo_home="$stage_root/cargo-home"
mkdir -p "$cargo_home"
sed 's|@vendor@|/opt/syssec/vendor|g' \
    "$SYSSEC_ASTERINAS_CARGO_VENDOR/.cargo/config.toml" \
    > "$cargo_home/config.toml"

exec docker run --rm --network=none --platform=linux/amd64 \
    --mount "type=bind,src=$stage_root,dst=$stage_root" \
    --mount "type=bind,src=$SYSSEC_CARGO_OSDK_HOST,dst=/root/.cargo/bin/cargo-osdk,readonly" \
    --mount "type=bind,src=$glibc_root,dst=$glibc_root,readonly" \
    --mount "type=bind,src=$gcc_lib_root,dst=$gcc_lib_root,readonly" \
    --mount "type=bind,src=$libgcc_root,dst=$libgcc_root,readonly" \
    --mount "type=bind,src=$SYSSEC_ASTERINAS_CARGO_VENDOR,dst=/opt/syssec/vendor,readonly" \
    --workdir "$checkout" \
    --env "CARGO_HOME=$cargo_home" \
    --env CARGO_NET_OFFLINE \
    --env CARGO_TARGET_DIR \
    --env TMPDIR \
    --env QEMU_HOSTFWD \
    --env RUSTUP_SKIP_UPDATE_CHECK \
    --env RUSTUP_TOOLCHAIN \
    --env "OSDK_SOURCE_ROOT=$checkout" \
    "$SYSSEC_ASTERINAS_DEV_IMAGE" \
    make "$@"
