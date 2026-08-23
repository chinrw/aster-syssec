#!/bin/sh

set -eu

: "${ASTERINAS_PINNED_SOURCE:?enter through the Nix development shell}"
: "${SYSSEC_WORK_ROOT:?set an evidence directory outside the Asterinas source}"

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
project_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)

PYTHONPATH="$project_root/src" python3 -m aster_syssec config-check \
    --asterinas "$ASTERINAS_PINNED_SOURCE" \
    --work-root "$SYSSEC_WORK_ROOT"

PYTHONPATH="$project_root/src" python3 -m aster_syssec inventory \
    --asterinas "$ASTERINAS_PINNED_SOURCE" \
    --work-root "$SYSSEC_WORK_ROOT" \
    --check
