#!/bin/sh

set -eu

: "${ASTERINAS_REPO:?set ASTERINAS_REPO to the Asterinas checkout}"
: "${SYSSEC_WORK_ROOT:?set SYSSEC_WORK_ROOT outside the source checkout}"

base=${1:-origin/main}
script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
project_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)

set -- config-check \
    --asterinas "$ASTERINAS_REPO" \
    --work-root "$SYSSEC_WORK_ROOT"
if [ -n "${SYSSEC_SPECULA_PROFILE:-}" ]; then
    set -- "$@" --specula-profile "$SYSSEC_SPECULA_PROFILE"
fi

PYTHONPATH="$project_root/src" python3 -m aster_syssec "$@"

set -- inventory \
    --asterinas "$ASTERINAS_REPO" \
    --work-root "$SYSSEC_WORK_ROOT" \
    --check
if [ -n "${SYSSEC_BASELINE_CATALOG:-}" ]; then
    set -- "$@" --baseline "$SYSSEC_BASELINE_CATALOG"
fi

PYTHONPATH="$project_root/src" python3 -m aster_syssec "$@"

set -- review \
    --asterinas "$ASTERINAS_REPO" \
    --work-root "$SYSSEC_WORK_ROOT" \
    --changed-from "$base"
if [ "${SYSSEC_FAIL_ON_CANDIDATES:-0}" = 1 ]; then
    set -- "$@" --fail-on-candidates
fi

PYTHONPATH="$project_root/src" python3 -m aster_syssec "$@"
