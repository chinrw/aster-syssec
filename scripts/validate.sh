#!/bin/sh

set -eu

script_dir=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
project_root=$(CDPATH='' cd -- "$script_dir/.." && pwd)

cd "$project_root"
PYTHONPATH=src python3 -m unittest discover -v
PYTHONPATH=src python3 -m compileall -q src tests
sh -n scripts/ci-integration.sh scripts/ci-pr.sh scripts/validate.sh
if command -v ruff >/dev/null 2>&1; then
    ruff check src tests
    ruff format --check src tests
fi
if command -v pyright >/dev/null 2>&1; then
    pyright src tests
fi
if command -v shellcheck >/dev/null 2>&1; then
    shellcheck scripts/*.sh
fi
if command -v actionlint >/dev/null 2>&1; then
    actionlint .github/workflows/*.yml
fi

if [ "$#" -gt 0 ]; then
    PYTHONPATH=src python3 -m aster_syssec inventory \
        --asterinas "$1" \
        --work-root "${SYSSEC_WORK_ROOT:?set SYSSEC_WORK_ROOT for live validation}" \
        --check
fi
