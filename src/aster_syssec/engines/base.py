from __future__ import annotations

import os
from dataclasses import dataclass
from pathlib import Path

from ..runs import RunContext
from ..source import require_disjoint_paths


@dataclass(frozen=True)
class EngineContext:
    source_root: Path
    work_root: Path
    run: RunContext


def resolve_cache_root(context: EngineContext) -> Path:
    configured = os.environ.get("SYSSEC_CACHE_ROOT")
    root = (
        Path(configured).expanduser().resolve()
        if configured
        else (context.work_root / "cache").resolve()
    )
    require_disjoint_paths(context.source_root, root)
    return root
