from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from ..runs import RunContext


@dataclass(frozen=True)
class EngineContext:
    source_root: Path
    work_root: Path
    run: RunContext
