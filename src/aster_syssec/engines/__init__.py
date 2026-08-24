from __future__ import annotations

from ..engine_results import EngineExecution
from ..targets import VerificationTarget
from .base import EngineContext
from .fuzz import doctor_fuzz, execute_fuzz
from .kani import doctor_kani, execute_kani
from .layout import doctor_layout, execute_layout
from .loom import doctor_loom, execute_loom
from .miri import doctor_miri, execute_miri


def execute_target(
    target: VerificationTarget, context: EngineContext
) -> EngineExecution:
    if target.engine == "kani":
        return execute_kani(target, context)
    if target.engine == "miri":
        return execute_miri(target, context)
    if target.engine == "layout":
        return execute_layout(target, context)
    if target.engine == "fuzz":
        return execute_fuzz(target, context)
    if target.engine == "loom":
        return execute_loom(target, context)
    raise ValueError(f"verification engine adapter is not implemented: {target.engine}")


def doctor_engine(engine: str) -> dict[str, str | None]:
    if engine == "kani":
        return doctor_kani()
    if engine == "miri":
        return doctor_miri()
    if engine == "layout":
        return doctor_layout()
    if engine == "fuzz":
        return doctor_fuzz()
    if engine == "loom":
        return doctor_loom()
    return {
        "engine": engine,
        "adapter": "not-implemented",
        "status": "unavailable",
        "executable": None,
        "version": None,
    }


__all__ = ["EngineContext", "doctor_engine", "execute_target"]
