from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any

ENGINE_OUTCOMES = frozenset(
    {
        "pass",
        "counterexample",
        "mismatch",
        "incomplete",
        "unsupported",
        "timeout",
        "crash",
        "hang",
        "compile-error",
        "tool-error",
    }
)


@dataclass(frozen=True)
class EngineExecution:
    result: dict[str, Any]
    schema: str

    @property
    def outcome(self) -> str:
        return str(self.result["outcome"])

    @property
    def expectation_met(self) -> bool:
        return bool(self.result["expectation_met"])


def evidence_id(prefix: str, value: Any) -> str:
    payload = json.dumps(
        value, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    )
    digest = hashlib.sha256(payload.encode("utf-8")).hexdigest()[:16].upper()
    return f"{prefix}-{digest}"
