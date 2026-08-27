from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from enum import Enum
from typing import Any

from .schemas import validate_instance


class SafetyClass(str, Enum):
    CORE = "core"
    MODEL = "model"
    LAB = "lab"


@dataclass(frozen=True)
class SafetyPolicy:
    safety_class: SafetyClass
    agent_mode: str
    network: bool
    may_generate_reproducer: bool
    requires_authorization: bool

    @classmethod
    def from_mapping(cls, value: Mapping[str, Any]) -> SafetyPolicy:
        item = dict(value)
        validate_instance(item, "safety-policy.schema.json")
        return cls(
            safety_class=SafetyClass(item["class"]),
            agent_mode=item["agent_mode"],
            network=item["network"],
            may_generate_reproducer=item["may_generate_reproducer"],
            requires_authorization=item["requires_authorization"],
        )

    def summary(self) -> dict[str, object]:
        return {
            "class": self.safety_class.value,
            "agent_mode": self.agent_mode,
            "network": self.network,
            "may_generate_reproducer": self.may_generate_reproducer,
            "requires_authorization": self.requires_authorization,
        }


def require_core_execution(policy: SafetyPolicy, *, operation: str) -> None:
    require_core_class(policy.safety_class, operation=operation)


def require_core_class(safety_class: SafetyClass, *, operation: str) -> None:
    if safety_class is SafetyClass.CORE:
        return
    if safety_class is SafetyClass.MODEL:
        raise ValueError(
            f"{operation} only executes core targets; use the explicit model entrypoint"
        )
    raise ValueError(
        f"{operation} does not execute lab targets; use the separately gated syssec-lab package"
    )


def require_profile_target_safety(
    *,
    profile_class: SafetyClass,
    target_id: str,
    target_policy: SafetyPolicy,
) -> None:
    if target_policy.safety_class is profile_class:
        return
    raise ValueError(
        f"profile safety class {profile_class.value} cannot select target "
        f"{target_id} with safety class {target_policy.safety_class.value}"
    )
