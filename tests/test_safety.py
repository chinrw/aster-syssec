from __future__ import annotations

import unittest

from aster_syssec.safety import (
    SafetyClass,
    SafetyPolicy,
    require_core_execution,
    require_profile_target_safety,
)


def policy(safety_class: str) -> SafetyPolicy:
    values = {
        "core": {
            "class": "core",
            "agent_mode": "allowed",
            "network": False,
            "may_generate_reproducer": False,
            "requires_authorization": False,
        },
        "model": {
            "class": "model",
            "agent_mode": "analysis-only",
            "network": True,
            "may_generate_reproducer": False,
            "requires_authorization": False,
        },
        "lab": {
            "class": "lab",
            "agent_mode": "manual-only",
            "network": False,
            "may_generate_reproducer": True,
            "requires_authorization": True,
        },
    }
    return SafetyPolicy.from_mapping(values[safety_class])


class SafetyPolicyTests(unittest.TestCase):
    def test_core_policy_is_the_only_main_execution_class(self) -> None:
        core = policy("core")

        self.assertEqual(core.safety_class, SafetyClass.CORE)
        require_core_execution(core, operation="run-target")

    def test_model_policy_requires_the_explicit_model_entrypoint(self) -> None:
        with self.assertRaisesRegex(ValueError, "explicit model entrypoint"):
            require_core_execution(policy("model"), operation="run-target")

    def test_lab_policy_cannot_execute_through_the_main_package(self) -> None:
        with self.assertRaisesRegex(ValueError, "does not execute lab targets"):
            require_core_execution(policy("lab"), operation="run-target")

    def test_policy_combinations_fail_closed(self) -> None:
        with self.assertRaisesRegex(ValueError, "safety-policy.schema.json"):
            SafetyPolicy.from_mapping(
                {
                    "class": "core",
                    "agent_mode": "manual-only",
                    "network": False,
                    "may_generate_reproducer": True,
                    "requires_authorization": True,
                }
            )

    def test_profile_cannot_select_a_target_from_another_safety_class(self) -> None:
        with self.assertRaisesRegex(ValueError, "profile safety class core"):
            require_profile_target_safety(
                profile_class=SafetyClass.CORE,
                target_id="model-target",
                target_policy=policy("model"),
            )


if __name__ == "__main__":
    unittest.main()
