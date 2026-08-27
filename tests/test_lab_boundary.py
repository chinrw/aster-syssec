from __future__ import annotations

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path

from aster_syssec_lab.cli import main

PROJECT_ROOT = Path(__file__).resolve().parents[1]


def authorization() -> dict[str, object]:
    return {
        "schema_version": 1,
        "authorization_id": "LAB-AUTH-0123456789ABCDEF",
        "repository": "asterinas/asterinas",
        "revision": "1" * 40,
        "authorization": "owned defensive test environment",
        "allowed_scope": ["specified syscall family", "isolated local VM"],
        "excluded": [
            "external targets",
            "network propagation",
            "persistence",
            "credential theft",
            "production deployment",
        ],
        "approved_by": "Test Owner",
        "approved_at": "2099-01-01T00:00:00Z",
        "expires_at": "2099-01-02T00:00:00Z",
        "execution": {
            "environment": "isolated-vm",
            "network": "off",
            "agent_mode": "manual-only",
        },
    }


class LabBoundaryTests(unittest.TestCase):
    def test_boundary_reports_that_case_execution_is_unavailable(self) -> None:
        output = io.StringIO()
        with contextlib.redirect_stdout(output):
            status = main(["boundary", "--json"])

        result = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(result["safety_class"], "lab")
        self.assertFalse(result["execution_available"])
        self.assertTrue(result["authorization_required"])
        self.assertEqual(result["network"], "off")

    def test_authorization_check_validates_without_executing(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            path = Path(tmp) / "authorization.json"
            path.write_text(json.dumps(authorization()), encoding="utf-8")
            output = io.StringIO()
            with contextlib.redirect_stdout(output):
                status = main(["authorization", "check", "--file", str(path), "--json"])

        result = json.loads(output.getvalue())
        self.assertEqual(status, 0)
        self.assertEqual(result["status"], "valid")
        self.assertFalse(result["executed"])

    def test_authorization_cannot_enable_network_access(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            value = authorization()
            execution = value["execution"]
            assert isinstance(execution, dict)
            execution["network"] = "on"
            path = Path(tmp) / "authorization.json"
            path.write_text(json.dumps(value), encoding="utf-8")
            stderr = io.StringIO()
            with contextlib.redirect_stderr(stderr):
                status = main(["authorization", "check", "--file", str(path), "--json"])

        self.assertEqual(status, 2)
        self.assertIn("'off' was expected", stderr.getvalue())

    def test_lab_workflow_has_no_automatic_trigger(self) -> None:
        workflow = (PROJECT_ROOT / ".github/workflows/lab.yml").read_text(
            encoding="utf-8"
        )
        triggers = workflow.split("permissions:", 1)[0]

        self.assertIn("workflow_dispatch:", triggers)
        self.assertNotIn("pull_request:", triggers)
        self.assertNotIn("push:", triggers)
        self.assertNotIn("schedule:", triggers)

    def test_core_package_never_imports_the_lab_package(self) -> None:
        core = PROJECT_ROOT / "src/aster_syssec"
        imports = [
            path
            for path in core.rglob("*.py")
            if "aster_syssec_lab" in path.read_text(encoding="utf-8")
        ]

        self.assertEqual(imports, [])


if __name__ == "__main__":
    unittest.main()
