from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aster_syssec.config import load_registry
from aster_syssec.inventory import InventoryBuilder, compare_baseline
from tests.helpers import write_fixture


class InventoryTests(unittest.TestCase):
    def test_merges_arch_dispatch_and_reconciles_evidence(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = write_fixture(Path(tmp))
            catalog = InventoryBuilder(root, load_registry()).build()

        read = next(item for item in catalog.syscalls if item.name == "read")
        self.assertEqual(set(read.architectures), {"x86_64", "riscv64", "loongarch64"})
        self.assertEqual(read.architectures["x86_64"].number, 0)
        self.assertEqual(read.architectures["riscv64"].number, 63)
        self.assertEqual(read.handler_path, "kernel/core/src/syscall/read.rs")
        self.assertEqual(read.scml.status, "described")
        self.assertEqual(read.regression.status, "referenced")

        recvmsg = next(item for item in catalog.syscalls if item.name == "recvmsg")
        self.assertEqual(recvmsg.regression.status, "missing")
        self.assertIn("socket-cmsg-iovec", recvmsg.security_tracks)

    def test_structural_drift_is_distinct_from_coverage_debt(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = write_fixture(Path(tmp))
            catalog = InventoryBuilder(root, load_registry()).build()

        by_kind = {item.kind for item in catalog.drift}
        self.assertIn("handler-missing", by_kind)
        self.assertIn("scml-without-dispatch", by_kind)
        self.assertIn("regression-coverage-missing", by_kind)
        missing = next(item for item in catalog.drift if item.kind == "handler-missing")
        coverage = next(
            item for item in catalog.drift
            if item.kind == "regression-coverage-missing" and item.syscall == "recvmsg"
        )
        self.assertEqual(missing.severity, "error")
        self.assertEqual(coverage.severity, "warning")

    def test_baseline_promotes_new_missing_evidence_to_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = write_fixture(Path(tmp))
            catalog = InventoryBuilder(root, load_registry()).build()
        baseline = catalog.to_dict()
        baseline["syscalls"] = [item for item in baseline["syscalls"] if item["name"] != "missing"]

        drift = compare_baseline(catalog, baseline)

        new_missing = next(item for item in drift if item.syscall == "missing")
        self.assertEqual(new_missing.kind, "new-syscall-evidence-missing")
        self.assertEqual(new_missing.severity, "error")


if __name__ == "__main__":
    unittest.main()
