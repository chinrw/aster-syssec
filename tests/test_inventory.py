from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aster_syssec.config import load_registry
from aster_syssec.inventory import InventoryBuilder, compare_baseline
from tests.helpers import write_fixture


class InventoryTests(unittest.TestCase):
    def test_handler_effects_are_scoped_to_the_function_and_reachable_helpers(
        self,
    ) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = write_fixture(Path(tmp))
            pair = root / "kernel/core/src/syscall/pair.rs"
            pair.write_text(
                """
fn copy_out_helper(user_addr: Vaddr) -> Result<()> {
    user_space.write_val(user_addr, &value)?;
    Ok(())
}

pub(super) fn sys_pair_in(user_addr: Vaddr, ctx: &Context) -> Result<SyscallReturn> {
    // user_space.write_val(user_addr, &value)? is documentation, not an effect.
    let example = "capable(CapSet::SYS_ADMIN)";
    let value: Input = ctx.user_space().read_val(user_addr)?;
    Ok(value.into())
}

pub(super) fn sys_pair_out(user_addr: Vaddr, ctx: &Context) -> Result<SyscallReturn> {
    copy_out_helper(user_addr)?;
    capable(CapSet::SYS_ADMIN)?;
    Ok(0.into())
}
""".lstrip(),
                encoding="utf-8",
            )
            for relative in (
                "kernel/core/src/syscall/arch/x86.rs",
                "kernel/core/src/syscall/arch/generic.rs",
            ):
                path = root / relative
                text = path.read_text(encoding="utf-8")
                insertion = (
                    "    SYS_PAIR_IN = 300 => sys_pair_in(args[..2]);\n"
                    "    SYS_PAIR_OUT = 301 => sys_pair_out(args[..2]);\n"
                )
                path.write_text(text.replace("}", insertion + "}", 1), encoding="utf-8")

            catalog = InventoryBuilder(root, load_registry()).build()

        pair_in = next(item for item in catalog.syscalls if item.name == "pair_in")
        pair_out = next(item for item in catalog.syscalls if item.name == "pair_out")
        self.assertIn("read_val", pair_in.copy_in_operations)
        self.assertNotIn("write_val", pair_in.copy_out_operations)
        self.assertNotIn("capability-check", pair_in.permission_checks)
        self.assertNotIn("read_val", pair_out.copy_in_operations)
        self.assertIn("write_val", pair_out.copy_out_operations)
        self.assertIn("capability-check", pair_out.permission_checks)

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
            item
            for item in catalog.drift
            if item.kind == "regression-coverage-missing" and item.syscall == "recvmsg"
        )
        self.assertEqual(missing.severity, "error")
        self.assertEqual(coverage.severity, "warning")

    def test_baseline_promotes_new_missing_evidence_to_error(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = write_fixture(Path(tmp))
            catalog = InventoryBuilder(root, load_registry()).build()
        baseline = catalog.to_dict()
        baseline["syscalls"] = [
            item for item in baseline["syscalls"] if item["name"] != "missing"
        ]

        drift = compare_baseline(catalog, baseline)

        new_missing = next(item for item in drift if item.syscall == "missing")
        self.assertEqual(new_missing.kind, "new-syscall-evidence-missing")
        self.assertEqual(new_missing.severity, "error")


if __name__ == "__main__":
    unittest.main()
