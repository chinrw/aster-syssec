from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aster_syssec.config import load_registry
from aster_syssec.inventory import InventoryBuilder
from aster_syssec.scanner import StaticReviewer
from tests.helpers import write_fixture


class ScannerTests(unittest.TestCase):
    def test_emits_candidates_without_promoting_them(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = write_fixture(Path(tmp))
            registry = load_registry()
            catalog = InventoryBuilder(root, registry).build()
            reviewer = StaticReviewer(root, registry, catalog)
            result = reviewer.review([root / "kernel/core/src/syscall/recvmsg.rs"])

        rules = {candidate.rule_id for candidate in result.candidates}
        self.assertIn("FLAGS-TRUNCATE-UNKNOWN", rules)
        self.assertIn("COPYOUT-AFTER-SIDE-EFFECT", rules)
        self.assertTrue(all(candidate.status == "candidate" for candidate in result.candidates))
        self.assertTrue(all(candidate.security_impact is None for candidate in result.candidates))

    def test_ignores_rule_text_in_comments_and_strings(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = write_fixture(Path(tmp))
            registry = load_registry()
            catalog = InventoryBuilder(root, registry).build()
            reviewer = StaticReviewer(root, registry, catalog)
            result = reviewer.review([root / "kernel/core/src/syscall/read.rs"])

        self.assertNotIn("FLAGS-TRUNCATE-UNKNOWN", {item.rule_id for item in result.candidates})
        self.assertNotIn("REACHABLE-PANIC", {item.rule_id for item in result.candidates})

    def test_selected_scope_scans_unproven_helpers_explicitly(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = write_fixture(Path(tmp))
            registry = load_registry()
            catalog = InventoryBuilder(root, registry).build()
            reviewer = StaticReviewer(root, registry, catalog)
            result = reviewer.review(
                [root / "kernel/core/src/syscall/read.rs"],
                scope="selected",
            )

        match = next(item for item in result.candidates if item.rule_id == "FLAGS-TRUNCATE-UNKNOWN")
        self.assertEqual(match.symbol, "selected_but_not_proven_reachable")
        self.assertIn("does not prove syscall reachability", result.limitations[0])

    def test_rule_filter_limits_the_candidate_contract(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = write_fixture(Path(tmp))
            registry = load_registry()
            catalog = InventoryBuilder(root, registry).build()
            result = StaticReviewer(root, registry, catalog).review(
                [root / "kernel/core/src/syscall/recvmsg.rs"],
                rule_ids=["FLAGS-TRUNCATE-UNKNOWN"],
            )

        self.assertEqual(result.rules_run, ("FLAGS-TRUNCATE-UNKNOWN",))
        self.assertEqual({item.rule_id for item in result.candidates}, {"FLAGS-TRUNCATE-UNKNOWN"})


if __name__ == "__main__":
    unittest.main()
