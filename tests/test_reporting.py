from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from aster_syssec.config import load_registry
from aster_syssec.inventory import InventoryBuilder
from aster_syssec.reporting import aggregate_runs
from aster_syssec.runs import RunContext
from aster_syssec.scanner import StaticReviewer
from tests.helpers import write_fixture


def write_review_run(source: Path, work: Path) -> tuple[Path, int]:
    registry = load_registry()
    catalog = InventoryBuilder(source, registry).build()
    result = StaticReviewer(source, registry, catalog).review(
        [source / "kernel/core/src/syscall/recvmsg.rs"]
    )
    run = RunContext.start(
        work_root=work,
        command="review",
        source_root=source,
        registry=registry,
        parameters={},
    )
    findings = run.write_json(
        "review/findings.json",
        result.to_dict(),
        schema="review-result.schema.json",
    )
    run.complete([findings])
    return findings, len(result.candidates)


class ReportingTests(unittest.TestCase):
    def test_aggregate_distinguishes_unique_candidates_from_occurrences(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            work = base / "work"
            _, per_run = write_review_run(source, work)
            _, repeated = write_review_run(source, work)

            summary = aggregate_runs(work)

        self.assertEqual(repeated, per_run)
        self.assertEqual(summary["candidates"], per_run)
        self.assertEqual(summary["candidate_occurrences"], per_run * 2)

    def test_aggregate_reports_tampered_evidence_instead_of_counting_it(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            source = write_fixture(base / "source")
            work = base / "work"
            findings, _ = write_review_run(source, work)
            findings.write_text(
                findings.read_text(encoding="utf-8") + " ", encoding="utf-8"
            )

            summary = aggregate_runs(work)

        self.assertEqual(summary["candidates"], 0)
        self.assertEqual(len(summary["invalid_runs"]), 1)
        self.assertIn("artifact hash", summary["invalid_runs"][0]["error"])


if __name__ == "__main__":
    unittest.main()
