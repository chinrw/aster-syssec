from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Catalog, ReviewResult
from .runs import verify_run_manifest

REVIEW_RESULT_SCHEMA = "https://asterinas.dev/syssec/review-result.schema.json"
DRIFT_LIST_SCHEMA = "https://asterinas.dev/syssec/drift-list.schema.json"


def catalog_markdown(catalog: Catalog) -> str:
    lines = [
        "# Asterinas syscall inventory",
        "",
        f"Source revision: `{catalog.source.get('revision') or 'working tree'}`",
        "",
        "| Syscall | Handler | Architectures | SCML | Regression | Tracks |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in catalog.syscalls:
        architectures = ", ".join(
            f"{name}:{dispatch.number}/{dispatch.arity}"
            for name, dispatch in sorted(item.architectures.items())
        )
        lines.append(
            "| "
            + " | ".join(
                (
                    _cell(item.name),
                    _cell(item.handler),
                    _cell(architectures),
                    item.scml.status,
                    item.regression.status,
                    _cell(", ".join(item.security_tracks)),
                )
            )
            + " |"
        )
    lines.extend(["", "## Drift", ""])
    if not catalog.drift:
        lines.append("No drift detected.")
    else:
        for item in catalog.drift:
            anchor = f" ({item.path})" if item.path else ""
            lines.append(f"- `{item.severity}` `{item.kind}`: {item.message}{anchor}")
    lines.append("")
    return "\n".join(lines)


def review_markdown(result: ReviewResult) -> str:
    lines = [
        "# Asterinas syscall security review",
        "",
        f"Source revision: `{result.source.get('revision') or 'working tree'}`",
        f"Files selected: {len(result.files_selected)}",
        f"Files with scanned syscall-reachable code: {len(result.files_scanned)}",
        f"Functions scanned: {result.functions_scanned}",
        f"Candidates: {len(result.candidates)}",
        "",
        "Every item below is a candidate. Runtime reproduction and contract validation are required before promotion.",
        "",
        "Static-backend limitations:",
        "",
        *[f"- {item}" for item in result.limitations],
        "",
        "| ID | Rule | Track | Confidence | Source | Property |",
        "| --- | --- | --- | --- | --- | --- |",
    ]
    for item in result.candidates:
        lines.append(
            "| "
            + " | ".join(
                (
                    item.finding_id,
                    item.rule_id,
                    item.track,
                    item.confidence,
                    f"{_cell(item.path)}:{item.line}",
                    item.violated_property,
                )
            )
            + " |"
        )
    for item in result.candidates:
        lines.extend(
            [
                "",
                f"## {item.finding_id}: {item.title}",
                "",
                f"- Source: `{item.path}:{item.line}` ({item.symbol or 'unknown symbol'})",
                f"- Evidence: `{item.evidence}`",
                f"- Review requirement: {item.rationale}",
                "- Security impact: not established",
            ]
        )
    lines.append("")
    return "\n".join(lines)


def aggregate_runs(
    work_root: Path, *, exclude_run: Path | None = None
) -> dict[str, Any]:
    manifests: list[dict[str, Any]] = []
    candidate_ids: set[str] = set()
    candidate_occurrences = 0
    structural_errors = 0
    invalid_runs: list[dict[str, str]] = []
    for path in sorted((work_root / "runs").rglob("run-manifest.json")):
        if exclude_run is not None and path.parent.resolve() == exclude_run.resolve():
            continue
        try:
            manifest = verify_run_manifest(path)
        except (OSError, ValueError) as error:
            invalid_runs.append({"manifest": str(path), "error": str(error)})
            continue
        manifests.append(manifest)
        for artifact in manifest["outputs"]:
            artifact_path = path.parent / artifact["path"]
            if artifact.get("schema") == REVIEW_RESULT_SCHEMA:
                findings = json.loads(artifact_path.read_text(encoding="utf-8"))
                ids = {
                    item["finding_id"]
                    for item in findings["candidates"]
                    if isinstance(item.get("finding_id"), str)
                }
                candidate_occurrences += len(findings["candidates"])
                candidate_ids.update(ids)
            elif artifact.get("schema") == DRIFT_LIST_SCHEMA:
                drift = json.loads(artifact_path.read_text(encoding="utf-8"))
                structural_errors += sum(
                    item.get("severity") == "error" for item in drift
                )
    return {
        "schema_version": 1,
        "runs": len(manifests),
        "by_status": {
            status: sum(item.get("status") == status for item in manifests)
            for status in ("running", "completed", "failed")
        },
        "candidates": len(candidate_ids),
        "candidate_occurrences": candidate_occurrences,
        "structural_errors": structural_errors,
        "run_ids": [item.get("run_id") for item in manifests],
        "invalid_runs": invalid_runs,
    }


def aggregate_markdown(summary: dict[str, Any]) -> str:
    return "\n".join(
        [
            "# aster-syssec run summary",
            "",
            f"- Runs: {summary['runs']}",
            f"- Completed: {summary['by_status']['completed']}",
            f"- Failed: {summary['by_status']['failed']}",
            f"- Still marked running: {summary['by_status']['running']}",
            f"- Static candidates: {summary['candidates']}",
            f"- Candidate occurrences: {summary['candidate_occurrences']}",
            f"- Structural inventory errors: {summary['structural_errors']}",
            f"- Invalid or tampered runs: {len(summary['invalid_runs'])}",
            "",
            "Candidates are not confirmed findings.",
            "",
        ]
    )


def _cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")
