from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from .models import Catalog, ReviewResult


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
                f"- Security impact: not established",
            ]
        )
    lines.append("")
    return "\n".join(lines)


def aggregate_runs(work_root: Path, *, exclude_run: Path | None = None) -> dict[str, Any]:
    manifests: list[dict[str, Any]] = []
    candidate_count = 0
    structural_errors = 0
    for path in sorted((work_root / "runs").rglob("run-manifest.json")):
        if exclude_run is not None and path.parent.resolve() == exclude_run.resolve():
            continue
        try:
            manifest = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            continue
        manifests.append(manifest)
        findings = path.parent / "review/findings.json"
        if findings.is_file():
            try:
                candidate_count += len(json.loads(findings.read_text(encoding="utf-8"))["candidates"])
            except (OSError, KeyError, json.JSONDecodeError):
                pass
        drift = path.parent / "catalog/drift.json"
        if drift.is_file():
            try:
                structural_errors += sum(
                    item.get("severity") == "error"
                    for item in json.loads(drift.read_text(encoding="utf-8"))
                )
            except (OSError, json.JSONDecodeError):
                pass
    return {
        "schema_version": 1,
        "runs": len(manifests),
        "by_status": {
            status: sum(item.get("status") == status for item in manifests)
            for status in ("running", "completed", "failed")
        },
        "candidates": candidate_count,
        "structural_errors": structural_errors,
        "run_ids": [item.get("run_id") for item in manifests],
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
            f"- Structural inventory errors: {summary['structural_errors']}",
            "",
            "Candidates are not confirmed findings.",
            "",
        ]
    )


def _cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ")
