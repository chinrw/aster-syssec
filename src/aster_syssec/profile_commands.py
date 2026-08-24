from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path

from .config import Registry, validate_registry_against_checkout
from .inventory import InventoryBuilder, compare_baseline
from .reporting import catalog_markdown, review_markdown
from .runs import RunContext
from .scanner import StaticReviewer
from .selection import select_review_paths


@dataclass(frozen=True)
class ProfileCommandContext:
    source_root: Path
    registry: Registry
    run: RunContext
    changed_from: str | None
    baseline: Path | None


def execute_profile_command(
    command: str,
    context: ProfileCommandContext,
) -> dict[str, str]:
    if command == "config-check":
        catalog = InventoryBuilder(context.source_root, context.registry).build()
        issues = validate_registry_against_checkout(
            context.registry,
            context.source_root,
            catalog=catalog,
        )
        status = "fail" if any(item.status == "FAIL" for item in issues) else "ok"
        context.run.write_json(
            "profile/commands/config-check.json",
            {
                "status": status,
                "issues": [item.__dict__ for item in issues],
            },
            schema="config-check.schema.json",
        )
        return {
            "command": command,
            "outcome": "fail" if status == "fail" else "pass",
        }
    if command in {"inventory --check", "inventory --check --baseline"}:
        catalog = InventoryBuilder(context.source_root, context.registry).build()
        if command.endswith("--baseline"):
            if context.baseline is None:
                raise ValueError(
                    "profile inventory --check --baseline requires --baseline"
                )
            baseline = json.loads(context.baseline.read_text(encoding="utf-8"))
            context.run.write_json(
                "profile/inputs/baseline.json",
                baseline,
                schema="syscall-catalog.schema.json",
            )
            catalog = type(catalog)(
                source=catalog.source,
                syscalls=catalog.syscalls,
                drift=(*catalog.drift, *compare_baseline(catalog, baseline)),
            )
        context.run.write_json(
            "profile/commands/inventory/syscalls.json",
            catalog.to_dict(),
            schema="syscall-catalog.schema.json",
        )
        context.run.write_json(
            "profile/commands/inventory/drift.json",
            [item.__dict__ for item in catalog.drift],
            schema="drift-list.schema.json",
        )
        context.run.write_text(
            "profile/commands/inventory/syscall-matrix.md",
            catalog_markdown(catalog),
            media_type="text/markdown; charset=utf-8",
        )
        failed = any(item.severity == "error" for item in catalog.drift)
        return {
            "command": command,
            "outcome": "fail" if failed else "pass",
        }
    if command in {"review", "review --changed-from"}:
        changed_from = (
            context.changed_from if command.endswith("--changed-from") else None
        )
        if command.endswith("--changed-from") and changed_from is None:
            raise ValueError("profile review --changed-from requires --changed-from")
        catalog = InventoryBuilder(context.source_root, context.registry).build()
        paths = select_review_paths(
            context.source_root,
            context.registry,
            catalog,
            changed_from=changed_from,
        )
        result = StaticReviewer(
            context.source_root,
            context.registry,
            catalog,
        ).review(paths)
        context.run.write_json(
            "profile/commands/review/findings.json",
            result.to_dict(),
            schema="review-result.schema.json",
        )
        context.run.write_text(
            "profile/commands/review/report.md",
            review_markdown(result),
            media_type="text/markdown; charset=utf-8",
        )
        context.run.write_json(
            "profile/commands/review/selection.json",
            {
                "tracks": [],
                "changed_from": changed_from,
                "scope": "handlers",
                "rules": list(result.rules_run),
                "files": list(result.files_selected),
                "files_with_scanned_code": list(result.files_scanned),
            },
            schema="review-selection.schema.json",
        )
        return {"command": command, "outcome": "pass"}
    return {"command": command, "outcome": "unsupported"}
