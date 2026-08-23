from __future__ import annotations

import argparse
import json
import os
import sys
from pathlib import Path
from typing import Any, Sequence

from .agent_review import prepare_aster_code_review
from .config import Registry, load_registry, require_tracks
from .doctor import run_doctor
from .inventory import InventoryBuilder, compare_baseline
from .reporting import (
    aggregate_markdown,
    aggregate_runs,
    catalog_markdown,
    review_markdown,
)
from .runs import RunContext
from .scanner import RULE_IDS, StaticReviewer
from .selection import select_review_paths
from .source import ensure_asterinas_checkout
from .specula import prepare_handoff


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="syssec",
        description="Evidence-first Asterinas syscall security reviewer",
    )
    parser.add_argument("--version", action="version", version="aster-syssec 0.1.0")
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser("doctor", help="validate source, profile, and engine availability")
    _add_source_options(doctor)
    doctor.add_argument("--specula-profile", type=Path)
    doctor.add_argument("--specula-repo", type=Path)
    doctor.add_argument("--json", action="store_true", help="print machine-readable result")
    doctor.set_defaults(handler=_doctor)

    inventory = subparsers.add_parser("inventory", help="build and reconcile the syscall catalog")
    _add_source_options(inventory)
    inventory.add_argument("--check", action="store_true", help="fail on structural drift")
    inventory.add_argument(
        "--baseline",
        type=Path,
        help="schema-version-1 catalog used to detect new or changed dispatch and lost evidence",
    )
    inventory.add_argument(
        "--strict-coverage",
        action="store_true",
        help="with --check, also fail on SCML or regression coverage warnings",
    )
    inventory.add_argument("--json", action="store_true", help="print summary as JSON")
    inventory.set_defaults(handler=_inventory)

    review = subparsers.add_parser("review", help="scan syscall paths and emit security candidates")
    _add_source_options(review)
    review.add_argument("--track", action="append", default=[], help="security track id; repeatable")
    review.add_argument("--path", action="append", default=[], help="checkout-relative file or directory")
    review.add_argument("--changed-from", help="Git base for changed-path review")
    review.add_argument(
        "--scope",
        choices=("handlers", "selected"),
        default="handlers",
        help="handlers follows same-file calls; selected scans every function in selected paths",
    )
    review.add_argument(
        "--rule",
        action="append",
        choices=RULE_IDS,
        default=[],
        help="run one static rule id; repeatable",
    )
    review.add_argument(
        "--fail-on-candidates",
        action="store_true",
        help="return 1 when one or more candidates are emitted",
    )
    review.add_argument("--json", action="store_true", help="print summary as JSON")
    review.set_defaults(handler=_review)

    model = subparsers.add_parser("model", help="prepare a gated Specula dry-run or analysis handoff")
    _add_source_options(model)
    model.add_argument("--track", required=True, help="one security track id")
    model.add_argument("--stage", choices=("dry-run", "analysis"), default="dry-run")
    model.add_argument("--specula-profile", required=True, type=Path)
    model.add_argument("--specula-repo", required=True, type=Path)
    model.add_argument("--run-id")
    model.add_argument(
        "--export-linked",
        action="store_true",
        help="export exact HEAD when the source is a linked worktree",
    )
    model.add_argument("--json", action="store_true", help="print machine-readable handoff")
    model.set_defaults(handler=_model)

    agent_review = subparsers.add_parser(
        "agent-review",
        help="prepare the checkout's aster-code-review backend without executing agents",
    )
    _add_source_options(agent_review)
    target = agent_review.add_mutually_exclusive_group(required=True)
    target.add_argument("--base", help="review merge-base(base, HEAD)..HEAD")
    target.add_argument("--path", action="append", help="working-tree file or file:line-range")
    agent_review.add_argument("--agent-profile", default="codex")
    agent_review.add_argument(
        "--per-persona-context",
        choices=("auto", "yes", "no"),
        default="auto",
    )
    agent_review.add_argument("--json", action="store_true")
    agent_review.set_defaults(handler=_agent_review)

    report = subparsers.add_parser("report", help="summarize prior reviewer runs")
    _add_source_options(report)
    report.add_argument("--json", action="store_true", help="print summary as JSON")
    report.set_defaults(handler=_report)

    tracks = subparsers.add_parser("tracks", help="list configured security tracks")
    tracks.add_argument("--config-root", type=Path)
    tracks.add_argument("--json", action="store_true")
    tracks.set_defaults(handler=_tracks)
    return parser


def _add_source_options(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--asterinas",
        required=True,
        type=Path,
        help="authoritative Asterinas checkout",
    )
    parser.add_argument(
        "--work-root",
        type=Path,
        default=None,
        help="evidence root; defaults to SYSSEC_WORK_ROOT or ~/.cache/aster-syssec",
    )
    parser.add_argument("--config-root", type=Path, help="override bundled property/track registry")


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (ValueError, OSError, json.JSONDecodeError) as error:
        print(f"syssec: {error}", file=sys.stderr)
        return 2


def _doctor(args: argparse.Namespace) -> int:
    registry = load_registry(args.config_root)
    run = _start_run(args, registry, "doctor", {
        "specula_profile": _optional_path(args.specula_profile),
        "specula_repo": _optional_path(args.specula_repo),
    })
    try:
        result = run_doctor(
            args.asterinas,
            registry,
            profile_root=args.specula_profile,
            specula_repo=args.specula_repo,
        )
        output = run.write_json("doctor/doctor.json", result.to_dict())
        run.complete([output])
    except BaseException as error:
        run.fail(error)
        raise
    summary = result.to_dict()
    _print_result(args.json, summary, f"doctor: {result.status}; run={run.root}")
    return 1 if result.status == "fail" else 0


def _inventory(args: argparse.Namespace) -> int:
    registry = load_registry(args.config_root)
    run = _start_run(args, registry, "inventory", {
        "check": args.check,
        "strict_coverage": args.strict_coverage,
        "baseline": _optional_path(args.baseline),
    })
    try:
        ensure_asterinas_checkout(args.asterinas)
        catalog = InventoryBuilder(args.asterinas, registry).build()
        if args.baseline is not None:
            baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
            additions = compare_baseline(catalog, baseline)
            catalog = type(catalog)(
                source=catalog.source,
                syscalls=catalog.syscalls,
                drift=tuple((*catalog.drift, *additions)),
            )
        catalog_json = run.write_json("catalog/syscalls.json", catalog.to_dict())
        drift_json = run.write_json("catalog/drift.json", [item.__dict__ for item in catalog.drift])
        matrix = run.write_text("catalog/syscall-matrix.md", catalog_markdown(catalog))
        run.complete([catalog_json, drift_json, matrix])
    except BaseException as error:
        run.fail(error)
        raise
    errors = sum(item.severity == "error" for item in catalog.drift)
    warnings = sum(item.severity == "warning" for item in catalog.drift)
    summary = {
        "run": str(run.root),
        "syscalls": len(catalog.syscalls),
        "structural_errors": errors,
        "coverage_warnings": warnings,
    }
    _print_result(
        args.json,
        summary,
        f"inventory: {len(catalog.syscalls)} syscalls, {errors} errors, {warnings} warnings; run={run.root}",
    )
    if args.check and (errors or (args.strict_coverage and warnings)):
        return 1
    return 0


def _review(args: argparse.Namespace) -> int:
    registry = load_registry(args.config_root)
    require_tracks(registry, args.track)
    run = _start_run(args, registry, "review", {
        "tracks": args.track,
        "paths": args.path,
        "changed_from": args.changed_from,
        "scope": args.scope,
        "rules": args.rule,
        "fail_on_candidates": args.fail_on_candidates,
    })
    try:
        ensure_asterinas_checkout(args.asterinas)
        catalog = InventoryBuilder(args.asterinas, registry).build()
        paths = select_review_paths(
            args.asterinas,
            registry,
            catalog,
            track_ids=args.track,
            requested_paths=args.path,
            changed_from=args.changed_from,
        )
        if not paths:
            raise ValueError("review selection contains no Rust files")
        result = StaticReviewer(args.asterinas, registry, catalog).review(
            paths,
            scope=args.scope,
            rule_ids=args.rule or None,
        )
        findings = run.write_json("review/findings.json", result.to_dict())
        report = run.write_text("review/report.md", review_markdown(result))
        selection = run.write_json("review/selection.json", {
            "tracks": args.track,
            "changed_from": args.changed_from,
            "scope": args.scope,
            "rules": list(result.rules_run),
            "files": list(result.files_selected),
            "files_with_scanned_code": list(result.files_scanned),
        })
        run.complete([findings, report, selection])
    except BaseException as error:
        run.fail(error)
        raise
    summary = {
        "run": str(run.root),
        "files_selected": len(result.files_selected),
        "files_scanned": len(result.files_scanned),
        "functions_scanned": result.functions_scanned,
        "candidates": len(result.candidates),
        "confirmed_findings": 0,
    }
    _print_result(
        args.json,
        summary,
        f"review: {len(result.files_selected)} selected, {len(result.files_scanned)} scanned files, "
        f"{len(result.candidates)} candidates, 0 confirmed; run={run.root}",
    )
    return 1 if args.fail_on_candidates and result.candidates else 0


def _model(args: argparse.Namespace) -> int:
    registry = load_registry(args.config_root)
    track = require_tracks(registry, [args.track])[0]
    run = _start_run(args, registry, "model", {
        "track": args.track,
        "stage": args.stage,
        "specula_profile": str(args.specula_profile.resolve()),
        "specula_repo": str(args.specula_repo.resolve()),
        "export_linked": args.export_linked,
        "requested_run_id": args.run_id,
    })
    try:
        ensure_asterinas_checkout(args.asterinas)
        handoff, command, extra = prepare_handoff(
            source_root=args.asterinas,
            profile_root=args.specula_profile,
            specula_repo=args.specula_repo,
            track=track,
            stage=args.stage,
            run_root=run.root,
            run_id=args.run_id,
            export_linked=args.export_linked,
        )
        handoff_path = run.write_json("specula/handoff.json", handoff)
        outputs = [handoff_path, *extra]
        if command:
            command_path = run.write_text(
                "specula/command.sh",
                "#!/bin/sh\nset -eu\n\nexec " + command + "\n",
            )
            command_path.chmod(0o755)
            outputs.append(command_path)
        run.complete(outputs)
    except BaseException as error:
        run.fail(error)
        raise
    summary = {
        "run": str(run.root),
        "ready": handoff["ready"],
        "blockers": handoff["blockers"],
        "specula_run_id": handoff["execution_identity"]["run_id"],
    }
    _print_result(
        args.json,
        summary,
        f"model handoff: {'ready' if handoff['ready'] else 'blocked'}; run={run.root}",
    )
    return 0 if handoff["ready"] else 1


def _agent_review(args: argparse.Namespace) -> int:
    registry = load_registry(args.config_root)
    run = _start_run(args, registry, "agent-review", {
        "base": args.base,
        "paths": args.path or [],
        "agent_profile": args.agent_profile,
        "per_persona_context": args.per_persona_context,
    })
    try:
        ensure_asterinas_checkout(args.asterinas)
        handoff, command = prepare_aster_code_review(
            source_root=args.asterinas,
            run_root=run.root,
            agent_profile=args.agent_profile,
            per_persona_context=args.per_persona_context,
            base=args.base,
            paths=args.path or (),
        )
        handoff_path = run.write_json("agent-review/handoff.json", handoff)
        command_path = run.write_text(
            "agent-review/command.sh",
            "#!/bin/sh\nset -eu\n\n" + command + "\n",
        )
        command_path.chmod(0o755)
        run.complete([handoff_path, command_path])
    except BaseException as error:
        run.fail(error)
        raise
    summary = {
        "run": str(run.root),
        "ready": True,
        "mode": handoff["mode"],
        "executed": False,
        "command": str(command_path),
    }
    _print_result(
        args.json,
        summary,
        f"agent-review handoff: ready, not executed; command={command_path}; run={run.root}",
    )
    return 0


def _report(args: argparse.Namespace) -> int:
    registry = load_registry(args.config_root)
    work_root = _work_root(args.work_root)
    run = RunContext.start(
        work_root=work_root,
        command="report",
        source_root=args.asterinas,
        registry=registry,
        parameters={},
    )
    try:
        summary = aggregate_runs(work_root, exclude_run=run.root)
        output_json = run.write_json("report/summary.json", summary)
        output_md = run.write_text("report/summary.md", aggregate_markdown(summary))
        run.complete([output_json, output_md])
    except BaseException as error:
        run.fail(error)
        raise
    _print_result(args.json, summary, f"report: {summary['runs']} runs; run={run.root}")
    return 0


def _tracks(args: argparse.Namespace) -> int:
    registry = load_registry(args.config_root)
    values = [
        {
            "id": track.id,
            "description": track.description,
            "specula_readiness": track.specula_readiness,
            "engines": list(track.engines),
        }
        for track in registry.tracks.values()
    ]
    if args.json:
        print(json.dumps(values, indent=2, sort_keys=True))
    else:
        for item in values:
            print(f"{item['id']}: {item['description']} [{item['specula_readiness']}]")
    return 0


def _start_run(
    args: argparse.Namespace,
    registry: Registry,
    command: str,
    parameters: dict[str, Any],
) -> RunContext:
    return RunContext.start(
        work_root=_work_root(args.work_root),
        command=command,
        source_root=args.asterinas,
        registry=registry,
        parameters=parameters,
    )


def _work_root(explicit: Path | None) -> Path:
    if explicit is not None:
        return explicit.resolve()
    configured = os.environ.get("SYSSEC_WORK_ROOT")
    if configured:
        return Path(configured).expanduser().resolve()
    cache = os.environ.get("XDG_CACHE_HOME")
    if cache:
        return (Path(cache).expanduser() / "aster-syssec").resolve()
    return (Path.home() / ".cache/aster-syssec").resolve()


def _print_result(as_json: bool, value: dict[str, Any], text: str) -> None:
    if as_json:
        print(json.dumps(value, indent=2, sort_keys=True))
    else:
        print(text)


def _optional_path(path: Path | None) -> str | None:
    return str(path.resolve()) if path is not None else None
