from __future__ import annotations

import argparse
import json
import os
import sys
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from . import __version__
from .agent_review import prepare_aster_code_review
from .config import (
    Registry,
    load_registry,
    require_tracks,
    validate_registry_against_checkout,
)
from .doctor import run_doctor
from .engines import EngineContext, doctor_engine, execute_target
from .evidence import DEFAULT_MAX_BYTES, DEFAULT_MAX_FILES, pack_evidence
from .handoff import verify_handoff
from .inventory import InventoryBuilder, compare_baseline
from .profile_commands import ProfileCommandContext, execute_profile_command
from .profiles import load_profile_registry
from .reporting import (
    aggregate_markdown,
    aggregate_runs,
    catalog_markdown,
    review_markdown,
)
from .runs import RunContext
from .safety import (
    require_core_class,
    require_core_execution,
    require_profile_target_safety,
)
from .scanner import RULE_IDS, StaticReviewer
from .schemas import validate_instance
from .selection import select_review_paths
from .source import ensure_asterinas_checkout
from .specula import prepare_handoff
from .targets import load_target_registry, validate_targets_against_checkout


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="syssec",
        description="Evidence-first Asterinas syscall security reviewer",
    )
    parser.add_argument(
        "--version", action="version", version=f"aster-syssec {__version__}"
    )
    subparsers = parser.add_subparsers(dest="command", required=True)

    doctor = subparsers.add_parser(
        "doctor", help="validate source, profile, and engine availability"
    )
    _add_source_options(doctor)
    doctor.add_argument("--specula-profile", type=Path)
    doctor.add_argument("--specula-repo", type=Path)
    doctor.add_argument(
        "--json", action="store_true", help="print machine-readable result"
    )
    doctor.set_defaults(handler=_doctor)

    config_check = subparsers.add_parser(
        "config-check",
        help="validate Track configuration against an Asterinas checkout",
    )
    _add_source_options(config_check)
    config_check.add_argument("--specula-profile", type=Path)
    config_check.add_argument("--json", action="store_true")
    config_check.set_defaults(handler=_config_check)

    inventory = subparsers.add_parser(
        "inventory", help="build and reconcile the syscall catalog"
    )
    _add_source_options(inventory)
    inventory.add_argument(
        "--check", action="store_true", help="fail on structural drift"
    )
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

    review = subparsers.add_parser(
        "review", help="scan syscall paths and emit security candidates"
    )
    _add_source_options(review)
    review.add_argument(
        "--track", action="append", default=[], help="security track id; repeatable"
    )
    review.add_argument(
        "--path",
        action="append",
        default=[],
        help="checkout-relative file or directory",
    )
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

    model = subparsers.add_parser(
        "model", help="prepare a gated Specula dry-run or analysis handoff"
    )
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
    model.add_argument(
        "--json", action="store_true", help="print machine-readable handoff"
    )
    model.set_defaults(handler=_model)

    agent_review = subparsers.add_parser(
        "agent-review",
        help="prepare the checkout's aster-code-review backend without executing agents",
    )
    _add_source_options(agent_review)
    target = agent_review.add_mutually_exclusive_group(required=True)
    target.add_argument("--base", help="review merge-base(base, HEAD)..HEAD")
    target.add_argument(
        "--path", action="append", help="working-tree file or file:line-range"
    )
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

    targets = subparsers.add_parser(
        "targets", help="inspect configured verification targets"
    )
    target_commands = targets.add_subparsers(dest="target_command", required=True)
    targets_list = target_commands.add_parser(
        "list", help="list validated verification targets"
    )
    targets_list.add_argument("--config-root", type=Path)
    targets_list.add_argument("--target-root", type=Path)
    targets_list.add_argument("--json", action="store_true")
    targets_list.set_defaults(handler=_targets_list)
    targets_check = target_commands.add_parser(
        "check", help="validate targets against an Asterinas checkout"
    )
    _add_source_options(targets_check)
    targets_check.add_argument("--target-root", type=Path)
    targets_check.add_argument("--json", action="store_true")
    targets_check.set_defaults(handler=_targets_check)

    run_target = subparsers.add_parser(
        "run-target", help="execute one verification target and normalize its evidence"
    )
    _add_source_options(run_target)
    run_target.add_argument("--target-root", type=Path)
    run_target.add_argument("--target", required=True)
    run_target.add_argument("--json", action="store_true")
    run_target.set_defaults(handler=_run_target)

    engine = subparsers.add_parser("engine", help="inspect verification engines")
    engine_commands = engine.add_subparsers(dest="engine_command", required=True)
    engine_doctor = engine_commands.add_parser(
        "doctor", help="check whether one engine adapter and tool are callable"
    )
    engine_doctor.add_argument("--engine", required=True)
    engine_doctor.add_argument("--json", action="store_true")
    engine_doctor.set_defaults(handler=_engine_doctor)

    run_profile = subparsers.add_parser("run", help="execute one verification profile")
    _add_source_options(run_profile)
    run_profile.add_argument("--profile", required=True)
    run_profile.add_argument("--profile-config", type=Path)
    run_profile.add_argument("--target-root", type=Path)
    run_profile.add_argument("--changed-from")
    run_profile.add_argument("--baseline", type=Path)
    run_profile.add_argument("--json", action="store_true")
    run_profile.set_defaults(handler=_run_profile)

    evidence = subparsers.add_parser(
        "evidence", help="verify and package registered run evidence"
    )
    evidence_commands = evidence.add_subparsers(dest="evidence_command", required=True)
    evidence_pack = evidence_commands.add_parser(
        "pack", help="copy verified manifest artifacts into a bounded upload tree"
    )
    evidence_pack.add_argument("--work-root", required=True, type=Path)
    evidence_pack.add_argument("--output", required=True, type=Path)
    evidence_pack.add_argument("--max-bytes", type=int, default=DEFAULT_MAX_BYTES)
    evidence_pack.add_argument("--max-files", type=int, default=DEFAULT_MAX_FILES)
    evidence_pack.add_argument("--json", action="store_true")
    evidence_pack.set_defaults(handler=_evidence_pack)

    verify = subparsers.add_parser(
        "verify-handoff",
        help="fail closed when a prepared handoff identity no longer matches",
    )
    verify.add_argument("--handoff", required=True, type=Path)
    verify.add_argument("--json", action="store_true")
    verify.set_defaults(handler=_verify_handoff)
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
    parser.add_argument(
        "--config-root", type=Path, help="override bundled property/track registry"
    )


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (TypeError, ValueError, OSError, json.JSONDecodeError) as error:
        print(f"syssec: {error}", file=sys.stderr)
        return 2


def _doctor(args: argparse.Namespace) -> int:
    registry = load_registry(args.config_root)
    run = _start_run(
        args,
        registry,
        "doctor",
        {
            "specula_profile": _optional_path(args.specula_profile),
            "specula_repo": _optional_path(args.specula_repo),
        },
    )
    try:
        result = run_doctor(
            args.asterinas,
            registry,
            profile_root=args.specula_profile,
            specula_repo=args.specula_repo,
        )
        output = run.write_json(
            "doctor/doctor.json",
            result.to_dict(),
            schema="doctor.schema.json",
        )
        run.complete([output])
    except BaseException as error:
        run.fail(error)
        raise
    summary = result.to_dict()
    _print_result(args.json, summary, f"doctor: {result.status}; run={run.root}")
    return 1 if result.status == "fail" else 0


def _config_check(args: argparse.Namespace) -> int:
    registry = load_registry(args.config_root)
    run = _start_run(
        args,
        registry,
        "config-check",
        {"specula_profile": _optional_path(args.specula_profile)},
    )
    try:
        ensure_asterinas_checkout(args.asterinas)
        catalog = InventoryBuilder(args.asterinas, registry).build()
        issues = validate_registry_against_checkout(
            registry,
            args.asterinas,
            catalog=catalog,
            profile_root=args.specula_profile,
        )
        status = (
            "fail"
            if any(item.status == "FAIL" for item in issues)
            else "warn"
            if any(item.status == "WARN" for item in issues)
            else "ok"
        )
        result = {
            "status": status,
            "issues": [item.__dict__ for item in issues],
        }
        output = run.write_json(
            "config/config-check.json",
            result,
            schema="config-check.schema.json",
        )
        run.complete([output])
    except BaseException as error:
        run.fail(error)
        raise
    _print_result(
        args.json,
        result,
        f"config-check: {status}, {len(issues)} issues; run={run.root}",
    )
    return 1 if status == "fail" else 0


def _inventory(args: argparse.Namespace) -> int:
    registry = load_registry(args.config_root)
    run = _start_run(
        args,
        registry,
        "inventory",
        {
            "check": args.check,
            "strict_coverage": args.strict_coverage,
            "baseline": _optional_path(args.baseline),
        },
    )
    try:
        ensure_asterinas_checkout(args.asterinas)
        catalog = InventoryBuilder(args.asterinas, registry).build()
        if args.baseline is not None:
            baseline = json.loads(args.baseline.read_text(encoding="utf-8"))
            additions = compare_baseline(catalog, baseline)
            catalog = type(catalog)(
                source=catalog.source,
                syscalls=catalog.syscalls,
                drift=(*catalog.drift, *additions),
            )
        catalog_json = run.write_json(
            "catalog/syscalls.json",
            catalog.to_dict(),
            schema="syscall-catalog.schema.json",
        )
        drift_json = run.write_json(
            "catalog/drift.json",
            [item.__dict__ for item in catalog.drift],
            schema="drift-list.schema.json",
        )
        matrix = run.write_text(
            "catalog/syscall-matrix.md",
            catalog_markdown(catalog),
            media_type="text/markdown; charset=utf-8",
        )
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
    run = _start_run(
        args,
        registry,
        "review",
        {
            "tracks": args.track,
            "paths": args.path,
            "changed_from": args.changed_from,
            "scope": args.scope,
            "rules": args.rule,
            "fail_on_candidates": args.fail_on_candidates,
        },
    )
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
        findings = run.write_json(
            "review/findings.json",
            result.to_dict(),
            schema="review-result.schema.json",
        )
        report = run.write_text(
            "review/report.md",
            review_markdown(result),
            media_type="text/markdown; charset=utf-8",
        )
        selection = run.write_json(
            "review/selection.json",
            {
                "tracks": args.track,
                "changed_from": args.changed_from,
                "scope": args.scope,
                "rules": list(result.rules_run),
                "files": list(result.files_selected),
                "files_with_scanned_code": list(result.files_scanned),
            },
            schema="review-selection.schema.json",
        )
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
    run = _start_run(
        args,
        registry,
        "model",
        {
            "track": args.track,
            "stage": args.stage,
            "specula_profile": str(args.specula_profile.resolve()),
            "specula_repo": str(args.specula_repo.resolve()),
            "export_linked": args.export_linked,
            "requested_run_id": args.run_id,
        },
    )
    try:
        ensure_asterinas_checkout(args.asterinas)
        plan = prepare_handoff(
            source_root=args.asterinas,
            profile_root=args.specula_profile,
            specula_repo=args.specula_repo,
            track=track,
            stage=args.stage,
            run_root=run.root,
            run_id=args.run_id,
            export_linked=args.export_linked,
        )
        handoff = plan.evidence
        handoff_path = run.write_json(
            "specula/handoff.json",
            handoff,
            schema=plan.schema,
        )
        outputs = [handoff_path, *plan.artifacts]
        command = plan.command_with_preflight(handoff_path)
        if command:
            command_path = run.write_text(
                "specula/command.sh",
                "#!/bin/sh\nset -eu\n\n" + command + "\n",
                media_type="text/x-shellscript; charset=utf-8",
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
    run = _start_run(
        args,
        registry,
        "agent-review",
        {
            "base": args.base,
            "paths": args.path or [],
            "agent_profile": args.agent_profile,
            "per_persona_context": args.per_persona_context,
        },
    )
    try:
        ensure_asterinas_checkout(args.asterinas)
        plan = prepare_aster_code_review(
            source_root=args.asterinas,
            run_root=run.root,
            agent_profile=args.agent_profile,
            per_persona_context=args.per_persona_context,
            base=args.base,
            paths=args.path or (),
        )
        handoff = plan.evidence
        handoff_path = run.write_json(
            "agent-review/handoff.json",
            handoff,
            schema=plan.schema,
        )
        command = plan.command_with_preflight(handoff_path)
        if command is None:
            raise ValueError(
                "agent-review handoff unexpectedly has no execution command"
            )
        command_path = run.write_text(
            "agent-review/command.sh",
            "#!/bin/sh\nset -eu\n\n" + command + "\n",
            media_type="text/x-shellscript; charset=utf-8",
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
        output_json = run.write_json(
            "report/summary.json",
            summary,
            schema="report-summary.schema.json",
        )
        output_md = run.write_text(
            "report/summary.md",
            aggregate_markdown(summary),
            media_type="text/markdown; charset=utf-8",
        )
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


def _targets_list(args: argparse.Namespace) -> int:
    registry = load_registry(args.config_root)
    targets = load_target_registry(registry, args.target_root)
    values = [target.summary() for target in targets.targets.values()]
    if args.json:
        print(json.dumps(values, indent=2, sort_keys=True))
    else:
        for item in values:
            print(
                f"{item['id']}: {item['engine']} {item['track']} "
                f"safety={item['safety']['class']} "
                f"expected={item['expected']} pr_blocking={str(item['pr_blocking']).lower()}"
            )
    return 0


def _targets_check(args: argparse.Namespace) -> int:
    registry = load_registry(args.config_root)
    targets = load_target_registry(registry, args.target_root)
    run = _start_run(
        args,
        registry,
        "targets-check",
        {
            "target_root": _optional_path(args.target_root),
            "target_registry_hash": targets.config_hash,
        },
    )
    try:
        ensure_asterinas_checkout(args.asterinas)
        issues = validate_targets_against_checkout(targets, args.asterinas)
        result = {
            "schema_version": 1,
            "status": "fail" if issues else "ok",
            "target_registry_hash": targets.config_hash,
            "targets": len(targets.targets),
            "issues": [item.__dict__ for item in issues],
        }
        output = run.write_json(
            "targets/check.json",
            result,
            schema="target-check.schema.json",
        )
        run.complete([output])
    except BaseException as error:
        run.fail(error)
        raise
    _print_result(
        args.json,
        result,
        f"targets check: {result['status']}, {len(issues)} issues; run={run.root}",
    )
    return 1 if issues else 0


def _run_target(args: argparse.Namespace) -> int:
    registry = load_registry(args.config_root)
    targets = load_target_registry(registry, args.target_root)
    target = targets.require(args.target)
    require_core_execution(target.safety, operation="run-target")
    work_root = _work_root(args.work_root)
    run = RunContext.start(
        work_root=work_root,
        command="run-target",
        source_root=args.asterinas,
        registry=registry,
        parameters={
            "target": target.id,
            "target_config_sha256": target.config_sha256,
            "target_registry_hash": targets.config_hash,
            "safety_class": target.safety.safety_class.value,
        },
    )
    try:
        ensure_asterinas_checkout(args.asterinas)
        target_issues = tuple(
            issue
            for issue in validate_targets_against_checkout(targets, args.asterinas)
            if issue.target == target.id
        )
        if target_issues:
            detail = "; ".join(issue.detail for issue in target_issues)
            raise ValueError(
                f"verification target {target.id} is not executable: {detail}"
            )
        execution = execute_target(
            target,
            EngineContext(
                source_root=args.asterinas.resolve(),
                work_root=work_root,
                run=run,
            ),
        )
        run.complete()
    except BaseException as error:
        run.fail(error)
        raise
    summary = {
        "run": str(run.root),
        "target": target.id,
        "engine": target.engine,
        "safety_class": target.safety.safety_class.value,
        "outcome": execution.outcome,
        "expected": target.policy.expected,
        "expectation_met": execution.expectation_met,
    }
    _print_result(
        args.json,
        summary,
        f"run-target: {target.id} outcome={execution.outcome}; run={run.root}",
    )
    return 0 if execution.expectation_met else 1


def _engine_doctor(args: argparse.Namespace) -> int:
    result = doctor_engine(args.engine)
    validate_instance(result, "engine-doctor.schema.json")
    _print_result(
        args.json,
        result,
        f"engine doctor: {args.engine} {result['status']}",
    )
    return 0 if result["status"] == "available" else 1


def _run_profile(args: argparse.Namespace) -> int:
    registry = load_registry(args.config_root)
    targets = load_target_registry(registry, args.target_root)
    profiles = load_profile_registry(args.profile_config)
    profile = profiles.require(args.profile)
    selected = [targets.require(target_id) for target_id in profile.targets]
    require_core_class(profile.safety_class, operation="run profile")
    for target in selected:
        require_profile_target_safety(
            profile_class=profile.safety_class,
            target_id=target.id,
            target_policy=target.safety,
        )
    work_root = _work_root(args.work_root)
    run = RunContext.start(
        work_root=work_root,
        command="run-profile",
        source_root=args.asterinas,
        registry=registry,
        parameters={
            "profile": profile.id,
            "safety_class": profile.safety_class.value,
            "profile_config_sha256": profiles.config_sha256,
            "target_registry_hash": targets.config_hash,
            "changed_from": args.changed_from,
            "baseline": _optional_path(args.baseline),
        },
    )
    try:
        ensure_asterinas_checkout(args.asterinas)
        all_issues = validate_targets_against_checkout(targets, args.asterinas)
        command_context = ProfileCommandContext(
            source_root=args.asterinas.resolve(),
            registry=registry,
            run=run,
            changed_from=args.changed_from,
            baseline=args.baseline,
        )
        command_results = [
            execute_profile_command(command, command_context)
            for command in profile.commands
        ]
        command_failed = any(item["outcome"] != "pass" for item in command_results)
        target_results: list[dict[str, Any]] = []
        for target in selected:
            if profile.fail_fast and command_failed:
                break
            issues = [issue for issue in all_issues if issue.target == target.id]
            if issues:
                detail = "; ".join(issue.detail for issue in issues)
                raise ValueError(
                    f"verification target {target.id} is not executable: {detail}"
                )
            execution = execute_target(
                target,
                EngineContext(
                    source_root=args.asterinas.resolve(),
                    work_root=work_root,
                    run=run,
                ),
            )
            result_path = f"engines/{target.engine}/{target.id}/result.json"
            result_artifact = run.artifact_record(result_path)
            target_results.append(
                {
                    "target": target.id,
                    "engine": target.engine,
                    "safety_class": target.safety.safety_class.value,
                    "result_id": execution.result["result_id"],
                    "outcome": execution.outcome,
                    "expected": target.policy.expected,
                    "expectation_met": execution.expectation_met,
                    "run_manifest": "run-manifest.json",
                    "result_path": result_path,
                    "result_sha256": result_artifact["sha256"],
                }
            )
            if profile.fail_fast and not execution.expectation_met:
                break
        passed = all(item["outcome"] == "pass" for item in command_results) and all(
            item["expectation_met"] for item in target_results
        )
        result = {
            "schema_version": 1,
            "profile": profile.id,
            "safety_class": profile.safety_class.value,
            "status": "pass" if passed else "fail",
            "profile_config_sha256": profiles.config_sha256,
            "target_registry_hash": targets.config_hash,
            "command_results": command_results,
            "target_results": target_results,
            "failed_targets": [
                item["target"] for item in target_results if not item["expectation_met"]
            ],
            "external_required": list(profile.external_required),
        }
        run.write_json(
            "profile/result.json", result, schema="profile-result.schema.json"
        )
        run.complete()
    except BaseException as error:
        run.fail(error)
        raise
    summary = {"run": str(run.root), **result}
    _print_result(
        args.json,
        summary,
        _profile_summary_text(result, run.root),
    )
    return 0 if result["status"] == "pass" else 1


def _profile_summary_text(result: dict[str, Any], run_root: Path) -> str:
    lines = [
        f"run profile: {result['profile']} status={result['status']}; run={run_root}"
    ]
    for command in result["command_results"]:
        lines.append(f"command: {command['command']}; observed: {command['outcome']}")
    for target in result["target_results"]:
        lines.extend(
            [
                f"target: {target['target']}",
                f"engine: {target['engine']}",
                f"expected: {target['expected']}",
                f"observed: {target['outcome']}",
                f"result: {target['result_path']}",
                f"result_sha256: {target['result_sha256']}",
            ]
        )
    if result["failed_targets"]:
        lines.append(f"failed targets: {', '.join(result['failed_targets'])}")
    return "\n".join(lines)


def _evidence_pack(args: argparse.Namespace) -> int:
    result = pack_evidence(
        args.work_root,
        args.output,
        max_bytes=args.max_bytes,
        max_files=args.max_files,
    )
    _print_result(
        args.json,
        result,
        "evidence pack: "
        f"manifests={result['manifests']} files={result['files']} "
        f"bytes={result['bytes']} sha256={result['content_sha256']}; "
        f"output={result['output']}",
    )
    return 0


def _verify_handoff(args: argparse.Namespace) -> int:
    result = verify_handoff(args.handoff)
    _print_result(
        args.json,
        result,
        f"handoff preflight: verified {result['kind']}; handoff={result['handoff']}",
    )
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
