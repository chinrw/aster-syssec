from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from datetime import datetime
from pathlib import Path
from typing import Any

from aster_syssec.schemas import validate_instance

from . import __version__


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="syssec-lab",
        description="Authorization-gated aster-syssec Lab boundary",
    )
    parser.add_argument(
        "--version", action="version", version=f"aster-syssec-lab {__version__}"
    )
    commands = parser.add_subparsers(dest="command", required=True)

    boundary = commands.add_parser(
        "boundary", help="report the Lab package execution boundary"
    )
    boundary.add_argument("--json", action="store_true")
    boundary.set_defaults(handler=_boundary)

    authorization = commands.add_parser(
        "authorization", help="validate a Lab authorization document"
    )
    authorization_commands = authorization.add_subparsers(
        dest="authorization_command", required=True
    )
    check = authorization_commands.add_parser(
        "check", help="validate authorization without executing a Lab case"
    )
    check.add_argument("--file", required=True, type=Path)
    check.add_argument("--json", action="store_true")
    check.set_defaults(handler=_authorization_check)
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    try:
        return int(args.handler(args))
    except (OSError, TypeError, ValueError, json.JSONDecodeError) as error:
        print(f"syssec-lab: {error}", file=sys.stderr)
        return 2


def _boundary(args: argparse.Namespace) -> int:
    result = {
        "schema_version": 1,
        "safety_class": "lab",
        "execution_available": False,
        "authorization_required": True,
        "environment": "isolated-vm",
        "network": "off",
        "agent_mode": "manual-only",
        "evidence_root": "separate-required",
    }
    _print_result(args.json, result)
    return 0


def _authorization_check(args: argparse.Namespace) -> int:
    path = args.file.expanduser().resolve()
    value = _read_json_object(path)
    validate_instance(value, "lab-authorization.schema.json")
    approved_at = _date_time(value["approved_at"])
    expires_at = _date_time(value["expires_at"])
    if expires_at <= approved_at:
        raise ValueError("Lab authorization expires_at must follow approved_at")
    if expires_at <= datetime.now(expires_at.tzinfo):
        raise ValueError("Lab authorization has expired")
    result = {
        "schema_version": 1,
        "status": "valid",
        "authorization_id": value["authorization_id"],
        "repository": value["repository"],
        "revision": value["revision"],
        "expires_at": value["expires_at"],
        "executed": False,
    }
    _print_result(args.json, result)
    return 0


def _read_json_object(path: Path) -> dict[str, Any]:
    value = json.loads(path.read_text(encoding="utf-8"))
    if not isinstance(value, dict):
        raise TypeError("Lab authorization must be a JSON object")
    return value


def _date_time(value: str) -> datetime:
    return datetime.fromisoformat(value)


def _print_result(as_json: bool, result: dict[str, object]) -> None:
    if as_json:
        print(json.dumps(result, indent=2, sort_keys=True))
        return
    print("\n".join(f"{key}: {value}" for key, value in result.items()))
