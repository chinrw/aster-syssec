from __future__ import annotations

import hashlib
import json
import re
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from ..engine_results import evidence_id
from ..schemas import validate_instance
from ..source import atomic_write_json

_TARGET = "pipe-partial-efault-linux-diff"
_CASE_ID = "pipe-partial-efault-read"
_COMPARATOR = "partial-efault-pipe-read-v1"
_FIELDS = (
    "return",
    "errno",
    "first_byte",
    "remaining_return",
    "remaining_errno",
    "remaining_byte_0",
    "remaining_byte_1",
)
_SHA256 = re.compile(r"^[0-9a-f]{64}$")


class PartialEfaultComparator:
    def compare(
        self,
        *,
        asterinas_result_path: str | Path,
        linux_result_path: str | Path,
        output_path: str | Path,
    ) -> dict[str, Any]:
        asterinas, asterinas_sha256 = _read_result(
            asterinas_result_path,
            label="Asterinas",
        )
        linux, linux_sha256 = _read_result(
            linux_result_path,
            label="Linux oracle",
        )
        _require_identity(asterinas, platform="asterinas", label="Asterinas")
        _require_identity(linux, platform="linux-oracle", label="Linux oracle")

        destination = Path(output_path).resolve()
        if destination.exists() or destination.is_symlink():
            raise ValueError(f"comparison output already exists: {destination}")

        diagnostics: list[str] = []
        asterinas_guest = _comparable_guest(asterinas, "Asterinas", diagnostics)
        linux_guest = _comparable_guest(linux, "linux-oracle", diagnostics)
        binary_sha256 = _common_binary_sha256(asterinas, linux, diagnostics)
        fields = _compare_fields(asterinas_guest, linux_guest, diagnostics)

        if diagnostics:
            status = "incomplete"
            disposition = "incomplete"
        elif all(field["matched"] for field in fields):
            status = "match"
            disposition = "baseline"
        else:
            status = "mismatch"
            disposition = "candidate"

        seed = {
            "comparator": _COMPARATOR,
            "asterinas_sha256": asterinas_sha256,
            "linux_sha256": linux_sha256,
            "status": status,
        }
        comparison = {
            "schema_version": 1,
            "comparison_id": evidence_id("ORACLE-COMPARISON", seed),
            "compared_at": datetime.now(UTC).isoformat(),
            "target": _TARGET,
            "case_id": _CASE_ID,
            "comparator": _COMPARATOR,
            "binary_sha256": binary_sha256,
            "asterinas_result": {
                "result_id": asterinas["result_id"],
                "sha256": asterinas_sha256,
            },
            "linux_result": {
                "result_id": linux["result_id"],
                "sha256": linux_sha256,
            },
            "status": status,
            "disposition": disposition,
            "fields": fields,
            "diagnostics": diagnostics,
        }
        validate_instance(comparison, "oracle-comparison.schema.json")
        atomic_write_json(destination, comparison)
        return comparison


def _read_result(
    value: str | Path,
    *,
    label: str,
) -> tuple[dict[str, Any], str]:
    path = Path(value).resolve(strict=True)
    if not path.is_file():
        raise ValueError(f"{label} runtime result is not a file: {path}")
    payload = path.read_bytes()
    try:
        result = json.loads(payload)
    except (UnicodeDecodeError, json.JSONDecodeError) as error:
        raise ValueError(f"{label} runtime result is not valid JSON") from error
    try:
        validate_instance(result, "runtime-result.schema.json")
    except ValueError as error:
        raise ValueError(f"{label} runtime result is invalid: {error}") from error
    return result, hashlib.sha256(payload).hexdigest()


def _require_identity(
    result: dict[str, Any],
    *,
    platform: str,
    label: str,
) -> None:
    if result["platform"] != platform:
        raise ValueError(f"{label} result requires {platform} platform")
    if result["target"] != _TARGET:
        raise ValueError(f"{label} result target is not {_TARGET}")
    guest = result["guest_result"]
    if result["outcome"] == "normal" and guest["case_id"] != _CASE_ID:
        raise ValueError(f"{label} result case is not {_CASE_ID}")


def _comparable_guest(
    result: dict[str, Any],
    label: str,
    diagnostics: list[str],
) -> dict[str, Any] | None:
    if result["outcome"] != "normal":
        diagnostics.append(f"{label} outcome is {result['outcome']}")
        return None
    guest = result["guest_result"]
    if guest["exit_kind"] != "normal":
        diagnostics.append(f"{label} guest exit_kind is {guest['exit_kind']}")
        return None
    return guest


def _common_binary_sha256(
    asterinas: dict[str, Any],
    linux: dict[str, Any],
    diagnostics: list[str],
) -> str | None:
    asterinas_sha256 = asterinas["tool"].get("binary_sha256")
    linux_sha256 = linux["tool"].get("binary_sha256")
    if not isinstance(asterinas_sha256, str) or not _SHA256.fullmatch(asterinas_sha256):
        diagnostics.append("Asterinas binary_sha256 is missing or invalid")
        return None
    if not isinstance(linux_sha256, str) or not _SHA256.fullmatch(linux_sha256):
        diagnostics.append("linux-oracle binary_sha256 is missing or invalid")
        return None
    if asterinas_sha256 != linux_sha256:
        diagnostics.append("runtime results used different static binaries")
        return None
    return asterinas_sha256


def _compare_fields(
    asterinas: dict[str, Any] | None,
    linux: dict[str, Any] | None,
    diagnostics: list[str],
) -> list[dict[str, Any]]:
    fields: list[dict[str, Any]] = []
    for name in _FIELDS:
        asterinas_value = asterinas.get(name) if asterinas is not None else None
        linux_value = linux.get(name) if linux is not None else None
        if asterinas is not None and type(asterinas_value) is not int:
            diagnostics.append(f"Asterinas guest result lacks integer field {name}")
        if linux is not None and type(linux_value) is not int:
            diagnostics.append(f"linux-oracle guest result lacks integer field {name}")
        fields.append(
            {
                "name": name,
                "relation": "equal",
                "asterinas": asterinas_value,
                "linux": linux_value,
                "matched": (
                    type(asterinas_value) is int
                    and type(linux_value) is int
                    and asterinas_value == linux_value
                ),
            }
        )
    return fields
