from __future__ import annotations

import json

from ..schemas import validate_instance

BEGIN_MARKER = "SYSSEC_RESULT_BEGIN"
END_MARKER = "SYSSEC_RESULT_END"


class GuestProtocolError(ValueError):
    def __init__(self, code: str, message: str) -> None:
        self.code = code
        super().__init__(message)


def _reject_json_constant(value: str) -> object:
    raise ValueError(f"non-standard JSON constant: {value}")


def parse_guest_result(
    output: bytes,
    *,
    max_output_bytes: int,
) -> dict[str, object]:
    if len(output) > max_output_bytes:
        raise GuestProtocolError(
            "output-too-large",
            "guest output exceeds the configured limit",
        )

    try:
        text = output.decode("utf-8")
    except UnicodeDecodeError as error:
        raise GuestProtocolError(
            "non-utf8",
            "guest output is not valid UTF-8",
        ) from error

    lines = text.splitlines()
    if BEGIN_MARKER not in lines:
        raise GuestProtocolError(
            "missing-begin-marker",
            "guest output has no result begin marker",
        )
    if END_MARKER not in lines:
        raise GuestProtocolError(
            "missing-end-marker",
            "guest output has no result end marker",
        )
    if lines.count(BEGIN_MARKER) > 1:
        raise GuestProtocolError(
            "duplicate-begin-marker",
            "guest output has more than one result begin marker",
        )
    if lines.count(END_MARKER) > 1:
        raise GuestProtocolError(
            "duplicate-end-marker",
            "guest output has more than one result end marker",
        )
    begin = lines.index(BEGIN_MARKER)
    end = lines.index(END_MARKER)
    if end < begin:
        raise GuestProtocolError(
            "invalid-marker-order",
            "guest result end marker precedes its begin marker",
        )
    payload = "\n".join(lines[begin + 1 : end]).lstrip()
    try:
        decoder = json.JSONDecoder(parse_constant=_reject_json_constant)
        value, consumed = decoder.raw_decode(payload)
    except (json.JSONDecodeError, ValueError) as error:
        raise GuestProtocolError(
            "invalid-json",
            "guest result is not valid JSON",
        ) from error
    if payload[consumed:].strip():
        raise GuestProtocolError(
            "extra-result-content",
            "guest result contains content after its JSON value",
        )
    if not isinstance(value, dict):
        raise GuestProtocolError(
            "non-object",
            "guest result must be a JSON object",
        )
    try:
        validate_instance(value, "guest-result.schema.json")
    except ValueError as error:
        raise GuestProtocolError(
            "invalid-guest-result",
            "guest result does not match its schema",
        ) from error
    return value
