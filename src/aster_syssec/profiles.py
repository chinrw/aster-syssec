from __future__ import annotations

import hashlib
import tomllib
from dataclasses import dataclass
from importlib import resources
from pathlib import Path

from .safety import SafetyClass


@dataclass(frozen=True)
class VerificationProfile:
    id: str
    safety_class: SafetyClass
    commands: tuple[str, ...]
    targets: tuple[str, ...]
    external_required: tuple[str, ...]
    fail_fast: bool


@dataclass(frozen=True)
class ProfileRegistry:
    profiles: dict[str, VerificationProfile]
    config_sha256: str

    def require(self, profile_id: str) -> VerificationProfile:
        try:
            return self.profiles[profile_id]
        except KeyError as error:
            choices = ", ".join(sorted(self.profiles))
            raise ValueError(
                f"unknown verification profile {profile_id!r}; choose one of: {choices}"
            ) from error


def load_profile_registry(path: Path | None = None) -> ProfileRegistry:
    config = (
        Path(path).resolve()
        if path is not None
        else Path(
            str(resources.files("aster_syssec").joinpath("data/ci-profiles.toml"))
        )
    )
    if not config.is_file():
        raise ValueError(f"verification profile config does not exist: {config}")
    payload = config.read_bytes()
    try:
        parsed = tomllib.loads(payload.decode("utf-8"))
    except (UnicodeDecodeError, tomllib.TOMLDecodeError) as error:
        raise ValueError(f"invalid verification profile config: {error}") from error
    if parsed.get("version") != 1 or not isinstance(parsed.get("profiles"), dict):
        raise ValueError("verification profile config must contain version 1 profiles")
    profiles: dict[str, VerificationProfile] = {}
    for profile_id, item in parsed["profiles"].items():
        if not isinstance(item, dict):
            raise TypeError(f"verification profile must be an object: {profile_id}")
        allowed = {
            "implemented_commands",
            "safety_class",
            "targets",
            "external_required",
            "blocking",
            "fail_fast",
        }
        unknown = sorted(set(item) - allowed)
        if unknown:
            raise ValueError(
                f"verification profile {profile_id} has unknown keys: {unknown}"
            )
        safety_class = item.get("safety_class")
        if not isinstance(safety_class, str):
            raise TypeError(
                f"verification profile {profile_id} must declare safety_class"
            )
        try:
            parsed_safety_class = SafetyClass(safety_class)
        except ValueError as error:
            raise ValueError(
                f"verification profile {profile_id} has unknown safety_class: {safety_class}"
            ) from error
        profiles[profile_id] = VerificationProfile(
            id=profile_id,
            safety_class=parsed_safety_class,
            commands=_string_tuple(item.get("implemented_commands", []), profile_id),
            targets=_string_tuple(item.get("targets", []), profile_id),
            external_required=_string_tuple(
                item.get("external_required", []), profile_id
            ),
            fail_fast=bool(item.get("fail_fast", True)),
        )
    return ProfileRegistry(
        profiles=profiles,
        config_sha256=hashlib.sha256(payload).hexdigest(),
    )


def _string_tuple(value: object, profile_id: str) -> tuple[str, ...]:
    if not isinstance(value, list) or any(not isinstance(item, str) for item in value):
        raise ValueError(f"verification profile {profile_id} entries must be strings")
    return tuple(value)
