from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Iterable

from .config import Registry
from .models import Catalog, DispatchEntry, Drift, EvidenceCoverage, SyscallEntry
from .source import inspect_source


DISPATCH_RE = re.compile(
    r"(?m)^\s*(SYS_[A-Z0-9_]+)\s*=\s*(\d+)\s*=>\s*"
    r"(sys_[a-zA-Z0-9_]+)\s*\(\s*args\s*\[\s*\.\.\s*(\d+)\s*\]"
)
HANDLER_RE = re.compile(
    r"(?ms)\bpub(?:\([^)]*\))?\s+(?:async\s+)?fn\s+"
    r"(sys_[a-zA-Z0-9_]+)\s*\((.*?)\)\s*->"
)
SCML_CALL_RE = re.compile(r"(?m)^\s*([a-z][a-z0-9_]*)\s*\(")
IDENT_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")
SCML_ALIASES = {
    "get_priority": {"getpriority"},
    "set_priority": {"setpriority"},
    "rt_sigpending": {"sigpending"},
    "rt_sigsuspend": {"sigsuspend"},
}


@dataclass(frozen=True)
class _RawDispatch:
    name: str
    handler: str
    architecture: str
    number: int
    arity: int
    constant: str
    path: str
    line: int


@dataclass(frozen=True)
class _HandlerInfo:
    path: str
    line: int
    types: tuple[str, ...]
    user_pointers: tuple[str, ...]
    copy_in: tuple[str, ...]
    copy_out: tuple[str, ...]
    objects: tuple[str, ...]
    permission_checks: tuple[str, ...]
    locks_waits: tuple[str, ...]


class InventoryBuilder:
    def __init__(self, source_root: Path, registry: Registry):
        self.source_root = Path(source_root).resolve()
        self.registry = registry

    def build(self) -> Catalog:
        raw_dispatch = self._dispatch_entries()
        handlers = self._handler_index()
        scml_calls, scml_files = self._scml_index()
        test_identifiers, test_files = self._test_index()

        by_name: dict[str, list[_RawDispatch]] = defaultdict(list)
        handler_aliases: dict[str, set[str]] = defaultdict(set)
        for item in raw_dispatch:
            by_name[item.name].append(item)
            handler_aliases[item.handler].add(item.name)

        syscalls: list[SyscallEntry] = []
        for name in sorted(by_name):
            entries = by_name[name]
            handler = entries[0].handler
            handler_info = handlers.get(handler)
            aliases = handler_aliases[handler]
            evidence_aliases = set(aliases) | {handler.removeprefix("sys_")}
            for alias in tuple(evidence_aliases):
                evidence_aliases.update(SCML_ALIASES.get(alias, ()))
            scml_matches = sorted(
                {
                    file
                    for alias in evidence_aliases
                    for file in scml_files.get(alias, ())
                }
            )
            test_matches = sorted(
                {
                    file
                    for alias in aliases | {handler.removeprefix("sys_")}
                    for file in test_files.get(alias, ())
                }
            )
            architectures = {
                item.architecture: DispatchEntry(
                    number=item.number,
                    arity=item.arity,
                    constant=item.constant,
                    path=item.path,
                    line=item.line,
                )
                for item in entries
            }
            arities = [item.arity for item in entries]
            syscalls.append(
                SyscallEntry(
                    name=name,
                    handler=handler,
                    architectures=architectures,
                    handler_path=handler_info.path if handler_info else None,
                    handler_line=handler_info.line if handler_info else None,
                    raw_abi_argument_count=max(arities),
                    converted_rust_types=handler_info.types if handler_info else (),
                    user_pointers=handler_info.user_pointers if handler_info else (),
                    copy_in_operations=handler_info.copy_in if handler_info else (),
                    copy_out_operations=handler_info.copy_out if handler_info else (),
                    kernel_objects_reached=handler_info.objects if handler_info else (),
                    permission_checks=handler_info.permission_checks if handler_info else (),
                    locks_and_waits=handler_info.locks_waits if handler_info else (),
                    scml=EvidenceCoverage(
                        status="described" if scml_matches else "missing",
                        files=tuple(scml_matches[:50]),
                        reference_count=sum(scml_calls.get(alias, 0) for alias in evidence_aliases),
                    ),
                    regression=EvidenceCoverage(
                        status="referenced" if test_matches else "missing",
                        files=tuple(test_matches[:50]),
                        reference_count=sum(test_identifiers.get(alias, 0) for alias in aliases),
                    ),
                    security_tracks=self.registry.tracks_for_syscall(
                        name,
                        handler_info.path if handler_info else None,
                    ),
                )
            )

        drift = self._drift(
            raw_dispatch=raw_dispatch,
            handlers=handlers,
            scml_files=scml_files,
            syscalls=syscalls,
            handler_aliases=handler_aliases,
        )
        snapshot = inspect_source(self.source_root)
        return Catalog(
            source=snapshot.to_dict(),
            syscalls=tuple(syscalls),
            drift=tuple(drift),
        )

    def _dispatch_entries(self) -> list[_RawDispatch]:
        paths = {
            "x86_64": self.source_root / "kernel/core/src/syscall/arch/x86.rs",
            "riscv64": self.source_root / "kernel/core/src/syscall/arch/riscv.rs",
            "loongarch64": self.source_root / "kernel/core/src/syscall/arch/loongarch.rs",
        }
        generic_path = self.source_root / "kernel/core/src/syscall/arch/generic.rs"
        generic = self._parse_dispatch_file(generic_path, "generic")
        result: list[_RawDispatch] = []
        for architecture, path in paths.items():
            specific = self._parse_dispatch_file(path, architecture) if path.is_file() else []
            if architecture == "x86_64":
                result.extend(specific)
                continue
            merged = {item.name: item for item in generic}
            merged.update({item.name: item for item in specific})
            for item in merged.values():
                result.append(
                    _RawDispatch(
                        name=item.name,
                        handler=item.handler,
                        architecture=architecture,
                        number=item.number,
                        arity=item.arity,
                        constant=item.constant,
                        path=item.path,
                        line=item.line,
                    )
                )
        return result

    def _parse_dispatch_file(self, path: Path, architecture: str) -> list[_RawDispatch]:
        if not path.is_file():
            return []
        text = path.read_text(encoding="utf-8")
        relative = path.relative_to(self.source_root).as_posix()
        result: list[_RawDispatch] = []
        for match in DISPATCH_RE.finditer(text):
            constant, number, handler, arity = match.groups()
            result.append(
                _RawDispatch(
                    name=constant.removeprefix("SYS_").lower(),
                    handler=handler,
                    architecture=architecture,
                    number=int(number),
                    arity=int(arity),
                    constant=constant,
                    path=relative,
                    line=text.count("\n", 0, match.start()) + 1,
                )
            )
        return result

    def _handler_index(self) -> dict[str, _HandlerInfo]:
        syscall_root = self.source_root / "kernel/core/src/syscall"
        result: dict[str, _HandlerInfo] = {}
        if not syscall_root.is_dir():
            return result
        for path in sorted(syscall_root.rglob("*.rs")):
            if "/arch/" in path.as_posix():
                continue
            text = path.read_text(encoding="utf-8")
            relative = path.relative_to(self.source_root).as_posix()
            for match in HANDLER_RE.finditer(text):
                symbol, raw_params = match.groups()
                parameters = _split_parameters(raw_params)
                types = tuple(param_type for _, param_type in parameters)
                pointers = tuple(
                    name
                    for name, param_type in parameters
                    if "Vaddr" in param_type
                    or "VmReader" in param_type
                    or "VmWriter" in param_type
                    or any(token in name.lower() for token in ("ptr", "addr", "user_buf"))
                )
                result[symbol] = _HandlerInfo(
                    path=relative,
                    line=text.count("\n", 0, match.start()) + 1,
                    types=types,
                    user_pointers=pointers,
                    copy_in=_operation_names(text, _COPY_IN_PATTERNS),
                    copy_out=_operation_names(text, _COPY_OUT_PATTERNS),
                    objects=_operation_names(text, _OBJECT_PATTERNS),
                    permission_checks=_operation_names(text, _PERMISSION_PATTERNS),
                    locks_waits=_operation_names(text, _LOCK_WAIT_PATTERNS),
                )
        return result

    def _scml_index(self) -> tuple[dict[str, int], dict[str, set[str]]]:
        root = self.source_root / "book/src/kernel/linux-compatibility/syscall-flag-coverage"
        counts: dict[str, int] = defaultdict(int)
        files: dict[str, set[str]] = defaultdict(set)
        if not root.is_dir():
            return counts, files
        for path in sorted(root.rglob("*.scml")):
            text = _strip_line_comments(path.read_text(encoding="utf-8"))
            relative = path.relative_to(self.source_root).as_posix()
            for name in SCML_CALL_RE.findall(text):
                counts[name] += 1
                files[name].add(relative)
        return counts, files

    def _test_index(self) -> tuple[dict[str, int], dict[str, set[str]]]:
        root = self.source_root / "test/initramfs/src/regression"
        counts: dict[str, int] = defaultdict(int)
        files: dict[str, set[str]] = defaultdict(set)
        if not root.is_dir():
            return counts, files
        suffixes = {".c", ".h", ".rs", ".sh", ".S", ".s"}
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix not in suffixes:
                continue
            text = path.read_text(encoding="utf-8", errors="replace")
            relative = path.relative_to(self.source_root).as_posix()
            identifiers = IDENT_RE.findall(text)
            for name in identifiers:
                normalized = name.removeprefix("SYS_").lower() if name.startswith("SYS_") else name
                counts[normalized] += 1
                files[normalized].add(relative)
        return counts, files

    def _drift(
        self,
        *,
        raw_dispatch: list[_RawDispatch],
        handlers: dict[str, _HandlerInfo],
        scml_files: dict[str, set[str]],
        syscalls: list[SyscallEntry],
        handler_aliases: dict[str, set[str]],
    ) -> list[Drift]:
        drift: list[Drift] = []
        number_index: dict[tuple[str, int], _RawDispatch] = {}
        for item in raw_dispatch:
            key = (item.architecture, item.number)
            previous = number_index.get(key)
            if previous and (previous.name != item.name or previous.handler != item.handler):
                drift.append(
                    Drift(
                        kind="duplicate-syscall-number",
                        severity="error",
                        syscall=item.name,
                        path=item.path,
                        message=(
                            f"{item.architecture} syscall number {item.number} maps to both "
                            f"{previous.name} and {item.name}"
                        ),
                    )
                )
            else:
                number_index[key] = item

        seen_missing_handlers: set[str] = set()
        for item in syscalls:
            if item.handler not in handlers and item.handler not in seen_missing_handlers:
                seen_missing_handlers.add(item.handler)
                drift.append(
                    Drift(
                        kind="handler-missing",
                        severity="error",
                        syscall=item.name,
                        path=next(iter(item.architectures.values())).path,
                        message=f"dispatch references {item.handler}, but no handler definition was found",
                    )
                )
            if item.scml.status == "missing":
                drift.append(
                    Drift(
                        kind="scml-coverage-missing",
                        severity="warning",
                        syscall=item.name,
                        path=item.handler_path,
                        message=f"{item.name} is dispatched but has no matching SCML declaration",
                    )
                )
            if item.regression.status == "missing":
                drift.append(
                    Drift(
                        kind="regression-coverage-missing",
                        severity="warning",
                        syscall=item.name,
                        path=item.handler_path,
                        message=f"{item.name} is dispatched but is not referenced by regression sources",
                    )
                )

        handler_arities: dict[str, set[int]] = defaultdict(set)
        handler_paths: dict[str, str] = {}
        for item in raw_dispatch:
            handler_arities[item.handler].add(item.arity)
            handler_paths[item.handler] = item.path
        for handler, arities in sorted(handler_arities.items()):
            if len(arities) > 1:
                drift.append(
                    Drift(
                        kind="architecture-arity-mismatch",
                        severity="warning",
                        syscall=handler.removeprefix("sys_"),
                        path=handler_paths[handler],
                        message=f"{handler} is dispatched with architecture arities {sorted(arities)}",
                    )
                )

        known_scml_names = {
            alias
            for aliases in handler_aliases.values()
            for alias in aliases
        } | {handler.removeprefix("sys_") for handler in handler_aliases}
        for name in tuple(known_scml_names):
            known_scml_names.update(SCML_ALIASES.get(name, ()))
        for name, paths in sorted(scml_files.items()):
            if name not in known_scml_names:
                drift.append(
                    Drift(
                        kind="scml-without-dispatch",
                        severity="warning",
                        syscall=name,
                        path=sorted(paths)[0],
                        message=f"SCML declares {name}, but no matching dispatched handler was found",
                    )
                )
        return sorted(drift, key=lambda item: (item.severity != "error", item.kind, item.syscall or ""))


def compare_baseline(catalog: Catalog, baseline: dict[str, Any]) -> tuple[Drift, ...]:
    if baseline.get("schema_version") != 1 or not isinstance(baseline.get("syscalls"), list):
        raise ValueError("baseline catalog must be a schema_version 1 syscall catalog")
    baseline_by_name = {item["name"]: item for item in baseline["syscalls"]}
    additions: list[Drift] = []
    for current in catalog.syscalls:
        previous = baseline_by_name.get(current.name)
        if previous is None:
            missing = []
            if current.scml.status != "described":
                missing.append("SCML")
            if current.regression.status != "referenced":
                missing.append("regression")
            additions.append(
                Drift(
                    kind="new-syscall-evidence-missing" if missing else "new-syscall",
                    severity="error" if missing else "info",
                    syscall=current.name,
                    path=current.handler_path,
                    message=(
                        f"new syscall {current.name} lacks {', '.join(missing)} evidence"
                        if missing
                        else f"new syscall {current.name} has handler, SCML, and regression evidence"
                    ),
                )
            )
            continue

        if previous.get("handler") != current.handler:
            additions.append(
                Drift(
                    kind="dispatch-handler-changed",
                    severity="error",
                    syscall=current.name,
                    path=current.handler_path,
                    message=(
                        f"{current.name} handler changed from {previous.get('handler')} to {current.handler}"
                    ),
                )
            )
        previous_arches = previous.get("architectures", {})
        current_arches = {
            architecture: {"number": entry.number, "arity": entry.arity}
            for architecture, entry in current.architectures.items()
        }
        for architecture in sorted(set(previous_arches) | set(current_arches)):
            old = previous_arches.get(architecture)
            new = current_arches.get(architecture)
            old_shape = (
                {"number": old.get("number"), "arity": old.get("arity")} if isinstance(old, dict) else None
            )
            if old_shape != new:
                additions.append(
                    Drift(
                        kind="architecture-dispatch-changed",
                        severity="error",
                        syscall=current.name,
                        path=current.handler_path,
                        message=f"{current.name} {architecture} dispatch changed from {old_shape} to {new}",
                    )
                )
        if previous.get("scml", {}).get("status") == "described" and current.scml.status != "described":
            additions.append(
                Drift(
                    kind="scml-coverage-regressed",
                    severity="error",
                    syscall=current.name,
                    path=current.handler_path,
                    message=f"{current.name} lost its baseline SCML evidence",
                )
            )
        if previous.get("regression", {}).get("status") == "referenced" and current.regression.status != "referenced":
            additions.append(
                Drift(
                    kind="regression-coverage-regressed",
                    severity="error",
                    syscall=current.name,
                    path=current.handler_path,
                    message=f"{current.name} lost its baseline regression reference",
                )
            )
    current_names = {item.name for item in catalog.syscalls}
    for removed in sorted(set(baseline_by_name) - current_names):
        additions.append(
            Drift(
                kind="syscall-removed",
                severity="error",
                syscall=removed,
                message=f"baseline syscall {removed} is no longer dispatched",
            )
        )
    return tuple(additions)


def _split_parameters(raw: str) -> list[tuple[str, str]]:
    result: list[tuple[str, str]] = []
    current: list[str] = []
    depth = 0
    for char in raw:
        if char in "(<[{":
            depth += 1
        elif char in ")>]}":
            depth = max(depth - 1, 0)
        if char == "," and depth == 0:
            _append_parameter(result, "".join(current))
            current = []
        else:
            current.append(char)
    _append_parameter(result, "".join(current))
    return result


def _append_parameter(result: list[tuple[str, str]], raw: str) -> None:
    raw = raw.strip()
    if not raw or ":" not in raw:
        return
    name, param_type = raw.split(":", 1)
    result.append((name.strip().removeprefix("mut "), " ".join(param_type.split())))


def _strip_line_comments(text: str) -> str:
    return "\n".join(line.split("//", 1)[0] for line in text.splitlines())


def _operation_names(text: str, patterns: Iterable[tuple[str, re.Pattern[str]]]) -> tuple[str, ...]:
    return tuple(name for name, pattern in patterns if pattern.search(text))


_COPY_IN_PATTERNS = (
    ("read_val", re.compile(r"\bread_val\s*\(")),
    ("read_slice", re.compile(r"\bread_slice\s*\(")),
    ("read_bytes", re.compile(r"\bread_bytes\s*\(")),
    ("reader", re.compile(r"\.reader\s*\(")),
    ("copy_from_user", re.compile(r"\bcopy_[a-z_]*from_user\b")),
)
_COPY_OUT_PATTERNS = (
    ("write_val", re.compile(r"\bwrite_val\s*\(")),
    ("write_slice", re.compile(r"\bwrite_slice\s*\(")),
    ("write_bytes", re.compile(r"\bwrite_bytes\s*\(")),
    ("writer", re.compile(r"\.writer\s*\(")),
    ("copy_to_user", re.compile(r"\bcopy_[a-z_]*to_user\b")),
)
_OBJECT_PATTERNS = (
    ("file-table", re.compile(r"\b(?:get_file|file_table|add_file)\b")),
    ("socket", re.compile(r"\b(?:socket|as_socket_or_err)\b")),
    ("vma", re.compile(r"\b(?:vmar|vma|page_fault)\b")),
    ("process", re.compile(r"\b(?:process|thread|task)\b")),
    ("credentials", re.compile(r"\b(?:credential|capability|CapSet)\b")),
)
_PERMISSION_PATTERNS = (
    ("capability-check", re.compile(r"\b(?:check_[a-z_]*cap|CapSet::|capable)\b")),
    ("access-check", re.compile(r"\b(?:check_[a-z_]*(?:access|permission)|may_[a-z_]+)\b")),
)
_LOCK_WAIT_PATTERNS = (
    ("lock", re.compile(r"\.(?:lock|read|write)\s*\(")),
    ("file-table-borrow", re.compile(r"borrow_file_table")),
    ("wait", re.compile(r"\b(?:wait|poll|sleep|recvmsg)\s*\(")),
)
