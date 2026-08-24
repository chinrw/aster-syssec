from __future__ import annotations

import os
import shutil
import signal
import subprocess
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from pathlib import Path


@dataclass(frozen=True)
class ProcessResult:
    stdout: str
    stderr: str
    returncode: int | None
    timed_out: bool
    duration_ms: int

    @property
    def signal(self) -> int | None:
        return (
            -self.returncode
            if self.returncode is not None and self.returncode < 0
            else None
        )

    @property
    def exit_code(self) -> int | None:
        return (
            self.returncode
            if self.returncode is not None and self.returncode >= 0
            else None
        )


def run_process(
    argv: Sequence[str],
    *,
    cwd: Path,
    environment: Mapping[str, str],
    timeout_seconds: int,
    memory_bytes: int,
) -> ProcessResult:
    started = time.monotonic()
    prlimit = shutil.which("prlimit")
    if prlimit is None:
        raise RuntimeError("engine execution requires prlimit to enforce memory limits")
    command = [prlimit, f"--as={memory_bytes}", "--", *argv]
    process = subprocess.Popen(
        command,
        cwd=cwd,
        env=dict(environment),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        start_new_session=True,
    )
    try:
        stdout, stderr = process.communicate(timeout=timeout_seconds)
        timed_out = False
    except subprocess.TimeoutExpired:
        os.killpg(process.pid, signal.SIGKILL)
        stdout, stderr = process.communicate()
        timed_out = True
    duration_ms = max(0, round((time.monotonic() - started) * 1000))
    return ProcessResult(
        stdout=stdout,
        stderr=stderr,
        returncode=process.returncode,
        timed_out=timed_out,
        duration_ms=duration_ms,
    )
