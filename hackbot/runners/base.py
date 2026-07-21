"""Shared dry-run / approve execution helper."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from ..policy_guard import ScopePolicy, host_from_target


@dataclass(frozen=True)
class RunnerResult:
    command: list[str]
    executed: bool
    returncode: int | None
    stdout: str
    stderr: str
    message: str


def require_in_scope(target_dir: Path, host_or_url: str) -> ScopePolicy:
    policy = ScopePolicy.load(target_dir)
    host = host_from_target(host_or_url)
    policy.assert_host_allowed(host)
    return policy


def run_command(
    command: list[str],
    *,
    approve: bool = False,
    cwd: Path | None = None,
) -> RunnerResult:
    printable = " ".join(command)
    print(f"command: {printable}")
    if not approve:
        print("dry-run: pass --approve to execute")
        return RunnerResult(
            command=command,
            executed=False,
            returncode=None,
            stdout="",
            stderr="",
            message="dry-run",
        )
    completed = subprocess.run(
        command,
        cwd=str(cwd) if cwd else None,
        capture_output=True,
        text=True,
        check=False,
    )
    if completed.stdout:
        print(completed.stdout)
    if completed.stderr:
        print(completed.stderr, end="")
    return RunnerResult(
        command=command,
        executed=True,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        message="executed",
    )
