"""Shared dry-run / approve execution helper."""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from pathlib import Path

from .. import ui
from ..policy_guard import ScopePolicy, host_from_target


@dataclass(frozen=True)
class RunnerResult:
    command: list[str]
    executed: bool
    returncode: int | None
    stdout: str
    stderr: str
    message: str


def require_in_scope(
    target_dir: Path,
    host_or_url: str,
    *,
    action: str = "",
    force: bool = False,
) -> ScopePolicy:
    """Load SCOPE and gate host (+ optional action aggression).

    When action is empty, only host gates apply (OOS hard-block; NOT_CONFIRMED
    unless force). When action is set, full assert_action_allowed runs.
    """
    policy = ScopePolicy.load(target_dir)
    host = host_from_target(host_or_url)
    if action:
        policy.assert_action_allowed(host, action, force=force)
    else:
        if policy.is_explicitly_out_of_scope(host):
            raise PermissionError(
                f"host out of scope: {host} "
                "(OUT_OF_SCOPE cannot be overridden with /force)"
            )
        if not policy.contains_host(host) and not force:
            raise PermissionError(
                f"host not confirmed in SCOPE.md: {host}. "
                "Add it to SCOPE or use /force (operator responsibility)."
            )
    return policy


def run_command(
    command: list[str],
    *,
    approve: bool = False,
    cwd: Path | None = None,
) -> RunnerResult:
    printable = " ".join(command)
    ui.code_panel(printable, title="command", lexer="bash")
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(
            command=command,
            executed=False,
            returncode=None,
            stdout="",
            stderr="",
            message="dry-run",
        )
    with ui.console.status("[cyan]running...[/]", spinner="dots"):
        completed = subprocess.run(
            command,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            check=False,
        )
    if completed.stdout:
        ui.code_panel(completed.stdout.rstrip(), title="stdout", lexer="text")
    if completed.stderr:
        ui.code_panel(completed.stderr.rstrip(), title="stderr", lexer="text")
    if completed.returncode == 0:
        ui.success(f"exit {completed.returncode}")
    else:
        ui.error(f"exit {completed.returncode}")
    return RunnerResult(
        command=command,
        executed=True,
        returncode=completed.returncode,
        stdout=completed.stdout,
        stderr=completed.stderr,
        message="executed",
    )
