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
    tool: str | None = None,
) -> ScopePolicy:
    """Load SCOPE and gate target URL/host (+ optional action aggression).

    When action is empty, only target gates apply (OOS hard-block; NOT_CONFIRMED
    unless force). When action is set, full assert_action_allowed runs. Pass
    ``tool`` (tool id) so aggression/prohibited use the tool registry, not only
    free-text action labels.
    """
    policy = ScopePolicy.load(target_dir)
    if action:
        policy.assert_action_allowed(
            host_or_url,
            action,
            force=force,
            tool=tool,
        )
    else:
        if policy.target_out_of_scope(host_or_url):
            host = host_from_target(host_or_url)
            raise PermissionError(
                f"host out of scope: {host or host_or_url} "
                "(OUT_OF_SCOPE cannot be overridden with /force)"
            )
        if not policy.target_in_scope(host_or_url) and not force:
            raise PermissionError(
                f"target not confirmed in SCOPE.md: {host_or_url}. "
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
