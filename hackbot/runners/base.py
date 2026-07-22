"""Shared dry-run / approve execution helper."""

from __future__ import annotations

import subprocess
import threading
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .. import ui
from ..config import get_config
from ..policy_guard import ScopePolicy, host_from_target
from ..procutil import kill_process_tree, popen_new_group_kwargs

# Re-export for callers that imported kill_process_tree from runners.base.
__all__ = [
    "RunnerResult",
    "kill_process_tree",
    "require_in_scope",
    "run_command",
]


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

    When action is empty, only target gates apply (OOS blocked unless force;
    NOT_CONFIRMED unless force). When action is set, full assert_action_allowed
    runs. Pass ``tool`` (tool id) so aggression/prohibited use the tool registry,
    not only free-text action labels.
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
            if force:
                return policy
            host = host_from_target(host_or_url)
            raise PermissionError(
                f"host out of scope: {host or host_or_url}. "
                "Remove from Out of Scope, or use /force (operator responsibility)."
            )
        if not policy.target_in_scope(host_or_url) and not force:
            raise PermissionError(
                f"target not confirmed in SCOPE.md: {host_or_url}. "
                "Add it to SCOPE or use /force (operator responsibility)."
            )
    return policy


def _default_cancel_check() -> bool:
    """Honor hunt stop + REPL interrupt while a subprocess is running."""
    try:
        from .. import hunt_controller

        if bool(getattr(hunt_controller, "_STOP_REQUESTED", False)):
            return True
    except Exception:  # noqa: BLE001
        pass
    try:
        from ..turn_bus import turn_cancel_requested

        return turn_cancel_requested()
    except Exception:  # noqa: BLE001
        return False


def run_command(
    command: list[str],
    *,
    approve: bool = False,
    cwd: Path | None = None,
    timeout: float | None = None,
    cancel_check: Callable[[], bool] | None = None,
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

    cfg_timeout = float(get_config().safety.subprocess_timeout_sec)
    limit = float(timeout) if timeout is not None else cfg_timeout
    limit = max(5.0, limit)
    cancel = cancel_check or _default_cancel_check

    popen_kwargs: dict[str, object] = {
        "cwd": str(cwd) if cwd else None,
        "stdout": subprocess.PIPE,
        "stderr": subprocess.PIPE,
        "text": True,
    }
    popen_kwargs.update(popen_new_group_kwargs())

    with ui.console.status("[cyan]running...[/]", spinner="dots"):
        proc = subprocess.Popen(command, **popen_kwargs)  # type: ignore[arg-type]
        stdout_chunks: list[str] = []
        stderr_chunks: list[str] = []

        def _drain(stream: Any, bucket: list[str]) -> None:
            if stream is None:
                return
            try:
                while True:
                    chunk = stream.read(4096)
                    if not chunk:
                        break
                    bucket.append(chunk)
            except Exception:  # noqa: BLE001
                pass

        # Drain pipes while waiting — a full stdout pipe freezes the child (and
        # stacked hung tools look like a frozen VM).
        readers = [
            threading.Thread(target=_drain, args=(proc.stdout, stdout_chunks), daemon=True),
            threading.Thread(target=_drain, args=(proc.stderr, stderr_chunks), daemon=True),
        ]
        for t in readers:
            t.start()
        stdout = ""
        stderr = ""
        message = "executed"
        returncode: int | None = None
        deadline = time.monotonic() + limit
        try:
            while True:
                if cancel():
                    kill_process_tree(proc)
                    message = "cancelled"
                    ui.warn("subprocess cancelled (hunt stop)")
                    break
                if time.monotonic() >= deadline:
                    kill_process_tree(proc)
                    message = "timeout"
                    ui.error(f"subprocess timed out after {limit:.0f}s")
                    break
                if proc.poll() is not None:
                    returncode = proc.returncode
                    break
                time.sleep(0.1)
        except Exception:  # noqa: BLE001
            kill_process_tree(proc)
            returncode = proc.returncode
            message = "error"
        for t in readers:
            t.join(timeout=2.0)
        stdout = "".join(stdout_chunks)
        stderr = "".join(stderr_chunks)
        if returncode is None:
            returncode = proc.returncode

    if stdout:
        ui.code_panel(stdout.rstrip(), title="stdout", lexer="text")
    if stderr:
        ui.code_panel(stderr.rstrip(), title="stderr", lexer="text")
    if message == "executed":
        if returncode == 0:
            ui.success(f"exit {returncode}")
        else:
            ui.error(f"exit {returncode}")
    return RunnerResult(
        command=command,
        executed=True,
        returncode=returncode,
        stdout=stdout or "",
        stderr=stderr or "",
        message=message,
    )
