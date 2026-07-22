"""Shared dry-run / approve execution helper."""

from __future__ import annotations

import os
import signal
import subprocess
import sys
import time
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path

from .. import ui
from ..config import get_config
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


def kill_process_tree(proc: subprocess.Popen[str]) -> None:
    """Best-effort terminate process and children (Windows taskkill / POSIX group)."""
    if proc.poll() is not None:
        return
    pid = proc.pid
    try:
        if sys.platform == "win32":
            subprocess.run(
                ["taskkill", "/F", "/T", "/PID", str(pid)],
                capture_output=True,
                check=False,
            )
        else:
            try:
                os.killpg(pid, signal.SIGTERM)
            except (ProcessLookupError, PermissionError, OSError):
                proc.terminate()
            deadline = time.monotonic() + 3.0
            while proc.poll() is None and time.monotonic() < deadline:
                time.sleep(0.05)
            if proc.poll() is None:
                try:
                    os.killpg(pid, signal.SIGKILL)
                except (ProcessLookupError, PermissionError, OSError):
                    proc.kill()
    except Exception:  # noqa: BLE001
        try:
            proc.kill()
        except Exception:  # noqa: BLE001
            pass


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
    if sys.platform != "win32":
        popen_kwargs["start_new_session"] = True
    else:
        # New process group so taskkill /T can reap children.
        popen_kwargs["creationflags"] = getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0)

    with ui.console.status("[cyan]running...[/]", spinner="dots"):
        proc = subprocess.Popen(command, **popen_kwargs)  # type: ignore[arg-type]
        stdout = ""
        stderr = ""
        message = "executed"
        returncode: int | None = None
        deadline = time.monotonic() + limit
        try:
            while True:
                if cancel():
                    kill_process_tree(proc)
                    stdout, stderr = proc.communicate(timeout=5)
                    returncode = proc.returncode
                    message = "cancelled"
                    ui.warn("subprocess cancelled (hunt stop)")
                    break
                if time.monotonic() >= deadline:
                    kill_process_tree(proc)
                    stdout, stderr = proc.communicate(timeout=5)
                    returncode = proc.returncode
                    message = "timeout"
                    ui.error(f"subprocess timed out after {limit:.0f}s")
                    break
                if proc.poll() is not None:
                    stdout, stderr = proc.communicate(timeout=5)
                    returncode = proc.returncode
                    break
                time.sleep(0.1)
        except Exception:  # noqa: BLE001
            kill_process_tree(proc)
            try:
                stdout, stderr = proc.communicate(timeout=5)
            except Exception:  # noqa: BLE001
                stdout, stderr = "", ""
            returncode = proc.returncode
            message = "error"

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
