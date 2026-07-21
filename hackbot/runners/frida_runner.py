"""Frida / Objection helpers — approve-gated, lab/bounty only.

Does not silently hook apps. Operator must approve; scripts are templates under
frida_scripts/ (SSL unpin checklist style). No credential theft payloads.
"""

from __future__ import annotations

import json
import shutil
import subprocess
from pathlib import Path
from typing import Any

from .. import ui
from .base import RunnerResult

SCRIPTS_DIR = Path(__file__).resolve().parent / "frida_scripts"

ALLOWED_SCRIPTS = {
    "ssl_unpin_lab.js": "Lab SSL unpin template (authorized builds only)",
    "enumerate_classes.js": "Enumerate loaded class names (capped)",
}


def frida_available() -> bool:
    return bool(shutil.which("frida") or shutil.which("frida-ps"))


def objection_available() -> bool:
    return bool(shutil.which("objection"))


def frida_status() -> dict[str, Any]:
    return {
        "ok": True,
        "frida": frida_available(),
        "frida_path": shutil.which("frida") or shutil.which("frida-ps"),
        "objection": objection_available(),
        "objection_path": shutil.which("objection"),
        "scripts": [
            {"name": n, "desc": d, "path": str(SCRIPTS_DIR / n)}
            for n, d in ALLOWED_SCRIPTS.items()
            if (SCRIPTS_DIR / n).exists()
        ],
        "hint": (
            "Hooks require approve + in-scope lab/bounty app. "
            "Example: frida_run_script --script ssl_unpin_lab.js --package com.example.app approve"
        ),
        "auto_hook": False,
    }


def frida_list_apps(*, timeout: float = 15.0) -> dict[str, Any]:
    exe = shutil.which("frida-ps") or shutil.which("frida")
    if not exe:
        return {"ok": True, "wired": False, "apps": [], "error": "frida_missing"}
    cmd = [exe, "-Uai"] if "frida-ps" in exe else [exe, "ps", "-Uai"]
    if exe.endswith("frida") or exe.endswith("frida.exe"):
        # frida CLI may not list; prefer frida-ps
        ps = shutil.which("frida-ps")
        if ps:
            cmd = [ps, "-Uai"]
        else:
            return {"ok": False, "error": "frida-ps_missing", "hint": "pip install frida-tools"}
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, check=False)
    except (OSError, subprocess.TimeoutExpired) as exc:
        return {"ok": False, "error": type(exc).__name__, "detail": str(exc)[:200]}
    apps = []
    for line in (proc.stdout or "").splitlines()[1:]:
        parts = line.split()
        if len(parts) >= 2:
            apps.append({"pid": parts[0], "name": " ".join(parts[1:])[:120]})
        if len(apps) >= 80:
            break
    return {"ok": True, "wired": True, "count": len(apps), "apps": apps, "stderr": (proc.stderr or "")[:200]}


def frida_run_script(
    *,
    package: str,
    script: str = "ssl_unpin_lab.js",
    approve: bool = False,
    spawn: bool = True,
    timeout: float = 45.0,
) -> RunnerResult:
    """Attach/spawn with an allowlisted script. Requires approve."""
    plan = {"package": package, "script": script, "spawn": spawn, "approve": approve}
    ui.code_panel(json.dumps(plan, indent=2), title="frida_run_script", lexer="json")
    cmd = ["frida", "-U", package, "-l", script]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    if script not in ALLOWED_SCRIPTS:
        return RunnerResult(
            cmd,
            False,
            None,
            json.dumps(
                {
                    "ok": False,
                    "error": "script_not_allowlisted",
                    "allowed": list(ALLOWED_SCRIPTS),
                }
            ),
            "",
            "error",
        )
    script_path = SCRIPTS_DIR / script
    if not script_path.exists():
        return RunnerResult(cmd, False, None, json.dumps({"ok": False, "error": "script_missing"}), "", "error")

    frida = shutil.which("frida")
    if not frida:
        return RunnerResult(
            cmd,
            False,
            None,
            json.dumps({"ok": False, "error": "frida_missing", "hint": "pip install frida-tools"}),
            "",
            "error",
        )

    args = [frida, "-U"]
    if spawn:
        args += ["-f", package, "-l", str(script_path), "--no-pause"]
    else:
        args += ["-n", package, "-l", str(script_path)]
    # Cap runtime: use timeout then kill — avoid hanging REPL
    try:
        proc = subprocess.run(
            args,
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        out = (exc.stdout or b"").decode("utf-8", errors="replace") if isinstance(exc.stdout, bytes) else (exc.stdout or "")
        err = (exc.stderr or b"").decode("utf-8", errors="replace") if isinstance(exc.stderr, bytes) else (exc.stderr or "")
        return RunnerResult(
            args,
            True,
            0,
            json.dumps(
                {
                    "ok": True,
                    "timed_out": True,
                    "stdout_preview": out[:1500],
                    "stderr_preview": err[:500],
                    "hint": "Process timed out (expected for long attach). Check device logs.",
                }
            ),
            "",
            "executed",
        )
    except OSError as exc:
        return RunnerResult(args, False, None, json.dumps({"ok": False, "error": str(exc)}), "", "error")

    return RunnerResult(
        args,
        True,
        proc.returncode,
        json.dumps(
            {
                "ok": proc.returncode == 0,
                "returncode": proc.returncode,
                "stdout_preview": (proc.stdout or "")[:1500],
                "stderr_preview": (proc.stderr or "")[:500],
            }
        ),
        "",
        "executed",
    )


def objection_explore(
    *,
    package: str,
    approve: bool = False,
    timeout: float = 20.0,
) -> RunnerResult:
    """Start objection explore (non-interactive smoke). Approve required."""
    plan = {"package": package, "approve": approve}
    cmd = ["objection", "-g", package, "explore"]
    ui.code_panel(json.dumps(plan, indent=2), title="objection_explore", lexer="json")
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")
    exe = shutil.which("objection")
    if not exe:
        return RunnerResult(cmd, False, None, json.dumps({"ok": False, "error": "objection_missing"}), "", "error")
    # Non-interactive: run `env` then exit via echo
    try:
        proc = subprocess.run(
            [exe, "-g", package, "explore", "-c", "env"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired) as exc:
        return RunnerResult(cmd, False, None, json.dumps({"ok": False, "error": type(exc).__name__}), "", "error")
    return RunnerResult(
        cmd,
        True,
        proc.returncode,
        json.dumps(
            {
                "ok": True,
                "stdout_preview": (proc.stdout or "")[:1200],
                "stderr_preview": (proc.stderr or "")[:400],
            }
        ),
        "",
        "executed",
    )
