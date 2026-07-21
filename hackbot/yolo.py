"""Session YOLO: skip y/n approve + soft-force.

YOLO does NOT mean endless autonomous chaining. Step mode (default ON) still
pauses after each meaningful hunt act for the operator.

Hard rail unchanged: explicit OUT_OF_SCOPE stays blocked.
Operator owns the risk. Password/secrets never live in this module.
"""

from __future__ import annotations

import os

from . import ui
from .audit import log_decision
from .force import disable_force, enable_force, is_forced

_YOLO_ACTIVE = False
_YOLO_ENABLED_FORCE = False

YOLO_BANNER = (
    "**YOLO ON - operator responsibility**\n\n"
    "Approve prompts are skipped. Soft SCOPE gates follow `/force` (ON with yolo).\n"
    "Explicit **OUT_OF_SCOPE** hosts stay hard-blocked.\n"
    "Lab tools may use local sudo (`.hackbot/sudo_pass` / `HACKBOT_SUDO_PASS`).\n"
    "Step mode still pauses after each hunt act - YOLO is not 'run forever'.\n\n"
    "Turn off with `/yolo off`. Full-budget loop: `HACKBOT_STEP_MODE=0`."
)


def is_yolo() -> bool:
    if _YOLO_ACTIVE:
        return True
    return os.environ.get("HACKBOT_YOLO", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def enable_yolo(*, quiet: bool = False) -> None:
    global _YOLO_ACTIVE, _YOLO_ENABLED_FORCE
    _YOLO_ACTIVE = True
    os.environ["HACKBOT_YOLO"] = "1"
    if not is_forced():
        enable_force()
        _YOLO_ENABLED_FORCE = True
    else:
        _YOLO_ENABLED_FORCE = False
    # Drop Codex resume so next turn gets danger-full-access (not old read-only session).
    try:
        from . import codex_backend

        codex_backend._CODEX_SESSION_READY = False
        codex_backend._CODEX_LAST_SANDBOX = None
    except Exception:  # noqa: BLE001
        pass
    if not quiet:
        ui.markdown_panel(YOLO_BANNER, title="yolo")
    log_decision("ALLOW", "yolo ON", kind="yolo", extra={"force": is_forced()})


def disable_yolo() -> None:
    global _YOLO_ACTIVE, _YOLO_ENABLED_FORCE
    _YOLO_ACTIVE = False
    os.environ.pop("HACKBOT_YOLO", None)
    if _YOLO_ENABLED_FORCE:
        disable_force()
        _YOLO_ENABLED_FORCE = False
    ui.success("yolo OFF — approve prompts back")
    log_decision("ALLOW", "yolo OFF", kind="yolo")


def boot_yolo_from_env() -> None:
    """Call once at REPL start if HACKBOT_YOLO already set."""
    if os.environ.get("HACKBOT_YOLO", "").strip().lower() in {"1", "true", "yes", "on"}:
        enable_yolo(quiet=False)


def yolo_auto_approve(description: str) -> bool:
    """Approve-fn used when YOLO is on (audited, no Confirm UI)."""
    log_decision("ALLOW", description, kind="yolo_approve")
    return True
