"""Operator step mode: one meaningful step per turn, then wait.

YOLO skips y/n approve prompts. It does NOT by itself authorize full-budget loops.
Default ON (``HACKBOT_STEP_MODE=1``). Disable with ``/step off``, ``HACKBOT_STEP_MODE=0``,
or natural language like "não pausa / até achar a vulnerabilidade".
"""

from __future__ import annotations

import os
import re

from . import ui
from .audit import log_decision

# None = follow env; True/False = session override from /step or NL.
_STEP_OVERRIDE: bool | None = None

STEP_MODE_BLOCK = """
OPERATOR STEP MODE (ON — HACKBOT_STEP_MODE=1 / /step on):
- Do ONE meaningful step this turn (one hypothesis, one probe, or one validation).
- Then STOP: short result + ONE next-step suggestion. Wait for the operator.
- YOLO only skips y/n approve — it does NOT mean keep executing forever.
- Do not chain endless dry-runs, shell loops, or RESUME appends in one turn.
- After you finish the step, return control. The operator will say continue / resume.
"""

FULL_HUNT_BLOCK = """
FULL HUNT MODE (step mode OFF):
- Keep executing until a finding candidate, hard blocker, or budget is exhausted.
- Prefer run_hunt (resume=true when paused) over tiny one-off probes.
- Still respect SCOPE / OUT_OF_SCOPE. Still one coherent hypothesis chain — no spam.
- Do NOT stop just to ask "continue?" unless you hit needs_setup / MFA / real blocker.
"""

# Operator wants unattended batches until finding.
_FULL_HUNT_RE = re.compile(
    r"(?i)("
    r"sem\s+pausar|n[aã]o\s+paus|para\s+de\s+(ficar\s+)?pausar|"
    r"n[aã]o\s+fica\s+pausando|stop\s+pausing|don'?t\s+pause|"
    r"at[eé]\s+achar|until\s+(you\s+)?find|keep\s+(going|hunting)|"
    r"full\s+budget|n[aã]o\s+pare|don'?t\s+stop|run\s+until|"
    r"executa\s+at[eé]|s[oó]\s+executa\s+at[eé]|sem\s+parar"
    r")"
)


def step_mode_enabled() -> bool:
    if _STEP_OVERRIDE is not None:
        return _STEP_OVERRIDE
    raw = (os.environ.get("HACKBOT_STEP_MODE") or "1").strip().lower()
    return raw not in {"0", "false", "off", "no"}


def enable_step_mode(*, quiet: bool = False) -> None:
    global _STEP_OVERRIDE
    _STEP_OVERRIDE = True
    os.environ["HACKBOT_STEP_MODE"] = "1"
    if not quiet:
        ui.info("step mode ON — pause after each hunt act")
    log_decision("ALLOW", "step mode ON", kind="step_mode")


def disable_step_mode(*, quiet: bool = False) -> None:
    global _STEP_OVERRIDE
    _STEP_OVERRIDE = False
    os.environ["HACKBOT_STEP_MODE"] = "0"
    if not quiet:
        ui.warn(
            "step mode OFF — hunt runs to finding / budget / blocker "
            "(not endless; still SCOPE-gated)"
        )
    log_decision("ALLOW", "step mode OFF", kind="step_mode")


def step_mode_preamble() -> str:
    return STEP_MODE_BLOCK if step_mode_enabled() else FULL_HUNT_BLOCK


def maybe_disable_from_prompt(text: str) -> bool:
    """If operator asks to stop pausing / hunt until finding, turn step mode off."""
    if not text or not _FULL_HUNT_RE.search(text):
        return False
    if not step_mode_enabled():
        return False
    disable_step_mode(quiet=False)
    return True
