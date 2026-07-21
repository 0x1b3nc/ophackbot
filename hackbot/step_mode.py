"""Operator step mode: one meaningful step per turn, then wait.

YOLO skips y/n approve prompts. It does NOT authorize endless autonomous chaining.
Default ON (``HACKBOT_STEP_MODE=1``). Set to ``0`` for old full-budget hunt loops.
"""

from __future__ import annotations

import os

STEP_MODE_BLOCK = """
OPERATOR STEP MODE (default ON — HACKBOT_STEP_MODE=1):
- Do ONE meaningful step this turn (one hypothesis, one probe, or one validation).
- Then STOP: short result + ONE next-step suggestion. Wait for the operator.
- YOLO only skips y/n approve — it does NOT mean keep executing forever.
- Do not chain endless dry-runs, shell loops, or RESUME appends in one turn.
- After you finish the step, return control. The operator will say continue / resume.
"""


def step_mode_enabled() -> bool:
    raw = (os.environ.get("HACKBOT_STEP_MODE") or "1").strip().lower()
    return raw not in {"0", "false", "off", "no"}


def step_mode_preamble() -> str:
    return STEP_MODE_BLOCK if step_mode_enabled() else ""
