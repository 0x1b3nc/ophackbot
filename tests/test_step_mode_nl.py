"""Step mode session toggle + NL 'don't pause' detection."""

from __future__ import annotations

import os
import unittest

from hackbot import step_mode as step_mod
from hackbot.step_mode import (
    disable_step_mode,
    enable_step_mode,
    maybe_disable_from_prompt,
    step_mode_enabled,
)
from hackbot.tools import _normalize_tool_args


class StepModeSessionTests(unittest.TestCase):
    def setUp(self) -> None:
        step_mod._STEP_OVERRIDE = None
        os.environ.pop("HACKBOT_STEP_MODE", None)

    def tearDown(self) -> None:
        step_mod._STEP_OVERRIDE = None
        os.environ.pop("HACKBOT_STEP_MODE", None)

    def test_nl_disables_step_mode(self) -> None:
        self.assertTrue(step_mode_enabled())
        self.assertTrue(
            maybe_disable_from_prompt(
                "porque voce não só executa até achar a vulnerabilidade? para de ficar pausando"
            )
        )
        self.assertFalse(step_mode_enabled())

    def test_slash_style_toggle(self) -> None:
        disable_step_mode(quiet=True)
        self.assertFalse(step_mode_enabled())
        enable_step_mode(quiet=True)
        self.assertTrue(step_mode_enabled())

    def test_run_hunt_prompt_autofill(self) -> None:
        out = _normalize_tool_args(
            "run_hunt",
            {"target_dir": "targets/aylo", "approve": True},
        )
        self.assertTrue(out.get("prompt"))
        self.assertIn("hunt", out["prompt"].lower())


if __name__ == "__main__":
    unittest.main()
