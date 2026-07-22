"""Operator step mode: one hunt act then pause; YOLO ≠ endless."""

from __future__ import annotations

import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hackbot.hunt_controller import run_hunt
from hackbot.step_mode import step_mode_enabled, step_mode_preamble
from hackbot.yolo import YOLO_BANNER


SCOPE = """# Scope

## In Scope
- 127.0.0.1

## Explicitly Allowed
- Passive recon
- Automated scanning
- Active scanning
"""


class StepModeUnitTests(unittest.TestCase):
    def test_default_on(self) -> None:
        with mock.patch.dict(os.environ, {"HACKBOT_STEP_MODE": ""}, clear=False):
            os.environ.pop("HACKBOT_STEP_MODE", None)
            self.assertTrue(step_mode_enabled())
            self.assertIn("ONE meaningful step", step_mode_preamble())

    def test_can_disable(self) -> None:
        with mock.patch.dict(os.environ, {"HACKBOT_STEP_MODE": "0"}, clear=False):
            self.assertFalse(step_mode_enabled())
            self.assertIn("FULL HUNT MODE", step_mode_preamble())

    def test_yolo_banner_mentions_step_pause(self) -> None:
        self.assertIn("not", YOLO_BANNER.lower())
        self.assertIn("step mode", YOLO_BANNER.lower())


class HuntStepPauseTests(unittest.TestCase):
    def test_pauses_after_one_act(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        with mock.patch.dict(os.environ, {"HACKBOT_STEP_MODE": "1"}, clear=False):
            result = run_hunt(
                root,
                "explora o que der em 127.0.0.1",
                host="127.0.0.1",
                approve_session=False,
                budget=8,
                force=True,
            )
        self.assertTrue(result["ok"])
        self.assertEqual(result.get("stop_reason"), "paused_for_operator")
        self.assertEqual(int(result["acts_done"]), 1)
        self.assertGreater(int(result["budget_remaining"]), 0)

    def test_resume_after_step_pause(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        with mock.patch.dict(os.environ, {"HACKBOT_STEP_MODE": "1"}, clear=False):
            first = run_hunt(
                root,
                "explora o que der em 127.0.0.1",
                host="127.0.0.1",
                approve_session=False,
                budget=8,
                force=True,
            )
            self.assertEqual(first.get("stop_reason"), "paused_for_operator")
            second = run_hunt(
                root,
                "resume hunt",
                host="127.0.0.1",
                approve_session=False,
                budget=8,
                force=True,
                resume=True,
            )
        self.assertTrue(second["ok"])
        self.assertEqual(second.get("stop_reason"), "paused_for_operator")
        self.assertEqual(int(second["acts_done"]), 2)


if __name__ == "__main__":
    unittest.main()
