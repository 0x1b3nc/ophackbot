"""Regression tests for the 12-bug audit fixes."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hackbot import force as force_mod
from hackbot.policy_guard import ScopePolicy
from hackbot.turn_bus import (
    begin_turn_epoch,
    bind_turn_epoch,
    bump_cancel_epoch,
    clear_turn_cancel,
    current_cancel_epoch,
    reset_turn_epoch,
    turn_cancel_requested,
)


class CancelEpochTests(unittest.TestCase):
    def tearDown(self) -> None:
        clear_turn_cancel()

    def test_old_turn_stays_cancelled_after_clear(self) -> None:
        epoch = begin_turn_epoch()
        token = bind_turn_epoch(epoch)
        try:
            self.assertFalse(turn_cancel_requested())
            bump_cancel_epoch()
            self.assertTrue(turn_cancel_requested())
            # Next turn clears flags but old epoch remains cancelled.
            begin_turn_epoch()
            self.assertTrue(turn_cancel_requested())
        finally:
            reset_turn_epoch(token)

    def test_new_turn_not_cancelled(self) -> None:
        bump_cancel_epoch()
        epoch = begin_turn_epoch()
        token = bind_turn_epoch(epoch)
        try:
            self.assertEqual(epoch, current_cancel_epoch())
            self.assertFalse(turn_cancel_requested())
        finally:
            reset_turn_epoch(token)


class ScopeConstraintTests(unittest.TestCase):
    def test_bare_host_rejected_when_path_constrained(self) -> None:
        raw = """---
in_scope:
  - https://api.example.com/v1
out_of_scope: []
allowed:
  - active testing
---
# Scope
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SCOPE.md").write_text(raw, encoding="utf-8")
            policy = ScopePolicy.load(root)
            self.assertTrue(policy.structured)
            self.assertFalse(policy.target_in_scope("api.example.com"))
            self.assertTrue(policy.target_in_scope("https://api.example.com/v1/users"))
            self.assertFalse(policy.target_in_scope("https://api.example.com/other"))

    def test_broken_yaml_fail_closed(self) -> None:
        raw = """---
in_scope: [example.com
out_of_scope:
  - evil.com
---
# Scope
evil.com is mentioned in body
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SCOPE.md").write_text(raw, encoding="utf-8")
            policy = ScopePolicy.load(root)
            self.assertTrue(policy.structured)
            self.assertFalse(policy.contains_host("evil.com"))
            self.assertFalse(policy.contains_host("example.com"))

    def test_unstructured_l2_hard_deny(self) -> None:
        raw = """# Scope

## In Scope
- example.com

## Explicitly Allowed
- Passive recon only
"""
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SCOPE.md").write_text(raw, encoding="utf-8")
            policy = ScopePolicy.load(root)
            self.assertFalse(policy.structured)
            with self.assertRaises(PermissionError):
                policy.assert_action_allowed("example.com", "nuclei scan", force=False)


class ForceArgTests(unittest.TestCase):
    def tearDown(self) -> None:
        force_mod._FORCE_ACTIVE = False  # noqa: SLF001

    def test_model_force_true_ignored_without_session(self) -> None:
        from hackbot.tools import _resolve_force_arg

        force_mod._FORCE_ACTIVE = False  # noqa: SLF001
        with mock.patch.dict("os.environ", {"HACKBOT_ALLOW_ARG_FORCE": "0"}):
            self.assertFalse(_resolve_force_arg({"force": True}))
            self.assertTrue(_resolve_force_arg({"force": True, "_operator_force": True}))
        force_mod._FORCE_ACTIVE = True  # noqa: SLF001
        with mock.patch.dict("os.environ", {"HACKBOT_ALLOW_ARG_FORCE": "0"}):
            self.assertTrue(_resolve_force_arg({"force": True}))


class RunnerOkShapeTests(unittest.TestCase):
    def test_timeout_not_ok(self) -> None:
        from hackbot.runners.base import RunnerResult
        from hackbot.tools import _runner_result_ok

        bad = RunnerResult(
            command=["x"],
            executed=True,
            returncode=-1,
            stdout="",
            stderr="",
            message="timeout",
        )
        self.assertFalse(_runner_result_ok(bad))
        dry = RunnerResult(
            command=["x"],
            executed=False,
            returncode=None,
            stdout="",
            stderr="",
            message="dry-run",
        )
        self.assertTrue(_runner_result_ok(dry))


if __name__ == "__main__":
    unittest.main()
