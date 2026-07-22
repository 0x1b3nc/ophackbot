"""Tests for /force session flag and policy gate overrides (incl. OOS)."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hackbot import force as force_mod
from hackbot import yolo as yolo_mod
from hackbot.policy_guard import ScopePolicy
from hackbot.tools import execute_tool


SCOPE_NO_L3 = """# Scope

## In Scope
- example.com

## Explicitly Allowed
- Passive recon
- Automated scanning with nuclei at low rate

## Explicitly Prohibited
- DoS
- Brute force
"""

SCOPE_WITH_OOS = """# Scope

## In Scope
- example.com

## Out of Scope
- admin.example.com

## Explicitly Allowed
- Passive recon
"""


def _reset_force_yolo() -> None:
    force_mod._FORCE_ACTIVE = False  # noqa: SLF001
    yolo_mod._YOLO_ACTIVE = False  # noqa: SLF001
    yolo_mod._YOLO_ENABLED_FORCE = False  # noqa: SLF001
    os.environ.pop("HACKBOT_YOLO", None)


class ForceModuleTests(unittest.TestCase):
    def setUp(self) -> None:
        _reset_force_yolo()

    def tearDown(self) -> None:
        _reset_force_yolo()

    def test_toggle(self) -> None:
        self.assertFalse(force_mod.is_forced())
        with mock.patch.object(force_mod, "ui"):
            force_mod.enable_force()
        self.assertTrue(force_mod.is_forced())
        with mock.patch.object(force_mod, "ui"):
            force_mod.disable_force()
        self.assertFalse(force_mod.is_forced())

    def test_prompt_wants_force(self) -> None:
        self.assertTrue(force_mod.prompt_wants_force("eu assumo a responsabilidade"))
        self.assertTrue(force_mod.prompt_wants_force("/force httpx on example.com"))
        self.assertFalse(force_mod.prompt_wants_force("force httpx on example.com"))
        self.assertFalse(force_mod.prompt_wants_force("test brute force on example.com"))

    def test_force_off_refused_while_yolo(self) -> None:
        with mock.patch.object(yolo_mod, "ui"), mock.patch.object(force_mod, "ui"):
            yolo_mod.enable_yolo(quiet=True)
            self.assertTrue(force_mod.is_forced())
            ok = force_mod.disable_force(quiet=True)
            self.assertFalse(ok)
            self.assertTrue(force_mod.is_forced())
            yolo_mod.disable_yolo()
        self.assertFalse(force_mod.is_forced())

    def test_yolo_implies_is_forced(self) -> None:
        with mock.patch.object(yolo_mod, "ui"), mock.patch.object(force_mod, "ui"):
            yolo_mod.enable_yolo(quiet=True)
            # Even if the raw flag is cleared, YOLO keeps force semantics.
            force_mod._FORCE_ACTIVE = False  # noqa: SLF001
            self.assertTrue(force_mod.is_forced())
            yolo_mod.disable_yolo()


class ForcePolicyGateTests(unittest.TestCase):
    def setUp(self) -> None:
        _reset_force_yolo()

    def tearDown(self) -> None:
        _reset_force_yolo()

    def _policy(self, text: str) -> ScopePolicy:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(text, encoding="utf-8")
        return ScopePolicy.load(root)

    def test_level3_blocked_without_force(self) -> None:
        policy = self._policy(SCOPE_NO_L3)
        with self.assertRaises(PermissionError):
            policy.assert_action_allowed("example.com", "dos stress", force=False)

    def test_level3_allowed_with_force(self) -> None:
        policy = self._policy(SCOPE_NO_L3)
        gate = policy.assert_action_allowed("example.com", "dos stress", force=True)
        self.assertTrue(gate["force_override"])
        self.assertEqual(gate["aggression"], 3)

    def test_oos_blocked_without_force(self) -> None:
        policy = self._policy(SCOPE_WITH_OOS)
        with self.assertRaises(PermissionError):
            policy.assert_action_allowed("admin.example.com", "httpx", force=False)

    def test_oos_allowed_with_force(self) -> None:
        policy = self._policy(SCOPE_WITH_OOS)
        gate = policy.assert_action_allowed("admin.example.com", "httpx", force=True)
        self.assertTrue(gate["force_override"])
        self.assertEqual(gate["status"], "OUT_OF_SCOPE_FORCED")
        self.assertTrue(
            any("OUT_OF_SCOPE" in w for w in (gate.get("warnings") or []))
        )

    def test_not_confirmed_needs_force(self) -> None:
        policy = self._policy(SCOPE_NO_L3)
        with self.assertRaises(PermissionError):
            policy.assert_action_allowed("other.com", "httpx", force=False)
        gate = policy.assert_action_allowed("other.com", "httpx", force=True)
        self.assertTrue(gate["force_override"])

    def test_scope_check_oos_forced(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE_WITH_OOS, encoding="utf-8")
        blocked = json.loads(
            execute_tool(
                "scope_check",
                {"target_dir": str(root), "host": "admin.example.com", "force": False},
            )
        )
        self.assertEqual(blocked.get("status"), "OUT_OF_SCOPE")
        self.assertFalse(blocked.get("allowed"))
        forced = json.loads(
            execute_tool(
                "scope_check",
                {"target_dir": str(root), "host": "admin.example.com", "force": True},
            )
        )
        self.assertEqual(forced.get("status"), "OUT_OF_SCOPE_FORCED")
        self.assertTrue(forced.get("allowed"))
        self.assertTrue(forced.get("force_override"))

    def test_run_tool_dry_run_level3_with_force(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE_NO_L3, encoding="utf-8")
        force_mod._FORCE_ACTIVE = False  # noqa: SLF001
        out = execute_tool(
            "run_tool",
            {
                "target_dir": str(root),
                "tool": "rate_probe",
                "host": "example.com",
                "approve": False,
                "force": True,
                "total": 5,
                "concurrency": 2,
            },
        )
        data = json.loads(out)
        self.assertTrue(data.get("ok"))
        self.assertFalse(data.get("executed"))
        self.assertTrue(data.get("force_override"))


if __name__ == "__main__":
    unittest.main()
