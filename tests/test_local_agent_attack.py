"""Offline agent plans attacks via campaign / playbook."""

from __future__ import annotations

import unittest
from unittest import mock

from hackbot.local_agent import build_plan, interpret


class LocalAgentAttackTests(unittest.TestCase):
    def test_rate_limit_intent(self) -> None:
        text = "test rate-limit on example.com for targets/demo"
        interp = interpret(text)
        self.assertIn("rate-limit", interp.classes)
        self.assertEqual(interp.host, "example.com")
        plan = build_plan(text, interp)
        tools = [a.tool for a in plan]
        # Campaign or dedicated playbook — both are valid hunt paths
        self.assertTrue("run_campaign" in tools or "run_playbook" in tools)

    def test_attack_idor_uses_playbook_or_campaign(self) -> None:
        text = "attack idor on example.com/api/orders/1 targets/demo"
        interp = interpret(text)
        plan = build_plan(text, interp)
        tools = [a.tool for a in plan]
        self.assertTrue("run_campaign" in tools or "run_playbook" in tools)

    def test_force_in_prompt(self) -> None:
        text = "force test rate-limit on example.com for targets/demo"
        interp = interpret(text)
        self.assertTrue(interp.force)

    def test_session_force_flag(self) -> None:
        with mock.patch("hackbot.local_agent.is_forced", return_value=True):
            interp = interpret("dry-run httpx on example.com for targets/demo")
        self.assertTrue(interp.force)
        plan = build_plan("dry-run httpx on example.com for targets/demo", interp)
        run = next(a for a in plan if a.tool == "run_tool")
        self.assertTrue(run.args.get("force"))


if __name__ == "__main__":
    unittest.main()
