"""IDOR playbook tool_calls + offline plan + assert_diff via cache."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from hackbot.local_agent import build_plan, interpret
from hackbot.playbooks import executable_steps, playbook_for
from hackbot import tools as tools_mod
from hackbot.tools import execute_tool


SCOPE = """# Scope

## In Scope
- example.com

## Explicitly Allowed
- Automated scanning
- Active testing
"""


class HuntIdorTests(unittest.TestCase):
    def test_idor_playbook_executable(self) -> None:
        pb = playbook_for("idor")
        steps = executable_steps(pb, max_aggression=2)
        tools = [s.tool_call.get("tool") for s in steps if s.tool_call]
        self.assertIn("http_request", tools)
        self.assertIn("assert_diff", tools)

    def test_offline_attack_idor_plan(self) -> None:
        text = "attack idor on https://example.com/api/orders/1 for targets/demo"
        interp = interpret(text)
        plan = build_plan(text, interp)
        tools = [a.tool for a in plan]
        self.assertTrue("run_campaign" in tools or "run_playbook" in tools)
        if "run_playbook" in tools:
            self.assertIn("show_identity", tools)

    def test_assert_diff_from_cache(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        (root / "evidence" / "safe").mkdir(parents=True)
        key_a = tools_mod._cache_key(root, "idor_A")  # noqa: SLF001
        key_b = tools_mod._cache_key(root, "idor_B")  # noqa: SLF001
        tools_mod._RESPONSE_CACHE[key_a] = {  # noqa: SLF001
            "status": 200,
            "body": '{"id":9,"email":"owner@x.com"}',
            "sha256": "aaaa",
            "length": 30,
        }
        tools_mod._RESPONSE_CACHE[key_b] = {  # noqa: SLF001
            "status": 200,
            "body": '{"id":9,"email":"owner@x.com"}',
            "sha256": "bbbb",
            "length": 30,
        }
        out = execute_tool(
            "assert_diff",
            {
                "target_dir": str(root),
                "label_a": "idor_A",
                "label_b": "idor_B",
                "object_hint": "owner@x.com",
            },
        )
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertIn(data["verdict"], {"confirmed", "likely"})

    def test_http_request_dry_run(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        (root / "secrets").mkdir()
        (root / "secrets" / "sessions.yaml").write_text(
            "sessions:\n  A:\n    authorization: Bearer tokA\n",
            encoding="utf-8",
        )
        out = execute_tool(
            "http_request",
            {
                "target_dir": str(root),
                "url": "https://example.com/api/orders/1",
                "session": "A",
                "label": "t1",
                "approve": False,
            },
        )
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertFalse(data["executed"])


if __name__ == "__main__":
    unittest.main()
