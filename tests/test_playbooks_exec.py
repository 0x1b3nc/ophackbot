"""Executable playbook dry-run tests."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from hackbot.playbooks import executable_steps, playbook_for
from hackbot.tools import execute_tool

SCOPE = """# Scope

## In Scope
- example.com

## Explicitly Allowed
- Passive recon
- Automated scanning
- Rate-limit testing
"""


class PlaybookExecTests(unittest.TestCase):
    def test_rate_limit_playbook_has_tool_calls(self) -> None:
        pb = playbook_for("rate-limit")
        self.assertEqual(pb.class_name, "rate-limit")
        steps = executable_steps(pb, max_aggression=3)
        self.assertTrue(any(s.tool_call for s in steps))
        self.assertTrue(any(s.aggression == 3 for s in steps))

    def test_aggression_filter(self) -> None:
        pb = playbook_for("rate-limit")
        low = executable_steps(pb, max_aggression=1)
        self.assertTrue(all(s.aggression <= 1 for s in low))
        self.assertFalse(any(s.aggression >= 3 for s in low))

    def test_dos_alias(self) -> None:
        pb = playbook_for("dos")
        self.assertIn("rate", pb.summary.lower() + pb.class_name)

    def test_run_playbook_dry_run(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        out = execute_tool(
            "run_playbook",
            {
                "target_dir": str(root),
                "task": "rate-limit",
                "host": "example.com",
                "approve": False,
                "force": False,
            },
        )
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertFalse(data["executed"])
        self.assertGreaterEqual(len(data.get("steps") or []), 1)
        self.assertEqual(data.get("max_aggression"), 3)  # SCOPE allows level3


if __name__ == "__main__":
    unittest.main()
