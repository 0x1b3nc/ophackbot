"""Regression: update_resume UnboundLocalError + domain arg KeyError."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hackbot.tools import _domain_arg, execute_tool


class DomainArgTests(unittest.TestCase):
    def test_domain_from_url(self) -> None:
        self.assertEqual(_domain_arg({"url": "https://www.bmw.de/x"}), "www.bmw.de")

    def test_domain_required_soft_fail(self) -> None:
        out = json.loads(execute_tool("wayback_urls", {}))
        self.assertFalse(out.get("ok", True))
        self.assertIn("domain", out.get("error", "").lower())


class UpdateResumeTests(unittest.TestCase):
    def test_update_resume_after_approve(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text("---\nin_scope: [example.com]\n---\n", encoding="utf-8")
        (root / "RESUME.md").write_text(
            "# Resume\n\n## Safe Next Step\n\n- old\n",
            encoding="utf-8",
        )
        out = json.loads(
            execute_tool(
                "update_resume",
                {"target_dir": str(root), "next_step": "map_surface next"},
                approve_fn=lambda _d: True,
            )
        )
        self.assertTrue(out.get("ok"))
        text = (root / "RESUME.md").read_text(encoding="utf-8")
        self.assertIn("map_surface next", text)


if __name__ == "__main__":
    unittest.main()
