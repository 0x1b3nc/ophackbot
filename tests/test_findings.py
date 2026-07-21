"""FINDINGS / RESUME loop."""

from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from hackbot.findings import Finding, append_finding, next_finding_id, parse_latest_finding
from hackbot.tools import execute_tool


SCOPE = """# Scope

## In Scope
- example.com
"""


class FindingsTests(unittest.TestCase):
    def test_append_and_parse(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "FINDINGS.md").write_text("# Findings\n\nNo confirmed findings yet.\n", encoding="utf-8")
        fid = next_finding_id((root / "FINDINGS.md").read_text(encoding="utf-8"))
        self.assertEqual(fid, "C-001")
        append_finding(
            root,
            Finding(
                finding_id=fid,
                title="IDOR orders",
                class_name="idor",
                endpoint="https://example.com/api/orders/1",
                verdict="confirmed",
                asset="example.com",
                preconditions="A/B",
                observed="B got 200",
                impact="PII leak",
                evidence="evidence/safe/x",
                next_step="Report",
            ),
        )
        latest = parse_latest_finding(root)
        assert latest is not None
        self.assertEqual(latest["finding_id"], "C-001")
        self.assertIn("IDOR", latest["title"])

    def test_log_finding_tool(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        (root / "FINDINGS.md").write_text("# Findings\n\n", encoding="utf-8")
        (root / "RESUME.md").write_text(
            "# Resume\n\n## Last State\n\n- x\n\n## Accounts\n\n- None\n\n## Safe Next Step\n\n- old\n",
            encoding="utf-8",
        )
        out = execute_tool(
            "log_finding",
            {
                "target_dir": str(root),
                "title": "BOLA on orders",
                "class_name": "idor",
                "endpoint": "https://example.com/api/orders/1",
                "verdict": "likely",
            },
            approve_fn=lambda _p: True,
        )
        self.assertIn("C-001", out)
        self.assertIn("BOLA", (root / "FINDINGS.md").read_text(encoding="utf-8"))


if __name__ == "__main__":
    unittest.main()
