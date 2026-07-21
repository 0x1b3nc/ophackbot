"""Multi-platform report drafts + browser A/B diff."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hackbot.findings import parse_finding_by_id, report_fields_from_finding
from hackbot.local_agent import build_plan, interpret
from hackbot.reporting import normalize_platform, render_report
from hackbot.runners import browser as browser_runner
from hackbot.tools import execute_tool


class ReportDraftTests(unittest.TestCase):
    def test_normalize_platform(self) -> None:
        self.assertEqual(normalize_platform(None), "generic")
        self.assertEqual(normalize_platform("H1"), "hackerone")
        self.assertEqual(normalize_platform("ywh"), "yeswehack")
        self.assertEqual(normalize_platform("synack"), "synack")

    def test_generic_render_mentions_portals(self) -> None:
        body = render_report(
            "generic",
            title="C-001 IDOR",
            target="https://example.com/api/orders/1",
            preconditions="A/B accounts",
            steps="1. swap id",
            impact="cross-account read",
            evidence="evidence/safe/",
            vuln_type="idor",
        )
        self.assertIn("Bugcrowd", body)
        self.assertIn("YesWeHack", body)
        self.assertIn("C-001 IDOR", body)

    def test_write_report_from_findings(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "FINDINGS.md").write_text(
            "# Findings\n\n"
            "## C-001 Orders IDOR\n\n"
            "- Status: draft\n"
            "- Class: idor\n"
            "- Verdict: likely\n"
            "- Asset: example.com\n"
            "- Endpoint: https://example.com/api/orders/1\n"
            "- Preconditions: A/B\n"
            "- Observed: B got A's order\n"
            "- Impact: PII leak\n"
            "- Evidence: evidence/safe/idor.json\n"
            "- Next step: draft report\n",
            encoding="utf-8",
        )
        out = json.loads(
            execute_tool(
                "write_report_draft",
                {
                    "target_dir": str(root),
                    "platform": "generic",
                    "finding_id": "latest",
                },
                approve_fn=lambda _d: True,
            )
        )
        self.assertTrue(out["ok"])
        self.assertEqual(out["platform"], "generic")
        path = Path(out["path"])
        self.assertTrue(path.exists())
        text = path.read_text(encoding="utf-8")
        self.assertIn("Orders IDOR", text)
        self.assertIn("api/orders/1", text)
        self.assertIn("Severity hint", text)
        self.assertTrue(out.get("severity_hint"))
        self.assertIn("CVSS", text)

    def test_nl_report_defaults_generic(self) -> None:
        text = "monta o draft do report a partir do FINDINGS targets/demo"
        interp = interpret(text)
        self.assertIn("report", interp.intents)
        self.assertIsNone(interp.platform)
        plan = build_plan(text, interp)
        action = next(a for a in plan if a.tool == "write_report_draft")
        self.assertEqual(action.args.get("platform"), "generic")

    def test_nl_yeswehack(self) -> None:
        text = "draft yeswehack do finding targets/demo"
        interp = interpret(text)
        self.assertEqual(interp.platform, "yeswehack")
        plan = build_plan(text, interp)
        action = next(a for a in plan if a.tool == "write_report_draft")
        self.assertEqual(action.args.get("platform"), "yeswehack")

    def test_parse_finding_by_id(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "FINDINGS.md").write_text(
            "## C-001 First\n\n- Endpoint: /a\n\n## C-002 Second\n\n- Endpoint: /b\n",
            encoding="utf-8",
        )
        latest = parse_finding_by_id(root, "latest")
        self.assertEqual(latest["finding_id"], "C-002")
        first = parse_finding_by_id(root, "C-001")
        self.assertEqual(first["finding_id"], "C-001")
        fields = report_fields_from_finding(first)
        self.assertIn("/a", fields["target"])


class BrowserDiffTests(unittest.TestCase):
    def test_diff_dry_or_missing(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(
            "# Scope\n\n## In Scope\n- example.com\n", encoding="utf-8"
        )
        secrets = root / "secrets"
        secrets.mkdir()
        (secrets / "sessions.yaml").write_text(
            "sessions:\n  A:\n    authorization: Bearer aaa\n"
            "  B:\n    authorization: Bearer bbb\n",
            encoding="utf-8",
        )
        out = json.loads(
            execute_tool(
                "browser_diff_sessions",
                {
                    "target_dir": str(root),
                    "url": "https://example.com/api/me",
                    "approve": False,
                },
            )
        )
        self.assertTrue(out.get("dry_run") or out.get("error") == "playwright_missing")

    def test_diff_missing_session(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(
            "# Scope\n\n## In Scope\n- example.com\n", encoding="utf-8"
        )
        with mock.patch.object(browser_runner, "playwright_available", return_value=True):
            result = browser_runner.browser_diff_sessions(
                root, "https://example.com/me", approve=True
            )
        payload = json.loads(result.stdout)
        self.assertEqual(payload.get("error"), "session_missing")

    def test_nl_diff(self) -> None:
        text = "compara sessão A vs B em https://example.com/api/me targets/demo"
        interp = interpret(text)
        self.assertIn("browser_diff", interp.intents)
        plan = build_plan(text, interp)
        self.assertTrue(any(a.tool == "browser_diff_sessions" for a in plan))


class PromoteAndSeverityTests(unittest.TestCase):
    def test_severity_for_idor(self) -> None:
        from hackbot.severity import severity_for_class

        sev = severity_for_class("idor")
        self.assertEqual(sev.severity, "High")
        self.assertTrue(sev.vector.startswith("CVSS:3.1/"))
        sev2 = severity_for_class("SQL Injection")
        self.assertEqual(severity_for_class("sqli").severity, "Critical")
        self.assertEqual(sev2.severity, "Critical")

    def test_promote_browser_diff(self) -> None:
        from hackbot.hunt_memory import HuntMemory
        from hackbot.validator import promote_browser_diff

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(
            "# Scope\n\n## In Scope\n- example.com\n", encoding="utf-8"
        )
        (root / "RESUME.md").write_text("# Resume\n\n## Safe Next Step\n\n- TBD\n", encoding="utf-8")
        snap = {
            "status": 200,
            "body_hash": "abcd1234abcd1234",
            "body_len": 120,
            "title": "me",
        }
        diff = {
            "status_equal": True,
            "body_hash_equal": True,
            "body_len_equal": True,
            "idor_soft_hint": True,
        }
        vr = promote_browser_diff(
            root,
            url="https://example.com/api/me",
            diff=diff,
            snap_a=snap,
            snap_b=snap,
        )
        self.assertIsNotNone(vr)
        assert vr is not None
        self.assertTrue(vr.ok)
        self.assertEqual(vr.status, "validated")
        self.assertTrue(vr.finding_id.startswith("C-"))
        findings = (root / "FINDINGS.md").read_text(encoding="utf-8")
        self.assertIn("likely", findings.lower())
        self.assertIn("Severity hint", findings)
        self.assertIn("idor", findings.lower())
        cands = HuntMemory(root).load_candidates()
        self.assertTrue(any(c.module == "idor" and c.status == "validated" for c in cands))

        # Second promote dedups / skips
        vr2 = promote_browser_diff(
            root,
            url="https://example.com/api/me",
            diff=diff,
            snap_a=snap,
            snap_b=snap,
        )
        self.assertIsNotNone(vr2)
        assert vr2 is not None
        self.assertEqual(vr2.status, "skipped")

    def test_promote_skips_without_hint(self) -> None:
        from hackbot.validator import promote_browser_diff

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        out = promote_browser_diff(
            root,
            url="https://example.com/x",
            diff={"idor_soft_hint": False},
            snap_a={},
            snap_b={},
        )
        self.assertIsNone(out)


if __name__ == "__main__":
    unittest.main()
