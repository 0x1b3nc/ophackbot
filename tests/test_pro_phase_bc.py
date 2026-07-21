"""Phase B/C: confidence, FP signatures, sinks, submit_ready, second-order XSS."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from hackbot.fp_signatures import confidence_score, match_fp_signatures
from hackbot.sink_registry import build_sink_registry, has_sink
from hackbot.hunt_memory import Endpoint, HuntMemory
from hackbot.tools import execute_tool
from hackbot.validator import validate_and_log
from hackbot.hunt_memory import Candidate


SCOPE = "# Scope\n\n## In Scope\n- example.com\n\n## Explicitly Allowed\n- Active testing\n"


class ConfidenceFpTests(unittest.TestCase):
    def test_public_path_idor_fp(self) -> None:
        fp = match_fp_signatures(
            module="idor",
            observed="identical bodies",
            url="https://example.com/",
            verdict="likely",
        )
        self.assertTrue(fp["is_fp"])
        self.assertIn("idor_on_public_path", fp["hits"])

    def test_confirmed_needs_high_score(self) -> None:
        score = confidence_score(
            module="idor",
            verdict="confirmed",
            fp={"is_fp": False},
            has_ownership_diff=True,
        )
        self.assertGreaterEqual(score, 0.75)

    def test_fp_lowers_score(self) -> None:
        score = confidence_score(
            module="idor",
            verdict="likely",
            fp={"is_fp": True, "hits": ["public_html_shell"]},
            has_ownership_diff=False,
        )
        self.assertLess(score, 0.75)


class ValidatorGateTests(unittest.TestCase):
    def test_low_confidence_rejected(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        mem = HuntMemory(root)
        cand = Candidate(
            id="C1",
            module="idor",
            title="public twin",
            url="https://example.com/",
            detail="<!doctype html><html>home</html>",
            status="pending",
        )
        mem.upsert_candidate(cand)
        vr = validate_and_log(
            root,
            cand,
            observed="<!doctype html><html>home</html> identical A/B",
            verdict="likely",
            write_finding=True,
        )
        self.assertFalse(vr.ok)
        self.assertEqual(vr.status, "rejected")
        findings = (root / "FINDINGS.md").read_text(encoding="utf-8") if (root / "FINDINGS.md").exists() else ""
        self.assertNotIn("public twin", findings.lower())


class SinkRegistryTests(unittest.TestCase):
    def test_build_and_has_sink(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        mem = HuntMemory(root)
        mem.upsert_endpoints(
            [
                Endpoint(
                    url="https://example.com/api/users/1",
                    method="GET",
                    params=["id"],
                    source="test",
                ),
                Endpoint(
                    url="https://example.com/graphql",
                    method="POST",
                    params=[],
                    source="test",
                ),
            ],
            host="example.com",
        )
        data = build_sink_registry(root)
        self.assertTrue(data["ok"])
        self.assertTrue(has_sink(root, "id"))
        self.assertTrue(has_sink(root, "graphql"))


class SubmitReadyTests(unittest.TestCase):
    def test_submit_ready_marks_resume(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        (root / "RESUME.md").write_text("# Resume\n\n## Safe Next Step\n- old\n", encoding="utf-8")
        out = json.loads(
            execute_tool("submit_ready", {"target_dir": str(root), "finding_id": "F-001"})
        )
        self.assertTrue(out["ok"])
        text = (root / "RESUME.md").read_text(encoding="utf-8")
        self.assertIn("HUMAN SUBMIT", text)


class SecondOrderDryTests(unittest.TestCase):
    def test_second_order_dry_run(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        out = json.loads(
            execute_tool(
                "second_order_xss",
                {
                    "target_dir": str(root),
                    "url": "https://example.com/comment",
                    "approve": False,
                    "force": True,
                },
            )
        )
        self.assertTrue(out.get("ok") or out.get("detail", {}).get("dry_run") or "dry" in str(out).lower())
        detail = out.get("detail") or {}
        self.assertTrue(detail.get("dry_run") or out.get("executed") is False)


class TelemetryFpRateTests(unittest.TestCase):
    def test_fp_rate_in_stats(self) -> None:
        from hackbot.hunt_telemetry import record_telemetry, telemetry_stats

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        record_telemetry(root, {"module": "idor", "outcome": "fp_rejected", "signal": False})
        record_telemetry(root, {"module": "idor", "outcome": "validated", "signal": True})
        stats = telemetry_stats(root)
        self.assertEqual(stats["rejected"], 1)
        self.assertEqual(stats["validated"], 1)
        self.assertAlmostEqual(stats["fp_rate"], 0.5)


if __name__ == "__main__":
    unittest.main()
