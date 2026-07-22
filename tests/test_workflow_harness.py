"""Workflow harness + coverage_map + elite packs — dry-run / SCOPE gates."""

from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path

from hackbot.coverage_map import coverage_summary, mark_coverage, mark_coverage_url
from hackbot.tool_packs import PACKS, filter_tool_specs, resolve_packs
from hackbot.tools import TOOL_SPECS, execute_tool
from hackbot.workflow_harness import list_workflows, load_workflow, preview_workflow, run_workflow

ROOT = Path(__file__).resolve().parents[1]
TEMPLATE_WF = ROOT / "templates" / "target" / "hunt" / "workflows" / "idor_invite_accept.yaml"


class CoverageMapTests(unittest.TestCase):
    def test_mark_and_summary(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            td = Path(tmp)
            mark_coverage(
                td, cls="idor", method="GET", path="/api/x", authz="A", status="dry"
            )
            mark_coverage_url(
                td,
                cls="idor",
                url="https://app.example.com/api/x",
                method="GET",
                authz="A",
                status="pos",
            )
            summary = coverage_summary(td)
            self.assertTrue(summary["ok"])
            self.assertGreaterEqual(summary["total"], 1)
            self.assertIn("pos", summary["counts"])


class WorkflowHarnessTests(unittest.TestCase):
    def _target(self) -> Path:
        tmp = Path(tempfile.mkdtemp())
        self.addCleanup(lambda: shutil.rmtree(tmp, ignore_errors=True))
        (tmp / "SCOPE.md").write_text(
            "---\nin_scope:\n  - app.example.com\nout_of_scope:\n  - evil.com\n"
            "allowed:\n  - Passiveive testing\nprohibited:\n  - DoS\n---\n",
            encoding="utf-8",
        )
        wf_dir = tmp / "hunt" / "workflows"
        wf_dir.mkdir(parents=True)
        shutil.copyfile(TEMPLATE_WF, wf_dir / "idor_invite_accept.yaml")
        return tmp

    def test_list_and_load(self) -> None:
        td = self._target()
        self.assertIn("idor_invite_accept", list_workflows(td))
        wf = load_workflow(td, "idor_invite_accept")
        prev = preview_workflow(wf)
        self.assertEqual(prev["id"], "idor_invite_accept")
        self.assertGreaterEqual(len(prev["steps"]), 2)

    def test_dry_run_no_traffic(self) -> None:
        td = self._target()
        out = run_workflow(td, "idor_invite_accept", approve=False)
        self.assertTrue(out["ok"])
        self.assertFalse(out["executed"])
        self.assertEqual(out["message"], "dry-run")
        cov = coverage_summary(td)
        self.assertGreaterEqual(cov["counts"].get("dry", 0), 1)

    def test_oos_blocks_active_request(self) -> None:
        td = self._target()
        # Rewrite workflow to hit OOS host
        bad = (
            "id: bad\nclass: idor\naggression_max: 2\nvars:\n"
            "  base_url: https://evil.com\nsteps:\n"
            "  - id: hit\n    kind: request\n    account: A\n"
            "    request:\n      method: GET\n      url: \"{base_url}/x\"\n      label: x\n"
        )
        (td / "hunt" / "workflows" / "bad.yaml").write_text(bad, encoding="utf-8")
        out = run_workflow(
            td,
            "bad",
            approve=True,
            approve_fn=lambda _d: True,
        )
        self.assertTrue(out.get("stopped") or not out.get("ok"))
        # scope_denied on first request step
        results = out.get("results") or []
        if results:
            self.assertIn(
                results[0].get("kind") or "",
                {"scope_denied", ""},
            )
            self.assertFalse(results[0].get("ok", True))

    def test_tool_workflow_load(self) -> None:
        td = self._target()
        raw = execute_tool(
            "workflow_load",
            {"target_dir": str(td), "workflow_id": "idor_invite_accept"},
        )
        data = json.loads(raw)
        self.assertTrue(data.get("ok"))
        self.assertEqual(data.get("id"), "idor_invite_accept")

    def test_tool_workflow_run_dry(self) -> None:
        td = self._target()
        raw = execute_tool(
            "workflow_run",
            {
                "target_dir": str(td),
                "workflow_id": "idor_invite_accept",
                "approve": False,
            },
        )
        data = json.loads(raw)
        self.assertTrue(data.get("ok"))
        self.assertFalse(data.get("executed"))


class ElitePackTests(unittest.TestCase):
    def test_elite_tools_in_normal_packs(self) -> None:
        self.assertIn("workflow_run", PACKS["core"])
        self.assertIn("open_knowledge", PACKS["core"])
        self.assertIn("ssrf_protocol_matrix", PACKS["inject"])
        self.assertIn("browser_map_spa", PACKS["browser"])
        self.assertIn("proxy_correlate", PACKS["recon"])

    def test_filter_auto_surface_has_elite(self) -> None:
        specs = filter_tool_specs(TOOL_SPECS, ["core", "recon", "inject", "report"])
        names = {s["name"] for s in specs}
        self.assertIn("workflow_run", names)
        self.assertIn("coverage_map", names)
        self.assertIn("http_request", names)
        self.assertIn("open_knowledge", names)

    def test_resolve_study_extreme_is_full_kit(self) -> None:
        import os
        from unittest import mock

        with mock.patch.dict(os.environ, {"HACKBOT_TOOL_PACK": "study-extreme"}):
            packs = resolve_packs("")
        self.assertEqual(packs, ["all"])
        with mock.patch.dict(os.environ, {"HACKBOT_TOOL_PACK": "advanced"}):
            self.assertEqual(resolve_packs(""), ["all"])


class FindingScoreTests(unittest.TestCase):
    def test_finding_score_tool(self) -> None:
        raw = execute_tool(
            "finding_score",
            {
                "module": "idor",
                "verdict": "confirmed",
                "observed": "private email field for other user",
                "url": "https://app.example.com/api/u/1",
                "has_ownership_diff": True,
            },
        )
        data = json.loads(raw)
        self.assertTrue(data.get("ok"))
        self.assertIn("confidence", data)


if __name__ == "__main__":
    unittest.main()
