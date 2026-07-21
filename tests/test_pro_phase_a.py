"""Phase A reliability: FINDINGS whitelist, observe HTML, mine_params chain, browser_diff."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hackbot.diffing import assert_idor_diff
from hackbot.hunt_controller import FINDING_MODULES, Hypothesis, _chain_from_result, _already_attempted
from hackbot.hunt_memory import HuntMemory
from hackbot.observe import observe_v2
from hackbot.surface import map_surface
from hackbot.tools import execute_tool


SCOPE = "# Scope\n\n## In Scope\n- example.com\n\n## Explicitly Allowed\n- Active testing\n"


class FindingsWhitelistTests(unittest.TestCase):
    def test_bootstrap_not_finding_module(self) -> None:
        self.assertNotIn("session_bootstrap", FINDING_MODULES)
        self.assertNotIn("discover_paths", FINDING_MODULES)
        self.assertNotIn("analyze_headers", FINDING_MODULES)
        self.assertIn("idor", FINDING_MODULES)


class IdenticalBodyNotLikelyTests(unittest.TestCase):
    def test_identical_public_inconclusive(self) -> None:
        a = {"status": 200, "body": "<html>home</html>", "sha256": "x"}
        b = {"status": 200, "body": "<html>home</html>", "sha256": "x"}
        d = assert_idor_diff(a, b)
        self.assertEqual(d.verdict, "inconclusive")


class MineParamsChainTests(unittest.TestCase):
    def test_chain_reads_found_param(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        mem = HuntMemory(root)
        hyp = Hypothesis(module="mine_params", url="https://example.com/search", title="m")
        result = {
            "signal": False,
            "detail": {"found": [{"param": "q", "status": 200}], "ok": True},
        }
        follows = _chain_from_result(hyp, result, mem, "example.com")
        params = {(f.module, (f.params or {}).get("param")) for f in follows}
        self.assertIn(("sqli", "q"), params)
        self.assertIn(("xss", "q"), params)


class ObserveHtmlTests(unittest.TestCase):
    def test_map_surface_dry_still_ok(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        out = map_surface(root, "https://example.com", approve=False, force=True)
        self.assertTrue(out["ok"])
        self.assertTrue(out.get("dry_run"))

    def test_observe_v2_dry(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        out = observe_v2(root, "https://example.com", approve=False, force=True, execute_tool=None)
        self.assertTrue(out["ok"])
        self.assertIn("tags", out)


class DedupeNeedsSetupTests(unittest.TestCase):
    def test_needs_setup_not_terminal(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        mem = HuntMemory(root)
        mem.append_attempt(
            {
                "phase": "act",
                "module": "idor",
                "url": "https://example.com/x",
                "method": "GET",
                "params": {},
                "dedupe_key": "idor|GET|https://example.com/x|",
                "outcome": "needs_setup",
            }
        )
        hyp = Hypothesis(module="idor", url="https://example.com/x", title="t")
        self.assertFalse(_already_attempted(mem, hyp))


class BrowserDiffSignalTests(unittest.TestCase):
    def test_act_maps_idor_soft_hint(self) -> None:
        from hackbot.hunt_controller import _act

        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")

        def fake_tool(name, args, approve_fn=None):
            self.assertEqual(name, "browser_diff_sessions")
            self.assertFalse(args.get("promote"))
            return json.dumps(
                {
                    "ok": True,
                    "diff": {"idor_soft_hint": True},
                    "reason": "soft hint",
                }
            )

        hyp = Hypothesis(module="browser_diff", url="https://example.com/", title="b")
        out = _act(
            root,
            hyp,
            host="example.com",
            approve=False,
            force=True,
            approve_fn=None,
            execute_tool=fake_tool,
        )
        self.assertTrue(out["signal"])


class BootstrapDryTests(unittest.TestCase):
    def test_bootstrap_tool_dry(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        (root / "secrets").mkdir()
        (root / "secrets" / "accounts.yaml").write_text(
            "accounts:\n  A:\n    username: a\n    password: p\n",
            encoding="utf-8",
        )
        out = json.loads(
            execute_tool(
                "session_bootstrap",
                {
                    "target_dir": str(root),
                    "base_url": "https://example.com",
                    "approve": False,
                    "force": True,
                },
            )
        )
        self.assertFalse(out["executed"])


if __name__ == "__main__":
    unittest.main()
