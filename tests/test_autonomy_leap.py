"""Autonomy leap: idor_probe, discover_paths, OOB canary, cookie jar."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hackbot.hunt_jar import cookie_header, merge_set_cookie
from hackbot.local_agent import build_plan, interpret
from hackbot.oob import enrich_ssrf_payloads, mint_canary, oob_configured
from hackbot.runners import idor_probe
from hackbot.tools import execute_tool


SCOPE = "# Scope\n\n## In Scope\n- example.com\n"


class IdorProbeTests(unittest.TestCase):
    def test_dry_run_needs_sessions(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        (root / "secrets").mkdir()
        out = execute_tool(
            "idor_probe",
            {
                "target_dir": str(root),
                "url": "https://example.com/api/orders/1",
                "approve": False,
                "force": True,
            },
        )
        data = json.loads(out)
        self.assertIn(data.get("detail", {}).get("error"), {"sessions_missing", None})
        # Without sessions: runner returns error (not dry-run)
        self.assertFalse(data.get("signal"))

    def test_dry_run_with_sessions(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        (root / "secrets").mkdir()
        (root / "secrets" / "sessions.yaml").write_text(
            "sessions:\n  A:\n    authorization: Bearer a\n  B:\n    authorization: Bearer b\n",
            encoding="utf-8",
        )
        out = execute_tool(
            "idor_probe",
            {
                "target_dir": str(root),
                "url": "https://example.com/api/orders/1",
                "approve": False,
                "force": True,
            },
        )
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertFalse(data["executed"])
        self.assertTrue(data.get("detail", {}).get("dry_run"))

    def test_swap_param_helper(self) -> None:
        swapped = idor_probe._swap_id_param(  # noqa: SLF001
            "https://example.com/x?id=1&q=a", "id", "999999"
        )
        self.assertIn("id=999999", swapped)
        self.assertIn("q=a", swapped)


class DiscoverPathsTests(unittest.TestCase):
    def test_dry_run(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        out = execute_tool(
            "discover_paths",
            {
                "target_dir": str(root),
                "base_url": "https://example.com",
                "approve": False,
                "force": True,
                "limit": 5,
            },
        )
        data = json.loads(out)
        self.assertTrue(data["ok"])
        self.assertFalse(data["executed"])
        self.assertEqual(data.get("detail", {}).get("paths"), 5)


class OobTests(unittest.TestCase):
    def test_mint_local(self) -> None:
        with mock.patch.dict(os.environ, {}, clear=False):
            os.environ.pop("HACKBOT_OOB_BASE", None)
            c = mint_canary(kind="ssrf")
            self.assertTrue(c["ok"])
            self.assertFalse(c["oob_configured"])
            self.assertIn("hb-ssrf-", c["label"])
            self.assertTrue(c["http_url"])

    def test_mint_with_base(self) -> None:
        with mock.patch.dict(os.environ, {"HACKBOT_OOB_BASE": "https://oast.example"}, clear=False):
            self.assertTrue(oob_configured())
            c = mint_canary(kind="xss", tag="t1")
            self.assertTrue(c["oob_configured"])
            self.assertIn("oast.example", c["http_url"])
            enriched = enrich_ssrf_payloads([("http://127.0.0.1/", ("localhost",))], canary=c)
            self.assertGreater(len(enriched), 1)
            self.assertTrue(any(c["token"] in markers for _, markers in enriched))

    def test_oob_mint_tool(self) -> None:
        data = json.loads(execute_tool("oob_mint", {"kind": "ssrf"}))
        self.assertTrue(data["ok"])
        self.assertIn("token", data)


class JarTests(unittest.TestCase):
    def test_merge_and_header(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        merge_set_cookie(
            root,
            ["sid=abc123; Path=/; Domain=example.com", "theme=dark"],
            url="https://example.com/login",
        )
        hdr = cookie_header(root, host="example.com")
        self.assertIn("sid=abc123", hdr)
        self.assertIn("theme=dark", hdr)
        self.assertTrue((root / "secrets" / "cookie_jar.json").exists())


class NlAutonomyTests(unittest.TestCase):
    def test_idor_probe_intent(self) -> None:
        text = "testa idor probe em https://example.com/api/orders/1 targets/demo"
        interp = interpret(text)
        self.assertIn("idor_probe", interp.intents)
        plan = build_plan(text, interp)
        self.assertTrue(any(a.tool == "idor_probe" for a in plan))

    def test_discover_intent(self) -> None:
        text = "content discovery em example.com targets/demo"
        interp = interpret(text)
        self.assertIn("discover_paths", interp.intents)
        plan = build_plan(text, interp)
        self.assertTrue(any(a.tool == "discover_paths" for a in plan))

    def test_oob_intent(self) -> None:
        text = "mint oob canary collaborator"
        interp = interpret(text)
        self.assertIn("oob", interp.intents)
        plan = build_plan(text, interp)
        self.assertTrue(any(a.tool == "oob_mint" for a in plan))


if __name__ == "__main__":
    unittest.main()
