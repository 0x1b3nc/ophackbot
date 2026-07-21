"""Wave: demo, ssrf/race/ws, learning stats, tool packs, mobsf/frida stubs."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hackbot.demo import ensure_demo_workspace, run_demo_smoke
from hackbot.learning import rebuild_stats, record_technique, learn_stats
from hackbot.local_agent import build_plan, interpret
from hackbot.tool_packs import filter_tool_specs, resolve_packs
from hackbot.tools import TOOL_SPECS, execute_tool


class DemoTests(unittest.TestCase):
    def test_ensure_and_smoke(self) -> None:
        root = ensure_demo_workspace()
        self.assertTrue((root / "SCOPE.md").exists())
        self.assertTrue((root / "secrets" / "sessions.example.yaml").exists())
        self.assertTrue((root / "DEMO.md").exists())
        out = run_demo_smoke()
        self.assertTrue(out["ok"], msg=out)


class ProbeNlTests(unittest.TestCase):
    def test_ssrf_race_ws(self) -> None:
        for text, tool in (
            ("testa ssrf em https://example.com/?url=x targets/demo", "ssrf_probe"),
            ("race condition em https://example.com/checkout targets/demo", "race_probe"),
            ("websocket wss://example.com/ws targets/demo", "websocket_probe"),
        ):
            interp = interpret(text)
            plan = build_plan(text, interp)
            self.assertTrue(any(a.tool == tool for a in plan), msg=text)

    def test_dry_probes(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(
            "# Scope\n\n## In Scope\n- example.com\n\n"
            "## Explicitly Allowed\n- Active testing\n"
            "- Controlled race condition testing\n",
            encoding="utf-8",
        )
        for tool, extra in (
            ("ssrf_probe", {"param": "url"}),
            ("race_probe", {}),
            ("websocket_probe", {}),
        ):
            out = json.loads(
                execute_tool(
                    tool,
                    {
                        "target_dir": str(root),
                        "url": "https://example.com/"
                        if tool != "websocket_probe"
                        else "wss://example.com/ws",
                        "approve": False,
                        **extra,
                    },
                )
            )
            self.assertTrue(out.get("dry_run") or out.get("ok"), msg=tool)


class LearningRichTests(unittest.TestCase):
    def test_stats(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        learn_dir = Path(tmp.name)
        techniques = learn_dir / "techniques.jsonl"
        stats_file = learn_dir / "stats.json"
        with mock.patch("hackbot.learning.LEARN_DIR", learn_dir), mock.patch(
            "hackbot.learning.TECHNIQUES", techniques
        ), mock.patch("hackbot.learning.STATS_FILE", stats_file), mock.patch(
            "hackbot.learning.PATTERNS_FILE", learn_dir / "patterns.jsonl"
        ):
            record_technique(
                program="demo", module="idor", summary="x", host="example.com", outcome="validated"
            )
            stats = rebuild_stats()
            self.assertGreaterEqual(stats["total"], 1)
            self.assertIn("idor", stats["by_module"])
            self.assertTrue(learn_stats().get("ok"))


class ToolPackTests(unittest.TestCase):
    def test_auto_packs(self) -> None:
        packs = resolve_packs("testa ssrf e race no browser", explicit="auto")
        self.assertIn("core", packs)
        specs = filter_tool_specs(TOOL_SPECS, packs)
        names = {s["name"] for s in specs}
        self.assertIn("set_target", names)
        self.assertLess(len(specs), len(TOOL_SPECS))

    def test_all_pack(self) -> None:
        specs = filter_tool_specs(TOOL_SPECS, ["all"])
        self.assertEqual(len(specs), len(TOOL_SPECS))


class MobileDeepTests(unittest.TestCase):
    def test_frida_mobsf_status(self) -> None:
        fr = json.loads(execute_tool("frida_status", {}))
        self.assertTrue(fr["ok"])
        self.assertFalse(fr.get("auto_hook"))
        ms = json.loads(execute_tool("mobsf_health", {}))
        self.assertTrue(ms["ok"])

    def test_frida_script_dry(self) -> None:
        out = json.loads(
            execute_tool(
                "frida_run_script",
                {"package": "com.example.app", "script": "ssl_unpin_lab.js", "approve": False},
            )
        )
        self.assertTrue(out.get("dry_run"))


if __name__ == "__main__":
    unittest.main()
