"""Waves 1–11 autonomy coverage tests (dry-run / unit)."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hackbot.accounts import ensure_accounts_example, load_accounts
from hackbot.hunt_controller import Hypothesis, _decide, _rerank
from hackbot.hunt_telemetry import (
    clear_pause,
    is_paused,
    prehunt_checklist,
    record_telemetry,
    request_pause,
    telemetry_stats,
)
from hackbot.interactsh_client import interactsh_status
from hackbot.local_agent import build_plan, interpret
from hackbot.openapi_parse import parse_openapi_dict
from hackbot.tools import execute_tool


SCOPE = "# Scope\n\n## In Scope\n- example.com\n\n## Explicitly Allowed\n- Automated scanning\n"


class Wave1SessionTests(unittest.TestCase):
    def test_accounts_example_and_load(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        ensure_accounts_example(root)
        self.assertTrue((root / "secrets" / "accounts.example.yaml").exists())
        (root / "secrets" / "accounts.yaml").write_text(
            "accounts:\n  A:\n    username: a\n    password: p\n  B:\n    username: b\n    password: q\n",
            encoding="utf-8",
        )
        data = load_accounts(root)
        self.assertEqual(data.ready_names(), ["A", "B"])

    def test_session_bootstrap_dry(self) -> None:
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
        self.assertTrue(out["ok"])
        self.assertFalse(out["executed"])

    def test_nl_bootstrap(self) -> None:
        text = "faz login com accounts.yaml em example.com targets/demo"
        interp = interpret(text)
        self.assertIn("session_bootstrap", interp.intents)
        plan = build_plan(text, interp)
        self.assertTrue(any(a.tool == "session_bootstrap" for a in plan))


class Wave2ObserveTests(unittest.TestCase):
    def test_openapi_parse(self) -> None:
        spec = {
            "openapi": "3.0.0",
            "servers": [{"url": "https://example.com"}],
            "paths": {
                "/api/orders/{id}": {
                    "get": {"parameters": [{"name": "id", "in": "path"}]},
                    "patch": {"parameters": [{"name": "id", "in": "path"}]},
                }
            },
        }
        eps = parse_openapi_dict(spec, base_url="https://example.com")
        self.assertGreaterEqual(len(eps), 2)
        self.assertTrue(any(e.method == "PATCH" for e in eps))


class Wave3DecideTests(unittest.TestCase):
    def test_decide_bootstrap_when_accounts(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        (root / "secrets").mkdir()
        (root / "secrets" / "accounts.yaml").write_text(
            "accounts:\n  A:\n    username: a\n    password: p\n  B:\n    username: b\n    password: q\n",
            encoding="utf-8",
        )
        (root / "hunt").mkdir()
        from hackbot.hunt_memory import HuntMemory

        mem = HuntMemory(root)
        queue = _decide(mem, "example.com", "https://example.com", target_dir=root)
        mods = [h.module for h in queue]
        self.assertIn("session_bootstrap", mods)
        self.assertIn("secrets", mods)

    def test_rerank(self) -> None:
        q = [
            Hypothesis(module="cors", url="https://x", title="c", priority=10),
            Hypothesis(module="session_bootstrap", url="https://x", title="s", priority=10),
        ]
        out = _rerank(q, {"signal": True, "outcome": "needs_setup", "summary": "401"})
        self.assertGreaterEqual(out[0].priority, out[-1].priority)


class Wave4IdorTests(unittest.TestCase):
    def test_idor_methods_dry(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        (root / "secrets").mkdir()
        (root / "secrets" / "sessions.yaml").write_text(
            "sessions:\n  A:\n    authorization: Bearer a\n  B:\n    authorization: Bearer b\n",
            encoding="utf-8",
        )
        out = json.loads(
            execute_tool(
                "idor_probe",
                {
                    "target_dir": str(root),
                    "url": "https://example.com/api/orders/1",
                    "methods": "GET,PATCH",
                    "matrix": "both",
                    "approve": False,
                    "force": True,
                },
            )
        )
        self.assertTrue(out["ok"])
        self.assertFalse(out["executed"])
        self.assertIn("PATCH", str(out.get("detail", {}).get("methods")))


class Wave5ValidateTests(unittest.TestCase):
    def test_checklist(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        data = prehunt_checklist(root)
        self.assertTrue(data["checks"]["scope"])


class Wave6to11Tests(unittest.TestCase):
    def test_advanced_http_dry(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        for tool in ("mass_assignment_probe", "method_override_probe", "hpp_probe"):
            out = json.loads(
                execute_tool(
                    tool,
                    {
                        "target_dir": str(root),
                        "url": "https://example.com/api/me",
                        "approve": False,
                        "force": True,
                    },
                )
            )
            self.assertTrue(out["ok"], msg=tool)
            self.assertFalse(out["executed"], msg=tool)

    def test_interactsh_status(self) -> None:
        self.assertTrue(interactsh_status()["ok"])
        self.assertTrue(json.loads(execute_tool("interactsh_status", {}))["ok"])

    def test_cdp_dry(self) -> None:
        out = json.loads(execute_tool("cdp_attach", {"approve": False}))
        self.assertTrue(out.get("dry_run") or out.get("ok"))

    def test_pause_telemetry(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        request_pause(root)
        self.assertTrue(is_paused(root))
        clear_pause(root)
        self.assertFalse(is_paused(root))
        record_telemetry(root, {"module": "idor", "signal": True})
        stats = telemetry_stats(root)
        self.assertEqual(stats["events"], 1)

    def test_burp_history_tool(self) -> None:
        out = json.loads(execute_tool("burp_proxy_history", {}))
        self.assertIn("ok", out)


if __name__ == "__main__":
    unittest.main()
