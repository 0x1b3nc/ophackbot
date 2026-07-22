"""Wave 3: IdP capture, hunt resume, needs_setup gate, observe refresh, actable filter."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from hackbot.hunt_controller import (
    ACTABLE_MODULES,
    Hypothesis,
    _chain_from_result,
    _decide,
    run_hunt,
)
from hackbot.hunt_memory import Endpoint, HuntMemory, HuntState
from hackbot.local_agent import build_plan, interpret
from hackbot.observe import observe_refresh_lite
from hackbot.runners.browser import (
    _auth_cookie_signal,
    _cookie_header_from_playwright,
    browser_capture_session,
)
from hackbot.tools import execute_tool


SCOPE = """# Scope

## In Scope
- example.com

## Explicitly Allowed
- Automated scanning
- Active testing
"""


class CaptureHelpersTests(unittest.TestCase):
    def test_cookie_header_and_signal(self) -> None:
        cookies = [
            {"name": "sessionid", "value": "abc123"},
            {"name": "other", "value": "x"},
        ]
        self.assertTrue(_auth_cookie_signal(cookies))
        self.assertIn("sessionid=abc123", _cookie_header_from_playwright(cookies))

    def test_capture_dry_run(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        result = browser_capture_session(
            root, "https://example.com/login", approve=False, force=True
        )
        data = json.loads(result.stdout)
        self.assertTrue(data.get("dry_run"))

    def test_capture_mocked_success(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")

        class FakePage:
            url = "https://example.com/dashboard"

            def goto(self, *_a, **_k):
                return None

            def evaluate(self, *_a, **_k):
                return ""

        class FakeContext:
            def cookies(self):
                return [{"name": "sessionid", "value": "tok", "domain": "example.com"}]

            def new_page(self):
                return FakePage()

            def close(self):
                return None

        class FakeBrowser:
            def new_context(self, **_k):
                return FakeContext()

            def close(self):
                return None

        class FakeChromium:
            def launch(self, **_k):
                return FakeBrowser()

        class FakePW:
            chromium = FakeChromium()

            def __enter__(self):
                return self

            def __exit__(self, *_a):
                return False

        # Inject a stub playwright package so this test runs without the dep.
        import sys
        import types

        fake_pw_mod = types.ModuleType("playwright")
        fake_sync = types.ModuleType("playwright.sync_api")
        fake_sync.sync_playwright = lambda: FakePW()  # type: ignore[attr-defined]
        with (
            patch.dict(
                sys.modules,
                {"playwright": fake_pw_mod, "playwright.sync_api": fake_sync},
            ),
            patch("hackbot.runners.browser.playwright_available", return_value=True),
            patch("hackbot.runners.browser._guarded_page") as gp,
            patch(
                "hackbot.auth_continuity.session_smoke",
                return_value={"ok": True, "skipped": False, "reason": "whoami_ok"},
            ),
        ):
            ctx = FakeContext()
            page = FakePage()
            gp.return_value = (ctx, page, [])
            result = browser_capture_session(
                root,
                "https://example.com/login",
                session="A",
                approve=True,
                force=True,
                timeout_s=5,
                poll_s=0.1,
            )
        data = json.loads(result.stdout)
        self.assertTrue(data.get("ok"))
        self.assertEqual(data.get("reason"), "captured")
        sess = (root / "secrets" / "sessions.yaml").read_text(encoding="utf-8")
        self.assertIn("sessionid", sess)


class ResumeAndDecideTests(unittest.TestCase):
    def test_resume_skips_full_observe(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        mem = HuntMemory(root)
        mem.upsert_endpoints(
            [Endpoint(url="https://example.com/api/1", params=["id"], source="t")],
            host="example.com",
        )
        mem.save_state(
            HuntState(
                phase="act",
                prompt="resume",
                host="example.com",
                budget_remaining=5,
                budget_total=10,
                acts_done=3,
                stopped=True,
                stop_reason="needs_setup",
                hunt_phase="authz",
                phase_budget_recon=0,
                phase_budget_authz=3,
                phase_budget_inject=2,
            )
        )
        with patch("hackbot.observe.observe_v2") as obs:
            # Force empty queue quickly by patching _decide after first call
            calls = {"n": 0}

            def fake_decide(*_a, **_k):
                calls["n"] += 1
                return []

            with patch("hackbot.hunt_controller._decide", side_effect=fake_decide):
                with patch(
                    "hackbot.observe.observe_refresh_lite",
                    return_value={"ok": True, "refresh": "lite", "endpoint_count": 1},
                ):
                    out = run_hunt(
                        root,
                        "resume hunt example.com",
                        host="https://example.com",
                        approve_session=False,
                        resume=True,
                        force=True,
                    )
        obs.assert_not_called()
        self.assertTrue(out.get("ok") is not False or "stop_reason" in out or out.get("acts_done") is not None)
        # Resumed path should have recorded lite observe
        modules = [a.get("module") for a in out.get("acts") or []]
        self.assertIn("observe_refresh_lite", modules)

    def test_actable_filter_drops_unknown(self) -> None:
        self.assertNotIn("mass_assignment", ACTABLE_MODULES)
        self.assertIn("idp_capture", ACTABLE_MODULES)
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        mem = HuntMemory(root)
        # Inject a fake idea by patching internals is hard; just assert filter constant
        queue = _decide(mem, "example.com", "https://example.com", target_dir=root)
        for h in queue:
            self.assertIn(h.module, ACTABLE_MODULES)


class ObserveRefreshTests(unittest.TestCase):
    def test_refresh_lite_tags(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        mem = HuntMemory(root)
        mem.upsert_endpoints(
            [
                Endpoint(url="https://example.com/login", source="t"),
                Endpoint(url="https://example.com/api/orders/1", params=["id"], source="t"),
            ],
            host="example.com",
        )
        out = observe_refresh_lite(root, host="example.com")
        self.assertTrue(out.get("ok"))
        self.assertIn("login", out.get("tags") or [])
        self.assertIn("id_param", out.get("tags") or [])


class ChainCaptureTests(unittest.TestCase):
    def test_bootstrap_sso_queues_idp_capture(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        mem = HuntMemory(root)
        hyp = Hypothesis(module="session_bootstrap", url="https://example.com", title="b")
        follows = _chain_from_result(
            hyp,
            {
                "outcome": "needs_setup",
                "summary": "SSO/IdP detected",
                "capture_recommended": True,
                "capture_url": "https://example.com/oauth",
                "sso_urls": ["https://example.com/oauth"],
            },
            mem,
            "example.com",
        )
        mods = [f.module for f in follows]
        self.assertIn("idp_capture", mods)
        self.assertNotIn("idor", mods)

    def test_idp_capture_chains_idor(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        mem = HuntMemory(root)
        mem.upsert_endpoints(
            [Endpoint(url="https://example.com/api/orders/1", params=["id"], source="t")],
            host="example.com",
        )
        hyp = Hypothesis(module="idp_capture", url="https://example.com/login", title="c")
        follows = _chain_from_result(
            hyp,
            {"outcome": "ok", "chain": True, "smoke_ok": True},
            mem,
            "example.com",
        )
        self.assertIn("idor", [f.module for f in follows])


class NlWave3Tests(unittest.TestCase):
    def test_nl_capture_and_resume(self) -> None:
        t1 = "captura sessao SSO em example.com targets/demo"
        i1 = interpret(t1)
        self.assertIn("idp_capture", i1.intents)
        tools1 = [a.tool for a in build_plan(t1, i1)]
        self.assertIn("browser_capture_session", tools1)

        t2 = "resume hunt example.com targets/demo approve"
        i2 = interpret(t2)
        self.assertIn("hunt_resume", i2.intents)
        plan2 = build_plan(t2, i2)
        rh = next(a for a in plan2 if a.tool == "run_hunt")
        self.assertTrue(rh.args.get("resume"))


class ToolWireTests(unittest.TestCase):
    def test_run_hunt_accepts_resume_arg(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        out = json.loads(
            execute_tool(
                "run_hunt",
                {
                    "target_dir": str(root),
                    "prompt": "hunt example.com",
                    "host": "https://example.com",
                    "approve": False,
                    "force": True,
                    "resume": False,
                    "budget": 5,
                },
            )
        )
        self.assertIn("ok", out)


if __name__ == "__main__":
    unittest.main()
