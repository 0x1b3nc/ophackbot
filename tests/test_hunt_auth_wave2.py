"""Wave 2 hunt/auth: login detect, SSO needs_setup, session smoke, chain gating."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from hackbot.auth_continuity import session_smoke, sso_needs_setup_payload
from hackbot.hunt_controller import Hypothesis, _chain_from_result
from hackbot.hunt_memory import Endpoint, HuntMemory
from hackbot.local_agent import build_plan, interpret
from hackbot.login_detect import classify_login_html, detect_login
from hackbot.runners.session_bootstrap import session_bootstrap
from hackbot.tools import execute_tool


SCOPE = """# Scope

## In Scope
- example.com

## Explicitly Allowed
- Automated scanning
- Active testing
"""


class ClassifyLoginTests(unittest.TestCase):
    def test_form_with_password(self) -> None:
        html = (
            '<form action="/login"><input name="email" />'
            '<input type="password" name="password" /></form>'
        )
        out = classify_login_html(html, url="https://example.com/login", status=200)
        self.assertEqual(out["kind"], "form")
        self.assertEqual(out["user_field"], "email")
        self.assertEqual(out["pass_field"], "password")

    def test_sso_without_password(self) -> None:
        html = (
            '<a href="https://login.microsoftonline.com/common/oauth2/v2.0/authorize">'
            "Sign in with Microsoft</a>"
        )
        out = classify_login_html(html, url="https://example.com/login", status=200)
        self.assertEqual(out["kind"], "sso")
        self.assertTrue(out["sso_urls"])

    def test_json_api_path(self) -> None:
        out = classify_login_html(
            '{"error":"missing credentials"}',
            url="https://example.com/api/auth/login",
            status=400,
            content_type="application/json",
        )
        self.assertEqual(out["kind"], "json_api")
        self.assertIn("json", out["content_type"])


class DetectLoginToolTests(unittest.TestCase):
    def test_detect_login_dry_run(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        out = detect_login(root, "https://example.com", approve=False, force=True)
        self.assertTrue(out.get("dry_run"))

    def test_nl_detect_login(self) -> None:
        text = "detecta login em example.com targets/demo"
        interp = interpret(text)
        self.assertIn("detect_login", interp.intents)
        tools = [a.tool for a in build_plan(text, interp)]
        self.assertIn("detect_login", tools)


class SsoBootstrapTests(unittest.TestCase):
    def test_sso_payload(self) -> None:
        p = sso_needs_setup_payload(
            login_url="https://example.com/login",
            sso_urls=["https://login.microsoftonline.com/x"],
        )
        self.assertTrue(p["needs_setup"])
        self.assertEqual(p["reason"], "sso_detected")
        self.assertIn("will not bypass", p["hint"])

    def test_bootstrap_sso_needs_setup(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        (root / "secrets").mkdir()
        (root / "secrets" / "accounts.yaml").write_text(
            "accounts:\n  A:\n    username: a@x.com\n    password: p\n",
            encoding="utf-8",
        )
        detect_payload = {
            "ok": True,
            "kind": "sso",
            "login_url": "https://example.com/login",
            "sso_urls": ["https://okta.example/oauth2"],
            "needs_setup": True,
            "reason": "sso_detected",
            "confidence": "high",
        }
        with patch(
            "hackbot.runners.session_bootstrap.detect_login",
            return_value=detect_payload,
        ):
            result = session_bootstrap(
                root, "https://example.com", approve=True, force=True
            )
        data = json.loads(result.stdout)
        self.assertTrue(data.get("needs_setup"))
        self.assertEqual(data.get("reason"), "sso_detected")
        self.assertFalse(data.get("ok"))


class SessionSmokeTests(unittest.TestCase):
    def test_smoke_dry_run(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        out = session_smoke(root, "https://example.com", approve=False, force=True)
        self.assertTrue(out.get("dry_run"))
        self.assertTrue(out.get("skipped"))

    def test_smoke_ok_mock(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        (root / "secrets").mkdir()
        (root / "secrets" / "sessions.yaml").write_text(
            "sessions:\n  A:\n    cookie: sid=1\n",
            encoding="utf-8",
        )
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.body = b'{"id":1,"email":"a@x.com"}'
        mock_resp.url = "https://example.com/api/me"
        mock_resp.headers = {}
        with patch("hackbot.auth_continuity.scoped_fetch_bytes", return_value=mock_resp):
            out = session_smoke(
                root, "https://example.com", session="A", approve=True, force=True
            )
        self.assertTrue(out.get("ok"))
        self.assertFalse(out.get("skipped"))
        self.assertEqual(out.get("reason"), "whoami_ok")

    def test_smoke_unauthorized(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        (root / "secrets").mkdir()
        (root / "secrets" / "sessions.yaml").write_text(
            "sessions:\n  A:\n    cookie: sid=1\n",
            encoding="utf-8",
        )
        mock_resp = MagicMock()
        mock_resp.status = 401
        mock_resp.body = b"unauthorized"
        mock_resp.url = "https://example.com/api/me"
        mock_resp.headers = {}
        with patch("hackbot.auth_continuity.scoped_fetch_bytes", return_value=mock_resp):
            out = session_smoke(
                root, "https://example.com", session="A", approve=True, force=True
            )
        self.assertFalse(out.get("ok"))
        self.assertEqual(out.get("reason"), "unauthorized")

    def test_nl_session_smoke(self) -> None:
        text = "testa sessão A em example.com targets/demo"
        interp = interpret(text)
        self.assertIn("session_smoke", interp.intents)
        plan = build_plan(text, interp)
        sm = next(a for a in plan if a.tool == "session_smoke")
        self.assertEqual(sm.args.get("session"), "A")


class ChainGatingTests(unittest.TestCase):
    def test_idor_after_bootstrap_when_smoke_ok(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        mem = HuntMemory(root)
        mem.upsert_endpoints(
            [Endpoint(url="https://example.com/api/orders/1", params=["id"], source="test")],
            host="example.com",
        )
        hyp = Hypothesis(module="session_bootstrap", url="https://example.com", title="boot")
        follows = _chain_from_result(
            hyp,
            {"chain": True, "smoke_ok": True, "summary": "bootstrap sessions=['A']"},
            mem,
            "example.com",
        )
        self.assertIn("idor", [f.module for f in follows])

    def test_no_idor_when_smoke_fail(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        mem = HuntMemory(root)
        mem.upsert_endpoints(
            [Endpoint(url="https://example.com/api/orders/1", params=["id"], source="test")],
            host="example.com",
        )
        hyp = Hypothesis(module="session_bootstrap", url="https://example.com", title="boot")
        follows = _chain_from_result(
            hyp,
            {"chain": True, "smoke_ok": False, "summary": "bootstrap smoke_failed"},
            mem,
            "example.com",
        )
        self.assertNotIn("idor", [f.module for f in follows])

    def test_oauth_boost_on_sso_needs_setup(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        mem = HuntMemory(root)
        hyp = Hypothesis(module="session_bootstrap", url="https://example.com", title="boot")
        follows = _chain_from_result(
            hyp,
            {
                "outcome": "needs_setup",
                "summary": "SSO/IdP detected — operator must complete login",
                "sso_urls": ["https://example.com/oauth/authorize"],
            },
            mem,
            "example.com",
        )
        mods = [f.module for f in follows]
        self.assertIn("oauth", mods)
        self.assertNotIn("idor", mods)


class ToolWireTests(unittest.TestCase):
    def test_detect_login_tool_dry(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        out = json.loads(
            execute_tool(
                "detect_login",
                {
                    "target_dir": str(root),
                    "base_url": "https://example.com",
                    "approve": False,
                    "force": True,
                },
            )
        )
        self.assertTrue(out.get("ok"))
        self.assertTrue(out.get("dry_run"))


if __name__ == "__main__":
    unittest.main()
