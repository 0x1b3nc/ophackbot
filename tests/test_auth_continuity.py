"""Auth continuity: CSRF inject, MFA needs_setup, 401 detection, refresh dry-run."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from hackbot.auth_continuity import (
    extract_csrf,
    inject_csrf,
    looks_like_mfa,
    mfa_needs_setup_payload,
    prepare_write,
    refresh_session,
    result_indicates_unauthorized,
)
from hackbot.hunt_controller import Hypothesis, _chain_from_result
from hackbot.hunt_memory import HuntMemory


SCOPE = """# Scope

## In Scope
- example.com

## Explicitly Allowed
- Automated scanning
- Active testing
"""


class CsrfTests(unittest.TestCase):
    def test_extract_csrf_input_and_meta(self) -> None:
        html = '<input type="hidden" name="authenticity_token" value="tok123">'
        field, token = extract_csrf(html, "csrf_token")
        self.assertEqual(token, "tok123")
        self.assertEqual(field, "authenticity_token")

        html2 = '<meta name="csrf-token" content="meta999">'
        field2, token2 = extract_csrf(html2)
        self.assertEqual(token2, "meta999")

    def test_inject_csrf_json_and_form(self) -> None:
        out = inject_csrf('{"name":"x"}', field="csrf_token", token="abc")
        data = json.loads(out or "{}")
        self.assertEqual(data["csrf_token"], "abc")
        self.assertEqual(data["name"], "x")

        form = inject_csrf(
            "a=1",
            field="_token",
            token="zzz",
            content_type="application/x-www-form-urlencoded",
        )
        self.assertIn("_token=zzz", form or "")
        self.assertIn("a=1", form or "")


class MfaTests(unittest.TestCase):
    def test_looks_like_mfa(self) -> None:
        self.assertTrue(looks_like_mfa("Enter your verification code (TOTP)", 200))
        self.assertFalse(looks_like_mfa("welcome dashboard", 200))
        self.assertFalse(looks_like_mfa("mfa setup page", 500))

    def test_mfa_payload_clear(self) -> None:
        p = mfa_needs_setup_payload(session="A", login_url="https://example.com/login")
        self.assertTrue(p["needs_setup"])
        self.assertEqual(p["reason"], "mfa_detected")
        self.assertIn("will not bypass MFA", p["hint"])
        self.assertGreaterEqual(len(p["next_steps"]), 2)


class UnauthorizedDetectionTests(unittest.TestCase):
    def test_summary_and_nested_status(self) -> None:
        self.assertTrue(result_indicates_unauthorized({"summary": "got 401 from API"}))
        self.assertTrue(
            result_indicates_unauthorized(
                {"summary": "clean", "detail": {"rows": [{"status": 401}]}}
            )
        )
        self.assertTrue(
            result_indicates_unauthorized(
                {"summary": "x", "detail": {"status_a": 401, "status_b": 200}}
            )
        )
        self.assertFalse(
            result_indicates_unauthorized({"summary": "needs_setup mfa", "outcome": "needs_setup"})
        )


class PrepareWriteTests(unittest.TestCase):
    def test_prepare_write_injects_headers_and_body(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        (root / "secrets").mkdir()
        (root / "secrets" / "sessions.yaml").write_text(
            "sessions:\n  A:\n    cookie: sid=1\n",
            encoding="utf-8",
        )
        (root / "secrets" / "accounts.yaml").write_text(
            "login:\n  csrf_field: csrf_token\naccounts:\n  A:\n    username: a\n    password: p\n",
            encoding="utf-8",
        )

        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.body = b'<input name="csrf_token" value="live-csrf">'
        mock_resp.headers = {}

        with patch("hackbot.auth_continuity.scoped_fetch_bytes", return_value=mock_resp):
            body, headers, meta = prepare_write(
                root,
                "https://example.com/api/orders/1",
                session="A",
                body='{"title":"n"}',
                force=True,
            )
        self.assertTrue(meta.get("ok"))
        self.assertEqual(headers.get("X-CSRF-Token"), "live-csrf")
        parsed = json.loads(body or "{}")
        self.assertEqual(parsed["csrf_token"], "live-csrf")
        self.assertEqual(parsed["title"], "n")
        cache = (root / "hunt" / "csrf.yaml").read_text(encoding="utf-8")
        self.assertIn("live-csrf", cache)


class RefreshTests(unittest.TestCase):
    def test_refresh_requires_approve(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        out = refresh_session(root, "https://example.com", session="A", approve=False)
        self.assertFalse(out["ok"])
        self.assertEqual(out["error"], "approve_required")


class ChainAuthWallTests(unittest.TestCase):
    def test_chain_queues_bootstrap_on_401(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        mem = HuntMemory(root)
        hyp = Hypothesis(module="idor", url="https://example.com/api/1", title="idor")
        follows = _chain_from_result(
            hyp,
            {"summary": "unauthorized", "detail": {"status": 401}},
            mem,
            "example.com",
        )
        mods = [f.module for f in follows]
        self.assertIn("session_bootstrap", mods)

    def test_chain_skips_bootstrap_after_successful_refresh(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        mem = HuntMemory(root)
        hyp = Hypothesis(module="idor", url="https://example.com/api/1", title="idor")
        follows = _chain_from_result(
            hyp,
            {
                "summary": "clean",
                "auth_refreshed": True,
                "detail": {"status": 200},
            },
            mem,
            "example.com",
        )
        mods = [f.module for f in follows]
        self.assertNotIn("session_bootstrap", mods)


if __name__ == "__main__":
    unittest.main()
