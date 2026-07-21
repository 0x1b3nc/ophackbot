"""Interactsh client + Burp control plane (mocked network)."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hackbot import interactsh_client as ic
from hackbot.oob import mint_canary, poll_oob
from hackbot.runners import burp
from hackbot.tools import execute_tool


SCOPE = "# Scope\n\n## In Scope\n- example.com\n\n## Explicitly Allowed\n- Active testing\n"


class InteractshClientTests(unittest.TestCase):
    def setUp(self) -> None:
        self._env = os.environ.copy()
        ic._SESSION = None

    def tearDown(self) -> None:
        os.environ.clear()
        os.environ.update(self._env)
        ic._SESSION = None

    def test_status_disabled(self) -> None:
        os.environ.pop("HACKBOT_INTERACTSH", None)
        os.environ.pop("HACKBOT_INTERACTSH_SERVER", None)
        os.environ.pop("HACKBOT_OOB_BASE", None)
        st = ic.interactsh_status()
        self.assertTrue(st["ok"])
        self.assertFalse(st["interactsh_enabled"])

    def test_register_mocked(self) -> None:
        os.environ["HACKBOT_INTERACTSH"] = "1"
        os.environ["HACKBOT_INTERACTSH_SERVER"] = "oast.test"

        class _Resp:
            status = 200

            def read(self, _n: int = 0) -> bytes:
                return b'{"message":"registration successful"}'

            def getcode(self) -> int:
                return 200

            def __enter__(self) -> "_Resp":
                return self

            def __exit__(self, *a: object) -> None:
                return None

        with mock.patch("urllib.request.urlopen", return_value=_Resp()):
            out = ic.interactsh_register(force_new=True)
        self.assertTrue(out.get("ok"), msg=out)
        self.assertEqual(out.get("mode"), "interactsh")
        self.assertIn("oast.test", out["canary"]["dns_host"])

    def test_legacy_poll_sends_auth(self) -> None:
        os.environ.pop("HACKBOT_INTERACTSH", None)
        os.environ.pop("HACKBOT_INTERACTSH_SERVER", None)
        os.environ["HACKBOT_OOB_BASE"] = "https://oob.example"
        os.environ["HACKBOT_OOB_POLL_URL"] = "https://poll.example/TOKEN"
        os.environ["HACKBOT_OOB_AUTH"] = "secret-token"
        canary = mint_canary(kind="ssrf", prefer_interactsh=False)
        captured: dict[str, str] = {}

        class _Resp:
            def read(self, _n: int = 0) -> bytes:
                return canary["token"].encode()

            def __enter__(self) -> "_Resp":
                return self

            def __exit__(self, *a: object) -> None:
                return None

        def fake_urlopen(req: object, timeout: float = 0) -> _Resp:
            get_header = getattr(req, "get_header", None)
            captured["auth"] = get_header("Authorization") if callable(get_header) else ""
            captured["url"] = getattr(req, "full_url", "") or ""
            return _Resp()

        with mock.patch("urllib.request.urlopen", side_effect=fake_urlopen):
            out = poll_oob(canary)
        self.assertTrue(out.get("signal"))
        self.assertIn("secret-token", captured.get("auth") or "")
        self.assertIn(canary["token"], captured.get("url") or "")


class BurpReplayTests(unittest.TestCase):
    def test_replay_dry_run(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        out = burp.burp_replay_request(
            root,
            url="https://example.com/api",
            approve=False,
            force=True,
        )
        self.assertTrue(out.get("dry_run"))

    def test_replay_tool_dry(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        raw = execute_tool(
            "burp_replay",
            {
                "target_dir": str(root),
                "url": "https://example.com/",
                "approve": False,
                "force": True,
            },
        )
        data = json.loads(raw)
        self.assertTrue(data.get("ok") or data.get("dry_run"))

    def test_mcp_cmd_missing(self) -> None:
        os.environ.pop("HACKBOT_BURP_MCP_CMD", None)
        out = burp.burp_mcp_call("send_http_request", {"url": "https://example.com/"})
        self.assertFalse(out.get("ok"))
        self.assertIn("not set", out.get("error") or "")


class XxeOobDryTests(unittest.TestCase):
    def test_xxe_dry_shows_oob_flag(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
        os.environ["HACKBOT_OOB_BASE"] = "https://oob.example"
        try:
            raw = execute_tool(
                "xxe_probe",
                {
                    "target_dir": str(root),
                    "url": "https://example.com/xml",
                    "approve": False,
                    "force": True,
                },
            )
            data = json.loads(raw)
            detail = data.get("detail") or data
            self.assertTrue(detail.get("dry_run") or data.get("ok"))
        finally:
            os.environ.pop("HACKBOT_OOB_BASE", None)


if __name__ == "__main__":
    unittest.main()
