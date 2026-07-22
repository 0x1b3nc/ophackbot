"""http_request tool results must include headers for the model."""

from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from hackbot.runners.http_request import mask_response_headers
from hackbot.tools import _headers_for_model, _tool_http_request


SCOPE = """# Scope

## In Scope
- example.com

## Explicitly Allowed
- Passive recon
- Automated scanning
"""


class HttpToolResultTests(unittest.TestCase):
    def test_mask_keeps_server_redacts_cookie(self) -> None:
        out = mask_response_headers(
            {
                "Server": "postgres-server",
                "Set-Cookie": "sid=secret",
                "X-Powered-By": "Express",
            }
        )
        self.assertEqual(out["Server"], "postgres-server")
        self.assertEqual(out["X-Powered-By"], "Express")
        self.assertEqual(out["Set-Cookie"], "***")

    def test_headers_for_model_accepts_dict_and_json_string(self) -> None:
        self.assertEqual(_headers_for_model({"Server": "nginx"}), {"Server": "nginx"})
        self.assertEqual(
            _headers_for_model('{"Server": "nginx"}'),
            {"Server": "nginx"},
        )

    def test_tool_result_includes_headers(self) -> None:
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        root = Path(tmp.name)
        (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")

        fake_stdout = json.dumps(
            {
                "ok": True,
                "method": "HEAD",
                "url": "https://example.com/api/",
                "final_url": "https://example.com/api/",
                "status": 200,
                "elapsed_ms": 12.0,
                "length": 0,
                "sha256": "abc",
                "headers": {
                    "Server": "elasticsearch-server",
                    "Content-Type": "application/json",
                },
                "body_preview": "",
                "body": "",
                "error": "",
                "redirect_hops": [],
            }
        )

        class FakeResult:
            executed = True
            returncode = 0
            stdout = fake_stdout
            stderr = ""
            message = "executed"

        with mock.patch(
            "hackbot.tools.http_request_runner.http_request",
            return_value=FakeResult(),
        ):
            raw = _tool_http_request(
                {
                    "target_dir": str(root),
                    "url": "https://example.com/api/",
                    "method": "HEAD",
                    "approve": False,
                },
                approve_fn=None,
            )
        data = json.loads(raw)
        self.assertIn("headers", data)
        self.assertEqual(data["headers"].get("Server"), "elasticsearch-server")
        self.assertEqual(data.get("method"), "HEAD")
        self.assertIn("headers", (data.get("hint") or "").lower())


if __name__ == "__main__":
    unittest.main()
