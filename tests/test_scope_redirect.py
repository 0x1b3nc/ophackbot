"""HB-001: redirects must re-gate SCOPE (OOS blocked without force)."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from hackbot.runners import http_request as http_mod


SCOPE = """---
in_scope:
  - 127.0.0.1
out_of_scope:
  - localhost
allowed:
  - Active testing
---
# Scope
"""


class _RedirectLab(BaseHTTPRequestHandler):
    hits: list[tuple[str, str]] = []

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def do_GET(self) -> None:  # noqa: N802
        host = self.headers.get("Host", "")
        _RedirectLab.hits.append((host, self.path))
        if self.path == "/start":
            # Cross-host redirect to OOS hostname (same port via Host)
            port = self.server.server_address[1]  # type: ignore[attr-defined]
            self.send_response(302)
            self.send_header("Location", f"http://localhost:{port}/landing")
            self.end_headers()
            return
        if self.path == "/landing":
            body = b"OUT_OF_SCOPE_REACHED"
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        self.send_response(404)
        self.end_headers()


class ScopeRedirectTests(unittest.TestCase):
    def setUp(self) -> None:
        _RedirectLab.hits = []
        self.server = HTTPServer(("127.0.0.1", 0), _RedirectLab)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()

    def test_redirect_to_oos_blocked(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
            result = http_mod.http_request(
                root,
                f"http://127.0.0.1:{self.port}/start",
                approve=True,
                force=False,
            )
            payload = json.loads(result.stdout)
            self.assertFalse(payload.get("ok"))
            self.assertIn("out of scope", (payload.get("error") or "").lower())
            # Landing must never be hit
            landing = [h for h in _RedirectLab.hits if h[1] == "/landing"]
            self.assertEqual(landing, [])

    def test_redirect_to_oos_allowed_with_force(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
            result = http_mod.http_request(
                root,
                f"http://127.0.0.1:{self.port}/start",
                approve=True,
                force=True,
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload.get("ok"), payload)
            landing = [h for h in _RedirectLab.hits if h[1] == "/landing"]
            self.assertEqual(len(landing), 1)


if __name__ == "__main__":
    unittest.main()
