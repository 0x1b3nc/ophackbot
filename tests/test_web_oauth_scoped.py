"""CORS / open-redirect / oauth use scoped HTTP (incl. no-follow redirects)."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from hackbot.runners.web_probes import cors_probe, open_redirect_probe
from hackbot.scoped_http import scoped_fetch_no_redirect
from hackbot.tools import execute_tool


SCOPE = """---
in_scope:
  - 127.0.0.1
out_of_scope:
  - localhost
allowed:
  - Active testing
---
"""


class _Lab(BaseHTTPRequestHandler):
    hits: list[str] = []

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def do_GET(self) -> None:  # noqa: N802
        from urllib.parse import parse_qs, urlparse

        host = self.headers.get("Host", "")
        _Lab.hits.append(f"{host}{self.path}")
        parsed = urlparse(self.path)
        qs = parse_qs(parsed.query)
        if parsed.path.startswith("/redir"):
            self.send_response(302)
            self.send_header(
                "Location",
                f"http://localhost:{self.server.server_address[1]}/landing",
            )
            self.end_headers()
            return
        if "next" in qs:
            self.send_response(302)
            self.send_header("Location", qs["next"][0])
            self.end_headers()
            return
        if parsed.path == "/cors":
            origin = self.headers.get("Origin", "")
            body = b"ok"
            self.send_response(200)
            self.send_header("Access-Control-Allow-Origin", origin or "*")
            self.send_header("Access-Control-Allow-Credentials", "true")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)
            return
        body = b"landing"
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class WebOauthScopedTests(unittest.TestCase):
    def setUp(self) -> None:
        _Lab.hits = []
        self.server = HTTPServer(("127.0.0.1", 0), _Lab)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()

    def test_no_redirect_records_location_without_follow(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
            url = f"http://127.0.0.1:{self.port}/redir"
            resp = scoped_fetch_no_redirect(
                url,
                target_dir=root,
                action="open redirect probe",
                force=False,
                timeout=5,
            )
            self.assertIn(resp.status, {302, 301, 303, 307, 308})
            self.assertTrue(resp.hops)
            self.assertFalse(resp.hops[0].get("followed", True))
            # Must not have fetched the OOS landing host
            self.assertFalse(any("localhost" in h and "/landing" in h for h in _Lab.hits))

    def test_open_redirect_probe_dry_and_live_signal(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
            url = f"http://127.0.0.1:{self.port}/"
            dry = open_redirect_probe(root, url, approve=False, force=False)
            self.assertEqual(dry.message, "dry-run")
            live = open_redirect_probe(
                root,
                url,
                param="next",
                approve=True,
                force=False,
            )
            payload = json.loads(live.stdout)
            self.assertTrue(payload.get("ok"))
            self.assertTrue(payload.get("signal"))
            self.assertIn("evil.example", payload.get("location", ""))

    def test_cors_probe_uses_scoped_transport(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
            result = cors_probe(
                root,
                f"http://127.0.0.1:{self.port}/cors",
                origin="https://evil.example",
                approve=True,
                force=False,
            )
            payload = json.loads(result.stdout)
            self.assertTrue(payload.get("ok"))
            self.assertTrue(payload.get("reflected"))

    def test_show_config_tool(self) -> None:
        raw = execute_tool("show_config", {"reload": True})
        data = json.loads(raw)
        self.assertTrue(data.get("ok"))
        self.assertIn("safety", data)
        self.assertGreaterEqual(int(data["safety"]["default_max_rps"]), 1)


if __name__ == "__main__":
    unittest.main()
