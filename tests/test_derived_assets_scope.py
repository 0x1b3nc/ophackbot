"""HB-002: HAR-derived OpenAPI must not fetch OOS hosts without force."""

from __future__ import annotations

import json
import tempfile
import threading
import unittest
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

from hackbot.observe import observe_v2
from hackbot.runners.har_import import import_har


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


class _Lab(BaseHTTPRequestHandler):
    hits: list[tuple[str, str]] = []

    def log_message(self, format: str, *args) -> None:  # noqa: A003
        return

    def do_GET(self) -> None:  # noqa: N802
        host = self.headers.get("Host", "")
        _Lab.hits.append((host, self.path))
        if self.path == "/":
            body = b"<html><body>ok</body></html>"
        elif self.path == "/openapi.json":
            body = b'{"openapi":"3.0.0","paths":{}}'
        else:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "application/json" if "openapi" in self.path else "text/html")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)


class DerivedAssetsScopeTests(unittest.TestCase):
    def setUp(self) -> None:
        _Lab.hits = []
        self.server = HTTPServer(("127.0.0.1", 0), _Lab)
        self.port = self.server.server_address[1]
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self) -> None:
        self.server.shutdown()

    def test_har_skips_oos_seed_and_observe_skips_fetch(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "SCOPE.md").write_text(SCOPE, encoding="utf-8")
            har = {
                "log": {
                    "entries": [
                        {
                            "request": {
                                "method": "GET",
                                "url": f"http://localhost:{self.port}/openapi.json",
                                "headers": [],
                            },
                            "response": {"status": 200},
                        }
                    ]
                }
            }
            har_path = root / "traffic.har"
            har_path.write_text(json.dumps(har), encoding="utf-8")
            imported = import_har(har_path, root)
            self.assertGreaterEqual(int(imported.get("skipped_oos") or 0), 1)
            self.assertEqual(int(imported.get("endpoints_seeded") or 0), 0)

            # Even if somehow on surface, observe must not fetch OOS openapi
            from hackbot.hunt_memory import Endpoint, HuntMemory

            HuntMemory(root).upsert_endpoints(
                [
                    Endpoint(
                        url=f"http://localhost:{self.port}/openapi.json",
                        source="har",
                    )
                ],
                host="127.0.0.1",
            )
            out = observe_v2(
                root,
                f"http://127.0.0.1:{self.port}/",
                approve=True,
                force=False,
            )
            openapi_steps = [
                s for s in (out.get("steps") or []) if s.get("step") == "openapi_fetch"
            ]
            self.assertTrue(openapi_steps)
            self.assertTrue(
                any(s.get("skipped") or "scope" in str(s.get("error", "")).lower() for s in openapi_steps)
            )
            oos_openapi = [
                h for h in _Lab.hits if "localhost" in h[0] and h[1] == "/openapi.json"
            ]
            self.assertEqual(oos_openapi, [])


class BoolParseAndJarTests(unittest.TestCase):
    def test_parse_bool_false_string(self) -> None:
        from hackbot.boolparse import parse_bool

        self.assertFalse(parse_bool("false"))
        self.assertFalse(parse_bool("0"))
        self.assertTrue(parse_bool("true"))

    def test_jar_session_isolation(self) -> None:
        from hackbot.hunt_jar import cookie_header, merge_set_cookie

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            merge_set_cookie(
                root,
                ["sidA=aaa; Domain=example.com"],
                url="https://example.com/",
                session="A",
            )
            merge_set_cookie(
                root,
                ["sidB=bbb; Domain=example.com"],
                url="https://example.com/",
                session="B",
            )
            a = cookie_header(root, host="example.com", session="A")
            b = cookie_header(root, host="example.com", session="B")
            self.assertIn("sidA=aaa", a)
            self.assertNotIn("sidB", a)
            self.assertIn("sidB=bbb", b)
            self.assertNotIn("sidA", b)


if __name__ == "__main__":
    unittest.main()
