"""Local web UI API smoke tests."""

from __future__ import annotations

import json
import threading
import unittest
from http.client import HTTPConnection
from unittest import mock

from hackbot.web_server import HackbotHandler, ThreadingHTTPServer, _resolve_mode


class WebServerTests(unittest.TestCase):
    def test_resolve_mode_defaults_offline(self) -> None:
        with mock.patch.dict("os.environ", {"HACKBOT_PROVIDER": "", "HACKBOT_LOCAL": ""}, clear=False):
            mode, label = _resolve_mode()
        self.assertEqual(mode, "offline")
        self.assertIn("offline", label)

    def test_status_endpoint(self) -> None:
        httpd = ThreadingHTTPServer(("127.0.0.1", 0), HackbotHandler)
        port = httpd.server_address[1]
        thread = threading.Thread(target=httpd.serve_forever, daemon=True)
        thread.start()
        try:
            conn = HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/api/status")
            resp = conn.getresponse()
            body = json.loads(resp.read().decode("utf-8"))
            self.assertEqual(resp.status, 200)
            self.assertTrue(body.get("ok"))
            self.assertIn("mode", body)
            conn.close()

            conn = HTTPConnection("127.0.0.1", port, timeout=5)
            conn.request("GET", "/")
            resp = conn.getresponse()
            html = resp.read().decode("utf-8")
            self.assertEqual(resp.status, 200)
            self.assertIn("hackbot", html.lower())
            conn.close()
        finally:
            httpd.shutdown()
            httpd.server_close()


if __name__ == "__main__":
    unittest.main()
