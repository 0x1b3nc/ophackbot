"""Cursor-like compact UI helpers."""

from __future__ import annotations

import unittest

from hackbot.ui import format_http_action, format_session_footer, short_host


class UiCompactTests(unittest.TestCase):
    def test_session_footer(self) -> None:
        self.assertEqual(
            format_session_footer("codex", "high", "aylo", "yolo", "step off"),
            "codex · high · aylo · yolo · step off",
        )
        self.assertEqual(format_session_footer("", "  "), "")

    def test_short_host(self) -> None:
        self.assertEqual(short_host("https://www.adultforce.com/api"), "www.adultforce.com/api")
        self.assertEqual(short_host("https://example.com/"), "example.com")

    def test_http_action_ok(self) -> None:
        line = format_http_action(
            "HEAD",
            "https://www.adultforce.com/api",
            status=200,
            elapsed_ms=120.4,
        )
        self.assertIn("HEAD", line)
        self.assertIn("www.adultforce.com/api", line)
        self.assertIn("200", line)
        self.assertIn("120ms", line)

    def test_http_action_timeout(self) -> None:
        line = format_http_action(
            "HEAD",
            "https://www.adultforce.com/api",
            error="URLError: <urlopen error timed out>",
        )
        self.assertIn("HEAD", line)
        self.assertIn("timeout", line)
        self.assertNotIn("URLError", line)


if __name__ == "__main__":
    unittest.main()
