"""Codex ```hackbot-tool``` bridge: extract, normalize, apply, continue."""

from __future__ import annotations

import json
import unittest
from unittest import mock

from hackbot.codex_backend import (
    PREAMBLE_CHAT,
    PREAMBLE_HUNT,
    _SESSION_RULES,
    _apply_tool_calls,
    _curl_bypass_nudge,
    _extract_tool_calls,
    _normalize_tool_call,
    _shell_http_urls,
    _tool_continue_prompt,
)


class CodexToolBridgeTests(unittest.TestCase):
    def test_preamble_requires_hackbot_tool_for_http(self) -> None:
        self.assertIn("hackbot-tool", PREAMBLE_HUNT)
        self.assertIn("http_request", PREAMBLE_HUNT)
        self.assertIn("MUST emit", _SESSION_RULES)
        self.assertIn("Do NOT use shell", _SESSION_RULES)
        self.assertNotIn("Do NOT run shell commands", PREAMBLE_CHAT)

    def test_extract_tool_block(self) -> None:
        raw = (
            "Vou fazer o GET.\n\n```hackbot-tool\n"
            + json.dumps(
                {
                    "tool": "http_request",
                    "args": {
                        "url": "https://example.com/",
                        "method": "GET",
                        "approve": True,
                    },
                }
            )
            + "\n```\n"
        )
        cleaned, calls = _extract_tool_calls(raw)
        self.assertEqual(len(calls), 1)
        self.assertEqual(calls[0]["tool"], "http_request")
        self.assertNotIn("hackbot-tool", cleaned)

    def test_normalize_fills_active_target_dir(self) -> None:
        fake = mock.Mock()
        fake.target_dir = "targets/aylo"
        with mock.patch("hackbot.codex_backend.get_active", return_value=fake):
            name, args = _normalize_tool_call(
                {"tool": "http_request", "args": {"url": "https://x/", "approve": True}}
            )
        self.assertEqual(name, "http_request")
        self.assertEqual(args.get("target_dir"), "targets/aylo")

    def test_apply_runs_execute_tool(self) -> None:
        with mock.patch(
            "hackbot.tools.execute_tool",
            return_value=json.dumps({"ok": True, "status": 200}),
        ) as ex:
            out = _apply_tool_calls(
                [
                    {
                        "tool": "http_request",
                        "args": {
                            "target_dir": "targets/demo",
                            "url": "https://example.com/",
                            "approve": True,
                        },
                    }
                ],
                approve_fn=lambda _d: True,
            )
        self.assertEqual(len(out), 1)
        self.assertTrue(out[0]["ok"])
        ex.assert_called_once()
        self.assertEqual(ex.call_args[0][0], "http_request")

    def test_shell_http_detection_and_nudge(self) -> None:
        urls = _shell_http_urls("curl -s https://www.adultforce.com/api/")
        self.assertEqual(urls, ["https://www.adultforce.com/api/"])
        nudge = _curl_bypass_nudge("proximo passo", urls)
        self.assertIn("http_request", nudge)
        self.assertIn("hackbot-tool", nudge)
        self.assertIn("adultforce.com", nudge)

    def test_continue_prompt_includes_result(self) -> None:
        text = _tool_continue_prompt(
            "GET na home",
            [
                {
                    "tool": "http_request",
                    "ok": True,
                    "result": '{"ok": true, "status": 200}',
                    "args": {"url": "https://example.com/"},
                }
            ],
        )
        self.assertIn("http_request", text)
        self.assertIn("200", text)
        self.assertIn("GET na home", text)
        self.assertIn("Do NOT claim tools are missing", text)


if __name__ == "__main__":
    unittest.main()
