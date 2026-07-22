"""Codex JSON stream progress: think/run/tool/plan visible live."""

from __future__ import annotations

import json
import unittest

from hackbot.codex_backend import _handle_event


class CodexStreamEventTests(unittest.TestCase):
    def test_thread_started_prints_nothing(self) -> None:
        printed: list[str] = []
        hdr: dict = {}
        shown = _handle_event(
            {"type": "thread.started", "thread_id": "abc"},
            hdr,
            before_print=lambda: printed.append("stop"),
        )
        self.assertFalse(shown)
        self.assertEqual(printed, [])

    def test_turn_started_silent(self) -> None:
        hdr: dict = {}
        shown = _handle_event({"type": "turn.started"}, hdr)
        self.assertFalse(shown)

    def test_reasoning_shows_think(self) -> None:
        hdr: dict = {}
        shown = _handle_event(
            {
                "type": "item.completed",
                "item": {
                    "id": "r1",
                    "type": "reasoning",
                    "text": "Vou validar o health endpoint com http_request.",
                },
            },
            hdr,
        )
        self.assertTrue(shown)

    def test_agent_message_announces_tool_proposal(self) -> None:
        sink: list[str] = []
        hdr: dict = {}
        body = (
            "Proximo passo.\n\n```hackbot-tool\n"
            + json.dumps(
                {
                    "tool": "http_request",
                    "args": {
                        "url": "https://www.adultforce.com/api/",
                        "method": "GET",
                        "approve": True,
                    },
                }
            )
            + "\n```\n"
        )
        shown = _handle_event(
            {
                "type": "item.completed",
                "item": {"id": "m1", "type": "agent_message", "text": body},
            },
            hdr,
            answer_sink=sink,
        )
        self.assertTrue(shown)
        self.assertEqual(sink[0].strip(), body.strip())
        self.assertIn("http_request", sink[0])

    def test_agent_message_plan_line_without_tool(self) -> None:
        hdr: dict = {}
        shown = _handle_event(
            {
                "type": "item.completed",
                "item": {
                    "id": "m2",
                    "type": "agent_message",
                    "text": "Vou checar o endpoint de health com um GET baixo impacto.",
                },
            },
            hdr,
            answer_sink=[],
        )
        self.assertTrue(shown)

    def test_command_list_argv_shows_raw_zsh(self) -> None:
        hdr: dict = {}
        meta: dict = {"shell_http": []}
        script = (
            "for u in 'https://www.adultforce.com/api/' 'https://www.adultforce.com/api'; do "
            "curl -k -sS -H 'X-Bug-Bounty: durkzprg' \"$u\"; done"
        )
        shown1 = _handle_event(
            {
                "type": "item.started",
                "item": {
                    "id": "c1",
                    "type": "command_execution",
                    "command": ["/usr/bin/zsh", "-lc", script],
                    "status": "in_progress",
                    "aggregated_output": "",
                    "exit_code": None,
                },
            },
            hdr,
            meta=meta,
        )
        shown2 = _handle_event(
            {
                "type": "item.completed",
                "item": {
                    "id": "c1",
                    "type": "command_execution",
                    "command": ["/usr/bin/zsh", "-lc", script],
                    "status": "completed",
                    "aggregated_output": "200 https://www.adultforce.com/api/\n",
                    "exit_code": 0,
                },
            },
            hdr,
            meta=meta,
        )
        self.assertTrue(shown1)
        self.assertTrue(shown2)
        self.assertTrue(any("adultforce.com" in u for u in meta["shell_http"]))


if __name__ == "__main__":
    unittest.main()
