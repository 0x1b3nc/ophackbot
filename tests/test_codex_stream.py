"""Codex JSON stream progress: spinner only stops on visible lines; capture answer."""

from __future__ import annotations

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

    def test_agent_message_captured_and_shown(self) -> None:
        stops: list[str] = []
        sink: list[str] = []
        hdr: dict = {}
        shown = _handle_event(
            {
                "type": "item.completed",
                "item": {"type": "agent_message", "text": "Vou rodar o next step."},
            },
            hdr,
            before_print=lambda: stops.append("x"),
            answer_sink=sink,
        )
        self.assertTrue(shown)
        self.assertEqual(stops, ["x"])
        self.assertEqual(sink, ["Vou rodar o next step."])

    def test_command_started_shows_run(self) -> None:
        hdr: dict = {}
        shown = _handle_event(
            {
                "type": "item.started",
                "item": {
                    "type": "command_execution",
                    "command": "curl -s https://example.com",
                    "status": "in_progress",
                },
            },
            hdr,
        )
        self.assertTrue(shown)


if __name__ == "__main__":
    unittest.main()
