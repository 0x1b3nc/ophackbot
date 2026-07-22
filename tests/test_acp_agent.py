"""ACP agent helpers + mode bridge."""

from __future__ import annotations

import unittest
from unittest import mock

from hackbot.acp_agent import prompt_blocks_to_text
from hackbot.turn_bridge import resolve_mode


class PromptBlocksTests(unittest.TestCase):
    def test_text_blocks(self) -> None:
        out = prompt_blocks_to_text(
            [
                {"type": "text", "text": "hello"},
                {"type": "text", "text": "world"},
            ]
        )
        self.assertEqual(out, "hello\nworld")

    def test_object_blocks(self) -> None:
        class B:
            text = "ping"

        self.assertEqual(prompt_blocks_to_text([B()]), "ping")


class TurnBridgeModeTests(unittest.TestCase):
    def test_defaults_offline(self) -> None:
        with mock.patch.dict(
            "os.environ",
            {"HACKBOT_PROVIDER": "", "HACKBOT_LOCAL": "", "HACKBOT_BACKEND": ""},
            clear=False,
        ):
            mode, label = resolve_mode()
        self.assertEqual(mode, "offline")
        self.assertIn("offline", label)


class WebServerModeAliasTests(unittest.TestCase):
    def test_web_server_uses_turn_bridge(self) -> None:
        from hackbot import web_server

        with mock.patch.dict(
            "os.environ",
            {"HACKBOT_PROVIDER": "", "HACKBOT_LOCAL": ""},
            clear=False,
        ):
            mode, _ = web_server._resolve_mode()
        self.assertEqual(mode, "offline")


if __name__ == "__main__":
    unittest.main()
