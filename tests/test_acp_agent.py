"""ACP agent helpers + slash bridge + mode bridge."""

from __future__ import annotations

import unittest
from unittest import mock

from hackbot.acp_agent import prompt_blocks_to_text
from hackbot.tui_commands import handle_slash
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


class SlashCommandTests(unittest.TestCase):
    def test_models_is_local_not_hunt(self) -> None:
        with mock.patch.dict("os.environ", {"HACKBOT_PROVIDER": "codex"}, clear=False):
            with mock.patch(
                "hackbot.model_catalog.known_models",
                return_value=[("gpt-5", "default")],
            ):
                with mock.patch(
                    "hackbot.model_catalog.live_models_status",
                    return_value="ok",
                ):
                    result = handle_slash("/models")
        self.assertTrue(result.handled)
        body = "\n".join(result.messages)
        self.assertIn("models", body.lower())
        self.assertIn("gpt-5", body)

    def test_unknown_slash_not_forwarded(self) -> None:
        result = handle_slash("/toad:about")
        self.assertTrue(result.handled)
        body = "\n".join(result.messages)
        self.assertIn("not a hackbot", body.lower())

    def test_plain_text_not_handled(self) -> None:
        result = handle_slash("check scope on example.com")
        self.assertFalse(result.handled)


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
