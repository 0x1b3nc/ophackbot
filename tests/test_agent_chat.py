"""Agent chat fast-path wiring (no live LLM)."""

from __future__ import annotations

import unittest
from unittest.mock import patch

from hackbot.agent import SYSTEM_CHAT, SYSTEM_HUNT, run_agent
from hackbot.intent import is_chat_prompt
from hackbot.llm import LLMResponse


class AgentChatTests(unittest.TestCase):
    def test_chat_uses_short_system_and_no_tools(self) -> None:
        self.assertTrue(is_chat_prompt("olá"))
        captured: dict = {}

        def fake_chat(**kwargs):
            captured["system"] = kwargs["system"]
            captured["tools"] = kwargs["tools"]
            return LLMResponse(text="hey", tool_calls=[], raw={})

        with patch("hackbot.agent.chat", side_effect=fake_chat), patch(
            "hackbot.agent.detect_provider", return_value=("openai", "gpt-4o")
        ), patch("hackbot.agent.streaming_enabled", return_value=False):
            history: list = []
            run_agent("olá", history=history, approve_fn=lambda _d: False)
        self.assertEqual(captured["system"], SYSTEM_CHAT)
        self.assertEqual(captured["tools"], [])
        self.assertNotEqual(captured["system"], SYSTEM_HUNT)


if __name__ == "__main__":
    unittest.main()
