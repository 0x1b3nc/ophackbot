"""Agent chat fast-path wiring (no live LLM)."""

from __future__ import annotations

import json
import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from hackbot.agent import SYSTEM_CHAT, SYSTEM_HUNT, run_agent
from hackbot.intent import is_chat_prompt
from hackbot.llm import LLMResponse, ToolCall


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

    def test_http_model_continues_after_write_file(self) -> None:
        """OpenAI/Anthropic/etc must not idle after approved write_file."""
        with tempfile.TemporaryDirectory() as tmp:
            target = Path(tmp) / "SCOPE.md"
            calls: list[str] = []

            def fake_chat(**kwargs):
                n = len(calls)
                # Track last user-ish content for continue nudge.
                msgs = kwargs.get("messages") or []
                blob = json.dumps(msgs)
                calls.append(blob)
                if n == 0:
                    return LLMResponse(
                        text="creating scope",
                        tool_calls=[
                            ToolCall(
                                id="t1",
                                name="write_file",
                                arguments={
                                    "path": str(target),
                                    "content": "---\nin_scope: []\n",
                                },
                            )
                        ],
                        raw={},
                    )
                if n == 1:
                    # Model would normally stop here after write — we nudge.
                    return LLMResponse(text="SCOPE criado.", tool_calls=[], raw={})
                return LLMResponse(
                    text="Seguindo: dry-run httpx next.",
                    tool_calls=[],
                    raw={},
                )

            with patch.dict(
                os.environ, {"HACKBOT_FILEOP_CONTINUE": "1"}, clear=False
            ):
                with patch("hackbot.agent.chat", side_effect=fake_chat), patch(
                    "hackbot.agent.detect_provider", return_value=("openai", "gpt-4o")
                ), patch("hackbot.agent.streaming_enabled", return_value=False), patch(
                    "hackbot.agent.resolve_packs", return_value=["all"]
                ), patch(
                    "hackbot.agent.filter_tool_specs",
                    side_effect=lambda specs, _p: specs,
                ), patch(
                    "hackbot.model_catalog.resolve_model",
                    return_value=("gpt-4o", "test"),
                ):
                    history: list = []
                    run_agent(
                        "inicie o hunting no aylo",
                        history=history,
                        approve_fn=lambda _d: True,
                    )
            self.assertTrue(target.exists())
            self.assertGreaterEqual(len(calls), 3)
            self.assertIn("file-op", calls[2].lower())
            self.assertIn("dry-run httpx", history[-1]["content"])


if __name__ == "__main__":
    unittest.main()
