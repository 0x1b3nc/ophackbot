"""Tests for chat vs hunt prompt classification and effort auto."""

from __future__ import annotations

import os
import unittest

from hackbot.intent import is_chat_prompt, is_hunt_prompt, resolve_effort_for_prompt


class IntentTests(unittest.TestCase):
    def test_greetings_are_chat(self) -> None:
        for text in ("olá", "ola", "hi", "hello", "thanks", "obrigado", "oi"):
            self.assertTrue(is_chat_prompt(text), text)
            self.assertFalse(is_hunt_prompt(text), text)

    def test_hunt_signals(self) -> None:
        for text in (
            "is example.com in scope for targets/demo",
            "open IDOR notes",
            "dry-run httpx on example.com",
            "create a file teste.md in Downloads",
            "Pronto inicie o hunting",
            "pode iniciar a caça",
            "start the hunt please",
        ):
            self.assertTrue(is_hunt_prompt(text), text)
            self.assertFalse(is_chat_prompt(text), text)

    def test_effort_auto(self) -> None:
        old = os.environ.get("HACKBOT_EFFORT")
        try:
            os.environ["HACKBOT_EFFORT"] = "auto"
            self.assertEqual(resolve_effort_for_prompt("olá"), "minimal")
            self.assertEqual(resolve_effort_for_prompt("check IDOR on example.com"), "medium")
            os.environ["HACKBOT_EFFORT"] = "high"
            self.assertEqual(resolve_effort_for_prompt("olá"), "high")
        finally:
            if old is None:
                os.environ.pop("HACKBOT_EFFORT", None)
            else:
                os.environ["HACKBOT_EFFORT"] = old


if __name__ == "__main__":
    unittest.main()
