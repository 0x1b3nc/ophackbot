"""Prompt router: PT-BR/EN confidence + offline route."""

from __future__ import annotations

import unittest
from unittest import mock

from hackbot.prompt_router import (
    _guess_lang,
    offline_confidence,
    route_prompt,
)


class PromptRouterTests(unittest.TestCase):
    def test_guess_lang_pt(self) -> None:
        self.assertEqual(_guess_lang("faz um ataque e me entrega o resultado"), "pt-BR")

    def test_guess_lang_en(self) -> None:
        self.assertEqual(_guess_lang("run a full assault and deliver results"), "en")

    def test_confidence_higher_with_host_and_modules(self) -> None:
        low = offline_confidence("go", host=None, intents=[], classes=["recon"])
        high = offline_confidence(
            "ddos and secrets scan on example.com",
            host="example.com",
            intents=["campaign"],
            classes=["rate-limit", "secrets"],
        )
        self.assertGreater(high, low)

    def test_route_offline_no_llm_when_confident(self) -> None:
        with mock.patch("hackbot.prompt_router.model_usable_for_route", return_value=True):
            with mock.patch("hackbot.prompt_router.llm_interpret") as llm:
                d = route_prompt(
                    "ddos and credential leak on example.com for targets/demo",
                    host="example.com",
                    target_dir="targets/demo",
                    intents=["campaign"],
                    classes=["rate-limit", "secrets"],
                )
                self.assertEqual(d.source, "offline")
                llm.assert_not_called()

    def test_route_escalates_when_low_confidence(self) -> None:
        fake = mock.Mock()
        fake.language = "pt-BR"
        fake.intent = "campaign"
        fake.modules = ["secrets", "recon"]
        fake.host = "example.com"
        fake.target_dir = "targets/demo"
        fake.endpoint = None
        fake.tool = None
        fake.approve = False
        fake.force = False
        fake.summary_pt = "Explorar o alvo"
        fake.summary_en = "Explore the target"
        fake.source = "llm"
        fake.confidence = 0.85
        fake.used_default_pack = False

        with mock.patch("hackbot.prompt_router.auto_route_enabled", return_value=True):
            with mock.patch("hackbot.prompt_router.model_usable_for_route", return_value=True):
                with mock.patch("hackbot.prompt_router.llm_interpret", return_value=fake):
                    d = route_prompt(
                        "faz algo util ai",
                        host=None,
                        intents=[],
                        classes=["recon"],
                    )
        self.assertEqual(d.source, "offline+llm")
        self.assertEqual(d.host, "example.com")
        self.assertIn("secrets", d.modules)


if __name__ == "__main__":
    unittest.main()
