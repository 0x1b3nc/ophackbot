"""Strict model catalogs — unknown ids rejected for every provider."""

from __future__ import annotations

import unittest
from unittest import mock

from hackbot.model_catalog import known_models, resolve_model


class ModelCatalogTests(unittest.TestCase):
    def test_openai_accepts_known(self) -> None:
        with mock.patch("hackbot.model_catalog.fetch_live_models", return_value=None):
            mid, src = resolve_model("openai", "gpt-4o")
        self.assertEqual(mid, "gpt-4o")
        self.assertEqual(src, "curated")

    def test_openai_alias(self) -> None:
        with mock.patch("hackbot.model_catalog.fetch_live_models", return_value=None):
            mid, _ = resolve_model("openai", "4o-mini")
        self.assertEqual(mid, "gpt-4o-mini")

    def test_openai_rejects_garbage(self) -> None:
        with mock.patch("hackbot.model_catalog.fetch_live_models", return_value=None):
            with self.assertRaises(ValueError):
                resolve_model("openai", "qualquer-merda")

    def test_anthropic_rejects_garbage(self) -> None:
        with mock.patch("hackbot.model_catalog.fetch_live_models", return_value=None):
            with self.assertRaises(ValueError):
                resolve_model("anthropic", "claude-inventado")

    def test_deepseek_only_real(self) -> None:
        with mock.patch("hackbot.model_catalog.fetch_live_models", return_value=None):
            mid, _ = resolve_model("deepseek", "reasoner")
            self.assertEqual(mid, "deepseek-reasoner")
            with self.assertRaises(ValueError):
                resolve_model("deepseek", "deepseek-ultra-fake")

    def test_live_extends_allowlist(self) -> None:
        with mock.patch(
            "hackbot.model_catalog.fetch_live_models",
            return_value=["acme/special-model-xyz"],
        ):
            mid, src = resolve_model("openrouter", "acme/special-model-xyz")
        self.assertEqual(mid, "acme/special-model-xyz")
        self.assertEqual(src, "live")

    def test_lmstudio_requires_live(self) -> None:
        with mock.patch("hackbot.model_catalog.fetch_live_models", return_value=None):
            with self.assertRaises(ValueError):
                resolve_model("lmstudio", "local-model")

    def test_codex_default(self) -> None:
        with mock.patch("hackbot.model_catalog.fetch_live_models", return_value=None):
            mid, _ = resolve_model("codex", "default")
        self.assertEqual(mid, "")

    def test_known_models_lists_openai(self) -> None:
        with mock.patch("hackbot.model_catalog.fetch_live_models", return_value=None):
            rows = known_models("openai", include_live=False)
        ids = [r[0] for r in rows]
        self.assertIn("gpt-4o", ids)
        self.assertNotIn("qualquer-merda", ids)

    def test_cursor_still_resolves_grok(self) -> None:
        with mock.patch("hackbot.cursor_models.fetch_live_catalog", return_value=None):
            mid, _ = resolve_model("cursor", "grok 4.5")
        self.assertEqual(mid, "grok-4.5")


if __name__ == "__main__":
    unittest.main()
