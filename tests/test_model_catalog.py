"""Strict model catalogs — unknown ids rejected for every provider."""

from __future__ import annotations

import unittest
from unittest import mock

from hackbot.model_catalog import (
    clear_model_cache,
    fetch_live_models,
    known_models,
    resolve_model,
)


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

    def test_anthropic_live_extends(self) -> None:
        clear_model_cache("anthropic")
        with mock.patch(
            "hackbot.model_catalog._fetch_anthropic_models",
            return_value=["claude-opus-4-6-20260204"],
        ):
            mid, src = resolve_model("anthropic", "claude-opus-4-6-20260204")
        self.assertEqual(mid, "claude-opus-4-6-20260204")
        self.assertEqual(src, "live")

    def test_live_cache_avoids_refetch(self) -> None:
        clear_model_cache("openrouter")
        with mock.patch(
            "hackbot.model_catalog._fetch_live_uncached",
            return_value=["acme/one"],
        ) as fetch:
            a = fetch_live_models("openrouter")
            b = fetch_live_models("openrouter")
        self.assertEqual(a, ["acme/one"])
        self.assertEqual(b, ["acme/one"])
        self.assertEqual(fetch.call_count, 1)

    def test_force_refresh_refetches(self) -> None:
        clear_model_cache("ollama")
        with mock.patch(
            "hackbot.model_catalog._fetch_live_uncached",
            side_effect=[["m1"], ["m2"]],
        ) as fetch:
            self.assertEqual(fetch_live_models("ollama"), ["m1"])
            self.assertEqual(fetch_live_models("ollama", force_refresh=True), ["m2"])
        self.assertEqual(fetch.call_count, 2)


if __name__ == "__main__":
    unittest.main()
