"""Cursor model catalog, effort+fast parsing, ModelSelection build."""

from __future__ import annotations

import os
import unittest
from unittest import mock

from hackbot.cursor_models import (
    build_model_selection,
    format_selection_label,
    parse_effort_fast,
    resolve_cursor_model,
)


class ParseEffortFastTests(unittest.TestCase):
    def test_high_fast(self) -> None:
        effort, fast = parse_effort_fast("high fast")
        self.assertEqual(effort, "high")
        self.assertTrue(fast)

    def test_medium_dash_fast(self) -> None:
        effort, fast = parse_effort_fast("medium-fast")
        self.assertEqual(effort, "medium")
        self.assertTrue(fast)

    def test_nofast(self) -> None:
        effort, fast = parse_effort_fast("high nofast")
        self.assertEqual(effort, "high")
        self.assertFalse(fast)

    def test_effort_only(self) -> None:
        effort, fast = parse_effort_fast("low")
        self.assertEqual(effort, "low")
        self.assertIsNone(fast)


class ResolveModelTests(unittest.TestCase):
    def test_grok_aliases(self) -> None:
        for raw in ("grok", "grok-4.5", "cursor-grok-4.5", "cursor-grok-4.5-high-fast"):
            with mock.patch("hackbot.cursor_models.fetch_live_catalog", return_value=None):
                r = resolve_cursor_model(raw, effort="high", fast=True, require_known=True)
            self.assertEqual(r.entry.id, "grok-4.5")
            self.assertEqual(r.effort, "high")
            self.assertTrue(r.fast)

    def test_composer_default_standard(self) -> None:
        with mock.patch.dict(os.environ, {"HACKBOT_CURSOR_FAST": ""}, clear=False):
            os.environ.pop("HACKBOT_CURSOR_FAST", None)
            with mock.patch("hackbot.cursor_models.fetch_live_catalog", return_value=None):
                r = resolve_cursor_model("composer-2.5", effort="medium", require_known=True)
            self.assertEqual(r.entry.id, "composer-2.5")
            self.assertFalse(r.fast)

    def test_rejects_garbage(self) -> None:
        with mock.patch("hackbot.cursor_models.fetch_live_catalog", return_value=None):
            with self.assertRaises(ValueError):
                resolve_cursor_model("qualquer-merda-xyz", require_known=True)

    def test_build_selection_params(self) -> None:
        with mock.patch("hackbot.cursor_models.fetch_live_catalog", return_value=None):
            r = resolve_cursor_model("grok-4.5", effort="high", fast=True)
        sel = build_model_selection(r)
        # If cursor_sdk installed, get real ModelSelection
        self.assertEqual(getattr(sel, "id", sel), "grok-4.5")
        params = getattr(sel, "params", ())
        if params:
            as_map = {p.id: p.value for p in params}
            self.assertEqual(as_map.get("thinking"), "high")
            self.assertEqual(as_map.get("fast"), "true")
        label = format_selection_label(sel)
        self.assertIn("grok-4.5", label)
        self.assertIn("fast", label)


if __name__ == "__main__":
    unittest.main()
