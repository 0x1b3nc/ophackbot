"""Chronological note feed + no final megadump duplicate."""

from __future__ import annotations

import unittest

from hackbot.step_mode import REPORTING_STYLE_BLOCK, step_mode_preamble
from hackbot.ui import markdown_panel


class ReportingStyleTests(unittest.TestCase):
    def test_preamble_includes_reporting_style(self) -> None:
        text = step_mode_preamble()
        self.assertIn("OPERATOR REPORTING STYLE", text)
        self.assertIn("## Done", text)
        self.assertIn("## Next steps", REPORTING_STYLE_BLOCK)


class MarkdownNoteEmitTests(unittest.TestCase):
    def test_markdown_panel_emits_note(self) -> None:
        from hackbot import live_feed

        live_feed.clear()
        sink: list[tuple[str, str]] = []

        def _sink(kind: str, text: str) -> None:
            sink.append((kind, text))

        live_feed.set_feed_sink(_sink)
        try:
            markdown_panel("Step done: got 200 on /health.", title="hackbot (test)")
            events = live_feed.drain_pending()
            self.assertTrue(any(k == "note" for k, _ in events) or any(k == "note" for k, _ in sink))
            blobs = [t for k, t in events + sink if k == "note"]
            self.assertTrue(any("200" in b for b in blobs))
        finally:
            live_feed.set_feed_sink(None)
            live_feed.clear()


if __name__ == "__main__":
    unittest.main()
