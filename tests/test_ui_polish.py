"""CLI polish: unescape agent text + compact shell command summaries."""

from __future__ import annotations

import unittest
from unittest import mock

from hackbot.ui import ensure_prompt_line, normalize_agent_text, stop_live, summarize_command


class UiPolishTests(unittest.TestCase):
    def test_unescape_literal_newlines(self) -> None:
        raw = (
            "## Finding\\n\\n- CORS weak\\n- health leak\\n\\n"
            "### Next\\n\\nKeep hunting.\\n"
        )
        out = normalize_agent_text(raw)
        self.assertIn("\n", out)
        self.assertNotIn("\\n", out)
        self.assertIn("## Finding", out)

    def test_leave_real_markdown_alone(self) -> None:
        raw = "## Finding\n\n- real newlines already\n"
        self.assertEqual(normalize_agent_text(raw), raw)

    def test_summarize_zsh_curl(self) -> None:
        cmd = (
            '/usr/bin/zsh -lc "for u in a b; do curl -sS -H \'X-Bug-Bounty: x\' '
            "https://www.adultforce.com/api; done\""
        )
        s = summarize_command(cmd)
        self.assertTrue(s.startswith("curl "), s)
        self.assertIn("adultforce.com", s)
        self.assertNotIn("zsh", s)
        self.assertIn("×N", s)

    def test_summarize_list_argv(self) -> None:
        s = summarize_command(["/usr/bin/zsh", "-lc", "curl -sS https://example.com/x"])
        self.assertEqual(s, "curl GET https://example.com/x")

    def test_ensure_prompt_line_stops_live(self) -> None:
        with mock.patch("hackbot.ui.console.clear_live") as clear:
            with mock.patch("hackbot.ui.console.print") as pr:
                ensure_prompt_line()
        clear.assert_called_once()
        pr.assert_called()
        stop_live()  # smoke


if __name__ == "__main__":
    unittest.main()
