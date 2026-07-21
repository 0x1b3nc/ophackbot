"""CLI polish: unescape agent text + compact shell command summaries."""

from __future__ import annotations

import unittest
from unittest import mock

from hackbot.ui import (
    ensure_prompt_line,
    format_stream_command,
    normalize_agent_text,
    stop_live,
    summarize_command,
)


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

    def test_stream_command_keeps_raw_zsh(self) -> None:
        script = (
            "for u in 'https://www.adultforce.com/api/' 'https://www.adultforce.com/api'; "
            "do code=$(curl -k -sS -o /tmp/b -w '%{http_code}' -H 'X-Bug-Bounty: durkzprg' \"$u\"); "
            "echo \"$code $u\"; done"
        )
        raw = format_stream_command(["/usr/bin/zsh", "-lc", script])
        self.assertTrue(raw.startswith("/usr/bin/zsh -lc '"), raw)
        self.assertIn("curl -k -sS", raw)
        self.assertIn("adultforce.com", raw)
        self.assertIn("for u in", raw)

    def test_ensure_prompt_line_stops_live(self) -> None:
        with mock.patch("hackbot.ui.console.clear_live") as clear:
            with mock.patch("hackbot.ui.console.print") as pr:
                ensure_prompt_line()
        clear.assert_called_once()
        pr.assert_called()
        stop_live()  # smoke


if __name__ == "__main__":
    unittest.main()
