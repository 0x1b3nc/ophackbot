"""Alt+Enter rewrite — Textual drops alt on Esc+CR → enter."""

from __future__ import annotations

import unittest

from hackbot.tui_app import _NEWLINE_KEYS, _rewrite_key_for_alt


class RewriteAltEnterTests(unittest.TestCase):
    def test_plain_enter_unchanged(self) -> None:
        self.assertEqual(_rewrite_key_for_alt("enter", alt=False), "enter")

    def test_alt_enter_rewritten(self) -> None:
        self.assertEqual(_rewrite_key_for_alt("enter", alt=True), "alt+enter")

    def test_alt_ctrl_j_rewritten(self) -> None:
        self.assertEqual(_rewrite_key_for_alt("ctrl+j", alt=True), "alt+enter")

    def test_newline_keys_cover_combos(self) -> None:
        for key in ("ctrl+j", "alt+enter", "shift+enter", "ctrl+enter"):
            self.assertIn(key, _NEWLINE_KEYS)


if __name__ == "__main__":
    unittest.main()
