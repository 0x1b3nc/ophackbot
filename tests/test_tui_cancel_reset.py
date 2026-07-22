"""After Ctrl+C, cancel flags must clear so the next TUI prompt can run."""

from __future__ import annotations

import unittest

from hackbot.codex_backend import clear_codex_cancel, codex_cancel_requested, request_codex_cancel
from hackbot.turn_bus import clear_turn_cancel, turn_cancel_requested


class TuiCancelResetTests(unittest.TestCase):
    def tearDown(self) -> None:
        clear_turn_cancel()

    def test_clear_turn_cancel_unblocks(self) -> None:
        request_codex_cancel()
        self.assertTrue(codex_cancel_requested() or turn_cancel_requested())
        clear_turn_cancel()
        self.assertFalse(codex_cancel_requested())
        self.assertFalse(turn_cancel_requested())


if __name__ == "__main__":
    unittest.main()
