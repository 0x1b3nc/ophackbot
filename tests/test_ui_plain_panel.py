"""Plain UI panels must not Rich-ellipsis clip captured tool stdout."""

from __future__ import annotations

import io
import json
import os
import unittest
from unittest import mock


class PlainPanelTests(unittest.TestCase):
    def test_code_panel_plain_prints_full_json(self) -> None:
        buf = io.StringIO()
        # Re-import path: patch module-level flags used by code_panel.
        import hackbot.ui as ui

        plan = {
            "seed": "https://api.glassdoor.com/very/long/path/that/must/survive",
            "host": "api.glassdoor.com",
            "approve": True,
            "katana": False,
        }
        body = json.dumps(plan, indent=2)
        with mock.patch.object(ui, "_force_plain", True), mock.patch.object(
            ui, "console"
        ) as cons:
            printed: list[str] = []

            def _print(*args, **kwargs):  # noqa: ANN001
                printed.append(str(args[0]) if args else "")

            cons.print.side_effect = _print
            cons.is_terminal = False
            ui.code_panel(body, title="surface_map", lexer="json")
            joined = "\n".join(printed)
            self.assertIn("── surface_map ──", joined)
            self.assertIn("https://api.glassdoor.com/very/long/path/that/must/survive", joined)
            self.assertNotIn("glassdoor.co...", joined)

    def test_plain_ui_true_when_force_plain(self) -> None:
        import hackbot.ui as ui

        with mock.patch.object(ui, "_force_plain", True):
            self.assertTrue(ui.plain_ui())


if __name__ == "__main__":
    unittest.main()
