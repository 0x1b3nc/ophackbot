"""Boot the Textual TUI (console mute, YOLO, run loop)."""

from __future__ import annotations

import os
import sys


def start_tui() -> int:
    try:
        from textual.app import App  # noqa: F401
    except ImportError:
        sys.stderr.write("Textual missing. Install:  pip install 'hackbot-kit[tui]'\n")
        return 1

    import io

    from .. import live_feed
    from ..operator_gate import set_tui_console_mute
    from ..yolo import enable_yolo, is_yolo
    from .app import HackbotTUI

    os.environ.setdefault("HACKBOT_PLAIN", "1")
    set_tui_console_mute(True)
    sink = io.StringIO()
    try:
        from .. import ui

        ui.console.file = sink  # type: ignore[misc]
        ui.console.quiet = True
    except Exception:  # noqa: BLE001
        pass

    if not is_yolo():
        enable_yolo(quiet=True)

    try:
        HackbotTUI().run(mouse=True)
    finally:
        live_feed.set_feed_sink(None)
        set_tui_console_mute(False)
        try:
            from .. import ui

            ui.console.file = sys.stderr  # type: ignore[misc]
            ui.console.quiet = False
        except Exception:  # noqa: BLE001
            pass
    return 0
