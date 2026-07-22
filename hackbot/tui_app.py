"""Backward-compatible entry — prefer ``hackbot.tui.start_tui``.

Kept so ``from hackbot.tui_app import start_tui`` and older docs keep working.
"""

from __future__ import annotations

from .tui import start_tui

__all__ = ["start_tui"]
