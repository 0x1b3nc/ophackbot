"""hackbot Textual TUI package.

Run: ``python -m hackbot tui`` (via ``hackbot.tui.start_tui``).

Composer (mode A, Textual-native):
  Enter       → newline (TextArea default)
  Ctrl+Enter  → send
  Send button → send
"""

from __future__ import annotations

from typing import TYPE_CHECKING, Any

from .boot import start_tui

if TYPE_CHECKING:
    from .app import HackbotTUI as HackbotTUI

__all__ = ["HackbotTUI", "start_tui"]


def __getattr__(name: str) -> Any:
    if name == "HackbotTUI":
        from .app import HackbotTUI as _HackbotTUI

        return _HackbotTUI
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
