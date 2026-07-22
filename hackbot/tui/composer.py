"""Multiline composer — Textual-native Enter=newline; Ctrl+Enter sends."""

from __future__ import annotations

from textual import events
from textual.binding import Binding
from textual.widgets import TextArea

from ..clipboard import read_text as clipboard_read


class PromptArea(TextArea):
    """Chat composer aligned with Textual TextArea defaults.

    Enter inserts a newline (native TextArea ``_on_key``).
    Ctrl+Enter submits via ``action_submit_prompt``.
    """

    BINDINGS = [
        Binding("ctrl+enter", "submit_prompt", "send", show=True, priority=True),
    ]

    async def _on_key(self, event: events.Key) -> None:
        """Submit on Ctrl+Enter; let Enter fall through to TextArea newline."""
        key = (event.key or "").lower()
        aliases = {(a or "").lower() for a in (event.aliases or [])}
        if key == "ctrl+enter" or "ctrl+enter" in aliases:
            event.stop()
            event.prevent_default()
            self.action_submit_prompt()
            return
        # Do not intercept enter — Textual inserts "\n".
        await super()._on_key(event)

    def action_submit_prompt(self) -> None:
        submit = getattr(self.app, "submit_composer", None)
        if callable(submit):
            submit()

    def action_paste(self) -> None:
        """Prefer OS clipboard — app.clipboard is often empty / truncated."""
        if self.read_only:
            return
        text = clipboard_read()
        if text is None:
            text = self.app.clipboard or ""
        if not text:
            return
        if result := self._replace_via_keyboard(text, *self.selection):
            self.move_cursor(result.end_location)
