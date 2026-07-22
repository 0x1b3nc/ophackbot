"""Click-to-copy chat bubbles."""

from __future__ import annotations

from textual.events import Click
from textual.widgets import Markdown, Static


class CopyableStatic(Static):
    """Static that stores plain source text for clean click-to-copy."""

    def __init__(self, renderable: str, *, plain: str, **kwargs) -> None:  # noqa: ANN003
        # markup=False — JSON/tool dumps contain [ ] that Rich markup would eat.
        kwargs.setdefault("markup", False)
        super().__init__(renderable, **kwargs)
        self.plain_source = plain

    def on_click(self, event: Click) -> None:
        event.stop()
        copy_fn = getattr(self.app, "copy_plain", None)
        if callable(copy_fn):
            copy_fn(self.plain_source, label="message")


class CopyableMarkdown(Markdown):
    """Markdown bubble with plain source for clean click-to-copy."""

    def __init__(self, markdown: str, *, plain: str, **kwargs) -> None:  # noqa: ANN003
        super().__init__(markdown, **kwargs)
        self.plain_source = plain

    def on_click(self, event: Click) -> None:
        event.stop()
        copy_fn = getattr(self.app, "copy_plain", None)
        if callable(copy_fn):
            copy_fn(self.plain_source, label="message")
