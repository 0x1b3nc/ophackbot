"""Click-to-copy chat bubbles."""

from __future__ import annotations

from typing import Any

from textual.events import Click
from textual.widgets import Markdown, Static


class CopyableStatic(Static):
    """Static that stores plain source text for clean click-to-copy.

    Live stream pins and the updating think/draft line use this so click/F2
    paths can copy tool dumps the same way as final bot replies.
    """

    def __init__(self, renderable: str = "", *, plain: str | None = None, **kwargs: Any) -> None:
        # markup=False — JSON/tool dumps contain [ ] that Rich markup would eat.
        kwargs.setdefault("markup", False)
        super().__init__(renderable, **kwargs)
        self.plain_source = plain if plain is not None else (renderable or "")

    def update(self, content: Any = "", *, layout: bool = True) -> None:
        if isinstance(content, str):
            self.plain_source = content
        super().update(content, layout=layout)

    def on_click(self, event: Click) -> None:
        event.stop()
        copy_fn = getattr(self.app, "copy_plain", None)
        if callable(copy_fn):
            copy_fn(self.plain_source, label="stream")


class CopyableMarkdown(Markdown):
    """Markdown bubble with plain source for clean click-to-copy."""

    def __init__(self, markdown: str, *, plain: str, **kwargs: Any) -> None:
        super().__init__(markdown, **kwargs)
        self.plain_source = plain

    def on_click(self, event: Click) -> None:
        event.stop()
        copy_fn = getattr(self.app, "copy_plain", None)
        if callable(copy_fn):
            copy_fn(self.plain_source, label="message")
