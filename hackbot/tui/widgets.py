"""Click-to-copy stream pins. Final Markdown copies via F2 / /copy only."""

from __future__ import annotations

from typing import Any

from textual.events import Click
from textual.widgets import Markdown, Static


class CopyableStatic(Static):
    """Static that stores plain source text for clean click-to-copy.

    Used for live stream / tool dumps. Final Markdown replies do NOT use
    click-to-copy (Markdown links looked like targets and confused operators).
    """

    def __init__(self, renderable: str = "", *, plain: str | None = None, **kwargs: Any) -> None:
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


class ReplyMarkdown(Markdown):
    """Final / mid-turn assistant Markdown — no click-to-copy, no link navigation.

    Clicking headings/paths used to steal focus and copy opaque text. Copy via
    F2 / Ctrl+Y / /copy instead.
    """

    def __init__(self, markdown: str, *, plain: str, **kwargs: Any) -> None:
        kwargs.setdefault("open_links", False)
        super().__init__(markdown, **kwargs)
        self.plain_source = plain
