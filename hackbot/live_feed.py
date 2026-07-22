"""Thread-safe live activity feed for TUI (and other non-Rich sinks).

Backends keep calling ``ui.*``; when a sink is registered, events are mirrored
here so Textual can show thinking/tools without painting under the alt screen.
"""

from __future__ import annotations

import threading
from collections import deque
from typing import Callable

FeedFn = Callable[[str, str], None]  # (kind, text)

_lock = threading.Lock()
_sink: FeedFn | None = None
_buffer: deque[tuple[str, str]] = deque(maxlen=80)


def set_feed_sink(fn: FeedFn | None) -> None:
    global _sink
    with _lock:
        _sink = fn
        if fn is None:
            _buffer.clear()


def emit(kind: str, text: str) -> None:
    kind = (kind or "info").strip() or "info"
    text = (text or "").rstrip()
    if not text:
        return
    with _lock:
        _buffer.append((kind, text))
        sink = _sink
    if sink is not None:
        try:
            sink(kind, text)
        except Exception:  # noqa: BLE001
            pass


def snapshot(limit: int = 24) -> list[tuple[str, str]]:
    with _lock:
        items = list(_buffer)
    return items[-limit:]


def clear() -> None:
    with _lock:
        _buffer.clear()
