"""Thread-safe live activity feed for TUI (and other non-Rich sinks).

Backends keep calling ``ui.*``; events buffer here so Textual can poll on the
UI thread (avoid flooding ``call_from_thread`` per think token).
"""

from __future__ import annotations

import threading
from collections import deque
from typing import Callable

FeedFn = Callable[[str, str], None]  # (kind, text)

_lock = threading.Lock()
_sink: FeedFn | None = None
_buffer: deque[tuple[str, str]] = deque(maxlen=400)
_pending: deque[tuple[str, str]] = deque(maxlen=600)


def set_feed_sink(fn: FeedFn | None) -> None:
    global _sink
    with _lock:
        _sink = fn
        if fn is None:
            _buffer.clear()
            _pending.clear()


def emit(kind: str, text: str) -> None:
    kind = (kind or "info").strip() or "info"
    raw = text or ""
    # Preserve think/draft whitespace; drop empty noise for other kinds.
    if kind in {"think", "thinking", "reasoning", "draft"}:
        if not raw:
            return
        text = raw
    else:
        text = raw.rstrip()
        if not text:
            return
    with _lock:
        _buffer.append((kind, text))
        _pending.append((kind, text))
        sink = _sink
    # Optional immediate sink (may no-op); TUI prefers drain_pending().
    if sink is not None:
        try:
            sink(kind, text)
        except Exception:  # noqa: BLE001
            pass


def drain_pending(limit: int = 80) -> list[tuple[str, str]]:
    """Pop queued events for UI-thread processing."""
    out: list[tuple[str, str]] = []
    with _lock:
        while _pending and len(out) < limit:
            out.append(_pending.popleft())
    return out


def snapshot(limit: int = 24) -> list[tuple[str, str]]:
    with _lock:
        items = list(_buffer)
    return items[-limit:]


def clear() -> None:
    with _lock:
        _buffer.clear()
        _pending.clear()
