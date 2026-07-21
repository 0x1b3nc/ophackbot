"""Serialize operator prompts and mute live UI while waiting for y/n.

Cursor SDK can invoke CustomTools on worker threads while the main thread
streams assistant/tool events. Without a gate, Confirm.ask races stdin and
stream prints land on the prompt line — later approvals appear to "skip" the
first. One tool + one prompt at a time; console stays quiet during approve
except the permission UI itself.
"""

from __future__ import annotations

import threading
from contextlib import contextmanager
from typing import Iterator

_tool_lock = threading.RLock()
_approve_depth = 0
_approve_guard = threading.Lock()
_ui_force_depth = 0
_ui_force_guard = threading.Lock()


def stream_output_allowed() -> bool:
    """False while an operator approve prompt is on screen (Cursor stream)."""
    with _approve_guard:
        return _approve_depth == 0


def console_output_allowed() -> bool:
    """Rich console gate: muted during approve unless permission UI forces it."""
    with _ui_force_guard:
        if _ui_force_depth > 0:
            return True
    return stream_output_allowed()


@contextmanager
def force_console_output() -> Iterator[None]:
    """Allow permission panels / Confirm prompts while stream is otherwise muted."""
    global _ui_force_depth
    with _ui_force_guard:
        _ui_force_depth += 1
    try:
        yield
    finally:
        with _ui_force_guard:
            _ui_force_depth = max(0, _ui_force_depth - 1)


@contextmanager
def operator_prompt_active() -> Iterator[None]:
    """Mute cursor/live stream for the duration of Confirm.ask / permission UI."""
    global _approve_depth
    with _approve_guard:
        _approve_depth += 1
    try:
        with force_console_output():
            yield
    finally:
        with _approve_guard:
            _approve_depth = max(0, _approve_depth - 1)


@contextmanager
def serialized_tool_call() -> Iterator[None]:
    """Run at most one CustomTool execute at a time (approve → answer → next)."""
    with _tool_lock:
        yield
