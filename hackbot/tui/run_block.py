"""Cursor-style run blocks: $ cmd + timing, preview, fold long output."""

from __future__ import annotations

import re
from typing import Any

from textual.app import ComposeResult
from textual.containers import Vertical
from textual.events import Click
from textual.widgets import Static

from .widgets import CopyableStatic

_PREVIEW_LINES = 4
_FOLD_AFTER = 6  # fold when more than this many lines


def format_duration_ms(ms: float | int | None) -> str:
    """Format milliseconds like Cursor: ``348ms``, ``1.9s``, ``11s``."""
    if ms is None:
        return ""
    try:
        val = float(ms)
    except (TypeError, ValueError):
        return ""
    if val < 0:
        return ""
    if val < 1000:
        return f"{int(round(val))}ms"
    sec = val / 1000.0
    if sec < 10:
        return f"{sec:.1f}s"
    return f"{int(round(sec))}s"


def fold_output(
    text: str, *, preview_lines: int = _PREVIEW_LINES, fold_after: int = _FOLD_AFTER
) -> tuple[str, int]:
    """Return (display_text, hidden_line_count). hidden=0 means show full."""
    raw = (text or "").rstrip()
    if not raw:
        return "(no output)", 0
    lines = raw.splitlines()
    if len(lines) <= fold_after:
        return raw, 0
    preview = "\n".join(lines[:preview_lines])
    hidden = len(lines) - preview_lines
    return preview, hidden


def parse_out_payload(text: str) -> tuple[str, str, str]:
    """Split ``exit=0 dur=348ms\\nbody`` → (exit, dur, body)."""
    body = (text or "").strip()
    exit_s = ""
    dur_s = ""
    if not body:
        return exit_s, dur_s, ""
    first, _, rest = body.partition("\n")
    head = first.strip()
    if re.match(r"^(exit=|dur=)", head):
        for part in head.split():
            if part.startswith("exit="):
                exit_s = part[5:]
            elif part.startswith("dur="):
                dur_s = part[4:]
        body = rest.lstrip("\n")
    return exit_s, dur_s, body


def duration_from_item(item: dict[str, Any]) -> str:
    """Best-effort duration string from a Codex/Cursor item dict."""
    for key in ("duration_ms", "elapsed_ms", "durationMs", "elapsedMs"):
        if key in item and item[key] is not None:
            return format_duration_ms(item[key])
    for key in ("duration", "elapsed"):
        val = item.get(key)
        if val is None:
            continue
        if isinstance(val, (int, float)):
            # Heuristic: small floats are seconds; large ints are ms.
            if float(val) < 100:
                return format_duration_ms(float(val) * 1000)
            return format_duration_ms(val)
        if isinstance(val, str) and val.strip():
            return val.strip()
    return ""


class RunBlock(Vertical):
    """One shell/tool invocation — Cursor-like fold, not a fake disclosure glyph."""

    DEFAULT_CSS = """
    RunBlock {
        width: 100%;
        height: auto;
        margin: 1 0;
        padding: 0 0 0 1;
        border-left: tall #4B0082;
    }
    RunBlock > .run-head {
        width: 100%;
        height: auto;
        color: #64D9E8;
        text-style: bold;
        text-wrap: wrap;
    }
    RunBlock > .msg-out {
        width: 100%;
        height: auto;
        color: #E8E8FF;
        padding: 0 1 0 0;
        text-wrap: wrap;
    }
    """

    def __init__(self, cmd: str, *, kind: str = "shell", pending_out: str | None = None, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self.cmd = (cmd or "").strip() or "(command)"
        self.kind = kind if kind in {"shell", "panel"} else "shell"
        self.full_out = ""
        self.expanded = False
        self.duration = ""
        self.exit_code = ""
        self._pending_out = pending_out
        wid = kwargs.get("id") or self.id
        self._head_id = f"{wid}-head" if wid else None
        self._body_id = f"{wid}-body" if wid else None

    def compose(self) -> ComposeResult:
        yield Static(self._head_label(), classes="run-head", markup=False, id=self._head_id)
        yield CopyableStatic(
            "(waiting for output…)" if self.kind == "shell" else "",
            plain="",
            classes="msg-out",
            id=self._body_id,
        )

    def on_mount(self) -> None:
        if self._pending_out is not None:
            out = self._pending_out
            self._pending_out = None
            self.set_output(out)

    def _head_label(self) -> str:
        cmd = self.cmd if len(self.cmd) <= 140 else self.cmd[:137] + "…"
        if self.kind == "panel":
            return f"── {cmd} ──"
        bits = [f"$ {cmd}"]
        if self.duration:
            bits.append(self.duration)
        if self.exit_code not in {"", "0", "None"}:
            bits.append(f"exit={self.exit_code}")
        return "  ".join(bits)

    def _refresh_head(self) -> None:
        if not self._head_id:
            return
        try:
            self.query_one(f"#{self._head_id}", Static).update(self._head_label())
        except Exception:  # noqa: BLE001
            pass

    def set_output(self, text: str, *, duration: str = "", exit_code: str = "") -> None:
        if duration:
            self.duration = duration
        if exit_code != "":
            self.exit_code = exit_code
        self.full_out = (text or "").rstrip()
        # Failures stay expanded — Cursor shows errors in the open stream.
        if self.exit_code not in {"", "0", "None"}:
            self.expanded = True
        self._refresh_head()
        self._render_body()

    def _render_body(self) -> None:
        if not self._body_id:
            return
        try:
            body = self.query_one(f"#{self._body_id}", CopyableStatic)
        except Exception:  # noqa: BLE001
            return
        full = self.full_out or "(no output)"
        if self.expanded:
            # Keep plain_source as full text for click-to-copy.
            body.update(full)
            return
        preview, hidden = fold_output(full)
        if hidden <= 0:
            body.update(preview)
            return
        shown = f"{preview}\n... {hidden} output lines hidden · click to expand"
        body.update(shown)
        # Copy should still get the full output, not the fold hint.
        body.plain_source = full

    def should_fold_click(self) -> bool:
        if not self.full_out:
            return False
        _, hidden = fold_output(self.full_out)
        return hidden > 0 and not self.expanded

    def on_click(self, event: Click) -> None:
        if not self.full_out:
            return
        _, hidden = fold_output(self.full_out)
        if hidden <= 0:
            return
        widget_id = getattr(event.widget, "id", None)
        # Collapsed body / any click → expand. Head click when open → collapse.
        if not self.expanded:
            event.stop()
            self.expanded = True
            self._render_body()
            return
        if widget_id == self._head_id:
            event.stop()
            self.expanded = False
            self._render_body()
