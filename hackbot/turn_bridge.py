"""Shared turn runner for non-REPL front-ends (ACP / deprecated web UI).

Resolves the same provider rails as the REPL (codex / cursor / model / offline)
and auto-approves via YOLO (OOS still blocked).
"""

from __future__ import annotations

import os
import threading
from typing import Any

from .codex_backend import codex_available, run_codex_turn
from .cursor_backend import cursor_available, run_cursor_turn
from .local_agent import run_local_agent
from .providers import ConfigError, resolve_config
from .yolo import is_yolo, yolo_auto_approve

_CODEX_HISTORY: list[tuple[str, str]] = []
_CURSOR_HISTORY: list[tuple[str, str]] = []
_MODEL_HISTORY: list[dict[str, Any]] = []
_LOCK = threading.Lock()


def resolve_mode() -> tuple[str, str]:
    if os.environ.get("HACKBOT_LOCAL", "").strip() in {"1", "true", "yes"}:
        return "offline", "offline"
    provider = (
        os.environ.get("HACKBOT_PROVIDER", "").strip().lower()
        or os.environ.get("HACKBOT_BACKEND", "").strip().lower()
    )
    if not provider or provider == "offline":
        return "offline", "offline (default)"
    try:
        cfg = resolve_config()
    except ConfigError as exc:
        return "offline", f"offline ({exc})"
    if cfg.wire == "codex":
        if codex_available():
            return "codex", f"codex / {cfg.model or 'plan default'}"
        return "offline", "offline (codex not logged in)"
    if cfg.wire == "cursor":
        if cursor_available():
            return "cursor", f"cursor / {cfg.model or 'composer-2.5'}"
        return "offline", "offline (cursor unavailable)"
    return "model", f"{cfg.provider} / {cfg.model or 'default'}"


def bridge_approve(prompt: str) -> bool:
    """Approve path for non-interactive front-ends (YOLO / auto)."""
    if is_yolo():
        return yolo_auto_approve(prompt)
    return yolo_auto_approve(prompt)


def run_bridged_turn(prompt: str) -> str:
    """Run one user turn through the active brain. Thread-safe."""
    mode, _ = resolve_mode()
    with _LOCK:
        if mode == "codex":
            answer = run_codex_turn(
                prompt,
                history=_CODEX_HISTORY,
                model=os.environ.get("HACKBOT_MODEL") or None,
                approve_fn=bridge_approve,
                allow_file_ops=True,
            )
            if answer != "(cancelled)":
                _CODEX_HISTORY.append(("user", prompt))
                _CODEX_HISTORY.append(("hackbot", answer))
                if len(_CODEX_HISTORY) > 12:
                    del _CODEX_HISTORY[: len(_CODEX_HISTORY) - 12]
            return answer
        if mode == "cursor":
            answer = run_cursor_turn(
                prompt,
                history=_CURSOR_HISTORY,
                model=os.environ.get("HACKBOT_MODEL") or None,
                approve_fn=bridge_approve,
                allow_file_ops=True,
            )
            if answer != "(cancelled)":
                _CURSOR_HISTORY.append(("user", prompt))
                _CURSOR_HISTORY.append(("hackbot", answer))
                if len(_CURSOR_HISTORY) > 12:
                    del _CURSOR_HISTORY[: len(_CURSOR_HISTORY) - 12]
            return answer
        if mode == "model":
            from .agent import run_agent

            run_agent(prompt, history=_MODEL_HISTORY, approve_fn=bridge_approve)
            for msg in reversed(_MODEL_HISTORY):
                if msg.get("role") == "assistant" and msg.get("content"):
                    return str(msg["content"])
            return "(no model response)"
        try:
            from .local_agent import interpret

            interp = interpret(prompt)
            summary = (
                f"offline · intents={list(getattr(interp, 'intents', []) or [])} "
                f"host={getattr(interp, 'host', None) or '—'}"
            )
        except Exception:  # noqa: BLE001
            summary = "offline turn complete"
        run_local_agent(prompt, approve_fn=bridge_approve)
        return (
            f"{summary}\n\n"
            "Tool/plan chatter may also appear on the ACP client stderr / host terminal."
        )


def clear_bridge_histories() -> None:
    with _LOCK:
        _CODEX_HISTORY.clear()
        _CURSOR_HISTORY.clear()
        _MODEL_HISTORY.clear()
