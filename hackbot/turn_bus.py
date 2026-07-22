"""Background turns + operator inbox (Claude/Codex-style interrupt queue).

While a turn runs, the REPL keeps accepting input. Enter with text enqueues the
message and interrupts the current turn; the worker then runs the queued prompt.
"""

from __future__ import annotations

import queue
import threading
from typing import Any, Callable

from . import ui

TurnFn = Callable[[str], None]

_SENTINEL = object()


class TurnBus:
    def __init__(self, *, sync: bool = False) -> None:
        self._sync = sync
        self._inbox: queue.Queue[Any] = queue.Queue()
        self._cancel = threading.Event()
        self._busy = threading.Event()
        self._turn_fn: TurnFn | None = None
        self._thread = threading.Thread(
            target=self._loop, name="hackbot-turn", daemon=True
        )
        self._started = False
        self._lock = threading.Lock()
        self._queued_preview: list[str] = []

    def start(self, turn_fn: TurnFn) -> None:
        self._turn_fn = turn_fn
        if self._sync:
            self._started = True
            return
        if not self._started:
            self._started = True
            self._thread.start()

    def shutdown(self) -> None:
        self.request_interrupt()
        if not self._sync:
            self._inbox.put(_SENTINEL)

    def is_busy(self) -> bool:
        return self._busy.is_set()

    def queued_count(self) -> int:
        with self._lock:
            return len(self._queued_preview)

    def cancel_requested(self) -> bool:
        return self._cancel.is_set()

    def clear_cancel(self) -> None:
        self._cancel.clear()

    def request_interrupt(self) -> None:
        """Pause/kill the in-flight turn (codex proc + hunt stop)."""
        self._cancel.set()
        try:
            from .codex_backend import request_codex_cancel

            request_codex_cancel()
        except Exception:  # noqa: BLE001
            pass
        try:
            from .hunt_controller import request_stop

            request_stop()
        except Exception:  # noqa: BLE001
            pass

    def submit(self, text: str, *, interrupt_if_busy: bool = True) -> None:
        """Enqueue operator text. If a turn is running, interrupt it."""
        text = (text or "").strip()
        if not text:
            return
        if self._sync:
            assert self._turn_fn is not None
            self._run_one(text)
            return
        with self._lock:
            self._queued_preview.append(text)
        self._inbox.put(text)
        if interrupt_if_busy and self.is_busy():
            ui.warn(f"queued — interrupting current turn ({self.queued_count()} waiting)")
            self.request_interrupt()
        elif self.is_busy():
            ui.info(f"queued ({self.queued_count()}): {text[:80]}")

    def _run_one(self, text: str) -> None:
        assert self._turn_fn is not None
        with self._lock:
            if self._queued_preview and self._queued_preview[0] == text:
                self._queued_preview.pop(0)
            elif text in self._queued_preview:
                self._queued_preview.remove(text)
        self.clear_cancel()
        try:
            from .codex_backend import clear_codex_cancel
            from .hunt_controller import clear_stop

            clear_codex_cancel()
            clear_stop()
        except Exception:  # noqa: BLE001
            pass
        self._busy.set()
        try:
            self._turn_fn(text)
        except Exception as exc:  # noqa: BLE001
            ui.error(f"turn crashed: {type(exc).__name__}: {exc}")
        finally:
            self._busy.clear()
            self.clear_cancel()

    def _loop(self) -> None:
        while True:
            item = self._inbox.get()
            if item is _SENTINEL:
                break
            self._run_one(str(item))


# Process-global bus used by cancel checks in backends.
_BUS: TurnBus | None = None


def get_bus() -> TurnBus | None:
    return _BUS


def set_bus(bus: TurnBus | None) -> None:
    global _BUS
    _BUS = bus


def turn_cancel_requested() -> bool:
    bus = _BUS
    return bool(bus and bus.cancel_requested())
