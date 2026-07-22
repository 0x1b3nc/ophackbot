"""Background turns + operator inbox (Claude/Codex-style interrupt queue).

While a turn runs, the REPL keeps accepting input. Enter with text enqueues the
message and interrupts the current turn; the worker then runs the queued prompt.

Cancel uses a monotonic **epoch**: interrupt bumps the epoch so an old turn still
sees cancel even if the next turn cleared the Event flags.
"""

from __future__ import annotations

import contextvars
import queue
import threading
from typing import Any, Callable

from . import ui

TurnFn = Callable[[str], None]

_SENTINEL = object()

# Process-wide cancel — survives ``set_bus(None)`` during shutdown so in-flight
# turns still see interrupt after the REPL tears down the bus pointer.
_GLOBAL_CANCEL = threading.Event()
_CANCEL_EPOCH = 0
_CANCEL_EPOCH_LOCK = threading.Lock()
_turn_epoch: contextvars.ContextVar[int] = contextvars.ContextVar(
    "hackbot_turn_epoch", default=-1
)


def bump_cancel_epoch() -> int:
    """Advance cancel epoch (interrupt). Old turns remain cancelled forever."""
    global _CANCEL_EPOCH
    with _CANCEL_EPOCH_LOCK:
        _CANCEL_EPOCH += 1
        return _CANCEL_EPOCH


def current_cancel_epoch() -> int:
    with _CANCEL_EPOCH_LOCK:
        return _CANCEL_EPOCH


def bind_turn_epoch(epoch: int) -> contextvars.Token[int]:
    """Bind this worker thread/task to a turn epoch for cancel checks."""
    return _turn_epoch.set(int(epoch))


def reset_turn_epoch(token: contextvars.Token[int]) -> None:
    _turn_epoch.reset(token)


def begin_turn_epoch() -> int:
    """Clear cancel flags for a *new* turn; return the epoch this turn owns.

    An older turn that still holds a smaller epoch keeps seeing cancel via
    ``turn_cancel_requested()`` even after flags are cleared.
    """
    epoch = current_cancel_epoch()
    clear_turn_cancel_flags_only()
    return epoch


def clear_turn_cancel_flags_only() -> None:
    """Clear Event flags + codex/hunt stop — does **not** rewind the epoch."""
    _GLOBAL_CANCEL.clear()
    bus = _BUS
    if bus is not None:
        bus.clear_cancel()
    try:
        from .codex_backend import clear_codex_cancel

        clear_codex_cancel()
    except Exception:  # noqa: BLE001
        pass
    try:
        from .hunt_controller import clear_stop

        clear_stop()
    except Exception:  # noqa: BLE001
        pass


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
        self._idle = threading.Event()
        self._idle.set()

    def start(self, turn_fn: TurnFn) -> None:
        self._turn_fn = turn_fn
        if self._sync:
            self._started = True
            return
        if not self._started:
            self._started = True
            self._thread.start()

    def shutdown(self, *, wait: bool = True, timeout: float = 8.0) -> None:
        """Interrupt in-flight work, stop the worker, optionally wait until idle."""
        self.request_interrupt()
        if not self._sync:
            self._inbox.put(_SENTINEL)
            if wait:
                self._idle.wait(timeout=timeout)
                if self._thread.is_alive():
                    self._thread.join(timeout=max(0.1, timeout / 2))

    def is_busy(self) -> bool:
        return self._busy.is_set()

    def queued_count(self) -> int:
        with self._lock:
            return len(self._queued_preview)

    def cancel_requested(self) -> bool:
        return self._cancel.is_set() or _GLOBAL_CANCEL.is_set()

    def clear_cancel(self) -> None:
        self._cancel.clear()
        _GLOBAL_CANCEL.clear()

    def request_interrupt(self) -> None:
        """Pause/kill the in-flight turn (codex proc + hunt stop)."""
        bump_cancel_epoch()
        self._cancel.set()
        _GLOBAL_CANCEL.set()
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
        try:
            from .cursor_backend import close_cursor_agent

            # Best-effort: drop durable agent so a cancelled run cannot resume.
            if self.is_busy():
                close_cursor_agent()
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
        epoch = begin_turn_epoch()
        token = bind_turn_epoch(epoch)
        self._idle.clear()
        self._busy.set()
        try:
            self._turn_fn(text)
        except Exception as exc:  # noqa: BLE001
            ui.error(f"turn crashed: {type(exc).__name__}: {exc}")
        finally:
            reset_turn_epoch(token)
            self._busy.clear()
            clear_turn_cancel_flags_only()
            self._idle.set()

    def _loop(self) -> None:
        while True:
            item = self._inbox.get()
            if item is _SENTINEL:
                break
            self._run_one(str(item))
        self._idle.set()


# Process-global bus used by cancel checks in backends.
_BUS: TurnBus | None = None


def get_bus() -> TurnBus | None:
    return _BUS


def set_bus(bus: TurnBus | None) -> None:
    global _BUS
    _BUS = bus


def turn_cancel_requested() -> bool:
    """True if the operator interrupted the current turn (queue / Ctrl+C / exit)."""
    my = _turn_epoch.get()
    if my >= 0 and my < current_cancel_epoch():
        return True
    if _GLOBAL_CANCEL.is_set():
        return True
    bus = _BUS
    return bool(bus and bus.cancel_requested())


def clear_turn_cancel() -> None:
    """Clear interrupt flags so the next prompt can run after Ctrl+C / stop.

    Prefer ``begin_turn_epoch()`` at turn start so old turns stay cancelled.
    """
    clear_turn_cancel_flags_only()
