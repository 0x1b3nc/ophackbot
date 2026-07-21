"""Windows fix for cursor-sdk bridge discovery (WinError 10038).

``cursor_sdk._bridge._read_discovery`` uses ``selectors.DefaultSelector`` on the
bridge subprocess stderr pipe. On Windows, ``select()`` only accepts sockets —
pipe FDs raise ``OSError: [WinError 10038]``.

We replace discovery with a non-blocking ``os.read`` + sleep poll that matches
the upstream parse logic.
"""

from __future__ import annotations

import codecs
import os
import time
from typing import Any, Mapping

_PATCHED = False


def apply_windows_bridge_patch() -> bool:
    """Monkey-patch cursor_sdk bridge discovery on Windows. Idempotent."""
    global _PATCHED
    if _PATCHED:
        return True
    if os.name != "nt":
        return False
    try:
        from cursor_sdk import _bridge
        from cursor_sdk.errors import CursorSDKError
    except ImportError:
        return False

    def _read_discovery_windows(
        process: Any, timeout: float
    ) -> Mapping[str, Any]:
        if process.stderr is None:
            raise CursorSDKError("Bridge process stderr is unavailable")
        stderr_fd = process.stderr.fileno()
        was_blocking = os.get_blocking(stderr_fd)
        os.set_blocking(stderr_fd, False)
        try:
            decoder = codecs.getincrementaldecoder("utf-8")(errors="replace")
            deadline = time.monotonic() + timeout
            stderr_lines: list[str] = []
            pending = ""

            def drain_available() -> Mapping[str, Any] | None:
                nonlocal pending
                while True:
                    try:
                        chunk = os.read(stderr_fd, 8192)
                    except BlockingIOError:
                        return None
                    if not chunk:
                        final_text = decoder.decode(b"", final=True)
                        if final_text:
                            pending += final_text
                        if pending:
                            line = pending
                            pending = ""
                            stderr_lines.append(line)
                            return _bridge.parse_discovery_line(line)
                        return None
                    pending += decoder.decode(chunk)
                    while "\n" in pending:
                        line, pending = pending.split("\n", 1)
                        line += "\n"
                        stderr_lines.append(line)
                        discovery = _bridge.parse_discovery_line(line)
                        if discovery is not None:
                            return discovery

            while time.monotonic() < deadline:
                discovery = drain_available()
                if discovery is not None:
                    return discovery
                exit_code = process.poll()
                if exit_code is not None:
                    discovery = drain_available()
                    if discovery is not None:
                        return discovery
                    raise CursorSDKError(
                        f"Bridge exited before discovery with status {exit_code}: "
                        + "".join(stderr_lines)
                        + pending
                    )
                time.sleep(0.05)
            raise CursorSDKError("Timed out waiting for bridge discovery")
        finally:
            try:
                os.set_blocking(stderr_fd, was_blocking)
            except OSError:
                pass

    _bridge._read_discovery = _read_discovery_windows  # type: ignore[assignment]
    _PATCHED = True
    return True
