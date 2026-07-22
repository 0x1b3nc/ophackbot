"""Cross-platform clipboard helpers for TUI / REPL.

Textual's OSC-52 alone is unreliable (Cursor terminal, some SSH, WT prompts).
This module tries OS-native backends first, then OSC-52, then a temp file.
"""

from __future__ import annotations

import os
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def clipboard_fallback_path() -> Path:
    return Path(tempfile.gettempdir()) / "hackbot-clipboard.txt"


def copy_text(text: str, *, osc52_write=None) -> tuple[bool, str]:
    """Copy ``text`` to the system clipboard.

    Returns ``(ok, method)`` where method is a short label
    (``powershell`` / ``clip`` / ``pyperclip`` / ``xclip`` / … /
    ``osc52`` / ``file:…``).
    """
    data = text or ""
    if not data.strip():
        return False, "empty"

    if sys.platform == "win32":
        ok, method = _windows_copy(data)
        if ok:
            return True, method

    try:
        import pyperclip

        pyperclip.copy(data)
        return True, "pyperclip"
    except Exception:  # noqa: BLE001
        pass

    for cmd, label in (
        (["xclip", "-selection", "clipboard"], "xclip"),
        (["xsel", "--clipboard", "--input"], "xsel"),
        (["wl-copy"], "wl-copy"),
        (["clip.exe"], "clip.exe"),  # WSL → Windows
    ):
        if not shutil.which(cmd[0]):
            continue
        try:
            subprocess.run(
                cmd,
                input=data.encode("utf-8"),
                check=True,
                timeout=5,
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return True, label
        except Exception:  # noqa: BLE001
            continue

    if callable(osc52_write):
        try:
            osc52_write(data)
            return True, "osc52"
        except Exception:  # noqa: BLE001
            pass

    try:
        path = clipboard_fallback_path()
        path.write_text(data, encoding="utf-8")
        return True, f"file:{path}"
    except Exception:  # noqa: BLE001
        return False, "failed"


def _windows_copy(data: str) -> tuple[bool, str]:
    """Unicode-safe clipboard on Windows via temp file + Set-Clipboard."""
    clip_bin = shutil.which("clip") or shutil.which("clip.exe")
    ps = shutil.which("powershell") or shutil.which("pwsh")
    tmp: Path | None = None
    try:
        fd, name = tempfile.mkstemp(prefix="hb-clip-", suffix=".txt")
        os.close(fd)
        tmp = Path(name)
        tmp.write_text(data, encoding="utf-8-sig", newline="\n")

        if ps:
            script = (
                "Get-Content -LiteralPath $env:HB_CLIP_FILE -Raw -Encoding UTF8 "
                "| Set-Clipboard"
            )
            env = os.environ.copy()
            env["HB_CLIP_FILE"] = str(tmp)
            try:
                subprocess.run(
                    [ps, "-NoProfile", "-NonInteractive", "-Command", script],
                    check=True,
                    timeout=10,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                    env=env,
                )
                return True, "powershell"
            except Exception:  # noqa: BLE001
                pass

        if clip_bin:
            try:
                subprocess.run(
                    [clip_bin],
                    input=data.encode("utf-16le"),
                    check=True,
                    timeout=5,
                    stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL,
                )
                return True, "clip"
            except Exception:  # noqa: BLE001
                pass
    finally:
        if tmp is not None:
            try:
                tmp.unlink(missing_ok=True)
            except Exception:  # noqa: BLE001
                pass

    return False, "win-miss"
