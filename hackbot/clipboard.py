"""Cross-platform clipboard helpers for TUI / REPL.

Textual's OSC-52 alone is unreliable (Cursor terminal, some SSH, WT prompts).
This module tries OS-native backends first, then OSC-52, then a temp file.

Also normalizes text so terminal cell-padding spaces (the "infinite gap" when
selecting short lines across the full TUI width) do not survive into paste.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path


def clipboard_fallback_path() -> Path:
    return Path(tempfile.gettempdir()) / "hackbot-clipboard.txt"


def normalize_copied_text(text: str) -> str:
    """Clean text that came from a terminal screen selection.

    Terminal select copies *cells*, so short lines are padded with spaces to the
    window width (paste looks like a huge gap). Soft-wrapped long lines also
    pick up junk spaces at the wrap point.

    We strip trailing whitespace per line and collapse absurd runs of spaces
    that only appear from cell padding (2+ spaces between non-space tokens on
    the same line are preserved when they look intentional — e.g. code indent
    at line start stays; mid-line 8+ spaces from a full-width drag get collapsed).
    """
    if not text:
        return ""
    s = text.replace("\r\n", "\n").replace("\r", "\n")
    lines: list[str] = []
    for raw in s.split("\n"):
        # Keep leading indent (code / lists); drop trailing cell padding
        line = raw.rstrip(" \t")
        # Full-width drag often leaves a single logical line with a huge
        # middle gap ("text" + 80 spaces + nothing). Collapse 4+ mid spaces.
        if "    " in line.lstrip():
            lead = len(line) - len(line.lstrip(" "))
            body = line[lead:]
            body = re.sub(r" {4,}", " ", body)
            line = (" " * lead) + body
        lines.append(line)
    while lines and lines[-1] == "":
        lines.pop()
    return "\n".join(lines)


def copy_text(text: str, *, osc52_write=None, normalize: bool = True) -> tuple[bool, str]:
    """Copy ``text`` to the system clipboard.

    Returns ``(ok, method)`` where method is a short label
    (``powershell`` / ``clip`` / ``pyperclip`` / ``xclip`` / … /
    ``osc52`` / ``file:…``).
    """
    data = normalize_copied_text(text) if normalize else (text or "")
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


def read_text(*, allow_file_fallback: bool = False) -> str | None:
    """Best-effort read from the system clipboard.

    Does **not** read ``hackbot-clipboard.txt`` by default — that file is only a
    last-resort *write* sink and can be stale from a prior session.
    """
    if sys.platform == "win32":
        ps = shutil.which("powershell") or shutil.which("pwsh")
        if ps:
            try:
                r = subprocess.run(
                    [ps, "-NoProfile", "-NonInteractive", "-Command", "Get-Clipboard -Raw"],
                    check=True,
                    timeout=8,
                    capture_output=True,
                    text=True,
                    encoding="utf-8",
                    errors="replace",
                )
                return r.stdout
            except Exception:  # noqa: BLE001
                pass
    try:
        import pyperclip

        return pyperclip.paste()
    except Exception:  # noqa: BLE001
        pass
    for cmd in (
        ["xclip", "-selection", "clipboard", "-o"],
        ["xsel", "--clipboard", "--output"],
        ["wl-paste"],
    ):
        if not shutil.which(cmd[0]):
            continue
        try:
            r = subprocess.run(
                cmd,
                check=True,
                timeout=5,
                capture_output=True,
            )
            return r.stdout.decode("utf-8", errors="replace")
        except Exception:  # noqa: BLE001
            continue
    if allow_file_fallback:
        path = clipboard_fallback_path()
        if path.is_file():
            try:
                return path.read_text(encoding="utf-8")
            except Exception:  # noqa: BLE001
                return None
    return None


def clean_clipboard() -> tuple[bool, str, int, int]:
    """Read clipboard, normalize padding, write back.

    Returns ``(ok, method, before_len, after_len)``.
    """
    raw = read_text(allow_file_fallback=False)
    if raw is None:
        return False, "empty", 0, 0
    cleaned = normalize_copied_text(raw)
    if not cleaned.strip():
        return False, "empty", len(raw), 0
    ok, method = copy_text(cleaned, normalize=False)
    return ok, method, len(raw), len(cleaned)


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
