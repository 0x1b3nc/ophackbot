"""Plain-text helpers for live stream pins."""

from __future__ import annotations

import re


def plain_text(text: str) -> str:
    """Strip Markdown markers for live stream lines only (think/tool/plan pins)."""
    s = text or ""
    s = re.sub(r"```[a-zA-Z0-9_+-]*\n?", "", s)
    s = s.replace("```", "")
    s = re.sub(r"^#{1,6}\s*", "", s, flags=re.M)
    s = re.sub(r"\*\*(.+?)\*\*", r"\1", s)
    s = re.sub(r"__(.+?)__", r"\1", s)
    s = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", r"\1", s)
    s = re.sub(r"`([^`]+)`", r"\1", s)
    s = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", s)
    return s.strip()
