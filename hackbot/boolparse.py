"""Strict boolean parsing for tool args (avoid bool('false') == True)."""

from __future__ import annotations

from typing import Any


def parse_bool(value: Any, *, default: bool = False) -> bool:
    """Parse common truthy/falsey forms. Unknown strings fall back to ``default``."""
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    if isinstance(value, (int, float)):
        return value != 0
    if isinstance(value, str):
        key = value.strip().lower()
        if key in {"1", "true", "yes", "on", "y"}:
            return True
        if key in {"0", "false", "no", "off", "n", ""}:
            return False
        return default
    return bool(value)
