"""Operator line input with proper paste handling.

Rich ``Prompt.ask`` treats a trailing newline in the clipboard as Enter, so a
paste immediately starts a turn before the operator can keep typing.
``prompt_toolkit`` uses bracketed-paste: multi-line / newline-terminated pastes
land in the buffer and wait for a real Enter.
"""

from __future__ import annotations

from typing import Callable


def ask_operator_line(tag: str, *, fallback: Callable[[str], str] | None = None) -> str:
    """Prompt ``hackbot · <tag>: `` and return stripped input."""
    label = f"hackbot · {tag}: "
    try:
        from prompt_toolkit import prompt as pt_prompt
        from prompt_toolkit.formatted_text import FormattedText
        from prompt_toolkit.styles import Style
    except ImportError:
        if fallback is not None:
            return (fallback(f"[bold cyan]hackbot[/] [dim]· {tag}[/]") or "").strip()
        return input(label).strip()

    style = Style.from_dict(
        {
            "name": "bold ansicyan",
            "sep": "ansibrightblack",
            "tag": "ansibrightblack",
        }
    )
    message = FormattedText(
        [
            ("class:name", "hackbot"),
            ("class:sep", " · "),
            ("class:tag", f"{tag}: "),
        ]
    )
    try:
        text = pt_prompt(message, style=style)
    except (EOFError, KeyboardInterrupt):
        raise
    except Exception:
        if fallback is not None:
            return (fallback(f"[bold cyan]hackbot[/] [dim]· {tag}[/]") or "").strip()
        return input(label).strip()
    return (text or "").strip()
