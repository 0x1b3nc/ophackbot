"""Operator line input with proper paste handling + concurrent-turn support.

Rich ``Prompt.ask`` treats a trailing newline in the clipboard as Enter, so a
paste immediately starts a turn before the operator can keep typing.
``prompt_toolkit`` uses bracketed-paste: multi-line / newline-terminated pastes
land in the buffer and wait for a real Enter.

While a turn runs on a worker thread, the main thread keeps a PromptSession
open under ``patch_stdout`` so the operator can type/queue; approve prompts
from the worker use ``run_in_terminal`` so they do not race the input line.

Prompt chrome colors follow sossost/claude-hq (MIT) dark theme tokens.
"""

from __future__ import annotations

from contextlib import contextmanager
from typing import Callable, Iterator

_SESSION = None  # prompt_toolkit.PromptSession | None
_PATCH = None

# claude-hq dark: accent #d4a574, muted #6b6b76
_ACCENT = "#d4a574"
_MUTED = "#6b6b76"


def get_prompt_session():
    return _SESSION


@contextmanager
def operator_input_session() -> Iterator[None]:
    """Install a shared PromptSession + patch_stdout for the REPL lifetime."""
    global _SESSION, _PATCH
    try:
        from prompt_toolkit import PromptSession
        from prompt_toolkit.patch_stdout import patch_stdout
    except ImportError:
        yield
        return

    session = PromptSession()
    _SESSION = session
    # raw=True: keep Rich/ANSI SGR codes. Default patch_stdout strips ESC and
    # leaves garbage like "?[1;32m✓?[0m" in the terminal.
    try:
        patch_cm = patch_stdout(raw=True)
    except TypeError:
        patch_cm = patch_stdout()
    _PATCH = patch_cm
    patch_cm.__enter__()
    try:
        yield
    finally:
        try:
            patch_cm.__exit__(None, None, None)
        except Exception:  # noqa: BLE001
            pass
        _PATCH = None
        _SESSION = None


def ask_operator_line(tag: str, *, fallback: Callable[[str], str] | None = None) -> str:
    """Clean prompt — no bottom_toolbar (it paints a broken white bar on Kali)."""
    label = f"› {tag} "
    try:
        from prompt_toolkit.formatted_text import FormattedText
        from prompt_toolkit.styles import Style
    except ImportError:
        if fallback is not None:
            return (fallback(f"[bold #d4a574]›[/] [dim]{tag}[/]") or "").strip()
        return input(label).strip()

    style = Style.from_dict(
        {
            "prompt": f"bold {_ACCENT}",
            "tag": _MUTED,
            "rprompt": _MUTED,
        }
    )
    message = FormattedText(
        [
            ("class:prompt", "› "),
            ("class:tag", f"{tag} "),
        ]
    )
    # Short right-side hint — never a full-width toolbar.
    rprompt = FormattedText([("class:rprompt", "ctrl+c stop")])
    try:
        session = _SESSION
        kwargs: dict = {"style": style, "rprompt": rprompt}
        if session is not None:
            text = session.prompt(message, **kwargs)
        else:
            from prompt_toolkit import prompt as pt_prompt

            text = pt_prompt(message, **kwargs)
    except (EOFError, KeyboardInterrupt):
        raise
    except TypeError:
        try:
            session = _SESSION
            if session is not None:
                text = session.prompt(message, style=style)
            else:
                from prompt_toolkit import prompt as pt_prompt

                text = pt_prompt(message, style=style)
        except (EOFError, KeyboardInterrupt):
            raise
        except Exception:
            if fallback is not None:
                return (fallback(f"[bold #d4a574]›[/] [dim]{tag}[/]") or "").strip()
            return input(label).strip()
    except Exception:
        if fallback is not None:
            return (fallback(f"[bold #d4a574]›[/] [dim]{tag}[/]") or "").strip()
        return input(label).strip()
    return (text or "").strip()


def ask_yes_no(message: str, *, default: str = "n") -> str:
    """Ask y/n; safe while the main PromptSession is active (run_in_terminal).

    Returns the raw answer string (caller normalizes).
    """
    from rich.prompt import Prompt

    def _ask() -> str:
        return Prompt.ask(message, default=default) or ""

    session = _SESSION
    if session is None:
        return _ask()

    try:
        from prompt_toolkit.application import run_in_terminal
    except ImportError:
        return _ask()

    box: dict[str, str] = {"v": ""}

    def _in_term() -> None:
        box["v"] = _ask()

    # Worker thread (turn) → temporarily own the TTY for the approve prompt.
    run_in_terminal(_in_term)
    return box["v"]
