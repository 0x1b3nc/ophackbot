"""Operator /force override: conscious bypass of ALL SCOPE gates.

When force is ON, the operator can hit any host/action they ask for — including
explicitly OUT_OF_SCOPE. Legal/operational risk is strictly theirs.
Without force, OOS and soft gates still block as usual.
Active traffic still needs approve (unless YOLO skips approve).
"""

from __future__ import annotations

from . import ui

_FORCE_ACTIVE = False

FORCE_BANNER = (
    "**FORCE ON — operator responsibility**\n\n"
    "You are overriding **all** SCOPE gates: OUT_OF_SCOPE hosts, level-3 / "
    "prohibited wording, and hosts not confirmed in SCOPE.md.\n\n"
    "- **Approve** is still required before any active traffic (unless `/yolo on`).\n"
    "- Legal/operational risk is **yours** alone.\n\n"
    "Turn off with `/force off`."
)

# Words in a prompt that force this turn (OR with session flag).
FORCE_WORDS = (
    "/force",
    "i assume responsibility",
    "i assume the responsibility",
    "eu assumo",
    "eu assumo a responsabilidade",
    "assume responsibility",
)


def is_forced() -> bool:
    return _FORCE_ACTIVE


def enable_force(*, quiet: bool = False) -> None:
    global _FORCE_ACTIVE
    _FORCE_ACTIVE = True
    if not quiet:
        ui.markdown_panel(FORCE_BANNER, title="force")


def disable_force(*, quiet: bool = False) -> None:
    global _FORCE_ACTIVE
    _FORCE_ACTIVE = False
    if not quiet:
        ui.success("force OFF — SCOPE soft gates restored")


def set_force(on: bool) -> None:
    if on:
        enable_force()
    else:
        disable_force()


def prompt_wants_force(text: str) -> bool:
    """True if the prompt itself asks for a one-shot force override."""
    import re

    low = text.lower()
    if any(w in low for w in FORCE_WORDS):
        return True
    tokens = re.findall(r"[a-z0-9_/]+", low)
    # bare "force" token, but not the phrase "brute force"
    if "force" in tokens and "brute" not in tokens and "bruteforce" not in tokens:
        return True
    return False


def effective_force(*, prompt_force: bool = False, arg_force: bool | None = None) -> bool:
    """Session OR prompt OR explicit tool arg."""
    if arg_force is True:
        return True
    if arg_force is False and not prompt_force and not _FORCE_ACTIVE:
        return False
    return _FORCE_ACTIVE or prompt_force or bool(arg_force)
