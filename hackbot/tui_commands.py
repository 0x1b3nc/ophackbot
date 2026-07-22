"""Slash-command handling for the Textual TUI (returns text, no Rich chrome)."""

from __future__ import annotations

import json
import os
from dataclasses import dataclass
from typing import Callable

from .providers import PROVIDERS
from .session import clear_active, get_active, set_active, status_line
from .step_mode import disable_step_mode, enable_step_mode, step_mode_enabled
from .turn_bridge import resolve_mode
from .yolo import disable_yolo, enable_yolo, is_yolo

CommandHandler = Callable[[str], "CmdResult"]


@dataclass
class CmdResult:
    messages: list[str]
    handled: bool = True
    clear_chat: bool = False
    exit_app: bool = False
    refresh_status: bool = True


HACKBOT_SLASH: list[tuple[str, str]] = [
    ("/help", "Show shortcuts"),
    ("/status", "Provider, target, yolo, step"),
    ("/clear", "Clear the chat pane"),
    ("/exit", "Quit the TUI"),
    ("/yolo on", "Auto-approve tools + force (incl. OOS)"),
    ("/yolo off", "Ask before tools"),
    ("/step on", "Pause after each act"),
    ("/step off", "Full hunt until finding/budget"),
    ("/force on", "Full SCOPE override (incl. OOS)"),
    ("/force off", "Force off"),
    ("/target ", "Set active target (e.g. /target demo)"),
    ("/target clear", "Clear active target"),
    ("/providers", "List brains"),
    ("/provider ", "Set brain (codex|cursor|offline|…)"),
    ("/codex", "Switch to Codex"),
    ("/cursor", "Switch to Cursor"),
    ("/local", "Switch to offline brain"),
    ("/offline", "Switch to offline brain"),
    ("/models", "List allowed model ids"),
    ("/models refresh", "Refetch live model catalog"),
    ("/model ", "Set model id (e.g. /model composer-2.5)"),
    ("/effort ", "Set effort: /effort high fast | medium | high nofast"),
    ("/fast on", "Cursor ModelSelection fast=true (grok/composer)"),
    ("/fast off", "Cursor fast=false (standard)"),
    ("/tools", "Installed tool stack status"),
    ("/config", "Show effective config"),
    ("/hunt ", "Start hunt prompt (needs /target)"),
    ("/sessions", "Show saved A/B identity"),
    ("/copy", "Copy last reply to clipboard"),
    ("/copy all", "Copy full chat to clipboard"),
    ("/cleanclip", "Strip terminal padding spaces from clipboard"),
    ("/paste", "Load OS clipboard into composer (full multiline)"),
]


def filter_slash_commands(prefix: str) -> list[tuple[str, str]]:
    p = (prefix or "").strip().lower()
    if not p.startswith("/"):
        return []
    return [(c, d) for c, d in HACKBOT_SLASH if c.lower().startswith(p) or p == "/"]


def handle_slash(text: str) -> CmdResult:
    """Handle a slash command. If not a command, handled=False."""
    raw = (text or "").strip()
    if not raw.startswith("/"):
        return CmdResult(messages=[], handled=False, refresh_status=False)

    low = raw.lower()
    if low in {"/exit", "/quit", "/q"}:
        return CmdResult(messages=["bye"], exit_app=True)

    if low == "/clear":
        return CmdResult(messages=[], clear_chat=True)

    if low == "/help":
        lines = [
            "**hackbot** operator commands (handled locally — never sent to the model):",
            "",
        ]
        for cmd, desc in HACKBOT_SLASH:
            lines.append(f"- `{cmd}` — {desc}")
        return CmdResult(messages=["\n".join(lines)])

    if low == "/status":
        mode, label = resolve_mode()
        active = get_active()
        lines = [
            f"**mode** {label}",
            f"**target** {active.name if active else '—'}",
            f"**hunt** {status_line()}",
            f"**yolo** {'on' if is_yolo() else 'off'}",
            f"**step** {'on' if step_mode_enabled() else 'off'}",
        ]
        return CmdResult(messages=["\n".join(lines)])

    if low.startswith("/yolo"):
        arg = raw[len("/yolo") :].strip().lower()
        if arg in {"", "on", "1", "true", "yes"}:
            enable_yolo(quiet=True)
            return CmdResult(messages=["yolo **on** (force on; OOS overridable)"])
        if arg in {"off", "0", "false", "no"}:
            disable_yolo()
            return CmdResult(messages=["yolo **off**"])
        return CmdResult(messages=[f"yolo is {'on' if is_yolo() else 'off'} — `/yolo on|off`"])

    if low.startswith("/step"):
        arg = raw[len("/step") :].strip().lower()
        if arg in {"", "on", "1", "true", "yes"}:
            enable_step_mode(quiet=True)
            return CmdResult(messages=["step **on**"])
        if arg in {"off", "0", "false", "no", "full", "hunt"}:
            disable_step_mode(quiet=True)
            return CmdResult(messages=["step **off** (full hunt)"])
        return CmdResult(
            messages=[
                f"step is {'on' if step_mode_enabled() else 'off'} — `/step on|off`"
            ]
        )

    if low.startswith("/force"):
        from .force import disable_force, enable_force, is_forced

        arg = raw[len("/force") :].strip().lower()
        if arg in {"", "on", "1", "true", "yes"}:
            enable_force(quiet=True)
            return CmdResult(messages=["force **on**"])
        if arg in {"off", "0", "false", "no"}:
            from .yolo import is_yolo

            if is_yolo():
                return CmdResult(
                    messages=[
                        "force stays **on** while yolo is on — `/yolo off` first"
                    ]
                )
            disable_force(quiet=True)
            return CmdResult(messages=["force **off**"])
        return CmdResult(messages=[f"force is {'on' if is_forced() else 'off'}"])

    if low.startswith("/target"):
        arg = raw[len("/target") :].strip()
        if not arg:
            return CmdResult(
                messages=[f"hunt: {status_line()}", "set: `/target <name>` · clear: `/target clear`"]
            )
        if arg.lower() in {"clear", "none", "off"}:
            clear_active()
            return CmdResult(messages=["active target cleared"])
        try:
            sess = set_active(arg)
        except FileNotFoundError as exc:
            return CmdResult(messages=[f"error: {exc}"])
        extra = f"\nnext: {sess.next_step}" if sess.next_step else ""
        return CmdResult(messages=[f"active target → **{sess.name}**\n{status_line()}{extra}"])

    if low == "/providers":
        names = ", ".join(sorted(PROVIDERS.keys()))
        return CmdResult(messages=[f"providers: {names}, offline"])

    if low.startswith("/provider"):
        arg = raw[len("/provider") :].strip().lower()
        if not arg:
            _, label = resolve_mode()
            return CmdResult(messages=[f"provider: {label}", "set: `/provider <name>`"])
        if arg not in PROVIDERS and arg not in {"offline", "local"}:
            return CmdResult(messages=[f"unknown `{arg}` — try `/providers`"])
        if arg in {"offline", "local"}:
            os.environ["HACKBOT_PROVIDER"] = "offline"
        else:
            os.environ["HACKBOT_PROVIDER"] = arg
        _, label = resolve_mode()
        return CmdResult(messages=[f"provider → **{label}**"])

    if low == "/codex":
        os.environ["HACKBOT_PROVIDER"] = "codex"
        try:
            from .codex_backend import codex_available

            codex_available(force=True)
        except Exception:  # noqa: BLE001
            pass
        mode, label = resolve_mode()
        if mode == "codex":
            return CmdResult(messages=[f"switched to **codex** ({label})"])
        return CmdResult(messages=["codex not ready — run `codex login` first"])

    if low == "/cursor":
        os.environ["HACKBOT_PROVIDER"] = "cursor"
        mode, label = resolve_mode()
        if mode == "cursor":
            return CmdResult(messages=[f"switched to **cursor** ({label})"])
        return CmdResult(
            messages=[
                "cursor not ready — set `CURSOR_API_KEY` and `pip install 'hackbot-kit[cursor]'`"
            ]
        )

    if low in {"/local", "/offline"}:
        os.environ["HACKBOT_PROVIDER"] = "offline"
        _, label = resolve_mode()
        return CmdResult(messages=[f"switched to **offline** ({label})"])

    if low in {"/tools", "/caps", "/capabilities", "/stack"}:
        try:
            from .capabilities import collect_capabilities

            caps = collect_capabilities(probe_network=False)
            return CmdResult(messages=[f"```json\n{json.dumps(caps, indent=2, default=str)}\n```"])
        except Exception as exc:  # noqa: BLE001
            return CmdResult(messages=[f"tools status error: {exc}"])

    if low in {"/config", "/cfg"}:
        try:
            from .config import get_config

            cfg = get_config(reload=True)
            return CmdResult(
                messages=[f"```json\n{json.dumps(cfg.to_public_dict(), indent=2)}\n```"]
            )
        except Exception as exc:  # noqa: BLE001
            return CmdResult(messages=[f"config error: {exc}"])

    if low == "/models" or low.startswith("/models "):
        return _cmd_models_text(raw)

    if low.startswith("/model"):
        return _cmd_model_set(raw)

    if low.startswith("/effort"):
        return _cmd_effort(raw)

    if low.startswith("/fast"):
        return _cmd_fast(raw)

    if low in {"/sessions", "/identity"}:
        active = get_active()
        if active is None:
            return CmdResult(messages=["no active target — `/target <name>` first"])
        try:
            from .tools import execute_tool

            out = execute_tool("show_identity", {"target_dir": str(active.target_dir)})
            return CmdResult(messages=[f"```json\n{out}\n```"])
        except Exception as exc:  # noqa: BLE001
            return CmdResult(messages=[f"identity error: {exc}"])

    if low.startswith("/hunt"):
        rest = raw[len("/hunt") :].strip()
        if rest.lower() in {"", "help", "?"}:
            return CmdResult(
                messages=[
                    "usage: `/hunt <prompt>` · `/hunt status` · `/hunt stop`",
                    "needs `/target` first",
                ]
            )
        # Let the turn bridge / local agent interpret full /hunt lines.
        return CmdResult(messages=[], handled=False, refresh_status=False)

    # Unknown slash — still ours; never forward to the model.
    return CmdResult(
        messages=[
            f"`{raw}` is not a hackbot operator command.",
            "Try `/help`. Slash commands are not hunt steps — they never go to the model.",
        ],
        handled=True,
    )


def _provider_for_models() -> str:
    mode, _ = resolve_mode()
    try:
        from .providers import ConfigError, resolve_config

        prov = resolve_config().provider
    except Exception:  # noqa: BLE001
        prov = os.environ.get("HACKBOT_PROVIDER", "").strip().lower()
    if mode in {"cursor", "codex", "model"} and prov in {"", "offline"}:
        if mode == "cursor":
            return "cursor"
        if mode == "codex":
            return "codex"
    if not prov or prov == "offline":
        return os.environ.get("HACKBOT_PROVIDER") or "openai"
    return prov


def _cmd_models_text(raw: str) -> CmdResult:
    from .model_catalog import clear_model_cache, known_models, live_models_status

    refresh = raw.strip().lower() in {"/models refresh", "/models --refresh"}
    prov = _provider_for_models()
    lines = [f"**models ({prov})**"]
    if refresh:
        clear_model_cache(prov)
        try:
            from .model_catalog import fetch_live_models

            fetch_live_models(prov, force_refresh=True)
            lines.append("_cache cleared — refetched_")
        except Exception as exc:  # noqa: BLE001
            lines.append(f"refresh warn: {exc}")
    rows = known_models(prov, include_live=True)
    if not rows:
        lines.append("no known models — set API key / start local server, then `/models refresh`")
    else:
        for mid, note in rows:
            lines.append(f"- `{mid}` — {note}")
    if prov not in {"cursor", "offline"}:
        try:
            lines.append(f"live: {live_models_status(prov)}")
        except Exception:  # noqa: BLE001
            pass
    lines.append("set: `/model <id>`")
    if prov == "cursor":
        lines.append("")
        lines.append("effort+fast (grok-4.5 / composer-2.5):")
        lines.append("- `/effort high fast` · `/effort medium` · `/effort high nofast`")
        lines.append("- `/fast on` · `/fast off`")
    return CmdResult(messages=["\n".join(lines)])


def _cmd_model_set(raw: str) -> CmdResult:
    from .model_catalog import resolve_model

    arg = raw[len("/model") :].strip()
    if not arg:
        return CmdResult(
            messages=[
                f"model: `{os.environ.get('HACKBOT_MODEL') or '(provider default)'}`",
                "set: `/model <id>` · list: `/models`",
            ]
        )
    prov = _provider_for_models()
    mode, _ = resolve_mode()
    if not prov or prov == "offline":
        if mode == "cursor":
            prov = "cursor"
        elif mode == "codex":
            prov = "codex"
        else:
            return CmdResult(messages=["pick a provider first: `/provider openai|codex|cursor|…`"])
    try:
        canonical, source = resolve_model(prov, arg)
    except ValueError as exc:
        return CmdResult(messages=[str(exc), "list valid ids: `/models`"])
    os.environ["HACKBOT_MODEL"] = canonical
    msg = f"model → **{canonical}** [{source}]"
    if prov == "cursor":
        try:
            from .cursor_backend import close_cursor_agent
            from .cursor_models import resolve_cursor_model

            close_cursor_agent()
            resolved = resolve_cursor_model(canonical, require_known=True)
            msg += f"\nwill request: `{resolved.display()}`"
            msg += "\neffort+fast: `/effort high fast` · `/effort medium` · `/fast on|off`"
        except Exception:  # noqa: BLE001
            msg += "\neffort+fast: `/effort high fast` · `/fast on|off`"
    return CmdResult(messages=[msg])


def _cmd_effort(raw: str) -> CmdResult:
    from .cursor_models import parse_effort_fast

    arg = raw[len("/effort") :].strip()
    fast_on = os.environ.get("HACKBOT_CURSOR_FAST", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    if not arg:
        return CmdResult(
            messages=[
                f"effort: `{os.environ.get('HACKBOT_EFFORT', 'auto')}`",
                f"fast: `{'on' if fast_on else 'off'}`",
                "levels: `auto | minimal | low | medium | high | xhigh`",
                "cursor (grok-4.5 / composer-2.5):",
                "- `/effort high fast`",
                "- `/effort medium`",
                "- `/effort high nofast`",
                "- `/fast on` · `/fast off`",
            ]
        )
    level, fast = parse_effort_fast(arg)
    if not level:
        return CmdResult(
            messages=[
                f"unknown effort `{arg}`",
                "examples: `low` · `medium` · `high` · `high fast` · `medium nofast`",
            ]
        )
    os.environ["HACKBOT_EFFORT"] = level
    if fast is not None:
        os.environ["HACKBOT_CURSOR_FAST"] = "1" if fast else "0"
        try:
            from .cursor_backend import close_cursor_agent

            close_cursor_agent()
        except Exception:  # noqa: BLE001
            pass
    msg = f"effort → **{level}**"
    if fast is True:
        msg += " + **fast**"
    elif fast is False:
        msg += " + standard (nofast)"
    mode, _ = resolve_mode()
    if mode == "cursor" or os.environ.get("HACKBOT_PROVIDER", "").lower() == "cursor":
        try:
            from .cursor_models import resolve_cursor_model

            resolved = resolve_cursor_model(
                os.environ.get("HACKBOT_MODEL"),
                effort=level,
                fast=fast if fast is not None else None,
                require_known=False,
            )
            msg += f"\nwill request: `{resolved.display()}`"
        except Exception:  # noqa: BLE001
            pass
    return CmdResult(messages=[msg])


def _cmd_fast(raw: str) -> CmdResult:
    arg = raw[len("/fast") :].strip().lower()
    if arg in {"on", "1", "true", "yes"}:
        os.environ["HACKBOT_CURSOR_FAST"] = "1"
        try:
            from .cursor_backend import close_cursor_agent

            close_cursor_agent()
        except Exception:  # noqa: BLE001
            pass
        return CmdResult(messages=["cursor fast: **on** (ModelSelection `fast=true`)"])
    if arg in {"off", "0", "false", "no"}:
        os.environ["HACKBOT_CURSOR_FAST"] = "0"
        try:
            from .cursor_backend import close_cursor_agent

            close_cursor_agent()
        except Exception:  # noqa: BLE001
            pass
        return CmdResult(messages=["cursor fast: **off** (standard)"])
    cur = os.environ.get("HACKBOT_CURSOR_FAST", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }
    return CmdResult(
        messages=[
            f"fast: `{'on' if cur else 'off'}`",
            "set: `/fast on|off` · or `/effort high fast`",
        ]
    )
