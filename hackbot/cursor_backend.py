"""Bridge to the Cursor Python SDK so hackbot can think + drive tools.

Local Agent (cursor-sdk) against the kit cwd. When ``HACKBOT_CURSOR_TOOLS=1``
(default), phase-filtered hackbot tools are registered as SDK CustomTools so
Cursor can call httpx/probes/fileops under SCOPE/approve (same rails as the
HTTP agent). Default mode is ``agent`` with tools on, ``plan`` when tools off
(override with ``HACKBOT_CURSOR_MODE``). Fileop JSON remains a fallback.

Auth: ``CURSOR_API_KEY`` (Dashboard → Integrations / API Keys).
Install: ``pip install 'hackbot-kit[cursor]'`` or ``pip install cursor-sdk``.
"""

from __future__ import annotations

import os
import time
from pathlib import Path
from typing import Any, Callable

from rich.text import Text as _Text

from . import ui
from .codex_backend import (
    _FILEOP_RULES,
    _MAX_FILEOP_CONTINUES,
    _apply_fileops,
    _extract_fileops,
    _file_create_hint,
    _fileop_continue_prompt,
    _should_continue_after_fileops,
    _try_direct_file_create,
)
from .cursor_models import (
    build_model_selection,
    format_selection_label,
    resolve_cursor_model,
    set_last_resolved_label,
)
from .cursor_tools import (
    build_cursor_custom_tools,
    cursor_tools_enabled,
    cursor_tools_fingerprint,
    set_cursor_approve_fn,
    tools_preamble_block,
)
from .intent import is_chat_prompt, resolve_effort_for_prompt
from .llm import streaming_enabled
from .operator_gate import stream_output_allowed
from .session import get_active
from .tool_packs import resolve_packs

ApproveFn = Callable[[str], bool]

ROOT = Path(__file__).resolve().parents[1]

# Durable agent handle for this process (closed on clear / provider switch).
_AGENT: Any = None
_AGENT_ID: str | None = None
_AGENT_FINGERPRINT: str | None = None


def ui_text(text: str, style: str) -> _Text:
    return _Text(text, style=style)


PREAMBLE_CHAT = """You are Hackbot, a short friendly authorized bounty/lab CLI agent.
Answer briefly in first person. Prefer not to edit the repo with your own tools.
If they want hunting work, ask for a concrete task (host, target folder, bug class).
""" + _FILEOP_RULES + """
Task:
"""

PREAMBLE_HUNT = """You are Hackbot, my authorized bug-bounty / lab agent in this repo.

Hard rules:
- Authorized research only. Never attack unauthorized hosts.
- Read local context only when the task needs it (SCOPE.md, notes). Skip for small talk.
- Host is IN SCOPE only if it is in that program's SCOPE.md.
- For hunt steps: falsifiable hypothesis, endpoint, aggression 0-3, policy quote,
  concrete tool call, expected evidence, stop criteria, cleanup.
- Dry-run first. Label active work "ACTIVE - needs operator approve".
- Be concise, technical, first person.
- Prefer calling the registered hackbot custom tools for recon/probes/traffic.
  Do not invent out-of-band shell/curl against live targets.
- Do ONE meaningful step, then STOP with result + ONE next suggestion. Wait.
  YOLO skips y/n only - it is not permission to run forever.
""" + _FILEOP_RULES + """
Only emit a file-op block when a file change is needed and you cannot use write_file.

Task:
"""


def cursor_available(*, force: bool = False) -> bool:
    """True when CURSOR_API_KEY is set and cursor_sdk imports."""
    del force  # reserved for future TTL cache
    from .cursor_bridge_win import apply_windows_bridge_patch
    from .providers import _first_env

    if not _first_env(("CURSOR_API_KEY",)):
        return False
    try:
        import cursor_sdk  # noqa: F401
    except ImportError:
        return False
    apply_windows_bridge_patch()
    return True


def close_cursor_agent() -> None:
    """Dispose the durable agent (e.g. /clear or leaving /provider cursor)."""
    global _AGENT, _AGENT_ID, _AGENT_FINGERPRINT
    agent = _AGENT
    _AGENT = None
    _AGENT_ID = None
    _AGENT_FINGERPRINT = None
    if agent is None:
        return
    try:
        close = getattr(agent, "close", None)
        if callable(close):
            close()
    except Exception:
        pass


def _is_bridge_dead(exc: BaseException) -> bool:
    err = str(exc).lower()
    name = type(exc).__name__.lower()
    needles = (
        "connection refused",
        "errno 111",
        "connecterror",
        "bridge request failed",
        "networkerror",
        "broken pipe",
        "connection reset",
    )
    return any(n in err for n in needles) or any(n in name for n in ("networkerror", "connecterror"))


def _cursor_mode() -> str:
    """Explicit HACKBOT_CURSOR_MODE wins; else agent when tools on, plan when off."""
    raw = (os.environ.get("HACKBOT_CURSOR_MODE") or "").strip().lower()
    if raw in {"agent", "plan"}:
        return raw
    return "agent" if cursor_tools_enabled() else "plan"


def _api_key() -> str:
    from .providers import _first_env

    return _first_env(("CURSOR_API_KEY",)) or ""


def _build_prompt(user_prompt: str, *, chat_mode: bool, tools_on: bool, pack_label: str, tool_count: int) -> str:
    preamble = PREAMBLE_CHAT if chat_mode else PREAMBLE_HUNT
    parts = [preamble]
    if not chat_mode:
        from .step_mode import step_mode_preamble

        parts.append(tools_preamble_block(enabled=tools_on, pack_label=pack_label, tool_count=tool_count))
        block = step_mode_preamble()
        if block:
            parts.append(block)
    parts.append(_file_create_hint(user_prompt))
    active = get_active()
    if active and not chat_mode:
        parts.append("\nActive target session:\n" + active.context_block() + "\n")
    parts.append("\n" + user_prompt.strip() + "\n")
    return "\n".join(parts)


def _ensure_agent(
    selection: Any,
    fingerprint: str,
    *,
    custom_tools: dict[str, Any] | None = None,
) -> Any:
    """Return a live Agent handle, recreating when model/effort/fast/mode/tools change."""
    global _AGENT, _AGENT_ID, _AGENT_FINGERPRINT
    from .cursor_bridge_win import apply_windows_bridge_patch

    apply_windows_bridge_patch()
    mode = _cursor_mode()
    tools = custom_tools or {}
    tool_fp = f"n={len(tools)}"
    fp = f"{fingerprint}|mode={mode}|{tool_fp}"
    if _AGENT is not None and _AGENT_FINGERPRINT == fp:
        return _AGENT
    if _AGENT is not None:
        close_cursor_agent()

    from cursor_sdk import Agent, LocalAgentOptions

    key = _api_key()
    if not key:
        raise RuntimeError("CURSOR_API_KEY is not set")

    local_kwargs: dict[str, Any] = {"cwd": str(ROOT)}
    if tools:
        local_kwargs["custom_tools"] = tools

    try:
        from cursor_sdk import AgentOptions

        agent = Agent.create(
            AgentOptions(
                model=selection,
                api_key=key,
                mode=mode,
                local=LocalAgentOptions(**local_kwargs),
            )
        )
    except TypeError:
        agent = Agent.create(
            model=selection,
            api_key=key,
            local=LocalAgentOptions(**local_kwargs),
        )
    enter = getattr(agent, "__enter__", None)
    if callable(enter):
        agent = enter()
    _AGENT = agent
    _AGENT_ID = getattr(agent, "agent_id", None) or getattr(agent, "agentId", None)
    _AGENT_FINGERPRINT = fp
    return agent


def _assistant_text_from_messages(messages: Any) -> str:
    chunks: list[str] = []
    for message in messages:
        mtype = getattr(message, "type", None) or (
            message.get("type") if isinstance(message, dict) else None
        )
        if mtype != "assistant":
            continue
        inner = getattr(message, "message", None)
        if inner is None and isinstance(message, dict):
            inner = message.get("message")
        content = getattr(inner, "content", None) if inner is not None else None
        if content is None and isinstance(inner, dict):
            content = inner.get("content")
        if not content:
            continue
        for block in content:
            btype = getattr(block, "type", None) or (
                block.get("type") if isinstance(block, dict) else None
            )
            if btype == "text":
                text = getattr(block, "text", None) or (
                    block.get("text") if isinstance(block, dict) else None
                )
                if text:
                    chunks.append(str(text))
    return "".join(chunks).strip()


def _run_send(agent: Any, prompt: str, *, selection: Any) -> tuple[str, str]:
    """Send one prompt; return (assistant_text, resolved_model_label). Always wait()."""
    mode = _cursor_mode()
    send_kwargs: dict[str, Any] = {}
    try:
        from cursor_sdk import SendOptions

        send_kwargs["options"] = SendOptions(mode=mode, model=selection)
    except Exception:
        send_kwargs = {}

    try:
        if send_kwargs:
            run = agent.send(prompt, **send_kwargs)
        else:
            run = agent.send(prompt)
    except TypeError:
        run = agent.send(prompt)

    stream_answer = ""
    # Live token print is off (mangled spaces); keep a spinner so the REPL isn't silent.
    wait_status = ui.console.status("[cyan]thinking…[/]", spinner="dots")
    wait_status.start()
    try:
        if streaming_enabled():
            try:
                stream = run.messages() if hasattr(run, "messages") else run.stream()
                for message in stream:
                    mtype = getattr(message, "type", None)
                    if mtype == "assistant":
                        piece = _assistant_text_from_messages([message])
                        if not piece:
                            continue
                        # Keep snapshots for wait() fallback; do not live-print tokens
                        # (Cursor deltas often arrive without spaces → "I'llload…").
                        if (
                            not stream_answer
                            or piece.startswith(stream_answer)
                            or len(piece) >= len(stream_answer)
                        ):
                            stream_answer = piece
                        if stream_output_allowed():
                            wait_status.update("[cyan]thinking…[/]")
                    elif mtype == "tool_call":
                        name = getattr(message, "name", "?")
                        tstatus = str(getattr(message, "status", "") or "")
                        # Stop spinner before tool UI / possible Confirm.ask (shared console).
                        wait_status.stop()
                        if stream_output_allowed():
                            ui.console.print(
                                ui_text(f"cursor tool  {name}  {tstatus}", "hb.dim")
                            )
                        # Resume spinner only after the tool finishes (not while approve waits).
                        if tstatus.lower() in {"completed", "error", "failed", "cancelled"}:
                            if stream_output_allowed():
                                wait_status.start()
                                wait_status.update("[cyan]thinking…[/]")
            except Exception:
                pass

        if stream_output_allowed():
            wait_status.start()
            wait_status.update("[cyan]thinking…[/]")
        result = run.wait() if hasattr(run, "wait") else None
    finally:
        wait_status.stop()
        ui.stop_live()
    status = getattr(result, "status", None) if result is not None else None

    resolved_label = format_selection_label(selection)
    if result is not None:
        rm = getattr(result, "model", None)
        if rm is not None:
            resolved_label = format_selection_label(rm)

    # Prefer final wait() text — stream chunks can mangle spaces when interleaved.
    answer = ""
    for attr in ("text", "result"):
        if result is not None and hasattr(result, attr):
            val = getattr(result, attr)
            if callable(val):
                try:
                    val = val()
                except TypeError:
                    pass
            if isinstance(val, str) and val.strip():
                answer = val.strip()
                break
    if not answer and hasattr(run, "text") and callable(run.text):
        try:
            answer = (run.text() or "").strip()
        except Exception:
            pass
    if not answer:
        answer = stream_answer.strip()

    if status == "error":
        rid = getattr(result, "id", None) or getattr(run, "id", "?")
        raise RuntimeError(f"cursor run failed (status=error) id={rid}")
    if status == "cancelled":
        return "(cancelled)", resolved_label
    return answer or "(cursor produced no output)", resolved_label


def run_cursor_turn(
    user_prompt: str,
    *,
    history: list[tuple[str, str]] | None = None,
    model: str | None = None,
    approve_fn: ApproveFn | None = None,
    allow_file_ops: bool = True,
    _fileop_depth: int = 0,
    _orig_user_prompt: str | None = None,
) -> str:
    """Run one turn through the Cursor SDK local agent and display the answer."""
    del history  # durable Agent holds conversation; REPL still stores for /clear UX
    orig = _orig_user_prompt if _orig_user_prompt is not None else user_prompt

    if allow_file_ops and _fileop_depth == 0:
        direct = _try_direct_file_create(user_prompt, approve_fn)
        if direct is not None:
            ui.turn_timing(0.0, 1)
            return direct

    if not cursor_available():
        msg = (
            "cursor unavailable. Set CURSOR_API_KEY and install cursor-sdk:\n"
            "  pip install 'hackbot-kit[cursor]'\n"
            "  setx CURSOR_API_KEY \"cursor_...\""
        )
        ui.error(msg)
        return msg

    chat_mode = False if _fileop_depth > 0 else is_chat_prompt(user_prompt)
    # Effort for ModelSelection: auto → skip on chat, medium on hunt; explicit levels always apply.
    raw_eff = (os.environ.get("HACKBOT_EFFORT") or "auto").strip().lower()
    if raw_eff in {"", "auto"} and chat_mode:
        effort: str | None = None
    else:
        effort = resolve_effort_for_prompt(orig if _fileop_depth > 0 else user_prompt)
    try:
        resolved = resolve_cursor_model(
            model or os.environ.get("HACKBOT_MODEL"),
            effort=effort,
            api_key=_api_key(),
            require_known=True,
        )
    except ValueError as exc:
        ui.error(str(exc))
        return str(exc)

    selection = build_model_selection(resolved)
    mode = _cursor_mode()
    tools_on = cursor_tools_enabled() and not chat_mode
    packs = resolve_packs(user_prompt) if tools_on else []
    pack_label = ",".join(packs) if packs else "off"
    custom_tools = build_cursor_custom_tools(user_prompt) if tools_on else {}
    set_cursor_approve_fn(approve_fn)
    ui.info(
        f"cursor  requested={resolved.display()}  mode={mode}  "
        f"catalog={resolved.source}  tools={len(custom_tools)} ({pack_label})"
    )
    try:
        from .capabilities import collect_capabilities, compact_line

        ui.info(compact_line(collect_capabilities(prompt=user_prompt)))
    except Exception:  # noqa: BLE001
        pass

    prompt = _build_prompt(
        user_prompt,
        chat_mode=chat_mode,
        tools_on=bool(custom_tools),
        pack_label=pack_label,
        tool_count=len(custom_tools),
    )
    started = time.perf_counter()
    tool_fp = cursor_tools_fingerprint(user_prompt if tools_on else "")

    agent_fp = f"{resolved.fingerprint()}|{tool_fp}"
    try:
        agent = _ensure_agent(selection, agent_fp, custom_tools=custom_tools)
        answer, used_label = _run_send(agent, prompt, selection=selection)
    except KeyboardInterrupt:
        ui.warn("cancelled")
        ui.turn_timing(time.perf_counter() - started, 0)
        return "(cancelled)"
    except Exception as exc:
        name = type(exc).__name__
        err = str(exc)
        if _is_bridge_dead(exc):
            close_cursor_agent()
            msg = (
                "cursor bridge died (Connection refused). "
                "Usually happens if Approve y/n took too long. "
                "Fix: /clear  then resend the task; answer y/n promptly. "
                f"Detail: {exc}"
            )
        elif name == "CursorAgentError" or "CursorAgent" in name:
            msg = f"cursor startup failed: {exc}"
        elif "10038" in err or "não é um soquete" in err or "not a socket" in err.lower():
            close_cursor_agent()
            msg = (
                "cursor bridge failed on Windows (WinError 10038). "
                "Update hackbot (cursor_bridge_win patch) and /exit then restart the REPL. "
                f"Detail: {exc}"
            )
        else:
            msg = f"cursor error: {name}: {exc}"
        ui.error(msg)
        ui.markdown_panel(msg, title="hackbot (cursor)")
        ui.turn_timing(time.perf_counter() - started, 0)
        return msg
    finally:
        set_cursor_approve_fn(None)

    set_last_resolved_label(used_label)
    ui.success(f"used model  {used_label}")

    ops: list[dict[str, Any]] = []
    if allow_file_ops:
        answer, ops = _extract_fileops(answer)

    ui.markdown_panel(answer, title=f"hackbot (cursor · {used_label})")
    applied: list[dict[str, Any]] = []
    if ops:
        applied = _apply_fileops(ops, approve_fn, source="cursor")

    if (
        allow_file_ops
        and _should_continue_after_fileops(applied, answer=answer)
        and _fileop_depth < _MAX_FILEOP_CONTINUES
    ):
        ui.info("file ops applied; continuing cursor (don't re-ask me)")
        cont = run_cursor_turn(
            _fileop_continue_prompt(orig, applied),
            model=model,
            approve_fn=approve_fn,
            allow_file_ops=allow_file_ops,
            _fileop_depth=_fileop_depth + 1,
            _orig_user_prompt=orig,
        )
        combined = "\n\n".join(p for p in (answer, cont) if (p or "").strip()).strip()
        ui.turn_timing(time.perf_counter() - started, len(ops))
        return combined or answer
    if applied and not _should_continue_after_fileops(applied, answer=answer):
        ui.info("file ops done; turn complete (not auto-continuing)")

    ui.turn_timing(time.perf_counter() - started, len(ops))
    return answer
