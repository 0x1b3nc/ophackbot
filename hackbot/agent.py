"""Agent loop: user prompt -> LLM thinks -> tools -> answer."""

from __future__ import annotations

import json
import time
from typing import Any, Callable

from . import ui
from .intent import is_chat_prompt, resolve_effort_for_prompt
from .llm import LLMError, chat, detect_provider, streaming_enabled
from .tools import TOOL_SPECS, execute_tool

ApproveFn = Callable[[str], bool]

SYSTEM_HUNT = """You are Hackbot, my authorized bug-bounty / lab agent CLI.

You help with authorized security research only: bug bounty programs, my labs,
CTFs, contracted pentests, education. Never attack systems without authorization.

Before plans, severity, reports, or next hunting steps:
1. Read docs/OPERATING_RULES.md (via read_file) when relevant
2. Use open_knowledge for the bug class
3. Read targets/<program>/SCOPE.md, PLAN.md, FINDINGS.md, RESUME.md
4. If not confirmed locally, say it is inference

Always prefer:
- falsifiable hypothesis
- concrete target/endpoint
- aggression level 0-3 with a policy quote
- dry-run tools first (run_tool approve=false)
- ask for approve=true only after scope is IN_SCOPE and you showed the command

Filesystem: you CAN create, write, edit, append, move, and delete files
(write_file, edit_file, append_file, make_dir, move_path, delete_path). Use them
whenever it helps. The operator is ALWAYS asked to approve before each change.
If denied, respect it and adjust.

Use tools instead of guessing file contents. Keep answers short, technical, first
person as my agent. When done with tools, give a clear final answer.
"""

SYSTEM_CHAT = """You are Hackbot, a short, friendly authorized bounty/lab CLI agent.
Answer briefly in first person. Do not call tools. Do not invent scope findings.
If they ask for hunting work, say you'll need a concrete task (host, target folder,
or bug class) and keep it short.
"""

# Keep history from ballooning across long sessions.
_MAX_HISTORY_MSGS = 24
_MAX_TOOL_RESULT_CHARS = 2500


def _trim_history(messages: list[dict[str, Any]]) -> None:
    """Mutate messages: cap length and shrink fat tool results."""
    for msg in messages:
        if msg.get("role") == "tool" and isinstance(msg.get("content"), str):
            content = msg["content"]
            if len(content) > _MAX_TOOL_RESULT_CHARS:
                msg["content"] = content[:_MAX_TOOL_RESULT_CHARS] + "...(truncated)"
    if len(messages) > _MAX_HISTORY_MSGS:
        # Keep the newest messages; prefer dropping older user/assistant pairs.
        del messages[: len(messages) - _MAX_HISTORY_MSGS]


def _verbose() -> bool:
    import os

    return os.environ.get("HACKBOT_VERBOSE", "").strip().lower() in {"1", "true", "yes", "on"}


def run_agent(
    user_prompt: str,
    *,
    history: list[dict[str, Any]] | None = None,
    approve_fn: ApproveFn | None = None,
    max_rounds: int | None = None,
) -> list[dict[str, Any]]:
    """
    Run one user turn (possibly multi tool-round). Mutates and returns history.
    """
    messages = history if history is not None else []
    messages.append({"role": "user", "content": user_prompt})
    _trim_history(messages)

    chat_mode = is_chat_prompt(user_prompt)
    effort = resolve_effort_for_prompt(user_prompt)
    rounds = 1 if chat_mode else (max_rounds if max_rounds is not None else 8)
    system = SYSTEM_CHAT if chat_mode else SYSTEM_HUNT
    tools = [] if chat_mode else TOOL_SPECS

    provider, model = detect_provider()
    ui.info(f"model {provider}:{model}  effort={effort or '-'}  mode={'chat' if chat_mode else 'hunt'}")

    started = time.perf_counter()
    tools_used = 0

    try:
        for _ in range(rounds):
            response = _one_llm_call(system, messages, tools, effort)
            if response is None:
                _trim_history(messages)
                ui.turn_timing(time.perf_counter() - started, tools_used)
                return messages

            if not response.tool_calls:
                messages.append({"role": "assistant", "content": response.text})
                _trim_history(messages)
                ui.turn_timing(time.perf_counter() - started, tools_used)
                return messages

            messages.append(
                {
                    "role": "assistant",
                    "content": response.text,
                    "tool_calls": [
                        {
                            "id": tc.id,
                            "name": tc.name,
                            "arguments": tc.arguments,
                        }
                        for tc in response.tool_calls
                    ],
                }
            )

            for tc in response.tool_calls:
                tools_used += 1
                if _verbose():
                    ui.kv("tool", tc.name)
                    ui.code_panel(json.dumps(tc.arguments, indent=2), title="args", lexer="json")
                else:
                    ui.tool_line(tc.name, "running")
                result = execute_tool(tc.name, tc.arguments, approve_fn=approve_fn)
                ok = True
                try:
                    parsed = json.loads(result)
                    ok = bool(parsed.get("ok", True)) if isinstance(parsed, dict) else True
                    if isinstance(parsed, dict) and parsed.get("ok") is False:
                        ok = False
                except json.JSONDecodeError:
                    pass
                if _verbose():
                    preview = result if len(result) < 1200 else result[:1200] + "...(truncated)"
                    ui.code_panel(preview, title="result", lexer="json")
                else:
                    ui.tool_line(tc.name, "ok" if ok else "fail")
                messages.append(
                    {
                        "role": "tool",
                        "tool_call_id": tc.id,
                        "name": tc.name,
                        "content": result,
                    }
                )

        ui.warn("hit max tool rounds; stopping this turn")
    except KeyboardInterrupt:
        ui.warn("cancelled")
        if messages and messages[-1].get("role") == "user":
            messages.pop()
    finally:
        _trim_history(messages)

    ui.turn_timing(time.perf_counter() - started, tools_used)
    return messages


def _one_llm_call(
    system: str,
    messages: list[dict[str, Any]],
    tools: list[dict[str, Any]],
    effort: str | None,
):
    if streaming_enabled():
        try:
            with ui.Stream(title="hackbot") as stream:
                response = chat(
                    system=system,
                    messages=messages,
                    tools=tools,
                    effort=effort,
                    on_reasoning=stream.reasoning,
                    on_text=stream.answer,
                )
                streamed = stream.answer_text()
        except LLMError as exc:
            ui.error(str(exc))
            return None
        if response.text and not streamed:
            ui.markdown_panel(response.text, title="hackbot")
        return response

    with ui.console.status("[cyan]thinking...[/]", spinner="dots"):
        try:
            response = chat(
                system=system,
                messages=messages,
                tools=tools,
                effort=effort,
            )
        except LLMError as exc:
            ui.error(str(exc))
            return None
    if response.text:
        ui.markdown_panel(response.text, title="hackbot")
    return response
