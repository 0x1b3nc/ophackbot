"""Agent loop: user prompt -> LLM thinks -> tools -> answer."""

from __future__ import annotations

from typing import Any, Callable

from . import ui
from .llm import LLMError, chat, detect_provider, streaming_enabled
from .tools import TOOL_SPECS, execute_tool

ApproveFn = Callable[[str], bool]

SYSTEM = """You are Hackbot, my authorized bug-bounty / lab agent CLI.

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
whenever it helps (update PLAN.md, save notes, scaffold a target, fix a file).
The operator is ALWAYS asked to approve before each change actually happens, so
propose the concrete edit and let the tool handle the permission prompt. If an
action is denied, respect it and adjust.

Use tools instead of guessing file contents. Keep answers short, technical, first person as my agent ("I'll check scope..."). English is fine for technical content.
When you're done with tools, give a clear final answer to the user.
"""


def run_agent(
    user_prompt: str,
    *,
    history: list[dict[str, Any]] | None = None,
    approve_fn: ApproveFn | None = None,
    max_rounds: int = 8,
) -> list[dict[str, Any]]:
    """
    Run one user turn (possibly multi tool-round). Mutates and returns history.
    """
    messages = history if history is not None else []
    messages.append({"role": "user", "content": user_prompt})

    provider, model = detect_provider()
    ui.info(f"model {provider}:{model}")

    for _ in range(max_rounds):
        if streaming_enabled():
            try:
                with ui.Stream(title="hackbot") as stream:
                    response = chat(
                        system=SYSTEM,
                        messages=messages,
                        tools=TOOL_SPECS,
                        on_reasoning=stream.reasoning,
                        on_text=stream.answer,
                    )
                    streamed = stream.answer_text()
            except LLMError as exc:
                ui.error(str(exc))
                return messages
            if response.text and not streamed:
                ui.markdown_panel(response.text, title="hackbot")
        else:
            with ui.console.status("[cyan]thinking...[/]", spinner="dots"):
                try:
                    response = chat(system=SYSTEM, messages=messages, tools=TOOL_SPECS)
                except LLMError as exc:
                    ui.error(str(exc))
                    return messages
            if response.text:
                ui.markdown_panel(response.text, title="hackbot")

        if not response.tool_calls:
            messages.append({"role": "assistant", "content": response.text})
            return messages

        # Record assistant tool call turn
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

        # Keep one tool-result record per call for OpenAI; Anthropic converter
        # will fold consecutive tool roles into user/tool_result blocks.
        for tc in response.tool_calls:
            ui.kv("tool", tc.name)
            ui.code_panel(
                __import__("json").dumps(tc.arguments, indent=2),
                title="args",
                lexer="json",
            )
            result = execute_tool(tc.name, tc.arguments, approve_fn=approve_fn)
            preview = result if len(result) < 1200 else result[:1200] + "...(truncated)"
            ui.code_panel(preview, title="result", lexer="json")
            messages.append(
                {
                    "role": "tool",
                    "tool_call_id": tc.id,
                    "name": tc.name,
                    "content": result,
                }
            )

    ui.warn("hit max tool rounds; stopping this turn")
    return messages
