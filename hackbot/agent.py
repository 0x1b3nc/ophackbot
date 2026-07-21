"""Agent loop: user prompt -> LLM thinks -> tools -> answer."""

from __future__ import annotations

import json
import time
from typing import Any, Callable

from . import ui
from .codex_backend import (
    _MAX_FILEOP_CONTINUES,
    _fileop_continue_prompt,
    _should_continue_after_fileops,
    file_mutation_result,
)
from .intent import is_chat_prompt, resolve_effort_for_prompt
from .llm import LLMError, chat, detect_provider, streaming_enabled
from .session import get_active
from .tools import TOOL_SPECS, execute_tool
from .tool_packs import filter_tool_specs, resolve_packs

ApproveFn = Callable[[str], bool]

SYSTEM_HUNT = """You are Hackbot, my authorized bug-bounty / lab agent CLI.

You help with authorized security research only: bug bounty programs, my labs,
CTFs, contracted pentests, education. Never attack systems without authorization.

CRITICAL UX — natural language first:
- The operator should NOT need slash commands. `/hunt`, `/session`, `/target` are
  optional shortcuts only.
- If they say credentials/tokens are in file X or folder Y: call
  `load_sessions_from_file` (or `read_file` then `set_session`). Do not tell them
  to type `/session`.
- If they give a test email/password for account A/B (or say update accounts.yaml):
  call `set_account`. Do NOT ask them to edit YAML by hand.
- Login surface: `detect_login` (form/JSON/SSO). SSO or MFA → `needs_setup`; use
  `browser_capture_session` (headed; operator finishes IdP — never type IdP passwords)
  or `set_session`, then `run_hunt` with `resume=true`. After sessions: `session_smoke`.
- If they say "explora o que der" / "go hunt" / open-ended attack: call `run_hunt`
  (or `run_campaign` when they name specific classes). Do not tell them to type `/hunt`.
- If they name an image/screenshot: call `read_image`. After OCR, if they asked to
  update SCOPE/accounts/files from what is in the image, chain `write_file` /
  `edit_file` / `set_account` with approve — do not stop at OCR only.
- Extract / resume page content: `extract_page` (HTML text+links). SPA thin →
  `browser_navigate` + `browser_eval`.
- Browser: `browser_navigate` / `screenshot` / `cookies` / `storage` / `network` /
  `browser_with_session` / `browser_diff_sessions` (A vs B soft IDOR hint).
- Reports: `write_report_draft` with platform=generic (default) or bugcrowd/h1/intigriti/
  yeswehack/synack/immunefi — portable draft with severity/CVSS hints from bug class.
- `browser_diff_sessions` soft IDOR hints auto-promote candidate → validator (verdict=likely).
- Mobile: `mobile_status`, `adb_devices`, `inspect_apk`, `mobile_bridge` (APK+HAR→hunt).
- Burp: `import_burp_xml` / `import_har`; `burp_rest_health`; `burp_replay` /
  `burp_replay_history` for local control-plane send (REST/MCP/fallback).

- After findings: `build_chains`. Cross-program memory: `learn_suggest` / `learn_record`.
- If they name a HAR / Burp export: call `import_har` / `import_burp_xml`.
- If they name a JS bundle: call `analyze_js`.
- If they paste a JWT: call `analyze_jwt`.
- If they ask for subdomains: `crt_subdomains`. Historical URLs: `wayback_urls`.
- GraphQL / CORS / open redirect / SSRF / race / websocket / param mining / headers:
  use the matching probe tools.
- IDOR A/B ownership: prefer `idor_probe` (systematic) over manual http_request+assert_diff.
- Content discovery: `discover_paths` seeds surface early in hunt.
- Blind/OOB: prefer `HACKBOT_INTERACTSH=1` (`interactsh_register` / `interactsh_poll`);
  legacy `HACKBOT_OOB_BASE` + `oob_mint` / `oob_poll`. SSRF/XSS/XXE auto-mint+poll.
- Cookie jar: `http_request` persists Set-Cookie under secrets/cookie_jar.json across acts.
- Mobile deep: `mobsf_*`, `frida_run_script` / `objection_explore` (approve-gated allowlisted scripts).
- CDP extras: `browser_console`, `browser_set_cookie`.
- If they name a target folder: `set_target`. If they only name a host and a
  target is already active, use the active target.
- Folders: `list_dir` when they say "na pasta X".
- Tool surface is phase-filtered (`HACKBOT_TOOL_PACK=auto|all|core,recon,...`).

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
After SCOPE/setup file writes land, KEEP GOING on the original hunt task
(run_hunt / map_surface / dry-run probes). Do not stop idle waiting for the
operator to re-ask "now hunt".

Lab autonomy: if `/tools` / capabilities shows Burp down or Go/gau missing, call
`stack_prepare` and/or `burp_ensure` (and `lab_exec` with sudo when needed). Do not
ask the operator to open Burp by hand. Under YOLO, approve is automatic — keep hunting.
OUT_OF_SCOPE stays blocked.

Use tools instead of guessing file contents. Prefer open_playbook for a bug class
before inventing steps. Prefer set_target when the user names a program folder.
Keep answers short, technical, first person as my agent. When done with tools,
give a clear final answer.
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
    active = get_active()
    if active and not chat_mode:
        system = system + "\n\n## Active target session\n" + active.context_block()
    if chat_mode:
        tools = []
    else:
        packs = resolve_packs(user_prompt)
        tools = filter_tool_specs(TOOL_SPECS, packs)
        if packs != ["all"]:
            ui.info(f"tool packs: {','.join(packs)} ({len(tools)} tools)")

    provider, model = detect_provider()
    try:
        from .model_catalog import resolve_model

        canonical, src = resolve_model(provider, model)
        if canonical != model:
            import os

            os.environ["HACKBOT_MODEL"] = canonical
            model = canonical
        ui.info(f"model ok [{src}] {provider}:{model or '(default)'}")
    except ValueError as exc:
        ui.error(str(exc))
        ui.info("fix with: /models  then  /model <id>")
        messages.pop()  # drop the user turn we just appended
        return messages
    mode_label = "chat" if chat_mode else "hunt"
    ui.info(f"model {provider}:{model}  effort={effort or '-'}  mode={mode_label}")
    if active and not chat_mode:
        from .session import status_line

        ui.info(status_line())

    started = time.perf_counter()
    tools_used = 0
    pending_fileops: list[dict[str, Any]] = []
    fileop_continues = 0
    # Extra budget when we auto-nudge after approved file writes (all providers).
    max_iters = rounds + (_MAX_FILEOP_CONTINUES * 3 if not chat_mode else 0)

    try:
        for _ in range(max_iters):
            response = _one_llm_call(system, messages, tools, effort)
            if response is None:
                _trim_history(messages)
                ui.turn_timing(time.perf_counter() - started, tools_used)
                return messages

            if not response.tool_calls:
                messages.append({"role": "assistant", "content": response.text})
                # Same bug as Codex/Cursor fileop path: model writes SCOPE then
                # idles. Nudge one more hunt round after successful mutations.
                if (
                    not chat_mode
                    and _should_continue_after_fileops(pending_fileops)
                    and fileop_continues < _MAX_FILEOP_CONTINUES
                ):
                    ui.info("file ops applied; continuing model (don't re-ask me)")
                    messages.append(
                        {
                            "role": "user",
                            "content": _fileop_continue_prompt(
                                user_prompt, pending_fileops
                            ),
                        }
                    )
                    pending_fileops = []
                    fileop_continues += 1
                    continue
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

            round_fileops: list[dict[str, Any]] = []
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
                mut = file_mutation_result(tc.name, result)
                if mut is not None:
                    round_fileops.append(mut)
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
            if round_fileops:
                pending_fileops = round_fileops

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
