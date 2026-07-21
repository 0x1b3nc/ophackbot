"""In-process Cursor CustomTool bridge → hackbot ``execute_tool`` + approve.

Cursor SDK local agents accept ``LocalAgentOptions(custom_tools=…)``. We register
phase-filtered TOOL_SPECS so the Cursor brain can drive httpx/probes/fileops
under the same SCOPE / approve / caps rails as the HTTP agent — no MCP subprocess.
"""

from __future__ import annotations

import json
import os
from typing import Any, Callable

from .operator_gate import serialized_tool_call
from .tool_packs import filter_tool_specs, resolve_packs
from .tools import TOOL_SPECS, execute_tool

ApproveFn = Callable[[str], bool]

# Per-turn approve callback (agent is durable; tools close over this holder).
_APPROVE_HOLDER: dict[str, ApproveFn | None] = {"fn": None}

_MAX_TOOL_RESULT_CHARS = 6000


def set_cursor_approve_fn(fn: ApproveFn | None) -> None:
    _APPROVE_HOLDER["fn"] = fn


def cursor_tools_enabled() -> bool:
    raw = (os.environ.get("HACKBOT_CURSOR_TOOLS") or "1").strip().lower()
    return raw not in {"0", "false", "off", "no"}


def cursor_tools_fingerprint(prompt: str = "") -> str:
    if not cursor_tools_enabled():
        return "tools=off"
    packs = resolve_packs(prompt)
    return f"tools=on|packs={','.join(packs)}"


def _trim_result(raw: str) -> str:
    if len(raw) <= _MAX_TOOL_RESULT_CHARS:
        return raw
    return raw[:_MAX_TOOL_RESULT_CHARS] + "...(truncated)"


def _make_execute(tool_name: str) -> Callable[[Any, Any], str]:
    def _execute(arguments: Any, _context: Any = None) -> str:
        # One CustomTool at a time so permission prompts never overlap.
        with serialized_tool_call():
            args = dict(arguments or {}) if isinstance(arguments, dict) else {}
            try:
                result = execute_tool(
                    tool_name, args, approve_fn=_APPROVE_HOLDER.get("fn")
                )
            except Exception as exc:  # noqa: BLE001 — surface to Cursor as tool error
                return json.dumps(
                    {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
                )
            if isinstance(result, str):
                return _trim_result(result)
            try:
                return _trim_result(json.dumps(result, ensure_ascii=False, default=str))
            except (TypeError, ValueError):
                return _trim_result(str(result))

    return _execute


def build_cursor_custom_tools(prompt: str = "") -> dict[str, Any]:
    """Build ``{name: CustomTool}`` for Agent.create. Empty when tools disabled."""
    if not cursor_tools_enabled():
        return {}

    from cursor_sdk.types import CustomTool

    packs = resolve_packs(prompt)
    specs = filter_tool_specs(TOOL_SPECS, packs)
    out: dict[str, Any] = {}
    for spec in specs:
        name = str(spec.get("name") or "").strip()
        if not name or name in out:
            continue
        desc = str(spec.get("description") or name)
        schema = spec.get("parameters") or {"type": "object", "properties": {}}
        out[name] = CustomTool(
            execute=_make_execute(name),
            description=desc,
            input_schema=schema if isinstance(schema, dict) else {"type": "object"},
        )
    return out


def tools_preamble_block(*, enabled: bool, pack_label: str, tool_count: int) -> str:
    if not enabled:
        return (
            "\nHackbot tools: OFF for this Cursor session "
            "(HACKBOT_CURSOR_TOOLS=0). Propose commands; do not send live traffic yourself.\n"
        )
    return f"""
Hackbot custom tools are registered on this agent ({tool_count} tools, packs={pack_label}).
CALL them by name (http_request, map_surface, write_file, run_hunt, capabilities, …).
External recon CLIs: run_tool with tool=httpx|katana|nuclei|ffuf|reconftw|hexstrike
(after dry-run; approve=true only when IN_SCOPE). Call capabilities first to see
what binaries/HexStrike/Burp are actually up.
Do NOT use raw shell/curl for in-scope bounty traffic — use the hackbot tools so
SCOPE checks, redaction, caps, and operator approve apply.
Dry-run first (approve=false / omit approve). Only request approve=true after
scope is IN_SCOPE and you showed what will run.
Filesystem tools (write_file, edit_file, …) always ask the operator to approve.
After a file write is approved (SCOPE.md, accounts, notes), CONTINUE the original
hunt task in the same turn — call run_hunt / map_surface / probes next. Do not
stop and wait for the operator to say "now hunt" again.
"""
