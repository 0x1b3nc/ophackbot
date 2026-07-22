"""Bridge to the OpenAI Codex CLI so hackbot can think using your ChatGPT plan.

Shells out to ``codex exec``. Sandbox is NOT stuck on read-only anymore:
hunt needs network + /tmp (httpx/curl). Default is workspace-write with
network; ``/yolo`` uses danger-full-access. Override with
``HACKBOT_CODEX_SANDBOX``. File writes for SCOPE etc. still prefer
``hackbot-fileop`` so the operator approve gate (or YOLO) applies.

Uses whatever auth `codex login` set up - typically your ChatGPT (Plus/Pro/
Business) subscription, so it spends plan quota instead of paid API credit.
"""

from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from typing import Any, Callable

from rich.text import Text as _Text

from . import ui
from .intent import is_chat_prompt, resolve_effort_for_prompt
from .llm import streaming_enabled
from .session import get_active

ApproveFn = Callable[[str], bool]

# Cache for `codex login status` (subprocess is slow).
_CODEX_AVAIL: tuple[float, bool] | None = None
_CODEX_AVAIL_TTL = 90.0
# After the first successful exec in this process, resume --last for speed.
_CODEX_SESSION_READY = False
_CODEX_LAST_SANDBOX: str | None = None
_CODEX_CANCEL = threading.Event()
_CODEX_PROC: subprocess.Popen[str] | None = None
_CODEX_PROC_LOCK = threading.Lock()

_SANDBOX_OK = frozenset({"read-only", "workspace-write", "danger-full-access"})


def request_codex_cancel() -> None:
    """Kill in-flight ``codex exec`` (operator interrupt / queued message)."""
    global _CODEX_PROC
    _CODEX_CANCEL.set()
    with _CODEX_PROC_LOCK:
        proc = _CODEX_PROC
    if proc is not None and proc.poll() is None:
        try:
            proc.kill()
        except OSError:
            pass


def clear_codex_cancel() -> None:
    _CODEX_CANCEL.clear()


def codex_cancel_requested() -> bool:
    if _CODEX_CANCEL.is_set():
        return True
    try:
        from .turn_bus import turn_cancel_requested

        return turn_cancel_requested()
    except Exception:  # noqa: BLE001
        return False


def ui_text(text: str, style: str) -> _Text:
    return _Text(text, style=style)


def codex_sandbox_mode() -> str:
    """Pick Codex OS sandbox. read-only breaks live hunt (no net, no /tmp)."""
    raw = (os.environ.get("HACKBOT_CODEX_SANDBOX") or "").strip().lower()
    if raw in _SANDBOX_OK:
        return raw
    try:
        from .yolo import is_yolo

        if is_yolo():
            return "danger-full-access"
    except Exception:  # noqa: BLE001
        pass
    # Default: write workspace + /tmp, and enable network (see cmd builder).
    return "workspace-write"


# Prefer hackbot-fileop for disk mutations (approve/YOLO audit). Shell may have
# network depending on sandbox — do not claim "read-only forever".
_FILEOP_RE = re.compile(r"```hackbot-fileop\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_TOOL_RE = re.compile(r"```hackbot-tool\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)
_MAX_TOOL_CONTINUES = 2
_MAX_TOOL_CONTINUES_FULL = 16
_MAX_TOOL_RESULT_CHARS = 6000


def _tool_continue_budget() -> int:
    """How many tool→continue rounds in one operator turn."""
    try:
        from .step_mode import step_mode_enabled

        if not step_mode_enabled():
            return _MAX_TOOL_CONTINUES_FULL
    except Exception:  # noqa: BLE001
        pass
    return _MAX_TOOL_CONTINUES

_FILEOP_ALIASES = {
    "write": "write_file", "write_file": "write_file", "create": "write_file", "overwrite": "write_file",
    "append": "append_file", "append_file": "append_file",
    "edit": "edit_file", "edit_file": "edit_file", "replace": "edit_file",
    "delete": "delete_path", "delete_path": "delete_path", "remove": "delete_path", "rm": "delete_path",
    "mkdir": "make_dir", "make_dir": "make_dir", "makedir": "make_dir",
    "move": "move_path", "move_path": "move_path", "rename": "move_path", "mv": "move_path",
}

# Shared with HTTP model agent + Cursor: tools that mutate disk via approve.
FILE_MUTATION_TOOLS = frozenset(
    {
        "write_file",
        "append_file",
        "edit_file",
        "delete_path",
        "make_dir",
        "move_path",
    }
)


def _extract_fileops(answer: str) -> tuple[str, list[dict[str, Any]]]:
    """Pull ```hackbot-fileop``` JSON blocks out of codex's answer.

    Returns (answer_without_blocks, ops)."""
    ops: list[dict[str, Any]] = []
    for match in _FILEOP_RE.finditer(answer):
        raw = match.group(1).strip()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        for item in data if isinstance(data, list) else [data]:
            if isinstance(item, dict):
                ops.append(item)
    cleaned = _FILEOP_RE.sub("", answer).strip()
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned, ops


def _normalize_op_args(tool: str, item: dict[str, Any]) -> dict[str, Any]:
    """Map a codex file-op directive onto hackbot tool arguments (forgiving)."""
    def pick(*keys: str) -> Any:
        for k in keys:
            if item.get(k) is not None:
                return item[k]
        return None

    if tool in {"write_file", "append_file"}:
        return {"path": pick("path", "file"), "content": pick("content", "text", "body") or ""}
    if tool == "edit_file":
        return {
            "path": pick("path", "file"),
            "old_string": pick("old_string", "old", "find", "search") or "",
            "new_string": pick("new_string", "new", "replace", "replacement") or "",
            "replace_all": bool(item.get("replace_all")),
        }
    if tool in {"delete_path", "make_dir"}:
        return {"path": pick("path", "file", "dir")}
    if tool == "move_path":
        return {"src": pick("src", "from", "source"), "dst": pick("dst", "to", "dest", "target")}
    return {k: v for k, v in item.items() if k != "op"}


def _apply_fileops(
    ops: list[dict[str, Any]],
    approve_fn: ApproveFn | None,
    *,
    source: str = "codex",
) -> list[dict[str, Any]]:
    """Execute proposed file ops through hackbot's approve-gated tools.

    Returns one result dict per op: tool, path, ok, error (optional).
    """
    from . import tools  # local import avoids any import cycle

    applied: list[dict[str, Any]] = []
    ui.console.print(ui_text(f"{source} proposes {len(ops)} file change(s):", "hb.label"))
    for item in ops:
        op = str(item.get("op", "")).strip().lower()
        tool = _FILEOP_ALIASES.get(op)
        if tool is None:
            ui.error(f"unknown file op {op!r} - skipped")
            applied.append({"tool": op or "?", "path": "", "ok": False, "error": "unknown op"})
            continue
        args = _normalize_op_args(tool, item)
        result = tools.execute_tool(tool, args, approve_fn=approve_fn)
        try:
            parsed = json.loads(result)
        except json.JSONDecodeError:
            parsed = {"ok": False, "error": result}
        where = parsed.get("path") or parsed.get("to") or parsed.get("deleted") or args.get("path") or ""
        if parsed.get("ok"):
            ui.success(f"{tool}  {where}")
            applied.append({"tool": tool, "path": where, "ok": True})
        else:
            err = parsed.get("error", "failed")
            ui.error(f"{tool}: {err}")
            applied.append({"tool": tool, "path": where, "ok": False, "error": err})
    return applied


def _fileop_continue_prompt(
    user_prompt: str, applied: list[dict[str, Any]]
) -> str:
    """Tell the brain file ops landed so it can keep working (don't stop after write)."""
    lines = []
    for row in applied:
        mark = "ok" if row.get("ok") else f"FAILED ({row.get('error') or 'denied'})"
        lines.append(f"- {row.get('tool')} {row.get('path') or ''} → {mark}")
    body = "\n".join(lines) if lines else "- (none)"
    return (
        "Hackbot applied your file-op proposal(s) (operator approve gate):\n"
        f"{body}\n\n"
        "Continue the user's ORIGINAL task only if setup is still incomplete "
        "(e.g. SCOPE just created and hunt not started).\n"
        "If you already have a reportable finding / submission draft / stop criteria, "
        "do NOT invent more dry-runs. Give a short final summary + one next-step "
        "suggestion, then STOP and wait for the operator.\n"
        "Do NOT re-emit the same file-op.\n"
        f"Original task: {user_prompt.strip()}"
    )


def _known_tool_names() -> frozenset[str]:
    from . import tools

    return frozenset(str(spec.get("name") or "") for spec in tools.TOOL_SPECS if spec.get("name"))


def _extract_tool_calls(answer: str) -> tuple[str, list[dict[str, Any]]]:
    """Pull ```hackbot-tool``` JSON blocks out of the answer."""
    calls: list[dict[str, Any]] = []
    for match in _TOOL_RE.finditer(answer):
        raw = match.group(1).strip()
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        for item in data if isinstance(data, list) else [data]:
            if isinstance(item, dict):
                calls.append(item)
    cleaned = _TOOL_RE.sub("", answer).strip()
    cleaned = re.sub(r"\n{3,}", "\n\n", cleaned)
    return cleaned, calls


def _tool_needs_target_dir(name: str) -> bool:
    from . import tools

    for spec in tools.TOOL_SPECS:
        if spec.get("name") != name:
            continue
        props = (spec.get("parameters") or {}).get("properties") or {}
        required = (spec.get("parameters") or {}).get("required") or []
        return "target_dir" in props or "target_dir" in required
    return False


def _normalize_tool_call(
    item: dict[str, Any],
    *,
    default_prompt: str = "",
) -> tuple[str, dict[str, Any]]:
    name = str(
        item.get("tool") or item.get("name") or item.get("op") or ""
    ).strip()
    args = item.get("args") if isinstance(item.get("args"), dict) else None
    if args is None:
        args = item.get("arguments") if isinstance(item.get("arguments"), dict) else None
    if args is None:
        args = {
            k: v
            for k, v in item.items()
            if k not in {"tool", "name", "op", "args", "arguments"}
        }
    else:
        args = dict(args)
    if name and _tool_needs_target_dir(name) and not args.get("target_dir"):
        active = get_active()
        if active is not None:
            args["target_dir"] = str(active.target_dir)
    if name == "run_hunt" and not str(args.get("prompt") or "").strip() and default_prompt:
        args["prompt"] = default_prompt.strip()
    return name, args


def _apply_tool_calls(
    calls: list[dict[str, Any]],
    approve_fn: ApproveFn | None,
    *,
    source: str = "codex",
    default_prompt: str = "",
) -> list[dict[str, Any]]:
    """Execute ```hackbot-tool``` proposals through hackbot's gated tools."""
    from . import tools

    known = _known_tool_names()
    applied: list[dict[str, Any]] = []
    ui.console.print(ui_text(f"{source} proposes {len(calls)} tool call(s):", "hb.label"))
    for item in calls:
        name, args = _normalize_tool_call(item, default_prompt=default_prompt)
        if not name or name not in known:
            ui.error(f"unknown tool {name!r} - skipped")
            applied.append(
                {
                    "tool": name or "?",
                    "ok": False,
                    "error": "unknown tool",
                    "result": "",
                }
            )
            continue
        bits = [name]
        if args.get("method"):
            bits.append(str(args.get("method")).upper())
        if args.get("url"):
            bits.append(str(args.get("url")))
        elif args.get("host"):
            bits.append(str(args.get("host")))
        # Same visual language as Codex shell runs.
        ui.activity("run", "hackbot " + " ".join(bits), style="hb.cmd")
        result = tools.execute_tool(name, args, approve_fn=approve_fn)
        try:
            parsed = json.loads(result)
            ok = bool(parsed.get("ok", True)) if isinstance(parsed, dict) else True
            err = parsed.get("error") if isinstance(parsed, dict) else None
        except json.JSONDecodeError:
            parsed = None
            ok = not result.startswith("(")
            err = None if ok else result[:200]
        clipped = result if len(result) <= _MAX_TOOL_RESULT_CHARS else (
            result[: _MAX_TOOL_RESULT_CHARS - 1] + "…"
        )
        ui.activity(
            "out/ok" if ok else "out/fail",
            clipped if ok else (str(err) if err else clipped),
            style="hb.ok" if ok else "hb.warn",
        )
        applied.append(
            {
                "tool": name,
                "ok": ok,
                "error": err,
                "result": clipped,
                "args": {k: args.get(k) for k in ("url", "method", "host", "path", "target_dir") if k in args},
            }
        )
    return applied


def _tool_continue_prompt(
    user_prompt: str, applied: list[dict[str, Any]]
) -> str:
    from .step_mode import step_mode_enabled

    if step_mode_enabled():
        instructions = [
            "Hackbot executed your hackbot-tool call(s). Results follow.",
            "Write 2–5 lines on what the result means (no raw dump re-paste).",
            "Then ONE next step suggestion and STOP for the operator.",
            "Do NOT claim tools are missing. Emit another hackbot-tool only if one "
            "more step is truly required this turn.",
        ]
    else:
        instructions = [
            "Hackbot executed your hackbot-tool call(s). Results follow.",
            "FULL HUNT MODE is ON — do NOT stop to ask the operator to continue.",
            "First: 2–5 lines on what THIS result means (no raw body re-paste).",
            "Then immediately emit the NEXT hackbot-tool call(s) to keep hunting.",
            "Only STOP with ## Done / ## Evidence / ## Next steps when you have: a "
            "finding candidate, a hard blocker (needs_setup/MFA/OOS), or it is no "
            "longer worth continuing (budget/dead ends).",
            "If a result includes saved_body / saved_path, use read_file on that "
            "path for the full JS/body — do not assume body_preview is complete.",
            "http_request results include a headers object — use it for Server/"
            "tech disclosure; do not invent that headers were missing.",
            "Do NOT claim tools are missing.",
        ]
    chunks: list[str] = [*instructions, ""]
    for i, row in enumerate(applied, 1):
        mark = "ok" if row.get("ok") else f"FAILED ({row.get('error') or 'error'})"
        chunks.append(f"### tool {i}: {row.get('tool')} → {mark}")
        if row.get("args"):
            chunks.append(f"args: {json.dumps(row.get('args'), ensure_ascii=False)}")
        chunks.append("result:")
        chunks.append(str(row.get("result") or ""))
        chunks.append("")
    chunks.append(f"Original task: {user_prompt.strip()}")
    return "\n".join(chunks)


_SHELL_HTTP_RE = re.compile(
    r"(?i)\b(?:curl|wget|httpx|httpie)\b.*\bhttps?://[^\s\"']+",
)


def _shell_http_urls(command: str) -> list[str]:
    """Extract http(s) URLs from a shell probe command (curl/wget/httpx)."""
    text = command or ""
    if not _SHELL_HTTP_RE.search(text) and not re.search(
        r"(?i)\b(?:curl|wget|httpx)\b", text
    ):
        return []
    return re.findall(r"https?://[^\s\"'\\]+", text)


def _curl_bypass_nudge(user_prompt: str, urls: list[str]) -> str:
    uniq = []
    for u in urls:
        if u not in uniq:
            uniq.append(u)
    listed = "\n".join(f"- {u}" for u in uniq[:8]) or "- (url from your curl)"
    return (
        "STOP. You used raw shell curl/wget/httpx against a target. That bypasses "
        "Hackbot SCOPE/approve/redaction.\n"
        "Re-do the SAME request now with ONE hackbot-tool block using http_request "
        "(approve=true). Do NOT use shell curl for this.\n"
        f"URLs you hit:\n{listed}\n\n"
        "Example:\n"
        "```hackbot-tool\n"
        '{"tool": "http_request", "args": {"url": "'
        + (uniq[0] if uniq else "https://example.com/")
        + '", "method": "GET", "approve": true}}\n'
        "```\n"
        f"Original task: {user_prompt.strip()}"
    )


_SETUP_BASENAMES = frozenset(
    {
        "scope.md",
        "accounts.yaml",
        "accounts.yml",
        "sessions.yaml",
        "sessions.yml",
    }
)


def _is_setup_fileop(applied: list[dict[str, Any]]) -> bool:
    """Only program-setup writes (SCOPE/accounts/sessions) may auto-continue the hunt.

    Everything else (RESUME, FINDINGS, reports, random edits) ends the turn.
    No phrase-matching — allowlist only, so we cannot loop on unknown cases.
    """
    ok_rows = [r for r in applied if r.get("ok")]
    if not ok_rows:
        return False
    saw_setup_write = False
    for row in ok_rows:
        tool = str(row.get("tool") or "")
        path = str(row.get("path") or "").replace("\\", "/")
        base = path.rsplit("/", 1)[-1].lower()
        if tool == "make_dir" and "/targets/" in f"/{path.lower()}/":
            continue
        if tool == "write_file" and base in _SETUP_BASENAMES:
            saw_setup_write = True
            continue
        return False
    return saw_setup_write


def _should_continue_after_fileops(
    applied: list[dict[str, Any]],
    *,
    answer: str = "",
) -> bool:
    """Auto-continue ONLY after setup file creates — default is stop."""
    del answer  # unused; keep kw for call-site compat
    if not applied or not any(row.get("ok") for row in applied):
        return False
    # Default OFF: one step then wait. Opt-in with HACKBOT_FILEOP_CONTINUE=1
    # (still allowlist-only: SCOPE/accounts/sessions writes).
    flag = os.environ.get("HACKBOT_FILEOP_CONTINUE", "0").strip().lower()
    if flag in {"0", "false", "off", "no"}:
        return False
    return _is_setup_fileop(applied)


def file_mutation_result(tool: str, result_json: str) -> dict[str, Any] | None:
    """If tool is a disk mutation, return {tool, path, ok, error?} for continue logic."""
    if tool not in FILE_MUTATION_TOOLS:
        return None
    try:
        parsed = json.loads(result_json)
    except json.JSONDecodeError:
        return {"tool": tool, "path": "", "ok": False, "error": "bad json"}
    if not isinstance(parsed, dict):
        return {"tool": tool, "path": "", "ok": False, "error": "bad result"}
    where = parsed.get("path") or parsed.get("to") or parsed.get("deleted") or ""
    if parsed.get("ok"):
        return {"tool": tool, "path": where, "ok": True}
    return {
        "tool": tool,
        "path": where,
        "ok": False,
        "error": parsed.get("error") or "failed",
    }


ROOT = Path(__file__).resolve().parents[1]

_TOOL_RULES = """
TOOLS — you HAVE them. Do NOT invent "http_request unavailable".

For ANY HTTP(S) against the active/in-scope target, you MUST emit a hackbot-tool
block with http_request (or idor_probe / map_surface / etc). Do NOT use shell
curl/wget/httpx against bounty targets — that skips SCOPE/approve/redaction.

```hackbot-tool
{"tool": "http_request", "args": {"url": "https://example.com/api/", "method": "GET", "approve": true}}
```

Hackbot runs the block and feeds you the result (status, headers with secrets
redacted, body_preview, optional saved_body). HEAD returns headers even with an
empty body — do not claim headers were omitted. target_dir is auto-filled when a
target is active.

Common tools: http_request, map_surface, scope_check, capabilities, run_tool,
wayback_urls, crt_subdomains, burp_ensure, stack_prepare, lab_exec, run_hunt,
set_session, detect_login, idor_probe, extract_page, read_file, list_dir.

Shell is ONLY for local lab (PATH, apt, reading local files, burp on localhost).
NEVER claim "network: restricted" unless a command in THIS turn failed that way.
"""

_FILEOP_RULES = """
Files: for SCOPE/accounts/notes, emit ONE fenced hackbot-fileop block; Hackbot
applies it (kit, home, Downloads, Desktop) after approve (auto under YOLO).
Downloads/Desktop ARE allowed — never say you can only write inside the kit.

```hackbot-fileop
{"op": "write_file", "path": "C:/Users/me/Downloads/teste.md", "content": "# teste\\n"}
```

Ops: write_file, append_file, edit_file, delete_path, make_dir, move_path.
"""

_SESSION_RULES = _TOOL_RULES + "\n" + _FILEOP_RULES

PREAMBLE_CHAT = """You are Hackbot, a short friendly authorized bounty/lab CLI agent.
Answer briefly in first person.
Greetings/thanks only: no tools, no shell.
If they ask to fetch/probe/hunt/do something: emit hackbot-tool (http_request for
HTTP). Never invent a "no tools" limitation. Never curl in-scope targets.
""" + _SESSION_RULES + """
Task:
"""

PREAMBLE_HUNT = """You are Hackbot, my authorized bug-bounty / lab agent in this repo.

Hard rules:
- Authorized research only. Never attack unauthorized hosts.
- Read local context only when the task needs it (SCOPE.md, notes). Skip for small talk.
- Host is IN SCOPE only if it is in that program's SCOPE.md.
- For hunt steps: falsifiable hypothesis, endpoint, aggression 0-3, policy quote,
  ```hackbot-tool``` call (http_request), expected evidence, stop criteria.
- Under YOLO, approve is automatic — still use hackbot-tool, not raw curl.
- Be concise, technical, first person.
- Lab: stack_prepare / burp_ensure / lab_exec via hackbot-tool.
- Do ONE meaningful step, then STOP with result + ONE next suggestion. Wait.
""" + _SESSION_RULES + """
Only emit a file-op block when a file change is actually needed.
After the step lands: short result + ONE next-step suggestion, then STOP.

Task:
"""


def codex_available(*, force: bool = False) -> bool:
    """True if the codex binary exists and reports a logged-in session (cached)."""
    global _CODEX_AVAIL
    now = time.monotonic()
    if not force and _CODEX_AVAIL is not None:
        ts, ok = _CODEX_AVAIL
        if now - ts < _CODEX_AVAIL_TTL:
            return ok
    if shutil.which("codex") is None:
        _CODEX_AVAIL = (now, False)
        return False
    try:
        proc = subprocess.run(
            ["codex", "login", "status"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=20,
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        _CODEX_AVAIL = (now, False)
        return False
    out = (proc.stdout + proc.stderr).lower()
    ok = proc.returncode == 0 and "logged in" in out
    _CODEX_AVAIL = (now, ok)
    return ok


def _file_create_hint(user_prompt: str) -> str:
    """If NL clearly asks to create a file, pin the absolute path for Codex."""
    try:
        from .local_agent import (
            _default_new_file_content,
            _parse_create_file_path,
            interpret,
        )
    except Exception:
        return ""
    if "write_file" not in interpret(user_prompt).intents:
        return ""
    path = _parse_create_file_path(user_prompt)
    if not path:
        return (
            "\nUser asked to create/edit a file. Emit a hackbot-fileop write_file "
            "block with an absolute path under Downloads/Desktop/home/kit. "
            "Do not refuse.\n"
        )
    content = _default_new_file_content(path)
    payload = json.dumps(
        {"op": "write_file", "path": path.replace("\\", "/"), "content": content},
        ensure_ascii=False,
    )
    return (
        f"\nFILE CREATE: emit exactly this block (path is correct), then a one-line ack:\n"
        f"```hackbot-fileop\n{payload}\n```\n"
    )


def _try_direct_file_create(
    user_prompt: str, approve_fn: ApproveFn | None
) -> str | None:
    """Skip Codex for clear create-file NL — deterministic + no sandbox confusion."""
    try:
        from .local_agent import (
            _default_new_file_content,
            _parse_create_file_path,
            interpret,
        )
        from . import tools
    except Exception:
        return None
    if "write_file" not in interpret(user_prompt).intents:
        return None
    path = _parse_create_file_path(user_prompt)
    if not path:
        return None
    content = _default_new_file_content(path)
    ui.info("file create → write_file (model skipped; approve still required)")
    result = tools.execute_tool(
        "write_file",
        {"path": path, "content": content},
        approve_fn=approve_fn,
    )
    try:
        parsed = json.loads(result)
    except json.JSONDecodeError:
        parsed = {"ok": False, "error": result}
    if parsed.get("ok"):
        msg = f"Criei `{parsed.get('path', path)}`."
        ui.success(msg)
        return msg
    err = parsed.get("error") or "failed"
    if parsed.get("kind") == "denied":
        msg = "Ok — não gravei (approve recusado)."
        ui.warn(msg)
        return msg
    msg = f"Não consegui criar o arquivo: {err}"
    ui.error(msg)
    return msg


def _build_prompt(
    user_prompt: str,
    history: list[tuple[str, str]] | None,
    *,
    chat_mode: bool,
    resume: bool,
) -> str:
    hint = _file_create_hint(user_prompt)
    if resume and history:
        # Resume keeps session context but MUST restate tool/file rules — otherwise
        # Codex invents "no http_request" / "cannot run shell" / kit-only writes.
        recent = history[-4:]
        convo = "\n".join(f"{role}: {text}" for role, text in recent)
        return (
            "Continue.\n"
            + _SESSION_RULES
            + hint
            + f"\nRecent:\n{convo}\n\nUser: {user_prompt.strip()}\n"
        )
    preamble = PREAMBLE_CHAT if chat_mode else PREAMBLE_HUNT
    parts = [preamble, hint]
    if not chat_mode:
        from .step_mode import step_mode_preamble

        block = step_mode_preamble()
        if block:
            parts.append(block)
    if history and not chat_mode:
        recent = history[-4:]
        convo = "\n".join(f"{role}: {text}" for role, text in recent)
        parts.append("\nRecent conversation:\n" + convo + "\n")
    active = get_active()
    if active and not chat_mode:
        parts.append("\nActive target session:\n" + active.context_block() + "\n")
    parts.append("\n" + user_prompt.strip() + "\n")
    return "\n".join(parts)


_CODEX_EFFORT = {
    "minimal": "minimal",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "xhigh": "high",  # codex tops out at high
}


_MAX_FILEOP_CONTINUES = 2


def run_codex_turn(
    user_prompt: str,
    *,
    history: list[tuple[str, str]] | None = None,
    model: str | None = None,
    effort: str | None = None,
    timeout: int | None = None,
    approve_fn: ApproveFn | None = None,
    allow_file_ops: bool = True,
    _fileop_depth: int = 0,
    _orig_user_prompt: str | None = None,
) -> str:
    """Run one turn through ``codex exec`` and display the answer.

    Chat prompts use a light preamble (no file reads). Hunt prompts use the full
    preamble. Sandbox defaults to workspace-write+network (YOLO → danger-full-access).
    After the first successful turn in-process, later turns use
    ``codex exec resume --last`` when enabled (default on).

    After approved file-ops, automatically continues Codex so setup writes
    (SCOPE.md etc.) do not strand the hunt waiting for the user to re-ask.
    """
    global _CODEX_SESSION_READY, _CODEX_AVAIL, _CODEX_LAST_SANDBOX
    if codex_cancel_requested():
        ui.warn("cancelled")
        return "(cancelled)"
    orig = _orig_user_prompt if _orig_user_prompt is not None else user_prompt
    if allow_file_ops and _fileop_depth == 0:
        direct = _try_direct_file_create(user_prompt, approve_fn)
        if direct is not None:
            ui.turn_timing(0.0, 1)
            return direct
    raw_model = model if model is not None else os.environ.get("HACKBOT_MODEL")
    if raw_model and str(raw_model).strip():
        try:
            from .model_catalog import resolve_model

            canonical, src = resolve_model("codex", str(raw_model))
            model = canonical or None
            ui.info(f"codex model ok [{src}] {model or '(plan default)'}")
        except ValueError as exc:
            ui.error(str(exc))
            ui.info("fix with: /models  then  /model <id>")
            return str(exc)
    # Continuations after file-ops are always hunt work, even if the injector text
    # is short ("Continue…").
    chat_mode = False if _fileop_depth > 0 else is_chat_prompt(user_prompt)
    effort = effort if effort is not None else resolve_effort_for_prompt(
        orig if _fileop_depth > 0 else user_prompt
    )
    timeout = timeout if timeout is not None else (90 if chat_mode else 300)
    resume = (
        _CODEX_SESSION_READY
        and bool(history)
        and os.environ.get("HACKBOT_CODEX_RESUME", "1").strip().lower()
        not in {"0", "false", "off", "no"}
    )
    sandbox = codex_sandbox_mode()
    # Resume keeps the OLD session sandbox — if policy changed (e.g. /yolo on),
    # start fresh so network//tmp actually unlock.
    if resume and _CODEX_LAST_SANDBOX and _CODEX_LAST_SANDBOX != sandbox:
        resume = False
        _CODEX_SESSION_READY = False
        ui.warn(f"codex sandbox changed ({_CODEX_LAST_SANDBOX} → {sandbox}); fresh exec")

    prompt = _build_prompt(user_prompt, history, chat_mode=chat_mode, resume=resume)
    # Banner once per operator turn — not on every tool/fileop continue.
    if _fileop_depth == 0:
        ui.info(
            f"codex  effort={effort or '-'}  mode={'chat' if chat_mode else 'hunt'}"
            + f"  sandbox={sandbox}"
            + ("  resume" if resume else "")
        )
    else:
        ui.action_line("codex", f"continue · depth {_fileop_depth}")
    started = time.perf_counter()

    with tempfile.NamedTemporaryFile(
        "r", suffix=".txt", delete=False, encoding="utf-8"
    ) as handle:
        out_path = Path(handle.name)

    # Flags belong on `codex exec` before the `resume` subcommand.
    # Pass prompt via stdin (`-`) — Windows argv/NUL stdin caused
    # "Reading additional input from stdin..." / empty answers.
    cmd = [
        "codex",
        "exec",
        "--skip-git-repo-check",
        "--color",
        "never",
        "-C",
        str(ROOT),
        "-o",
        str(out_path),
        "--sandbox",
        sandbox,
    ]
    # workspace-write defaults to NO network — that is exactly the "curl blocked" bug.
    if sandbox == "workspace-write":
        cmd.extend(["-c", "sandbox_workspace_write.network_access=true"])
    if model and not resume:
        cmd.extend(["-m", model])
    if effort:
        level = _CODEX_EFFORT.get(effort)
        if level:
            cmd.extend(["-c", f'model_reasoning_effort="{level}"'])
    if streaming_enabled():
        cmd.append("--json")
    if resume:
        cmd.extend(["resume", "--last"])
    cmd.append("-")  # read PROMPT from stdin

    try:
        if streaming_enabled():
            captured = _run_streaming(cmd, prompt, timeout)
        else:
            captured = _run_quiet(cmd, prompt, timeout)
    except KeyboardInterrupt:
        out_path.unlink(missing_ok=True)
        ui.warn("cancelled")
        ui.turn_timing(time.perf_counter() - started, 0)
        return "(cancelled)"

    if captured is None:
        out_path.unlink(missing_ok=True)
        answer = "(codex failed to run)"
        ui.markdown_panel(answer, title="hackbot (codex)")
        ui.turn_timing(time.perf_counter() - started, 0)
        return answer
    stdout, error, stream_meta = captured
    if (error or "").strip() == "(cancelled)" or codex_cancel_requested():
        out_path.unlink(missing_ok=True)
        ui.warn("cancelled")
        ui.turn_timing(time.perf_counter() - started, 0)
        return "(cancelled)"

    answer = ""
    if out_path.exists():
        answer = out_path.read_text(encoding="utf-8", errors="replace").strip()
        out_path.unlink(missing_ok=True)

    if not answer:
        answer = (stdout or "").strip()
    if not answer:
        low = (error or "").lower()
        if "log in again" in low or ("token" in low and "401" in low):
            _CODEX_AVAIL = None
            answer = (
                "codex session expired. Run `codex login` (Sign in with ChatGPT), "
                "then try again."
            )
            ui.markdown_panel(answer, title="hackbot (codex)")
            ui.turn_timing(time.perf_counter() - started, 0)
            return answer
        # Empty / broken resume (common after a long approve wait) → fresh exec once.
        if resume:
            _CODEX_SESSION_READY = False
            ui.warn("codex resume empty/broken; retrying fresh exec")
            return run_codex_turn(
                user_prompt,
                history=history,
                model=model,
                effort=effort,
                timeout=timeout,
                approve_fn=approve_fn,
                allow_file_ops=allow_file_ops,
                _fileop_depth=_fileop_depth,
                _orig_user_prompt=orig,
            )
        answer = (error or "").strip() or "(codex produced no output)"

    ops: list[dict[str, Any]] = []
    tool_calls: list[dict[str, Any]] = []
    if allow_file_ops:
        answer, tool_calls = _extract_tool_calls(answer)
        answer, ops = _extract_fileops(answer)

    # Codex ignored the bridge and curled the target — force one redo via http_request.
    shell_http = list(stream_meta.get("shell_http") or [])
    if (
        allow_file_ops
        and not tool_calls
        and shell_http
        and _fileop_depth == 0
    ):
        if codex_cancel_requested():
            ui.warn("cancelled")
            return "(cancelled)"
        ui.warn("raw shell HTTP detected — forcing hackbot-tool http_request")
        hist = list(history or [])
        hist.append(("user", orig))
        hist.append(("hackbot", answer or "(shell probe)"))
        return run_codex_turn(
            _curl_bypass_nudge(orig, shell_http),
            history=hist,
            model=model,
            effort=effort,
            timeout=timeout,
            approve_fn=approve_fn,
            allow_file_ops=allow_file_ops,
            _fileop_depth=1,
            _orig_user_prompt=orig,
        )

    if codex_cancel_requested():
        ui.warn("cancelled")
        return "(cancelled)"

    ui.markdown_panel(answer, title="hackbot (codex)")
    applied_tools: list[dict[str, Any]] = []
    if tool_calls:
        applied_tools = _apply_tool_calls(
            tool_calls, approve_fn, default_prompt=orig
        )
    if codex_cancel_requested():
        ui.warn("cancelled")
        return "(cancelled)"
    applied: list[dict[str, Any]] = []
    if ops:
        applied = _apply_fileops(ops, approve_fn)
    if codex_cancel_requested():
        ui.warn("cancelled")
        return "(cancelled)"
    _CODEX_SESSION_READY = True
    _CODEX_LAST_SANDBOX = sandbox

    # Tool results must be fed back — otherwise Codex guesses and invents
    # "I don't have http_request".
    if applied_tools and _fileop_depth < _tool_continue_budget():
        ui.info("tool results ready; continuing codex")
        hist = list(history or [])
        hist.append(("user", orig))
        hist.append(("hackbot", answer or "(tools ran)"))
        cont = run_codex_turn(
            _tool_continue_prompt(orig, applied_tools),
            history=hist,
            model=model,
            effort=effort,
            timeout=timeout,
            approve_fn=approve_fn,
            allow_file_ops=allow_file_ops,
            _fileop_depth=_fileop_depth + 1,
            _orig_user_prompt=orig,
        )
        # Mid-turn answer already shown via markdown_panel → live_feed note.
        # Return only the continuation (latest segment) — do not concatenate
        # into one megadump (Cursor/Claude/Codex CLI pattern).
        ui.turn_timing(
            time.perf_counter() - started,
            len(ops) + len(applied_tools),
        )
        return (cont or "").strip() or answer

    if (
        allow_file_ops
        and _should_continue_after_fileops(applied, answer=answer)
        and _fileop_depth < _MAX_FILEOP_CONTINUES
    ):
        ui.info("file ops applied; continuing codex (don't re-ask me)")
        hist = list(history or [])
        hist.append(("user", orig))
        hist.append(("hackbot", answer or "(file ops applied)"))
        cont = run_codex_turn(
            _fileop_continue_prompt(orig, applied),
            history=hist,
            model=model,
            effort=effort,
            timeout=timeout,
            approve_fn=approve_fn,
            allow_file_ops=allow_file_ops,
            _fileop_depth=_fileop_depth + 1,
            _orig_user_prompt=orig,
        )
        ui.turn_timing(time.perf_counter() - started, len(ops) + len(applied_tools))
        return (cont or "").strip() or answer
    if applied and not _should_continue_after_fileops(applied, answer=answer):
        ui.info("file ops done; turn complete (not auto-continuing)")

    ui.turn_timing(time.perf_counter() - started, len(ops) + len(applied_tools))
    return answer


def _fmt_command(cmd: Any) -> str:
    """Command text for the live stream.

    Default = raw Codex look (``/usr/bin/zsh -lc 'for … curl …'``).
    Compact one-liners only when ``HACKBOT_STREAM_COMPACT=1``.
    """
    cmd = ui.coerce_command(cmd)
    if ui.stream_command_compact():
        return ui.summarize_command(cmd)
    return ui.format_stream_command(cmd)


def _clip(text: str, n: int = 160) -> str:
    text = " ".join((text or "").split())
    if len(text) <= n:
        return text
    return text[: n - 1] + "…"


def _item_text(item: dict[str, Any]) -> str:
    for key in ("text", "summary", "message", "query"):
        val = item.get(key)
        if isinstance(val, str) and val.strip():
            return val.strip()
        if isinstance(val, list):
            parts = [str(x).strip() for x in val if str(x).strip()]
            if parts:
                return " ".join(parts)
    return ""


def _announce_tool_proposals(text: str, printed_hdr: dict[str, Any], line: Callable[..., None]) -> None:
    """Surface ```hackbot-tool``` proposals from agent_message as live progress."""
    _, calls = _extract_tool_calls(text)
    for call in calls:
        name, args = _normalize_tool_call(call)
        if not name:
            continue
        bits = [name]
        if args.get("method"):
            bits.append(str(args.get("method")).upper())
        if args.get("url"):
            bits.append(str(args.get("url")))
        elif args.get("host"):
            bits.append(str(args.get("host")))
        elif args.get("path"):
            bits.append(str(args.get("path")))
        key = f"toolprop:{name}:{args.get('url') or args.get('path') or ''}"
        if printed_hdr.get(key):
            continue
        printed_hdr[key] = True
        line("tool", " ".join(bits), "hb.cmd")


def _handle_event(
    obj: dict[str, Any],
    printed_hdr: dict[str, Any],
    *,
    before_print: Callable[[], None] | None = None,
    answer_sink: list[str] | None = None,
    meta: dict[str, Any] | None = None,
) -> bool:
    """Render one codex JSON event. Return True if something was printed.

    Shows think / run (+ output) / tool proposals / plan. Final answer still
    lands in the markdown panel (not dumped as giant ``say`` lines).
    """
    shown = False

    def hdr() -> None:
        if not printed_hdr.get("v"):
            if before_print:
                before_print()
            ui.console.print(ui_text("codex", "hb.label"))
            printed_hdr["v"] = True

    def line(kind: str, text: str, style: str = "hb.muted") -> None:
        nonlocal shown
        text = (text or "").strip()
        if not text:
            return
        key = f"{kind}:{text}"
        if printed_hdr.get("last") == key:
            return
        if before_print:
            before_print()
        hdr()
        ui.activity(kind, text, style=style)
        printed_hdr["last"] = key
        shown = True

    etype = str(obj.get("type") or "")
    # Skip turn lifecycle noise — operators want think/run like Claude CLI / the screenshot.
    if etype in {"thread.started", "turn.started", "turn.completed"}:
        return shown
    if etype in {"error", "turn.failed"}:
        msg = obj.get("message") or obj.get("error") or etype
        if isinstance(msg, dict):
            msg = msg.get("message") or msg.get("error") or etype
        line("err", str(msg), "hb.warn")
        return shown

    # Newer "thread item" shape: {"type":"item.*","item":{...}}
    if "item" in obj and isinstance(obj["item"], dict):
        item = obj["item"]
        itype = str(item.get("type") or item.get("item_type") or "")
        ilow = itype.lower()
        item_id = str(item.get("id") or "")

        if "reason" in ilow:
            full = _item_text(item)
            if full:
                key = f"think_full:{item_id}"
                prev = str(printed_hdr.get(key) or "")
                if before_print:
                    before_print()
                hdr()
                if full.startswith(prev) and len(full) > len(prev):
                    ui.think_delta(full[len(prev) :], first=not prev)
                    printed_hdr[f"think_open:{item_id}"] = True
                    shown = True
                elif full != prev:
                    # Non-prefix update (rare) — print a fresh think line.
                    line("think", full if len(full) <= 400 else full[:399] + "…")
                printed_hdr[key] = full
                if etype == "item.completed" and printed_hdr.get(f"think_open:{item_id}"):
                    ui.console.print()
                    printed_hdr.pop(f"think_open:{item_id}", None)

        elif "command" in ilow or "exec" in ilow:
            raw_cmd = item.get("command") if item.get("command") is not None else item.get("cmd")
            cmd_text = ui.command_as_text(raw_cmd)
            if meta is not None:
                for url in _shell_http_urls(cmd_text):
                    meta.setdefault("shell_http", []).append(url)
            status = str(item.get("status") or "").lower()
            pretty = _fmt_command(raw_cmd) or "(command)"
            run_key = f"run_shown:{item_id or pretty[:120]}"
            if (
                (etype == "item.started" or status in {"in_progress", ""})
                and not printed_hdr.get(run_key)
            ):
                # Close any open think stream before the command dump.
                if any(k.startswith("think_open:") for k in printed_hdr):
                    ui.console.print()
                    for k in list(printed_hdr):
                        if k.startswith("think_open:"):
                            printed_hdr.pop(k, None)
                line("run", pretty, "hb.cmd")
                printed_hdr[run_key] = True
            if etype == "item.completed" or status in {"completed", "failed", "declined"}:
                if not printed_hdr.get(run_key):
                    line("run", pretty, "hb.cmd")
                    printed_hdr[run_key] = True
                exit_code = item.get("exit_code")
                out = str(item.get("aggregated_output") or "").strip()
                mark = "ok" if status != "failed" and exit_code in {0, None, "0"} else "fail"
                # Raw stream: show real command output (truncated only if huge).
                if out:
                    max_out = 24_000 if not ui.stream_command_compact() else 180
                    shown_out = out if len(out) <= max_out else out[: max_out - 1] + "…"
                    line(
                        f"out/{mark}",
                        shown_out if exit_code is None else f"exit={exit_code}\n{shown_out}",
                        "hb.ok" if mark == "ok" else "hb.warn",
                    )
                elif exit_code is not None:
                    line(
                        f"out/{mark}",
                        f"exit={exit_code}",
                        "hb.ok" if mark == "ok" else "hb.warn",
                    )

        elif "message" in ilow or ilow in {"agent_message", "assistant_message"}:
            text = _item_text(item)
            if text and answer_sink is not None:
                answer_sink.clear()
                answer_sink.append(text)
            if text:
                _announce_tool_proposals(text, printed_hdr, line)
                # Live narration (not the final panel dump): first line / plan.
                if "```hackbot-tool" not in text and "```hackbot-fileop" not in text:
                    first = text.strip().splitlines()[0] if text.strip() else ""
                    # Skip pure final-report dumps; still show short working notes.
                    looks_final = bool(
                        re.search(r"(?i)^\s*(\*\*)?(resultado|result|summary)\b", first)
                    )
                    if first and not looks_final:
                        line("plan", _clip(first, 160))

        elif "todo" in ilow:
            items = item.get("items") if isinstance(item.get("items"), list) else []
            for todo in items[:6]:
                if not isinstance(todo, dict):
                    continue
                mark = "x" if todo.get("completed") else " "
                line("todo", f"[{mark}] {_clip(str(todo.get('text') or ''), 120)}")

        elif "file" in ilow:
            changes = item.get("changes") if isinstance(item.get("changes"), list) else []
            if changes:
                for ch in changes[:5]:
                    if isinstance(ch, dict):
                        line("file", f"{ch.get('kind') or 'edit'} {ch.get('path') or '?'}")
            else:
                line("file", _clip(_item_text(item) or "file change", 120))

        elif "mcp" in ilow:
            line(
                "mcp",
                _clip(f"{item.get('server') or ''}.{item.get('tool') or ''} {_item_text(item)}", 160),
                "hb.cmd",
            )
        elif "web_search" in ilow or "search" in ilow:
            line("search", _clip(str(item.get("query") or _item_text(item)), 160))
        elif ilow:
            line("do", _clip(ilow.replace("_", " ") + " " + _item_text(item), 160))
        return shown

    # Classic shape: {"id":..,"msg":{"type":..,..}}
    msg = obj.get("msg") if isinstance(obj.get("msg"), dict) else None
    if msg is None:
        return shown
    mtype = str(msg.get("type") or "")
    if "reasoning" in mtype:
        snippet = _clip(_item_text(msg) or str(msg.get("text") or msg.get("summary") or ""), 200)
        if snippet:
            line("think", snippet)
    elif mtype == "exec_command_begin":
        raw_cmd = msg.get("command")
        if meta is not None:
            for url in _shell_http_urls(ui.command_as_text(raw_cmd)):
                meta.setdefault("shell_http", []).append(url)
        line("run", _fmt_command(raw_cmd), "hb.cmd")
    elif mtype == "exec_command_end":
        out = str(msg.get("aggregated_output") or msg.get("output") or "").strip()
        max_out = 4000 if not ui.stream_command_compact() else 180
        if out and len(out) > max_out:
            out = out[: max_out - 1] + "…"
        detail = out or _fmt_command(msg.get("command") or "")
        if msg.get("exit_code") is not None and out:
            detail = f"exit={msg.get('exit_code')}\n{detail}"
        elif msg.get("exit_code") is not None:
            detail = f"exit={msg.get('exit_code')}"
        line("out", detail)
    elif mtype == "error":
        line("err", str(msg.get("message") or "error"), "hb.warn")
    return shown


def _reap_proc(proc: subprocess.Popen[str] | None, *, timeout: float = 5.0) -> None:
    """Ensure a killed/finished Codex child does not linger as a zombie."""
    if proc is None:
        return
    try:
        if proc.poll() is None:
            try:
                proc.kill()
            except OSError:
                pass
        try:
            proc.wait(timeout=timeout)
        except Exception:  # noqa: BLE001
            pass
    except Exception:  # noqa: BLE001
        pass


def _run_quiet(
    cmd: list[str], prompt: str, timeout: int
) -> tuple[str, str, dict[str, Any]] | None:
    """Non-stream exec via Popen so operator interrupt can kill mid-flight."""
    global _CODEX_PROC
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
        )
    except OSError as exc:
        return "", f"(could not launch codex: {exc})", {}
    with _CODEX_PROC_LOCK:
        _CODEX_PROC = proc
    timed_out = False
    try:
        with ui.working("working · codex"):
            assert proc.stdin is not None
            proc.stdin.write(prompt)
            proc.stdin.close()
            try:
                stdout, stderr = proc.communicate(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                proc.kill()
                try:
                    stdout, stderr = proc.communicate(timeout=5)
                except Exception:  # noqa: BLE001
                    stdout, stderr = "", ""
                return "", f"(codex timed out after {timeout}s)", {}
        if codex_cancel_requested():
            return "", "(cancelled)", {}
        return stdout or "", stderr or "", {}
    except KeyboardInterrupt:
        proc.kill()
        raise
    finally:
        if timed_out or codex_cancel_requested() or (proc.poll() is None):
            _reap_proc(proc)
        with _CODEX_PROC_LOCK:
            if _CODEX_PROC is proc:
                _CODEX_PROC = None


def _run_streaming(
    cmd: list[str], prompt: str, timeout: int
) -> tuple[str, str, dict[str, Any]] | None:
    """Stream codex JSON events as a live transcript (think/run/tool/plan).

    Returns ``(last_agent_message, non_json_stderr, meta)``.
    Spinner only until the first progress line — then plain append-only output
    (restarting Rich Status was wiping the feeling of a live stream).
    """
    global _CODEX_PROC
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
            text=True,
            encoding="utf-8",
            errors="replace",
            bufsize=1,
        )
    except OSError as exc:
        return "", f"(could not launch codex: {exc})", {}

    with _CODEX_PROC_LOCK:
        _CODEX_PROC = proc

    errbuf: list[str] = []
    printed_hdr: dict[str, Any] = {}
    answer_sink: list[str] = []
    meta: dict[str, Any] = {"shell_http": []}
    assert proc.stdout is not None and proc.stdin is not None
    cancelled = False
    timed_out = False
    waiting = True
    trace = os.environ.get("HACKBOT_CODEX_TRACE", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }

    def _stop_waiting() -> None:
        nonlocal waiting
        if waiting:
            waiting = False
            ui.stop_live()

    try:
        # Close stdin after writing so Codex does not hang waiting for more input.
        proc.stdin.write(prompt)
        proc.stdin.close()
        # Scrollback line (not Rich Live) so it never glues onto the prompt row.
        ui.working_line("working · codex")
        for raw_line in proc.stdout:
            if codex_cancel_requested():
                cancelled = True
                proc.kill()
                break
            raw_line = raw_line.rstrip("\r\n")
            if not raw_line:
                continue
            try:
                obj = json.loads(raw_line)
            except json.JSONDecodeError:
                errbuf.append(raw_line)
                # Non-JSON progress lines from codex (rare with --json).
                flat = _clip(raw_line, 180)
                if flat and not flat.startswith("{"):
                    _stop_waiting()
                    if not printed_hdr.get("v"):
                        ui.console.print(ui_text("codex", "hb.label"))
                        printed_hdr["v"] = True
                    ui.activity("log", flat)
                continue
            if isinstance(obj, dict):
                if trace:
                    ui.activity("dbg", _clip(json.dumps(obj, ensure_ascii=False), 200))
                _handle_event(
                    obj,
                    printed_hdr,
                    before_print=_stop_waiting,
                    answer_sink=answer_sink,
                    meta=meta,
                )
        if not cancelled:
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                timed_out = True
                proc.kill()
                return "", f"(codex timed out after {timeout}s)", meta
    except KeyboardInterrupt:
        proc.kill()
        raise
    finally:
        _stop_waiting()
        ui.stop_live()
        if cancelled or timed_out or codex_cancel_requested() or (proc.poll() is None):
            _reap_proc(proc)
        with _CODEX_PROC_LOCK:
            if _CODEX_PROC is proc:
                _CODEX_PROC = None
    if cancelled or codex_cancel_requested():
        ui.warn("codex interrupted")
        return "", "(cancelled)", meta
    if printed_hdr.get("v"):
        ui.console.print()
    return (answer_sink[-1] if answer_sink else ""), "\n".join(errbuf), meta
