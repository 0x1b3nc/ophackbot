"""Bridge to the OpenAI Codex CLI so hackbot can think using your ChatGPT plan.

This shells out to `codex exec` (non-interactive) with a read-only sandbox.
Codex reasons over the real repo (it can read SCOPE.md, notes, docs itself),
then prints a final answer. Active traffic never happens here: the sandbox is
read-only, so Codex can *propose* commands but the operator still runs anything
active through hackbot's own approve-gated runners.

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


def ui_text(text: str, style: str) -> _Text:
    return _Text(text, style=style)


# Codex runs read-only and never writes files itself. Instead it emits
# ```hackbot-fileop``` blocks describing the change; hackbot performs them with
# plain Python (works anywhere, e.g. Downloads) and asks approval per operation.
_FILEOP_RE = re.compile(r"```hackbot-fileop\s*\n(.*?)```", re.DOTALL | re.IGNORECASE)

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
        "Continue the user's ORIGINAL task now. Do NOT re-emit the same file-op.\n"
        "If they asked to hunt / start recon, proceed with the next concrete steps "
        "(dry-run first, then ask for approve when you need live traffic).\n"
        f"Original task: {user_prompt.strip()}"
    )


def _should_continue_after_fileops(applied: list[dict[str, Any]]) -> bool:
    """Resume the brain after at least one successful write/edit."""
    if not applied or not any(row.get("ok") for row in applied):
        return False
    flag = os.environ.get("HACKBOT_FILEOP_CONTINUE", "1").strip().lower()
    return flag not in {"0", "false", "off", "no"}


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

_FILEOP_RULES = """
Files: your Codex sandbox is READ-ONLY — you never write disks yourself.
When the user asks to create/edit/delete a file, emit ONE fenced hackbot-fileop
block; Hackbot applies it (kit, home, Downloads, Desktop) after operator approve.
NEVER say you can only write inside the repo/kit. Downloads/Desktop ARE allowed.

```hackbot-fileop
{"op": "write_file", "path": "C:/Users/me/Downloads/teste.md", "content": "# teste\\n"}
```

Ops: write_file, append_file, edit_file, delete_path, make_dir, move_path.
After you emit a file-op, hackbot applies it (with approve) and automatically
continues you — do not stop the job waiting for the user to re-ask.
"""

PREAMBLE_CHAT = """You are Hackbot, a short friendly authorized bounty/lab CLI agent.
Answer briefly in first person. Do NOT read repo files. Do NOT run shell commands.
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
  concrete command, expected evidence, stop criteria, cleanup.
- Dry-run first. Label active work "ACTIVE - needs operator approve".
- Be concise, technical, first person.
""" + _FILEOP_RULES + """
Only emit a file-op block when a file change is actually needed.
After SCOPE/setup files land, keep going on the hunt — do not end the turn idle.

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
        # Resume keeps session context but MUST restate file-op rules — otherwise
        # Codex invents "I can only write inside the kit".
        recent = history[-4:]
        convo = "\n".join(f"{role}: {text}" for role, text in recent)
        return (
            "Continue.\n"
            + _FILEOP_RULES
            + hint
            + f"\nRecent:\n{convo}\n\nUser: {user_prompt.strip()}\n"
        )
    preamble = PREAMBLE_CHAT if chat_mode else PREAMBLE_HUNT
    parts = [preamble, hint]
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
    """Run one turn through `codex exec` (read-only) and display the answer.

    Chat prompts use a light preamble (no file reads). Hunt prompts use the full
    preamble. After the first successful turn in-process, later turns use
    `codex exec resume --last` when enabled (default on).

    After approved file-ops, automatically continues Codex so setup writes
    (SCOPE.md etc.) do not strand the hunt waiting for the user to re-ask.
    """
    global _CODEX_SESSION_READY, _CODEX_AVAIL
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
    prompt = _build_prompt(user_prompt, history, chat_mode=chat_mode, resume=resume)
    ui.info(
        f"codex  effort={effort or '-'}  mode={'chat' if chat_mode else 'hunt'}"
        + ("  resume" if resume else "")
        + (f"  after-fileop-{_fileop_depth}" if _fileop_depth else "")
    )
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
    ]
    if not resume:
        cmd.extend(["--sandbox", "read-only"])
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
    stdout, error = captured

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
    if allow_file_ops:
        answer, ops = _extract_fileops(answer)

    ui.markdown_panel(answer, title="hackbot (codex)")
    applied: list[dict[str, Any]] = []
    if ops:
        applied = _apply_fileops(ops, approve_fn)
    _CODEX_SESSION_READY = True

    if (
        allow_file_ops
        and _should_continue_after_fileops(applied)
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
        combined = "\n\n".join(p for p in (answer, cont) if (p or "").strip()).strip()
        ui.turn_timing(time.perf_counter() - started, len(ops))
        return combined or answer

    ui.turn_timing(time.perf_counter() - started, len(ops))
    return answer


def _run_quiet(cmd: list[str], prompt: str, timeout: int) -> tuple[str, str] | None:
    try:
        with ui.console.status("[cyan]codex is thinking...[/]", spinner="dots"):
            proc = subprocess.run(
                cmd,
                input=prompt,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
            )
    except subprocess.TimeoutExpired:
        return "", f"(codex timed out after {timeout}s)"
    except OSError as exc:
        return "", f"(could not launch codex: {exc})"
    return proc.stdout or "", proc.stderr or ""


def _fmt_command(cmd: Any) -> str:
    if isinstance(cmd, list):
        return " ".join(str(p) for p in cmd)
    return str(cmd)


def _handle_event(obj: dict[str, Any], printed_hdr: dict[str, Any]) -> None:
    """Render one codex JSON event as a concise dim progress line."""
    def hdr() -> None:
        if not printed_hdr.get("v"):
            ui.console.print(ui_text("codex", "hb.label"))
            printed_hdr["v"] = True

    def line(text: str, style: str = "hb.muted") -> None:
        text = text.strip()
        if text and printed_hdr.get("last") != text:  # skip consecutive dupes
            hdr()
            ui.console.print(ui_text(text, style))
            printed_hdr["last"] = text

    # Newer "thread item" shape: {"type":"item.completed","item":{...}}
    if "item" in obj and isinstance(obj["item"], dict):
        item = obj["item"]
        itype = item.get("type") or item.get("item_type") or ""
        if "reason" in itype:
            line(item.get("text") or item.get("summary") or "")
        elif "command" in itype or "exec" in itype:
            line("run: " + _fmt_command(item.get("command") or item.get("cmd") or ""), "hb.cmd")
        return

    # Classic shape: {"id":..,"msg":{"type":..,..}}
    msg = obj.get("msg") if isinstance(obj.get("msg"), dict) else None
    if msg is None:
        return
    mtype = msg.get("type", "")
    if "reasoning" in mtype and "delta" not in mtype:
        line(msg.get("text") or msg.get("summary") or "")
    elif mtype == "exec_command_begin":
        line("run: " + _fmt_command(msg.get("command") or ""), "hb.cmd")
    elif mtype == "error":
        line(msg.get("message") or "error", "hb.warn")


def _run_streaming(cmd: list[str], prompt: str, timeout: int) -> tuple[str, str] | None:
    """Stream codex JSON events as concise progress; return ('', raw-nonjson)."""
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
        return "", f"(could not launch codex: {exc})"

    errbuf: list[str] = []
    printed_hdr: dict[str, Any] = {}
    assert proc.stdout is not None and proc.stdin is not None
    try:
        # Close stdin after writing so Codex does not hang waiting for more input.
        proc.stdin.write(prompt)
        proc.stdin.close()
        with ui.console.status("[cyan]codex is thinking...[/]", spinner="dots"):
            for line in proc.stdout:
                line = line.rstrip("\r\n")
                if not line:
                    continue
                try:
                    obj = json.loads(line)
                except json.JSONDecodeError:
                    errbuf.append(line)
                    continue
                if isinstance(obj, dict):
                    _handle_event(obj, printed_hdr)
            try:
                proc.wait(timeout=timeout)
            except subprocess.TimeoutExpired:
                proc.kill()
                return "", f"(codex timed out after {timeout}s)"
    except KeyboardInterrupt:
        proc.kill()
        raise
    if printed_hdr.get("v"):
        ui.console.print()
    return "", "\n".join(errbuf)
