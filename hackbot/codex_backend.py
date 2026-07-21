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


def _apply_fileops(ops: list[dict[str, Any]], approve_fn: ApproveFn | None) -> None:
    """Execute codex's proposed file ops through hackbot's approve-gated tools."""
    from . import tools  # local import avoids any import cycle

    ui.console.print(ui_text(f"codex proposes {len(ops)} file change(s):", "hb.label"))
    for item in ops:
        op = str(item.get("op", "")).strip().lower()
        tool = _FILEOP_ALIASES.get(op)
        if tool is None:
            ui.error(f"unknown file op {op!r} - skipped")
            continue
        args = _normalize_op_args(tool, item)
        result = tools.execute_tool(tool, args, approve_fn=approve_fn)
        try:
            parsed = json.loads(result)
        except json.JSONDecodeError:
            parsed = {"ok": False, "error": result}
        if parsed.get("ok"):
            where = parsed.get("path") or parsed.get("to") or parsed.get("deleted") or ""
            ui.success(f"{tool}  {where}")
        else:
            ui.error(f"{tool}: {parsed.get('error', 'failed')}")


ROOT = Path(__file__).resolve().parents[1]

PREAMBLE_CHAT = """You are Hackbot, a short friendly authorized bounty/lab CLI agent.
Answer briefly in first person. Do NOT read repo files. Do NOT run shell commands.
Do NOT emit file-op blocks unless the user explicitly asked to create/edit a file.
If they want hunting work, ask for a concrete task (host, target folder, bug class).

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

Files: you are READ-ONLY. To change files, emit ONE fenced block per op (hackbot applies it with my approval):

```hackbot-fileop
{"op": "write_file", "path": "C:/Users/me/Downloads/teste.md", "content": "..."}
```

Ops: write_file, append_file, edit_file, delete_path, make_dir, move_path.
Only emit a block when a file change is actually needed.

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


def _build_prompt(
    user_prompt: str,
    history: list[tuple[str, str]] | None,
    *,
    chat_mode: bool,
    resume: bool,
) -> str:
    if resume and history:
        # Resume already has session context; send a short turn only.
        recent = history[-4:]
        convo = "\n".join(f"{role}: {text}" for role, text in recent)
        return f"Continue. Recent:\n{convo}\n\nUser: {user_prompt.strip()}\n"
    preamble = PREAMBLE_CHAT if chat_mode else PREAMBLE_HUNT
    parts = [preamble]
    if history and not chat_mode:
        recent = history[-4:]
        convo = "\n".join(f"{role}: {text}" for role, text in recent)
        parts.append("\nRecent conversation:\n" + convo + "\n")
    parts.append("\n" + user_prompt.strip() + "\n")
    return "\n".join(parts)


_CODEX_EFFORT = {
    "minimal": "minimal",
    "low": "low",
    "medium": "medium",
    "high": "high",
    "xhigh": "high",  # codex tops out at high
}


def run_codex_turn(
    user_prompt: str,
    *,
    history: list[tuple[str, str]] | None = None,
    model: str | None = None,
    effort: str | None = None,
    timeout: int | None = None,
    approve_fn: ApproveFn | None = None,
    allow_file_ops: bool = True,
) -> str:
    """Run one turn through `codex exec` (read-only) and display the answer.

    Chat prompts use a light preamble (no file reads). Hunt prompts use the full
    preamble. After the first successful turn in-process, later turns use
    `codex exec resume --last` when enabled (default on).
    """
    global _CODEX_SESSION_READY, _CODEX_AVAIL
    chat_mode = is_chat_prompt(user_prompt)
    effort = effort if effort is not None else resolve_effort_for_prompt(user_prompt)
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
    )
    started = time.perf_counter()

    with tempfile.NamedTemporaryFile(
        "r", suffix=".txt", delete=False, encoding="utf-8"
    ) as handle:
        out_path = Path(handle.name)

    # Flags belong on `codex exec` before the `resume` subcommand.
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
    cmd.append(prompt)

    try:
        if streaming_enabled():
            captured = _run_streaming(cmd, timeout)
        else:
            captured = _run_quiet(cmd, timeout)
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
        # Resume can fail if no prior session; fall back once to a fresh exec.
        if resume and ("resume" in low or "session" in low or "not found" in low):
            _CODEX_SESSION_READY = False
            return run_codex_turn(
                user_prompt,
                history=history,
                model=model,
                effort=effort,
                timeout=timeout,
                approve_fn=approve_fn,
                allow_file_ops=allow_file_ops,
            )
        answer = (error or "").strip() or "(codex produced no output)"

    ops: list[dict[str, Any]] = []
    if allow_file_ops and not chat_mode:
        answer, ops = _extract_fileops(answer)
    elif allow_file_ops and chat_mode:
        # Still honor an explicit file-op if the model emitted one.
        answer, ops = _extract_fileops(answer)

    ui.markdown_panel(answer, title="hackbot (codex)")
    if ops:
        _apply_fileops(ops, approve_fn)
    _CODEX_SESSION_READY = True
    ui.turn_timing(time.perf_counter() - started, len(ops))
    return answer


def _run_quiet(cmd: list[str], timeout: int) -> tuple[str, str] | None:
    try:
        with ui.console.status("[cyan]codex is thinking...[/]", spinner="dots"):
            proc = subprocess.run(
                cmd,
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                timeout=timeout,
                stdin=subprocess.DEVNULL,
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


def _run_streaming(cmd: list[str], timeout: int) -> tuple[str, str] | None:
    """Stream codex JSON events as concise progress; return ('', raw-nonjson)."""
    try:
        proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            encoding="utf-8",
            errors="replace",
            stdin=subprocess.DEVNULL,
            bufsize=1,
        )
    except OSError as exc:
        return "", f"(could not launch codex: {exc})"

    errbuf: list[str] = []
    printed_hdr: dict[str, Any] = {}
    assert proc.stdout is not None
    try:
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
