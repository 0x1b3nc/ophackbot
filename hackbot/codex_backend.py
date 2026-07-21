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
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Callable

from rich.text import Text as _Text

from . import ui
from .llm import streaming_enabled

ApproveFn = Callable[[str], bool]


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

PREAMBLE = """You are Hackbot, my authorized bug-bounty / lab agent, running inside this repository.

Hard rules:
- Authorized security research only (bug bounty, my labs, CTFs, contracted pentests, education). Never help attack a host that is not authorized.
- Read local context before you answer. Relevant files in this repo:
    docs/OPERATING_RULES.md
    bounty_knowledge/study_notes/INDEX.md
    targets/<program>/SCOPE.md, PLAN.md, FINDINGS.md, RESUME.md
  Open the ones that matter for the task instead of guessing.
- A host is only IN SCOPE if it appears in that program's SCOPE.md. If it is not there, say so and treat it as inference - do not propose active traffic.
- For any hunting step, produce: falsifiable hypothesis, target/endpoint, preconditions, aggression level 0-3, a short quote from SCOPE.md that authorizes it, a concrete command, expected evidence, stop criteria, cleanup.
- Dry-run first. Label any active or aggressive command clearly as "ACTIVE - needs operator approve". You are in a read-only sandbox, so never actually send active traffic; just propose it.
- Be concise and technical. First person, like my agent ("I'll check the scope, then...").

Changing files (create / edit / delete / move):
- You are in a READ-ONLY sandbox and CANNOT write files yourself. Do NOT try to create/edit files with shell commands (New-Item, apply_patch, echo>, etc.) - they fail with Access denied.
- Instead, when the task needs a file change, EMIT a fenced block that hackbot will run for me. Hackbot writes with plain Python (works ANYWHERE, including Downloads/Desktop, not just this repo) and asks my approval for each operation.
- Emit ONE block per operation, exactly like this (valid JSON):

```hackbot-fileop
{"op": "write_file", "path": "C:/Users/me/Downloads/teste.md", "content": "full file content here"}
```

  Valid ops and their keys:
  - {"op":"write_file","path":..,"content":..}   create or overwrite
  - {"op":"append_file","path":..,"content":..}  append to a file
  - {"op":"edit_file","path":..,"old_string":..,"new_string":..}  replace exact text
  - {"op":"delete_path","path":..}               delete a file or directory
  - {"op":"make_dir","path":..}                  create a directory
  - {"op":"move_path","src":..,"dst":..}         move or rename
- Use an absolute path when the user names a location (Downloads, Desktop, etc.). Still explain in prose what you're doing, and put the block(s) in your answer. Only emit a block when a file change is actually requested/needed - never for read-only questions.

Now handle this task:
"""


def codex_available() -> bool:
    """True if the codex binary exists and reports a logged-in session."""
    if shutil.which("codex") is None:
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
        return False
    out = (proc.stdout + proc.stderr).lower()
    return proc.returncode == 0 and "logged in" in out


def _build_prompt(user_prompt: str, history: list[tuple[str, str]] | None) -> str:
    parts = [PREAMBLE]
    if history:
        recent = history[-6:]
        convo = "\n".join(f"{role}: {text}" for role, text in recent)
        parts.append("\nRecent conversation (for context):\n" + convo + "\n")
    parts.append("\nCurrent task:\n" + user_prompt.strip() + "\n")
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
    timeout: int = 300,
    approve_fn: ApproveFn | None = None,
    allow_file_ops: bool = True,
) -> str:
    """Run one turn through `codex exec` (read-only) and display the answer.

    Codex never writes files itself (headless sandbox blocks it, even outside the
    repo). Instead it emits ```hackbot-fileop``` blocks; when ``allow_file_ops``
    is on, hackbot performs each one via its approve-gated tools (plain Python,
    so it works anywhere - Downloads, Desktop, etc.), asking permission per
    operation. Returns the (cleaned) final agent message for history.
    """
    prompt = _build_prompt(user_prompt, history)

    with tempfile.NamedTemporaryFile(
        "r", suffix=".txt", delete=False, encoding="utf-8"
    ) as handle:
        out_path = Path(handle.name)

    cmd = [
        "codex",
        "exec",
        "--sandbox",
        "read-only",
        "--skip-git-repo-check",
        "--color",
        "never",
        "-C",
        str(ROOT),
        "-o",
        str(out_path),
    ]
    if model:
        cmd.extend(["-m", model])
    if effort:
        level = _CODEX_EFFORT.get(effort)
        if level:
            cmd.extend(["-c", f'model_reasoning_effort="{level}"'])

    if streaming_enabled():
        # --json gives structured events (no giant prompt/file echo). We render
        # concise progress; the clean final answer still comes from -o.
        captured = _run_streaming(cmd + ["--json", prompt], timeout)
    else:
        captured = _run_quiet(cmd + [prompt], timeout)

    if captured is None:  # launch/timeout error message already returned
        out_path.unlink(missing_ok=True)
        answer = "(codex failed to run)"
        ui.markdown_panel(answer, title="hackbot (codex)")
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
            answer = (
                "codex session expired. Run `codex login` (Sign in with ChatGPT), "
                "then try again."
            )
            ui.markdown_panel(answer, title="hackbot (codex)")
            return answer
        answer = (error or "").strip() or "(codex produced no output)"

    ops: list[dict[str, Any]] = []
    if allow_file_ops:
        answer, ops = _extract_fileops(answer)

    ui.markdown_panel(answer, title="hackbot (codex)")

    if ops:
        _apply_fileops(ops, approve_fn)
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
    # A one-line spinner at the bottom; progress lines scroll above it without
    # flicker (unlike the old growing Live panel). This restores the "thinking"
    # indicator while codex works.
    with ui.console.status("[cyan]codex is thinking...[/]", spinner="dots"):
        for line in proc.stdout:
            line = line.rstrip("\r\n")
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                errbuf.append(line)  # header noise / auth errors
                continue
            if isinstance(obj, dict):
                _handle_event(obj, printed_hdr)
        try:
            proc.wait(timeout=timeout)
        except subprocess.TimeoutExpired:
            proc.kill()
            return "", f"(codex timed out after {timeout}s)"
    if printed_hdr.get("v"):
        ui.console.print()
    return "", "\n".join(errbuf)
