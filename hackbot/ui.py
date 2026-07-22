"""Terminal UI — visual language adapted from sossost/claude-hq (MIT).

Web dashboard tokens (warm accent, muted surfaces, compact tool rows) mapped to
Rich for the hackbot REPL. Logic stays ours; only look-and-feel was borrowed.
"""

from __future__ import annotations

import json
import os
import re
import sys
from contextlib import contextmanager
from typing import Iterator
from urllib.parse import urlparse

from rich.console import Console, Group
from rich.markdown import Markdown
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from . import __version__
from .operator_gate import console_output_allowed

# Palette from claude-hq dark theme (globals.css) — terminal adaptation.
_ACCENT = "#d4a574"
_FG = "#ececee"
_MUTED = "#6b6b76"
_SECONDARY = "#a0a0ab"
_OK = "#34d399"
_WARN = "#fbbf24"
_BAD = "#f87171"
_BORDER = "#232328"


def _enable_windows_vt() -> None:
    """Enable ANSI/VT processing so Rich colors render in Windows PowerShell."""
    if sys.platform != "win32":
        return
    # Some hosts already support VT; enabling is idempotent.
    try:
        import ctypes

        kernel32 = ctypes.windll.kernel32  # type: ignore[attr-defined]
        handle = kernel32.GetStdHandle(-11)  # STD_OUTPUT_HANDLE
        mode = ctypes.c_uint32()
        if not kernel32.GetConsoleMode(handle, ctypes.byref(mode)):
            return
        ENABLE_VIRTUAL_TERMINAL_PROCESSING = 0x0004
        kernel32.SetConsoleMode(handle, mode.value | ENABLE_VIRTUAL_TERMINAL_PROCESSING)
    except Exception:  # noqa: BLE001
        pass


_enable_windows_vt()

THEME = Theme(
    {
        "hb.brand": f"bold {_FG}",
        "hb.accent": _ACCENT,
        "hb.muted": _MUTED,
        "hb.ok": _OK,
        "hb.warn": _WARN,
        "hb.bad": _BAD,
        "hb.info": _FG,
        "hb.label": _SECONDARY,
        "hb.path": f"italic {_MUTED}",
        "hb.cmd": _FG,
        "hb.border": _BORDER,
    }
)

# Let Rich pick legacy Windows renderer when VT is unavailable.
# Forcing legacy_windows=False caused raw ←[36m escapes in plain PowerShell.
_force_plain = os.environ.get("HACKBOT_PLAIN", "").strip().lower() in {"1", "true", "yes", "on"}
console = Console(
    theme=THEME,
    highlight=False,
    force_terminal=None if not _force_plain else False,
    no_color=_force_plain or os.environ.get("NO_COLOR") is not None,
    color_system=None if _force_plain else "auto",
)

# Mute Rich output while Confirm.ask is waiting (parallel Cursor stream/tools).
_raw_console_print = console.print


def _gated_console_print(*args, **kwargs):  # type: ignore[no-untyped-def]
    if not console_output_allowed():
        return None
    return _raw_console_print(*args, **kwargs)


console.print = _gated_console_print  # type: ignore[method-assign]

_STATUS_STYLE = {
    "IN_SCOPE": "hb.ok",
    "NOT_CONFIRMED": "hb.warn",
    "OUT_OF_SCOPE": "hb.bad",
}


_COMMANDS = (
    ("target-init", "spin up targets/<name>"),
    ("scope-check", "host / action vs SCOPE.md"),
    ("context", "rules + target files"),
    ("knowledge", "open study notes for a class"),
    ("plan", "falsifiable hunt step"),
    ("evidence", "save redacted evidence"),
    ("redact", "redact a file to the terminal"),
    ("report", "Bugcrowd / H1 / Intigriti draft"),
    ("run", "print tool cmd; --approve to execute"),
)


def splash_agent() -> None:
    """Agent REPL home. Prompt in, tools out."""
    title = Text()
    title.append("hackbot", style="hb.accent")
    title.append(f"  v{__version__}", style="hb.muted")
    body = Text.from_markup(
        "[hb.muted]authorized bounty agent[/]\n"
        "[hb.muted]type a task. I think, use tools, and answer.[/]\n"
        "\n"
        "[hb.label]examples[/]\n"
        "[hb.muted]·[/] check if example.com is in scope for targets/demo\n"
        "[hb.muted]·[/] open IDOR notes and draft a plan for /api/orders/1\n"
        "[hb.muted]·[/] dry-run httpx on example.com for the demo target\n"
        "\n"
        "[hb.muted]scope first  ·  evidence redacted  ·  approve for active traffic[/]\n"
        "[hb.muted]/exit  /clear  /help[/]"
    )
    console.print()
    console.print(
        Panel(
            Group(title, Text(""), body),
            border_style=_BORDER,
            padding=(1, 2),
        )
    )
    console.print()


def splash() -> None:
    """Legacy command menu (used by `hackbot cmd`)."""
    title = Text()
    title.append("hackbot", style="hb.brand")
    title.append(f"  v{__version__}", style="hb.muted")

    cmds = Table(show_header=False, box=None, padding=(0, 2))
    cmds.add_column(style="hb.cmd", min_width=14)
    cmds.add_column(style="hb.muted")
    for name, desc in _COMMANDS:
        cmds.add_row(name, desc)

    console.print()
    console.print(
        Panel(
            Group(
                title,
                Text.from_markup("[hb.muted]low-level commands[/]"),
                Text(""),
                cmds,
            ),
            border_style="dim",
            padding=(1, 2),
        )
    )
    console.print()


def plain_ui() -> bool:
    """True when panels must not use Rich chrome (TUI / piped Codex capture)."""
    if _force_plain:
        return True
    try:
        return not console.is_terminal
    except Exception:  # noqa: BLE001
        return True


def rule(title: str = "") -> None:
    label = f"─── {title} ───" if title else "────────"
    try:
        from .live_feed import emit

        emit("log", label)
    except Exception:  # noqa: BLE001
        pass
    if plain_ui():
        console.print(label)
        return
    console.print(Rule(title, style="dim"))


def kv(label: str, value: str, *, style: str = "hb.info") -> None:
    width = max(14, min(28, len(label) + 2))
    plain = f"{label:<{width}}{value}"
    try:
        from .live_feed import emit

        emit("log", plain)
    except Exception:  # noqa: BLE001
        pass
    if plain_ui():
        # Full line — no Panel/Syntax width ellipsis when Codex captures stdout.
        console.print(plain)
        return
    line = Text()
    line.append(f"{label:<{width}}", style="hb.label")
    line.append(value, style=style)
    console.print(line)


def compact_text(text: str, *, max_chars: int = 2000) -> str:
    """Collapse runaway blank lines (common in AEM/HTML) for terminal panels."""
    text = (text or "").replace("\r\n", "\n").replace("\r", "\n")
    text = re.sub(r"[ \t]+\n", "\n", text)
    text = re.sub(r"\n{3,}", "\n\n", text)
    text = text.strip()
    if len(text) > max_chars:
        return text[:max_chars] + "\n…(truncated)"
    return text


def success(msg: str) -> None:
    console.print(Text.from_markup(f"[hb.ok]✓[/] {msg}"))


def warn(msg: str) -> None:
    console.print(Text.from_markup(f"[hb.warn]![/] {msg}"))


def error(msg: str) -> None:
    console.print(Text.from_markup(f"[hb.bad]✗[/] {msg}"))


def info(msg: str) -> None:
    try:
        from .live_feed import emit

        emit("info", msg)
    except Exception:  # noqa: BLE001
        pass
    console.print(Text.from_markup(f"[hb.muted]·[/] {msg}"))


def path_line(label: str, path: str) -> None:
    line = Text()
    line.append(f"{label:<14}", style="hb.label")
    line.append(path, style="hb.path")
    console.print(line)


def scope_result(host: str, status: str) -> None:
    style = _STATUS_STYLE.get(status, "hb.info")
    table = Table.grid(padding=(0, 2))
    table.add_column(style="hb.label")
    table.add_column()
    table.add_row("host", Text(host, style="hb.info"))
    table.add_row("status", Text(status, style=style))
    console.print(
        Panel(table, title="scope-check", border_style=_BORDER, padding=(1, 2))
    )


def aggression_result(level: int, quote: str, warnings: list[str] | None = None) -> None:
    level_style = "hb.ok" if level <= 1 else ("hb.warn" if level == 2 else "hb.bad")
    table = Table.grid(padding=(0, 2))
    table.add_column(style="hb.label")
    table.add_column()
    table.add_row("aggression", Text(str(level), style=level_style))
    table.add_row("policy", Text(quote, style="hb.muted"))
    console.print(
        Panel(table, title="action gate", border_style="dim", padding=(1, 2))
    )
    for w in warnings or []:
        warn(w)


def normalize_agent_text(text: str) -> str:
    """Fix answers that arrive with literal ``\\n`` / ``\\t`` instead of real newlines.

    Codex/Cursor sometimes dump JSON-escaped prose into the final panel — that
    looks like a wall of ``\\n``. Heuristic: only unescape when escaped breaks
    clearly outnumber real ones.
    """
    if not text:
        return text
    real_nl = text.count("\n")
    esc_nl = text.count("\\n")
    if esc_nl > 3 and esc_nl > real_nl:
        out = text.replace("\\r\\n", "\n").replace("\\n", "\n").replace("\\t", "\t")
        out = out.replace('\\"', '"')
        return out
    return text


def coerce_command(cmd: object) -> object:
    """Normalize Codex command payloads (list argv, JSON list string, or str)."""
    if isinstance(cmd, list):
        return cmd
    if isinstance(cmd, tuple):
        return list(cmd)
    if isinstance(cmd, str):
        s = cmd.strip()
        if s.startswith("[") and s.endswith("]"):
            try:
                parsed = json.loads(s)
            except json.JSONDecodeError:
                return cmd
            if isinstance(parsed, list):
                return parsed
        return cmd
    return cmd


def format_stream_command(cmd: object) -> str:
    """Full command for live stream — Codex-style ``/usr/bin/zsh -lc '…'``."""
    cmd = coerce_command(cmd)
    if isinstance(cmd, list) and cmd:
        if len(cmd) >= 3 and str(cmd[-2]) in {"-lc", "-c"}:
            shell = str(cmd[0])
            flag = str(cmd[-2])
            body = str(cmd[-1])
            if "'" in body and '"' not in body:
                return f'{shell} {flag} "{body}"'
            # Match the raw Codex transcript look from the operator screenshot.
            esc = body.replace("'", "'\\''")
            return f"{shell} {flag} '{esc}'"
        return " ".join(str(p) for p in cmd)
    text = str(cmd or "").strip()
    return text or "(empty)"


def command_as_text(cmd: object) -> str:
    """Flatten command to a searchable string (for URL sniffing etc.)."""
    cmd = coerce_command(cmd)
    if isinstance(cmd, list):
        return " ".join(str(p) for p in cmd)
    return str(cmd or "")


def summarize_command(cmd: object, *, max_len: int = 96) -> str:
    """Optional compact one-liner (``HACKBOT_STREAM_COMPACT=1``)."""
    body = ""
    if isinstance(cmd, list) and len(cmd) >= 3:
        # ["zsh", "-lc", "script…"] / ["/usr/bin/zsh", "-c", …]
        flag = str(cmd[-2])
        head = str(cmd[0]).rsplit("/", 1)[-1]
        if flag in {"-lc", "-c"} and head in {"zsh", "bash", "sh"}:
            body = str(cmd[-1])
    if not body:
        raw = " ".join(str(p) for p in cmd) if isinstance(cmd, list) else str(cmd or "").strip()
        if not raw:
            return "(empty)"
        # Unwrap login-shell wrappers Codex loves to emit.
        m = re.search(
            r"(?:/usr/bin/|/bin/)?(?:zsh|bash|sh)\s+-lc\s+(?P<q>['\"])(?P<body>.*)(?P=q)\s*$",
            raw,
            re.DOTALL,
        )
        body = m.group("body") if m else raw
    body = body.replace("\\\n", " ").replace("\n", " ")
    body = re.sub(r"\s+", " ", body).strip()

    if re.search(r"\bcurl\b", body):
        method = "GET"
        mm = re.search(r"(?:-X|--request)\s+([A-Z]+)", body)
        if mm:
            method = mm.group(1)
        elif re.search(r"\b-I\b|\b--head\b", body):
            method = "HEAD"
        url_m = re.search(r"https?://[^\s'\"\\]+", body)
        url = url_m.group(0) if url_m else "…"
        if len(url) > 64:
            url = url[:61] + "…"
        loops = " ×N" if re.search(r"\bfor\b", body) else ""
        return f"curl {method} {url}{loops}"

    if re.search(r"\bpython(?:3)?\b.*\bhackbot\b", body):
        return "python -m hackbot …"
    if re.search(r"\brig\b|\bgrep\b", body) and re.search(r"\bsed\b", body):
        return "shell · filter pipeline"
    if body.startswith("sed ") or "sed -n" in body:
        return "sed …"
    if len(body) > max_len:
        return body[: max_len - 1] + "…"
    return body


def stream_command_compact() -> bool:
    """Default OFF — show raw zsh -lc dumps. Set HACKBOT_STREAM_COMPACT=1 to shorten."""
    import os

    return os.environ.get("HACKBOT_STREAM_COMPACT", "0").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def activity(kind: str, detail: str, *, style: str = "hb.muted") -> None:
    """Progress line. Shell dumps print raw (no markup) so ``[`` in scripts is safe."""
    kind = (kind or "·").strip()
    detail = detail or ""
    if not detail.strip():
        return
    try:
        from .live_feed import emit

        # Full text for TUI — do not clip here (TUI applies its own soft cap).
        emit(kind, detail)
    except Exception:  # noqa: BLE001
        pass
    # Codex/Claude-CLI style: "run: /usr/bin/zsh -lc '…'" — plain text, wraps.
    shown = detail if len(detail) <= 8000 else detail[:8000] + "…"
    if (
        kind.startswith("run")
        or kind.startswith("out")
        or kind in {"log", "dbg", "think", "plan", "tool"}
    ):
        console.print(Text(f"{kind}: ", style="hb.label") + Text(shown, style=style))
        return
    # Safe for short labels; escape brackets that break Rich markup.
    safe = shown.replace("[", "\\[").replace("]", "\\]")
    console.print(
        Text.from_markup(f"[hb.label]{kind}[/] [{style}]{safe}[/]")
    )


def think_delta(text: str, *, first: bool = False) -> None:
    """Append-only reasoning stream (dim), Claude Code style."""
    if not text:
        return
    try:
        from .live_feed import emit

        emit("think", text if not first else f"(thinking)\n{text}")
    except Exception:  # noqa: BLE001
        pass
    if first:
        console.print(Text("think", style="hb.label"))
    console.print(Text(text, style="hb.muted"), end="")


def stop_live() -> None:
    """Stop any Rich Status/Live still attached (prevents prompt-line corruption)."""
    try:
        console.clear_live()
    except Exception:  # noqa: BLE001
        pass


def verbose_enabled() -> bool:
    """Full JSON panels / dumps. Default off — Cursor-like one-liners."""
    return os.environ.get("HACKBOT_VERBOSE", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def _prompt_session_open() -> bool:
    try:
        from .prompt_line import get_prompt_session

        return get_prompt_session() is not None
    except Exception:  # noqa: BLE001
        return False


def working_line(label: str = "working") -> None:
    """claude-hq RunningIndicator → muted pulse dots + label (scrollback)."""
    label = (label or "working").strip()
    try:
        from .live_feed import emit

        emit("working", label)
    except Exception:  # noqa: BLE001
        pass
    console.print(
        Text("··· ", style="hb.muted") + Text(label, style="hb.accent")
    )


@contextmanager
def working(label: str = "working") -> Iterator[None]:
    """Show in-flight work without gluing a Rich Status onto the PromptSession line.

    When the concurrent REPL prompt is open, print one scrollback line instead of
    ``console.status`` (which races the input row). Otherwise use a normal spinner.
    """
    stop_live()
    label = (label or "working").strip()
    if _prompt_session_open():
        working_line(label)
        try:
            yield
        finally:
            stop_live()
        return
    status = console.status(f"[{_ACCENT}]{label}[/]", spinner="dots")
    status.start()
    try:
        yield
    finally:
        try:
            status.stop()
        except Exception:  # noqa: BLE001
            pass
        stop_live()


def user_bubble(text: str) -> None:
    """User message chrome (claude-hq UserBubble → terminal)."""
    text = (text or "").strip()
    if not text:
        return
    console.print()
    console.print(Text("▌ ", style="hb.accent") + Text(text, style="hb.info"))
    console.print()


def thinking_label(*, streaming: bool = True) -> None:
    """Collapsed thinking header style from claude-hq ThinkingBlock."""
    try:
        from .live_feed import emit

        emit("think", "Thinking..." if streaming else "Thinking")
    except Exception:  # noqa: BLE001
        pass
    console.print(
        Text("▸ ", style="hb.muted")
        + Text("Thinking..." if streaming else "Thinking", style="hb.muted")
    )


def ensure_prompt_line() -> None:
    """Clean cursor + blank line before the operator prompt (spinner/print races)."""
    stop_live()
    try:
        sys.stdout.flush()
        sys.stderr.flush()
    except Exception:  # noqa: BLE001
        pass
    console.print()


def format_session_footer(*parts: str) -> str:
    """Pure helper: ``codex · high · aylo · yolo · step off``."""
    bits = [str(p).strip() for p in parts if str(p or "").strip()]
    return " · ".join(bits)


def session_footer(*parts: str) -> None:
    """Dim status strip after a turn (Cursor-like session chrome)."""
    line = format_session_footer(*parts)
    if not line:
        return
    console.print(Text(line, style="hb.muted"))


def short_host(url: str) -> str:
    """Host (+ path snip) for compact action lines."""
    raw = (url or "").strip()
    if not raw:
        return "?"
    try:
        parsed = urlparse(raw if "://" in raw else f"https://{raw}")
        host = parsed.netloc or parsed.path.split("/")[0] or raw
        path = parsed.path or ""
        if path in {"", "/"}:
            return host
        if len(path) > 36:
            path = path[:33] + "…"
        return f"{host}{path}"
    except Exception:  # noqa: BLE001
        return raw[:48]


def format_http_action(
    method: str,
    url: str,
    *,
    status: int | None = None,
    error: str | None = None,
    elapsed_ms: float | None = None,
) -> str:
    """One-line HTTP summary for scrollback."""
    method = (method or "GET").upper()
    target = short_host(url)
    if error:
        err = str(error)
        # Keep URLError/timeout readable without the full repr dump.
        low = err.lower()
        if "timed out" in low or "timeout" in low:
            tail = "timeout"
        elif "refused" in low:
            tail = "connection refused"
        else:
            tail = err.split(":", 1)[0].strip()[:40]
        return f"{method} {target} → {tail}"
    if status is None:
        return f"{method} {target}"
    bits = [f"{method} {target} → {status}"]
    if elapsed_ms is not None:
        bits.append(f"{elapsed_ms:.0f}ms")
    return " · ".join(bits)


def action_line(kind: str, detail: str, *, ok: bool | None = None) -> None:
    """claude-hq ToolBubble: muted name + detail + trailing status mark."""
    kind = (kind or "·").strip()
    detail = (detail or "").strip()
    if not detail:
        return
    mark = "ok" if ok is True else ("fail" if ok is False else "run")
    try:
        from .live_feed import emit

        emit("tool", f"[{mark}] {kind}  {detail}")
    except Exception:  # noqa: BLE001
        pass
    line = Text()
    line.append(f"{kind}  ", style="hb.label")
    shown = detail if len(detail) <= 500 else detail[:500] + "…"
    line.append(shown, style="hb.muted")
    if ok is True:
        line.append("  ✓", style="hb.ok")
    elif ok is False:
        line.append("  ✗", style="hb.bad")
    elif ok is None:
        line.append("  ·", style="hb.warn")
    console.print(line)


def maybe_code_panel(code: str, *, title: str = "command", lexer: str = "bash") -> None:
    """Panel only when verbose; otherwise skip (callers should print a one-liner)."""
    if verbose_enabled():
        code_panel(code, title=title, lexer=lexer)


def markdown_panel(md: str, *, title: str) -> None:
    """Assistant bubble — plain markdown under a soft accent label (claude-hq).

    Also mirrors to the TUI live feed as ``note`` so mid-turn narration appears
    chronologically (Cursor/Claude-style), not only as one final dump.
    """
    body = normalize_agent_text(md or "")
    if body.strip():
        try:
            from .live_feed import emit

            emit("note", body)
        except Exception:  # noqa: BLE001
            pass
    soft = title.lower().startswith("hackbot")
    if soft:
        console.print()
        console.print(Text(title, style="hb.accent"))
        console.print(Markdown(body))
        console.print()
        return
    console.print(
        Panel(
            Markdown(body),
            title=title,
            border_style=_BORDER,
            padding=(1, 2),
        )
    )


def code_panel(code: str, *, title: str = "command", lexer: str = "bash") -> None:
    # JSON / bash plans stay intact. Only squash huge HTML text dumps.
    body = compact_text(code, max_chars=2400) if lexer in {"text", "html", "xml"} else code
    if lexer == "text" and ("<html" in body[:200].lower() or "<!doctype" in body[:80].lower()):
        body = compact_text(body, max_chars=1800)
    # ``panel`` (not ``out``) so the TUI never merges this into an open RunBlock.
    try:
        from .live_feed import emit

        emit("panel", f"{title}\n{body}")
    except Exception:  # noqa: BLE001
        pass
    if plain_ui():
        # Codex captures tool stdout via a pipe. Rich Panel/Syntax ellipsis-clips
        # long lines to a tiny width — operators saw ``surface_map`` cut mid-URL.
        console.print(f"── {title} ──\n{body}", highlight=False, crop=False, overflow="ignore")
        return
    console.print(
        Panel(
            Syntax(body, lexer, theme="monokai", word_wrap=True),
            title=title,
            border_style=_BORDER,
            padding=(1, 2),
        )
    )


def dry_run_banner() -> None:
    console.print(
        Panel(
            Text.from_markup(
                "[hb.warn]dry-run[/]\n"
                "[hb.muted]I printed the command. Pass [hb.cmd]--approve[/] to execute.[/]"
            ),
            border_style="yellow",
            padding=(0, 2),
        )
    )


def permission(description: str) -> None:
    header = Text.from_markup(
        "[hb.warn]permission needed[/]\n"
        "[hb.muted]hackbot wants to do this. approve or deny below.[/]"
    )
    console.print(
        Panel(
            Group(header, Text(""), Text(description, style="hb.info")),
            border_style="yellow",
            padding=(1, 2),
        )
    )


def blocked(msg: str) -> None:
    console.print(
        Panel(
            Text.from_markup(f"[hb.bad]blocked[/]\n[hb.muted]{msg}[/]"),
            border_style="red",
            padding=(0, 2),
        )
    )


def file_panel(path: str, text: str, *, title: str | None = None) -> None:
    shown_title = title or path
    body = text or ""
    try:
        from .live_feed import emit

        emit("panel", f"{shown_title}\n{body}")
    except Exception:  # noqa: BLE001
        pass
    if plain_ui():
        console.print(
            f"── {shown_title} ──\n{body}",
            highlight=False,
            crop=False,
            overflow="ignore",
        )
        return
    console.print(
        Panel(
            Markdown(body) if body.lstrip().startswith("#") else Text(body),
            title=shown_title,
            subtitle=str(path),
            subtitle_align="right",
            border_style="dim",
            padding=(1, 2),
        )
    )


def routes_table(routes_text: str) -> None:
    table = Table(title="knowledge routes", border_style=_BORDER, show_lines=False)
    table.add_column("trigger", style="hb.label")
    table.add_column("notes", style="hb.muted")
    for line in routes_text.splitlines():
        if "->" in line or line.startswith("trigger"):
            continue
        if ":" not in line:
            continue
        key, _, rest = line.partition(":")
        table.add_row(key.strip(), rest.strip())
    console.print(table)


def plain(text: str) -> None:
    console.print(text)


def tool_line(name: str, status: str = "ok", *, detail: str = "") -> None:
    """One-line tool progress — matches claude-hq ToolBubble density."""
    ok = status in {"ok", "done"}
    bad = status in {"fail", "error"}
    running = status in {"running", "wait", "pending"}
    flag: bool | None
    if ok:
        flag = True
    elif bad:
        flag = False
    elif running:
        flag = None
    else:
        flag = None
    action_line(name, detail or status, ok=flag)


def turn_timing(seconds: float, tools_used: int = 0) -> None:
    console.print(
        Text(f"{seconds:.1f}s · {tools_used} tool{'s' if tools_used != 1 else ''}", style="hb.muted")
    )


class Stream:
    """Append-only (typewriter) streaming. No live re-render, so no flicker.

    Shows a working indicator until the first token arrives, then streams
    thinking (dim) and the answer under a rule.
    """

    def __init__(self, title: str = "hackbot") -> None:
        self.title = title
        self._answer: list[str] = []
        self._started_reasoning = False
        self._started_answer = False
        self._wait_cm = None

    def __enter__(self) -> "Stream":
        self._wait_cm = working("thinking…")
        self._wait_cm.__enter__()
        return self

    def _stop_wait(self) -> None:
        if self._wait_cm is not None:
            try:
                self._wait_cm.__exit__(None, None, None)
            except Exception:  # noqa: BLE001
                pass
            self._wait_cm = None
            stop_live()

    def reasoning(self, delta: str) -> None:
        if not delta:
            return
        self._stop_wait()
        if not self._started_reasoning:
            thinking_label(streaming=True)
            self._started_reasoning = True
        try:
            from .live_feed import emit

            emit("think", delta)
        except Exception:  # noqa: BLE001
            pass
        console.print(Text(delta, style="hb.muted"), end="")

    def answer(self, delta: str) -> None:
        if not delta:
            return
        self._stop_wait()
        if not self._started_answer:
            if self._started_reasoning:
                console.print()  # close the reasoning block
            console.print(Text(self.title, style="hb.accent"))
            self._started_answer = True
        self._answer.append(delta)
        try:
            from .live_feed import emit

            emit("draft", delta if len(delta) < 200 else delta[:197] + "…")
        except Exception:  # noqa: BLE001
            pass
        console.print(Text(delta, style="hb.info"), end="")

    def has_reasoning(self) -> bool:
        return self._started_reasoning

    def answer_text(self) -> str:
        return "".join(self._answer)

    def __exit__(self, *exc: object) -> None:
        self._stop_wait()
        if self._started_reasoning or self._started_answer:
            console.print()
        # Flush full answer as a chronological note (TUI mounts a bubble mid-turn).
        full = "".join(self._answer).strip()
        if full:
            try:
                from .live_feed import emit

                emit("note", full)
            except Exception:  # noqa: BLE001
                pass
