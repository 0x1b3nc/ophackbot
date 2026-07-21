"""Terminal UI. Claude/Codex-ish: muted chrome, clear status, markdown panels."""

from __future__ import annotations

from rich.console import Console, Group
from rich.markdown import Markdown
from rich.panel import Panel
from rich.rule import Rule
from rich.syntax import Syntax
from rich.table import Table
from rich.text import Text
from rich.theme import Theme

from . import __version__

THEME = Theme(
    {
        "hb.brand": "bold cyan",
        "hb.muted": "dim",
        "hb.ok": "bold green",
        "hb.warn": "bold yellow",
        "hb.bad": "bold red",
        "hb.info": "bold bright_white",
        "hb.label": "cyan",
        "hb.path": "dim italic",
        "hb.cmd": "bold white",
    }
)

console = Console(theme=THEME, highlight=False, legacy_windows=False)

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
    title.append("hackbot", style="hb.brand")
    title.append(f"  v{__version__}", style="hb.muted")
    body = Text.from_markup(
        "[hb.muted]authorized bounty agent[/]\n"
        "[hb.muted]type a task. I think, use tools, and answer.[/]\n"
        "\n"
        "[hb.label]examples[/]\n"
        "[hb.muted]-[/] check if example.com is in scope for targets/demo\n"
        "[hb.muted]-[/] open IDOR notes and draft a plan for /api/orders/1\n"
        "[hb.muted]-[/] dry-run httpx on example.com for the demo target\n"
        "\n"
        "[hb.muted]scope first  |  evidence redacted  |  active traffic needs your approve[/]\n"
        "[hb.muted]/exit  /clear  /help[/]    low-level: [hb.cmd]hackbot cmd ...[/]"
    )
    console.print()
    console.print(
        Panel(
            Group(title, Text(""), body),
            border_style="cyan",
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


def rule(title: str = "") -> None:
    console.print(Rule(title, style="dim"))


def kv(label: str, value: str, *, style: str = "hb.info") -> None:
    line = Text()
    line.append(f"{label:<14}", style="hb.label")
    line.append(value, style=style)
    console.print(line)


def success(msg: str) -> None:
    console.print(Text.from_markup(f"[hb.ok]✓[/] {msg}"))


def warn(msg: str) -> None:
    console.print(Text.from_markup(f"[hb.warn]![/] {msg}"))


def error(msg: str) -> None:
    console.print(Text.from_markup(f"[hb.bad]✗[/] {msg}"))


def info(msg: str) -> None:
    console.print(Text.from_markup(f"[hb.muted]-[/] {msg}"))


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
        Panel(table, title="scope-check", border_style="cyan", padding=(1, 2))
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


def markdown_panel(md: str, *, title: str) -> None:
    console.print(
        Panel(
            Markdown(md),
            title=title,
            border_style="cyan",
            padding=(1, 2),
        )
    )


def code_panel(code: str, *, title: str = "command", lexer: str = "bash") -> None:
    console.print(
        Panel(
            Syntax(code, lexer, theme="monokai", word_wrap=True),
            title=title,
            border_style="bright_black",
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
    console.print(
        Panel(
            Markdown(text) if text.lstrip().startswith("#") else Text(text),
            title=title or path,
            subtitle=str(path),
            subtitle_align="right",
            border_style="dim",
            padding=(1, 2),
        )
    )


def routes_table(routes_text: str) -> None:
    table = Table(title="knowledge routes", border_style="cyan", show_lines=False)
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


def tool_line(name: str, status: str = "ok") -> None:
    """One-line tool progress (compact UI)."""
    style = "hb.ok" if status in {"ok", "done"} else ("hb.bad" if status in {"fail", "error"} else "hb.muted")
    console.print(Text.from_markup(f"[hb.muted]tool[/] [hb.cmd]{name}[/] [{style}]{status}[/]"))


def turn_timing(seconds: float, tools_used: int = 0) -> None:
    console.print(
        Text(f"{seconds:.1f}s · {tools_used} tool{'s' if tools_used != 1 else ''}", style="hb.muted")
    )


class Stream:
    """Append-only (typewriter) streaming. No live re-render, so no flicker.

    Shows a spinner until the first token arrives, then streams thinking (dim)
    and the answer under a rule.
    """

    def __init__(self, title: str = "hackbot") -> None:
        self.title = title
        self._answer: list[str] = []
        self._started_reasoning = False
        self._started_answer = False
        self._status = None

    def __enter__(self) -> "Stream":
        self._status = console.status("[cyan]thinking...[/]", spinner="dots")
        self._status.start()
        return self

    def _stop_wait(self) -> None:
        if self._status is not None:
            self._status.stop()
            self._status = None

    def reasoning(self, delta: str) -> None:
        if not delta:
            return
        self._stop_wait()
        if not self._started_reasoning:
            console.print(Text("thinking", style="hb.label"))
            self._started_reasoning = True
        console.print(Text(delta, style="hb.muted"), end="")

    def answer(self, delta: str) -> None:
        if not delta:
            return
        self._stop_wait()
        if not self._started_answer:
            if self._started_reasoning:
                console.print()  # close the reasoning block
            console.print(Rule(self.title, style="dim"))
            self._started_answer = True
        self._answer.append(delta)
        console.print(Text(delta, style="hb.info"), end="")

    def has_reasoning(self) -> bool:
        return self._started_reasoning

    def answer_text(self) -> str:
        return "".join(self._answer)

    def __exit__(self, *exc: object) -> None:
        self._stop_wait()
        if self._started_reasoning or self._started_answer:
            console.print()
