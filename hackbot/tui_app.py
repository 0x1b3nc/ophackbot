"""hackbot Textual TUI — Toad-inspired layout, operator palette.

Run: ``python -m hackbot tui``

Color palette (operator-defined):
  fundo #0D0D26 · painel #191970 · borda #4B0082
  primária #8A2BE2 · secundária #7B68EE · texto #E8E8FF
  ok #4ADE80 · erro #FF6B9D · aviso #FFCB6B · info #64D9E8
"""

from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, TextIO

from . import live_feed
from .operator_gate import set_tui_console_mute
from .session import get_active, status_line
from .tui_commands import filter_slash_commands, handle_slash
from .turn_bridge import resolve_mode, run_bridged_turn
from .yolo import enable_yolo, is_yolo

# Operator palette (hex)
_BG = "#0D0D26"
_PANEL = "#191970"
_BORDER = "#4B0082"
_PRIMARY = "#8A2BE2"
_SECONDARY = "#7B68EE"
_TEXT = "#E8E8FF"
_OK = "#4ADE80"
_ERR = "#FF6B9D"
_WARN = "#FFCB6B"
_INFO = "#64D9E8"


def _status_line() -> str:
    mode, label = resolve_mode()
    active = get_active()
    tgt = active.name if active else "—"
    yolo = "yolo" if is_yolo() else "ask"
    bits = [f"hackbot · {label} · {tgt} · {yolo}"]
    if mode == "cursor" or os.environ.get("HACKBOT_PROVIDER", "").lower() == "cursor":
        effort = os.environ.get("HACKBOT_EFFORT", "auto")
        fast = os.environ.get("HACKBOT_CURSOR_FAST", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        bits.append(f"effort={effort}")
        bits.append("fast" if fast else "standard")
    bits.append(status_line())
    return " · ".join(bits)


@contextmanager
def _silence_stdio() -> Iterator[None]:
    """Redirect process stdout/stderr so SDK noise cannot paint under Textual."""
    real_out, real_err = sys.stdout, sys.stderr
    sink: TextIO = open(os.devnull, "w", encoding="utf-8", errors="replace")
    try:
        sys.stdout = sink  # type: ignore[assignment]
        sys.stderr = sink  # type: ignore[assignment]
        yield
    finally:
        sys.stdout, sys.stderr = real_out, real_err
        try:
            sink.close()
        except Exception:  # noqa: BLE001
            pass


def start_tui() -> int:
    try:
        from textual import work
        from textual.app import App, ComposeResult
        from textual.binding import Binding
        from textual.containers import Horizontal, Vertical, VerticalScroll
        from textual.widgets import Footer, Input, Markdown, OptionList, Static
        from textual.widgets.option_list import Option
    except ImportError:
        sys.stderr.write("Textual missing. Install:  pip install 'hackbot-kit[tui]'\n")
        return 1

    import io

    os.environ.setdefault("HACKBOT_PLAIN", "1")
    set_tui_console_mute(True)
    sink = io.StringIO()
    try:
        from . import ui

        ui.console.file = sink  # type: ignore[misc]
        ui.console.quiet = True
    except Exception:  # noqa: BLE001
        pass

    if not is_yolo():
        enable_yolo(quiet=True)

    class HackbotTUI(App[None]):
        TITLE = "hackbot"
        SUB_TITLE = str(Path.cwd())
        ENABLE_COMMAND_PALETTE = False
        CSS = f"""
        Screen {{
            background: {_BG};
            color: {_TEXT};
        }}
        #topbar {{
            dock: top;
            height: 3;
            background: {_PANEL};
            border-bottom: tall {_BORDER};
            padding: 0 1;
        }}
        #brand-row {{
            height: 1;
            color: {_PRIMARY};
            text-style: bold;
        }}
        #status {{
            height: 1;
            color: {_INFO};
        }}
        #sidebar {{
            width: 24;
            background: {_PANEL};
            border-right: tall {_BORDER};
            padding: 1 1;
        }}
        #side-title {{
            color: {_SECONDARY};
            text-style: bold;
            padding-bottom: 1;
        }}
        #side-help {{
            color: {_SECONDARY};
        }}
        #main {{
            background: {_BG};
            height: 1fr;
        }}
        #chat {{
            height: 1fr;
            background: {_BG};
            padding: 0 1 1 1;
            scrollbar-background: {_BG};
            scrollbar-color: {_BORDER};
            scrollbar-color-hover: {_PRIMARY};
        }}
        .msg-user {{
            color: {_INFO};
            padding: 1 1 0 1;
            text-style: bold;
        }}
        .msg-md {{
            padding: 0 1 1 1;
            background: {_BG};
            color: {_TEXT};
        }}
        #live-wrap {{
            height: 10;
            background: {_PANEL};
            border-top: tall {_BORDER};
            padding: 0 1;
        }}
        #live-title {{
            height: 1;
            color: {_SECONDARY};
            text-style: bold;
        }}
        #live {{
            height: 8;
            color: {_TEXT};
        }}
        #composer {{
            height: auto;
            background: {_PANEL};
            border-top: tall {_BORDER};
            padding: 1 1;
        }}
        #picker {{
            height: 9;
            border: tall {_BORDER};
            background: {_PANEL};
            display: none;
            margin-bottom: 1;
        }}
        #picker.visible {{
            display: block;
        }}
        #prompt {{
            background: {_BG};
            border: tall {_PRIMARY};
            color: {_TEXT};
            padding: 0 1;
        }}
        #prompt:focus {{
            border: tall {_SECONDARY};
        }}
        Footer {{
            background: {_PANEL};
            color: {_SECONDARY};
        }}
        """
        BINDINGS = [
            Binding("ctrl+c", "interrupt", "stop", show=True),
            Binding("ctrl+q", "quit", "quit", show=True),
            Binding("f1", "show_help", "help", show=True),
            Binding("ctrl+y", "copy_last", "copy last", show=True),
            Binding("ctrl+shift+c", "copy_last", "copy last", show=False),
        ]

        def __init__(self) -> None:
            super().__init__()
            self._busy = False
            self._picker_cmds: list[str] = []
            self._msg_i = 0
            self._last_plain: str = ""
            self._chat_plain: list[str] = []
            self._live_lines: list[str] = []
            self._think_buf: str = ""

        def compose(self) -> ComposeResult:
            with Vertical(id="topbar"):
                yield Static("hackbot", id="brand-row")
                yield Static(_status_line(), id="status")
            with Horizontal():
                with Vertical(id="sidebar"):
                    yield Static("session", id="side-title")
                    yield Static(
                        "/help\n"
                        "/target demo\n"
                        "/provider cursor\n"
                        "/model grok-4.5\n"
                        "/effort high fast\n"
                        "/fast on\n"
                        "/yolo on\n\n"
                        "mouse off → select/copy\n"
                        "ctrl+y → copy last\n"
                        "Enter send · / cmds",
                        id="side-help",
                    )
                with Vertical(id="main"):
                    yield VerticalScroll(id="chat")
                    with Vertical(id="live-wrap"):
                        yield Static("live · think / tools / cmds", id="live-title")
                        yield Static("idle", id="live")
                    with Vertical(id="composer"):
                        yield OptionList(id="picker")
                        yield Input(
                            placeholder="Message hackbot…  (/ for commands)",
                            id="prompt",
                        )
            yield Footer()

        def on_mount(self) -> None:
            live_feed.set_feed_sink(self._on_feed)
            self._append_md(
                f"**hackbot** ready\n\n`{_status_line()}`\n\n"
                f"Try `/model grok-4.5` then `/effort high fast`.\n\n"
                f"_Select text with the mouse (capture off). `ctrl+y` copies last reply._"
            )
            self.query_one("#prompt", Input).focus()

        def on_unmount(self) -> None:
            live_feed.set_feed_sink(None)

        def _on_feed(self, kind: str, text: str) -> None:
            """Called from worker threads — hop onto the UI thread."""
            try:
                self.call_from_thread(self._apply_feed, kind, text)
            except Exception:  # noqa: BLE001
                pass

        def _apply_feed(self, kind: str, text: str) -> None:
            kind = (kind or "info").strip().lower()
            text = (text or "").rstrip()
            if not text:
                return
            if kind in {"think", "thinking", "reasoning"}:
                # Coalesce think tokens into one rolling line.
                if text.startswith("(thinking)"):
                    self._think_buf = text
                else:
                    self._think_buf = (self._think_buf + text)[-900:]
                display = self._think_buf.replace("\n", " ")
                if len(display) > 220:
                    display = "…" + display[-217:]
                line = f"think  {display}"
                if self._live_lines and self._live_lines[-1].startswith("think  "):
                    self._live_lines[-1] = line
                else:
                    self._live_lines.append(line)
            elif kind == "draft":
                line = f"draft  {text}"
                if self._live_lines and self._live_lines[-1].startswith("draft  "):
                    self._live_lines[-1] = line
                else:
                    self._live_lines.append(line)
            else:
                label = {
                    "tool": "tool",
                    "run": "run",
                    "out": "out",
                    "working": "···",
                    "info": "·",
                    "log": "log",
                    "dbg": "dbg",
                    "plan": "plan",
                }.get(kind, kind[:8] or "·")
                self._live_lines.append(f"{label}  {text}")
            self._live_lines = self._live_lines[-40:]
            body = "\n".join(self._live_lines[-12:])
            try:
                self.query_one("#live", Static).update(body or "idle")
            except Exception:  # noqa: BLE001
                pass

        def _reset_live(self) -> None:
            self._live_lines = []
            self._think_buf = ""
            live_feed.clear()
            try:
                self.query_one("#live", Static).update("working…")
            except Exception:  # noqa: BLE001
                pass

        def _refresh_status(self) -> None:
            self.query_one("#status", Static).update(_status_line())
            self.sub_title = str(Path.cwd())

        def _append_user(self, text: str) -> None:
            chat = self.query_one("#chat", VerticalScroll)
            self._msg_i += 1
            chat.mount(Static(f"› {text}", classes="msg-user", id=f"u{self._msg_i}"))
            self._chat_plain.append(f"> {text}")
            chat.scroll_end(animate=False)

        def _append_md(self, text: str) -> None:
            chat = self.query_one("#chat", VerticalScroll)
            self._msg_i += 1
            mid = f"m{self._msg_i}"
            plain = text or "(empty)"
            chat.mount(Markdown(plain, classes="msg-md", id=mid))
            self._last_plain = plain
            self._chat_plain.append(plain)
            if len(self._chat_plain) > 200:
                self._chat_plain = self._chat_plain[-200:]
            chat.scroll_end(animate=False)

        def _copy_text(self, text: str) -> bool:
            data = (text or "").strip()
            if not data:
                return False
            try:
                import pyperclip

                pyperclip.copy(data)
                return True
            except Exception:  # noqa: BLE001
                pass
            # OSC 52 clipboard (works in many SSH/tmux terminals).
            try:
                import base64

                b64 = base64.b64encode(data.encode("utf-8")).decode("ascii")
                sys.stdout.write(f"\033]52;c;{b64}\a")
                sys.stdout.flush()
                return True
            except Exception:  # noqa: BLE001
                return False

        def action_copy_last(self) -> None:
            if self._copy_text(self._last_plain):
                self.notify("copied last reply", severity="information", timeout=2)
            else:
                self.notify(
                    "copy failed — select with mouse (capture off)",
                    severity="warning",
                    timeout=3,
                )

        def _hide_picker(self) -> None:
            picker = self.query_one("#picker", OptionList)
            picker.display = False
            picker.remove_class("visible")

        def _show_picker(self, prefix: str) -> None:
            picker = self.query_one("#picker", OptionList)
            picker.clear_options()
            matches = filter_slash_commands(prefix)
            if not matches:
                self._hide_picker()
                return
            top = matches[:12]
            self._picker_cmds = [c for c, _ in top]
            for i, (cmd, desc) in enumerate(top):
                picker.add_option(Option(f"{cmd}  —  {desc}", id=f"cmd-{i}"))
            picker.display = True
            picker.add_class("visible")

        def on_input_changed(self, event: Input.Changed) -> None:
            if event.input.id != "prompt":
                return
            val = event.value
            if val.startswith("/"):
                self._show_picker(val)
            else:
                self._hide_picker()

        def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
            idx = event.option_index
            if not (0 <= idx < len(self._picker_cmds)):
                return
            cmd = self._picker_cmds[idx].rstrip()
            prompt = self.query_one("#prompt", Input)
            if cmd in {"/target", "/provider", "/model", "/effort", "/hunt"} or self._picker_cmds[
                idx
            ].endswith(" "):
                prompt.value = cmd + " "
            else:
                prompt.value = cmd
            prompt.focus()
            self._hide_picker()

        def on_input_submitted(self, event: Input.Submitted) -> None:
            text = (event.value or "").strip()
            event.input.value = ""
            self._hide_picker()
            if not text or self._busy:
                return
            self._submit(text)

        def _submit(self, text: str) -> None:
            self._append_user(text)
            if text.startswith("/"):
                result = handle_slash(text)
                if result.exit_app:
                    self.exit()
                    return
                if result.clear_chat:
                    chat = self.query_one("#chat", VerticalScroll)
                    for child in list(chat.children):
                        child.remove()
                    self._append_md("_cleared_")
                    self._refresh_status()
                    return
                if result.handled:
                    for msg in result.messages:
                        self._append_md(msg)
                    if result.refresh_status:
                        self._refresh_status()
                    return
            self._busy = True
            self._reset_live()
            self.query_one("#status", Static).update(f"{_status_line()} · working…")
            self.run_hunt_turn(text)

        @work(thread=True, exclusive=True, exit_on_error=False)
        def run_hunt_turn(self, text: str) -> None:
            # Nuke stdout/stderr for this worker so SDK/tool noise cannot bleed under Textual.
            with _silence_stdio():
                try:
                    answer = run_bridged_turn(text)
                except Exception as exc:  # noqa: BLE001
                    answer = f"**Error:** `{type(exc).__name__}: {exc}`"
            self.call_from_thread(self._finish_turn, answer or "(empty)")

        def _finish_turn(self, answer: str) -> None:
            self._busy = False
            self._append_md(answer)
            if self._live_lines:
                try:
                    self.query_one("#live", Static).update(
                        "\n".join(self._live_lines[-12:]) + "\n· done"
                    )
                except Exception:  # noqa: BLE001
                    pass
            else:
                try:
                    self.query_one("#live", Static).update("idle")
                except Exception:  # noqa: BLE001
                    pass
            self._refresh_status()
            self.query_one("#prompt", Input).focus()

        def action_interrupt(self) -> None:
            try:
                from .codex_backend import request_codex_cancel

                request_codex_cancel()
            except Exception:  # noqa: BLE001
                pass
            self._append_md(f"**stop** requested")
            self._busy = False

        def action_show_help(self) -> None:
            self._submit("/help")

    try:
        # mouse=False → terminal native select/copy (Textual won't eat clicks).
        HackbotTUI().run(mouse=False)
    finally:
        live_feed.set_feed_sink(None)
        set_tui_console_mute(False)
        try:
            from . import ui

            ui.console.file = sys.stderr  # type: ignore[misc]
            ui.console.quiet = False
        except Exception:  # noqa: BLE001
            pass
    return 0
