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
        }}
        #chat {{
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
        #composer {{
            dock: bottom;
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
        ]

        def __init__(self) -> None:
            super().__init__()
            self._busy = False
            self._picker_cmds: list[str] = []
            self._msg_i = 0

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
                        "Enter send · / cmds",
                        id="side-help",
                    )
                with Vertical(id="main"):
                    yield VerticalScroll(id="chat")
                    with Vertical(id="composer"):
                        yield OptionList(id="picker")
                        yield Input(
                            placeholder="Message hackbot…  (/ for commands)",
                            id="prompt",
                        )
            yield Footer()

        def on_mount(self) -> None:
            self._append_md(
                f"**hackbot** ready\n\n`{_status_line()}`\n\n"
                f"Try `/model grok-4.5` then `/effort high fast`."
            )
            self.query_one("#prompt", Input).focus()

        def _refresh_status(self) -> None:
            self.query_one("#status", Static).update(_status_line())
            self.sub_title = str(Path.cwd())

        def _append_user(self, text: str) -> None:
            chat = self.query_one("#chat", VerticalScroll)
            self._msg_i += 1
            chat.mount(Static(f"› {text}", classes="msg-user", id=f"u{self._msg_i}"))
            chat.scroll_end(animate=False)

        def _append_md(self, text: str) -> None:
            chat = self.query_one("#chat", VerticalScroll)
            self._msg_i += 1
            mid = f"m{self._msg_i}"
            chat.mount(Markdown(text or "(empty)", classes="msg-md", id=mid))
            chat.scroll_end(animate=False)

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
        HackbotTUI().run()
    finally:
        set_tui_console_mute(False)
        try:
            from . import ui

            ui.console.file = sys.stderr  # type: ignore[misc]
            ui.console.quiet = False
        except Exception:  # noqa: BLE001
            pass
    return 0
