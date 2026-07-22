"""hackbot Textual TUI — our brand, our slash commands.

Run: ``python -m hackbot tui``
"""

from __future__ import annotations

import os
import sys
from pathlib import Path

from .operator_gate import set_tui_console_mute
from .session import get_active, status_line
from .tui_commands import filter_slash_commands, handle_slash
from .turn_bridge import resolve_mode, run_bridged_turn
from .yolo import enable_yolo, is_yolo


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


def _write_md(chat: object, text: str) -> None:
    """Write Markdown (or plain) into a RichLog without leaking Rich markup."""
    from rich.markdown import Markdown

    body = (text or "").rstrip()
    if not body:
        return
    # RichLog.renderable accepts Rich renderables
    chat.write(Markdown(body, code_theme="monokai"))  # type: ignore[attr-defined]


def start_tui() -> int:
    try:
        from textual import work
        from textual.app import App, ComposeResult
        from textual.binding import Binding
        from textual.containers import Horizontal, Vertical
        from textual.widgets import Footer, Header, Input, OptionList, RichLog, Static
        from textual.widgets.option_list import Option
    except ImportError:
        from . import ui

        ui.error("Textual missing. Install:  pip install 'hackbot-kit[tui]'")
        return 1

    # Keep Rich banners off the screen the TUI owns.
    os.environ.setdefault("HACKBOT_PLAIN", "1")
    set_tui_console_mute(True)
    try:
        from . import ui

        ui.console.file = sys.stderr  # type: ignore[misc]
        ui.console.quiet = True
    except Exception:  # noqa: BLE001
        pass

    if not is_yolo():
        enable_yolo(quiet=True)

    class HackbotTUI(App[None]):
        TITLE = "hackbot"
        SUB_TITLE = str(Path.cwd())
        ENABLE_COMMAND_PALETTE = False
        CSS = """
        Screen {
            background: #0a0a0c;
        }
        #sidebar {
            width: 26;
            background: #141416;
            border-right: solid #232328;
            padding: 1 1;
        }
        #brand {
            color: #d4a574;
            text-style: bold;
            padding-bottom: 1;
        }
        #side-help {
            color: #6b6b76;
        }
        #status {
            dock: top;
            height: 1;
            background: #141416;
            color: #a0a0ab;
            padding: 0 1;
        }
        #chat {
            background: #0a0a0c;
            border: none;
            padding: 0 1;
            scrollbar-size-vertical: 1;
        }
        #picker {
            height: 10;
            border: solid #2a2a2f;
            background: #1a1a1e;
            display: none;
        }
        #picker.visible {
            display: block;
        }
        #prompt {
            dock: bottom;
            margin: 0 1 1 1;
            background: #1a1a1e;
            border: solid #2a2a2f;
        }
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

        def compose(self) -> ComposeResult:
            yield Header(show_clock=False)
            yield Static(_status_line(), id="status")
            with Horizontal():
                with Vertical(id="sidebar"):
                    yield Static("hackbot", id="brand")
                    yield Static(
                        "Authorized hunt\n\n"
                        "/help\n"
                        "/target demo\n"
                        "/provider cursor\n"
                        "/model grok-4.5\n"
                        "/effort high fast\n"
                        "/yolo on\n\n"
                        "Enter = send\n"
                        "/ = commands",
                        id="side-help",
                    )
                with Vertical():
                    yield RichLog(
                        id="chat",
                        markup=True,
                        wrap=True,
                        highlight=False,
                        auto_scroll=True,
                    )
                    yield OptionList(id="picker")
                    yield Input(
                        placeholder="Message hackbot…  (/ for commands)",
                        id="prompt",
                    )
            yield Footer()

        def on_mount(self) -> None:
            chat = self.query_one("#chat", RichLog)
            chat.can_focus = False
            chat.write("[bold #d4a574]hackbot[/] ready")
            _write_md(chat, f"_{_status_line()}_")
            self.query_one("#prompt", Input).focus()

        def _refresh_status(self) -> None:
            self.query_one("#status", Static).update(_status_line())
            self.sub_title = str(Path.cwd())

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
            chat = self.query_one("#chat", RichLog)
            chat.write(f"[bold #ececee]›[/] {text}")
            if text.startswith("/"):
                result = handle_slash(text)
                if result.exit_app:
                    self.exit()
                    return
                if result.clear_chat:
                    chat.clear()
                    chat.write("[dim]cleared[/]")
                    self._refresh_status()
                    return
                if result.handled:
                    for msg in result.messages:
                        _write_md(chat, msg)
                    if result.refresh_status:
                        self._refresh_status()
                    return
            self._busy = True
            self.run_hunt_turn(text)

        @work(thread=True, exclusive=True, exit_on_error=False)
        def run_hunt_turn(self, text: str) -> None:
            try:
                answer = run_bridged_turn(text)
            except Exception as exc:  # noqa: BLE001
                answer = f"Error: {type(exc).__name__}: {exc}"
            self.call_from_thread(self._finish_turn, answer or "(empty)")

        def _finish_turn(self, answer: str) -> None:
            self._busy = False
            chat = self.query_one("#chat", RichLog)
            _write_md(chat, answer)
            self._refresh_status()
            self.query_one("#prompt", Input).focus()

        def action_interrupt(self) -> None:
            try:
                from .codex_backend import request_codex_cancel

                request_codex_cancel()
            except Exception:  # noqa: BLE001
                pass
            self.query_one("#chat", RichLog).write("[yellow]stop requested[/]")
            self._busy = False

        def action_show_help(self) -> None:
            self._submit("/help")

    try:
        HackbotTUI().run()
    finally:
        set_tui_console_mute(False)
        try:
            from . import ui

            ui.console.quiet = False
        except Exception:  # noqa: BLE001
            pass
    return 0
