"""hackbot Textual TUI — single scrollable chat (no sidebar, one live stream).

Run: ``python -m hackbot tui``
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

_BG = "#0D0D26"
_PANEL = "#191970"
_BORDER = "#4B0082"
_PRIMARY = "#8A2BE2"
_SECONDARY = "#7B68EE"
_TEXT = "#E8E8FF"
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
        from textual.containers import Vertical, VerticalScroll
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
            height: 1;
            background: {_PANEL};
            color: {_INFO};
            padding: 0 1;
        }}
        #chat {{
            height: 1fr;
            background: {_BG};
            padding: 0 1;
            scrollbar-size: 1 1;
            scrollbar-background: {_BG};
            scrollbar-color: {_BORDER};
            scrollbar-color-hover: {_PRIMARY};
            scrollbar-color-active: {_PRIMARY};
        }}
        .msg-user {{
            color: {_INFO};
            text-style: bold;
            margin-top: 1;
        }}
        .msg-md {{
            color: {_TEXT};
            margin-bottom: 1;
        }}
        .msg-live {{
            color: {_SECONDARY};
        }}
        #composer {{
            dock: bottom;
            height: auto;
            background: {_PANEL};
            border-top: tall {_BORDER};
            padding: 0 1;
        }}
        #picker {{
            height: 5;
            max-height: 5;
            border: tall {_BORDER};
            background: {_PANEL};
            display: none;
        }}
        #picker.visible {{
            display: block;
        }}
        #prompt {{
            height: 3;
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
            Binding("ctrl+y", "copy_last", "copy", show=True),
            Binding("pageup", "scroll_up", "scroll↑", show=False),
            Binding("pagedown", "scroll_down", "scroll↓", show=False),
            Binding("ctrl+u", "scroll_up", "scroll↑", show=False),
            Binding("ctrl+d", "scroll_down", "scroll↓", show=False),
        ]

        def __init__(self) -> None:
            super().__init__()
            self._busy = False
            self._picker_cmds: list[str] = []
            self._msg_i = 0
            self._last_plain: str = ""
            self._think_buf: str = ""
            self._live_widget_id: str | None = None  # single updating live line in chat
            self._feed_dirty = False

        def compose(self) -> ComposeResult:
            yield Static(_status_line(), id="topbar")
            yield VerticalScroll(id="chat")
            with Vertical(id="composer"):
                yield OptionList(id="picker")
                yield Input(placeholder="Message…  (/ cmds · PgUp/PgDn scroll)", id="prompt")
            yield Footer()

        def on_mount(self) -> None:
            live_feed.set_feed_sink(self._mark_feed)
            self.set_interval(0.1, self._pump_feed)
            self._append_md(
                "**hackbot** — `/provider` `/model` `/effort` `/target` · "
                "PgUp/PgDn or mouse wheel to scroll · `ctrl+y` copy last"
            )
            self.query_one("#prompt", Input).focus()

        def on_unmount(self) -> None:
            live_feed.set_feed_sink(None)

        def _chat(self) -> VerticalScroll:
            return self.query_one("#chat", VerticalScroll)

        def action_scroll_up(self) -> None:
            self._chat().scroll_page_up(animate=False)

        def action_scroll_down(self) -> None:
            self._chat().scroll_page_down(animate=False)

        def _mark_feed(self, _kind: str, _text: str) -> None:
            self._feed_dirty = True

        def _pump_feed(self) -> None:
            events = live_feed.drain_pending()
            if not events and not self._feed_dirty:
                return
            self._feed_dirty = False
            for kind, text in events:
                self._ingest_live(kind, text)

        def _ensure_live_line(self) -> Static:
            chat = self._chat()
            if self._live_widget_id:
                try:
                    return self.query_one(f"#{self._live_widget_id}", Static)
                except Exception:  # noqa: BLE001
                    self._live_widget_id = None
            self._msg_i += 1
            self._live_widget_id = f"live{self._msg_i}"
            w = Static("◌ …", classes="msg-live", id=self._live_widget_id)
            chat.mount(w)
            chat.scroll_end(animate=False)
            return w

        def _ingest_live(self, kind: str, text: str) -> None:
            """One place only: update a single live line inside the chat scroll."""
            if not self._busy:
                return
            kind = (kind or "info").strip().lower()
            text = text or ""
            if kind in {"think", "thinking", "reasoning"}:
                if text.startswith("(thinking)"):
                    self._think_buf = text
                else:
                    self._think_buf = (self._think_buf + text)[-1500:]
                display = self._think_buf.replace("\n", " ").strip()
                if len(display) > 240:
                    display = "…" + display[-237:]
                line = f"think  {display}"
            elif kind == "draft":
                flat = text.replace("\n", " ").strip()
                if len(flat) > 240:
                    flat = "…" + flat[-237:]
                line = f"draft  {flat}"
            else:
                if not text.strip():
                    return
                label = {
                    "tool": "tool",
                    "run": "run",
                    "out": "out",
                    "working": "···",
                    "info": "·",
                    "log": "log",
                    "dbg": "dbg",
                    "plan": "plan",
                    "err": "err",
                }.get(kind, kind[:8] or "·")
                # Sticky lines for tools/runs — append new Static; think/draft reuse one widget
                if label in {"tool", "run", "out", "err"}:
                    self._append_live_pin(f"{label}  {text.strip()[:200]}")
                    return
                line = f"{label}  {text.strip()[:200]}"
            w = self._ensure_live_line()
            w.update(f"◌ {line}")
            self._chat().scroll_end(animate=False)

        def _append_live_pin(self, line: str) -> None:
            """Pin a completed tool/run line, then keep the updating live widget below."""
            chat = self._chat()
            # Detach updating widget id so the next ensure creates a fresh one under pins
            old_id = self._live_widget_id
            self._msg_i += 1
            chat.mount(Static(f"· {line}", classes="msg-live", id=f"pin{self._msg_i}"))
            if old_id:
                try:
                    self.query_one(f"#{old_id}", Static).remove()
                except Exception:  # noqa: BLE001
                    pass
                self._live_widget_id = None
            self._ensure_live_line().update("◌ …")
            chat.scroll_end(animate=False)

        def _clear_live(self) -> None:
            self._think_buf = ""
            live_feed.clear()
            if self._live_widget_id:
                try:
                    self.query_one(f"#{self._live_widget_id}", Static).remove()
                except Exception:  # noqa: BLE001
                    pass
                self._live_widget_id = None

        def _refresh_status(self) -> None:
            self.query_one("#topbar", Static).update(_status_line())
            self.sub_title = str(Path.cwd())

        def _append_user(self, text: str) -> None:
            chat = self._chat()
            self._msg_i += 1
            chat.mount(Static(f"› {text}", classes="msg-user", id=f"u{self._msg_i}"))
            chat.scroll_end(animate=False)

        def _append_md(self, text: str) -> None:
            chat = self._chat()
            self._msg_i += 1
            plain = text or "(empty)"
            chat.mount(Markdown(plain, classes="msg-md", id=f"m{self._msg_i}"))
            self._last_plain = plain
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
                self.notify("copied", severity="information", timeout=2)
            else:
                self.notify("copy failed", severity="warning", timeout=3)

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
            top = matches[:8]
            self._picker_cmds = [c for c, _ in top]
            for i, (cmd, desc) in enumerate(top):
                picker.add_option(Option(f"{cmd}  —  {desc}", id=f"cmd-{i}"))
            picker.display = True
            picker.add_class("visible")

        def on_input_changed(self, event: Input.Changed) -> None:
            if event.input.id != "prompt":
                return
            if event.value.startswith("/"):
                self._show_picker(event.value)
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
                    chat = self._chat()
                    for child in list(chat.children):
                        child.remove()
                    self._live_widget_id = None
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
            self._clear_live()
            self._ensure_live_line().update("◌ working…")
            self.query_one("#topbar", Static).update(f"{_status_line()} · working…")
            self.run_hunt_turn(text)

        @work(thread=True, exclusive=True, exit_on_error=False)
        def run_hunt_turn(self, text: str) -> None:
            with _silence_stdio():
                try:
                    answer = run_bridged_turn(text)
                except Exception as exc:  # noqa: BLE001
                    answer = f"**Error:** `{type(exc).__name__}: {exc}`"
            self.call_from_thread(self._finish_turn, answer or "(empty)")

        def _finish_turn(self, answer: str) -> None:
            for kind, text in live_feed.drain_pending():
                self._ingest_live(kind, text)
            self._busy = False
            self._clear_live()
            self._append_md(answer)
            self._refresh_status()
            self.query_one("#prompt", Input).focus()

        def action_interrupt(self) -> None:
            try:
                from .codex_backend import request_codex_cancel

                request_codex_cancel()
            except Exception:  # noqa: BLE001
                pass
            self._busy = False
            self._clear_live()
            self._append_md("**stop** requested")

        def action_show_help(self) -> None:
            self._submit("/help")

    try:
        # mouse=True → wheel scroll works. Copy last reply with ctrl+y.
        HackbotTUI().run(mouse=True)
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
