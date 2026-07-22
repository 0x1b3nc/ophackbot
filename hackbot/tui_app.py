"""hackbot Textual TUI — full-width chat + scroll that sticks when you read history.

Run: ``python -m hackbot tui``

Layout: status · scrollable chat · multiline composer · footer.
Final replies use Markdown; live stream (think/tool/plan) stays plain text.

Composer is a TextArea (not single-line Input) so multiline paste keeps the
**full** prompt. ``Enter`` sends; ``Shift+Enter`` inserts a newline (Kitty
keyboard protocol — Textual enables it; works in Windows Terminal / Kitty /
WezTerm / Ghostty). ``Ctrl+J`` / ``Alt+Enter`` are fallbacks if Shift+Enter
is indistinguishable from Enter in a given terminal.

Copy: ``F2`` / ``Ctrl+Y`` / ``/copy`` / click message. ``/cleanclip`` after a
messy native select. ``/paste`` loads the OS clipboard into the composer.

Scroll (wheel + scrollbar + PgUp/PgDn) is **always** on. Copy does not
toggle mouse — use F2/click, not terminal-cell select.
"""

from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, TextIO

from . import live_feed
from .clipboard import copy_text as clipboard_copy
from .clipboard import read_text as clipboard_read
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

# Live tool/out pins — keep file dumps readable (was hard-clipped at 200 chars).
_LIVE_OUT_CHARS = 50_000
_LIVE_THINK_CHARS = 2_000
_LIVE_DRAFT_CHARS = 2_000

def _plain_text(text: str) -> str:
    """Strip Markdown markers for live stream lines only (think/tool/plan pins)."""
    import re

    s = text or ""
    # fenced code → keep inner text
    s = re.sub(r"```[a-zA-Z0-9_+-]*\n?", "", s)
    s = s.replace("```", "")
    # headings / bold / italic / inline code (keep content)
    s = re.sub(r"^#{1,6}\s*", "", s, flags=re.M)
    s = re.sub(r"\*\*(.+?)\*\*", r"\1", s)
    s = re.sub(r"__(.+?)__", r"\1", s)
    s = re.sub(r"(?<!\*)\*(?!\*)(.+?)(?<!\*)\*(?!\*)", r"\1", s)
    s = re.sub(r"`([^`]+)`", r"\1", s)
    s = re.sub(r"\[([^\]]+)\]\([^)]+\)", r"\1", s)
    return s.strip()


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
        from textual.events import Click
        from textual.widgets import Footer, Markdown, OptionList, Static, TextArea
        from textual.widgets.option_list import Option
    except ImportError:
        sys.stderr.write("Textual missing. Install:  pip install 'hackbot-kit[tui]'\n")
        return 1

    import io

    from .clipboard import clean_clipboard

    class CopyableStatic(Static):
        """Static that stores plain source text for clean click-to-copy."""

        def __init__(self, renderable: str, *, plain: str, **kwargs) -> None:  # noqa: ANN003
            # markup=False — JSON/tool dumps contain [ ] that Rich markup would eat.
            kwargs.setdefault("markup", False)
            super().__init__(renderable, **kwargs)
            self.plain_source = plain

        def on_click(self, event: Click) -> None:
            event.stop()
            app = self.app
            copy_fn = getattr(app, "copy_plain", None)
            if callable(copy_fn):
                copy_fn(self.plain_source, label="message")

    class CopyableMarkdown(Markdown):
        """Markdown bubble with plain source for clean click-to-copy."""

        def __init__(self, markdown: str, *, plain: str, **kwargs) -> None:  # noqa: ANN003
            super().__init__(markdown, **kwargs)
            self.plain_source = plain

        def on_click(self, event: Click) -> None:
            event.stop()
            app = self.app
            copy_fn = getattr(app, "copy_plain", None)
            if callable(copy_fn):
                copy_fn(self.plain_source, label="message")

    class PromptArea(TextArea):
        """Multiline composer — Enter sends; Shift+Enter = newline.

        Textual's TextArea hardcodes enter→newline in ``_on_key`` (before
        bindings), so we must override that handler or Enter can never send.
        """

        BINDINGS = [
            Binding("enter", "submit_prompt", "send", show=True, priority=True),
            Binding("shift+enter", "newline", "newline", show=True, priority=True),
            Binding("ctrl+j", "newline", "newline", show=False, priority=True),
            Binding("alt+enter", "newline", "newline", show=False, priority=True),
        ]

        async def _on_key(self, event) -> None:  # noqa: ANN001
            """Intercept Enter/Shift+Enter before TextArea inserts a newline."""
            key = getattr(event, "key", "") or ""
            if key == "enter":
                event.stop()
                event.prevent_default()
                self.action_submit_prompt()
                return
            if key in {"shift+enter", "ctrl+j", "alt+enter"}:
                event.stop()
                event.prevent_default()
                self.action_newline()
                return
            await super()._on_key(event)

        def action_submit_prompt(self) -> None:
            submit = getattr(self.app, "submit_composer", None)
            if callable(submit):
                submit()

        def action_newline(self) -> None:
            if self.read_only:
                return
            self.insert("\n")

        def action_paste(self) -> None:
            """Prefer OS clipboard — app.clipboard is often empty / truncated."""
            if self.read_only:
                return
            text = clipboard_read()
            if text is None:
                text = self.app.clipboard or ""
            if not text:
                return
            if result := self._replace_via_keyboard(text, *self.selection):
                self.move_cursor(result.end_location)
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
        # Full-bleed column: nothing side-padded, input width 100%.
        CSS = f"""
        Screen {{
            background: {_BG};
            color: {_TEXT};
            layout: vertical;
            overflow: hidden;
        }}
        #topbar {{
            height: 1;
            width: 100%;
            background: {_PANEL};
            color: {_INFO};
            padding: 0 1;
        }}
        #chat {{
            height: 1fr;
            width: 100%;
            background: {_BG};
            padding: 0 1;
            overflow-y: auto;
            scrollbar-size-vertical: 2;
            scrollbar-background: {_BG};
            scrollbar-color: {_BORDER};
            scrollbar-color-hover: {_PRIMARY};
            scrollbar-color-active: {_SECONDARY};
        }}
        .msg-user {{
            width: 100%;
            color: {_INFO};
            text-style: bold;
            margin-top: 1;
        }}
        .msg-md {{
            width: 100%;
            color: {_TEXT};
            margin-bottom: 1;
        }}
        .msg-live {{
            width: 100%;
            height: auto;
            color: {_SECONDARY};
        }}
        #composer {{
            width: 100%;
            height: auto;
            background: {_PANEL};
            border-top: tall {_BORDER};
            padding: 0;
            layout: vertical;
        }}
        #picker {{
            width: 100%;
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
            width: 100%;
            height: 7;
            min-height: 5;
            max-height: 12;
            background: {_BG};
            border: tall {_PRIMARY};
            color: {_TEXT};
            padding: 0 1;
            margin: 0;
        }}
        #prompt:focus {{
            border: tall {_SECONDARY};
        }}
        Footer {{
            width: 100%;
            background: {_PANEL};
            color: {_SECONDARY};
        }}
        """
        BINDINGS = [
            Binding("ctrl+c", "interrupt", "stop", show=True),
            Binding("ctrl+q", "quit", "quit", show=True),
            Binding("f1", "show_help", "help", show=True),
            # Prefer F2 / Ctrl+Y — Windows Terminal steals Ctrl+Shift+C for itself.
            Binding("f2", "copy_selection", "copy", show=True, priority=True),
            Binding("ctrl+y", "copy_last", "copy last", show=True, priority=True),
            Binding("alt+c", "copy_selection", "copy", show=False, priority=True),
            Binding("ctrl+shift+y", "copy_all", "copy all", show=True, priority=True),
            Binding("ctrl+shift+c", "copy_selection", "copy sel", show=False, priority=True),
            Binding("ctrl+insert", "copy_selection", "copy", show=False, priority=True),
            Binding("f3", "cleanclip", "cleanclip", show=False, priority=True),
            Binding("pageup", "scroll_up", "PgUp", show=True, priority=True),
            Binding("pagedown", "scroll_down", "PgDn", show=True, priority=True),
            Binding("ctrl+u", "scroll_up", "Half↑", show=False, priority=True),
            Binding("ctrl+d", "scroll_down", "Half↓", show=False, priority=True),
            Binding("ctrl+home", "scroll_top", "Top", show=False, priority=True),
            Binding("ctrl+end", "scroll_bottom", "Bottom", show=False, priority=True),
        ]

        def __init__(self) -> None:
            super().__init__()
            self._busy = False
            self._turn_gen = 0
            self._stop_shown = False
            self._picker_cmds: list[str] = []
            self._msg_i = 0
            self._last_plain: str = ""
            self._chat_plain: list[str] = []
            self._think_buf: str = ""
            self._live_widget_id: str | None = None
            self._feed_dirty = False

        def compose(self) -> ComposeResult:
            with Vertical():
                yield Static(_status_line(), id="topbar")
                yield VerticalScroll(id="chat")
                with Vertical(id="composer"):
                    yield OptionList(id="picker")
                    yield PromptArea(
                        soft_wrap=True,
                        tab_behavior="indent",
                        show_line_numbers=False,
                        placeholder=(
                            "Message…  Enter send · Shift+Enter newline · F2 copy · /paste"
                        ),
                        id="prompt",
                    )
            yield Footer()

        def on_mount(self) -> None:
            live_feed.set_feed_sink(self._mark_feed)
            self.set_interval(0.1, self._pump_feed)
            self._append_md(
                "**hackbot** — `/provider` `/model` `/effort` `/target`\n\n"
                "_**Send:** `Enter`. **Newline:** `Shift+Enter` "
                "(fallback `Ctrl+J` / `Alt+Enter` if your terminal can't tell them apart). "
                "**Copy:** `F2` / click message / `/copy`. "
                "**Scroll:** wheel + scrollbar + PgUp/PgDn. "
                "Stop: `ctrl+c` then send a new prompt._"
            )
            self.query_one("#prompt", PromptArea).focus()

        def on_unmount(self) -> None:
            live_feed.set_feed_sink(None)

        def _prompt(self) -> PromptArea:
            return self.query_one("#prompt", PromptArea)

        def _chat(self) -> VerticalScroll:
            return self.query_one("#chat", VerticalScroll)

        def _near_bottom(self, *, slack: int = 4) -> bool:
            """True if the user is already following the bottom of the chat."""
            chat = self._chat()
            try:
                return int(chat.max_scroll_y) - int(chat.scroll_y) <= slack
            except Exception:  # noqa: BLE001
                return True

        def _maybe_scroll_end(self, *, force: bool = False) -> None:
            """Follow new output only if already at bottom (or force=True)."""
            if force or self._near_bottom():
                self._chat().scroll_end(animate=False)

        def action_scroll_up(self) -> None:
            self._chat().scroll_page_up(animate=False)

        def action_scroll_down(self) -> None:
            self._chat().scroll_page_down(animate=False)

        def action_scroll_top(self) -> None:
            self._chat().scroll_home(animate=False)

        def action_scroll_bottom(self) -> None:
            self._chat().scroll_end(animate=False)

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
            w = Static("◌ …", classes="msg-live", id=self._live_widget_id, markup=False)
            chat.mount(w)
            self._maybe_scroll_end()
            return w

        def _ingest_live(self, kind: str, text: str) -> None:
            if not self._busy:
                return
            kind = (kind or "info").strip().lower()
            text = text or ""
            if kind in {"think", "thinking", "reasoning"}:
                if text.startswith("(thinking)"):
                    self._think_buf = text
                else:
                    self._think_buf = (self._think_buf + text)[-_LIVE_THINK_CHARS:]
                display = _plain_text(self._think_buf).replace("\n", " ").strip()
                if len(display) > 320:
                    display = "…" + display[-317:]
                line = f"think  {display}"
            elif kind == "draft":
                flat = _plain_text(text).replace("\n", " ").strip()
                if len(flat) > _LIVE_DRAFT_CHARS:
                    flat = "…" + flat[-(_LIVE_DRAFT_CHARS - 1) :]
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
                body = text.strip()
                # Tool/out dumps: keep raw text (JSON [ ] must not be markdown-stripped).
                if label in {"tool", "run", "out", "err", "log"}:
                    if len(body) > _LIVE_OUT_CHARS:
                        omitted = len(body) - _LIVE_OUT_CHARS
                        body = body[:_LIVE_OUT_CHARS] + f"\n… (+{omitted} chars)"
                    self._append_live_pin(f"{label}  {body}")
                    return
                body = _plain_text(body)
                if len(body) > 500:
                    body = body[:500] + "…"
                line = f"{label}  {body}"
            w = self._ensure_live_line()
            w.update(f"◌ {line}")
            self._maybe_scroll_end()

        def _append_live_pin(self, line: str) -> None:
            chat = self._chat()
            old_id = self._live_widget_id
            self._msg_i += 1
            # Keep newlines so file dumps / shell output stay readable.
            pin = f"· {line}"
            chat.mount(
                Static(pin, classes="msg-live", id=f"pin{self._msg_i}", markup=False)
            )
            self._chat_plain.append(pin)
            if old_id:
                try:
                    self.query_one(f"#{old_id}", Static).remove()
                except Exception:  # noqa: BLE001
                    pass
                self._live_widget_id = None
            self._ensure_live_line().update("◌ …")
            self._maybe_scroll_end()

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
            line = f"› {text}"
            chat.mount(
                CopyableStatic(line, plain=line, classes="msg-user", id=f"u{self._msg_i}")
            )
            self._chat_plain.append(line)
            self._maybe_scroll_end(force=True)

        def _append_md(self, text: str) -> None:
            """Final + slash replies: real Markdown. Live stream stays plain Static."""
            chat = self._chat()
            self._msg_i += 1
            plain = text or "(empty)"
            chat.mount(
                CopyableMarkdown(
                    plain, plain=plain, classes="msg-md", id=f"m{self._msg_i}"
                )
            )
            self._last_plain = plain
            self._chat_plain.append(plain)
            if len(self._chat_plain) > 300:
                self._chat_plain = self._chat_plain[-300:]
            self._maybe_scroll_end(force=True)

        def _append_bot(self, text: str) -> None:
            self._append_md(text)

        def copy_plain(self, text: str, *, label: str = "text") -> None:
            """Copy stored plain source (not terminal cells)."""
            if self._copy_text(text):
                self.notify(
                    f"copied {len((text or '').strip())} chars ({label})",
                    severity="information",
                    timeout=2,
                )
            else:
                self.notify("copy failed", severity="error", timeout=3)

        def _copy_text(self, text: str) -> bool:
            """Best-effort clipboard (OS-native first, then OSC-52, then file)."""
            ok, method = clipboard_copy(
                text or "",
                osc52_write=self.copy_to_clipboard,
            )
            if ok and method.startswith("file:"):
                self.notify(
                    f"clipboard blocked — saved {method[5:]}",
                    severity="warning",
                    timeout=8,
                )
            return ok

        def action_copy_selection(self) -> None:
            # Prefer Textual selection (clean) → else last stored reply (full plain).
            selected = None
            try:
                selected = self.screen.get_selected_text()
            except Exception:  # noqa: BLE001
                selected = None
            if (selected or "").strip():
                text = selected or ""
                kind = "selection"
            else:
                text = self._last_plain or ""
                kind = "last reply"
            if not (text or "").strip():
                self.notify(
                    "nothing to copy — click a message, or F2 after a reply",
                    severity="warning",
                    timeout=4,
                )
                return
            if self._copy_text(text):
                self.notify(
                    f"copied {len(text.strip())} chars ({kind})",
                    severity="information",
                    timeout=2,
                )
            else:
                self.notify("copy failed", severity="error", timeout=3)

        def action_copy_last(self) -> None:
            if self._copy_text(self._last_plain):
                self.notify("copied last reply", severity="information", timeout=2)
            else:
                self.notify("nothing to copy yet", severity="warning", timeout=3)

        def action_copy_all(self) -> None:
            blob = "\n\n".join(self._chat_plain).strip()
            if self._copy_text(blob):
                self.notify("copied full chat", severity="information", timeout=2)
            else:
                self.notify("copy failed", severity="warning", timeout=3)

        def action_cleanclip(self) -> None:
            ok, method, before, after = clean_clipboard()
            if ok:
                self.notify(
                    f"cleaned clipboard {before}→{after} chars ({method})",
                    severity="information",
                    timeout=3,
                )
            else:
                self.notify("cleanclip: clipboard empty or unreadable", severity="warning", timeout=3)

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

        def on_text_area_changed(self, event: TextArea.Changed) -> None:
            if event.text_area.id != "prompt":
                return
            # Slash picker only for a single-line /command draft
            val = (event.text_area.text or "")
            first = val.splitlines()[0] if val else ""
            if first.startswith("/") and "\n" not in val.strip():
                self._show_picker(first)
            else:
                self._hide_picker()

        def on_option_list_option_selected(self, event: OptionList.OptionSelected) -> None:
            idx = event.option_index
            if not (0 <= idx < len(self._picker_cmds)):
                return
            cmd = self._picker_cmds[idx].rstrip()
            prompt = self._prompt()
            if cmd in {"/target", "/provider", "/model", "/effort", "/hunt"} or self._picker_cmds[
                idx
            ].endswith(" "):
                prompt.load_text(cmd + " ")
            else:
                prompt.load_text(cmd)
            prompt.focus()
            self._hide_picker()

        def action_submit_composer(self) -> None:
            self.submit_composer()

        def submit_composer(self) -> None:
            prompt = self._prompt()
            text = (prompt.text or "").strip()
            prompt.load_text("")
            self._hide_picker()
            if not text:
                return
            if self._busy:
                self.action_interrupt()
            self._submit(text)

        def action_load_clipboard(self) -> None:
            """Fill composer from OS clipboard (full multiline)."""
            text = clipboard_read()
            if not text:
                self.notify("clipboard empty / unreadable", severity="warning", timeout=3)
                return
            self._prompt().load_text(text)
            self._prompt().focus()
            self.notify(f"pasted {len(text)} chars into composer", severity="information", timeout=2)

        def _reset_cancel_rails(self) -> None:
            """Must run before every new turn — otherwise post-Ctrl+C stays cancelled."""
            try:
                from .turn_bus import clear_turn_cancel

                clear_turn_cancel()
            except Exception:  # noqa: BLE001
                pass

        def _submit(self, text: str) -> None:
            # Local copy commands — never send to the model
            low = text.strip().lower()
            if low in {"/copy", "/copy last", "/copy l"}:
                self.action_copy_last()
                return
            if low in {"/copy all", "/copy a", "/copy full"}:
                self.action_copy_all()
                return
            if low in {"/copy sel", "/copy selection", "/copy s"}:
                self.action_copy_selection()
                return
            if low in {"/cleanclip", "/clipclean", "/copy clean"}:
                self.action_cleanclip()
                return
            if low in {"/paste", "/clip"}:
                self.action_load_clipboard()
                return

            self._append_user(text)
            if text.startswith("/") and "\n" not in text.strip():
                result = handle_slash(text)
                if result.exit_app:
                    self.exit()
                    return
                if result.clear_chat:
                    chat = self._chat()
                    for child in list(chat.children):
                        child.remove()
                    self._live_widget_id = None
                    self._chat_plain = []
                    self._append_md("_cleared_")
                    self._refresh_status()
                    return
                if result.handled:
                    for msg in result.messages:
                        self._append_md(msg)
                    if result.refresh_status:
                        self._refresh_status()
                    return
            self._reset_cancel_rails()
            self._stop_shown = False
            self._turn_gen += 1
            gen = self._turn_gen
            self._busy = True
            self._clear_live()
            self._ensure_live_line().update("◌ working…")
            self.query_one("#topbar", Static).update(f"{_status_line()} · working…")
            # exclusive=False so a new turn can start after interrupt (stale finish ignored)
            self.run_hunt_turn(text, gen)

        @work(thread=True, exclusive=False, exit_on_error=False)
        def run_hunt_turn(self, text: str, gen: int) -> None:
            with _silence_stdio():
                try:
                    answer = run_bridged_turn(text)
                except Exception as exc:  # noqa: BLE001
                    answer = f"Error: {type(exc).__name__}: {exc}"
            self.call_from_thread(self._finish_turn, answer or "(empty)", gen)

        def _finish_turn(self, answer: str, gen: int) -> None:
            # Ignore stale worker after Ctrl+C + new prompt
            if gen != self._turn_gen:
                return
            for kind, text in live_feed.drain_pending():
                self._ingest_live(kind, text)
            self._busy = False
            self._clear_live()
            # Don't re-print cancelled if we already showed **stop**
            if self._stop_shown and (answer or "").strip() in {"(cancelled)", "(empty)"}:
                self._refresh_status()
                self._prompt().focus()
                return
            self._append_md(answer)
            self._refresh_status()
            self._prompt().focus()

        def action_interrupt(self) -> None:
            try:
                from .turn_bus import get_bus

                bus = get_bus()
                if bus is not None:
                    bus.request_interrupt()
                else:
                    from . import turn_bus as tb
                    from .codex_backend import request_codex_cancel
                    from .hunt_controller import request_stop

                    request_codex_cancel()
                    request_stop()
                    tb._GLOBAL_CANCEL.set()
            except Exception:  # noqa: BLE001
                try:
                    from .codex_backend import request_codex_cancel

                    request_codex_cancel()
                except Exception:  # noqa: BLE001
                    pass
            # Invalidate in-flight finish + free the composer for a new prompt
            self._turn_gen += 1
            self._busy = False
            self._clear_live()
            if not self._stop_shown:
                self._append_md("**stop** requested — send a new message to continue")
                self._stop_shown = True
            self.query_one("#topbar", Static).update(f"{_status_line()} · stopped")
            self._prompt().focus()

        def action_show_help(self) -> None:
            self._submit("/help")

    try:
        # Mouse always on — scroll/wheel/scrollbar must not depend on copy mode.
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
