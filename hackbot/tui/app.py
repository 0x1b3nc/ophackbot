"""HackbotTUI App — Header, chat scroll, composer + Send, Footer."""

from __future__ import annotations

import os
import sys
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator, TextIO

from textual import on, work
from textual.app import App, ComposeResult
from textual.binding import Binding
from textual.containers import Horizontal, Vertical, VerticalScroll
from textual.widgets import Button, Footer, Header, OptionList, Static, TextArea
from textual.widgets.option_list import Option

from .. import live_feed
from ..clipboard import clean_clipboard
from ..clipboard import copy_text as clipboard_copy
from ..clipboard import read_text as clipboard_read
from ..session import get_active, status_line
from ..tui_commands import filter_slash_commands, handle_slash
from ..turn_bridge import resolve_mode, run_bridged_turn
from ..yolo import is_yolo
from .chat import plain_text
from .composer import PromptArea
from .run_block import RunBlock, parse_out_payload
from .theme import (
    BG,
    BORDER,
    INFO,
    LIVE_DRAFT_CHARS,
    LIVE_OUT_CHARS,
    LIVE_THINK_CHARS,
    PANEL,
    PRIMARY,
    SECONDARY,
    TEXT,
)
from .widgets import CopyableStatic, ReplyMarkdown

# Cap chat DOM — unbounded RunBlocks/pins during long hunts thrash VMs.
_MAX_CHAT_WIDGETS = 100
_MAX_PLAIN_CHARS = 8_000


def status_line_text() -> str:
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
def silence_stdio() -> Iterator[None]:
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


class HackbotTUI(App[None]):
    """Full-bleed chat TUI.

    Hunt turns run on a ``@work(thread=True)`` worker. The worker must not
    touch widgets directly — it finishes via ``call_from_thread``. Live
    ``ui.*`` output is mirrored through ``live_feed``; the UI thread polls
    pending events every 100ms (safe across threads).
    """

    TITLE = "hackbot"
    SUB_TITLE = str(Path.cwd())
    ENABLE_COMMAND_PALETTE = False

    CSS = f"""
    Screen {{
        background: {BG};
        color: {TEXT};
        layout: vertical;
        overflow: hidden;
    }}
    Header {{
        background: {PANEL};
        color: {INFO};
    }}
    #status {{
        height: 1;
        width: 100%;
        background: {PANEL};
        color: {INFO};
        padding: 0 1;
    }}
    #chat {{
        height: 1fr;
        width: 100%;
        background: {BG};
        padding: 0 1;
        overflow-y: auto;
        scrollbar-size-vertical: 2;
        scrollbar-background: {BG};
        scrollbar-color: {BORDER};
        scrollbar-color-hover: {PRIMARY};
        scrollbar-color-active: {SECONDARY};
    }}
    .msg-user {{
        width: 100%;
        color: {INFO};
        text-style: bold;
        margin-top: 1;
    }}
    .msg-md {{
        width: 100%;
        color: {TEXT};
        margin-bottom: 1;
    }}
    .msg-out {{
        width: 100%;
        height: auto;
        color: {TEXT};
        padding: 0 1;
        text-wrap: wrap;
    }}
    .msg-live {{
        width: 100%;
        height: auto;
        color: {SECONDARY};
        margin: 1 0;
        text-wrap: wrap;
    }}
    .msg-bot {{
        margin: 1 0;
    }}
    #composer {{
        width: 100%;
        height: auto;
        background: {PANEL};
        border-top: tall {BORDER};
        padding: 0 1 1 1;
        layout: vertical;
    }}
    #picker {{
        width: 100%;
        height: 5;
        max-height: 5;
        border: tall {BORDER};
        background: {PANEL};
        display: none;
    }}
    #picker.visible {{
        display: block;
    }}
    #composer-row {{
        height: auto;
        width: 100%;
        layout: horizontal;
    }}
    #prompt {{
        width: 1fr;
        height: 7;
        min-height: 5;
        max-height: 12;
        background: {BG};
        border: tall {PRIMARY};
        color: {TEXT};
        padding: 0 1;
        margin: 0;
    }}
    #prompt:focus {{
        border: tall {SECONDARY};
    }}
    #send {{
        width: 12;
        min-width: 10;
        height: 7;
        margin-left: 1;
        background: {PRIMARY};
        color: {TEXT};
        border: tall {BORDER};
        content-align: center middle;
    }}
    #send:hover {{
        background: {SECONDARY};
    }}
    Footer {{
        width: 100%;
        background: {PANEL};
        color: {SECONDARY};
    }}
    """

    BINDINGS = [
        Binding("ctrl+c", "interrupt", "stop", show=True),
        Binding("ctrl+q", "quit", "quit", show=True),
        Binding("f1", "show_help", "help", show=True),
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

    # Overridable in tests — avoid real model calls.
    turn_runner = staticmethod(run_bridged_turn)

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
        self._active_run_id: str | None = None
        self._saw_stream_notes = False

    def compose(self) -> ComposeResult:
        yield Header(show_clock=False)
        yield Static(status_line_text(), id="status")
        yield VerticalScroll(id="chat")
        with Vertical(id="composer"):
            yield OptionList(id="picker")
            with Horizontal(id="composer-row"):
                yield PromptArea(
                    soft_wrap=True,
                    tab_behavior="indent",
                    show_line_numbers=False,
                    placeholder="Message…  Enter newline · Ctrl+J send · F2 copy",
                    id="prompt",
                )
                yield Button("Send", id="send", variant="primary")
        yield Footer()

    def on_mount(self) -> None:
        live_feed.set_feed_sink(self._mark_feed)
        self.set_interval(0.1, self._pump_feed)
        self._append_md(
            "**hackbot** — `/provider` `/model` `/effort` `/target`\n\n"
            "_**Newline:** `Enter`. **Send:** `Ctrl+J` or the **Send** button "
            "(`Ctrl+Enter` only on Kitty/Ghostty/Windows Terminal — "
            "Kali's default terminal maps it to nothing useful). "
            "**Copy:** click a stream/tool block, or `F2` / `/copy` for the last reply "
            "(Markdown headings are not click-to-copy). "
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
        chat = self._chat()
        try:
            return int(chat.max_scroll_y) - int(chat.scroll_y) <= slack
        except Exception:  # noqa: BLE001
            return True

    def _maybe_scroll_end(self, *, force: bool = False) -> None:
        if force or self._near_bottom():
            self._chat().scroll_end(animate=False)

    def _remember_plain(self, text: str) -> None:
        blob = text or ""
        if len(blob) > _MAX_PLAIN_CHARS:
            blob = blob[:_MAX_PLAIN_CHARS] + "\n…"
        self._chat_plain.append(blob)
        if len(self._chat_plain) > 200:
            self._chat_plain = self._chat_plain[-200:]

    def _prune_chat(self) -> None:
        """Drop oldest durable widgets so long hunts don't balloon Textual DOM/RAM."""
        chat = self._chat()
        kids = [c for c in list(chat.children) if getattr(c, "id", None) != self._live_widget_id]
        overflow = len(kids) - _MAX_CHAT_WIDGETS
        if overflow <= 0:
            return
        for child in kids[:overflow]:
            try:
                child.remove()
            except Exception:  # noqa: BLE001
                pass

    def action_scroll_up(self) -> None:
        self._chat().scroll_page_up(animate=False)

    def action_scroll_down(self) -> None:
        self._chat().scroll_page_down(animate=False)

    def action_scroll_top(self) -> None:
        self._chat().scroll_home(animate=False)

    def action_scroll_bottom(self) -> None:
        self._chat().scroll_end(animate=False)

    def _mark_feed(self, _kind: str, _text: str) -> None:
        """Called from any thread via live_feed.emit — only flip a flag."""
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
        w = CopyableStatic(
            "◌ …", plain="◌ …", classes="msg-live", id=self._live_widget_id
        )
        chat.mount(w)
        self._maybe_scroll_end()
        return w

    def _ingest_live(self, kind: str, text: str) -> None:
        if not self._busy:
            return
        kind = (kind or "info").strip().lower()
        text = text or ""
        # Mid-turn assistant narration — durable Markdown bubble (no click-copy).
        if kind in {"note", "answer", "assistant"}:
            body = (text or "").strip()
            if not body:
                return
            self._saw_stream_notes = True
            self._active_run_id = None
            self._append_md(body)
            self._ensure_live_line().update("◌ …")
            return
        if kind in {"think", "thinking", "reasoning"}:
            if text.startswith("(thinking)"):
                self._think_buf = text
            else:
                self._think_buf = (self._think_buf + text)[-LIVE_THINK_CHARS:]
            display = plain_text(self._think_buf).replace("\n", " ").strip()
            if len(display) > 320:
                display = "…" + display[-317:]
            line = f"think  {display}"
        elif kind == "draft":
            flat = plain_text(text).replace("\n", " ").strip()
            if len(flat) > LIVE_DRAFT_CHARS:
                flat = "…" + flat[-(LIVE_DRAFT_CHARS - 1) :]
            line = f"draft  {flat}"
        else:
            if not text.strip():
                return
            # Codex emits "out/ok", "out/fail" — treat as "out".
            base = kind.split("/", 1)[0]
            mark = kind.split("/", 1)[1] if "/" in kind else ""
            label = {
                "tool": "tool",
                "run": "run",
                "out": "out",
                "panel": "panel",
                "working": "···",
                "info": "·",
                "log": "log",
                "dbg": "dbg",
                "plan": "plan",
                "err": "err",
            }.get(base, base[:8] or "·")
            body = text.strip()
            if label == "run":
                self._append_run_block(body)
                return
            if label == "panel":
                self._append_panel_block(body)
                return
            if label in {"out", "tool", "err", "log"}:
                if len(body) > LIVE_OUT_CHARS:
                    omitted = len(body) - LIVE_OUT_CHARS
                    body = body[:LIVE_OUT_CHARS] + f"\n… (+{omitted} chars)"
                if label == "out":
                    self._fill_run_output(body, mark=mark)
                    return
                prefix = "ok" if body.startswith("[ok]") or mark == "ok" else (
                    "fail" if body.startswith("[fail]") or mark == "fail" else "tool"
                )
                shown = body
                for p in ("[ok]", "[fail]", "[run]"):
                    if shown.startswith(p):
                        shown = shown[len(p) :].strip()
                tag = {"ok": "ok", "fail": "fail"}.get(prefix, "tool")
                self._append_live_pin(f"{tag}  {shown}", raw=True)
                return
            body = plain_text(body)
            if len(body) > 500:
                body = body[:500] + "…"
            line = f"{label}  {body}"
        w = self._ensure_live_line()
        w.update(f"◌ {line}")
        self._maybe_scroll_end()

    def _append_run_block(self, cmd: str) -> None:
        """Cursor-style run: ``$ cmd`` + folded output when it arrives."""
        chat = self._chat()
        old_id = self._live_widget_id
        self._msg_i += 1
        run_id = f"run{self._msg_i}"
        chat.mount(RunBlock(cmd, id=run_id))
        self._remember_plain(f"$ {cmd}")
        self._active_run_id = run_id
        if old_id:
            try:
                self.query_one(f"#{old_id}", Static).remove()
            except Exception:  # noqa: BLE001
                pass
            self._live_widget_id = None
        self._ensure_live_line().update("◌ …")
        self._prune_chat()
        self._maybe_scroll_end()

    def _append_panel_block(self, text: str) -> None:
        """Titled dump (surface_map, args, …) — never merges into an open run."""
        title, _, body = (text or "").partition("\n")
        title = (title or "panel").strip() or "panel"
        body = body.lstrip("\n")
        chat = self._chat()
        old_id = self._live_widget_id
        self._msg_i += 1
        panel_id = f"panel{self._msg_i}"
        chat.mount(RunBlock(title, kind="panel", pending_out=body or "(empty)", id=panel_id))
        self._remember_plain(f"{title}\n{body}")
        self._active_run_id = None
        if old_id:
            try:
                self.query_one(f"#{old_id}", Static).remove()
            except Exception:  # noqa: BLE001
                pass
            self._live_widget_id = None
        self._ensure_live_line().update("◌ …")
        self._prune_chat()
        self._maybe_scroll_end()

    def _fill_run_output(self, text: str, *, mark: str = "") -> None:
        """Fill the open RunBlock (preview + fold), or fall back to a pin."""
        exit_s, dur_s, body = parse_out_payload(text)
        if mark == "fail" and exit_s in {"", "0"}:
            exit_s = exit_s or "1"
        if self._active_run_id:
            try:
                block = self.query_one(f"#{self._active_run_id}", RunBlock)
                block.set_output(body or "(no output)", duration=dur_s, exit_code=exit_s)
                self._remember_plain(body or "(no output)")
                # Done with this run — later panels must not overwrite stdout.
                self._active_run_id = None
                self._maybe_scroll_end()
                return
            except Exception:  # noqa: BLE001
                self._active_run_id = None
        self._append_live_pin(f"out  {body or text.strip()}", raw=True)

    def _append_live_pin(self, line: str, *, raw: bool = False) -> None:
        chat = self._chat()
        old_id = self._live_widget_id
        self._msg_i += 1
        pin = line if raw else f"· {line}"
        chat.mount(
            CopyableStatic(
                pin, plain=pin, classes="msg-live", id=f"pin{self._msg_i}"
            )
        )
        self._remember_plain(pin)
        self._active_run_id = None
        if old_id:
            try:
                self.query_one(f"#{old_id}", Static).remove()
            except Exception:  # noqa: BLE001
                pass
            self._live_widget_id = None
        self._ensure_live_line().update("◌ …")
        self._prune_chat()
        self._maybe_scroll_end()

    def _clear_live(self) -> None:
        self._think_buf = ""
        live_feed.clear()
        self._active_run_id = None
        if self._live_widget_id:
            try:
                self.query_one(f"#{self._live_widget_id}", Static).remove()
            except Exception:  # noqa: BLE001
                pass
            self._live_widget_id = None

    def _refresh_status(self) -> None:
        self.query_one("#status", Static).update(status_line_text())
        self.sub_title = str(Path.cwd())

    def _append_user(self, text: str) -> None:
        chat = self._chat()
        self._msg_i += 1
        line = f"› {text}"
        chat.mount(
            CopyableStatic(
                line, plain=line, classes="msg-user", id=f"u{self._msg_i}"
            )
        )
        self._remember_plain(line)
        self._prune_chat()
        self._maybe_scroll_end(force=True)

    def _append_md(self, text: str) -> None:
        chat = self._chat()
        self._msg_i += 1
        plain = text or "(empty)"
        chat.mount(
            ReplyMarkdown(plain, plain=plain, classes="msg-md", id=f"m{self._msg_i}")
        )
        self._last_plain = plain
        self._remember_plain(plain)
        self._prune_chat()
        self._maybe_scroll_end(force=True)

    def _append_bot(self, text: str) -> None:
        self._append_md(text)

    def copy_plain(self, text: str, *, label: str = "text") -> None:
        if self._copy_text(text):
            self.notify(
                f"copied {len((text or '').strip())} chars ({label})",
                severity="information",
                timeout=2,
            )
        else:
            self.notify("copy failed", severity="error", timeout=3)

    def _copy_text(self, text: str) -> bool:
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
            self.notify(
                "cleanclip: clipboard empty or unreadable",
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
        top = matches[:8]
        self._picker_cmds = [c for c, _ in top]
        for i, (cmd, desc) in enumerate(top):
            picker.add_option(Option(f"{cmd}  —  {desc}", id=f"cmd-{i}"))
        picker.display = True
        picker.add_class("visible")

    def on_text_area_changed(self, event: TextArea.Changed) -> None:
        if event.text_area.id != "prompt":
            return
        val = event.text_area.text or ""
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

    @on(Button.Pressed, "#send")
    def on_send_pressed(self) -> None:
        self.submit_composer()

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
        text = clipboard_read()
        if not text:
            self.notify("clipboard empty / unreadable", severity="warning", timeout=3)
            return
        self._prompt().load_text(text)
        self._prompt().focus()
        self.notify(f"pasted {len(text)} chars into composer", severity="information", timeout=2)

    def _reset_cancel_rails(self) -> None:
        try:
            from ..turn_bus import clear_turn_cancel

            clear_turn_cancel()
        except Exception:  # noqa: BLE001
            pass

    def _submit(self, text: str) -> None:
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
        self.query_one("#status", Static).update(f"{status_line_text()} · working…")
        # exclusive=True: one turn at a time (overlapping Codex+tools freezes VMs).
        self.run_hunt_turn(text, gen)

    @work(thread=True, exclusive=True, exit_on_error=False)
    def run_hunt_turn(self, text: str, gen: int) -> None:
        import time as _time

        # Let interrupt killpg settle before clearing cancel for this turn.
        _time.sleep(0.15)
        if gen != self._turn_gen:
            return
        self._reset_cancel_rails()
        with silence_stdio():
            try:
                answer = self.turn_runner(text)
            except Exception as exc:  # noqa: BLE001
                answer = f"Error: {type(exc).__name__}: {exc}"
        self.call_from_thread(self._finish_turn, answer or "(empty)", gen)

    def _finish_turn(self, answer: str, gen: int) -> None:
        if gen != self._turn_gen:
            return
        for kind, text in live_feed.drain_pending():
            self._ingest_live(kind, text)
        self._busy = False
        self._clear_live()
        if self._stop_shown and (answer or "").strip() in {"(cancelled)", "(empty)"}:
            self._refresh_status()
            self._prompt().focus()
            return
        # Mid-turn notes already mounted the latest assistant text — skip duplicate.
        final = (answer or "").strip()
        if final and final != "(empty)":
            last = (self._last_plain or "").strip()
            if final != last:
                self._append_md(final)
        self._refresh_status()
        self._prompt().focus()

    def action_interrupt(self) -> None:
        try:
            from ..turn_bus import get_bus

            bus = get_bus()
            if bus is not None:
                bus.request_interrupt()
            else:
                from .. import turn_bus as tb
                from ..codex_backend import request_codex_cancel
                from ..hunt_controller import request_stop

                request_codex_cancel()
                request_stop()
                tb._GLOBAL_CANCEL.set()
        except Exception:  # noqa: BLE001
            try:
                from ..codex_backend import request_codex_cancel

                request_codex_cancel()
            except Exception:  # noqa: BLE001
                pass
        self._turn_gen += 1
        self._busy = False
        self._clear_live()
        if not self._stop_shown:
            self._append_md("**stop** requested — send a new message to continue")
            self._stop_shown = True
        self.query_one("#status", Static).update(f"{status_line_text()} · stopped")
        self._prompt().focus()

    def action_show_help(self) -> None:
        self._submit("/help")
