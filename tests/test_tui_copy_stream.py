"""CopyableStatic + Cursor-style RunBlock fold/fill."""

from __future__ import annotations

import pytest

textual = pytest.importorskip("textual")

from hackbot.tui.run_block import (  # noqa: E402
    RunBlock,
    fold_output,
    format_duration_ms,
    parse_out_payload,
)
from hackbot.tui.widgets import CopyableStatic  # noqa: E402


def test_copyable_static_update_syncs_plain() -> None:
    w = CopyableStatic("◌ …", plain="◌ …")
    assert w.plain_source == "◌ …"
    w.update('· out  {"a": 1}')
    assert w.plain_source == '· out  {"a": 1}'


def test_fold_output_short_stays_open() -> None:
    preview, hidden = fold_output("a\nb\nc")
    assert hidden == 0
    assert preview == "a\nb\nc"


def test_fold_output_long_hides_tail() -> None:
    text = "\n".join(f"line{i}" for i in range(20))
    preview, hidden = fold_output(text)
    assert hidden == 16
    assert "line0" in preview
    assert "line19" not in preview
    assert "lines hidden" not in preview


def test_parse_out_payload_meta() -> None:
    exit_s, dur_s, body = parse_out_payload("exit=0 dur=348ms\nhello\nworld")
    assert exit_s == "0"
    assert dur_s == "348ms"
    assert body == "hello\nworld"


def test_format_duration_ms() -> None:
    assert format_duration_ms(348) == "348ms"
    assert format_duration_ms(1900) == "1.9s"
    assert format_duration_ms(11_000) == "11s"


@pytest.mark.asyncio
async def test_run_out_fills_run_block(monkeypatch: pytest.MonkeyPatch) -> None:
    """out/ok must land in the open RunBlock — not be dropped as unknown kind."""
    from hackbot.tui.app import HackbotTUI

    app = HackbotTUI()
    monkeypatch.setattr(HackbotTUI, "turn_runner", staticmethod(lambda t: "done"))
    async with app.run_test() as pilot:
        app._busy = True
        app._ingest_live("run", "echo hello")
        await pilot.pause()
        run_id = app._active_run_id
        assert run_id, "run block should track id"
        app._ingest_live("out/ok", "exit=0 dur=12ms\nhello\nworld")
        await pilot.pause()
        assert app._active_run_id is None, "run slot clears after out"
        block = app.query_one(f"#{run_id}", RunBlock)
        assert block.duration == "12ms"
        assert "hello" in block.full_out
        assert "world" in block.full_out


@pytest.mark.asyncio
async def test_long_out_folds_with_hint(monkeypatch: pytest.MonkeyPatch) -> None:
    from hackbot.tui.app import HackbotTUI

    app = HackbotTUI()
    monkeypatch.setattr(HackbotTUI, "turn_runner", staticmethod(lambda t: "done"))
    long_out = "\n".join(f"L{i}" for i in range(20))
    async with app.run_test() as pilot:
        app._busy = True
        app._ingest_live("run", "python3 <<'PY'")
        await pilot.pause()
        run_id = app._active_run_id
        app._ingest_live("out/ok", f"exit=0\n{long_out}")
        await pilot.pause()
        block = app.query_one(f"#{run_id}", RunBlock)
        assert not block.expanded
        _, hidden = fold_output(block.full_out)
        assert hidden > 0
        assert "L19" in block.full_out
        # Expand and confirm full text is available for copy.
        block.expanded = True
        block._render_body()
        body = app.query_one(f"#{block._body_id}", CopyableStatic)
        assert "L19" in body.plain_source


@pytest.mark.asyncio
async def test_panel_kind_is_separate_block(monkeypatch: pytest.MonkeyPatch) -> None:
    from hackbot.tui.app import HackbotTUI

    app = HackbotTUI()
    monkeypatch.setattr(HackbotTUI, "turn_runner", staticmethod(lambda t: "done"))
    async with app.run_test() as pilot:
        app._busy = True
        app._ingest_live("run", "echo hi")
        await pilot.pause()
        run_id = app._active_run_id
        app._ingest_live(
            "panel",
            'surface_map\n{\n  "seed": "https://api.glassdoor.com/",\n  "host": "api.glassdoor.com"\n}',
        )
        await pilot.pause()
        assert app._active_run_id is None
        panels = list(app.query(RunBlock))
        assert any(b.kind == "panel" and b.cmd == "surface_map" for b in panels)
        panel = next(b for b in panels if b.kind == "panel")
        assert "api.glassdoor.com" in panel.full_out
        assert "glassdoor.co..." not in panel.full_out
        assert run_id
        run = app.query_one(f"#{run_id}", RunBlock)
        assert run.full_out == ""


@pytest.mark.asyncio
async def test_click_stream_pin_copies(monkeypatch: pytest.MonkeyPatch) -> None:
    from hackbot.tui.app import HackbotTUI

    copied: list[str] = []

    app = HackbotTUI()
    monkeypatch.setattr(
        app,
        "copy_plain",
        lambda text, label="text": copied.append(text),
    )
    async with app.run_test() as pilot:
        app._append_live_pin('out  {"ok": true}', raw=True)
        await pilot.pause()
        pin = next(
            w
            for w in app.query(CopyableStatic)
            if (w.plain_source or "").startswith("out  ")
        )
        await pilot.click(f"#{pin.id}")
        await pilot.pause()
        assert copied
        assert '{"ok": true}' in copied[0]
