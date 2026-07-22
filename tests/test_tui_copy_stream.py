"""CopyableStatic keeps plain_source in sync for stream pins."""

from __future__ import annotations

import pytest

textual = pytest.importorskip("textual")

from hackbot.tui.widgets import CopyableStatic  # noqa: E402


def test_copyable_static_update_syncs_plain() -> None:
    w = CopyableStatic("◌ …", plain="◌ …")
    assert w.plain_source == "◌ …"
    w.update("· out  {\"a\": 1}")
    assert w.plain_source == '· out  {"a": 1}'


@pytest.mark.asyncio
async def test_run_out_fills_collapsible(monkeypatch: pytest.MonkeyPatch) -> None:
    """out/ok must land in the open run block — not be dropped as unknown kind."""
    from hackbot.tui.app import HackbotTUI

    app = HackbotTUI()
    monkeypatch.setattr(HackbotTUI, "turn_runner", staticmethod(lambda t: "done"))
    async with app.run_test() as pilot:
        app._busy = True
        app._ingest_live("run", "echo hello")
        await pilot.pause()
        assert app._active_run_body_id, "run block should track body id"
        app._ingest_live("out/ok", "exit=0\nhello\nworld")
        await pilot.pause()
        body = app.query_one(f"#{app._active_run_body_id}", CopyableStatic)
        assert "hello" in (body.plain_source or "")
        assert "world" in body.plain_source


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
        pin = app.query_one(".msg-live", CopyableStatic)
        await pilot.click(f"#{pin.id}")
        await pilot.pause()
        assert copied
        assert '{"ok": true}' in copied[0]
