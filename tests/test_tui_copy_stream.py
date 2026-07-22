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
        app._append_live_pin('out  {"ok": true}')
        await pilot.pause()
        pin = app.query_one(".msg-live", CopyableStatic)
        await pilot.click(f"#{pin.id}")
        await pilot.pause()
        assert copied
        assert '{"ok": true}' in copied[0]
