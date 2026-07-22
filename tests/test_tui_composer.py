"""Pilot tests — Enter=newline, Ctrl+Enter/Send submit (mode A)."""

from __future__ import annotations

import pytest

textual = pytest.importorskip("textual")

from hackbot.tui.app import HackbotTUI  # noqa: E402
from hackbot.tui.composer import PromptArea  # noqa: E402


@pytest.fixture
def mock_turn(monkeypatch: pytest.MonkeyPatch) -> list[str]:
    calls: list[str] = []

    def _fake(text: str) -> str:
        calls.append(text)
        return f"echo:{text}"

    monkeypatch.setattr(HackbotTUI, "turn_runner", staticmethod(_fake))
    return calls


@pytest.mark.asyncio
async def test_enter_inserts_newline_does_not_submit(mock_turn: list[str]) -> None:
    app = HackbotTUI()
    async with app.run_test() as pilot:
        prompt = app.query_one("#prompt", PromptArea)
        prompt.focus()
        await pilot.press("h", "i")
        await pilot.press("enter")
        await pilot.press("t", "h", "e", "r", "e")
        await pilot.pause()
        assert "hi\nthere" in (prompt.text or "").replace("\r\n", "\n")
        assert mock_turn == []


@pytest.mark.asyncio
async def test_ctrl_enter_submits(mock_turn: list[str]) -> None:
    app = HackbotTUI()
    async with app.run_test() as pilot:
        prompt = app.query_one("#prompt", PromptArea)
        prompt.focus()
        await pilot.press("h", "e", "l", "l", "o")
        await pilot.press("ctrl+enter")
        await pilot.pause()
        # Worker may still be finishing — wait for idle turn
        for _ in range(50):
            if not app._busy and mock_turn:
                break
            await pilot.pause()
        assert mock_turn == ["hello"]
        assert (prompt.text or "").strip() == ""


@pytest.mark.asyncio
async def test_send_button_submits(mock_turn: list[str]) -> None:
    app = HackbotTUI()
    async with app.run_test() as pilot:
        prompt = app.query_one("#prompt", PromptArea)
        prompt.focus()
        await pilot.press("p", "i", "n")
        await pilot.click("#send")
        await pilot.pause()
        for _ in range(50):
            if not app._busy and mock_turn:
                break
            await pilot.pause()
        assert mock_turn == ["pin"]
        assert (prompt.text or "").strip() == ""
