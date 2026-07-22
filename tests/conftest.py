"""Pytest defaults for hackbot-kit."""

from __future__ import annotations

import pytest


@pytest.fixture(autouse=True)
def _allow_arg_force(monkeypatch: pytest.MonkeyPatch) -> None:
    """Tests pass force=True in tool args; production ignores naked model force."""
    monkeypatch.setenv("HACKBOT_ALLOW_ARG_FORCE", "1")
