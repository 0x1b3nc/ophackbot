"""HexStrike local server helper. Prints commands; executes only with --approve."""

from __future__ import annotations

from pathlib import Path

from .. import ui
from .base import RunnerResult, run_command

ROOT = Path(__file__).resolve().parents[2]
HEXSTRIKE_DIR = ROOT / "integrations" / "hexstrike"


def start_server(*, port: int = 8888, approve: bool = False) -> RunnerResult:
    script = HEXSTRIKE_DIR / "hexstrike_server.py"
    if not script.exists():
        ui.error(f"missing: {script}")
        return RunnerResult(
            command=[],
            executed=False,
            returncode=None,
            stdout="",
            stderr="",
            message="hexstrike_server.py not found",
        )
    return run_command(
        ["python", str(script), "--port", str(port)],
        approve=approve,
        cwd=HEXSTRIKE_DIR,
    )


def health_curl(*, port: int = 8888, approve: bool = False) -> RunnerResult:
    return run_command(
        ["curl", "-sS", f"http://127.0.0.1:{port}/health"],
        approve=approve,
    )
