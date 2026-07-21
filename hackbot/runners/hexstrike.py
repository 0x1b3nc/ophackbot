"""HexStrike local server helper. Prints commands; executes only with --approve.

Prefer Docker (integrations/hexstrike/docker-compose.yml): host loopback only,
no targets/ mount. See PROVENANCE.md.
"""

from __future__ import annotations

from pathlib import Path

from .. import ui
from .base import RunnerResult, run_command

ROOT = Path(__file__).resolve().parents[2]
HEXSTRIKE_DIR = ROOT / "integrations" / "hexstrike"


def start_server(*, port: int = 8888, approve: bool = False, docker: bool = False) -> RunnerResult:
    if docker or (_prefer_docker() and (HEXSTRIKE_DIR / "docker-compose.yml").exists()):
        ui.info(
            f"hexstrike via docker compose (host 127.0.0.1:{port}, no targets/ mount). "
            "see integrations/hexstrike/PROVENANCE.md"
        )
        return run_command(
            ["docker", "compose", "up", "-d", "--build"],
            approve=approve,
            cwd=HEXSTRIKE_DIR,
        )

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
    ui.info(
        f"hexstrike binds loopback only (127.0.0.1:{port}). "
        "prefer: docker compose in integrations/hexstrike/"
    )
    return run_command(
        ["python", str(script), "--port", str(port)],
        approve=approve,
        cwd=HEXSTRIKE_DIR,
    )


def _prefer_docker() -> bool:
    import os
    import shutil

    if os.environ.get("HACKBOT_HEXSTRIKE_DOCKER", "").strip().lower() in {"0", "false", "no", "off"}:
        return False
    if os.environ.get("HACKBOT_HEXSTRIKE_DOCKER", "").strip().lower() in {"1", "true", "yes", "on"}:
        return shutil.which("docker") is not None
    # Default: use docker when the binary exists
    return shutil.which("docker") is not None


def health_curl(*, port: int = 8888, approve: bool = False) -> RunnerResult:
    return run_command(
        ["curl", "-sS", f"http://127.0.0.1:{port}/health"],
        approve=approve,
    )
