"""reconFTW orchestration. Print-first; requires --approve to run."""

from __future__ import annotations

import os
import shutil
from pathlib import Path

from .. import ui
from .base import RunnerResult, require_in_scope, run_command


def resolve_reconftw() -> str | None:
    env = os.environ.get("RECONFTW_PATH")
    if env and Path(env).exists():
        return env
    found = shutil.which("reconftw") or shutil.which("reconftw.sh")
    return found


def run_recon(
    target_dir: Path,
    domain: str,
    *,
    mode: str = "recon",
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    require_in_scope(target_dir, domain, action="reconftw recon", force=force)
    binary = resolve_reconftw()
    if not binary:
        cmd = [
            "./reconftw.sh",
            "-d",
            domain,
            "-r" if mode == "recon" else f"-{mode}",
        ]
        ui.warn("reconftw not on PATH; showing expected command")
        ui.info("set RECONFTW_PATH to reconftw.sh if installed elsewhere")
        return run_command(cmd, approve=False)

    cmd = [binary, "-d", domain]
    if mode == "recon":
        cmd.append("-r")
    else:
        cmd.append(f"-{mode}")
    out_dir = target_dir / "recon" / "reconftw"
    out_dir.mkdir(parents=True, exist_ok=True)
    cmd.extend(["-o", str(out_dir)])
    return run_command(cmd, approve=approve)
