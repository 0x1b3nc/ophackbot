"""Full RESUME.md updates from autonomous hunt state."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .findings import update_resume_next_step
from .identity import load_identity


def write_hunt_resume(
    target_dir: Path,
    *,
    host: str,
    summary: str,
    acts_done: int,
    findings: list[str],
    failures: list[str] | None = None,
    next_step: str = "",
) -> Path:
    """Update RESUME Last State / Accounts / Safe Next Step after a hunt."""
    target_dir = Path(target_dir)
    ident = load_identity(target_dir)
    ready = ident.ready_sessions()
    accounts_note = f"Sessions ready: {', '.join(ready) or '(none)'} under secrets/sessions.yaml"
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    last_bits = [
        f"Hunt @ {stamp} host={host} acts={acts_done}",
        summary[:240],
    ]
    if findings:
        last_bits.append("Findings: " + ", ".join(findings[:8]))
    if failures:
        last_bits.append("Failures: " + "; ".join(failures[:5]))
    next_default = next_step or (
        f"Resume hunt on {host}: review FINDINGS, continue authz/write matrix, or import HAR."
        if findings
        else f"Continue Observe/Decide on {host}; ensure A/B sessions or accounts.yaml for IDOR."
    )
    # update_resume_next_step handles Safe Next Step + accounts; also patch Last State if present
    path = update_resume_next_step(target_dir, next_default, accounts_note=accounts_note)
    resume = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
    block = "\n".join(f"- {b}" for b in last_bits)
    if "## Last State" in resume or "## Last state" in resume:
        # naive append under Last State
        import re

        resume2 = re.sub(
            r"(## Last [Ss]tate\s*\n)(.*?)(\n## |\Z)",
            rf"\1{block}\n\3",
            resume,
            count=1,
            flags=re.S,
        )
        if resume2 != resume:
            path.write_text(resume2, encoding="utf-8")
            return path
    # Ensure sections exist
    if "## Last State" not in resume and "## Last state" not in resume:
        resume = resume.rstrip() + f"\n\n## Last State\n\n{block}\n"
        path.write_text(resume, encoding="utf-8")
    return path


def evidence_index_append(target_dir: Path, row: dict[str, Any]) -> Path:
    """Append candidate↔evidence↔finding link under hunt/evidence_index.jsonl."""
    path = Path(target_dir) / "hunt" / "evidence_index.jsonl"
    path.parent.mkdir(parents=True, exist_ok=True)
    import json

    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")
    return path
