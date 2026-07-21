"""Append-only approval / deny log for operator decisions."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
AUDIT_LOG = ROOT / "audit.log"


def log_decision(
    decision: str,
    description: str,
    *,
    kind: str = "approve",
    target: str = "",
    tool: str = "",
    host: str = "",
    extra: dict[str, Any] | None = None,
) -> None:
    """Append one structured ALLOW/DENY line. Best-effort: never raise."""
    stamp = datetime.now(timezone.utc).isoformat()
    summary = " ".join(description.split())
    if len(summary) > 300:
        summary = summary[:300] + "..."
    fields = [
        stamp,
        decision.upper(),
        f"kind={kind}",
    ]
    if target:
        fields.append(f"target={target}")
    if tool:
        fields.append(f"tool={tool}")
    if host:
        fields.append(f"host={host}")
    if extra:
        for key, val in extra.items():
            fields.append(f"{key}={val}")
    fields.append(summary)
    line = " | ".join(fields) + "\n"
    try:
        with AUDIT_LOG.open("a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        pass
