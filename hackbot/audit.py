"""Append-only approval / deny log for operator decisions."""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
AUDIT_LOG = ROOT / "audit.log"


def log_decision(decision: str, description: str) -> None:
    """Append one ALLOW/DENY line. Best-effort: never raise to the caller."""
    stamp = datetime.now(timezone.utc).isoformat()
    # One line: collapse newlines so the log stays line-oriented.
    summary = " ".join(description.split())
    if len(summary) > 400:
        summary = summary[:400] + "..."
    line = f"{stamp} | {decision.upper()} | {summary}\n"
    try:
        with AUDIT_LOG.open("a", encoding="utf-8") as handle:
            handle.write(line)
    except OSError:
        pass
