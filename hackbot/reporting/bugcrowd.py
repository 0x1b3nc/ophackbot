"""Bugcrowd / VRT-oriented report draft."""

from __future__ import annotations

from pathlib import Path

from ..redaction import redact_text

TEMPLATE = Path(__file__).resolve().parents[2] / "templates" / "reports" / "bugcrowd.md"


def render_bugcrowd(
    *,
    title: str,
    vrt: str,
    target: str,
    preconditions: str,
    steps: str,
    impact: str,
    evidence: str,
) -> str:
    base = TEMPLATE.read_text(encoding="utf-8") if TEMPLATE.exists() else _fallback()
    filled = (
        base.replace("{{TITLE}}", title)
        .replace("{{VRT}}", vrt)
        .replace("{{TARGET}}", target)
        .replace("{{PRECONDITIONS}}", preconditions)
        .replace("{{STEPS}}", steps)
        .replace("{{IMPACT}}", impact)
        .replace("{{EVIDENCE}}", evidence)
    )
    return redact_text(filled)


def _fallback() -> str:
    return """# {{TITLE}}

**VRT:** {{VRT}}
**Target:** {{TARGET}}

## Preconditions
{{PRECONDITIONS}}

## Steps to reproduce
{{STEPS}}

## Impact
{{IMPACT}}

## Evidence
{{EVIDENCE}}
"""
