"""Intigriti report draft."""

from __future__ import annotations

from pathlib import Path

from ..redaction import redact_text

TEMPLATE = Path(__file__).resolve().parents[2] / "templates" / "reports" / "intigriti.md"


def render_intigriti(
    *,
    title: str,
    endpoint: str,
    vulnerability_type: str,
    preconditions: str,
    steps: str,
    impact: str,
    evidence: str,
) -> str:
    base = TEMPLATE.read_text(encoding="utf-8") if TEMPLATE.exists() else _fallback()
    filled = (
        base.replace("{{TITLE}}", title)
        .replace("{{ENDPOINT}}", endpoint)
        .replace("{{TYPE}}", vulnerability_type)
        .replace("{{PRECONDITIONS}}", preconditions)
        .replace("{{STEPS}}", steps)
        .replace("{{IMPACT}}", impact)
        .replace("{{EVIDENCE}}", evidence)
    )
    return redact_text(filled)


def _fallback() -> str:
    return """# {{TITLE}}

**Endpoint:** {{ENDPOINT}}
**Type:** {{TYPE}}

## Description / preconditions
{{PRECONDITIONS}}

## Reproduction steps
{{STEPS}}

## Impact
{{IMPACT}}

## Proof
{{EVIDENCE}}
"""
