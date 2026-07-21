"""HackerOne report draft."""

from __future__ import annotations

from pathlib import Path

from ..redaction import redact_text

TEMPLATE = Path(__file__).resolve().parents[2] / "templates" / "reports" / "hackerone.md"


def render_hackerone(
    *,
    title: str,
    weakness: str,
    target: str,
    preconditions: str,
    steps: str,
    impact: str,
    evidence: str,
) -> str:
    base = TEMPLATE.read_text(encoding="utf-8") if TEMPLATE.exists() else _fallback()
    filled = (
        base.replace("{{TITLE}}", title)
        .replace("{{WEAKNESS}}", weakness)
        .replace("{{TARGET}}", target)
        .replace("{{PRECONDITIONS}}", preconditions)
        .replace("{{STEPS}}", steps)
        .replace("{{IMPACT}}", impact)
        .replace("{{EVIDENCE}}", evidence)
    )
    return redact_text(filled)


def _fallback() -> str:
    return """# {{TITLE}}

**Weakness:** {{WEAKNESS}}
**Asset:** {{TARGET}}

## Preconditions
{{PRECONDITIONS}}

## Steps
{{STEPS}}

## Impact
{{IMPACT}}

## Supporting material
{{EVIDENCE}}
"""
