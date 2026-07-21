"""Platform-agnostic bug-bounty report draft (works across programs)."""

from __future__ import annotations

from pathlib import Path

from ..redaction import redact_text

TEMPLATE = Path(__file__).resolve().parents[2] / "templates" / "reports" / "generic.md"

# Friendly labels for the header — not locked to one vendor.
PLATFORM_LABELS = {
    "generic": "Bug bounty (platform-agnostic)",
    "bugcrowd": "Bugcrowd",
    "hackerone": "HackerOne",
    "intigriti": "Intigriti",
    "yeswehack": "YesWeHack",
    "synack": "Synack",
    "immunefi": "Immunefi",
    "yogosha": "Yogosha",
}


def render_generic(
    *,
    title: str,
    target: str,
    preconditions: str,
    steps: str,
    impact: str,
    evidence: str,
    platform: str = "generic",
    vuln_type: str = "TBD",
    severity_hint: str = "TBD (confirm with program policy)",
    cvss_vector: str = "",
    observed: str = "",
) -> str:
    label = PLATFORM_LABELS.get(platform.lower(), platform or "Bug bounty")
    base = TEMPLATE.read_text(encoding="utf-8") if TEMPLATE.exists() else _fallback()
    filled = (
        base.replace("{{PLATFORM}}", label)
        .replace("{{TITLE}}", title)
        .replace("{{VULN_TYPE}}", vuln_type)
        .replace("{{SEVERITY}}", severity_hint)
        .replace("{{CVSS}}", cvss_vector or "TBD")
        .replace("{{TARGET}}", target)
        .replace("{{PRECONDITIONS}}", preconditions)
        .replace("{{STEPS}}", steps)
        .replace("{{OBSERVED}}", observed or "(see steps / evidence)")
        .replace("{{IMPACT}}", impact)
        .replace("{{EVIDENCE}}", evidence)
    )
    return redact_text(filled)


def _fallback() -> str:
    return """# {{TITLE}}

**Platform draft for:** {{PLATFORM}}  
**Type:** {{VULN_TYPE}}  
**Severity hint:** {{SEVERITY}}  
**CVSS hint:** {{CVSS}}  
**Asset / endpoint:** {{TARGET}}

> Paste into Bugcrowd, HackerOne, Intigriti, YesWeHack, Synack, or any program
> portal. Adjust field names to match that platform's form. Severity/CVSS are
> triage hints — confirm against the program policy.

## Summary
{{TITLE}}

## Preconditions
{{PRECONDITIONS}}

## Steps to reproduce
{{STEPS}}

## Observed behavior
{{OBSERVED}}

## Impact
{{IMPACT}}

## Evidence / PoC material
{{EVIDENCE}}

## Remediation (suggested)
- Enforce object-level authorization on every sensitive endpoint
- Deny by default for cross-account access; return consistent 403/404
- Add regression tests for A/B ownership checks

## Notes for triage
- All testing was authorized / in-scope for this program
- Tokens and cookies are redacted in attached evidence
- Severity/CVSS above are hints derived from bug class, not final ratings
"""
