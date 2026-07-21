"""Platform report draft helpers — multi-vendor, not locked to one portal."""

from __future__ import annotations

from typing import Any

from .bugcrowd import render_bugcrowd
from .generic import PLATFORM_LABELS, render_generic
from .hackerone import render_hackerone
from .intigriti import render_intigriti

__all__ = [
    "PLATFORM_LABELS",
    "normalize_platform",
    "render_bugcrowd",
    "render_generic",
    "render_hackerone",
    "render_intigriti",
    "render_report",
]

_ALIASES = {
    "generic": "generic",
    "any": "generic",
    "agnostic": "generic",
    "universal": "generic",
    "bounty": "generic",
    "bug bounty": "generic",
    "bugcrowd": "bugcrowd",
    "bc": "bugcrowd",
    "hackerone": "hackerone",
    "h1": "hackerone",
    "intigriti": "intigriti",
    "yeswehack": "yeswehack",
    "ywh": "yeswehack",
    "synack": "synack",
    "immunefi": "immunefi",
    "yogosha": "yogosha",
}


def normalize_platform(raw: str | None) -> str:
    key = (raw or "generic").strip().lower()
    return _ALIASES.get(key, key if key in PLATFORM_LABELS else "generic")


def render_report(
    platform: str,
    *,
    title: str,
    target: str,
    preconditions: str,
    steps: str,
    impact: str,
    evidence: str,
    vuln_type: str = "TBD",
    vrt: str = "",
    weakness: str = "",
    observed: str = "",
    severity_hint: str = "",
    cvss_vector: str = "",
) -> str:
    """Render a draft for the chosen platform (falls back to generic layout)."""
    from ..severity import severity_for_class

    plat = normalize_platform(platform)
    common: dict[str, Any] = dict(
        title=title,
        target=target,
        preconditions=preconditions,
        steps=steps,
        impact=impact,
        evidence=evidence,
    )
    vt = vuln_type or weakness or vrt or "TBD"
    sev = severity_for_class(vt)
    sev_line = severity_hint or sev.line()
    cvss = cvss_vector or sev.vector

    if plat == "bugcrowd":
        body = render_bugcrowd(vrt=vrt or vt, **common)
        return _append_severity_footer(body, sev_line, cvss)
    if plat == "hackerone":
        body = render_hackerone(weakness=weakness or vt, **common)
        return _append_severity_footer(body, sev_line, cvss)
    if plat == "intigriti":
        body = render_intigriti(
            endpoint=target,
            vulnerability_type=weakness or vt,
            **{k: v for k, v in common.items() if k != "target"},
        )
        return _append_severity_footer(body, sev_line, cvss)
    # yeswehack / synack / immunefi / yogosha / generic → shared skeleton
    return render_generic(
        platform=plat,
        vuln_type=vt,
        severity_hint=sev_line,
        cvss_vector=cvss,
        observed=observed,
        **common,
    )


def _append_severity_footer(body: str, severity_hint: str, cvss: str) -> str:
    footer = (
        "\n\n---\n\n"
        f"**Severity hint:** {severity_hint}\n\n"
        f"**CVSS hint:** {cvss or 'TBD'}\n\n"
        "_Hints only — confirm against the program's severity table / VRT / CVSS policy._\n"
    )
    if "Severity hint:" in body:
        return body
    return body.rstrip() + footer
