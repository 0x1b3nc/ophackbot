"""Severity / CVSS hints by bug class — triage aids, not final program severity."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class SeverityHint:
    severity: str  # Critical|High|Medium|Low|Info|TBD
    score: str  # e.g. "7.1" or "TBD"
    vector: str  # CVSS:3.1/...
    rationale: str

    def as_dict(self) -> dict[str, str]:
        return {
            "severity": self.severity,
            "score": self.score,
            "vector": self.vector,
            "rationale": self.rationale,
            "disclaimer": (
                "Hint only — confirm against the program's severity table / VRT / CVSS policy."
            ),
        }

    def line(self) -> str:
        if self.score == "TBD":
            return f"{self.severity} (confirm with program policy)"
        return f"{self.severity} ~{self.score} ({self.vector})"


# Conservative defaults for common classes. Operators must still triage.
_HINTS: dict[str, SeverityHint] = {
    "idor": SeverityHint(
        "High",
        "7.1",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "Cross-account read of sensitive objects (BOLA). Raise if writes/PII/finance.",
    ),
    "bola": SeverityHint(
        "High",
        "7.1",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "Broken object-level authorization.",
    ),
    "bac": SeverityHint(
        "High",
        "7.1",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "Broken access control / horizontal privilege.",
    ),
    "bfla": SeverityHint(
        "High",
        "8.1",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:H/A:N",
        "Broken function-level authorization.",
    ),
    "authz": SeverityHint(
        "High",
        "7.1",
        "CVSS:3.1/AV:N/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N",
        "Authorization failure.",
    ),
    "auth-bypass": SeverityHint(
        "Critical",
        "9.8",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "Authentication bypass without valid credentials.",
    ),
    "secrets": SeverityHint(
        "Critical",
        "9.1",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "Exposed credentials/keys — impact depends on scope of secret.",
    ),
    "sqli": SeverityHint(
        "Critical",
        "9.8",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "SQL injection.",
    ),
    "ssti": SeverityHint(
        "Critical",
        "9.8",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
        "Server-side template injection / RCE risk.",
    ),
    "xxe": SeverityHint(
        "High",
        "8.2",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:L/A:N",
        "XML external entity — file/SSRF impact varies.",
    ),
    "lfi": SeverityHint(
        "High",
        "7.5",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "Local file inclusion / path traversal.",
    ),
    "xss": SeverityHint(
        "Medium",
        "6.1",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N",
        "Reflected XSS baseline; stored/auth'd may be Higher.",
    ),
    "cors": SeverityHint(
        "Medium",
        "6.5",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
        "Misconfigured CORS with credentialed access risk.",
    ),
    "open_redirect": SeverityHint(
        "Low",
        "4.7",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        "Open redirect — often Low unless chained to OAuth/token theft.",
    ),
    "open-redirect": SeverityHint(
        "Low",
        "4.7",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:N/I:L/A:N",
        "Open redirect.",
    ),
    "oauth": SeverityHint(
        "High",
        "7.4",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:U/C:H/I:H/A:N",
        "OAuth/OIDC misconfig — confirm account takeover path.",
    ),
    "jwt": SeverityHint(
        "High",
        "7.4",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "JWT weakness (alg/none, claim tamper) — confirm forgeability.",
    ),
    "jwt_active": SeverityHint(
        "High",
        "7.4",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
        "Active JWT bypass probe signal.",
    ),
    "graphql": SeverityHint(
        "Medium",
        "5.3",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "GraphQL introspection/over-fetch — raise if authz broken.",
    ),
    "rate-limit": SeverityHint(
        "Low",
        "3.7",
        "CVSS:3.1/AV:N/AC:H/PR:N/UI:N/S:U/C:N/I:N/A:L",
        "Missing/weak rate limit — often informational unless auth abuse.",
    ),
    "race": SeverityHint(
        "High",
        "7.4",
        "CVSS:3.1/AV:N/AC:H/PR:L/UI:N/S:U/C:N/I:H/A:N",
        "Race/TOCTOU — confirm financial or state corruption impact.",
    ),
    "websocket": SeverityHint(
        "Medium",
        "5.3",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:N",
        "Websocket surface — raise if authz missing on frames.",
    ),
    "ssrf": SeverityHint(
        "High",
        "8.6",
        "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:N/A:N",
        "SSRF — raise to Critical if cloud metadata reachable.",
    ),
}
_DEFAULT = SeverityHint(
    "TBD",
    "TBD",
    "",
    "No default mapping — triage against program severity guidelines.",
)

# Aliases
_ALIASES = {
    "access-control": "authz",
    "auth_bypass": "auth-bypass",
    "openredirect": "open_redirect",
    "sql-injection": "sqli",
    "template-injection": "ssti",
    "path-traversal": "lfi",
    "path_traversal": "lfi",
    "credential-leak": "secrets",
    "secret": "secrets",
}


def normalize_class(class_name: str) -> str:
    raw = (class_name or "").strip().lower()
    if "," in raw:
        raw = raw.split(",", 1)[0].strip()
    raw = raw.replace(" ", "-")
    if raw in _ALIASES:
        return _ALIASES[raw]
    unders = raw.replace("-", "_")
    if unders in _HINTS:
        return unders
    if raw in _HINTS:
        return raw
    if unders in _ALIASES:
        return _ALIASES[unders]
    return unders or raw


def severity_for_class(class_name: str) -> SeverityHint:
    key = normalize_class(class_name)
    if key in _HINTS:
        return _HINTS[key]
    # try first token of comma-separated
    if "," in (class_name or ""):
        return severity_for_class(class_name.split(",", 1)[0])
    return _DEFAULT


def severity_fields(class_name: str) -> dict[str, Any]:
    hint = severity_for_class(class_name)
    data = hint.as_dict()
    data["line"] = hint.line()
    data["class"] = normalize_class(class_name) or class_name
    return data
