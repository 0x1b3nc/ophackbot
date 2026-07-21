"""Redact secrets, session material and PII from evidence text."""

from __future__ import annotations

import re

# Header names that must never leave the machine unredacted.
_SENSITIVE_HEADERS = (
    "authorization",
    "cookie",
    "set-cookie",
    "x-api-key",
    "x-auth-token",
    "x-access-token",
    "proxy-authorization",
)

_PATTERNS: list[tuple[re.Pattern[str], str]] = [
    (
        re.compile(r"(?im)^((?:authorization|cookie|set-cookie|x-api-key|x-auth-token|"
                   r"x-access-token|proxy-authorization)\s*:\s*).+$"),
        r"\1[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)\b(Bearer|Basic|Token)\s+[A-Za-z0-9\-._~+/]+=*"
        ),
        r"\1 [REDACTED]",
    ),
    (
        re.compile(
            r"(?i)\b(access_token|refresh_token|id_token|api[_-]?key|client_secret|"
            r"session[_-]?id|csrf[_-]?token|authenticity_token)\s*[:=]\s*['\"]?[^'\"\s,&]+"
        ),
        r"\1=[REDACTED]",
    ),
    (
        re.compile(
            r"(?i)([?&](?:token|access_token|refresh_token|api_key|key|session|auth|jwt)=)[^&\s]+"
        ),
        r"\1[REDACTED]",
    ),
    (
        re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b"),
        "[REDACTED_EMAIL]",
    ),
    (
        # JWT-shaped strings
        re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b"),
        "[REDACTED_JWT]",
    ),
    (
        # Common secret prefixes
        re.compile(
            r"\b(sk_live_|sk_test_|ghp_|gho_|github_pat_|xox[baprs]-|"
            r"AKIA[0-9A-Z]{16})\S*"
        ),
        "[REDACTED_SECRET]",
    ),
]


def redact_text(text: str) -> str:
    """Return a copy of text with secrets and common PII removed."""
    out = text
    for pattern, replacement in _PATTERNS:
        out = pattern.sub(replacement, out)
    return out


def looks_sensitive(text: str) -> bool:
    """True if text still appears to contain unredacted sensitive material."""
    lower = text.lower()
    for header in _SENSITIVE_HEADERS:
        # Unredacted header value after the colon
        marker = f"{header}:"
        idx = lower.find(marker)
        while idx != -1:
            rest = text[idx + len(marker) : idx + len(marker) + 40]
            if rest.strip() and "[redacted]" not in rest.lower():
                return True
            idx = lower.find(marker, idx + 1)
    if re.search(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\b", text):
        return True
    if re.search(r"(?i)\bBearer\s+[A-Za-z0-9\-._~+/]{8,}", text):
        return True
    return False
