"""JWT analysis (offline decode + common misconfig checks)."""

from __future__ import annotations

import base64
import json
from typing import Any


def b64url_json(part: str) -> Any:
    pad = "=" * (-len(part) % 4)
    return json.loads(base64.urlsafe_b64decode(part + pad).decode("utf-8", errors="replace"))


def analyze_jwt(token: str) -> dict[str, Any]:
    """Decode JWT header/payload and flag common bounty issues (no brute force)."""
    token = token.strip()
    if token.lower().startswith("bearer "):
        token = token[7:].strip()
    parts = token.split(".")
    if len(parts) < 2:
        return {"ok": False, "error": "not a JWT (need header.payload[.sig])"}

    try:
        header = b64url_json(parts[0])
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"header decode failed: {exc}"}
    try:
        payload = b64url_json(parts[1])
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"payload decode failed: {exc}"}

    issues: list[str] = []
    alg = str(header.get("alg") or "")
    if alg.lower() == "none":
        issues.append("alg=none (unsigned JWT — classic bypass)")
    if alg.upper() in {"HS256", "HS384", "HS512"} and "kid" in header:
        issues.append("HMAC JWT with kid — check path/SQL injection in kid")
    if "jku" in header or "x5u" in header:
        issues.append("jku/x5u present — check SSRF / key injection")
    if payload.get("role") in {"admin", "root", "superuser"}:
        issues.append(f"role claim looks privileged: {payload.get('role')}")
    if payload.get("admin") is True or payload.get("is_admin") is True:
        issues.append("boolean admin claim true — try flipping")
    for claim in ("exp", "nbf", "iat"):
        if claim not in payload:
            issues.append(f"missing {claim} claim")
    # Don't print full signature
    out = {
        "ok": True,
        "header": header,
        "payload": payload,
        "alg": alg,
        "has_signature": len(parts) >= 3 and bool(parts[2]),
        "issues": issues,
        "issue_count": len(issues),
    }
    return out
