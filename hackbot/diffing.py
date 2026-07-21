"""Structured response diff for authz validation (no LLM)."""

from __future__ import annotations

import hashlib
import json
import re
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class DiffResult:
    verdict: str  # confirmed | likely | negative | inconclusive
    reason: str
    status_a: int
    status_b: int
    length_a: int
    length_b: int
    same_hash: bool
    details: dict[str, Any]

    def as_dict(self) -> dict[str, Any]:
        return {
            "verdict": self.verdict,
            "reason": self.reason,
            "status_a": self.status_a,
            "status_b": self.status_b,
            "length_a": self.length_a,
            "length_b": self.length_b,
            "same_hash": self.same_hash,
            "details": self.details,
        }


def _as_response(obj: dict[str, Any] | str) -> dict[str, Any]:
    if isinstance(obj, str):
        try:
            obj = json.loads(obj)
        except json.JSONDecodeError:
            return {"status": 0, "body": obj, "length": len(obj), "sha256": _sha(obj)}
    return obj


def _sha(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


def _body(resp: dict[str, Any]) -> str:
    return str(resp.get("body") or resp.get("body_preview") or "")


def _status(resp: dict[str, Any]) -> int:
    try:
        return int(resp.get("status") or 0)
    except (TypeError, ValueError):
        return 0


def assert_idor_diff(
    resp_a: dict[str, Any] | str,
    resp_b: dict[str, Any] | str,
    *,
    object_hint: str = "",
) -> DiffResult:
    """Compare owner-A vs cross-account-B responses for IDOR signals."""
    a = _as_response(resp_a)
    b = _as_response(resp_b)
    sa, sb = _status(a), _status(b)
    ba, bb = _body(a), _body(b)
    ha = str(a.get("sha256") or _sha(ba))
    hb = str(b.get("sha256") or _sha(bb))
    same_hash = ha == hb
    la, lb = len(ba), len(bb)

    details: dict[str, Any] = {
        "hash_a": ha[:16],
        "hash_b": hb[:16],
        "object_hint": object_hint,
    }

    # Secure: B denied
    if sb in {401, 403, 404} and sa in {200, 201}:
        return DiffResult(
            "negative",
            f"B got {sb} while A got {sa} — access control appears to hold.",
            sa,
            sb,
            la,
            lb,
            same_hash,
            details,
        )

    # Both denied / error
    if sa >= 400 and sb >= 400:
        return DiffResult(
            "inconclusive",
            f"Both failed (A={sa}, B={sb}). Fix auth/baseline before claiming IDOR.",
            sa,
            sb,
            la,
            lb,
            same_hash,
            details,
        )

    # Classic IDOR: both 200, different bodies
    if sa == 200 and sb == 200 and not same_hash and lb > 0:
        hint_hit = False
        if object_hint and object_hint in bb:
            hint_hit = True
            details["hint_in_b"] = True
        # JSON overlap heuristic: shared keys with differing values
        overlap = _json_value_leak(ba, bb)
        details["json_leak_keys"] = overlap
        if hint_hit or overlap:
            return DiffResult(
                "confirmed",
                "B received 200 with distinct body containing owner/object signals.",
                sa,
                sb,
                la,
                lb,
                same_hash,
                details,
            )
        return DiffResult(
            "likely",
            "Both 200 with different bodies — likely object-level authz break; confirm fields manually.",
            sa,
            sb,
            la,
            lb,
            same_hash,
            details,
        )

    # Same body for A and B — usually public page, not IDOR (avoid FP on seed/home)
    if sa == 200 and sb == 200 and same_hash and la > 0:
        # Only elevate when object_hint suggests a private object identifier
        if object_hint and object_hint.strip() and any(ch.isdigit() for ch in object_hint):
            return DiffResult(
                "inconclusive",
                "Identical 200 bodies with object hint — verify sensitivity manually (not auto-likely).",
                sa,
                sb,
                la,
                lb,
                same_hash,
                details,
            )
        return DiffResult(
            "inconclusive",
            "A and B got identical 200 bodies — likely public resource, not IDOR.",
            sa,
            sb,
            la,
            lb,
            same_hash,
            details,
        )

    if sb == 200 and sa != 200:
        return DiffResult(
            "inconclusive",
            f"B got 200 but A got {sa} — unexpected; re-check sessions/ownership.",
            sa,
            sb,
            la,
            lb,
            same_hash,
            details,
        )

    return DiffResult(
        "inconclusive",
        f"No clear IDOR pattern (A={sa}/{la}, B={sb}/{lb}).",
        sa,
        sb,
        la,
        lb,
        same_hash,
        details,
    )


def _json_value_leak(body_a: str, body_b: str) -> list[str]:
    """Return keys where A and B are both JSON objects and values differ."""
    try:
        ja = json.loads(body_a)
        jb = json.loads(body_b)
    except json.JSONDecodeError:
        return []
    if not isinstance(ja, dict) or not isinstance(jb, dict):
        return []
    leaked: list[str] = []
    for key in list(ja.keys())[:40]:
        if key in jb and ja[key] != jb[key]:
            # Skip pure noise keys
            if key.lower() in {"timestamp", "ts", "requestid", "request_id", "traceid"}:
                continue
            leaked.append(str(key))
    # Also: B contains string values that look like IDs from A
    id_like = re.findall(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", body_a, re.I)
    id_like += re.findall(r"\b\d{3,}\b", body_a)
    for token in id_like[:10]:
        if token in body_b and token not in leaked:
            leaked.append(f"token:{token[:12]}")
    return leaked[:15]
