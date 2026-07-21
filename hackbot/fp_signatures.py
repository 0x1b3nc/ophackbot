"""False-positive signatures for evidence-gated FINDINGS (pro hunt)."""

from __future__ import annotations

import re
from typing import Any


# Patterns that commonly cause FP bounty reports
_FP_RULES: list[tuple[str, re.Pattern[str]]] = [
    ("public_html_shell", re.compile(r"<!doctype html>|<html[\s>]", re.I)),
    ("csrf_in_url", re.compile(r"[?&](csrf|_token|authenticity_token)=", re.I)),
    ("intentional_404_verbose", re.compile(r"nginx/|apache/|404 not found", re.I)),
    ("rate_limit_page", re.compile(r"too many requests|rate.?limit|retry.after", re.I)),
    ("login_form_generic", re.compile(r"<form[^>]+login|type=[\"']password[\"']", re.I)),
]


def match_fp_signatures(
    *,
    module: str,
    observed: str,
    url: str = "",
    verdict: str = "",
) -> dict[str, Any]:
    """Return hit info if observed evidence matches known FP signatures."""
    text = f"{observed}\n{url}"
    hits: list[str] = []
    for name, pat in _FP_RULES:
        if pat.search(text):
            hits.append(name)
    # Identical-body IDOR on root paths is almost always public
    if module in {"idor", "browser_diff"} and verdict in {"likely", "inconclusive"}:
        path = ""
        try:
            from urllib.parse import urlparse

            path = urlparse(url).path or "/"
        except Exception:  # noqa: BLE001
            path = "/"
        if path in {"/", "/index", "/index.html", "/home", "/login"}:
            hits.append("idor_on_public_path")
    return {
        "ok": True,
        "is_fp": bool(hits),
        "hits": hits,
        "reason": ",".join(hits) if hits else "",
    }


def confidence_score(
    *,
    module: str,
    verdict: str,
    rehit: dict[str, Any] | None = None,
    fp: dict[str, Any] | None = None,
    has_ownership_diff: bool = False,
) -> float:
    """0–1 confidence before promoting FINDINGS (confirmed needs ≥0.75)."""
    score = 0.35
    v = (verdict or "").lower()
    if v == "confirmed":
        score += 0.35
    elif v == "likely":
        score += 0.15
    elif v in {"negative", "inconclusive", "rejected"}:
        score -= 0.3
    if has_ownership_diff:
        score += 0.2
    if rehit:
        neg = rehit.get("negative") or {}
        pos = rehit.get("rehit") or {}
        try:
            if int(neg.get("status") or 0) in {401, 403, 404} and int(pos.get("status") or 0) == 200:
                score += 0.15
        except (TypeError, ValueError):
            pass
        if rehit.get("error"):
            score -= 0.05
    if fp and fp.get("is_fp"):
        score -= 0.4
    if module in {"browser_diff"}:
        score -= 0.1  # soft hints need more proof
    return max(0.0, min(1.0, round(score, 3)))
