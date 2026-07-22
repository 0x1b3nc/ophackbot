"""API endpoint sensitivity ranking and coverage cell seeding."""

from __future__ import annotations

import re
from typing import Any
from urllib.parse import urlparse

from .coverage_map import mark_coverage
from .hunt_memory import Endpoint

_ID_PATH = re.compile(
    r"/(users?|accounts?|orgs?|organizations?|teams?|projects?|orders?|"
    r"invites?|billing|admin|members?|workspaces?|tenants?)/"
    r"[^/]*\{?[\w.-]+\}?",
    re.I,
)
_BIZ = re.compile(
    r"(invite|role|billing|subscription|coupon|refund|export|import|share|"
    r"transfer|approval|admin|privilege|permission|owner|plan)",
    re.I,
)
_STATIC = re.compile(
    r"\.(css|js|png|jpe?g|gif|svg|ico|woff2?|ttf|map)(?:\?|$)|"
    r"/(static|assets|public|favicon)/",
    re.I,
)
_SENSITIVE_PARAM = re.compile(
    r"(^id$|_id$|uuid|account|user|org|team|order|tenant|project)",
    re.I,
)


def path_sensitivity(path: str) -> int:
    """Higher = more interesting for authz/business-logic hunts."""
    p = path or "/"
    if _STATIC.search(p):
        return 5
    score = 20
    if _ID_PATH.search(p):
        score += 45
    if _BIZ.search(p):
        score += 35
    if "/graphql" in p.lower():
        score += 30
    if any(x in p.lower() for x in ("/api/", "/v1/", "/v2/", "/internal/")):
        score += 15
    if any(x in p.lower() for x in ("/admin", "/billing", "/invite")):
        score += 20
    return min(score, 100)


def endpoint_risk_score(ep: Endpoint) -> int:
    try:
        path = urlparse(ep.url).path or ep.url
    except Exception:  # noqa: BLE001
        path = ep.url
    score = path_sensitivity(path)
    if ep.auth_required:
        score += 10
    if ep.has_id_param() or any(_SENSITIVE_PARAM.search(p or "") for p in ep.params):
        score += 15
    method = (ep.method or "GET").upper()
    # Prefer sensitive reads slightly before blind writes
    if method == "GET" and score >= 50:
        score += 5
    if method in {"POST", "PUT", "PATCH", "DELETE"} and _BIZ.search(path):
        score += 8
    if getattr(ep, "risk_score", 0):
        score = max(score, int(ep.risk_score))
    return min(score, 100)


def rank_endpoints(endpoints: list[Endpoint]) -> list[Endpoint]:
    """Sort sensitive API endpoints above public/static ones."""
    return sorted(endpoints, key=lambda e: (-endpoint_risk_score(e), e.url, e.method))


def suggest_classes(ep: Endpoint) -> list[str]:
    try:
        path = (urlparse(ep.url).path or "/").lower()
    except Exception:  # noqa: BLE001
        path = (ep.url or "/").lower()
    classes: list[str] = []
    if ep.has_id_param() or _ID_PATH.search(path) or re.search(r"/\{?\w*id\}?", path):
        classes.append("idor")
        classes.append("authz")
    if _BIZ.search(path):
        classes.append("business-logic")
    if "graphql" in path:
        classes.append("graphql")
    if any(x in path for x in ("/chat", "/completions", "/v1/messages", "/mcp", "/agents")):
        classes.extend(["llm", "prompt-injection"])
    if not classes and path_sensitivity(path) >= 40:
        classes.append("api")
    return classes or ["api"]


def seed_api_coverage(
    target_dir,
    endpoints: list[Endpoint],
    *,
    authz_states: tuple[str, ...] = ("anon", "session_a"),
    limit: int = 200,
) -> dict[str, Any]:
    """Seed coverage cells: class × method × path × param × authz."""
    marked = 0
    for ep in rank_endpoints(endpoints)[:limit]:
        try:
            path = urlparse(ep.url).path or "/"
        except Exception:  # noqa: BLE001
            path = "/"
        params = list(ep.params) or [""]
        for cls in suggest_classes(ep)[:3]:
            for param in params[:4]:
                for authz in authz_states:
                    mark_coverage(
                        target_dir,
                        cls=cls,
                        method=ep.method or "GET",
                        path=path,
                        param=param,
                        authz=authz,
                        status="untested",
                        note=f"seed:{ep.source}",
                    )
                    marked += 1
    return {"ok": True, "marked": marked}
