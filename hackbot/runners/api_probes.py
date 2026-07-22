"""API offensive probes — dry-run default, SCOPE-gated, canary payloads."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .. import ui
from ..coverage_map import mark_coverage_url
from ..redaction import redact_text
from . import advanced_http as adv
from . import http_request as http_mod
from . import web_probes
from .base import RunnerResult, require_in_scope
from .elite_probes import _dry, _gate, _save, graphql_authz_probe, graphql_batch_probe, oidc_probe

CANARY_BODY = {
    "role": "hb_canary_role",
    "isAdmin": False,
    "tenant_id": "HB_OTHER_TENANT_CANARY",
    "debug": False,
}


def _mark(target_dir: Path, cls: str, url: str, status: str, method: str = "GET") -> None:
    mark_coverage_url(target_dir, cls=cls, url=url, method=method, status=status, note="api_probe")


def api_authz_matrix(
    target_dir: Path,
    url: str,
    *,
    method: str = "GET",
    session_a: str = "A",
    session_b: str = "B",
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    plan = {
        "url": url,
        "method": method,
        "sessions": [session_a, session_b, "anon"],
        "approve": approve,
    }
    early = _gate(
        target_dir,
        url,
        action="api authz matrix",
        approve=approve,
        force=force,
        tool="api_authz_matrix",
        plan=plan,
    )
    if early:
        return early
    rows: list[dict[str, Any]] = []
    for sess in (session_a, session_b, ""):
        label = sess or "anon"
        try:
            result = http_mod.http_request(
                target_dir,
                url,
                method=method.upper(),
                session=sess or None,
                approve=True,
                force=force,
                label=f"authz_{label}",
            )
            payload = json.loads(result.stdout) if result.stdout else {}
        except Exception as exc:  # noqa: BLE001
            payload = {"error": type(exc).__name__}
        rows.append(
            {
                "session": label,
                "status": payload.get("status"),
                "preview": redact_text(str(payload.get("body_preview") or ""))[:200],
            }
        )
    statuses = [r.get("status") for r in rows if r.get("status") is not None]
    signal = False
    if len(statuses) >= 2 and statuses[0] == 200 and any(s == 200 for s in statuses[1:]):
        # A and B both 200 on same object URL → possible BOLA (manual triage)
        signal = statuses[1] == 200
    out = {"ok": True, "signal": signal, "rows": rows, "reason": "compare A/B/anon"}
    _save(target_dir, "api_authz_matrix", out)
    _mark(target_dir, "authz", url, "pos" if signal else "neg", method=method)
    return RunnerResult(["api_authz_matrix", url], True, 0, json.dumps(out), "", "executed")


def api_mass_assignment_probe(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
    session: str = "A",
) -> RunnerResult:
    return adv.mass_assignment_probe(
        target_dir,
        url,
        approve=approve,
        force=force,
        session=session,
        extra_fields=dict(CANARY_BODY),
    )


def api_method_override_probe(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
    session: str = "A",
) -> RunnerResult:
    return adv.method_override_probe(
        target_dir, url, approve=approve, force=force, session=session
    )


def api_hpp_probe(
    target_dir: Path,
    url: str,
    *,
    param: str = "id",
    owned_id: str = "owned",
    other_id: str = "other",
    approve: bool = False,
    force: bool = False,
    session: str = "A",
) -> RunnerResult:
    require_in_scope(target_dir, url, action="api hpp", force=force, tool="api_hpp_probe")
    parsed = urlparse(url if "://" in url else f"https://{url}")
    qs = parse_qs(parsed.query, keep_blank_values=True)
    polluted = urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            "",
            f"{param}={owned_id}&{param}={other_id}&"
            + urlencode({k: v[0] for k, v in qs.items() if k != param}),
            "",
        )
    )
    plan = {"url": polluted, "param": param, "approve": approve, "canary_ids": [owned_id, other_id]}
    ui.code_panel(json.dumps(plan, indent=2), title="api_hpp_probe", lexer="json")
    if not approve:
        _mark(target_dir, "hpp", url, "dry")
        return _dry(["api_hpp_probe", polluted], plan)
    result = http_mod.http_request(
        target_dir, polluted, session=session or None, approve=True, force=force, label="api_hpp"
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {}
    out = {
        "ok": True,
        "signal": False,
        "status": payload.get("status"),
        "preview": redact_text(str(payload.get("body_preview") or ""))[:200],
    }
    _mark(target_dir, "hpp", url, "active")
    return RunnerResult(["api_hpp_probe", polluted], True, 0, json.dumps(out), "", "executed")


def api_content_type_probe(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
    session: str = "A",
) -> RunnerResult:
    body = json.dumps(CANARY_BODY)
    plan = {
        "url": url,
        "types": ["application/json", "application/x-www-form-urlencoded", "multipart/form-data"],
        "approve": approve,
    }
    early = _gate(
        target_dir,
        url,
        action="api content-type probe",
        approve=approve,
        force=force,
        tool="api_content_type_probe",
        plan=plan,
    )
    if early:
        return early
    rows = []
    for ctype, data in (
        ("application/json", body),
        ("application/x-www-form-urlencoded", urlencode(CANARY_BODY)),
        ("multipart/form-data", body),
    ):
        result = http_mod.http_request(
            target_dir,
            url,
            method="POST",
            session=session or None,
            body=data,
            content_type=ctype,
            approve=True,
            force=force,
            label=f"ct_{ctype.split('/')[-1][:12]}",
            extra_headers={"X-Hackbot-Canary": "hb-api-canary"},
        )
        try:
            payload = json.loads(result.stdout) if result.stdout else {}
        except json.JSONDecodeError:
            payload = {}
        rows.append({"content_type": ctype, "status": payload.get("status")})
    out = {"ok": True, "rows": rows, "signal": len({r["status"] for r in rows}) > 1}
    _mark(target_dir, "api", url, "active", method="POST")
    return RunnerResult(["api_content_type_probe", url], True, 0, json.dumps(out), "", "executed")


def api_version_diff_probe(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
    session: str = "A",
) -> RunnerResult:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    path = parsed.path or "/"
    variants = []
    for needle, repl in (
        ("/v1/", "/v2/"),
        ("/api/", "/internal/"),
        ("/graphql", "/api/graphql"),
    ):
        if needle in path:
            variants.append(path.replace(needle, repl, 1))
    if not variants:
        variants = [path, path.rstrip("/") + "/v2"]
    plan = {"url": url, "variants": variants[:4], "approve": approve}
    early = _gate(
        target_dir,
        url,
        action="api version diff",
        approve=approve,
        force=force,
        tool="api_version_diff_probe",
        plan=plan,
    )
    if early:
        return early
    rows = []
    for p in variants[:4]:
        u = urlunparse((parsed.scheme, parsed.netloc, p, "", parsed.query, ""))
        try:
            require_in_scope(target_dir, u, action="api version diff", force=force)
            result = http_mod.http_request(
                target_dir, u, session=session or None, approve=True, force=force, label="ver_diff"
            )
            payload = json.loads(result.stdout) if result.stdout else {}
        except Exception as exc:  # noqa: BLE001
            payload = {"error": type(exc).__name__, "status": None}
        rows.append({"path": p, "status": payload.get("status")})
    out = {"ok": True, "rows": rows}
    _mark(target_dir, "api", url, "active")
    return RunnerResult(["api_version_diff_probe", url], True, 0, json.dumps(out), "", "executed")


def api_error_schema_probe(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
    session: str = "A",
) -> RunnerResult:
    plan = {"url": url, "body": {"hb_invalid": True}, "approve": approve}
    early = _gate(
        target_dir,
        url,
        action="api error schema",
        approve=approve,
        force=force,
        tool="api_error_schema_probe",
        plan=plan,
    )
    if early:
        return early
    result = http_mod.http_request(
        target_dir,
        url,
        method="POST",
        session=session or None,
        body=json.dumps({"hb_invalid_field": "HB_CANARY_SCHEMA", "__proto__": {"x": 1}}),
        content_type="application/json",
        approve=True,
        force=force,
        label="err_schema",
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {}
    preview = redact_text(str(payload.get("body_preview") or ""))
    out = {
        "ok": True,
        "status": payload.get("status"),
        "preview": preview[:400],
        "signal": any(k in preview.lower() for k in ("required", "schema", "validation", "field")),
    }
    _mark(target_dir, "api", url, "active", method="POST")
    return RunnerResult(["api_error_schema_probe", url], True, 0, json.dumps(out), "", "executed")


def api_cors_probe(
    target_dir: Path,
    url: str,
    *,
    origin: str = "https://hb-canary.example",
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    return web_probes.cors_probe(
        target_dir, url, origin=origin, approve=approve, force=force
    )


def api_cache_detect_probe(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    from .elite_probes import cache_poison_probe

    return cache_poison_probe(target_dir, url, approve=approve, force=force)


def api_graphql_variable_authz(
    target_dir: Path,
    url: str,
    *,
    query: str = "",
    session_a: str = "A",
    session_b: str = "B",
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    q = query or (
        "query HackbotObjectRead($id: ID!) { node(id: $id) { id __typename } }"
    )
    return graphql_authz_probe(
        target_dir,
        url,
        q,
        session_a=session_a,
        session_b=session_b,
        approve=approve,
        force=force,
    )


def api_graphql_batch_alias_probe(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    return graphql_batch_probe(target_dir, url, approve=approve, force=force)


def api_jwt_claim_diff(
    target_dir: Path,
    url: str,
    *,
    token: str = "",
    approve: bool = False,
    force: bool = False,
    session: str = "A",
) -> RunnerResult:
    """Offline JWT decode + optional safe active check with test-account token only."""
    import base64

    plan = {"url": url, "offline": True, "approve": approve, "has_token": bool(token)}
    ui.code_panel(json.dumps(plan, indent=2), title="api_jwt_claim_diff", lexer="json")
    claims: dict[str, Any] = {}
    if token and token.count(".") >= 2:
        try:
            payload_b64 = token.split(".")[1]
            pad = "=" * (-len(payload_b64) % 4)
            claims = json.loads(base64.urlsafe_b64decode(payload_b64 + pad).decode("utf-8"))
            # Drop obvious secrets
            for k in list(claims):
                if k.lower() in {"password", "secret", "key"}:
                    claims[k] = "[REDACTED]"
        except Exception as exc:  # noqa: BLE001
            claims = {"decode_error": type(exc).__name__}
    out: dict[str, Any] = {
        "ok": True,
        "claims": claims,
        "active": False,
        "note": "offline decode only unless approve+session token",
    }
    if not approve:
        _mark(target_dir, "jwt", url, "dry")
        return _dry(["api_jwt_claim_diff", url], {**plan, **out})
    require_in_scope(target_dir, url, action="jwt claim diff", force=force, tool="api_jwt_claim_diff")
    result = http_mod.http_request(
        target_dir,
        url,
        session=session or None,
        approve=True,
        force=force,
        label="jwt_claim",
        extra_headers={"X-Hackbot-Canary": "hb-api-canary"},
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {}
    out["active"] = True
    out["status"] = payload.get("status")
    _mark(target_dir, "jwt", url, "active")
    return RunnerResult(["api_jwt_claim_diff", url], True, 0, json.dumps(out), "", "executed")


def api_oauth_oidc_probe(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    return oidc_probe(target_dir, url, approve=approve, force=force)
