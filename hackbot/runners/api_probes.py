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


def _cache_authz_response(target_dir: Path, label: str, payload: dict[str, Any]) -> None:
    """Seed tools._RESPONSE_CACHE so assert_diff works after matrix."""
    try:
        from ..tools import _RESPONSE_CACHE, _cache_key

        _RESPONSE_CACHE[_cache_key(target_dir, label)] = payload
    except Exception:  # noqa: BLE001
        pass


def _swap_path_or_query(url: str, *, param: str, value: str) -> str:
    if not param or not value:
        return url
    parsed = urlparse(url if "://" in url else f"https://{url}")
    # path placeholder {id} or :id
    path = parsed.path or "/"
    for token in (f"{{{param}}}", f":{param}"):
        if token in path:
            path = path.replace(token, value)
            return urlunparse((parsed.scheme, parsed.netloc, path, "", parsed.query, ""))
    qs = parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [value]
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            path,
            "",
            urlencode({k: v[0] if v else "" for k, v in qs.items()}),
            "",
        )
    )


def api_authz_matrix(
    target_dir: Path,
    url: str,
    *,
    method: str = "GET",
    session_a: str = "A",
    session_b: str = "B",
    include_anon: bool = True,
    param: str = "",
    owned_id: str = "",
    other_id: str = "",
    body: str = "",
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    """Full A/B(/anon) authz matrix with session fixture checks + assert_idor_diff."""
    from ..diffing import assert_idor_diff
    from ..identity import load_identity

    identity = load_identity(target_dir)
    ready = set(identity.ready_sessions())
    url_base = url if "://" in url else f"https://{url}"
    url_owned = (
        _swap_path_or_query(url_base, param=param, value=owned_id)
        if param and owned_id
        else url_base
    )
    url_other = (
        _swap_path_or_query(url_base, param=param, value=other_id)
        if param and other_id
        else url_owned
    )
    plan = {
        "url": url_owned,
        "url_other": url_other if url_other != url_owned else None,
        "method": method,
        "sessions": [session_a, session_b] + (["anon"] if include_anon else []),
        "param": param or None,
        "approve": approve,
        "ready": sorted(ready),
        "fixtures_ok": session_a in ready and session_b in ready,
    }
    require_in_scope(target_dir, url_owned, action="api authz matrix", force=force, tool="api_authz_matrix")
    ui.code_panel(json.dumps(plan, indent=2), title="api_authz_matrix", lexer="json")
    cmd = ["api_authz_matrix", url_owned, session_a, session_b]

    if session_a not in ready or session_b not in ready:
        out = {
            "ok": False,
            "signal": False,
            "error": "sessions_missing",
            "ready": sorted(ready),
            "hint": "Load A/B into secrets/sessions.yaml (or session_bootstrap) before ACTIVE matrix.",
            **plan,
        }
        _mark(target_dir, "authz", url_owned, "dry", method=method)
        return RunnerResult(cmd, False, None, json.dumps(out), "", "error")

    if not approve:
        ui.dry_run_banner()
        _mark(target_dir, "authz", url_owned, "dry", method=method)
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    rows: list[dict[str, Any]] = []
    cached: dict[str, dict[str, Any]] = {}
    pairs = [
        (session_a, url_owned, f"authz_{session_a}"),
        (session_b, url_owned, f"authz_{session_b}"),
    ]
    if param and other_id:
        pairs.append((session_b, url_other, f"authz_{session_b}_other"))
    if include_anon:
        pairs.append(("", url_owned, "authz_anon"))

    meth = (method or "GET").upper()
    body_payload = None if meth == "GET" else (body or None)

    for sess, u, label in pairs:
        try:
            require_in_scope(target_dir, u, action="api authz matrix", force=force)
            result = http_mod.http_request(
                target_dir,
                u,
                method=meth,
                session=sess or None,
                body=body_payload,
                approve=True,
                force=force,
                label=label,
            )
            payload = json.loads(result.stdout) if result.stdout else {}
        except Exception as exc:  # noqa: BLE001
            payload = {"status": 0, "error": type(exc).__name__, "body_preview": "", "body": ""}
        _cache_authz_response(target_dir, label, payload)
        cached[label] = payload
        rows.append(
            {
                "session": sess or "anon",
                "label": label,
                "url": u,
                "status": payload.get("status"),
                "preview": redact_text(str(payload.get("body_preview") or ""))[:200],
            }
        )

    resp_a = cached.get(f"authz_{session_a}") or {}
    resp_b = cached.get(f"authz_{session_b}") or {}
    diff = assert_idor_diff(resp_a, resp_b, object_hint=url_owned)
    # Cross-object: B on other's id vs A on owned
    cross = None
    if f"authz_{session_b}_other" in cached:
        cross = assert_idor_diff(
            resp_a, cached[f"authz_{session_b}_other"], object_hint=url_other
        ).as_dict()

    signal = diff.verdict in {"confirmed", "likely"}
    if cross and cross.get("verdict") in {"confirmed", "likely"}:
        signal = True
    anon_status = next((r.get("status") for r in rows if r.get("session") == "anon"), None)
    out = {
        "ok": True,
        "signal": signal,
        "verdict": diff.verdict,
        "reason": diff.reason,
        "diff": diff.as_dict(),
        "cross_object": cross,
        "anon_status": anon_status,
        "rows": rows,
        "labels": {
            "assert_diff": [f"authz_{session_a}", f"authz_{session_b}"],
            "hint": "assert_diff label_a=authz_A label_b=authz_B (same process)",
        },
        "fixtures": {"ready": sorted(ready), "session_a": session_a, "session_b": session_b},
    }
    path = _save(target_dir, "api_authz_matrix", out)
    if path:
        out["evidence"] = path
    _mark(target_dir, "authz", url_owned, "pos" if signal else "neg", method=method)
    return RunnerResult(cmd, True, 0, json.dumps(out), "", "executed")


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
