"""Elite / advanced probes — capped, dry-run default, SCOPE-gated.

Detection-oriented. No DoS, no weaponized smuggle, no data destruction.
"""

from __future__ import annotations

import json
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse
from urllib.request import Request

import yaml

from .. import ui
from ..coverage_map import mark_coverage_url
from ..evidence import EvidenceStore
from ..hunt_memory import Endpoint, HuntMemory
from ..policy_guard import ScopePolicy, host_from_target
from ..redaction import redact_text
from ..scoped_http import scoped_urlopen
from .base import RunnerResult, require_in_scope


def _dry(cmd: list[str], plan: dict[str, Any]) -> RunnerResult:
    ui.dry_run_banner()
    return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")


def _gate(
    target_dir: Path,
    url: str,
    *,
    action: str,
    approve: bool,
    force: bool,
    tool: str,
    plan: dict[str, Any],
) -> RunnerResult | None:
    require_in_scope(target_dir, url, action=action, force=force, tool=tool)
    ui.code_panel(json.dumps(plan, indent=2), title=tool, lexer="json")
    if not approve:
        mark_coverage_url(
            target_dir, cls=tool.replace("_probe", "").replace("_check", ""), url=url, status="dry", note=tool
        )
        return _dry([tool, url], plan)
    return None


def _save(target_dir: Path, name: str, payload: dict[str, Any]) -> str:
    try:
        return str(
            EvidenceStore(target_dir).save(name, json.dumps(payload, indent=2, ensure_ascii=False))
        )
    except Exception:  # noqa: BLE001
        return ""


def _fetch(
    target_dir: Path,
    url: str,
    *,
    method: str = "GET",
    force: bool = False,
    headers: dict[str, str] | None = None,
    data: bytes | None = None,
    action: str = "elite probe",
    timeout: float = 12.0,
) -> tuple[int, dict[str, str], str]:
    hdrs = {"User-Agent": "hackbot-elite/1", **(headers or {})}
    req = Request(url, data=data, method=method.upper(), headers=hdrs)
    resp = scoped_urlopen(
        req,
        target_dir=target_dir,
        action=action,
        force=force,
        timeout=timeout,
        gate_initial=False,
    )
    body = (resp.body or b"")[:20000].decode("utf-8", errors="replace")
    rh = {k: v for k, v in (resp.headers.items() if resp.headers else [])}
    return int(resp.status), rh, body


def cache_poison_probe(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    plan = {"url": url, "checks": ["unkeyed_x_forwarded", "path_suffix_css"], "approve": approve}
    early = _gate(
        target_dir,
        url,
        action="cache poison detection",
        approve=approve,
        force=force,
        tool="cache_poison_probe",
        plan=plan,
    )
    if early:
        return early
    findings: list[str] = []
    parsed = urlparse(url)
    decoy = urljoin(url, (parsed.path or "/") + "/static.css")
    try:
        status, headers, _body = _fetch(
            target_dir, decoy, force=force, action="cache poison detection"
        )
        cache_hdr = str(headers.get("Cache-Control") or headers.get("Age") or "")
        if status == 200 and ("max-age" in cache_hdr.lower() or headers.get("Age")):
            findings.append("path_suffix_may_be_cached")
    except Exception as exc:  # noqa: BLE001
        findings.append(f"decoy_error:{type(exc).__name__}")
    try:
        _status, headers, body = _fetch(
            target_dir,
            url,
            force=force,
            action="cache poison detection",
            headers={"X-Forwarded-Host": "cache-canary.invalid"},
        )
        blob = (body or "")[:8000] + str(headers)
        if "cache-canary.invalid" in blob:
            findings.append("x_forwarded_host_reflected")
    except Exception as exc:  # noqa: BLE001
        findings.append(f"xfh_error:{type(exc).__name__}")
    payload = {
        "ok": True,
        "signal": bool(findings),
        "findings": findings,
        "url": redact_text(url),
    }
    ev = _save(target_dir, "cache_poison_probe.json", payload)
    mark_coverage_url(
        target_dir,
        cls="cache",
        url=url,
        status="pos" if findings else "neg",
        note="cache_poison_probe",
    )
    return RunnerResult(
        ["cache_poison_probe", url],
        True,
        0,
        json.dumps({**payload, "evidence": ev}),
        "",
        "executed",
    )


def http_smuggle_probe(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    plan = {
        "url": url,
        "mode": "detection_only",
        "note": "No CL.TE attack body; fingerprint only",
        "approve": approve,
    }
    early = _gate(
        target_dir,
        url,
        action="http smuggling detection",
        approve=approve,
        force=force,
        tool="http_smuggle_probe",
        plan=plan,
    )
    if early:
        return early
    hints: list[str] = []
    try:
        status, headers, _ = _fetch(
            target_dir, url, method="OPTIONS", force=force, action="http smuggling detection"
        )
        allow = str(headers.get("Allow") or "")
        via = str(headers.get("Via") or headers.get("Server") or "")
        if "chunked" in str(headers).lower():
            hints.append("chunked_mentioned")
        if via:
            hints.append(f"via_or_server:{redact_text(via)[:80]}")
        hints.append(f"options_status:{status}")
        if allow:
            hints.append(f"allow:{allow[:120]}")
    except Exception as exc:  # noqa: BLE001
        hints.append(f"error:{type(exc).__name__}")
    payload = {
        "ok": True,
        "signal": False,
        "detection_only": True,
        "hints": hints,
        "stop": "Do not escalate to desync DoS; lab proof only.",
        "url": redact_text(url),
    }
    ev = _save(target_dir, "http_smuggle_probe.json", payload)
    mark_coverage_url(target_dir, cls="smuggle", url=url, status="active", note="detect_only")
    return RunnerResult(
        ["http_smuggle_probe", url],
        True,
        0,
        json.dumps({**payload, "evidence": ev}),
        "",
        "executed",
    )


def host_header_probe(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    plan = {"url": url, "host_override": "evil.example", "approve": approve}
    early = _gate(
        target_dir,
        url,
        action="host header probe",
        approve=approve,
        force=force,
        tool="host_header_probe",
        plan=plan,
    )
    if early:
        return early
    findings: list[str] = []
    try:
        status, headers, body = _fetch(
            target_dir,
            url,
            force=force,
            action="host header probe",
            headers={"X-Forwarded-Host": "evil.example", "X-Host": "evil.example"},
        )
        blob = ((body or "") + str(headers))[:12000]
        if "evil.example" in blob:
            findings.append("host_reflection")
        if status in {301, 302, 303, 307, 308}:
            loc = str(headers.get("Location") or "")
            if "evil.example" in loc:
                findings.append("redirect_uses_injected_host")
    except Exception as exc:  # noqa: BLE001
        findings.append(f"error:{type(exc).__name__}")
    payload = {"ok": True, "signal": bool(findings), "findings": findings, "url": redact_text(url)}
    ev = _save(target_dir, "host_header_probe.json", payload)
    mark_coverage_url(
        target_dir, cls="host-header", url=url, status="pos" if findings else "neg"
    )
    return RunnerResult(
        ["host_header_probe", url],
        True,
        0,
        json.dumps({**payload, "evidence": ev}),
        "",
        "executed",
    )


def absolute_url_probe(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    plan = {"url": url, "mode": "absolute_form_compare", "approve": approve}
    early = _gate(
        target_dir,
        url,
        action="absolute url probe",
        approve=approve,
        force=force,
        tool="absolute_url_probe",
        plan=plan,
    )
    if early:
        return early
    findings: list[str] = []
    try:
        status, headers, body = _fetch(
            target_dir, url, force=force, action="absolute url probe"
        )
        loc = str(headers.get("Location") or "")
        if loc.startswith("//"):
            findings.append("protocol_relative_redirect")
        if "\\" in loc:
            findings.append("backslash_in_location")
        payload = {
            "ok": True,
            "signal": bool(findings),
            "status": status,
            "findings": findings,
            "location": redact_text(loc)[:200],
            "body_preview": redact_text((body or "")[:200]),
            "url": redact_text(url),
        }
    except Exception as exc:  # noqa: BLE001
        payload = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    ev = _save(target_dir, "absolute_url_probe.json", payload)
    return RunnerResult(
        ["absolute_url_probe", url],
        True,
        0,
        json.dumps({**payload, "evidence": ev}),
        "",
        "executed",
    )


def graphql_batch_probe(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    plan = {"url": url, "batch_size": 3, "approve": approve}
    early = _gate(
        target_dir,
        url,
        action="graphql batch probe",
        approve=approve,
        force=force,
        tool="graphql_batch_probe",
        plan=plan,
    )
    if early:
        return early
    batch = [
        {"query": "query { __typename }"},
        {"query": "query { __typename }"},
        {"query": "query { __typename }"},
    ]
    signal = False
    detail: dict[str, Any] = {}
    try:
        status, _headers, body = _fetch(
            target_dir,
            url,
            method="POST",
            force=force,
            action="graphql batch probe",
            headers={"Content-Type": "application/json"},
            data=json.dumps(batch).encode("utf-8"),
            timeout=15,
        )
        detail = {"status": status, "body_preview": redact_text((body or "")[:500])}
        if status == 200 and body and body.strip().startswith("["):
            signal = True
            detail["reason"] = "array_response_suggests_batching"
    except Exception as exc:  # noqa: BLE001
        detail = {"error": f"{type(exc).__name__}: {exc}"}
    payload = {"ok": True, "signal": signal, "detail": detail, "url": redact_text(url)}
    ev = _save(target_dir, "graphql_batch_probe.json", payload)
    mark_coverage_url(
        target_dir, cls="graphql", url=url, status="pos" if signal else "neg", param="batch"
    )
    return RunnerResult(
        ["graphql_batch_probe", url],
        True,
        0,
        json.dumps({**payload, "evidence": ev}),
        "",
        "executed",
    )


def graphql_authz_probe(
    target_dir: Path,
    url: str,
    query: str,
    *,
    session_a: str = "A",
    session_b: str = "B",
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    plan = {
        "url": url,
        "query": (query or "")[:200],
        "session_a": session_a,
        "session_b": session_b,
        "approve": approve,
    }
    early = _gate(
        target_dir,
        url,
        action="graphql authz probe",
        approve=approve,
        force=force,
        tool="graphql_authz_probe",
        plan=plan,
    )
    if early:
        return early
    from ..identity import load_identity

    ident = load_identity(target_dir)

    def _post(session: str) -> dict[str, Any]:
        headers = {"Content-Type": "application/json"}
        headers.update(ident.merge_headers(session) if session else {})
        status, _hdrs, body = _fetch(
            target_dir,
            url,
            method="POST",
            force=force,
            action="graphql authz probe",
            headers=headers,
            data=json.dumps({"query": query}).encode("utf-8"),
            timeout=15,
        )
        return {
            "status": status,
            "body": redact_text((body or "")[:1500]),
            "len": len(body or ""),
        }

    a = _post(session_a)
    b = _post(session_b)
    signal = a.get("status") == 200 and b.get("status") == 200 and a.get("body") == b.get("body")
    payload = {
        "ok": True,
        "signal": bool(signal),
        "reason": "identical_bodies_cross_session" if signal else "differ_or_denied",
        "a": a,
        "b": b,
        "url": redact_text(url),
    }
    ev = _save(target_dir, "graphql_authz_probe.json", payload)
    mark_coverage_url(
        target_dir,
        cls="graphql-authz",
        url=url,
        authz=f"{session_a}/{session_b}",
        status="pos" if signal else "neg",
    )
    return RunnerResult(
        ["graphql_authz_probe", url],
        True,
        0,
        json.dumps({**payload, "evidence": ev}),
        "",
        "executed",
    )


def websocket_authz_probe(
    target_dir: Path,
    url: str,
    *,
    message: str = "",
    session: str = "",
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    plan = {"url": url, "message": (message or "")[:120], "session": session, "approve": approve}
    early = _gate(
        target_dir,
        url,
        action="websocket authz probe",
        approve=approve,
        force=force,
        tool="websocket_authz_probe",
        plan=plan,
    )
    if early:
        return early
    from . import websocket_probe as ws

    result = ws.websocket_probe(
        target_dir,
        url,
        approve=True,
        force=force,
        message=message or "",
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    payload["authz_note"] = "Compare second session separately; check subscribe ACLs."
    payload["session"] = session or "anon"
    mark_coverage_url(
        target_dir, cls="websocket-authz", url=url, authz=session or "anon", status="active"
    )
    return RunnerResult(
        ["websocket_authz_probe", url],
        result.executed,
        result.returncode,
        json.dumps(payload),
        result.stderr,
        result.message,
    )


def saml_probe(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    plan = {"url": url, "checks": ["acs_form", "relay_state", "sig_hints"], "approve": approve}
    early = _gate(
        target_dir, url, action="saml probe", approve=approve, force=force, tool="saml_probe", plan=plan
    )
    if early:
        return early
    findings: list[str] = []
    try:
        status, _headers, body = _fetch(target_dir, url, force=force, action="saml probe", timeout=15)
        low = (body or "").lower()
        if "saml" in low or "sso" in low:
            findings.append("saml_markers")
        if "relaystate" in low.replace("_", ""):
            findings.append("relay_state_field")
        if "xml" in low and "signature" not in low:
            findings.append("possible_unsigned_assertion_surface")
        payload = {
            "ok": True,
            "status": status,
            "signal": bool(findings),
            "findings": findings,
            "url": redact_text(url),
            "note": "No assertion forge; lab-only for signature bypass PoCs.",
        }
    except Exception as exc:  # noqa: BLE001
        payload = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    ev = _save(target_dir, "saml_probe.json", payload)
    return RunnerResult(
        ["saml_probe", url], True, 0, json.dumps({**payload, "evidence": ev}), "", "executed"
    )


def oidc_probe(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    plan = {"url": url, "checks": ["discovery", "redirect_uri"], "approve": approve}
    early = _gate(
        target_dir, url, action="oidc probe", approve=approve, force=force, tool="oidc_probe", plan=plan
    )
    if early:
        return early
    parsed = urlparse(url)
    issuer = f"{parsed.scheme}://{parsed.netloc}"
    discovery = urljoin(issuer + "/", ".well-known/openid-configuration")
    detail: dict[str, Any] = {"issuer": issuer}
    try:
        status, _h, body = _fetch(
            target_dir, discovery, force=force, action="oidc probe", timeout=12
        )
        detail["discovery_status"] = status
        if status == 200 and body:
            try:
                meta = json.loads(body)
                detail["authorization_endpoint"] = meta.get("authorization_endpoint")
                detail["token_endpoint"] = meta.get("token_endpoint")
            except json.JSONDecodeError:
                detail["discovery_parse"] = "fail"
    except Exception as exc:  # noqa: BLE001
        detail["discovery_error"] = f"{type(exc).__name__}: {exc}"
    from . import oauth_jwt

    oauth_res = oauth_jwt.oauth_probe(target_dir, url, approve=False, force=force)
    try:
        detail["oauth_dry"] = json.loads(oauth_res.stdout) if oauth_res.stdout else {}
    except json.JSONDecodeError:
        detail["oauth_dry"] = {}
    payload = {"ok": True, "signal": bool(detail.get("authorization_endpoint")), "detail": detail}
    ev = _save(target_dir, "oidc_probe.json", payload)
    return RunnerResult(
        ["oidc_probe", url], True, 0, json.dumps({**payload, "evidence": ev}), "", "executed"
    )


def session_fixation_probe(
    target_dir: Path,
    url: str,
    *,
    login_url: str = "",
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    plan = {"url": url, "login_url": login_url or url, "approve": approve}
    early = _gate(
        target_dir,
        url,
        action="session fixation probe",
        approve=approve,
        force=force,
        tool="session_fixation_probe",
        plan=plan,
    )
    if early:
        return early
    findings: list[str] = []
    try:
        status, headers, _ = _fetch(
            target_dir, url, force=force, action="session fixation probe"
        )
        set_cookie = str(headers.get("Set-Cookie") or "")
        if set_cookie:
            findings.append("preauth_set_cookie")
        payload = {
            "ok": True,
            "status": status,
            "preauth_set_cookie": bool(set_cookie),
            "findings": findings,
            "next": "Compare cookie before/after login via browser_capture_session",
            "url": redact_text(url),
        }
    except Exception as exc:  # noqa: BLE001
        payload = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    ev = _save(target_dir, "session_fixation_probe.json", payload)
    return RunnerResult(
        ["session_fixation_probe", url],
        True,
        0,
        json.dumps({**payload, "evidence": ev}),
        "",
        "executed",
    )


def token_binding_check(
    target_dir: Path,
    url: str,
    *,
    session: str = "",
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    plan = {"url": url, "session": session, "approve": approve}
    early = _gate(
        target_dir,
        url,
        action="token binding check",
        approve=approve,
        force=force,
        tool="token_binding_check",
        plan=plan,
    )
    if early:
        return early
    from ..identity import load_identity

    headers = load_identity(target_dir).merge_headers(session) if session else {}
    try:
        status, _hdrs, _body = _fetch(
            target_dir,
            url,
            force=force,
            action="token binding check",
            headers=headers or None,
        )
        status2, _, _ = _fetch(
            target_dir,
            url,
            force=force,
            action="token binding check",
            headers={**(headers or {}), "User-Agent": "hackbot-token-binding-check/1"},
        )
        bound = status == 200 and status2 not in {200}
        payload = {
            "ok": True,
            "signal": bound,
            "status_default": status,
            "status_alt_ua": status2,
            "reason": "ua_sensitive" if bound else "token_accepted_across_ua",
            "url": redact_text(url),
        }
    except Exception as exc:  # noqa: BLE001
        payload = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    ev = _save(target_dir, "token_binding_check.json", payload)
    return RunnerResult(
        ["token_binding_check", url],
        True,
        0,
        json.dumps({**payload, "evidence": ev}),
        "",
        "executed",
    )


def cdn_origin_hint(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    plan = {"url": url, "approve": approve}
    early = _gate(
        target_dir,
        url,
        action="cdn origin hint",
        approve=approve,
        force=force,
        tool="cdn_origin_hint",
        plan=plan,
    )
    if early:
        return early
    hints: list[str] = []
    try:
        status, headers, _ = _fetch(target_dir, url, force=force, action="cdn origin hint")
        for k, v in headers.items():
            kl = k.lower()
            if kl in {"cf-ray", "x-amz-cf-id", "x-cache", "x-served-by", "via", "server"}:
                hints.append(f"{k}:{redact_text(str(v))[:80]}")
        payload = {"ok": True, "status": status, "hints": hints, "url": redact_text(url)}
    except Exception as exc:  # noqa: BLE001
        payload = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    ev = _save(target_dir, "cdn_origin_hint.json", payload)
    return RunnerResult(
        ["cdn_origin_hint", url], True, 0, json.dumps({**payload, "evidence": ev}), "", "executed"
    )


def takeover_probe(
    target_dir: Path,
    host: str,
    *,
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    url = host if "://" in host else f"https://{host}"
    plan = {"host": host, "mode": "fingerprint_only", "approve": approve}
    early = _gate(
        target_dir,
        url,
        action="subdomain takeover fingerprint",
        approve=approve,
        force=force,
        tool="takeover_probe",
        plan=plan,
    )
    if early:
        return early
    findings: list[str] = []
    dns_notes: list[str] = []
    h = host_from_target(url) or host
    try:
        infos = socket.getaddrinfo(h, 443)
        dns_notes.append(f"resolves:{len(infos)}")
    except socket.gaierror:
        dns_notes.append("nxdomain_or_no_resolve")
        findings.append("dangling_dns_candidate")
    try:
        status, _headers, body = _fetch(
            target_dir, url, force=force, action="subdomain takeover fingerprint"
        )
        text = (body or "").lower()
        for needle in (
            "no such app",
            "there is no app configured",
            "nosuchbucket",
            "no such bucket",
            "heroku | no such app",
        ):
            if needle in text:
                findings.append(f"fingerprint:{needle}")
        payload = {
            "ok": True,
            "status": status,
            "dns": dns_notes,
            "findings": findings,
            "signal": bool(findings),
            "host": h,
            "note": "Do not register/claim services; report fingerprint only.",
        }
    except Exception as exc:  # noqa: BLE001
        payload = {
            "ok": True,
            "dns": dns_notes,
            "findings": findings,
            "signal": bool(findings),
            "error": f"{type(exc).__name__}: {exc}",
        }
    ev = _save(target_dir, "takeover_probe.json", payload)
    return RunnerResult(
        ["takeover_probe", host], True, 0, json.dumps({**payload, "evidence": ev}), "", "executed"
    )


def ssrf_protocol_matrix(
    target_dir: Path,
    url: str,
    param: str,
    *,
    approve: bool = False,
    force: bool = False,
) -> RunnerResult:
    policy = ScopePolicy.load(target_dir)
    allow_exotic = policy.allows_level3() or force
    protocols = ["https", "http"]
    if allow_exotic:
        protocols.extend(["file", "gopher", "dict"])
    plan = {
        "url": url,
        "param": param,
        "protocols": protocols,
        "approve": approve,
        "exotic": allow_exotic,
    }
    early = _gate(
        target_dir,
        url,
        action="ssrf protocol matrix",
        approve=approve,
        force=force,
        tool="ssrf_protocol_matrix",
        plan=plan,
    )
    if early:
        return early
    from . import ssrf_probe as ssrf

    result = ssrf.ssrf_probe(target_dir, url, param=param, approve=True, force=force)
    try:
        base = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        base = {}
    payload = {
        "ok": True,
        "base": base,
        "protocols_planned": protocols,
        "exotic_blocked": not allow_exotic,
        "note": "file/gopher/dict only when SCOPE L3 or force; default http(s) canaries.",
    }
    ev = _save(target_dir, "ssrf_protocol_matrix.json", payload)
    mark_coverage_url(target_dir, cls="ssrf", url=url, param=param, status="active")
    return RunnerResult(
        ["ssrf_protocol_matrix", url],
        True,
        0,
        json.dumps({**payload, "evidence": ev}),
        "",
        "executed",
    )


def asset_graph_build(target_dir: Path) -> dict[str, Any]:
    mem = HuntMemory(target_dir)
    endpoints = mem.endpoints()
    nodes: list[dict[str, Any]] = []
    for ep in endpoints:
        nodes.append(
            {
                "url": ep.url,
                "method": ep.method or "GET",
                "params": list(ep.params or []),
                "source": ep.source or "",
            }
        )
    graph = {
        "updated": datetime.now(timezone.utc).isoformat(),
        "nodes": nodes[:500],
        "edges": [],
        "sources": sorted({str(n.get("source") or "") for n in nodes if n.get("source")}),
    }
    path = Path(target_dir) / "hunt" / "asset_graph.yaml"
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(graph, sort_keys=False, allow_unicode=True), encoding="utf-8")
    return {"ok": True, "nodes": len(nodes), "path": str(path), "sources": graph["sources"]}


def burp_watch(target_dir: Path, *, limit: int = 40) -> dict[str, Any]:
    from . import burp as burp_runner

    hist = burp_runner.burp_proxy_history(limit=limit)
    if not hist.get("ok"):
        return hist
    policy = ScopePolicy.load(target_dir)
    candidates: list[dict[str, Any]] = []
    seen: set[str] = set()
    rows = hist.get("items") or hist.get("history") or []
    for row in rows[:limit]:
        if not isinstance(row, dict):
            continue
        url = str(row.get("url") or row.get("path") or "")
        method = str(row.get("method") or "GET").upper()
        if not url:
            continue
        try:
            if policy.target_out_of_scope(url) or not policy.target_in_scope(url):
                continue
        except Exception:  # noqa: BLE001
            continue
        parsed = urlparse(url)
        key = f"{method}|{parsed.path}"
        if key in seen:
            continue
        seen.add(key)
        candidates.append(
            {
                "method": method,
                "url": redact_text(url),
                "path": parsed.path,
                "priority": _priority_for_path(parsed.path),
            }
        )
    candidates.sort(key=lambda c: -int(c.get("priority") or 0))
    return {"ok": True, "candidates": candidates[:limit], "count": len(candidates)}


def proxy_correlate(
    target_dir: Path, *, limit: int = 40, seed_surface: bool = True
) -> dict[str, Any]:
    watched = burp_watch(target_dir, limit=limit)
    if not watched.get("ok"):
        return watched
    seeded = 0
    if seed_surface:
        mem = HuntMemory(target_dir)
        eps: list[Endpoint] = []
        for c in watched.get("candidates") or []:
            # Prefer non-redacted raw if present
            url = str(c.get("url") or "")
            if not url or "…" in url or "[REDACTED]" in url:
                continue
            eps.append(
                Endpoint(
                    url=url,
                    method=str(c.get("method") or "GET"),
                    params=[],
                    auth_required=False,
                    source="burp",
                    notes="proxy_correlate",
                )
            )
        if eps:
            mem.upsert_endpoints(eps)
            seeded = len(eps)
    top = (watched.get("candidates") or [])[:5]
    next_step = ""
    if top:
        t = top[0]
        next_step = (
            f"hypothesis: authz on {t.get('path')} | endpoint={t.get('url')} | "
            f"aggression 2 | tool=idor_probe or workflow_run | expected evidence assert_diff"
        )
    return {
        "ok": True,
        "candidates": watched.get("candidates"),
        "seeded": seeded,
        "next_step": next_step,
    }


def _priority_for_path(path: str) -> int:
    p = (path or "").lower()
    score = 0
    for needle, pts in (
        ("/admin", 50),
        ("/api/", 40),
        ("/graphql", 45),
        ("/invite", 55),
        ("/order", 50),
        ("/account", 45),
        ("/user", 40),
        ("/login", 10),
    ):
        if needle in p:
            score += pts
    return score
