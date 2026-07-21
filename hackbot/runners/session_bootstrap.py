"""Detect login form/JSON/SSO, POST credentials from accounts.yaml, persist A/B sessions."""

from __future__ import annotations

import json
import re
import urllib.parse
from pathlib import Path
from typing import Any

from .. import ui
from ..accounts import ensure_accounts_example, load_accounts
from ..auth_continuity import (
    extract_csrf,
    looks_like_mfa,
    mfa_needs_setup_payload,
    session_smoke,
    sso_needs_setup_payload,
)
from ..hunt_jar import merge_set_cookie
from ..identity import save_session
from ..login_detect import detect_login
from ..redaction import redact_text
from .base import RunnerResult, require_in_scope


def _set_cookies_from_headers(headers: Any) -> list[str]:
    set_cookies: list[str] = []
    get_all = getattr(headers, "get_all", None) if headers else None
    if callable(get_all):
        set_cookies = list(get_all("Set-Cookie") or [])
    elif headers and headers.get("Set-Cookie"):
        set_cookies = [headers.get("Set-Cookie")]
    return set_cookies


def _persist_session(
    target_dir: Path,
    name: str,
    *,
    set_cookies: list[str],
    body: str,
    url: str,
) -> dict[str, Any]:
    cookie_parts = []
    for sc in set_cookies:
        first = sc.split(";", 1)[0].strip()
        if "=" in first:
            cookie_parts.append(first)
    cookie = "; ".join(cookie_parts)
    auth = ""
    m = re.search(r'"access_token"\s*:\s*"([^"]+)"', body)
    if not m:
        m = re.search(r'"token"\s*:\s*"([^"]+)"', body)
    if m:
        auth = f"Bearer {m.group(1)}"
    if not cookie and not auth:
        return {"ok": False, "error": "no_session_material"}
    save_session(
        target_dir,
        name,
        authorization=auth or None,
        cookie=cookie or None,
    )
    if set_cookies:
        try:
            merge_set_cookie(target_dir, set_cookies, url=url, session=name)
        except Exception:  # noqa: BLE001
            pass
    return {"ok": True, "has_cookie": bool(cookie), "has_auth": bool(auth)}


def session_bootstrap(
    target_dir: Path,
    base_url: str,
    *,
    approve: bool = False,
    force: bool = False,
    timeout: float = 15.0,
    sessions: list[str] | None = None,
) -> RunnerResult:
    """
    Login with accounts A/B from secrets/accounts.yaml.
    Detects form/JSON/SSO first. Dry-run unless approve. MFA/SSO → needs_setup.
    """
    require_in_scope(target_dir, base_url, action="session bootstrap login", force=force)
    ensure_accounts_example(target_dir)
    accounts = load_accounts(target_dir)
    wanted = sessions or ["A", "B"]
    ready = [n for n in wanted if accounts.get(n) and accounts.get(n).ready()]  # type: ignore[union-attr]
    base = base_url if "://" in base_url else f"https://{base_url}"
    parsed = urllib.parse.urlparse(base)
    origin = f"{parsed.scheme}://{parsed.netloc}"

    detected = detect_login(
        target_dir,
        base,
        approve=approve,
        force=force,
        timeout=timeout,
        persist=bool(approve),
    )

    # Prefer detected login URL; fall back to configured path
    login_path = accounts.login.path or "/login"
    login_url = urllib.parse.urljoin(origin + "/", login_path.lstrip("/"))
    content_type = accounts.login.content_type or "application/x-www-form-urlencoded"
    method = accounts.login.method or "POST"
    user_field = accounts.login.user_field
    pass_field = accounts.login.pass_field
    csrf_field = accounts.login.csrf_field

    if not detected.get("dry_run") and detected.get("ok"):
        kind = str(detected.get("kind") or "")
        if kind in {"form", "json_api"} and detected.get("login_url"):
            # Override defaults when config still looks stock OR detection is high-confidence
            stock = login_path in {"/login", "login"}
            if stock or detected.get("confidence") == "high":
                login_url = str(detected["login_url"])
                content_type = str(detected.get("content_type") or content_type)
                method = str(detected.get("method") or method)
                user_field = str(detected.get("user_field") or user_field)
                pass_field = str(detected.get("pass_field") or pass_field)
                csrf_field = str(detected.get("csrf_field") or csrf_field)

    plan = {
        "login_url": login_url,
        "accounts_ready": ready,
        "wanted": wanted,
        "approve": approve,
        "method": method,
        "content_type": content_type,
        "detect_kind": detected.get("kind") if not detected.get("dry_run") else None,
    }
    ui.code_panel(json.dumps(plan, indent=2), title="session_bootstrap", lexer="json")
    cmd = ["session_bootstrap", login_url, ",".join(ready)]

    if len(ready) < 1:
        return RunnerResult(
            cmd,
            False,
            None,
            json.dumps(
                {
                    "ok": False,
                    "signal": False,
                    "error": "accounts_missing",
                    "hint": "Copy secrets/accounts.example.yaml → accounts.yaml and fill A/B.",
                    "detect": detected,
                }
            ),
            "",
            "error",
        )

    if not approve:
        ui.dry_run_banner()
        return RunnerResult(
            cmd,
            False,
            None,
            json.dumps({"dry_run": True, **plan, "detect": detected}),
            "",
            "dry-run",
        )

    # SSO surface → operator setup (no password POST)
    if detected.get("kind") == "sso" or detected.get("reason") == "sso_detected":
        sso = sso_needs_setup_payload(
            login_url=str(detected.get("login_url") or login_url),
            sso_urls=list(detected.get("sso_urls") or []),
        )
        ui.warn("session_bootstrap: SSO/IdP detected — needs_setup (no IdP bypass)")
        for step in sso.get("next_steps") or []:
            ui.info(f"  → {step}")
        out = {
            "ok": False,
            "signal": False,
            "needs_setup": True,
            "reason": "sso_detected",
            "results": [],
            "login_url": login_url,
            "detect": detected,
            **sso,
        }
        return RunnerResult(cmd, True, 0, json.dumps(out), "", "executed")

    results: list[dict[str, Any]] = []
    needs_mfa = False
    for name in ready:
        acct = accounts.get(name)
        if not acct:
            continue
        from ..scoped_http import scoped_fetch_bytes

        try:
            resp = scoped_fetch_bytes(
                login_url,
                target_dir=target_dir,
                action="session bootstrap login",
                force=force,
                timeout=timeout,
                headers={"User-Agent": "hackbot-bootstrap"},
                max_bytes=80_000,
                gate_initial=False,
            )
            html = resp.body.decode("utf-8", errors="replace")
            pre_cookies = _set_cookies_from_headers(resp.headers)
        except Exception as exc:  # noqa: BLE001
            results.append({"session": name, "error": type(exc).__name__, "detail": str(exc)[:120]})
            continue

        _field, csrf = extract_csrf(html, csrf_field)
        use_json = "json" in (content_type or "").lower() or str(detected.get("kind")) == "json_api"
        if use_json:
            body_obj: dict[str, Any] = {
                user_field: acct.username,
                pass_field: acct.password,
            }
            # Common aliases for JSON APIs
            body_obj.setdefault("email", acct.username)
            body_obj.setdefault("username", acct.username)
            body_obj.setdefault("password", acct.password)
            if csrf:
                body_obj[csrf_field] = csrf
            encoded = json.dumps(body_obj).encode()
            headers = {
                "User-Agent": "hackbot-bootstrap",
                "Content-Type": "application/json",
                "Accept": "application/json",
            }
        else:
            body_map = {
                user_field: acct.username,
                pass_field: acct.password,
            }
            if csrf:
                body_map[csrf_field] = csrf
                body_map.setdefault(_field or csrf_field, csrf)
            encoded = urllib.parse.urlencode(body_map).encode()
            headers = {
                "User-Agent": "hackbot-bootstrap",
                "Content-Type": "application/x-www-form-urlencoded",
            }
        if pre_cookies:
            headers["Cookie"] = "; ".join(c.split(";", 1)[0] for c in pre_cookies)
        try:
            resp = scoped_fetch_bytes(
                login_url,
                target_dir=target_dir,
                action="session bootstrap login",
                force=force,
                timeout=timeout,
                method=method,
                data=encoded,
                headers=headers,
                max_bytes=80_000,
                gate_initial=False,
            )
            status = resp.status
            resp_body = resp.body.decode("utf-8", errors="replace")
            set_cookies = _set_cookies_from_headers(resp.headers) or pre_cookies
        except Exception as exc:  # noqa: BLE001
            results.append({"session": name, "error": type(exc).__name__})
            continue

        if looks_like_mfa(resp_body, status):
            needs_mfa = True
            mfa = mfa_needs_setup_payload(session=name, login_url=login_url)
            results.append(
                {
                    "session": name,
                    "status": status,
                    "outcome": "needs_setup",
                    "reason": "mfa_detected",
                    "hint": mfa.get("hint"),
                    "next_steps": mfa.get("next_steps"),
                    "preview": redact_text(resp_body[:120]),
                }
            )
            continue

        # SSO redirect after credential POST
        final_url = getattr(resp, "url", "") or ""
        if any(
            n in final_url.lower()
            for n in ("oauth", "openid", "okta", "auth0", "microsoftonline", "accounts.google")
        ):
            needs_mfa = True  # reuse needs_setup path
            sso = sso_needs_setup_payload(session=name, login_url=login_url, sso_urls=[final_url])
            results.append(
                {
                    "session": name,
                    "status": status,
                    "outcome": "needs_setup",
                    "reason": "sso_detected",
                    "hint": sso.get("hint"),
                    "next_steps": sso.get("next_steps"),
                    "preview": redact_text(resp_body[:120]),
                }
            )
            continue

        persisted = _persist_session(
            target_dir, name, set_cookies=set_cookies, body=resp_body, url=login_url
        )
        ok = bool(persisted.get("ok")) and status < 400
        if status in {301, 302, 303, 307, 308} and persisted.get("ok"):
            ok = True

        smoke: dict[str, Any] = {"skipped": True}
        if ok:
            smoke = session_smoke(
                target_dir,
                origin,
                session=name,
                approve=True,
                force=force,
                timeout=timeout,
            )
            if smoke.get("ok") is False and not smoke.get("skipped"):
                ok = False
                results.append(
                    {
                        "session": name,
                        "status": status,
                        "outcome": "failed",
                        "reason": "smoke_failed",
                        "persisted": persisted,
                        "smoke": smoke,
                        "preview": redact_text(resp_body[:120]),
                    }
                )
                continue

        results.append(
            {
                "session": name,
                "status": status,
                "outcome": "ok" if ok else "failed",
                "persisted": persisted,
                "smoke": smoke,
                "preview": redact_text(resp_body[:120]),
            }
        )

    ok_count = sum(1 for r in results if r.get("outcome") == "ok")
    needs_setup = needs_mfa or any(r.get("reason") == "sso_detected" for r in results)
    setup_reason = "mfa_detected"
    if any(r.get("reason") == "sso_detected" for r in results):
        setup_reason = "sso_detected"
    elif needs_mfa:
        setup_reason = "mfa_detected"

    out: dict[str, Any] = {
        "ok": ok_count > 0 and not needs_setup,
        "signal": ok_count >= 1,
        "needs_setup": needs_setup,
        "reason": (
            setup_reason
            if needs_setup
            else (f"bootstrapped {ok_count} sessions" if ok_count else "login_failed")
        ),
        "results": results,
        "login_url": login_url,
        "detect": {
            "kind": detected.get("kind"),
            "sso_urls": detected.get("sso_urls") or [],
            "confidence": detected.get("confidence"),
        },
    }
    if needs_setup:
        if setup_reason == "sso_detected":
            out.update(
                sso_needs_setup_payload(
                    login_url=login_url,
                    sso_urls=list(detected.get("sso_urls") or []),
                )
            )
        else:
            out.update(mfa_needs_setup_payload(login_url=login_url))
        out["results"] = results
        ui.warn(f"session_bootstrap: {setup_reason} — needs_setup (operator must finish login)")
        for step in out.get("next_steps") or []:
            ui.info(f"  → {step}")
    elif ok_count:
        ui.success(f"session_bootstrap: {ok_count} session(s) ready")
    else:
        ui.warn("session_bootstrap: no sessions persisted")
    return RunnerResult(cmd, True, 0, json.dumps(out), "", "executed")
