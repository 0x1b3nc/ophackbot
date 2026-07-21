"""Detect login form, POST credentials from accounts.yaml, persist A/B sessions."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .. import ui
from ..accounts import ensure_accounts_example, load_accounts
from ..hunt_jar import merge_set_cookie
from ..identity import save_session
from ..redaction import redact_text
from .base import RunnerResult, require_in_scope

_CSRF_NAMES = ("csrf", "csrf_token", "csrftoken", "_token", "authenticity_token", "xsrf")


def _extract_csrf(html: str, field: str) -> str:
    # Prefer configured field, then common names
    names = [field] + [n for n in _CSRF_NAMES if n != field]
    for name in names:
        m = re.search(
            rf'<input[^>]+name=["\']{re.escape(name)}["\'][^>]+value=["\']([^"\']+)["\']',
            html,
            re.I,
        )
        if m:
            return m.group(1)
        m = re.search(
            rf'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']{re.escape(name)}["\']',
            html,
            re.I,
        )
        if m:
            return m.group(1)
        m = re.search(rf'name=["\']{re.escape(name)}["\'][^>]*content=["\']([^"\']+)["\']', html, re.I)
        if m:
            return m.group(1)
        m = re.search(rf'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']', html, re.I)
        if m:
            return m.group(1)
    return ""


def _looks_like_mfa(body: str, status: int) -> bool:
    low = body.lower()
    keys = ("mfa", "2fa", "otp", "one-time", "totp", "verification code", "two-factor")
    return any(k in low for k in keys) and status in {200, 401, 403}


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
    Dry-run unless approve. MFA → needs_setup (no fake success).
    """
    require_in_scope(target_dir, base_url, action="session bootstrap login", force=force)
    ensure_accounts_example(target_dir)
    accounts = load_accounts(target_dir)
    wanted = sessions or ["A", "B"]
    ready = [n for n in wanted if accounts.get(n) and accounts.get(n).ready()]  # type: ignore[union-attr]
    base = base_url if "://" in base_url else f"https://{base_url}"
    parsed = urllib.parse.urlparse(base)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    login_path = accounts.login.path or "/login"
    login_url = urllib.parse.urljoin(origin + "/", login_path.lstrip("/"))

    plan = {
        "login_url": login_url,
        "accounts_ready": ready,
        "wanted": wanted,
        "approve": approve,
        "method": accounts.login.method,
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
                }
            ),
            "",
            "error",
        )

    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    results: list[dict[str, Any]] = []
    needs_mfa = False
    for name in ready:
        acct = accounts.get(name)
        if not acct:
            continue
        # GET login page for CSRF
        from ..scoped_http import scoped_fetch_bytes

        csrf = ""
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
        csrf = _extract_csrf(html, accounts.login.csrf_field)
        body_map = {
            accounts.login.user_field: acct.username,
            accounts.login.pass_field: acct.password,
        }
        if csrf:
            body_map[accounts.login.csrf_field] = csrf
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
                method=accounts.login.method,
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

        if _looks_like_mfa(resp_body, status):
            needs_mfa = True
            results.append(
                {
                    "session": name,
                    "status": status,
                    "outcome": "needs_setup",
                    "reason": "mfa_detected",
                    "preview": redact_text(resp_body[:120]),
                }
            )
            continue

        persisted = _persist_session(target_dir, name, set_cookies=set_cookies, body=resp_body, url=login_url)
        ok = bool(persisted.get("ok")) and status < 400
        # Also accept 302/303 redirects as login success if cookies landed
        if status in {301, 302, 303, 307, 308} and persisted.get("ok"):
            ok = True
        results.append(
            {
                "session": name,
                "status": status,
                "outcome": "ok" if ok else "failed",
                "persisted": persisted,
                "preview": redact_text(resp_body[:120]),
            }
        )

    ok_count = sum(1 for r in results if r.get("outcome") == "ok")
    out = {
        "ok": ok_count > 0 and not needs_mfa,
        "signal": ok_count >= 1,
        "needs_setup": needs_mfa,
        "reason": "mfa_detected" if needs_mfa else (f"bootstrapped {ok_count} sessions" if ok_count else "login_failed"),
        "results": results,
        "login_url": login_url,
    }
    if needs_mfa:
        ui.warn("session_bootstrap: MFA/2FA detected — needs_setup")
    elif ok_count:
        ui.success(f"session_bootstrap: {ok_count} session(s) ready")
    else:
        ui.warn("session_bootstrap: no sessions persisted")
    return RunnerResult(cmd, True, 0, json.dumps(out), "", "executed")
