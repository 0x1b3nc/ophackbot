"""Auth continuity: CSRF for writes, session refresh on 401, clear MFA needs_setup."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

import yaml

from .accounts import has_accounts, load_accounts
from .identity import load_identity, save_session
from .scoped_http import scoped_fetch_bytes

CSRF_FILE = "csrf.yaml"
_CSRF_NAMES = (
    "csrf",
    "csrf_token",
    "csrftoken",
    "_token",
    "authenticity_token",
    "xsrf",
    "xsrf_token",
)
_CSRF_HEADERS = (
    "X-CSRF-Token",
    "X-CSRFToken",
    "X-XSRF-TOKEN",
)


def extract_csrf(html: str, preferred_field: str = "csrf_token") -> tuple[str, str]:
    """Return (field_name, token) from HTML/meta, or ("", "")."""
    names = [preferred_field] + [n for n in _CSRF_NAMES if n != preferred_field]
    for name in names:
        m = re.search(
            rf'<input[^>]+name=["\']{re.escape(name)}["\'][^>]+value=["\']([^"\']+)["\']',
            html,
            re.I,
        )
        if m:
            return name, m.group(1)
        m = re.search(
            rf'<input[^>]+value=["\']([^"\']+)["\'][^>]+name=["\']{re.escape(name)}["\']',
            html,
            re.I,
        )
        if m:
            return name, m.group(1)
    m = re.search(
        r'<meta[^>]+name=["\']csrf-token["\'][^>]+content=["\']([^"\']+)["\']',
        html,
        re.I,
    )
    if m:
        return "csrf_token", m.group(1)
    m = re.search(
        r'<meta[^>]+name=["\']_csrf["\'][^>]+content=["\']([^"\']+)["\']',
        html,
        re.I,
    )
    if m:
        return "_csrf", m.group(1)
    return "", ""


def looks_like_mfa(body: str, status: int) -> bool:
    low = (body or "").lower()
    keys = (
        "mfa",
        "2fa",
        "otp",
        "one-time",
        "totp",
        "verification code",
        "two-factor",
        "authenticator app",
        "enter the code",
    )
    return any(k in low for k in keys) and status in {200, 401, 403}


def mfa_needs_setup_payload(*, session: str = "", login_url: str = "") -> dict[str, Any]:
    return {
        "ok": False,
        "needs_setup": True,
        "reason": "mfa_detected",
        "session": session,
        "login_url": login_url,
        "hint": (
            "MFA/2FA challenge detected. Complete login manually, save the resulting "
            "cookie/token into secrets/sessions.yaml (or /session set), then resume hunt. "
            "Hackbot will not bypass MFA."
        ),
        "next_steps": [
            "Finish MFA in a browser for the test account",
            "Copy Cookie / Authorization into secrets/sessions.yaml under A/B",
            "Or: /session set A --cookie '...' then /hunt again",
        ],
    }


def _csrf_path(target_dir: Path) -> Path:
    return Path(target_dir) / "hunt" / CSRF_FILE


def load_csrf_cache(target_dir: Path) -> dict[str, Any]:
    path = _csrf_path(target_dir)
    if not path.exists():
        return {"tokens": {}}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001
        return {"tokens": {}}
    if not isinstance(data, dict):
        return {"tokens": {}}
    data.setdefault("tokens", {})
    return data


def save_csrf_cache(target_dir: Path, data: dict[str, Any]) -> None:
    path = _csrf_path(target_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        yaml.safe_dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )


def fetch_csrf(
    target_dir: Path,
    url: str,
    *,
    session: str = "",
    force: bool = False,
    timeout: float = 12.0,
    preferred_field: str = "csrf_token",
) -> dict[str, Any]:
    """GET ``url`` with session auth and extract a CSRF token for later writes."""
    from .identity import load_identity

    full = url if "://" in url else f"https://{url}"
    headers = {"User-Agent": "hackbot-csrf"}
    if session:
        headers.update(load_identity(target_dir).merge_headers(session))
    try:
        resp = scoped_fetch_bytes(
            full,
            target_dir=target_dir,
            action="csrf fetch for write",
            force=force,
            timeout=timeout,
            headers=headers,
            max_bytes=120_000,
            gate_initial=True,
        )
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": type(exc).__name__, "detail": str(exc)[:160]}
    html = resp.body.decode("utf-8", errors="replace")
    field, token = extract_csrf(html, preferred_field)
    if not token:
        # try cache
        cache = load_csrf_cache(target_dir)
        cached = (cache.get("tokens") or {}).get(session or "_") or {}
        if cached.get("token"):
            return {
                "ok": True,
                "field": cached.get("field") or preferred_field,
                "token": cached["token"],
                "source": "cache",
                "status": resp.status,
            }
        return {"ok": False, "error": "csrf_not_found", "status": resp.status}
    cache = load_csrf_cache(target_dir)
    tokens = dict(cache.get("tokens") or {})
    tokens[session or "_"] = {"field": field, "token": token, "url": full}
    cache["tokens"] = tokens
    save_csrf_cache(target_dir, cache)
    # Also stash common CSRF headers on the session for subsequent requests
    if session and token:
        try:
            save_session(
                target_dir,
                session,
                headers={"X-CSRF-Token": token, "X-CSRFToken": token},
            )
        except Exception:  # noqa: BLE001
            pass
    return {
        "ok": True,
        "field": field,
        "token": token,
        "source": "live",
        "status": resp.status,
    }


def inject_csrf(
    body: str | None,
    *,
    field: str,
    token: str,
    content_type: str = "application/json",
) -> str | None:
    """Inject CSRF into JSON or leave body unchanged if not applicable."""
    if not token:
        return body
    if body is None:
        body = "{}"
    ct = (content_type or "").lower()
    if "json" in ct or (body.strip().startswith("{") or body.strip().startswith("[")):
        try:
            data = json.loads(body) if body.strip() else {}
        except json.JSONDecodeError:
            return body
        if isinstance(data, dict):
            data.setdefault(field or "csrf_token", token)
            data.setdefault("csrf_token", token)
            data.setdefault("_token", token)
            return json.dumps(data, separators=(",", ":"))
        return body
    # form-urlencoded
    from urllib.parse import parse_qsl, urlencode

    pairs = dict(parse_qsl(body, keep_blank_values=True))
    pairs[field or "csrf_token"] = token
    return urlencode(pairs)


def prepare_write(
    target_dir: Path,
    url: str,
    *,
    session: str,
    body: str | None,
    force: bool = False,
    content_type: str = "application/json",
) -> tuple[str | None, dict[str, str], dict[str, Any]]:
    """Fetch CSRF and return (body, extra_headers, meta)."""
    accounts = load_accounts(target_dir)
    preferred = accounts.login.csrf_field if accounts.login else "csrf_token"
    meta = fetch_csrf(
        target_dir,
        url,
        session=session,
        force=force,
        preferred_field=preferred,
    )
    extra: dict[str, str] = {}
    if meta.get("ok") and meta.get("token"):
        token = str(meta["token"])
        field = str(meta.get("field") or preferred)
        for h in _CSRF_HEADERS:
            extra[h] = token
        body = inject_csrf(body, field=field, token=token, content_type=content_type)
    return body, extra, meta


def refresh_session(
    target_dir: Path,
    base_url: str,
    *,
    session: str,
    approve: bool = False,
    force: bool = False,
    timeout: float = 15.0,
) -> dict[str, Any]:
    """Re-login one account from accounts.yaml and persist into sessions.yaml."""
    from .runners.session_bootstrap import session_bootstrap

    if not approve:
        return {"ok": False, "error": "approve_required", "session": session}
    if not has_accounts(target_dir):
        return {
            "ok": False,
            "error": "accounts_missing",
            "session": session,
            "hint": "Fill secrets/accounts.yaml then retry",
        }
    result = session_bootstrap(
        target_dir,
        base_url,
        approve=True,
        force=force,
        timeout=timeout,
        sessions=[session],
    )
    try:
        data = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        data = {}
    if data.get("needs_setup"):
        payload = mfa_needs_setup_payload(session=session, login_url=str(data.get("login_url") or ""))
        payload["refresh"] = False
        return payload
    rows = data.get("results") or []
    ok_row = next((r for r in rows if r.get("session") == session and r.get("outcome") == "ok"), None)
    if not ok_row and rows:
        ok_row = next((r for r in rows if r.get("outcome") == "ok"), None)
    ready = load_identity(target_dir).ready_sessions()
    return {
        "ok": bool(ok_row) and session in ready,
        "session": session,
        "refresh": True,
        "ready": ready,
        "detail": data,
        "reason": data.get("reason") or ("refreshed" if ok_row else "login_failed"),
    }


def refresh_ready_sessions(
    target_dir: Path,
    base_url: str,
    *,
    approve: bool = False,
    force: bool = False,
    sessions: list[str] | None = None,
) -> dict[str, Any]:
    """Refresh A/B (or given) sessions that have accounts configured."""
    accounts = load_accounts(target_dir)
    wanted = sessions or accounts.ready_names() or ["A", "B"]
    wanted = [s for s in wanted if accounts.get(s) and accounts.get(s).ready()]  # type: ignore[union-attr]
    if not wanted:
        return {
            "ok": False,
            "error": "accounts_missing",
            "hint": "No ready accounts in secrets/accounts.yaml",
            "needs_setup": True,
        }
    results = []
    needs_mfa = False
    for name in wanted:
        row = refresh_session(
            target_dir,
            base_url,
            session=name,
            approve=approve,
            force=force,
        )
        results.append(row)
        if row.get("needs_setup"):
            needs_mfa = True
    ok = any(r.get("ok") for r in results) and not needs_mfa
    out: dict[str, Any] = {
        "ok": ok,
        "needs_setup": needs_mfa,
        "results": results,
        "ready": load_identity(target_dir).ready_sessions(),
        "reason": "mfa_detected" if needs_mfa else ("refreshed" if ok else "refresh_failed"),
    }
    if needs_mfa:
        out.update(mfa_needs_setup_payload(login_url=base_url))
        out["results"] = results
    return out


def result_indicates_unauthorized(result: dict[str, Any]) -> bool:
    """True if act/tool result looks like auth expired (401/unauthorized)."""
    summary = str(result.get("summary") or "").lower()
    if "401" in summary or "unauthorized" in summary:
        return True
    if "mfa" in summary or "needs_setup" in summary:
        return False
    stack: list[Any] = [result.get("detail"), result]
    seen = 0
    while stack and seen < 40:
        seen += 1
        cur = stack.pop()
        if isinstance(cur, dict):
            st = cur.get("status")
            if st == 401 or st == "401":
                return True
            if cur.get("status_a") == 401 or cur.get("status_b") == 401:
                return True
            for row in cur.get("rows") or []:
                if isinstance(row, dict):
                    stack.append(row)
            for v in cur.values():
                if isinstance(v, (dict, list)):
                    stack.append(v)
        elif isinstance(cur, list):
            stack.extend(cur[:20])
    return False


def origin_from_target(url_or_host: str) -> str:
    raw = url_or_host if "://" in url_or_host else f"https://{url_or_host}"
    parsed = urlparse(raw)
    if parsed.scheme and parsed.netloc:
        return f"{parsed.scheme}://{parsed.netloc}"
    return raw
