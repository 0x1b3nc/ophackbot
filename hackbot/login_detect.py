"""Detect login surface: form, JSON API, SSO, or MFA (scoped GETs)."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from .accounts import LoginConfig, load_accounts, save_login_config
from .auth_continuity import looks_like_mfa
from .scoped_http import scoped_fetch_bytes

_CANDIDATE_PATHS = (
    "/login",
    "/signin",
    "/sign-in",
    "/auth/login",
    "/api/login",
    "/api/auth/login",
    "/session",
    "/users/sign_in",
)

_SSO_NEEDLES = (
    "oauth",
    "openid",
    "saml",
    "okta",
    "auth0",
    "accounts.google",
    "login.microsoftonline",
    "sso",
    "/authorize?",
    "oauth2",
)

_USER_FIELD_CANDIDATES = (
    "username",
    "email",
    "user",
    "login",
    "identifier",
    "account",
)
_PASS_FIELD_CANDIDATES = ("password", "pass", "passwd", "pwd")


def _origin(base_url: str) -> str:
    raw = base_url if "://" in base_url else f"https://{base_url}"
    p = urlparse(raw)
    return f"{p.scheme}://{p.netloc}"


def _extract_sso_urls(html: str, base: str) -> list[str]:
    found: list[str] = []
    seen: set[str] = set()
    for m in re.finditer(r'(?i)href=["\']([^"\']+)["\']', html or ""):
        href = m.group(1).strip()
        low = href.lower()
        if any(n in low for n in _SSO_NEEDLES):
            full = urljoin(base + "/", href)
            if full not in seen:
                seen.add(full)
                found.append(full)
        if len(found) >= 8:
            break
    # Also scan bare URLs in JS/HTML
    for m in re.finditer(r"(?i)https?://[^\s\"'<>]+", html or ""):
        url = m.group(0).rstrip(".,);")
        low = url.lower()
        if any(n in low for n in _SSO_NEEDLES) and url not in seen:
            seen.add(url)
            found.append(url)
        if len(found) >= 8:
            break
    return found


def _has_password_input(html: str) -> bool:
    return bool(re.search(r'(?i)<input[^>]+type=["\']password["\']', html or ""))


def _guess_fields(html: str, defaults: LoginConfig) -> tuple[str, str, str]:
    user = defaults.user_field
    pass_f = defaults.pass_field
    csrf = defaults.csrf_field
    for name in _USER_FIELD_CANDIDATES:
        if re.search(rf'(?i)<input[^>]+name=["\']{re.escape(name)}["\']', html or ""):
            user = name
            break
    for name in _PASS_FIELD_CANDIDATES:
        if re.search(rf'(?i)<input[^>]+name=["\']{re.escape(name)}["\']', html or ""):
            pass_f = name
            break
    for name in ("csrf_token", "csrf", "authenticity_token", "_token", "csrftoken"):
        if re.search(rf'(?i)name=["\']{re.escape(name)}["\']', html or ""):
            csrf = name
            break
    return user, pass_f, csrf


def _looks_like_json_login(html: str, url: str, content_type: str) -> bool:
    ct = (content_type or "").lower()
    path = urlparse(url).path.lower()
    if "json" in ct and ("login" in path or "auth" in path or "session" in path):
        return True
    low = (html or "").lower()
    if re.search(r"(?i)application/json[^\"']*login|login[^\"']*application/json", low):
        return True
    if "/api/" in path and ("login" in path or "auth" in path):
        return True
    if re.search(r'(?i)["\'](?:username|email|password)["\']\s*:', low) and "login" in path:
        return True
    return False


def classify_login_html(
    html: str,
    *,
    url: str,
    status: int,
    content_type: str = "",
    defaults: LoginConfig | None = None,
) -> dict[str, Any]:
    """Classify a single login response without network I/O (testable)."""
    defaults = defaults or LoginConfig()
    sso_urls = _extract_sso_urls(html, _origin(url))
    if looks_like_mfa(html, status):
        return {
            "kind": "mfa",
            "login_url": url,
            "method": defaults.method,
            "content_type": "application/x-www-form-urlencoded",
            "user_field": defaults.user_field,
            "pass_field": defaults.pass_field,
            "csrf_field": defaults.csrf_field,
            "sso_urls": sso_urls,
            "status": status,
            "confidence": "high",
        }
    # SSO-dominant page: SSO links and little/no local password form
    if sso_urls and not _has_password_input(html):
        return {
            "kind": "sso",
            "login_url": url,
            "method": defaults.method,
            "content_type": "application/x-www-form-urlencoded",
            "user_field": defaults.user_field,
            "pass_field": defaults.pass_field,
            "csrf_field": defaults.csrf_field,
            "sso_urls": sso_urls,
            "status": status,
            "confidence": "high",
        }
    if _has_password_input(html) or re.search(r"(?i)<form[^>]*>", html or ""):
        user, pass_f, csrf = _guess_fields(html, defaults)
        kind = "form"
        content_type = "application/x-www-form-urlencoded"
        if _looks_like_json_login(html, url, content_type):
            # Prefer form if password input present
            pass
        return {
            "kind": kind,
            "login_url": url,
            "method": "POST",
            "content_type": content_type,
            "user_field": user,
            "pass_field": pass_f,
            "csrf_field": csrf,
            "sso_urls": sso_urls,
            "status": status,
            "confidence": "high" if _has_password_input(html) else "medium",
        }
    if _looks_like_json_login(html, url, content_type):
        return {
            "kind": "json_api",
            "login_url": url,
            "method": "POST",
            "content_type": "application/json",
            "user_field": defaults.user_field if defaults.user_field != "username" else "email",
            "pass_field": "password",
            "csrf_field": defaults.csrf_field,
            "sso_urls": sso_urls,
            "status": status,
            "confidence": "medium",
        }
    if sso_urls:
        return {
            "kind": "sso",
            "login_url": url,
            "method": defaults.method,
            "content_type": "application/x-www-form-urlencoded",
            "user_field": defaults.user_field,
            "pass_field": defaults.pass_field,
            "csrf_field": defaults.csrf_field,
            "sso_urls": sso_urls,
            "status": status,
            "confidence": "medium",
        }
    return {
        "kind": "unknown",
        "login_url": url,
        "method": defaults.method,
        "content_type": "application/x-www-form-urlencoded",
        "user_field": defaults.user_field,
        "pass_field": defaults.pass_field,
        "csrf_field": defaults.csrf_field,
        "sso_urls": sso_urls,
        "status": status,
        "confidence": "low",
    }


def detect_login(
    target_dir: Path,
    base_url: str,
    *,
    approve: bool = False,
    force: bool = False,
    timeout: float = 12.0,
    persist: bool = False,
) -> dict[str, Any]:
    """Probe candidate login paths and return best classification."""
    accounts = load_accounts(target_dir)
    origin = _origin(base_url)
    configured = (accounts.login.path or "/login").strip() or "/login"
    paths: list[str] = []
    for p in (configured, *_CANDIDATE_PATHS):
        if p not in paths:
            paths.append(p)
    paths = paths[:8]

    plan = {
        "origin": origin,
        "paths": paths,
        "approve": approve,
        "persist": persist,
    }
    if not approve:
        return {"ok": True, "dry_run": True, **plan}

    from .runners.base import require_in_scope

    require_in_scope(target_dir, origin + "/", action="detect login", force=force)

    probes: list[dict[str, Any]] = []
    best: dict[str, Any] | None = None
    rank = {"form": 4, "json_api": 3, "sso": 2, "mfa": 5, "unknown": 0}

    for path in paths:
        url = urljoin(origin + "/", path.lstrip("/"))
        try:
            resp = scoped_fetch_bytes(
                url,
                target_dir=target_dir,
                action="detect login",
                force=force,
                timeout=timeout,
                headers={"User-Agent": "hackbot-login-detect"},
                max_bytes=100_000,
                gate_initial=True,
            )
        except Exception as exc:  # noqa: BLE001
            probes.append({"url": url, "error": type(exc).__name__, "detail": str(exc)[:120]})
            continue
        html = resp.body.decode("utf-8", errors="replace")
        ct = ""
        try:
            ct = resp.headers.get("Content-Type") or ""
        except Exception:  # noqa: BLE001
            ct = ""
        classified = classify_login_html(
            html,
            url=url,
            status=resp.status,
            content_type=ct,
            defaults=accounts.login,
        )
        probes.append(
            {
                "url": url,
                "status": resp.status,
                "kind": classified["kind"],
                "confidence": classified.get("confidence"),
            }
        )
        if best is None or rank.get(classified["kind"], 0) > rank.get(best.get("kind", ""), 0):
            best = classified
        elif (
            best
            and classified["kind"] == best.get("kind")
            and classified.get("confidence") == "high"
            and best.get("confidence") != "high"
        ):
            best = classified
        # Prefer configured path on tie
        if (
            best
            and classified["kind"] == best.get("kind")
            and path == configured
            and classified.get("confidence") in {"high", "medium"}
        ):
            best = classified

    if not best:
        return {
            "ok": False,
            "error": "no_login_surface",
            "probes": probes,
            "hint": "No login candidate responded; set login.path in accounts.yaml",
        }

    out: dict[str, Any] = {
        "ok": True,
        "kind": best["kind"],
        "login_url": best["login_url"],
        "method": best.get("method") or "POST",
        "content_type": best.get("content_type") or "application/x-www-form-urlencoded",
        "user_field": best.get("user_field"),
        "pass_field": best.get("pass_field"),
        "csrf_field": best.get("csrf_field"),
        "sso_urls": best.get("sso_urls") or [],
        "confidence": best.get("confidence"),
        "probes": probes,
        "status": best.get("status"),
    }
    if out["kind"] == "sso":
        from .auth_continuity import sso_needs_setup_payload

        out.update(sso_needs_setup_payload(login_url=out["login_url"], sso_urls=out["sso_urls"]))
        out["ok"] = True  # detection succeeded; setup still needed for login
        out["needs_setup"] = True
    elif out["kind"] == "mfa":
        from .auth_continuity import mfa_needs_setup_payload

        out.update(mfa_needs_setup_payload(login_url=out["login_url"]))
        out["ok"] = True
        out["needs_setup"] = True

    if persist and out["kind"] in {"form", "json_api"} and out.get("confidence") in {
        "high",
        "medium",
    }:
        path_only = urlparse(out["login_url"]).path or "/login"
        save_login_config(
            target_dir,
            path=path_only,
            method=str(out.get("method") or "POST"),
            user_field=str(out.get("user_field") or "username"),
            pass_field=str(out.get("pass_field") or "password"),
            csrf_field=str(out.get("csrf_field") or "csrf_token"),
            content_type=str(out.get("content_type") or ""),
        )
        out["persisted_login"] = True

    return out
