"""Browser automation via Playwright (optional). Scope + approve gated."""

from __future__ import annotations

import json
import os
import time
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from .. import ui
from ..evidence import EvidenceStore
from ..hunt_memory import Endpoint, HuntMemory
from ..redaction import redact_text
from ..scoped_http import attach_playwright_scope_guard
from .base import RunnerResult, require_in_scope

_AUTH_COOKIE_HINTS = (
    "session",
    "sid",
    "ssid",
    "auth",
    "token",
    "jwt",
    "access",
    "refresh",
    "connect.sid",
    "csrf",
    "remember",
    "id_token",
)


def playwright_available() -> bool:
    try:
        import playwright  # noqa: F401

        return True
    except ImportError:
        return False


def _missing_result(cmd: list[str]) -> RunnerResult:
    msg = (
        "Playwright not installed. Install with:\n"
        "  pip install playwright\n"
        "  playwright install chromium\n"
        "Or: pip install 'hackbot-kit[browser]'"
    )
    ui.warn(msg)
    return RunnerResult(
        cmd,
        False,
        None,
        json.dumps({"ok": False, "wired": False, "error": "playwright_missing", "hint": msg}),
        "",
        "missing_dep",
    )


def _redact_value(value: str, *, keep: int = 2) -> str:
    raw = value or ""
    if len(raw) <= keep * 2:
        return "[REDACTED]"
    return f"{raw[:keep]}…{raw[-keep:]}[REDACTED]"


def _load_session_headers(target_dir: Path, session_name: str) -> dict[str, str]:
    from ..identity import load_identity

    identity = load_identity(target_dir)
    sess = identity.get_session(session_name)
    if not sess or not sess.has_auth():
        return {}
    return identity.merge_headers(session_name)


def _cookie_dicts_from_header(cookie_header: str, url: str) -> list[dict[str, Any]]:
    """Parse Cookie header into Playwright add_cookies payloads."""
    parsed = urlparse(url)
    base = f"{parsed.scheme}://{parsed.netloc}"
    out: list[dict[str, Any]] = []
    for part in (cookie_header or "").split(";"):
        part = part.strip()
        if not part or "=" not in part:
            continue
        name, value = part.split("=", 1)
        name, value = name.strip(), value.strip()
        if not name:
            continue
        out.append({"name": name, "value": value, "url": base})
    return out


def _new_authed_context(browser: Any, url: str, headers: dict[str, str]) -> Any:
    """Create Playwright context with Authorization + Cookie from session headers."""
    extra = {k: v for k, v in headers.items() if k.lower() != "cookie"}
    context = browser.new_context(extra_http_headers=extra if extra else {})
    cookie_hdr = ""
    for k, v in headers.items():
        if k.lower() == "cookie":
            cookie_hdr = v
            break
    cookies = _cookie_dicts_from_header(cookie_hdr, url)
    if cookies:
        context.add_cookies(cookies)
    return context


def _guarded_page(
    browser: Any,
    target_dir: Path,
    *,
    action: str,
    force: bool,
    headers: dict[str, str] | None = None,
    url_for_cookies: str = "",
) -> tuple[Any, Any, list[dict[str, str]]]:
    """New context+page with SCOPE route guard on every request/redirect."""
    if headers:
        context = _new_authed_context(browser, url_for_cookies or "https://localhost/", headers)
    else:
        context = browser.new_context()
    blocked: list[dict[str, str]] = []
    attach_playwright_scope_guard(
        context, target_dir, action=action, force=force, blocked=blocked
    )
    page = context.new_page()
    return context, page, blocked


def _gate(
    target_dir: Path,
    url: str,
    *,
    action: str,
    approve: bool,
    force: bool,
    cmd: list[str],
    plan: dict[str, Any],
    title: str,
) -> RunnerResult | None:
    """Return early RunnerResult for missing dep / dry-run; else None to proceed."""
    require_in_scope(target_dir, url, action=action, force=force)
    ui.code_panel(json.dumps(plan, indent=2), title=title, lexer="json")
    if not playwright_available():
        return _missing_result(cmd)
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")
    return None


def browser_navigate(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
    wait_until: str = "domcontentloaded",
    timeout_ms: int = 20000,
) -> RunnerResult:
    plan = {"url": url, "approve": approve, "wait_until": wait_until}
    cmd = ["browser_navigate", url]
    early = _gate(
        target_dir,
        url,
        action="browser navigate playwright",
        approve=approve,
        force=force,
        cmd=cmd,
        plan=plan,
        title="browser_navigate",
    )
    if early:
        return early

    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            _ctx, page, blocked = _guarded_page(
                browser,
                target_dir,
                action="browser navigate playwright",
                force=force,
            )
            try:
                page.goto(url, wait_until=wait_until, timeout=timeout_ms)
            except Exception as exc:  # noqa: BLE001
                if blocked:
                    return RunnerResult(
                        cmd,
                        True,
                        1,
                        json.dumps(
                            {
                                "ok": False,
                                "url": url,
                                "error": "scope_blocked",
                                "blocked": blocked[:20],
                                "detail": str(exc)[:300],
                            }
                        ),
                        "",
                        "scope_blocked",
                    )
                raise
            title = page.title()
            final = page.url
            content = page.content()
            text = page.inner_text("body") if page.query_selector("body") else ""
            if blocked:
                return RunnerResult(
                    cmd,
                    True,
                    1,
                    json.dumps(
                        {
                            "ok": False,
                            "url": url,
                            "final_url": final,
                            "error": "scope_blocked",
                            "blocked": blocked[:20],
                        }
                    ),
                    "",
                    "scope_blocked",
                )
        finally:
            browser.close()

    payload = {
        "ok": True,
        "url": url,
        "final_url": final,
        "title": title,
        "html_chars": len(content),
        "text_preview": redact_text(text[:1500]),
        "html_preview": redact_text(content[:800]),
    }
    try:
        EvidenceStore(target_dir).save(
            "browser_navigate.json", json.dumps(payload, indent=2)
        )
    except Exception:
        pass
    ui.success(f"browser: {title or final}")
    return RunnerResult(cmd, True, 0, json.dumps(payload), "", "executed")


def browser_screenshot(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
    full_page: bool = True,
    timeout_ms: int = 20000,
) -> RunnerResult:
    plan = {"url": url, "approve": approve, "full_page": full_page}
    cmd = ["browser_screenshot", url]
    early = _gate(
        target_dir,
        url,
        action="browser screenshot playwright",
        approve=approve,
        force=force,
        cmd=cmd,
        plan=plan,
        title="browser_screenshot",
    )
    if early:
        return early

    from playwright.sync_api import sync_playwright

    out_dir = Path(target_dir) / "evidence" / "safe"
    out_dir.mkdir(parents=True, exist_ok=True)
    shot_path = out_dir / "browser_screenshot.png"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            _ctx, page, blocked = _guarded_page(
                browser,
                target_dir,
                action="browser screenshot playwright",
                force=force,
            )
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            except Exception as exc:  # noqa: BLE001
                if blocked:
                    return RunnerResult(
                        cmd,
                        True,
                        1,
                        json.dumps({"ok": False, "error": "scope_blocked", "blocked": blocked[:20], "detail": str(exc)[:200]}),
                        "",
                        "scope_blocked",
                    )
                raise
            page.screenshot(path=str(shot_path), full_page=full_page)
            title = page.title()
        finally:
            browser.close()

    payload = {
        "ok": True,
        "url": url,
        "title": title,
        "path": str(shot_path),
    }
    ui.success(f"screenshot -> {shot_path}")
    return RunnerResult(cmd, True, 0, json.dumps(payload), "", "executed")


def browser_eval(
    target_dir: Path,
    url: str,
    expression: str,
    *,
    approve: bool = False,
    force: bool = False,
    timeout_ms: int = 20000,
) -> RunnerResult:
    """Evaluate a short JS expression in page context (capped)."""
    expr = (expression or "").strip()
    if len(expr) > 500:
        return RunnerResult(
            ["browser_eval"],
            False,
            None,
            json.dumps({"ok": False, "error": "expression too long (max 500)"}),
            "",
            "error",
        )
    plan = {"url": url, "expression": expr[:120], "approve": approve}
    cmd = ["browser_eval", url]
    early = _gate(
        target_dir,
        url,
        action="browser eval playwright",
        approve=approve,
        force=force,
        cmd=cmd,
        plan=plan,
        title="browser_eval",
    )
    if early:
        return early

    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            _ctx, page, blocked = _guarded_page(
                browser,
                target_dir,
                action="browser eval playwright",
                force=force,
            )
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            except Exception as exc:  # noqa: BLE001
                if blocked:
                    return RunnerResult(
                        cmd,
                        True,
                        1,
                        json.dumps({"ok": False, "error": "scope_blocked", "blocked": blocked[:20], "detail": str(exc)[:200]}),
                        "",
                        "scope_blocked",
                    )
                raise
            value: Any = page.evaluate(expr)
        finally:
            browser.close()

    payload = {
        "ok": True,
        "url": url,
        "expression": expr,
        "result": redact_text(json.dumps(value, default=str)[:2000]),
    }
    return RunnerResult(cmd, True, 0, json.dumps(payload), "", "executed")


def browser_cookies(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
    timeout_ms: int = 20000,
) -> RunnerResult:
    """List cookies after navigation — values redacted."""
    plan = {"url": url, "approve": approve, "values": "redacted"}
    cmd = ["browser_cookies", url]
    early = _gate(
        target_dir,
        url,
        action="browser cookies playwright",
        approve=approve,
        force=force,
        cmd=cmd,
        plan=plan,
        title="browser_cookies",
    )
    if early:
        return early

    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            context, page, blocked = _guarded_page(
                browser,
                target_dir,
                action="browser cookies playwright",
                force=force,
            )
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            except Exception as exc:  # noqa: BLE001
                if blocked:
                    return RunnerResult(
                        cmd,
                        True,
                        1,
                        json.dumps({"ok": False, "error": "scope_blocked", "blocked": blocked[:20], "detail": str(exc)[:200]}),
                        "",
                        "scope_blocked",
                    )
                raise
            raw = context.cookies()
        finally:
            browser.close()

    cookies = []
    for c in raw:
        cookies.append(
            {
                "name": c.get("name"),
                "domain": c.get("domain"),
                "path": c.get("path"),
                "httpOnly": bool(c.get("httpOnly")),
                "secure": bool(c.get("secure")),
                "sameSite": c.get("sameSite"),
                "value": _redact_value(str(c.get("value") or "")),
            }
        )
    payload = {"ok": True, "url": url, "count": len(cookies), "cookies": cookies}
    try:
        EvidenceStore(target_dir).save(
            "browser_cookies.json", json.dumps(payload, indent=2)
        )
    except Exception:
        pass
    ui.success(f"cookies: {len(cookies)}")
    return RunnerResult(cmd, True, 0, json.dumps(payload), "", "executed")


def browser_storage(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
    timeout_ms: int = 20000,
) -> RunnerResult:
    """Dump localStorage + sessionStorage keys (values redacted)."""
    plan = {"url": url, "approve": approve, "values": "redacted"}
    cmd = ["browser_storage", url]
    early = _gate(
        target_dir,
        url,
        action="browser storage playwright",
        approve=approve,
        force=force,
        cmd=cmd,
        plan=plan,
        title="browser_storage",
    )
    if early:
        return early

    from playwright.sync_api import sync_playwright

    script = """() => {
      const dump = (store) => {
        const out = [];
        for (let i = 0; i < store.length; i++) {
          const k = store.key(i);
          out.push({key: k, value: store.getItem(k) || ""});
        }
        return out;
      };
      return {
        localStorage: dump(window.localStorage),
        sessionStorage: dump(window.sessionStorage),
      };
    }"""

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            _ctx, page, blocked = _guarded_page(
                browser,
                target_dir,
                action="browser storage playwright",
                force=force,
            )
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            except Exception as exc:  # noqa: BLE001
                if blocked:
                    return RunnerResult(
                        cmd,
                        True,
                        1,
                        json.dumps({"ok": False, "error": "scope_blocked", "blocked": blocked[:20], "detail": str(exc)[:200]}),
                        "",
                        "scope_blocked",
                    )
                raise
            raw = page.evaluate(script)
        finally:
            browser.close()

    def scrub(items: list[dict[str, Any]]) -> list[dict[str, str]]:
        out = []
        for item in items or []:
            out.append(
                {
                    "key": str(item.get("key") or ""),
                    "value": _redact_value(str(item.get("value") or "")),
                }
            )
        return out

    local = scrub(list(raw.get("localStorage") or []))
    session = scrub(list(raw.get("sessionStorage") or []))
    payload = {
        "ok": True,
        "url": url,
        "localStorage": local,
        "sessionStorage": session,
        "local_count": len(local),
        "session_count": len(session),
    }
    try:
        EvidenceStore(target_dir).save(
            "browser_storage.json", json.dumps(payload, indent=2)
        )
    except Exception:
        pass
    ui.success(f"storage: local={len(local)} session={len(session)}")
    return RunnerResult(cmd, True, 0, json.dumps(payload), "", "executed")


def browser_network(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
    timeout_ms: int = 20000,
    seed_surface: bool = True,
    limit: int = 80,
) -> RunnerResult:
    """Capture network requests during page load; optionally seed hunt surface."""
    plan = {
        "url": url,
        "approve": approve,
        "seed_surface": seed_surface,
        "limit": limit,
    }
    cmd = ["browser_network", url]
    early = _gate(
        target_dir,
        url,
        action="browser network playwright",
        approve=approve,
        force=force,
        cmd=cmd,
        plan=plan,
        title="browser_network",
    )
    if early:
        return early

    from playwright.sync_api import sync_playwright

    captured: list[dict[str, Any]] = []

    def on_response(response: Any) -> None:
        if len(captured) >= limit:
            return
        req = response.request
        captured.append(
            {
                "method": req.method,
                "url": redact_text(req.url),
                "status": response.status,
                "resource_type": req.resource_type,
            }
        )

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            _ctx, page, blocked = _guarded_page(
                browser,
                target_dir,
                action="browser network playwright",
                force=force,
            )
            page.on("response", on_response)
            try:
                page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            except Exception as exc:  # noqa: BLE001
                if blocked:
                    return RunnerResult(
                        cmd,
                        True,
                        1,
                        json.dumps({"ok": False, "error": "scope_blocked", "blocked": blocked[:20], "detail": str(exc)[:200]}),
                        "",
                        "scope_blocked",
                    )
                raise
            title = page.title()
            final = page.url
        finally:
            browser.close()

    seeded = 0
    if seed_surface:
        endpoints: list[Endpoint] = []
        hosts: set[str] = set()
        for row in captured:
            raw_url = str(row.get("url") or "")
            if not raw_url.startswith("http"):
                continue
            if row.get("resource_type") in {"image", "font", "media", "stylesheet"}:
                continue
            parsed = urlparse(raw_url)
            if parsed.netloc:
                hosts.add(parsed.netloc.split(":")[0])
            params = list(parse_qs(parsed.query).keys())
            endpoints.append(
                Endpoint(
                    url=raw_url.split("#")[0],
                    method=str(row.get("method") or "GET"),
                    params=sorted(set(params)),
                    source="browser_network",
                )
            )
        if endpoints:
            host = next(iter(hosts), urlparse(url).netloc.split(":")[0])
            HuntMemory(target_dir).upsert_endpoints(endpoints, host=host)
            seeded = len(endpoints)

    payload = {
        "ok": True,
        "url": url,
        "final_url": final,
        "title": title,
        "count": len(captured),
        "requests": captured,
        "endpoints_seeded": seeded,
    }
    try:
        EvidenceStore(target_dir).save(
            "browser_network.json", json.dumps(payload, indent=2)
        )
    except Exception:
        pass
    ui.success(f"network: {len(captured)} reqs, seeded={seeded}")
    return RunnerResult(cmd, True, 0, json.dumps(payload), "", "executed")


def browser_with_session(
    target_dir: Path,
    url: str,
    session: str = "A",
    *,
    approve: bool = False,
    force: bool = False,
    capture_network: bool = False,
    timeout_ms: int = 20000,
) -> RunnerResult:
    """Navigate with secrets/sessions.yaml credentials injected (values never logged)."""
    session_name = (session or "A").strip() or "A"
    headers = _load_session_headers(target_dir, session_name)
    plan = {
        "url": url,
        "session": session_name,
        "auth_ready": bool(headers),
        "header_names": sorted(headers.keys()),
        "capture_network": capture_network,
        "approve": approve,
    }
    cmd = ["browser_with_session", url, session_name]
    early = _gate(
        target_dir,
        url,
        action="browser with session playwright",
        approve=approve,
        force=force,
        cmd=cmd,
        plan=plan,
        title="browser_with_session",
    )
    if early:
        return early

    if not headers:
        return RunnerResult(
            cmd,
            False,
            None,
            json.dumps(
                {
                    "ok": False,
                    "error": "session_missing",
                    "session": session_name,
                    "hint": (
                        f"No auth in secrets/sessions.yaml for '{session_name}'. "
                        "Load via load_sessions_from_file or set_session first."
                    ),
                }
            ),
            "",
            "error",
        )

    from playwright.sync_api import sync_playwright

    captured: list[dict[str, Any]] = []

    def on_response(response: Any) -> None:
        if len(captured) >= 60:
            return
        req = response.request
        captured.append(
            {
                "method": req.method,
                "url": redact_text(req.url),
                "status": response.status,
                "resource_type": req.resource_type,
            }
        )

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            context, page, blocked = _guarded_page(
                browser,
                target_dir,
                action="browser with session playwright",
                force=force,
                headers=headers,
                url_for_cookies=url,
            )
            if capture_network:
                page.on("response", on_response)
            try:
                page.goto(
                    url,
                    wait_until="networkidle" if capture_network else "domcontentloaded",
                    timeout=timeout_ms,
                )
            except Exception as exc:  # noqa: BLE001
                if blocked:
                    return RunnerResult(
                        cmd,
                        True,
                        1,
                        json.dumps({"ok": False, "error": "scope_blocked", "blocked": blocked[:20], "detail": str(exc)[:200]}),
                        "",
                        "scope_blocked",
                    )
                raise
            title = page.title()
            final = page.url
            text = page.inner_text("body") if page.query_selector("body") else ""
            cookies_raw = context.cookies()
        finally:
            browser.close()

    cookies = [
        {
            "name": c.get("name"),
            "domain": c.get("domain"),
            "path": c.get("path"),
            "httpOnly": bool(c.get("httpOnly")),
            "secure": bool(c.get("secure")),
            "value": _redact_value(str(c.get("value") or "")),
        }
        for c in cookies_raw
    ]
    payload = {
        "ok": True,
        "url": url,
        "final_url": final,
        "title": title,
        "session": session_name,
        "auth_applied": True,
        "header_names": sorted(headers.keys()),
        "text_preview": redact_text(text[:1200]),
        "cookies": cookies,
        "cookie_count": len(cookies),
        "network": captured if capture_network else [],
        "network_count": len(captured),
    }
    try:
        EvidenceStore(target_dir).save(
            "browser_with_session.json", json.dumps(payload, indent=2)
        )
    except Exception:
        pass
    ui.success(f"browser session={session_name}: {title or final}")
    return RunnerResult(cmd, True, 0, json.dumps(payload), "", "executed")


def browser_diff_sessions(
    target_dir: Path,
    url: str,
    *,
    session_a: str = "A",
    session_b: str = "B",
    approve: bool = False,
    force: bool = False,
    timeout_ms: int = 20000,
    promote: bool = True,
    write_finding: bool = True,
) -> RunnerResult:
    """Fetch the same URL as session A and B; compare fingerprints; auto-promote soft IDOR hints."""
    import hashlib

    plan = {
        "url": url,
        "session_a": session_a,
        "session_b": session_b,
        "approve": approve,
        "promote": promote,
        "compare": "title/status/body_hash/length (no raw secrets)",
    }
    cmd = ["browser_diff_sessions", url, session_a, session_b]
    early = _gate(
        target_dir,
        url,
        action="browser diff sessions playwright",
        approve=approve,
        force=force,
        cmd=cmd,
        plan=plan,
        title="browser_diff_sessions",
    )
    if early:
        return early

    headers_a = _load_session_headers(target_dir, session_a)
    headers_b = _load_session_headers(target_dir, session_b)
    if not headers_a or not headers_b:
        missing = []
        if not headers_a:
            missing.append(session_a)
        if not headers_b:
            missing.append(session_b)
        return RunnerResult(
            cmd,
            False,
            None,
            json.dumps(
                {
                    "ok": False,
                    "error": "session_missing",
                    "missing": missing,
                    "hint": "Load A and B into secrets/sessions.yaml first.",
                }
            ),
            "",
            "error",
        )

    from playwright.sync_api import sync_playwright

    def _snap(browser: Any, headers: dict[str, str], label: str) -> dict[str, Any]:
        context, page, blocked = _guarded_page(
            browser,
            target_dir,
            action="browser diff sessions playwright",
            force=force,
            headers=headers,
            url_for_cookies=url,
        )
        try:
            resp = page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
        except Exception as exc:  # noqa: BLE001
            context.close()
            if blocked:
                return {
                    "session": label,
                    "status": 0,
                    "title": "",
                    "final_url": url,
                    "body_len": 0,
                    "body_hash": "",
                    "text_preview": "",
                    "header_names": sorted(headers.keys()),
                    "error": "scope_blocked",
                    "blocked": blocked[:10],
                    "detail": str(exc)[:200],
                }
            raise
        title = page.title()
        final = page.url
        text = page.inner_text("body") if page.query_selector("body") else ""
        status = int(resp.status) if resp else 0
        body_hash = hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()[:16]
        context.close()
        return {
            "session": label,
            "status": status,
            "title": title,
            "final_url": final,
            "body_len": len(text),
            "body_hash": body_hash,
            "text_preview": redact_text(text[:400]),
            "header_names": sorted(headers.keys()),
        }

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            snap_a = _snap(browser, headers_a, session_a)
            snap_b = _snap(browser, headers_b, session_b)
        finally:
            browser.close()

    same_status = snap_a["status"] == snap_b["status"]
    same_hash = snap_a["body_hash"] == snap_b["body_hash"]
    same_len = snap_a["body_len"] == snap_b["body_len"]
    # Soft IDOR hint: both succeed with near-identical bodies
    idor_hint = (
        same_status
        and snap_a["status"] in {200, 201}
        and (same_hash or abs(int(snap_a["body_len"]) - int(snap_b["body_len"])) < 40)
    )
    diff = {
        "status_equal": same_status,
        "body_hash_equal": same_hash,
        "body_len_equal": same_len,
        "idor_soft_hint": idor_hint,
    }
    payload: dict[str, Any] = {
        "ok": True,
        "url": url,
        "a": snap_a,
        "b": snap_b,
        "diff": diff,
        "hint": (
            "Both sessions got similar 2xx bodies — possible BOLA/IDOR; auto-promoting candidate."
            if idor_hint
            else "Responses differ or non-2xx — compare manually; not a confirmed finding."
        ),
    }

    promotion: dict[str, Any] | None = None
    if promote and idor_hint:
        try:
            from ..validator import promote_browser_diff

            vr = promote_browser_diff(
                target_dir,
                url=url,
                diff=diff,
                snap_a=snap_a,
                snap_b=snap_b,
                session_a=session_a,
                session_b=session_b,
                write_finding=write_finding,
            )
            if vr:
                promotion = {
                    "status": vr.status,
                    "ok": vr.ok,
                    "finding_id": vr.finding_id,
                    "evidence": vr.evidence,
                    "detail": vr.detail[:240],
                    "verdict": "likely",
                }
                if vr.finding_id:
                    payload["hint"] = (
                        f"Promoted to FINDINGS {vr.finding_id} (verdict=likely). "
                        "Confirm ownership swap before final severity / report."
                    )
        except Exception as exc:  # noqa: BLE001
            promotion = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    payload["promotion"] = promotion

    try:
        EvidenceStore(target_dir).save(
            "browser_diff_sessions.json", json.dumps(payload, indent=2)
        )
    except Exception:
        pass
    ui.success(
        f"diff {session_a}/{session_b}: status={snap_a['status']}/{snap_b['status']} "
        f"idor_hint={idor_hint} promoted={bool(promotion and promotion.get('finding_id'))}"
    )
    return RunnerResult(cmd, True, 0, json.dumps(payload), "", "executed")


def browser_console(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
    timeout_ms: int = 20000,
) -> RunnerResult:
    """Capture console messages during page load."""
    plan = {"url": url, "approve": approve}
    cmd = ["browser_console", url]
    early = _gate(
        target_dir,
        url,
        action="browser console playwright",
        approve=approve,
        force=force,
        cmd=cmd,
        plan=plan,
        title="browser_console",
    )
    if early:
        return early

    from playwright.sync_api import sync_playwright

    logs: list[dict[str, str]] = []

    def on_console(msg: Any) -> None:
        if len(logs) >= 50:
            return
        logs.append({"type": msg.type, "text": redact_text(str(msg.text)[:300])})

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            _ctx, page, blocked = _guarded_page(
                browser,
                target_dir,
                action="browser console playwright",
                force=force,
            )
            page.on("console", on_console)
            try:
                page.goto(url, wait_until="networkidle", timeout=timeout_ms)
            except Exception as exc:  # noqa: BLE001
                if blocked:
                    return RunnerResult(
                        cmd,
                        True,
                        1,
                        json.dumps({"ok": False, "error": "scope_blocked", "blocked": blocked[:20], "detail": str(exc)[:200]}),
                        "",
                        "scope_blocked",
                    )
                raise
            title = page.title()
        finally:
            browser.close()

    payload = {"ok": True, "url": url, "title": title, "count": len(logs), "logs": logs}
    try:
        EvidenceStore(target_dir).save("browser_console.json", json.dumps(payload, indent=2))
    except Exception:
        pass
    return RunnerResult(cmd, True, 0, json.dumps(payload), "", "executed")


def browser_set_cookie(
    target_dir: Path,
    url: str,
    *,
    name: str,
    value: str,
    session: str = "",
    approve: bool = False,
    force: bool = False,
    timeout_ms: int = 15000,
) -> RunnerResult:
    """Set one cookie then navigate (value never logged)."""
    plan = {
        "url": url,
        "cookie_name": name,
        "session": session or None,
        "approve": approve,
        "value": "[REDACTED]",
    }
    cmd = ["browser_set_cookie", url, name]
    early = _gate(
        target_dir,
        url,
        action="browser set cookie playwright",
        approve=approve,
        force=force,
        cmd=cmd,
        plan=plan,
        title="browser_set_cookie",
    )
    if early:
        return early

    headers = _load_session_headers(target_dir, session) if session else {}
    from playwright.sync_api import sync_playwright

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            context, page, blocked = _guarded_page(
                browser,
                target_dir,
                action="browser set cookie playwright",
                force=force,
                headers=headers or None,
                url_for_cookies=url,
            )
            context.add_cookies([{"name": name, "value": value, "url": url}])
            try:
                page.goto(url, wait_until="domcontentloaded", timeout=timeout_ms)
            except Exception as exc:  # noqa: BLE001
                if blocked:
                    return RunnerResult(
                        cmd,
                        True,
                        1,
                        json.dumps({"ok": False, "error": "scope_blocked", "blocked": blocked[:20], "detail": str(exc)[:200]}),
                        "",
                        "scope_blocked",
                    )
                raise
            title = page.title()
            cookies = [
                {
                    "name": c.get("name"),
                    "domain": c.get("domain"),
                    "value": _redact_value(str(c.get("value") or "")),
                }
                for c in context.cookies()
            ]
        finally:
            browser.close()

    payload = {"ok": True, "url": url, "title": title, "cookie_name": name, "cookies": cookies}
    return RunnerResult(cmd, True, 0, json.dumps(payload), "", "executed")


def _cookie_header_from_playwright(cookies: list[dict[str, Any]]) -> str:
    parts = []
    for c in cookies:
        name = str(c.get("name") or "").strip()
        value = str(c.get("value") or "")
        if name:
            parts.append(f"{name}={value}")
    return "; ".join(parts)


def _looks_authed_url(url: str) -> bool:
    low = (url or "").lower()
    loginish = ("login", "signin", "sign-in", "oauth", "authorize", "sso", "auth0", "okta")
    return not any(x in low for x in loginish)


def _auth_cookie_signal(cookies: list[dict[str, Any]]) -> bool:
    for c in cookies:
        name = str(c.get("name") or "").lower()
        if any(h in name for h in _AUTH_COOKIE_HINTS) and str(c.get("value") or ""):
            return True
    return len(cookies) >= 3


def browser_capture_session(
    target_dir: Path,
    url: str,
    *,
    session: str = "A",
    approve: bool = False,
    force: bool = False,
    timeout_s: float | None = None,
    poll_s: float = 2.0,
) -> RunnerResult:
    """
    Open a headed browser for operator IdP/MFA login, then persist cookies/token.

    Never types credentials into the IdP. Operator completes login; we poll until
    auth cookies appear or timeout.
    """
    full = url if "://" in url else f"https://{url}"
    require_in_scope(target_dir, full, action="browser capture session idp", force=force)
    timeout = float(
        timeout_s
        if timeout_s is not None
        else os.environ.get("HACKBOT_IDP_CAPTURE_TIMEOUT", "180")
    )
    headed_env = os.environ.get("HACKBOT_BROWSER_HEADED", "1").strip().lower()
    headed = headed_env not in {"0", "false", "no", "off"}
    plan = {
        "url": full,
        "session": session,
        "approve": approve,
        "timeout_s": timeout,
        "headed": headed,
    }
    cmd = ["browser_capture_session", full, session]
    ui.code_panel(json.dumps(plan, indent=2), title="browser_capture_session", lexer="json")
    if not playwright_available():
        return _missing_result(cmd)
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(
            cmd,
            False,
            None,
            json.dumps(
                {
                    "dry_run": True,
                    **plan,
                    "hint": "Approve to open headed Chromium; finish IdP login, then cookies are saved.",
                }
            ),
            "",
            "dry-run",
        )

    from ..auth_continuity import session_smoke, sso_needs_setup_payload
    from ..hunt_jar import merge_set_cookie
    from ..identity import save_session
    from playwright.sync_api import sync_playwright

    ui.warn(
        f"browser_capture_session: complete IdP/MFA for session {session} in the browser window "
        f"(timeout {int(timeout)}s). Hackbot will not type passwords."
    )

    captured_cookie = ""
    captured_auth = ""
    final_url = full
    cookie_count = 0
    reason = "timeout"

    with sync_playwright() as p:
        browser = p.chromium.launch(headless=not headed)
        try:
            context, page, blocked = _guarded_page(
                browser,
                target_dir,
                action="browser capture session idp",
                force=force,
            )
            try:
                page.goto(full, wait_until="domcontentloaded", timeout=min(60_000, int(timeout * 1000)))
            except Exception as exc:  # noqa: BLE001
                if blocked:
                    return RunnerResult(
                        cmd,
                        True,
                        1,
                        json.dumps(
                            {
                                "ok": False,
                                "error": "scope_blocked",
                                "blocked": blocked[:20],
                                "detail": str(exc)[:200],
                            }
                        ),
                        "",
                        "scope_blocked",
                    )
                # Keep going — operator may navigate manually
                ui.warn(f"initial navigation issue: {type(exc).__name__}")

            deadline = time.time() + timeout
            while time.time() < deadline:
                try:
                    final_url = page.url or final_url
                except Exception:  # noqa: BLE001
                    pass
                cookies = context.cookies()
                cookie_count = len(cookies)
                storage_token = ""
                try:
                    storage_token = page.evaluate(
                        """() => {
                          try {
                            return localStorage.getItem('access_token')
                              || localStorage.getItem('token')
                              || localStorage.getItem('id_token')
                              || sessionStorage.getItem('access_token')
                              || '';
                          } catch (e) { return ''; }
                        }"""
                    ) or ""
                except Exception:  # noqa: BLE001
                    storage_token = ""

                if _auth_cookie_signal(cookies) or (
                    storage_token and _looks_authed_url(final_url)
                ) or (_looks_authed_url(final_url) and cookie_count >= 2):
                    captured_cookie = _cookie_header_from_playwright(cookies)
                    if storage_token:
                        captured_auth = (
                            storage_token
                            if str(storage_token).lower().startswith("bearer ")
                            else f"Bearer {storage_token}"
                        )
                    reason = "captured"
                    break
                time.sleep(max(0.5, poll_s))
        finally:
            try:
                browser.close()
            except Exception:  # noqa: BLE001
                pass

    if reason != "captured" or (not captured_cookie and not captured_auth):
        setup = sso_needs_setup_payload(session=session, login_url=full, sso_urls=[full])
        setup.update(
            {
                "ok": False,
                "needs_setup": True,
                "capture_recommended": True,
                "reason": "capture_timeout",
                "final_url": final_url,
                "cookie_count": cookie_count,
                "next_steps": [
                    "Re-run browser_capture_session and finish IdP login before timeout",
                    "Or paste Cookie / Authorization via set_session",
                    "Then: resume hunt",
                ],
            }
        )
        ui.warn("browser_capture_session: timeout — needs_setup")
        return RunnerResult(cmd, True, 0, json.dumps(setup), "", "executed")

    save_session(
        target_dir,
        session,
        authorization=captured_auth or None,
        cookie=captured_cookie or None,
    )
    if captured_cookie:
        # Reconstruct Set-Cookie-ish list for jar merge
        try:
            merge_set_cookie(
                target_dir,
                [p.strip() for p in captured_cookie.split(";") if "=" in p],
                url=final_url or full,
                session=session,
            )
        except Exception:  # noqa: BLE001
            pass

    smoke = session_smoke(
        target_dir,
        final_url or full,
        session=session,
        approve=True,
        force=force,
    )
    payload = {
        "ok": True if smoke.get("ok") is not False else bool(smoke.get("skipped")),
        "session": session,
        "url": full,
        "final_url": final_url,
        "cookie_count": cookie_count,
        "has_cookie": bool(captured_cookie),
        "has_auth": bool(captured_auth),
        "smoke": {
            "ok": smoke.get("ok"),
            "skipped": smoke.get("skipped"),
            "reason": smoke.get("reason"),
        },
        "reason": "captured",
        "signal": False,
        "chain": True,
    }
    if smoke.get("ok") is False and not smoke.get("skipped"):
        payload["ok"] = False
        payload["chain"] = False
        payload["hint"] = smoke.get("hint") or "Session saved but whoami smoke failed"
        ui.warn("browser_capture_session: saved but smoke failed")
    else:
        ui.success(f"browser_capture_session: session {session} saved ({cookie_count} cookies)")
    return RunnerResult(cmd, True, 0, json.dumps(payload), "", "executed")


def cdp_attach(cdp_url: str = "http://127.0.0.1:9222", *, approve: bool = False) -> dict[str, Any]:
    """Probe a local Chromium remote-debugging CDP HTTP endpoint (no target traffic)."""
    import urllib.request

    plan = {"cdp_url": cdp_url, "approve": approve}
    if not approve:
        return {
            "ok": True,
            "dry_run": True,
            **plan,
            "hint": "Pass approve=true to GET /json/version on the local CDP port",
        }
    try:
        url = cdp_url.rstrip("/") + "/json/version"
        req = urllib.request.Request(url, headers={"User-Agent": "hackbot-cdp"})
        with urllib.request.urlopen(req, timeout=3) as resp:
            body = resp.read(4000).decode("utf-8", errors="replace")
        return {"ok": True, "up": True, "version": body[:500], **plan}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "up": False, "error": f"{type(exc).__name__}: {exc}", **plan}
