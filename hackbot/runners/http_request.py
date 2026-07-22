"""Authenticated HTTP request runner for authz hunting (A/B sessions)."""

from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any
from urllib.parse import urlparse
from urllib.request import Request

from .. import ui
from ..identity import load_identity
from ..redaction import redact_text
from ..scoped_http import scoped_urlopen
from .base import RunnerResult, require_in_scope

MAX_BODY_STORE = 200_000
PREVIEW_CHARS = 2000


def http_request(
    target_dir: Path,
    url: str,
    *,
    method: str = "GET",
    session: str | None = None,
    body: str | None = None,
    content_type: str | None = None,
    extra_headers: dict[str, str] | None = None,
    approve: bool = False,
    force: bool = False,
    timeout: float = 20.0,
    label: str = "",
    use_jar: bool = True,
) -> RunnerResult:
    """Send one request with program + session headers. Dry-run unless approve."""
    method = (method or "GET").upper()
    identity = load_identity(target_dir)
    headers = identity.merge_headers(session)
    if use_jar:
        from ..hunt_jar import cookie_header

        host = urlparse(url if "://" in url else f"https://{url}").hostname or ""
        jar_cookie = cookie_header(target_dir, host=host, session=session or "")
        if jar_cookie:
            existing = headers.get("Cookie") or headers.get("cookie") or ""
            headers["Cookie"] = f"{existing}; {jar_cookie}".strip("; ").strip()
    if extra_headers:
        headers.update(extra_headers)
    if body is not None and content_type:
        headers.setdefault("Content-Type", content_type)
    elif body is not None and "Content-Type" not in headers:
        headers.setdefault("Content-Type", "application/json")

    require_in_scope(
        target_dir,
        url,
        action="http_request idor authz",
        force=force,
    )

    full_url = url if "://" in url else f"https://{url}"
    masked_hdrs = {k: ("***" if k.lower() in {"authorization", "cookie", "x-api-key"} else v) for k, v in headers.items()}
    plan = {
        "method": method,
        "url": full_url,
        "session": session or "(none)",
        "headers": masked_hdrs,
        "body_len": len(body) if body else 0,
        "label": label or "",
    }
    if ui.verbose_enabled():
        ui.code_panel(json.dumps(plan, indent=2), title="http_request", lexer="json")
    else:
        ui.action_line(
            "http",
            ui.format_http_action(method, full_url),
        )

    cmd = ["http_request", method, full_url, f"session={session or '-'}"]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(
            command=cmd,
            executed=False,
            returncode=None,
            stdout=json.dumps({"dry_run": True, **plan}),
            stderr="",
            message="dry-run",
        )

    data = body.encode("utf-8") if body is not None else None
    req = Request(full_url, data=data, method=method, headers=headers)
    started = time.perf_counter()
    status = 0
    resp_headers: dict[str, str] = {}
    resp_body = ""
    err_msg = ""
    set_cookies: list[str] = []
    redirect_hops: list[dict[str, Any]] = []
    final_url = full_url
    try:
        # Initial URL already gated above; still re-gate every redirect hop.
        resp = scoped_urlopen(
            req,
            target_dir=target_dir,
            action="http_request idor authz",
            force=force,
            timeout=timeout,
            gate_initial=False,
        )
        status = resp.status
        set_cookies = resp.get_all("Set-Cookie")
        resp_headers = {k: v for k, v in (resp.headers.items() if resp.headers else [])}
        raw = resp.body[: MAX_BODY_STORE + 1]
        if len(raw) > MAX_BODY_STORE:
            raw = raw[:MAX_BODY_STORE]
        resp_body = raw.decode("utf-8", errors="replace")
        redirect_hops = list(resp.hops)
        final_url = resp.url or full_url
    except PermissionError as exc:
        err_msg = str(exc)
        set_cookies = []
    except Exception as exc:  # noqa: BLE001
        err_msg = f"{type(exc).__name__}: {exc}"
        set_cookies = []

    elapsed_ms = (time.perf_counter() - started) * 1000
    body_hash = hashlib.sha256(resp_body.encode("utf-8", errors="replace")).hexdigest()

    if use_jar and set_cookies:
        from ..hunt_jar import merge_set_cookie

        try:
            merge_set_cookie(
                target_dir,
                set_cookies,
                url=final_url,
                session=session or "",
            )
        except Exception:  # noqa: BLE001
            pass

    result_obj: dict[str, Any] = {
        "ok": not err_msg,
        "method": method,
        "url": full_url,
        "final_url": final_url,
        "redirect_hops": redirect_hops,
        "session": session,
        "label": label or f"{session or 'anon'}",
        "status": status,
        "elapsed_ms": round(elapsed_ms, 1),
        "length": len(resp_body),
        "sha256": body_hash,
        "headers": redact_text(json.dumps(dict(list(resp_headers.items())[:40]))),
        "body_preview": redact_text(resp_body[:PREVIEW_CHARS]),
        "body": resp_body,
        "error": err_msg,
    }
    summary = ui.format_http_action(
        method,
        full_url,
        status=status if not err_msg else None,
        error=err_msg or None,
        elapsed_ms=elapsed_ms if not err_msg else None,
    )
    ui.action_line("http", summary, ok=False if err_msg else True)
    if ui.verbose_enabled():
        ui.kv("status", str(status))
        ui.kv("length", str(len(resp_body)))
        ui.kv("sha256", body_hash[:16] + "…")
        if resp_body:
            preview = ui.compact_text(
                redact_text(resp_body[:PREVIEW_CHARS]), max_chars=PREVIEW_CHARS
            )
            ui.code_panel(preview, title="body_preview", lexer="text")

    # Persist a compact JSON (no secrets in request headers) under evidence/safe
    safe_payload = {
        k: result_obj[k]
        for k in (
            "method",
            "url",
            "session",
            "label",
            "status",
            "elapsed_ms",
            "length",
            "sha256",
            "headers",
            "body_preview",
            "error",
        )
    }
    # Keep full body for assert_diff in a sidecar under evidence/raw-ish path via return stdout
    stdout = json.dumps(result_obj)
    return RunnerResult(
        command=cmd,
        executed=True,
        returncode=0 if not err_msg else 1,
        stdout=stdout,
        stderr=err_msg,
        message=json.dumps(safe_payload),
    )
