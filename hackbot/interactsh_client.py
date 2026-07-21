"""Interactsh-style client helper (env-configured). No silent network without operator env."""

from __future__ import annotations

import json
import os
import urllib.request
from typing import Any

from .oob import mint_canary, oob_configured, poll_oob, wait_and_poll


def interactsh_status() -> dict[str, Any]:
    base = (os.environ.get("HACKBOT_OOB_BASE") or "").strip()
    poll = (os.environ.get("HACKBOT_OOB_POLL_URL") or "").strip()
    token = (os.environ.get("HACKBOT_OOB_AUTH") or "").strip()
    return {
        "ok": True,
        "configured": bool(base),
        "base": base[:80] if base else "",
        "poll_url_set": bool(poll),
        "auth_set": bool(token),
        "hint": "Set HACKBOT_OOB_BASE + HACKBOT_OOB_POLL_URL (+ optional HACKBOT_OOB_AUTH).",
    }


def interactsh_register() -> dict[str, Any]:
    """Mint a canary bound to configured OOB base (register == mint for env-driven setups)."""
    if not oob_configured():
        return {"ok": False, "error": "HACKBOT_OOB_BASE not set", **interactsh_status()}
    c = mint_canary(kind="interactsh")
    return {"ok": True, "canary": c, **interactsh_status()}


def interactsh_poll(canary: dict[str, Any] | None = None, *, wait: bool = True) -> dict[str, Any]:
    c = canary or mint_canary(kind="interactsh")
    # Optional bearer for poll URL
    auth = (os.environ.get("HACKBOT_OOB_AUTH") or "").strip()
    if auth and not wait:
        # Direct poll with auth header when poll URL set
        poll = (os.environ.get("HACKBOT_OOB_POLL_URL") or "").strip()
        if poll:
            try:
                url = poll.replace("TOKEN", str(c.get("token") or ""))
                req = urllib.request.Request(
                    url,
                    headers={"User-Agent": "hackbot-interactsh", "Authorization": f"Bearer {auth}"},
                )
                with urllib.request.urlopen(req, timeout=10) as resp:
                    body = resp.read(20_000).decode("utf-8", errors="replace")
                hits = [{"preview": body[:200]}] if str(c.get("token") or "") in body else []
                return {"ok": True, "canary": c, "hits": hits, "signal": bool(hits)}
            except Exception as exc:  # noqa: BLE001
                return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "canary": c}
    if wait:
        return {"ok": True, "canary": c, **wait_and_poll(c)}
    return {"ok": True, "canary": c, **poll_oob(c)}
