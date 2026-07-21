"""Capped SSTI probe (Jinja/Twig/Freemarker canaries)."""

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

# Math canaries — look for evaluated result without RCE
_PAYLOADS = (
    ("{{7*7}}", "49"),
    ("${7*7}", "49"),
    ("#{7*7}", "49"),
    ("<%= 7*7 %>", "49"),
    ("{{7*'7'}}", "7777777"),
)


def ssti_probe(
    target_dir: Path,
    url: str,
    *,
    param: str = "q",
    approve: bool = False,
    force: bool = False,
    timeout: float = 12.0,
) -> RunnerResult:
    require_in_scope(target_dir, url, action="ssti template injection probe", force=force)
    parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    plan = {"url": url, "param": param, "payloads": len(_PAYLOADS), "approve": approve}
    ui.code_panel(json.dumps(plan, indent=2), title="ssti_probe", lexer="json")
    cmd = ["ssti_probe", url, f"param={param}"]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    results: list[dict[str, Any]] = []
    signal = False
    reason = "no SSTI evaluation"
    for payload, expect in _PAYLOADS:
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
            req = urllib.request.Request(probe, headers={"User-Agent": "hackbot-ssti-probe"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = int(getattr(resp, "status", None) or resp.getcode())
                body = resp.read(80_000).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            body = exc.read(40_000).decode("utf-8", errors="replace") if exc.fp else ""
        except Exception as exc:  # noqa: BLE001
            results.append({"payload": payload, "error": f"{type(exc).__name__}: {exc}"})
            continue
        # Evaluated if expect appears and raw payload mostly gone
        hit = expect in body and payload not in body
        soft = expect in body
        results.append(
            {
                "payload": payload,
                "expect": expect,
                "status": status,
                "evaluated": hit,
                "soft_hit": soft,
                "preview": redact_text(body[:180]),
            }
        )
        if hit or soft:
            signal = True
            reason = f"SSTI canary {expect} for {payload}"
            break

    out = {"url": url, "param": param, "signal": signal, "reason": reason, "results": results}
    return RunnerResult(cmd, True, 0, json.dumps(out), "", "executed")
