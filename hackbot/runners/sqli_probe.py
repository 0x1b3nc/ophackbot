"""Capped SQLi boolean/error differential probe (authorized bounty only)."""

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

# Tiny, non-destructive probe set — stop on first clear signal
_TRUE_FALSE = (
    ("1", "baseline"),
    ("1 AND 1=1", "true"),
    ("1 AND 1=2", "false"),
    ("1'", "syntax"),
)

_ERROR_MARKERS = (
    "sql syntax",
    "mysql",
    "postgresql",
    "ora-",
    "sqlite",
    "odbc",
    "unclosed quotation",
    "syntax error",
)


def sqli_probe(
    target_dir: Path,
    url: str,
    *,
    param: str = "id",
    approve: bool = False,
    force: bool = False,
    timeout: float = 12.0,
) -> RunnerResult:
    require_in_scope(target_dir, url, action="sqli injection probe", force=force)
    parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    plan = {"url": url, "param": param, "probes": len(_TRUE_FALSE), "approve": approve}
    ui.code_panel(json.dumps(plan, indent=2), title="sqli_probe", lexer="json")
    cmd = ["sqli_probe", url, f"param={param}"]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    results: list[dict[str, Any]] = []
    for value, label in _TRUE_FALSE:
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
                action="sqli injection probe",
                force=force,
                timeout=timeout,
                headers={"User-Agent": "hackbot-sqli-probe"},
                max_bytes=80_000,
                gate_initial=False,
            )
            status = resp.status
            body = resp.body.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            results.append({"label": label, "error": f"{type(exc).__name__}: {exc}"})
            continue
        results.append(
            {
                "label": label,
                "status": status,
                "length": len(body),
                "error_marker": any(m in body.lower() for m in _ERROR_MARKERS),
                "preview": redact_text(body[:200]),
            }
        )

    by_label = {r["label"]: r for r in results if "label" in r}
    signal = False
    reason = "no differential"
    baseline = by_label.get("baseline")
    true_r = by_label.get("true")
    false_r = by_label.get("false")
    syntax = by_label.get("syntax")
    if true_r and false_r and baseline:
        if true_r.get("status") != false_r.get("status") or abs(
            int(true_r.get("length") or 0) - int(false_r.get("length") or 0)
        ) > max(40, int(baseline.get("length") or 0) * 0.05):
            if true_r.get("status") == baseline.get("status") and abs(
                int(true_r.get("length") or 0) - int(baseline.get("length") or 0)
            ) < 40:
                signal = True
                reason = "boolean true/false differential"
    if syntax and syntax.get("error_marker"):
        signal = True
        reason = "SQL error marker on syntax probe"
    if any(r.get("error_marker") for r in results):
        signal = True
        reason = reason if signal else "SQL error marker"

    payload = {
        "url": url,
        "param": param,
        "signal": signal,
        "reason": reason,
        "results": results,
    }
    ui.code_panel(json.dumps(payload, indent=2)[:3000], title="sqli_probe result", lexer="json")
    return RunnerResult(cmd, True, 0, json.dumps(payload), "", "executed")
