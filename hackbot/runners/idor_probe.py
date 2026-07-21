"""Systematic IDOR/BOLA A/B probe — same URL as session A then B + structured diff."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlencode, urlparse, urlunparse

from .. import ui
from ..diffing import assert_idor_diff
from ..identity import load_identity
from ..redaction import redact_text
from . import http_request as http_mod
from .base import RunnerResult, require_in_scope


def _swap_id_param(url: str, param: str, new_value: str) -> str:
    parsed = urlparse(url if "://" in url else f"https://{url}")
    qs = parse_qs(parsed.query, keep_blank_values=True)
    if param:
        qs[param] = [new_value]
    return urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            "",
            urlencode({k: v[0] if v else "" for k, v in qs.items()}),
            "",
        )
    )


def idor_probe(
    target_dir: Path,
    url: str,
    *,
    param: str = "",
    swap_value: str = "",
    session_a: str = "A",
    session_b: str = "B",
    approve: bool = False,
    force: bool = False,
    use_jar: bool = True,
    timeout: float = 20.0,
) -> RunnerResult:
    """
    Fetch resource as A, then as B (optionally with ID param swapped).
    Signal when structured diff says confirmed/likely.
    """
    require_in_scope(target_dir, url, action="idor bola authz probe", force=force)
    identity = load_identity(target_dir)
    ready = set(identity.ready_sessions())
    plan = {
        "url": url,
        "session_a": session_a,
        "session_b": session_b,
        "param": param or None,
        "swap_value": bool(swap_value),
        "approve": approve,
        "ready": sorted(ready),
    }
    ui.code_panel(json.dumps(plan, indent=2), title="idor_probe", lexer="json")
    cmd = ["idor_probe", url, session_a, session_b]

    if session_a not in ready or session_b not in ready:
        return RunnerResult(
            cmd,
            False,
            None,
            json.dumps(
                {
                    "ok": False,
                    "signal": False,
                    "error": "sessions_missing",
                    "ready": sorted(ready),
                    "hint": "Load A/B into secrets/sessions.yaml first.",
                }
            ),
            "",
            "error",
        )

    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    url_a = url if "://" in url else f"https://{url}"
    url_b = _swap_id_param(url_a, param, swap_value) if param and swap_value else url_a

    ra = http_mod.http_request(
        target_dir,
        url_a,
        session=session_a,
        approve=True,
        force=force,
        timeout=timeout,
        label="idor_A",
        use_jar=use_jar,
    )
    rb = http_mod.http_request(
        target_dir,
        url_b,
        session=session_b,
        approve=True,
        force=force,
        timeout=timeout,
        label="idor_B",
        use_jar=use_jar,
    )
    try:
        pa = json.loads(ra.stdout) if ra.stdout else {}
        pb = json.loads(rb.stdout) if rb.stdout else {}
    except json.JSONDecodeError:
        pa, pb = {}, {}

    diff = assert_idor_diff(pa, pb, object_hint=url_a)
    signal = diff.verdict in {"confirmed", "likely"}
    out: dict[str, Any] = {
        "ok": True,
        "signal": signal,
        "reason": diff.reason,
        "verdict": diff.verdict,
        "diff": diff.as_dict(),
        "url_a": url_a,
        "url_b": url_b,
        "status_a": pa.get("status"),
        "status_b": pb.get("status"),
        "preview_a": redact_text(str(pa.get("body_preview") or "")[:200]),
        "preview_b": redact_text(str(pb.get("body_preview") or "")[:200]),
    }
    ui.success(f"idor_probe verdict={diff.verdict} signal={signal}")
    return RunnerResult(cmd, True, 0, json.dumps(out), "", "executed")
