"""Capped mass-assignment / method-override / HPP probes (authorize-gated)."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urlencode, urlparse, parse_qs, urlunparse

from .. import ui
from . import http_request as http_mod
from .base import RunnerResult, require_in_scope


def mass_assignment_probe(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
    session: str = "A",
    extra_fields: dict[str, Any] | None = None,
) -> RunnerResult:
    require_in_scope(
        target_dir,
        url,
        action="mass assignment probe",
        force=force,
        tool="mass_assignment_probe",
    )
    fields = extra_fields or {"role": "admin", "isAdmin": True, "admin": True}
    plan = {"url": url, "fields": list(fields.keys()), "approve": approve}
    ui.code_panel(json.dumps(plan, indent=2), title="mass_assignment_probe", lexer="json")
    cmd = ["mass_assignment_probe", url]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")
    body = json.dumps(fields)
    result = http_mod.http_request(
        target_dir,
        url,
        method="POST",
        session=session or None,
        body=body,
        content_type="application/json",
        approve=True,
        force=force,
        label="mass_assign",
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {}
    preview = str(payload.get("body_preview") or "").lower()
    signal = any(k in preview for k in ("role", "admin", "isadmin")) and int(payload.get("status") or 0) < 400
    out = {
        "ok": True,
        "signal": signal,
        "reason": "response reflects privileged fields" if signal else "no privilege reflection",
        "status": payload.get("status"),
        "preview": payload.get("body_preview"),
    }
    return RunnerResult(cmd, True, 0, json.dumps(out), "", "executed")


def method_override_probe(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
    session: str = "A",
) -> RunnerResult:
    require_in_scope(
        target_dir,
        url,
        action="method override probe",
        force=force,
        tool="method_override_probe",
    )
    plan = {"url": url, "override": "DELETE", "approve": approve}
    ui.code_panel(json.dumps(plan, indent=2), title="method_override_probe", lexer="json")
    cmd = ["method_override_probe", url]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")
    result = http_mod.http_request(
        target_dir,
        url,
        method="POST",
        session=session or None,
        extra_headers={"X-HTTP-Method-Override": "DELETE", "X-Method-Override": "DELETE"},
        approve=True,
        force=force,
        label="method_override",
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {}
    status = int(payload.get("status") or 0)
    signal = status in {200, 204, 301, 302}
    return RunnerResult(
        cmd,
        True,
        0,
        json.dumps({"ok": True, "signal": signal, "status": status, "reason": "override accepted" if signal else "no override"}),
        "",
        "executed",
    )


def hpp_probe(
    target_dir: Path,
    url: str,
    *,
    param: str = "id",
    approve: bool = False,
    force: bool = False,
    session: str = "A",
) -> RunnerResult:
    require_in_scope(target_dir, url, action="http parameter pollution", force=force)
    parsed = urlparse(url if "://" in url else f"https://{url}")
    qs = parse_qs(parsed.query, keep_blank_values=True)
    # Duplicate param: id=1&id=2
    polluted = urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            "",
            f"{param}=1&{param}=999999&" + urlencode({k: v[0] for k, v in qs.items() if k != param}),
            "",
        )
    )
    plan = {"url": polluted, "param": param, "approve": approve}
    ui.code_panel(json.dumps(plan, indent=2), title="hpp_probe", lexer="json")
    cmd = ["hpp_probe", polluted]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")
    result = http_mod.http_request(
        target_dir, polluted, session=session or None, approve=True, force=force, label="hpp"
    )
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {}
    return RunnerResult(
        cmd,
        True,
        0,
        json.dumps(
            {
                "ok": True,
                "signal": False,
                "reason": "HPP probe completed (manual triage)",
                "status": payload.get("status"),
                "preview": payload.get("body_preview"),
            }
        ),
        "",
        "executed",
    )
