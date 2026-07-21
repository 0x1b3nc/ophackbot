"""Systematic IDOR/BOLA/BFLA A/B probe — read + capped write matrix."""

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

# Cap write methods (OPERATING_RULES matrix, still approve-gated)
WRITE_METHODS = ("PATCH", "PUT", "POST", "DELETE")


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


def _one_pair(
    target_dir: Path,
    url_a: str,
    url_b: str,
    *,
    session_a: str,
    session_b: str,
    method: str,
    body: str | None,
    force: bool,
    use_jar: bool,
    timeout: float,
    label_prefix: str,
) -> dict[str, Any]:
    ra = http_mod.http_request(
        target_dir,
        url_a,
        method=method,
        session=session_a,
        body=body,
        approve=True,
        force=force,
        timeout=timeout,
        label=f"{label_prefix}_A",
        use_jar=use_jar,
    )
    rb = http_mod.http_request(
        target_dir,
        url_b,
        method=method,
        session=session_b,
        body=body,
        approve=True,
        force=force,
        timeout=timeout,
        label=f"{label_prefix}_B",
        use_jar=use_jar,
    )
    try:
        pa = json.loads(ra.stdout) if ra.stdout else {}
        pb = json.loads(rb.stdout) if rb.stdout else {}
    except json.JSONDecodeError:
        pa, pb = {}, {}
    diff = assert_idor_diff(pa, pb, object_hint=url_a)
    return {
        "method": method,
        "verdict": diff.verdict,
        "reason": diff.reason,
        "signal": diff.verdict in {"confirmed", "likely"},
        "status_a": pa.get("status"),
        "status_b": pb.get("status"),
        "url_a": url_a,
        "url_b": url_b,
        "preview_a": redact_text(str(pa.get("body_preview") or "")[:160]),
        "preview_b": redact_text(str(pb.get("body_preview") or "")[:160]),
        "diff": diff.as_dict(),
    }


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
    use_jar: bool = False,
    timeout: float = 20.0,
    method: str = "GET",
    methods: str = "",
    body: str = "",
    matrix: str = "bola",
) -> RunnerResult:
    """
    Authz probe matrix:
    - bola: same URL, A then B (object ownership)
    - bfla: A vs B on privileged method (role)
    - both: ID swap + session swap
    methods: CSV of HTTP methods (default GET; optional write set capped).
    """
    require_in_scope(target_dir, url, action="idor bola authz probe", force=force)
    identity = load_identity(target_dir)
    ready = set(identity.ready_sessions())
    method_list = [m.strip().upper() for m in (methods or method or "GET").split(",") if m.strip()]
    # Cap: at most GET + 2 write methods (prefer PATCH/PUT over DELETE when both present)
    writes = [m for m in method_list if m in WRITE_METHODS]
    write_pref = [m for m in ("PATCH", "PUT", "POST", "DELETE") if m in writes][:2]
    reads = [m for m in method_list if m not in WRITE_METHODS] or ["GET"]
    method_list = list(dict.fromkeys(reads[:1] + write_pref))
    matrix = (matrix or "bola").lower()
    # GraphQL mutations: force POST + both matrix when body looks like a mutation
    body_l = (body or "").lower()
    if "graphql" in url.lower() or "mutation" in body_l:
        if "POST" not in method_list:
            method_list = ["POST"] + [m for m in method_list if m != "GET"][:2]
        if matrix in {"bola", "read"}:
            matrix = "both"
    plan = {
        "url": url,
        "session_a": session_a,
        "session_b": session_b,
        "param": param or None,
        "swap_value": bool(swap_value),
        "methods": method_list,
        "matrix": matrix,
        "approve": approve,
        "ready": sorted(ready),
    }
    ui.code_panel(json.dumps(plan, indent=2), title="idor_probe", lexer="json")
    cmd = ["idor_probe", url, session_a, session_b, ",".join(method_list)]

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
                    "hint": "Load A/B into secrets/sessions.yaml or run session_bootstrap.",
                }
            ),
            "",
            "error",
        )

    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    url_a = url if "://" in url else f"https://{url}"
    url_swapped = _swap_id_param(url_a, param, swap_value) if param and swap_value else url_a
    body_payload = body or (None if method_list == ["GET"] else "{}")

    rows: list[dict[str, Any]] = []
    for meth in method_list:
        b = None if meth == "GET" else (body_payload or "{}")
        if matrix in {"bola", "both", "read"}:
            # Same object URL as A then B
            rows.append(
                _one_pair(
                    target_dir,
                    url_a,
                    url_a,
                    session_a=session_a,
                    session_b=session_b,
                    method=meth,
                    body=b,
                    force=force,
                    use_jar=use_jar,
                    timeout=timeout,
                    label_prefix=f"idor_{meth}_bola",
                )
            )
        if matrix in {"bfla", "both"} and meth in WRITE_METHODS:
            # BFLA: privileged path/method as lower-priv session B (admin-ish URL)
            admin_url = url_a
            if "/api/" in url_a and "/admin" not in url_a:
                admin_url = url_a.replace("/api/", "/api/admin/", 1)
            elif not url_a.rstrip("/").endswith("/admin"):
                admin_url = url_a.rstrip("/") + "/admin"
            rows.append(
                _one_pair(
                    target_dir,
                    admin_url,
                    admin_url,
                    session_a=session_a,
                    session_b=session_b,
                    method=meth,
                    body=b,
                    force=force,
                    use_jar=use_jar,
                    timeout=timeout,
                    label_prefix=f"idor_{meth}_bfla",
                )
            )
        if matrix in {"both", "swap", "replay"} and param and swap_value:
            # Cross-object: A on own URL, B on swapped object ID
            rows.append(
                _one_pair(
                    target_dir,
                    url_a,
                    url_swapped,
                    session_a=session_a,
                    session_b=session_b,
                    method=meth,
                    body=b,
                    force=force,
                    use_jar=use_jar,
                    timeout=timeout,
                    label_prefix=f"idor_{meth}_swap",
                )
            )
            # Authz replay (BAC): A's exact object URL+body replayed as session B
            rows.append(
                _one_pair(
                    target_dir,
                    url_a,
                    url_a,
                    session_a=session_a,
                    session_b=session_b,
                    method=meth,
                    body=b,
                    force=force,
                    use_jar=use_jar,
                    timeout=timeout,
                    label_prefix=f"idor_{meth}_replay",
                )
            )

    if not rows:
        rows.append(
            _one_pair(
                target_dir,
                url_a,
                url_swapped if param and swap_value else url_a,
                session_a=session_a,
                session_b=session_b,
                method="GET",
                body=None,
                force=force,
                use_jar=use_jar,
                timeout=timeout,
                label_prefix="idor_GET",
            )
        )

    signal = any(r.get("signal") for r in rows)
    best = next((r for r in rows if r.get("verdict") == "confirmed"), None) or next(
        (r for r in rows if r.get("verdict") == "likely"), None
    ) or rows[0]
    out: dict[str, Any] = {
        "ok": True,
        "signal": signal,
        "reason": best.get("reason"),
        "verdict": best.get("verdict"),
        "matrix": matrix,
        "methods": method_list,
        "rows": rows,
        "url_a": url_a,
        "url_b": best.get("url_b"),
        "status_a": best.get("status_a"),
        "status_b": best.get("status_b"),
        "preview_a": best.get("preview_a"),
        "preview_b": best.get("preview_b"),
        "diff": best.get("diff"),
    }
    ui.success(f"idor_probe verdict={out['verdict']} signal={signal} rows={len(rows)}")
    return RunnerResult(cmd, True, 0, json.dumps(out), "", "executed")
