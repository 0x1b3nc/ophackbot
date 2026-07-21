"""Bounded race / TOCTOU probe — parallel identical requests, compare variance."""

from __future__ import annotations

import concurrent.futures
import hashlib
import json
import time
import urllib.error
import urllib.request
from collections import Counter
from pathlib import Path
from typing import Any

from .. import ui
from ..identity import load_identity
from ..redaction import redact_text
from .base import RunnerResult, require_in_scope

MAX_WORKERS = 12
MAX_BURST = 30


def race_probe(
    target_dir: Path,
    url: str,
    *,
    method: str = "GET",
    workers: int = 8,
    burst: int = 16,
    session: str = "",
    body: str = "",
    approve: bool = False,
    force: bool = False,
    timeout: float = 8.0,
) -> RunnerResult:
    """Fire a short parallel burst; signal if response bodies/status diverge oddly."""
    workers = max(2, min(int(workers), MAX_WORKERS))
    burst = max(2, min(int(burst), MAX_BURST))
    method = (method or "GET").upper()
    require_in_scope(
        target_dir,
        url,
        action="race condition probe",
        force=force,
        tool="race_probe",
    )
    full = url if "://" in url else f"https://{url}"

    headers: dict[str, str] = {"User-Agent": "hackbot-race-probe"}
    if session:
        identity = load_identity(target_dir)
        headers.update(identity.merge_headers(session))

    plan = {
        "url": full,
        "method": method,
        "workers": workers,
        "burst": burst,
        "session": session or None,
        "approve": approve,
    }
    ui.code_panel(json.dumps(plan, indent=2), title="race_probe", lexer="json")
    cmd = ["race_probe", method, full, str(workers), str(burst)]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    data_bytes = body.encode() if body and method in {"POST", "PUT", "PATCH"} else None

    def one(_i: int) -> dict[str, Any]:
        req = urllib.request.Request(full, data=data_bytes, method=method, headers=headers)
        started = time.perf_counter()
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = int(getattr(resp, "status", None) or resp.getcode())
                raw = resp.read(40_000)
            return {
                "status": status,
                "len": len(raw),
                "hash": hashlib.sha256(raw).hexdigest()[:12],
                "ms": round((time.perf_counter() - started) * 1000, 1),
            }
        except urllib.error.HTTPError as exc:
            raw = exc.read(20_000) if exc.fp else b""
            return {
                "status": int(exc.code),
                "len": len(raw),
                "hash": hashlib.sha256(raw).hexdigest()[:12] if raw else "",
                "ms": round((time.perf_counter() - started) * 1000, 1),
            }
        except Exception as exc:  # noqa: BLE001
            return {"error": type(exc).__name__, "ms": round((time.perf_counter() - started) * 1000, 1)}

    rows: list[dict[str, Any]] = []
    with concurrent.futures.ThreadPoolExecutor(max_workers=workers) as pool:
        futs = [pool.submit(one, i) for i in range(burst)]
        for fut in concurrent.futures.as_completed(futs):
            rows.append(fut.result())

    statuses = Counter(r.get("status") for r in rows if "status" in r)
    hashes = Counter(r.get("hash") for r in rows if r.get("hash"))
    # Soft race hint: mixed 2xx with divergent bodies, or mix of success+conflict
    signal = False
    reason = "uniform responses"
    if len(hashes) >= 2 and any(s in {200, 201} for s in statuses):
        signal = True
        reason = "divergent bodies under parallel burst (possible race)"
    elif len(statuses) >= 2 and ({200, 201} & set(statuses)) and ({409, 429, 500} & set(statuses)):
        signal = True
        reason = "mixed success/error under parallel burst"

    out = {
        "ok": True,
        "signal": signal,
        "reason": reason,
        "statuses": {str(k): v for k, v in statuses.items()},
        "unique_hashes": len(hashes),
        "sample": rows[:8],
        "note": redact_text("Race hint only — confirm business logic impact."),
    }
    return RunnerResult(cmd, True, 0, json.dumps(out), "", "executed")
