"""JS bundle analysis: endpoints, secrets, paths for attack-surface seeding."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from .. import ui
from ..redaction import redact_text
from .base import RunnerResult, require_in_scope

_URL_RE = re.compile(
    r"""(?<![A-Za-z0-9_])(?:https?:)?//[A-Za-z0-9.\-:_/?#&=%+~@]+|(?<![A-Za-z0-9_])(/[A-Za-z0-9_\-./]{2,}(?:\?[A-Za-z0-9_\-=&%]*)?)"""
)
_API_PATH_RE = re.compile(
    r"""["'`](/?(?:api|v\d+|graphql|rest|auth|oauth|users?|admin|internal)[/A-Za-z0-9_\-{}.]*)["'`]"""
)
_SECRET_PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("api_key_assign", re.compile(r"(?i)(?:api[_-]?key|apikey|secret|token)\s*[:=]\s*['\"]([A-Za-z0-9_\-]{16,})['\"]")),
    ("firebase", re.compile(r"AIza[0-9A-Za-z\-_]{35}")),
    ("slack", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
)


def analyze_js(
    target_dir: Path,
    source: str,
    *,
    approve: bool = False,
    force: bool = False,
    timeout: float = 20.0,
) -> RunnerResult:
    """Analyze a JS URL or local file for endpoints/secrets.

    `source` may be https://…/app.js or a readable local path.
    """
    is_url = source.startswith("http://") or source.startswith("https://")
    plan = {"source": source, "approve": approve, "kind": "url" if is_url else "file"}
    ui.code_panel(json.dumps(plan, indent=2), title="analyze_js", lexer="json")
    cmd = ["analyze_js", source]

    if is_url:
        require_in_scope(target_dir, source, action="js bundle analysis", force=force)
        if not approve:
            ui.dry_run_banner()
            return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")
        try:
            from ..scoped_http import scoped_fetch_bytes

            resp = scoped_fetch_bytes(
                source,
                target_dir=target_dir,
                action="js bundle analysis",
                force=force,
                timeout=timeout,
                headers={"User-Agent": "hackbot-js-analyzer"},
                max_bytes=2_000_000,
                gate_initial=False,
            )
            body = resp.body.decode("utf-8", errors="replace")
        except Exception as exc:  # noqa: BLE001
            return RunnerResult(cmd, True, 1, "", str(exc), f"fetch_error:{type(exc).__name__}")
        base = source
    else:
        path = Path(source).expanduser()
        if not path.is_absolute():
            # allow relative to target or cwd-like
            cand = Path(target_dir) / path
            path = cand if cand.exists() else path
        if not path.exists():
            return RunnerResult(cmd, False, None, json.dumps({"ok": False, "error": "missing file"}), "", "error")
        body = path.read_text(encoding="utf-8", errors="replace")[:2_000_000]
        base = str(path)

    endpoints: list[str] = []
    seen: set[str] = set()
    for m in _URL_RE.finditer(body):
        raw = m.group(0)
        if raw.startswith("//"):
            raw = "https:" + raw
        if raw.startswith("/"):
            if is_url:
                raw = urljoin(source, raw)
            else:
                continue
        if raw not in seen and len(raw) < 300:
            seen.add(raw)
            endpoints.append(raw)
    for m in _API_PATH_RE.finditer(body):
        path = m.group(1)
        if is_url:
            abs_u = urljoin(source, path)
        else:
            abs_u = path
        if abs_u not in seen:
            seen.add(abs_u)
            endpoints.append(abs_u)

    secrets: list[dict[str, str]] = []
    for kind, pattern in _SECRET_PATTERNS:
        for hit in pattern.findall(body)[:5]:
            val = hit if isinstance(hit, str) else hit[0] if hit else ""
            secrets.append({"kind": kind, "sample": redact_text(val[:40])})

    # Same-host filter when source is URL
    if is_url:
        host = urlparse(source).netloc
        endpoints = [e for e in endpoints if e.startswith("/") or urlparse(e).netloc in {"", host}]

    payload = {
        "ok": True,
        "source": base,
        "endpoint_count": len(endpoints[:200]),
        "endpoints": endpoints[:200],
        "secret_count": len(secrets),
        "secrets": secrets,
        "bytes_scanned": len(body),
    }
    ui.success(f"js: {payload['endpoint_count']} endpoints, {payload['secret_count']} secret hits")
    return RunnerResult(cmd, True if (is_url and approve) or not is_url else True, 0, json.dumps(payload), "", "executed")
