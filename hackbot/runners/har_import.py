"""HAR import: endpoints + secrets → hunt surface."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, urlparse

from ..hunt_memory import Endpoint, HuntMemory
from ..redaction import redact_text


def import_har(path: Path, target_dir: Path, *, max_entries: int = 500) -> dict[str, Any]:
    """Parse a HAR file and seed hunt surface + summarize interesting traffic."""
    text = path.read_text(encoding="utf-8", errors="replace")
    data = json.loads(text)
    log = data.get("log") or {}
    entries = log.get("entries") or []
    endpoints: list[Endpoint] = []
    hosts: set[str] = set()
    methods: dict[str, int] = {}
    status_codes: dict[str, int] = {}
    interesting: list[dict[str, Any]] = []

    for entry in entries[:max_entries]:
        req = entry.get("request") or {}
        resp = entry.get("response") or {}
        url = str(req.get("url") or "")
        if not url:
            continue
        method = str(req.get("method") or "GET").upper()
        status = str((resp.get("status") if isinstance(resp, dict) else "") or "")
        methods[method] = methods.get(method, 0) + 1
        if status:
            status_codes[status] = status_codes.get(status, 0) + 1
        parsed = urlparse(url)
        if parsed.netloc:
            hosts.add(parsed.netloc.split(":")[0])
        params = list(parse_qs(parsed.query).keys())
        # POST body params (form)
        post = req.get("postData") or {}
        if isinstance(post, dict) and post.get("text") and "application/x-www-form-urlencoded" in str(
            post.get("mimeType") or ""
        ):
            params.extend(parse_qs(str(post.get("text"))).keys())
        endpoints.append(
            Endpoint(
                url=url.split("#")[0],
                method=method,
                params=sorted(set(params)),
                auth_required=any(
                    str(h.get("name", "")).lower() in {"authorization", "cookie"}
                    for h in (req.get("headers") or [])
                    if isinstance(h, dict)
                ),
                source="har",
            )
        )
        # Flag auth/error-ish
        if status.startswith("5") or status in {"401", "403"} or "/admin" in url.lower():
            interesting.append(
                {
                    "method": method,
                    "url": redact_text(url)[:200],
                    "status": status,
                }
            )

    memory = HuntMemory(target_dir)
    if endpoints:
        host = next(iter(hosts), "")
        memory.upsert_endpoints(endpoints[:300], host=host)

    return {
        "ok": True,
        "path": str(path),
        "entries": min(len(entries), max_entries),
        "hosts": sorted(hosts),
        "methods": methods,
        "status_codes": status_codes,
        "endpoints_seeded": min(len(endpoints), 300),
        "interesting": interesting[:40],
        "surface": str(memory.root / "surface.yaml"),
    }
