"""OpenAPI / Swagger JSON → hunt surface endpoints."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from .hunt_memory import Endpoint, HuntMemory


def parse_openapi_dict(spec: dict[str, Any], *, base_url: str = "") -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    if not isinstance(spec, dict):
        return endpoints
    servers = spec.get("servers") or []
    if not base_url and isinstance(servers, list) and servers:
        url0 = servers[0].get("url") if isinstance(servers[0], dict) else ""
        if url0:
            base_url = str(url0)
    base_url = (base_url or "").rstrip("/")
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return endpoints
    for path, methods in list(paths.items())[:80]:
        if not isinstance(methods, dict):
            continue
        for method, op in methods.items():
            if method.lower() not in {"get", "post", "put", "patch", "delete"}:
                continue
            params: list[str] = []
            if isinstance(op, dict):
                for p in op.get("parameters") or []:
                    if isinstance(p, dict) and p.get("name"):
                        params.append(str(p["name"]))
            url = urljoin(base_url + "/", str(path).lstrip("/")) if base_url else str(path)
            endpoints.append(
                Endpoint(
                    url=url,
                    method=method.upper(),
                    params=params[:20],
                    source="openapi",
                    notes=(op.get("operationId") if isinstance(op, dict) else "") or "",
                )
            )
    return endpoints


def ingest_openapi_text(target_dir: Path, text: str, *, base_url: str = "", host: str = "") -> dict[str, Any]:
    try:
        spec = json.loads(text)
    except json.JSONDecodeError:
        return {"ok": False, "error": "invalid_json", "seeded": 0}
    eps = parse_openapi_dict(spec, base_url=base_url)
    if eps:
        HuntMemory(target_dir).upsert_endpoints(eps, host=host)
    return {"ok": True, "seeded": len(eps), "sample": [e.url for e in eps[:8]]}


def ingest_openapi_file(target_dir: Path, path: Path, *, base_url: str = "", host: str = "") -> dict[str, Any]:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"ok": False, "error": str(exc), "seeded": 0}
    return ingest_openapi_text(target_dir, text, base_url=base_url, host=host)
