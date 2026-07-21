"""Capped content discovery — seed hunt surface with interesting paths."""

from __future__ import annotations

import json
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from .. import ui
from ..hunt_memory import Endpoint, HuntMemory
from ..redaction import redact_text
from .base import RunnerResult, require_in_scope

# Small high-signal list — not a brute dictionary.
DEFAULT_PATHS = (
    "/.env",
    "/.git/HEAD",
    "/robots.txt",
    "/sitemap.xml",
    "/swagger.json",
    "/swagger/v1/swagger.json",
    "/openapi.json",
    "/api",
    "/api/v1",
    "/api/v2",
    "/graphql",
    "/graphiql",
    "/admin",
    "/login",
    "/actuator",
    "/actuator/health",
    "/health",
    "/status",
    "/debug",
    "/server-status",
    "/.well-known/security.txt",
    "/backup",
    "/config.json",
    "/wp-json",
    "/api/users",
    "/api/me",
    "/api/orders",
    "/internal",
    "/console",
    "/phpinfo.php",
    "/server-info",
    "/metrics",
    "/v1/api-docs",
    "/docs",
    "/redoc",
)

INTERESTING = {200, 201, 301, 302, 401, 403, 500}


def discover_paths(
    target_dir: Path,
    base_url: str,
    *,
    paths: list[str] | None = None,
    approve: bool = False,
    force: bool = False,
    limit: int = 40,
    timeout: float = 8.0,
    seed_surface: bool = True,
) -> RunnerResult:
    require_in_scope(target_dir, base_url, action="content discovery path fuzz", force=force)
    base = base_url if "://" in base_url else f"https://{base_url}"
    parsed = urlparse(base)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    wordlist = list(paths or DEFAULT_PATHS)[: max(1, min(int(limit), 80))]
    plan = {"base": origin, "paths": len(wordlist), "approve": approve, "limit": limit}
    ui.code_panel(json.dumps(plan, indent=2), title="discover_paths", lexer="json")
    cmd = ["discover_paths", origin, str(len(wordlist))]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    hits: list[dict[str, Any]] = []
    endpoints: list[Endpoint] = []
    for path in wordlist:
        url = urljoin(origin + "/", path.lstrip("/"))
        try:
            req = urllib.request.Request(url, method="GET", headers={"User-Agent": "hackbot-discover"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = int(getattr(resp, "status", None) or resp.getcode())
                body = resp.read(4000).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            body = exc.read(2000).decode("utf-8", errors="replace") if exc.fp else ""
        except Exception as exc:  # noqa: BLE001
            hits.append({"path": path, "error": type(exc).__name__})
            continue
        if status in INTERESTING:
            row = {
                "path": path,
                "url": url,
                "status": status,
                "length": len(body),
                "preview": redact_text(body[:120]),
            }
            hits.append(row)
            endpoints.append(
                Endpoint(url=url, method="GET", params=[], source="discover_paths", notes=f"status={status}")
            )

    seeded = 0
    if seed_surface and endpoints:
        HuntMemory(target_dir).upsert_endpoints(endpoints, host=parsed.netloc.split(":")[0])
        seeded = len(endpoints)

    signal = any(h.get("status") in {200, 201} and h.get("path") in {"/.env", "/.git/HEAD", "/phpinfo.php"} for h in hits)
    out = {
        "ok": True,
        "signal": signal,
        "reason": "sensitive path exposed" if signal else f"mapped {len(hits)} interesting paths",
        "hits": hits[:60],
        "endpoints_seeded": seeded,
        "base": origin,
    }
    ui.success(f"discover_paths: {len(hits)} hits, seeded={seeded}")
    return RunnerResult(cmd, True, 0, json.dumps(out), "", "executed")
