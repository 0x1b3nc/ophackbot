"""Observe v2 pipeline: deepen surface before Decide."""

from __future__ import annotations

import json
import os
import re
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from . import ui
from .hunt_memory import Endpoint, HuntMemory
from .openapi_parse import ingest_openapi_text
from .surface import map_surface, origin_of

_SCRIPT_SRC = re.compile(r"""<script[^>]+src=["']([^"']+)["']""", re.I)
_WS_RE = re.compile(r"""wss?://[^\s"'<>]+""", re.I)
_XML_HINT = re.compile(r"""(?:application/xml|text/xml|\.xml\b|soap)""", re.I)


def _env_truthy(name: str, default: str = "1") -> bool:
    return os.environ.get(name, default).strip().lower() not in {"0", "false", "no", "off"}


def observe_v2(
    target_dir: Path,
    seed: str,
    *,
    approve: bool = False,
    force: bool = False,
    execute_tool: Any = None,
) -> dict[str, Any]:
    """
    Run enriched Observe: map_surface → JS bundles → optional browser_network →
    auto HAR/Burp → OpenAPI hits → OSINT → tag ws/xml/mobile.
    """
    target_dir = Path(target_dir)
    memory = HuntMemory(target_dir)
    host = urlparse(seed if "://" in seed else f"https://{seed}").hostname or ""
    steps: list[dict[str, Any]] = []
    tags: set[str] = set()

    surface = map_surface(target_dir, seed, approve=approve, force=force)
    steps.append({"step": "map_surface", "ok": bool(surface.get("ok")), "detail": surface})

    # Script src → analyze_js (capped)
    html = ""
    try:
        raw_html = (surface.get("html_preview") or surface.get("body_preview") or "")
        html = str(raw_html)
    except Exception:  # noqa: BLE001
        html = ""
    # Also try reading from endpoints notes / fetch is already done in map_surface —
    # pull script URLs from any stored attempt detail is hard; re-scan seed page links via memory
    script_urls: list[str] = []
    for ep in memory.endpoints():
        if ep.url.endswith(".js") or "javascript" in (ep.notes or "").lower():
            script_urls.append(ep.url)
    # From surface detail if present
    for link in surface.get("links") or surface.get("script_srcs") or []:
        if isinstance(link, str) and link.endswith(".js"):
            script_urls.append(link)
    # Parse script tags if map_surface returned html
    for m in _SCRIPT_SRC.finditer(html):
        abs_u = urljoin(origin_of(seed) + "/", m.group(1))
        script_urls.append(abs_u)
    script_urls = list(dict.fromkeys(script_urls))[:5]

    js_seeded = 0
    js_errors = 0
    if execute_tool and script_urls and approve:
        for js_url in script_urls:
            try:
                raw = execute_tool(
                    "analyze_js",
                    {
                        "target_dir": str(target_dir),
                        "source": js_url,
                        "approve": approve,
                        "force": force,
                    },
                )
                data = json.loads(raw) if isinstance(raw, str) else (raw or {})
                if not isinstance(data, dict) or data.get("ok") is False:
                    js_errors += 1
                    steps.append(
                        {
                            "step": "analyze_js",
                            "source": js_url,
                            "error": str(
                                (data or {}).get("error")
                                if isinstance(data, dict)
                                else "analyze_js failed"
                            ),
                        }
                    )
                    continue
                seeded = int(
                    data.get("endpoints_seeded")
                    or len(data.get("endpoints") or [])
                    or 0
                )
                js_seeded += seeded
                tags.add("js")
                steps.append(
                    {"step": "analyze_js", "source": js_url, "ok": True, "seeded": seeded}
                )
            except Exception as exc:  # noqa: BLE001
                js_errors += 1
                steps.append(
                    {"step": "analyze_js", "source": js_url, "error": type(exc).__name__}
                )
        steps.append(
            {
                "step": "analyze_js_summary",
                "bundles": len(script_urls),
                "seeded": js_seeded,
                "errors": js_errors,
            }
        )
    elif script_urls:
        steps.append(
            {
                "step": "analyze_js",
                "skipped": True,
                "bundles": len(script_urls),
                "reason": "no_approve_or_tool",
            }
        )

    # SPA heuristic → browser_network
    ep_count = len(memory.endpoints())
    if ep_count <= 3 and script_urls and execute_tool and approve:
        try:
            raw = execute_tool(
                "browser_network",
                {
                    "target_dir": str(target_dir),
                    "url": seed if "://" in seed else f"https://{seed}",
                    "approve": approve,
                    "force": force,
                    "seed_surface": True,
                },
            )
            data = json.loads(raw) if isinstance(raw, str) else {}
            steps.append({"step": "browser_network", "ok": True, "detail": data})
            tags.add("spa")
        except Exception as exc:  # noqa: BLE001
            steps.append({"step": "browser_network", "error": type(exc).__name__})

    # Auto-import HAR / Burp XML under target
    imports = 0
    for pattern in ("**/*.har", "**/*burp*.xml", "**/burp*.xml"):
        for path in list(target_dir.glob(pattern))[:5]:
            if "secrets" in path.parts:
                continue
            if execute_tool is None:
                break
            tool = "import_har" if path.suffix.lower() == ".har" else "import_burp_xml"
            try:
                raw = execute_tool(
                    tool,
                    {"target_dir": str(target_dir), "path": str(path)},
                )
                imports += 1
                steps.append({"step": tool, "path": str(path), "result": json.loads(raw) if isinstance(raw, str) else raw})
                tags.add("har" if tool == "import_har" else "burp")
            except Exception as exc:  # noqa: BLE001
                steps.append({"step": tool, "error": type(exc).__name__, "path": str(path)})
    if imports:
        ui.info(f"observe_v2: imported {imports} traffic export(s)")

    # OpenAPI from local files or discovered endpoints
    for path in list(target_dir.glob("**/*openapi*.json"))[:3] + list(target_dir.glob("**/swagger.json"))[:2]:
        if "secrets" in path.parts:
            continue
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
            r = ingest_openapi_text(target_dir, text, base_url=origin_of(seed), host=host)
            steps.append({"step": "openapi_file", "path": str(path), **r})
            if r.get("seeded"):
                tags.add("openapi")
        except Exception as exc:  # noqa: BLE001
            steps.append({"step": "openapi_file", "error": type(exc).__name__})

    for ep in memory.endpoints():
        if any(x in ep.url.lower() for x in ("openapi", "swagger", "api-docs")):
            tags.add("openapi")
            if approve:
                try:
                    from .scoped_http import scoped_fetch_bytes

                    resp = scoped_fetch_bytes(
                        ep.url,
                        target_dir=target_dir,
                        action="observe openapi fetch",
                        force=force,
                        timeout=12,
                        headers={"User-Agent": "hackbot-observe-openapi"},
                        max_bytes=500_000,
                    )
                    text = resp.body.decode("utf-8", errors="replace")
                    r = ingest_openapi_text(target_dir, text, base_url=origin_of(seed), host=host)
                    steps.append(
                        {
                            "step": "openapi_fetch",
                            "url": ep.url,
                            "final_url": resp.url,
                            "redirect_hops": resp.hops,
                            **r,
                        }
                    )
                except PermissionError as exc:
                    steps.append(
                        {
                            "step": "openapi_fetch",
                            "url": ep.url,
                            "skipped": True,
                            "error": f"scope_denied: {exc}",
                        }
                    )
                    ui.warn(f"observe openapi skipped (scope): {exc}")
                except Exception as exc:  # noqa: BLE001
                    steps.append({"step": "openapi_fetch", "url": ep.url, "error": type(exc).__name__})

    # OSINT (crt / wayback) when enabled
    if _env_truthy("HACKBOT_OBSERVE_OSINT", "1") and execute_tool and host and "." in host:
        try:
            crt = json.loads(
                execute_tool("crt_subdomains", {"domain": host})
                if callable(execute_tool)
                else "{}"
            )
            steps.append({"step": "crt_subdomains", "detail": crt})
            tags.add("osint")
        except Exception as exc:  # noqa: BLE001
            steps.append({"step": "crt_subdomains", "error": type(exc).__name__})
        try:
            wb = json.loads(
                execute_tool("wayback_urls", {"domain": host, "limit": 40})
            )
            steps.append({"step": "wayback_urls", "detail": wb})
        except Exception as exc:  # noqa: BLE001
            steps.append({"step": "wayback_urls", "error": type(exc).__name__})

    # Tag websocket / xml / login / mobile artifacts
    extra_eps: list[Endpoint] = []
    for ep in list(memory.endpoints()):
        if _WS_RE.search(ep.url) or ep.url.startswith("ws"):
            tags.add("websocket")
        if _XML_HINT.search(ep.url) or _XML_HINT.search(ep.notes or ""):
            tags.add("xml")
        if "login" in ep.url.lower() or "auth" in ep.url.lower():
            tags.add("login")
        for m in _WS_RE.findall(ep.notes or ""):
            extra_eps.append(Endpoint(url=m.rstrip(".,)"), method="GET", source="observe_ws", notes="ws"))
            tags.add("websocket")
    if extra_eps:
        memory.upsert_endpoints(extra_eps[:10], host=host)

    # Mobile artifacts
    mobile_hits = list(target_dir.glob("**/*.apk"))[:2] + list(target_dir.glob("**/*.har"))[:2]
    if mobile_hits and execute_tool:
        tags.add("mobile")
        apk = next((p for p in mobile_hits if p.suffix.lower() == ".apk"), None)
        har = next((p for p in mobile_hits if p.suffix.lower() == ".har"), None)
        if apk or har:
            try:
                args: dict[str, Any] = {"target_dir": str(target_dir), "start_hunt": False}
                if apk:
                    args["apk_path"] = str(apk)
                if har:
                    args["har_path"] = str(har)
                raw = execute_tool("mobile_bridge", args)
                steps.append({"step": "mobile_bridge", "detail": json.loads(raw) if isinstance(raw, str) else raw})
            except Exception as exc:  # noqa: BLE001
                steps.append({"step": "mobile_bridge", "error": type(exc).__name__})

    # Persist tags on state-ish file under hunt/
    tags_path = target_dir / "hunt" / "observe_tags.json"
    tags_path.parent.mkdir(parents=True, exist_ok=True)
    tag_list = sorted(tags)
    tags_path.write_text(json.dumps({"tags": tag_list, "steps": len(steps)}, indent=2), encoding="utf-8")

    try:
        from .sink_registry import build_sink_registry

        build_sink_registry(target_dir)
    except Exception:  # noqa: BLE001
        pass

    out = {
        "ok": True,
        "host": host,
        "seed": seed,
        "tags": tag_list,
        "endpoint_count": len(memory.endpoints()),
        "steps": steps,
    }
    ui.success(f"observe_v2: endpoints={out['endpoint_count']} tags={tag_list}")
    return out


def load_observe_tags(target_dir: Path) -> set[str]:
    path = Path(target_dir) / "hunt" / "observe_tags.json"
    if not path.exists():
        return set()
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        return set(data.get("tags") or [])
    except Exception:  # noqa: BLE001
        return set()


def observe_refresh_lite(target_dir: Path, *, host: str = "") -> dict[str, Any]:
    """Re-tag surface from existing endpoints (no full crawl). Cheap mid-hunt refresh."""
    target_dir = Path(target_dir)
    memory = HuntMemory(target_dir)
    tags = load_observe_tags(target_dir)
    before = len(memory.endpoints())
    for ep in memory.endpoints():
        low = ep.url.lower()
        if "login" in low or "auth" in low or "oauth" in low:
            tags.add("login")
        if "graphql" in low:
            tags.add("graphql")
        if any(x in low for x in ("api/", "/v1/", "/v2/")):
            tags.add("api")
        if ep.has_id_param() or re.search(r"/\d+(?:/|$)", ep.url):
            tags.add("id_param")
        if _WS_RE.search(ep.url):
            tags.add("websocket")
        if _XML_HINT.search(ep.url) or _XML_HINT.search(ep.notes or ""):
            tags.add("xml")
        for p in ep.params:
            pl = p.lower()
            if pl in {"url", "uri", "redirect", "next", "callback"}:
                tags.add("ssrf_param")
            if pl in {"q", "query", "search", "id"}:
                tags.add("inject_param")

    tags_path = target_dir / "hunt" / "observe_tags.json"
    tags_path.parent.mkdir(parents=True, exist_ok=True)
    tag_list = sorted(tags)
    prev_steps = 0
    if tags_path.exists():
        try:
            prev_steps = int(json.loads(tags_path.read_text(encoding="utf-8")).get("steps") or 0)
        except Exception:  # noqa: BLE001
            prev_steps = 0
    tags_path.write_text(
        json.dumps(
            {"tags": tag_list, "steps": prev_steps, "refresh": "lite", "host": host},
            indent=2,
        ),
        encoding="utf-8",
    )
    try:
        from .sink_registry import build_sink_registry

        build_sink_registry(target_dir)
    except Exception:  # noqa: BLE001
        pass
    out = {
        "ok": True,
        "refresh": "lite",
        "host": host,
        "tags": tag_list,
        "endpoint_count": before,
    }
    ui.info(f"observe_refresh_lite: endpoints={before} tags={tag_list}")
    return out
