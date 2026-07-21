"""Attack-surface mapping that feeds the autonomous hunt loop."""

from __future__ import annotations

import json
import re
import shutil
import subprocess
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from . import ui
from .hunt_memory import Endpoint, HuntMemory
from .policy_guard import host_from_target
from .runners.base import require_in_scope

_LINK_RE = re.compile(r"""(?:href|src|action)\s*=\s*["']([^"']+)["']""", re.I)
_FORM_INPUT_RE = re.compile(
    r"""<input[^>]+(?:name|id)\s*=\s*["']([^"']+)["']""",
    re.I,
)
_QUERY_HINT_RE = re.compile(r"[?&]([a-zA-Z_][\w-]{0,40})=")
_TECH_HINTS = (
    ("wordpress", re.compile(r"wp-content|wordpress", re.I)),
    ("react", re.compile(r"__NEXT_DATA__|react", re.I)),
    ("django", re.compile(r"csrfmiddlewaretoken", re.I)),
    ("rails", re.compile(r"csrf-token|x-csrf-token", re.I)),
    ("spring", re.compile(r"jsessionid|whitelabel error", re.I)),
)


def normalize_seed(host_or_url: str) -> str:
    raw = (host_or_url or "").strip()
    if not raw:
        return ""
    if "://" not in raw:
        raw = f"https://{raw}"
    parsed = urllib.parse.urlparse(raw)
    if not parsed.netloc:
        return ""
    path = parsed.path or "/"
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, path, "", parsed.query, ""))


def origin_of(url: str) -> str:
    parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
    return f"{parsed.scheme}://{parsed.netloc}"


def extract_params_from_url(url: str) -> list[str]:
    parsed = urllib.parse.urlparse(url)
    names = list(urllib.parse.parse_qs(parsed.query).keys())
    names.extend(_QUERY_HINT_RE.findall(url))
    # dedupe preserve order
    seen: set[str] = set()
    out: list[str] = []
    for n in names:
        if n not in seen:
            seen.add(n)
            out.append(n)
    return out


def _absolutize(base: str, href: str) -> str | None:
    href = href.strip()
    if not href or href.startswith(("#", "mailto:", "javascript:", "data:")):
        return None
    try:
        abs_url = urllib.parse.urljoin(base, href)
    except ValueError:
        return None
    parsed = urllib.parse.urlparse(abs_url)
    if parsed.scheme not in {"http", "https"}:
        return None
    # Drop fragments
    return urllib.parse.urlunparse((parsed.scheme, parsed.netloc, parsed.path or "/", "", parsed.query, ""))


def _fetch(
    url: str,
    *,
    target_dir: Path,
    force: bool = False,
    timeout: float = 12.0,
) -> tuple[int, str, dict[str, str]]:
    from .scoped_http import scoped_fetch_bytes

    resp = scoped_fetch_bytes(
        url,
        target_dir=target_dir,
        action="surface recon httpx",
        force=force,
        timeout=timeout,
        headers={"User-Agent": "hackbot-surface-recon"},
        max_bytes=400_000,
    )
    body = resp.body.decode("utf-8", errors="replace")
    headers = {k.lower(): v for k, v in (resp.headers.items() if resp.headers else [])}
    return resp.status, body, headers


def _tech_from_body(body: str, headers: dict[str, str]) -> list[str]:
    hints: list[str] = []
    server = headers.get("server") or ""
    if server:
        hints.append(f"server:{server[:80]}")
    powered = headers.get("x-powered-by") or ""
    if powered:
        hints.append(f"powered:{powered[:80]}")
    for name, pattern in _TECH_HINTS:
        if pattern.search(body):
            hints.append(name)
    return hints


def _endpoints_from_html(base_url: str, body: str, *, same_origin: str) -> list[Endpoint]:
    found: dict[str, Endpoint] = {}
    for href in _LINK_RE.findall(body):
        abs_url = _absolutize(base_url, href)
        if not abs_url:
            continue
        if host_from_target(abs_url) != host_from_target(same_origin):
            continue
        params = extract_params_from_url(abs_url)
        found[abs_url] = Endpoint(url=abs_url, method="GET", params=params, source="html")
    for name in _FORM_INPUT_RE.findall(body):
        # Attach common form field names to the seed page itself
        seed = found.get(base_url) or Endpoint(url=base_url, source="html")
        if name not in seed.params:
            seed.params.append(name)
        found[base_url] = seed
    return list(found.values())


def _katana_urls(seed: str, *, timeout: float = 45.0) -> list[str]:
    if not shutil.which("katana"):
        return []
    try:
        completed = subprocess.run(
            ["katana", "-u", seed, "-silent", "-d", "2", "-jc", "-timeout", "8"],
            capture_output=True,
            text=True,
            timeout=timeout,
            check=False,
        )
    except (OSError, subprocess.TimeoutExpired):
        return []
    urls: list[str] = []
    for line in (completed.stdout or "").splitlines():
        line = line.strip()
        if line.startswith("http"):
            urls.append(line.split()[0])
    return urls[:80]


def map_surface(
    target_dir: Path,
    seed: str,
    *,
    approve: bool = False,
    force: bool = False,
    use_katana: bool = True,
) -> dict[str, Any]:
    """Map attack surface from a seed URL/host into hunt/surface.yaml."""
    seed_url = normalize_seed(seed)
    if not seed_url:
        return {"ok": False, "error": "empty or invalid seed URL/host"}

    require_in_scope(target_dir, seed_url, action="surface recon httpx", force=force)
    memory = HuntMemory(target_dir)
    host = host_from_target(seed_url)
    origin = origin_of(seed_url)

    plan = {
        "seed": seed_url,
        "host": host,
        "approve": approve,
        "katana": bool(use_katana and shutil.which("katana")),
    }
    ui.code_panel(json.dumps(plan, indent=2), title="surface_map", lexer="json")

    seed_ep = Endpoint(
        url=seed_url,
        method="GET",
        params=extract_params_from_url(seed_url),
        source="seed",
    )
    # Always seed the surface even on dry-run so Decide can plan.
    memory.upsert_endpoints([seed_ep], host=host)

    if not approve:
        ui.dry_run_banner()
        return {
            "ok": True,
            "dry_run": True,
            "host": host,
            "seed": seed_url,
            "endpoints": 1,
            "message": "dry-run: wrote seed endpoint only",
        }

    endpoints: list[Endpoint] = [seed_ep]
    tech: list[str] = []
    fetched = 0
    errors = 0
    html_preview = ""
    script_srcs: list[str] = []
    body = ""

    try:
        status, body, headers = _fetch(seed_url, target_dir=target_dir, force=force)
        fetched += 1
        tech.extend(_tech_from_body(body, headers))
        html_preview = body[:4000]
        for m in re.finditer(r"""<script[^>]+src=["']([^"']+)["']""", body, re.I):
            abs_u = _absolutize(seed_url, m.group(1))
            if abs_u:
                script_srcs.append(abs_u)
        script_srcs = list(dict.fromkeys(script_srcs))[:15]
        if status in {401, 403}:
            seed_ep.auth_required = True
            seed_ep.notes = f"status={status}"
        endpoints.extend(_endpoints_from_html(seed_url, body, same_origin=origin))
        # Common API/login guesses (bounded)
        for path in ("/login", "/api", "/api/v1", "/robots.txt", "/sitemap.xml"):
            guess = origin.rstrip("/") + path
            endpoints.append(Endpoint(url=guess, source="guess"))
    except Exception as exc:  # noqa: BLE001
        errors += 1
        seed_ep.notes = f"fetch_error:{type(exc).__name__}"

    if use_katana:
        for url in _katana_urls(seed_url):
            if host_from_target(url) != host:
                continue
            endpoints.append(
                Endpoint(url=url, params=extract_params_from_url(url), source="katana")
            )

    # Dedupe + cap
    by_url: dict[str, Endpoint] = {}
    for ep in endpoints:
        prev = by_url.get(ep.url)
        if prev:
            params = sorted(set(prev.params) | set(ep.params))
            by_url[ep.url] = Endpoint(
                url=ep.url,
                method=ep.method or prev.method,
                params=params,
                auth_required=ep.auth_required or prev.auth_required,
                source=ep.source if ep.source != "guess" else prev.source,
                notes=ep.notes or prev.notes,
            )
        else:
            by_url[ep.url] = ep

    capped = list(by_url.values())[:120]
    memory.upsert_endpoints(capped, host=host)
    if tech:
        memory.add_tech_hints(tech)

    ui.success(f"surface: {len(capped)} endpoints (fetched={fetched}, errors={errors})")
    return {
        "ok": True,
        "dry_run": False,
        "host": host,
        "seed": seed_url,
        "endpoints": len(capped),
        "fetched": fetched,
        "errors": errors,
        "tech_hints": tech,
        "surface_path": str(memory.root / "surface.yaml"),
        "html_preview": html_preview,
        "script_srcs": script_srcs,
        "body_preview": html_preview[:500],
    }


def seed_candidates_from_surface(memory: HuntMemory) -> list[dict[str, Any]]:
    """Heuristic hypotheses from mapped surface (for Decide offline)."""
    ideas: list[dict[str, Any]] = []
    for ep in memory.endpoints():
        if ep.has_id_param() or re.search(r"/\d+(?:/|$)", ep.url):
            idor_params: dict[str, str] = {}
            id_like = {"id", "user_id", "userid", "uid", "account_id", "order_id", "object_id", "uuid"}
            for p in ep.params:
                if p.lower() in id_like or p.lower().endswith("_id"):
                    idor_params["param"] = p
                    idor_params["swap_value"] = "999999"
                    break
            ideas.append(
                {
                    "module": "idor",
                    "url": ep.url,
                    "title": f"IDOR probe on {ep.url}",
                    "priority": 90,
                    "params": idor_params,
                }
            )
        for param in ep.url_like_params():
            ideas.append(
                {
                    "module": "ssrf",
                    "url": ep.url,
                    "title": f"SSRF via param {param}",
                    "priority": 70,
                    "params": {"param": param},
                }
            )
        if ep.params and ep.method.upper() in {"GET", "POST"}:
            # Prefer query-ish names for injection
            inj_params = [
                p
                for p in ep.params
                if p.lower() in {"q", "query", "search", "id", "name", "filter", "sort"}
                or p.lower().endswith("id")
            ]
            if inj_params:
                ideas.append(
                    {
                        "module": "sqli",
                        "url": ep.url,
                        "title": f"SQLi probe param={inj_params[0]}",
                        "priority": 55,
                        "params": {"param": inj_params[0]},
                    }
                )
                ideas.append(
                    {
                        "module": "xss",
                        "url": ep.url,
                        "title": f"XSS reflect param={inj_params[0]}",
                        "priority": 50,
                        "params": {"param": inj_params[0]},
                    }
                )
        path = urllib.parse.urlparse(ep.url).path.lower()
        if any(x in path for x in ("/login", "/signin", "/auth", "/session")):
            ideas.append(
                {
                    "module": "auth-bypass",
                    "url": ep.url,
                    "title": f"Auth-bypass at {ep.url}",
                    "priority": 75,
                }
            )
            ideas.append(
                {
                    "module": "brute",
                    "url": ep.url,
                    "title": f"Capped brute at {ep.url}",
                    "priority": 40,
                }
            )
    return ideas
