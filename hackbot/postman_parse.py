"""Postman Collection v2.0/v2.1 JSON → HuntMemory endpoints."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from .api_rank import endpoint_risk_score, seed_api_coverage
from .hunt_memory import Endpoint, HuntMemory

_VAR_RE = re.compile(r"\{\{([^}]+)\}\}")


def _sub_vars(text: str, variables: dict[str, str]) -> str:
    def repl(m: re.Match[str]) -> str:
        key = m.group(1).strip()
        return variables.get(key, m.group(0))

    return _VAR_RE.sub(repl, text or "")


def _collect_vars(collection: dict[str, Any], env: dict[str, Any] | None = None) -> dict[str, str]:
    out: dict[str, str] = {}
    for block in (collection.get("variable") or [], (env or {}).get("values") or []):
        if not isinstance(block, list):
            continue
        for item in block:
            if not isinstance(item, dict):
                continue
            key = str(item.get("key") or item.get("name") or "").strip()
            if not key:
                continue
            val = item.get("value")
            if val is None:
                val = item.get("enabled")  # noop
            out[key] = str(val if val is not None else "")
    # Common placeholders → canaries (never invent secrets)
    out.setdefault("baseUrl", out.get("baseUrl") or out.get("url") or "https://example.com")
    out.setdefault("host", out.get("host") or "example.com")
    return out


def _url_from_request(req: dict[str, Any], variables: dict[str, str]) -> str:
    raw = req.get("url")
    if isinstance(raw, str):
        return _sub_vars(raw, variables)
    if isinstance(raw, dict):
        if raw.get("raw"):
            return _sub_vars(str(raw["raw"]), variables)
        host = raw.get("host") or []
        path = raw.get("path") or []
        protocol = str(raw.get("protocol") or "https")
        if isinstance(host, list):
            host_s = ".".join(_sub_vars(str(h), variables) for h in host)
        else:
            host_s = _sub_vars(str(host), variables)
        if isinstance(path, list):
            path_s = "/".join(_sub_vars(str(p), variables) for p in path)
        else:
            path_s = _sub_vars(str(path), variables)
        base = f"{protocol}://{host_s}"
        return urljoin(base + "/", path_s.lstrip("/"))
    return ""


def _headers_and_auth(req: dict[str, Any], variables: dict[str, str]) -> tuple[list[str], bool, str]:
    params: list[str] = []
    auth_required = False
    notes: list[str] = []
    for h in req.get("header") or []:
        if not isinstance(h, dict):
            continue
        name = str(h.get("key") or "").strip()
        if name:
            params.append(f"hdr:{name}")
            if name.lower() in {"authorization", "cookie", "x-api-key", "api-key"}:
                auth_required = True
    auth = req.get("auth") or {}
    if isinstance(auth, dict) and auth.get("type"):
        auth_required = True
        notes.append(f"auth={auth.get('type')}")
    # query params
    url = req.get("url")
    if isinstance(url, dict):
        for q in url.get("query") or []:
            if isinstance(q, dict) and q.get("key"):
                params.append(str(q["key"]))
    return params[:40], auth_required, "; ".join(notes)


def _body_template(req: dict[str, Any], variables: dict[str, str]) -> str:
    body = req.get("body")
    if not isinstance(body, dict):
        return ""
    mode = str(body.get("mode") or "")
    if mode == "raw" and body.get("raw") is not None:
        return _sub_vars(str(body["raw"]), variables)[:2000]
    if mode == "urlencoded":
        pairs = []
        for item in body.get("urlencoded") or []:
            if isinstance(item, dict) and item.get("key"):
                pairs.append(f"{item['key']}={item.get('value') or ''}")
        return _sub_vars("&".join(pairs), variables)[:2000]
    if mode == "formdata":
        keys = [str(i.get("key")) for i in (body.get("formdata") or []) if isinstance(i, dict) and i.get("key")]
        return json.dumps({"form_keys": keys[:20]}, ensure_ascii=False)
    return ""


def _walk_items(items: list[Any], variables: dict[str, str], out: list[Endpoint]) -> None:
    for item in items or []:
        if not isinstance(item, dict):
            continue
        if isinstance(item.get("item"), list):
            _walk_items(item["item"], variables, out)
            continue
        req = item.get("request")
        if not isinstance(req, dict):
            continue
        method = str(req.get("method") or "GET").upper()
        url = _url_from_request(req, variables)
        if not url:
            continue
        params, auth_req, auth_note = _headers_and_auth(req, variables)
        body = _body_template(req, variables)
        name = str(item.get("name") or "")
        notes = " | ".join(x for x in (name, auth_note) if x)
        # Saved responses / examples
        for resp in (item.get("response") or [])[:2]:
            if isinstance(resp, dict) and resp.get("name"):
                notes = (notes + f" | example:{resp.get('name')}")[:400]
        ep = Endpoint(
            url=url,
            method=method,
            params=params,
            auth_required=auth_req,
            source="postman",
            notes=notes[:400],
            body_template=body,
            tags=["postman"],
        )
        ep.risk_score = endpoint_risk_score(ep)
        out.append(ep)


def parse_postman_dict(
    collection: dict[str, Any],
    *,
    environment: dict[str, Any] | None = None,
    base_url: str = "",
) -> list[Endpoint]:
    if not isinstance(collection, dict):
        return []
    info = collection.get("info") or {}
    # Accept v2.0 / v2.1 (schema URL optional)
    variables = _collect_vars(collection, environment)
    if base_url:
        variables["baseUrl"] = base_url.rstrip("/")
        variables["url"] = base_url.rstrip("/")
    endpoints: list[Endpoint] = []
    _walk_items(list(collection.get("item") or []), variables, endpoints)
    # Cap
    if isinstance(info, dict) and info.get("name"):
        for ep in endpoints:
            if not ep.notes:
                ep.notes = str(info.get("name"))
    return endpoints[:300]


def ingest_postman_text(
    target_dir: Path,
    text: str,
    *,
    base_url: str = "",
    host: str = "",
    environment_text: str = "",
    seed_coverage: bool = True,
) -> dict[str, Any]:
    try:
        collection = json.loads(text)
    except json.JSONDecodeError:
        return {"ok": False, "error": "invalid_json", "seeded": 0}
    if not isinstance(collection, dict):
        return {"ok": False, "error": "not_object", "seeded": 0}
    env = None
    if environment_text.strip():
        try:
            env = json.loads(environment_text)
        except json.JSONDecodeError:
            env = None
    eps = parse_postman_dict(collection, environment=env if isinstance(env, dict) else None, base_url=base_url)
    if eps:
        HuntMemory(target_dir).upsert_endpoints(eps, host=host)
        if seed_coverage:
            seed_api_coverage(target_dir, eps)
    return {
        "ok": True,
        "seeded": len(eps),
        "sample": [
            {"method": e.method, "url": e.url, "risk": e.risk_score}
            for e in sorted(eps, key=lambda x: -x.risk_score)[:8]
        ],
    }


def ingest_postman_file(
    target_dir: Path,
    path: Path,
    *,
    base_url: str = "",
    host: str = "",
    environment_path: Path | None = None,
    seed_coverage: bool = True,
) -> dict[str, Any]:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"ok": False, "error": str(exc), "seeded": 0}
    env_text = ""
    if environment_path:
        try:
            env_text = Path(environment_path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            env_text = ""
    return ingest_postman_text(
        target_dir,
        text,
        base_url=base_url,
        host=host,
        environment_text=env_text,
        seed_coverage=seed_coverage,
    )
