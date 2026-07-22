"""OpenAPI / Swagger (JSON+YAML) → HuntMemory endpoints with rich metadata."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urljoin

from .api_rank import endpoint_risk_score, seed_api_coverage
from .hunt_memory import Endpoint, HuntMemory

_METHODS = frozenset({"get", "post", "put", "patch", "delete", "head", "options"})
_SENS_PATH = re.compile(
    r"(user|account|org|team|project|order|invite|billing|admin|tenant|member)",
    re.I,
)


def _load_spec(text: str) -> dict[str, Any] | None:
    text = (text or "").strip()
    if not text:
        return None
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass
    try:
        import yaml

        data = yaml.safe_load(text)
        if isinstance(data, dict):
            return data
    except Exception:  # noqa: BLE001
        return None
    return None


def _resolve_ref(spec: dict[str, Any], node: Any, *, depth: int = 0) -> Any:
    if depth > 6 or not isinstance(node, dict):
        return node
    ref = node.get("$ref")
    if not isinstance(ref, str) or not ref.startswith("#/"):
        return node
    cur: Any = spec
    for part in ref[2:].split("/"):
        if not isinstance(cur, dict):
            return node
        cur = cur.get(part)
    if isinstance(cur, dict):
        return _resolve_ref(spec, cur, depth=depth + 1)
    return cur if cur is not None else node


def _base_from_spec(spec: dict[str, Any], base_url: str = "") -> str:
    if base_url:
        return base_url.rstrip("/")
    servers = spec.get("servers") or []
    if isinstance(servers, list) and servers:
        url0 = servers[0].get("url") if isinstance(servers[0], dict) else ""
        if url0:
            return str(url0).rstrip("/")
    # Swagger 2.0
    host = str(spec.get("host") or "").strip()
    if host:
        schemes = spec.get("schemes") or ["https"]
        scheme = str(schemes[0] if schemes else "https")
        base_path = str(spec.get("basePath") or "").rstrip("/")
        return f"{scheme}://{host}{base_path}"
    return ""


def _example_from_schema(schema: dict[str, Any]) -> Any:
    if not isinstance(schema, dict):
        return None
    if "example" in schema:
        return schema["example"]
    if "default" in schema:
        return schema["default"]
    enums = schema.get("enum")
    if isinstance(enums, list) and enums:
        return enums[0]
    examples = schema.get("examples")
    if isinstance(examples, dict) and examples:
        first = next(iter(examples.values()))
        if isinstance(first, dict) and "value" in first:
            return first["value"]
        return first
    if schema.get("type") == "object":
        props = schema.get("properties") or {}
        if isinstance(props, dict):
            out: dict[str, Any] = {}
            for k, v in list(props.items())[:12]:
                if isinstance(v, dict):
                    ex = _example_from_schema(v)
                    out[k] = ex if ex is not None else f"hb_{k}"
            return out or None
    if schema.get("type") == "array":
        items = schema.get("items") if isinstance(schema.get("items"), dict) else {}
        ex = _example_from_schema(items) if items else "hb_item"
        return [ex]
    t = schema.get("type")
    if t == "string":
        return "hb_canary"
    if t == "integer":
        return 1
    if t == "boolean":
        return False
    return None


def _param_names(spec: dict[str, Any], path_item: dict[str, Any], op: dict[str, Any]) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for block in (path_item.get("parameters") or [], op.get("parameters") or []):
        if not isinstance(block, list):
            continue
        for p in block:
            p = _resolve_ref(spec, p) if isinstance(p, dict) else p
            if not isinstance(p, dict) or not p.get("name"):
                continue
            name = str(p["name"])
            if name in seen:
                continue
            seen.add(name)
            names.append(name)
            # examples / defaults / enums as soft hints in notes only — keep params as names
            schema = p.get("schema") if isinstance(p.get("schema"), dict) else {}
            if not schema and p.get("type"):
                schema = {"type": p.get("type"), "enum": p.get("enum"), "default": p.get("default")}
    return names[:40]


def _body_template(spec: dict[str, Any], op: dict[str, Any]) -> str:
    # OAS3 requestBody
    rb = op.get("requestBody")
    rb = _resolve_ref(spec, rb) if isinstance(rb, dict) else rb
    if isinstance(rb, dict):
        content = rb.get("content") or {}
        if isinstance(content, dict):
            for ctype in ("application/json", "application/x-www-form-urlencoded", "multipart/form-data"):
                media = content.get(ctype)
                if not isinstance(media, dict):
                    continue
                if "example" in media:
                    try:
                        return json.dumps(media["example"], ensure_ascii=False)[:2000]
                    except (TypeError, ValueError):
                        pass
                examples = media.get("examples")
                if isinstance(examples, dict) and examples:
                    first = next(iter(examples.values()))
                    val = first.get("value") if isinstance(first, dict) else first
                    try:
                        return json.dumps(val, ensure_ascii=False)[:2000]
                    except (TypeError, ValueError):
                        pass
                schema = _resolve_ref(spec, media.get("schema") or {})
                if isinstance(schema, dict):
                    ex = _example_from_schema(schema)
                    if ex is not None:
                        try:
                            return json.dumps(ex, ensure_ascii=False)[:2000]
                        except (TypeError, ValueError):
                            pass
    # Swagger 2 body param
    for p in op.get("parameters") or []:
        p = _resolve_ref(spec, p) if isinstance(p, dict) else p
        if isinstance(p, dict) and str(p.get("in") or "") == "body":
            schema = _resolve_ref(spec, p.get("schema") or {})
            if isinstance(schema, dict):
                ex = _example_from_schema(schema)
                if ex is not None:
                    try:
                        return json.dumps(ex, ensure_ascii=False)[:2000]
                    except (TypeError, ValueError):
                        pass
    return ""


def _op_auth_required(spec: dict[str, Any], op: dict[str, Any]) -> bool:
    sec = op.get("security")
    if sec is None:
        sec = spec.get("security")
    if isinstance(sec, list):
        if len(sec) == 0:
            return False
        return True
    schemes = spec.get("components", {}).get("securitySchemes") if isinstance(spec.get("components"), dict) else None
    if schemes is None:
        schemes = spec.get("securityDefinitions")
    return bool(schemes)


def _security_notes(spec: dict[str, Any], op: dict[str, Any]) -> str:
    bits: list[str] = []
    schemes = {}
    comps = spec.get("components")
    if isinstance(comps, dict) and isinstance(comps.get("securitySchemes"), dict):
        schemes = comps["securitySchemes"]
    elif isinstance(spec.get("securityDefinitions"), dict):
        schemes = spec["securityDefinitions"]
    sec = op.get("security")
    if sec is None:
        sec = spec.get("security") or []
    if not isinstance(sec, list):
        return ""
    for req in sec[:4]:
        if not isinstance(req, dict):
            continue
        for name, scopes in req.items():
            sch = schemes.get(name) if isinstance(schemes, dict) else None
            if isinstance(sch, dict):
                bits.append(
                    f"{name}:{sch.get('type') or '?'}:"
                    f"{sch.get('name') or sch.get('scheme') or ''}"
                )
            else:
                bits.append(str(name))
            if isinstance(scopes, list) and scopes:
                bits.append("scopes=" + ",".join(str(s) for s in scopes[:6]))
    return "; ".join(bits)[:300]


def parse_openapi_dict(spec: dict[str, Any], *, base_url: str = "") -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    if not isinstance(spec, dict):
        return endpoints
    base = _base_from_spec(spec, base_url)
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return endpoints
    for path, path_item in list(paths.items())[:200]:
        if not isinstance(path_item, dict):
            continue
        path_item = _resolve_ref(spec, path_item) if "$ref" in path_item else path_item
        if not isinstance(path_item, dict):
            continue
        for method, op in path_item.items():
            if method.lower() not in _METHODS or not isinstance(op, dict):
                continue
            params = _param_names(spec, path_item, op)
            body = _body_template(spec, op)
            auth_req = _op_auth_required(spec, op)
            tags = [str(t) for t in (op.get("tags") or []) if t][:8]
            if op.get("deprecated"):
                tags.append("deprecated")
            if _SENS_PATH.search(str(path)):
                tags.append("sensitive-path")
            op_id = str(op.get("operationId") or "")
            summary = str(op.get("summary") or "")
            sec_note = _security_notes(spec, op)
            notes_bits = [x for x in (op_id, summary, sec_note) if x]
            url = urljoin(base + "/", str(path).lstrip("/")) if base else str(path)
            ep = Endpoint(
                url=url,
                method=method.upper(),
                params=params,
                auth_required=auth_req,
                source="openapi",
                notes=" | ".join(notes_bits)[:400],
                body_template=body,
                tags=tags,
            )
            ep.risk_score = endpoint_risk_score(ep)
            endpoints.append(ep)
    return endpoints


def ingest_openapi_text(
    target_dir: Path,
    text: str,
    *,
    base_url: str = "",
    host: str = "",
    seed_coverage: bool = True,
) -> dict[str, Any]:
    spec = _load_spec(text)
    if not spec:
        return {"ok": False, "error": "invalid_openapi", "seeded": 0}
    eps = parse_openapi_dict(spec, base_url=base_url)
    if eps:
        HuntMemory(target_dir).upsert_endpoints(eps, host=host)
        if seed_coverage:
            seed_api_coverage(target_dir, eps)
    return {
        "ok": True,
        "seeded": len(eps),
        "sample": [
            {"method": e.method, "url": e.url, "risk": e.risk_score, "auth": e.auth_required}
            for e in sorted(eps, key=lambda x: -x.risk_score)[:8]
        ],
    }


def ingest_openapi_file(
    target_dir: Path,
    path: Path,
    *,
    base_url: str = "",
    host: str = "",
    seed_coverage: bool = True,
) -> dict[str, Any]:
    try:
        text = Path(path).read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"ok": False, "error": str(exc), "seeded": 0}
    return ingest_openapi_text(
        target_dir, text, base_url=base_url, host=host, seed_coverage=seed_coverage
    )
