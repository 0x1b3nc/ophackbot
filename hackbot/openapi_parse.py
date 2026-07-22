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


class _RefResolver:
    """Resolve local (#/…) and relative file refs (./schemas.yaml#/components/…)."""

    def __init__(self, root: dict[str, Any], *, base_dir: Path | None = None) -> None:
        self.root = root
        self.base_dir = Path(base_dir) if base_dir else None
        self._file_cache: dict[str, dict[str, Any]] = {}

    def resolve(self, node: Any, *, depth: int = 0) -> Any:
        if depth > 24:
            return node
        if isinstance(node, list):
            return [self.resolve(x, depth=depth + 1) for x in node[:80]]
        if not isinstance(node, dict):
            return node
        # allOf merge (shallow useful fields)
        if "allOf" in node and isinstance(node["allOf"], list):
            merged: dict[str, Any] = {k: v for k, v in node.items() if k != "allOf"}
            props: dict[str, Any] = {}
            for part in node["allOf"][:12]:
                resolved = self.resolve(part, depth=depth + 1)
                if isinstance(resolved, dict):
                    for k, v in resolved.items():
                        if k == "properties" and isinstance(v, dict):
                            props.update(v)
                        elif k not in merged:
                            merged[k] = v
            if props:
                merged_props = dict(merged.get("properties") or {})
                merged_props.update(props)
                merged["properties"] = merged_props
            node = merged
        ref = node.get("$ref")
        if not isinstance(ref, str) or not ref:
            # Recurse into common containers
            out = dict(node)
            for key in ("schema", "items", "properties", "content", "parameters", "requestBody"):
                if key in out:
                    out[key] = self.resolve(out[key], depth=depth + 1)
            return out
        target = self._load_ref(ref)
        if target is None:
            return node
        if isinstance(target, dict):
            # Keep sibling extensions occasionally present beside $ref
            siblings = {k: v for k, v in node.items() if k != "$ref"}
            resolved = self.resolve(target, depth=depth + 1)
            if siblings and isinstance(resolved, dict):
                return {**resolved, **siblings}
            return resolved
        return target

    def _load_ref(self, ref: str) -> Any:
        if ref.startswith("#/"):
            return self._pointer(self.root, ref[1:])
        # file ref: path#/pointer or path only
        file_part, _, ptr = ref.partition("#")
        file_part = file_part.strip()
        if not file_part or not self.base_dir:
            return None
        path = (self.base_dir / file_part).resolve()
        try:
            path.relative_to(self.base_dir.resolve())
        except ValueError:
            # allow sibling dirs one level up within same parent
            try:
                path.relative_to(self.base_dir.resolve().parent)
            except ValueError:
                return None
        key = str(path)
        if key not in self._file_cache:
            try:
                text = path.read_text(encoding="utf-8", errors="replace")
            except OSError:
                return None
            loaded = _load_spec(text)
            if not loaded:
                return None
            self._file_cache[key] = loaded
        doc = self._file_cache[key]
        if ptr:
            return self._pointer(doc, ptr if ptr.startswith("/") else "/" + ptr)
        return doc

    @staticmethod
    def _pointer(doc: dict[str, Any], pointer: str) -> Any:
        cur: Any = doc
        for part in pointer.strip("/").split("/"):
            part = part.replace("~1", "/").replace("~0", "~")
            if not isinstance(cur, dict):
                return None
            cur = cur.get(part)
        return cur


def _resolve_ref(
    spec: dict[str, Any],
    node: Any,
    *,
    depth: int = 0,
    base_dir: Path | None = None,
    resolver: _RefResolver | None = None,
) -> Any:
    res = resolver or _RefResolver(spec, base_dir=base_dir)
    return res.resolve(node, depth=depth)


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


def _param_names(
    spec: dict[str, Any],
    path_item: dict[str, Any],
    op: dict[str, Any],
    *,
    resolver: _RefResolver,
) -> list[str]:
    names: list[str] = []
    seen: set[str] = set()
    for block in (path_item.get("parameters") or [], op.get("parameters") or []):
        if not isinstance(block, list):
            continue
        for p in block:
            p = resolver.resolve(p) if isinstance(p, dict) else p
            if not isinstance(p, dict) or not p.get("name"):
                continue
            name = str(p["name"])
            if name in seen:
                continue
            seen.add(name)
            names.append(name)
    return names[:40]


def _body_template(
    spec: dict[str, Any],
    op: dict[str, Any],
    *,
    resolver: _RefResolver,
) -> str:
    # OAS3 requestBody
    rb = op.get("requestBody")
    rb = resolver.resolve(rb) if isinstance(rb, dict) else rb
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
                schema = resolver.resolve(media.get("schema") or {})
                if isinstance(schema, dict):
                    ex = _example_from_schema(schema)
                    if ex is not None:
                        try:
                            return json.dumps(ex, ensure_ascii=False)[:2000]
                        except (TypeError, ValueError):
                            pass
    # Swagger 2 body param
    for p in op.get("parameters") or []:
        p = resolver.resolve(p) if isinstance(p, dict) else p
        if isinstance(p, dict) and str(p.get("in") or "") == "body":
            schema = resolver.resolve(p.get("schema") or {})
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


def parse_openapi_dict(
    spec: dict[str, Any],
    *,
    base_url: str = "",
    base_dir: Path | None = None,
) -> list[Endpoint]:
    endpoints: list[Endpoint] = []
    if not isinstance(spec, dict):
        return endpoints
    resolver = _RefResolver(spec, base_dir=base_dir)
    base = _base_from_spec(spec, base_url)
    paths = spec.get("paths") or {}
    if not isinstance(paths, dict):
        return endpoints
    for path, path_item in list(paths.items())[:200]:
        if not isinstance(path_item, dict):
            continue
        path_item = resolver.resolve(path_item) if "$ref" in path_item else path_item
        if not isinstance(path_item, dict):
            continue
        for method, op in path_item.items():
            if method.lower() not in _METHODS or not isinstance(op, dict):
                continue
            params = _param_names(spec, path_item, op, resolver=resolver)
            body = _body_template(spec, op, resolver=resolver)
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
    base_dir: Path | None = None,
) -> dict[str, Any]:
    spec = _load_spec(text)
    if not spec:
        return {"ok": False, "error": "invalid_openapi", "seeded": 0}
    eps = parse_openapi_dict(spec, base_url=base_url, base_dir=base_dir)
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
        "base_dir": str(base_dir) if base_dir else "",
    }


def ingest_openapi_file(
    target_dir: Path,
    path: Path,
    *,
    base_url: str = "",
    host: str = "",
    seed_coverage: bool = True,
) -> dict[str, Any]:
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8", errors="replace")
    except OSError as exc:
        return {"ok": False, "error": str(exc), "seeded": 0}
    return ingest_openapi_text(
        target_dir,
        text,
        base_url=base_url,
        host=host,
        seed_coverage=seed_coverage,
        base_dir=path.parent,
    )
