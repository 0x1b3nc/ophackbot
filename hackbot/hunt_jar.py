"""Persistent cookie jar for a target hunt (survives across probe acts)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

JAR_NAME = "cookie_jar.json"


def jar_path(target_dir: Path) -> Path:
    # Under secrets/ so live cookie values stay gitignored with sessions.yaml
    root = Path(target_dir) / "secrets"
    root.mkdir(parents=True, exist_ok=True)
    return root / JAR_NAME


def load_jar(target_dir: Path) -> dict[str, Any]:
    path = jar_path(target_dir)
    if not path.exists():
        return {"cookies": {}, "updated": ""}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"cookies": {}, "updated": ""}
    data.setdefault("cookies", {})
    return data


def save_jar(target_dir: Path, data: dict[str, Any]) -> Path:
    from datetime import datetime, timezone

    data = dict(data)
    data["updated"] = datetime.now(timezone.utc).isoformat()
    path = jar_path(target_dir)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def cookie_header(target_dir: Path, *, host: str = "") -> str:
    jar = load_jar(target_dir)
    cookies = jar.get("cookies") or {}
    parts = []
    for name, meta in cookies.items():
        if not isinstance(meta, dict):
            continue
        domain = str(meta.get("domain") or "")
        if host and domain and not (host.endswith(domain) or domain.endswith(host)):
            continue
        val = meta.get("value")
        if val is None:
            continue
        parts.append(f"{name}={val}")
    return "; ".join(parts)


def merge_set_cookie(target_dir: Path, set_cookie_headers: list[str], *, url: str = "") -> dict[str, Any]:
    """Parse Set-Cookie headers into the hunt jar (values stay local, gitignored via hunt/)."""
    host = urlparse(url).hostname or "" if url else ""
    jar = load_jar(target_dir)
    cookies: dict[str, Any] = dict(jar.get("cookies") or {})
    for header in set_cookie_headers:
        if not header or "=" not in header:
            continue
        first, _, rest = header.partition(";")
        name, _, value = first.partition("=")
        name, value = name.strip(), value.strip()
        if not name:
            continue
        domain = host
        m = re.search(r"(?i)domain=([^;]+)", rest)
        if m:
            domain = m.group(1).strip().lstrip(".")
        cookies[name] = {"value": value, "domain": domain, "raw_attrs": rest[:120]}
    jar["cookies"] = cookies
    save_jar(target_dir, jar)
    return jar


def clear_jar(target_dir: Path) -> None:
    path = jar_path(target_dir)
    if path.exists():
        path.unlink()
