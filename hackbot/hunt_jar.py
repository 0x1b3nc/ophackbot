"""Persistent cookie jar for a target hunt — namespaced by session when set.

Shared (legacy) cookies live under the empty session key ``""``. IDOR A/B
should prefer ``use_jar=False`` or pass distinct session keys so cookies do
not cross-contaminate.
"""

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
        return {"cookies": {}, "sessions": {}, "updated": ""}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except json.JSONDecodeError:
        return {"cookies": {}, "sessions": {}, "updated": ""}
    data.setdefault("cookies", {})
    data.setdefault("sessions", {})
    # Migrate flat legacy cookies into sessions[""]
    if data["cookies"] and "" not in data["sessions"]:
        data["sessions"][""] = dict(data["cookies"])
    return data


def save_jar(target_dir: Path, data: dict[str, Any]) -> Path:
    from datetime import datetime, timezone

    data = dict(data)
    data["updated"] = datetime.now(timezone.utc).isoformat()
    # Keep legacy flat mirror of shared bucket for older readers
    sessions = data.get("sessions") or {}
    data["cookies"] = dict(sessions.get("") or {})
    path = jar_path(target_dir)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
    return path


def _domain_matches(host: str, domain: str) -> bool:
    """Conservative cookie domain match (no bare-TLD endswith)."""
    host = (host or "").lower().lstrip(".")
    domain = (domain or "").lower().lstrip(".")
    if not host or not domain:
        return True
    if host == domain:
        return True
    # Require a dot boundary: foo.example.com matches example.com
    return host.endswith("." + domain)


def cookie_header(target_dir: Path, *, host: str = "", session: str = "") -> str:
    jar = load_jar(target_dir)
    sessions = jar.get("sessions") or {}
    # Prefer session bucket; fall back to shared only when session empty
    if session:
        cookies = dict(sessions.get(session) or {})
    else:
        cookies = dict(sessions.get("") or jar.get("cookies") or {})
    parts = []
    for name, meta in cookies.items():
        if not isinstance(meta, dict):
            continue
        domain = str(meta.get("domain") or "")
        if host and domain and not _domain_matches(host, domain):
            continue
        val = meta.get("value")
        if val is None:
            continue
        parts.append(f"{name}={val}")
    return "; ".join(parts)


def merge_set_cookie(
    target_dir: Path,
    set_cookie_headers: list[str],
    *,
    url: str = "",
    session: str = "",
) -> dict[str, Any]:
    """Parse Set-Cookie headers into the hunt jar (session-namespaced)."""
    host = urlparse(url).hostname or "" if url else ""
    jar = load_jar(target_dir)
    sessions: dict[str, Any] = dict(jar.get("sessions") or {})
    key = session or ""
    cookies: dict[str, Any] = dict(sessions.get(key) or {})
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
    sessions[key] = cookies
    jar["sessions"] = sessions
    save_jar(target_dir, jar)
    return jar


def clear_jar(target_dir: Path) -> None:
    path = jar_path(target_dir)
    if path.exists():
        path.unlink()
