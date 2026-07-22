"""Hunt coverage map — class × endpoint × param × authz status.

Artifact: ``targets/<name>/hunt/coverage.yaml``

Statuses: untested | dry | active | neg | pos
"""

from __future__ import annotations

from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

VALID_STATUS = frozenset({"untested", "dry", "active", "neg", "pos"})

# Promote order — never downgrade pos → neg accidentally unless explicit.
_RANK = {"untested": 0, "dry": 1, "active": 2, "neg": 3, "pos": 4}


def coverage_path(target_dir: Path) -> Path:
    return Path(target_dir) / "hunt" / "coverage.yaml"


def make_key(
    *,
    cls: str,
    method: str = "GET",
    path: str = "/",
    param: str = "",
    authz: str = "",
) -> str:
    return "|".join(
        [
            (cls or "unknown").strip().lower(),
            (method or "GET").strip().upper(),
            (path or "/").strip() or "/",
            (param or "").strip().lower(),
            (authz or "").strip().lower(),
        ]
    )


def key_from_url(
    *,
    cls: str,
    url: str,
    method: str = "GET",
    param: str = "",
    authz: str = "",
) -> str:
    try:
        parsed = urlparse(url)
        path = parsed.path or "/"
    except Exception:  # noqa: BLE001
        path = url or "/"
    return make_key(cls=cls, method=method, path=path, param=param, authz=authz)


def load_coverage(target_dir: Path) -> dict[str, Any]:
    path = coverage_path(target_dir)
    if not path.is_file():
        return {"updated": "", "entries": {}}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001
        return {"updated": "", "entries": {}}
    if not isinstance(data, dict):
        return {"updated": "", "entries": {}}
    entries = data.get("entries") or {}
    if not isinstance(entries, dict):
        entries = {}
    return {"updated": str(data.get("updated") or ""), "entries": entries}


def save_coverage(target_dir: Path, data: dict[str, Any]) -> Path:
    path = coverage_path(target_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    payload = {
        "updated": datetime.now(timezone.utc).isoformat(),
        "entries": data.get("entries") or {},
    }
    path.write_text(
        yaml.safe_dump(payload, sort_keys=True, allow_unicode=True),
        encoding="utf-8",
    )
    return path


def mark_coverage(
    target_dir: Path,
    *,
    cls: str,
    method: str = "GET",
    path: str = "/",
    param: str = "",
    authz: str = "",
    status: str = "dry",
    note: str = "",
    force_status: bool = False,
) -> dict[str, Any]:
    """Upsert one coverage cell. By default only upgrades status rank."""
    status = (status or "untested").strip().lower()
    if status not in VALID_STATUS:
        status = "untested"
    key = make_key(cls=cls, method=method, path=path, param=param, authz=authz)
    data = load_coverage(target_dir)
    entries: dict[str, Any] = dict(data.get("entries") or {})
    prev = entries.get(key) or {}
    prev_status = str(prev.get("status") or "untested")
    if force_status or _RANK.get(status, 0) >= _RANK.get(prev_status, 0):
        entries[key] = {
            "status": status,
            "class": (cls or "").strip().lower(),
            "method": (method or "GET").strip().upper(),
            "path": path or "/",
            "param": param or "",
            "authz": authz or "",
            "note": (note or prev.get("note") or "")[:200],
            "updated": datetime.now(timezone.utc).isoformat(),
        }
    data["entries"] = entries
    out = save_coverage(target_dir, data)
    return {"ok": True, "key": key, "entry": entries[key], "path": str(out)}


def mark_coverage_url(
    target_dir: Path,
    *,
    cls: str,
    url: str,
    method: str = "GET",
    param: str = "",
    authz: str = "",
    status: str = "dry",
    note: str = "",
) -> dict[str, Any]:
    try:
        parsed = urlparse(url)
        path = parsed.path or "/"
    except Exception:  # noqa: BLE001
        path = "/"
    return mark_coverage(
        target_dir,
        cls=cls,
        method=method,
        path=path,
        param=param,
        authz=authz,
        status=status,
        note=note,
    )


def coverage_summary(target_dir: Path) -> dict[str, Any]:
    data = load_coverage(target_dir)
    entries = data.get("entries") or {}
    counts = {s: 0 for s in VALID_STATUS}
    by_class: dict[str, dict[str, int]] = {}
    for ent in entries.values():
        if not isinstance(ent, dict):
            continue
        st = str(ent.get("status") or "untested")
        if st not in counts:
            st = "untested"
        counts[st] += 1
        cls = str(ent.get("class") or "unknown")
        by_class.setdefault(cls, {s: 0 for s in VALID_STATUS})
        by_class[cls][st] = by_class[cls].get(st, 0) + 1
    total = sum(counts.values())
    tested = counts["dry"] + counts["active"] + counts["neg"] + counts["pos"]
    pct = round(100.0 * tested / total, 1) if total else 0.0
    return {
        "ok": True,
        "updated": data.get("updated") or "",
        "total": total,
        "counts": counts,
        "coverage_pct": pct,
        "by_class": by_class,
        "path": str(coverage_path(target_dir)),
    }


def untested_priorities(
    target_dir: Path,
    *,
    prefer_classes: tuple[str, ...] = (
        "idor",
        "authz",
        "bfla",
        "business-logic",
        "ssrf",
        "llm",
        "rag",
        "mcp",
        "prompt-injection",
        "agentic",
    ),
    limit: int = 12,
) -> list[dict[str, Any]]:
    """Return cells still untested/dry, preferring authz/business-logic classes."""
    data = load_coverage(target_dir)
    rows: list[tuple[int, dict[str, Any]]] = []
    for key, ent in (data.get("entries") or {}).items():
        if not isinstance(ent, dict):
            continue
        st = str(ent.get("status") or "untested")
        if st not in {"untested", "dry"}:
            continue
        cls = str(ent.get("class") or "")
        prio = 0
        for i, pref in enumerate(prefer_classes):
            if pref in cls:
                prio = 100 - i
                break
        if st == "untested":
            prio += 5
        rows.append((prio, {"key": key, **ent}))
    rows.sort(key=lambda x: (-x[0], x[1].get("path") or ""))
    return [r[1] for r in rows[:limit]]
