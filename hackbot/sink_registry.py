"""Sink registry written during Observe — Decide seeds only tagged sinks."""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml

from .hunt_memory import HuntMemory


def sinks_path(target_dir: Path) -> Path:
    return Path(target_dir) / "hunt" / "sinks.yaml"


def build_sink_registry(target_dir: Path) -> dict[str, Any]:
    memory = HuntMemory(target_dir)
    sinks: dict[str, list[dict[str, Any]]] = {
        "id": [],
        "url_like": [],
        "xml": [],
        "graphql": [],
        "auth": [],
        "websocket": [],
    }
    for ep in memory.endpoints():
        row = {"url": ep.url, "method": ep.method, "params": list(ep.params), "source": ep.source}
        if ep.has_id_param() or any(ch.isdigit() for ch in ep.url):
            sinks["id"].append(row)
        for p in ep.url_like_params():
            sinks["url_like"].append({**row, "param": p})
        low = ep.url.lower() + " " + (ep.notes or "").lower()
        if "xml" in low or "soap" in low:
            sinks["xml"].append(row)
        if "graphql" in low:
            sinks["graphql"].append(row)
        if "login" in low or "oauth" in low or "auth" in low:
            sinks["auth"].append(row)
        if ep.url.startswith("ws"):
            sinks["websocket"].append(row)
    # Cap lists
    for k in sinks:
        sinks[k] = sinks[k][:40]
    data = {"ok": True, "sinks": sinks}
    path = sinks_path(target_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(yaml.safe_dump(data, sort_keys=False), encoding="utf-8")
    return data


def load_sinks(target_dir: Path) -> dict[str, list[dict[str, Any]]]:
    path = sinks_path(target_dir)
    if not path.exists():
        return {}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return dict(data.get("sinks") or {})
    except Exception:  # noqa: BLE001
        return {}


def has_sink(target_dir: Path, kind: str) -> bool:
    sinks = load_sinks(target_dir)
    return bool(sinks.get(kind))
