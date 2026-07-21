"""Hunt telemetry + pause/resume helpers (Wave 11 UX)."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .hunt_memory import HuntMemory


def telemetry_path(target_dir: Path) -> Path:
    return Path(target_dir) / "hunt" / "telemetry.jsonl"


def record_telemetry(target_dir: Path, row: dict[str, Any]) -> None:
    path = telemetry_path(target_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    row = dict(row)
    row.setdefault("ts", datetime.now(timezone.utc).isoformat())
    with path.open("a", encoding="utf-8") as fh:
        fh.write(json.dumps(row) + "\n")


def telemetry_stats(target_dir: Path) -> dict[str, Any]:
    path = telemetry_path(target_dir)
    if not path.exists():
        return {"ok": True, "events": 0, "modules": {}}
    modules: dict[str, int] = {}
    signals = 0
    events = 0
    for line in path.read_text(encoding="utf-8", errors="replace").splitlines():
        if not line.strip():
            continue
        events += 1
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        mod = str(row.get("module") or "unknown")
        modules[mod] = modules.get(mod, 0) + 1
        if row.get("signal"):
            signals += 1
    return {"ok": True, "events": events, "signals": signals, "modules": modules}


def pause_flag(target_dir: Path) -> Path:
    return Path(target_dir) / "hunt" / "PAUSED"


def request_pause(target_dir: Path) -> None:
    path = pause_flag(target_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text("paused\n", encoding="utf-8")


def clear_pause(target_dir: Path) -> None:
    path = pause_flag(target_dir)
    if path.exists():
        path.unlink()


def is_paused(target_dir: Path) -> bool:
    return pause_flag(target_dir).exists()


def rich_hunt_status(target_dir: Path) -> dict[str, Any]:
    memory = HuntMemory(target_dir)
    base = memory.status_summary()
    return {
        **base,
        "paused": is_paused(target_dir),
        "telemetry": telemetry_stats(target_dir),
        "observe_tags": _tags(target_dir),
    }


def _tags(target_dir: Path) -> list[str]:
    path = Path(target_dir) / "hunt" / "observe_tags.json"
    if not path.exists():
        return []
    try:
        return list(json.loads(path.read_text(encoding="utf-8")).get("tags") or [])
    except Exception:  # noqa: BLE001
        return []


def prehunt_checklist(target_dir: Path) -> dict[str, Any]:
    from .accounts import has_accounts
    from .identity import load_identity
    from .policy_guard import ScopePolicy

    target_dir = Path(target_dir)
    checks = {
        "scope": (target_dir / "SCOPE.md").exists(),
        "sessions": len(load_identity(target_dir).ready_sessions()) >= 1,
        "accounts": has_accounts(target_dir),
        "oob": bool((__import__("os").environ.get("HACKBOT_OOB_BASE") or "").strip()),
        "har": any(target_dir.glob("**/*.har")),
    }
    try:
        ScopePolicy.load(target_dir)
        checks["scope_parseable"] = True
    except Exception:  # noqa: BLE001
        checks["scope_parseable"] = False
    ready = checks["scope"] and checks["scope_parseable"]
    return {"ok": ready, "checks": checks, "hint": "Need SCOPE.md; sessions or accounts.yaml for authz hunt"}
