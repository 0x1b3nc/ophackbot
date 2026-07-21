"""Cross-program learning: techniques, patterns, payload hints, aggregate stats."""

from __future__ import annotations

import json
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
LEARN_DIR = ROOT / "learning"
TECHNIQUES = LEARN_DIR / "techniques.jsonl"
STATS_FILE = LEARN_DIR / "stats.json"
PATTERNS_FILE = LEARN_DIR / "patterns.jsonl"


def _ensure() -> None:
    LEARN_DIR.mkdir(parents=True, exist_ok=True)
    if not TECHNIQUES.exists():
        TECHNIQUES.write_text("", encoding="utf-8")
    if not PATTERNS_FILE.exists():
        PATTERNS_FILE.write_text("", encoding="utf-8")


def record_technique(
    *,
    program: str,
    module: str,
    summary: str,
    host: str = "",
    outcome: str = "signal",
    tags: list[str] | None = None,
    param: str = "",
    payload: str = "",
    url: str = "",
    method: str = "",
    body: str = "",
) -> Path:
    """Append one successful/interesting technique for future hunts."""
    _ensure()
    row = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "program": program,
        "module": module,
        "host": host,
        "outcome": outcome,
        "summary": (summary or "")[:500],
        "tags": tags or [],
        "param": (param or "")[:80],
        "payload": (payload or "")[:300],
        "url": (url or "")[:300],
        "method": (method or "")[:16],
        "body": (body or "")[:400],
    }
    with TECHNIQUES.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    return TECHNIQUES


def list_techniques(
    *,
    module: str = "",
    program: str = "",
    limit: int = 40,
) -> list[dict[str, Any]]:
    _ensure()
    rows: list[dict[str, Any]] = []
    for line in TECHNIQUES.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if module and row.get("module") != module:
            continue
        if program and row.get("program") != program:
            continue
        rows.append(row)
    return rows[-limit:]


def _win_rate(by_outcome: dict[str, int]) -> float:
    good = sum(by_outcome.get(k, 0) for k in ("validated", "found", "confirmed", "signal"))
    total = sum(by_outcome.values()) or 1
    return round(good / total, 3)


def rebuild_stats() -> dict[str, Any]:
    """Aggregate techniques.jsonl into stats.json for richer Decide hints."""
    _ensure()
    rows = list_techniques(limit=2000)
    by_module: dict[str, int] = {}
    by_program: dict[str, int] = {}
    by_outcome: dict[str, int] = {}
    hosts: dict[str, int] = {}
    by_param: dict[str, int] = {}
    for row in rows:
        mod = str(row.get("module") or "unknown")
        by_module[mod] = by_module.get(mod, 0) + 1
        prog = str(row.get("program") or "")
        if prog:
            by_program[prog] = by_program.get(prog, 0) + 1
        out = str(row.get("outcome") or "")
        by_outcome[out] = by_outcome.get(out, 0) + 1
        host = str(row.get("host") or "")
        if host:
            hosts[host] = hosts.get(host, 0) + 1
        param = str(row.get("param") or "")
        if param:
            key = f"{mod}:{param}"
            by_param[key] = by_param.get(key, 0) + 1
    stats = {
        "ok": True,
        "updated": datetime.now(timezone.utc).isoformat(),
        "total": len(rows),
        "by_module": dict(sorted(by_module.items(), key=lambda x: -x[1])[:20]),
        "by_program": dict(sorted(by_program.items(), key=lambda x: -x[1])[:20]),
        "by_outcome": by_outcome,
        "top_hosts": dict(sorted(hosts.items(), key=lambda x: -x[1])[:20]),
        "top_params": dict(sorted(by_param.items(), key=lambda x: -x[1])[:20]),
        "win_rate_hint": _win_rate(by_outcome),
    }
    STATS_FILE.write_text(json.dumps(stats, indent=2), encoding="utf-8")
    return stats


def learn_stats() -> dict[str, Any]:
    if STATS_FILE.exists():
        try:
            return json.loads(STATS_FILE.read_text(encoding="utf-8"))
        except json.JSONDecodeError:
            pass
    return rebuild_stats()


def record_pattern(
    *,
    pattern: str,
    module: str,
    note: str = "",
    program: str = "",
) -> Path:
    _ensure()
    row = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "pattern": (pattern or "")[:200],
        "module": module,
        "note": (note or "")[:400],
        "program": program,
    }
    with PATTERNS_FILE.open("a", encoding="utf-8") as handle:
        handle.write(json.dumps(row, ensure_ascii=False) + "\n")
    return PATTERNS_FILE


def suggest_for_host(host: str, *, limit: int = 10) -> dict[str, Any]:
    """Rank modules that worked elsewhere — soft hints for Decide."""
    rows = list_techniques(limit=500)
    scores: dict[str, int] = {}
    samples: dict[str, str] = {}
    for row in rows:
        mod = str(row.get("module") or "")
        if not mod:
            continue
        boost = 3 if host and host in str(row.get("host") or "") else 1
        if row.get("outcome") in {"signal", "found", "validated", "confirmed"}:
            scores[mod] = scores.get(mod, 0) + boost
            samples.setdefault(mod, str(row.get("summary") or "")[:160])
    try:
        stats = learn_stats()
        for mod, count in (stats.get("by_module") or {}).items():
            scores[mod] = scores.get(mod, 0) + min(int(count), 5)
    except Exception:  # noqa: BLE001
        pass
    ranked = sorted(scores.items(), key=lambda x: -x[1])[:limit]
    return {
        "ok": True,
        "host": host,
        "suggestions": [
            {"module": m, "score": s, "sample": samples.get(m, "")} for m, s in ranked
        ],
        "payload_hints": suggest_payload_hints(host, limit=limit),
        "stats_total": learn_stats().get("total"),
    }


def suggest_payload_hints(host: str = "", *, limit: int = 12) -> list[dict[str, Any]]:
    """Return param/payload/body hints from past wins for Decide to seed probes."""
    rows = list_techniques(limit=800)
    best: dict[str, dict[str, Any]] = {}
    for row in rows:
        if row.get("outcome") not in {"signal", "found", "validated", "confirmed"}:
            continue
        mod = str(row.get("module") or "")
        if not mod:
            continue
        has_hint = any(row.get(k) for k in ("param", "payload", "body", "url"))
        if not has_hint:
            continue
        score = 2
        if host and host in str(row.get("host") or ""):
            score += 4
        if row.get("outcome") in {"validated", "confirmed"}:
            score += 3
        prev = best.get(mod)
        if prev and int(prev.get("score") or 0) >= score:
            continue
        best[mod] = {
            "module": mod,
            "score": score,
            "param": str(row.get("param") or ""),
            "payload": str(row.get("payload") or ""),
            "body": str(row.get("body") or ""),
            "url": str(row.get("url") or ""),
            "method": str(row.get("method") or ""),
            "sample": str(row.get("summary") or "")[:160],
        }
    ranked = sorted(best.values(), key=lambda x: -int(x.get("score") or 0))
    return ranked[:limit]


def ingest_from_hunt(target_dir: Path, *, program: str = "") -> dict[str, Any]:
    """Pull validated candidates + attempts into the learning log (with payloads)."""
    from .hunt_memory import HuntMemory

    memory = HuntMemory(target_dir)
    program = program or Path(target_dir).name
    host = str(memory.load_surface().get("host") or "")
    n = 0
    for c in memory.load_candidates():
        if c.status != "validated":
            continue
        params = dict(c.params or {})
        record_technique(
            program=program,
            module=c.module,
            summary=c.detail or c.title,
            host=host,
            outcome="validated",
            tags=["hunt_candidate"],
            param=str(params.get("param") or ""),
            payload=str(params.get("payload") or ""),
            url=c.url,
            method=str(params.get("_winning_method") or params.get("_method") or params.get("methods") or ""),
            body=str(params.get("body") or ""),
        )
        if params.get("param") or params.get("payload"):
            record_pattern(
                pattern=f"{c.module}:{params.get('param') or 'url'}",
                module=c.module,
                note=(c.detail or "")[:200],
                program=program,
            )
        n += 1
    for row in memory.recent_attempts(80):
        if row.get("outcome") in {"found", "validated"} or row.get("signal"):
            params = row.get("params") if isinstance(row.get("params"), dict) else {}
            record_technique(
                program=program,
                module=str(row.get("module") or "unknown"),
                summary=str(row.get("detail") or row.get("outcome") or ""),
                host=host,
                outcome=str(row.get("outcome") or "signal"),
                tags=["hunt_attempt"],
                param=str(params.get("param") or ""),
                payload=str(params.get("payload") or ""),
                url=str(row.get("url") or ""),
                method=str(row.get("method") or params.get("methods") or ""),
                body=str(params.get("body") or ""),
            )
            n += 1
    stats = rebuild_stats()
    return {"ok": True, "recorded": n, "path": str(TECHNIQUES), "stats": stats}
