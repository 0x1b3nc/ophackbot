"""Persistent hunt memory per target: surface, attempts, candidates."""

from __future__ import annotations

import json
from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

HUNT_DIR = "hunt"
SURFACE_FILE = "surface.yaml"
ATTEMPTS_FILE = "attempts.jsonl"
CANDIDATES_FILE = "candidates.yaml"
STATE_FILE = "state.yaml"


@dataclass
class Endpoint:
    url: str
    method: str = "GET"
    params: list[str] = field(default_factory=list)
    auth_required: bool = False
    source: str = "seed"
    notes: str = ""

    def has_id_param(self) -> bool:
        id_like = {"id", "user_id", "userid", "uid", "account_id", "order_id", "object_id", "uuid"}
        return any(p.lower() in id_like or p.lower().endswith("_id") for p in self.params)

    def url_like_params(self) -> list[str]:
        urlish = {"url", "uri", "link", "redirect", "next", "callback", "webhook", "target", "dest", "destination"}
        return [p for p in self.params if p.lower() in urlish or "url" in p.lower()]


@dataclass
class Candidate:
    id: str
    module: str
    title: str
    url: str
    status: str = "pending"  # pending | validated | rejected | needs_setup
    evidence: str = ""
    detail: str = ""
    params: dict[str, str] = field(default_factory=dict)


@dataclass
class HuntState:
    phase: str = "idle"
    prompt: str = ""
    host: str = ""
    budget_remaining: int = 0
    budget_total: int = 0
    acts_done: int = 0
    failures: int = 0
    stopped: bool = False
    stop_reason: str = ""
    last_summary: str = ""


def hunt_dir(target_dir: Path) -> Path:
    path = Path(target_dir) / HUNT_DIR
    path.mkdir(parents=True, exist_ok=True)
    return path


class HuntMemory:
    """Read/write hunt artifacts under targets/<name>/hunt/."""

    def __init__(self, target_dir: Path) -> None:
        self.target_dir = Path(target_dir)
        self.root = hunt_dir(self.target_dir)

    # --- surface ---

    def load_surface(self) -> dict[str, Any]:
        path = self.root / SURFACE_FILE
        if not path.exists():
            return {"host": "", "endpoints": [], "tech_hints": [], "updated": ""}
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        data.setdefault("endpoints", [])
        data.setdefault("tech_hints", [])
        data.setdefault("host", "")
        return data

    def save_surface(self, data: dict[str, Any]) -> Path:
        data = dict(data)
        data["updated"] = datetime.now(timezone.utc).isoformat()
        path = self.root / SURFACE_FILE
        path.write_text(
            yaml.safe_dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
        return path

    def endpoints(self) -> list[Endpoint]:
        raw = self.load_surface().get("endpoints") or []
        out: list[Endpoint] = []
        for item in raw:
            if not isinstance(item, dict) or not item.get("url"):
                continue
            out.append(
                Endpoint(
                    url=str(item["url"]),
                    method=str(item.get("method") or "GET"),
                    params=list(item.get("params") or []),
                    auth_required=bool(item.get("auth_required")),
                    source=str(item.get("source") or "unknown"),
                    notes=str(item.get("notes") or ""),
                )
            )
        return out

    def upsert_endpoints(self, endpoints: list[Endpoint], *, host: str = "") -> Path:
        data = self.load_surface()
        if host:
            data["host"] = host
        by_url = {e.url: e for e in self.endpoints()}
        for ep in endpoints:
            prev = by_url.get(ep.url)
            if prev:
                merged_params = sorted(set(prev.params) | set(ep.params))
                by_url[ep.url] = Endpoint(
                    url=ep.url,
                    method=ep.method or prev.method,
                    params=merged_params,
                    auth_required=ep.auth_required or prev.auth_required,
                    source=ep.source or prev.source,
                    notes=ep.notes or prev.notes,
                )
            else:
                by_url[ep.url] = ep
        data["endpoints"] = [asdict(e) for e in by_url.values()]
        return self.save_surface(data)

    def add_tech_hints(self, hints: list[str]) -> Path:
        data = self.load_surface()
        existing = list(data.get("tech_hints") or [])
        for h in hints:
            if h and h not in existing:
                existing.append(h)
        data["tech_hints"] = existing
        return self.save_surface(data)

    # --- attempts ---

    def append_attempt(self, record: dict[str, Any]) -> Path:
        path = self.root / ATTEMPTS_FILE
        row = dict(record)
        row.setdefault("ts", datetime.now(timezone.utc).isoformat())
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, ensure_ascii=False) + "\n")
        return path

    def recent_attempts(self, limit: int = 20) -> list[dict[str, Any]]:
        path = self.root / ATTEMPTS_FILE
        if not path.exists():
            return []
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        out: list[dict[str, Any]] = []
        for line in lines[-limit:]:
            line = line.strip()
            if not line:
                continue
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
        return out

    # --- candidates ---

    def load_candidates(self) -> list[Candidate]:
        path = self.root / CANDIDATES_FILE
        if not path.exists():
            return []
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        items = data.get("candidates") or []
        out: list[Candidate] = []
        for item in items:
            if not isinstance(item, dict) or not item.get("id"):
                continue
            out.append(
                Candidate(
                    id=str(item["id"]),
                    module=str(item.get("module") or ""),
                    title=str(item.get("title") or ""),
                    url=str(item.get("url") or ""),
                    status=str(item.get("status") or "pending"),
                    evidence=str(item.get("evidence") or ""),
                    detail=str(item.get("detail") or ""),
                    params=dict(item.get("params") or {}),
                )
            )
        return out

    def save_candidates(self, candidates: list[Candidate]) -> Path:
        path = self.root / CANDIDATES_FILE
        payload = {"candidates": [asdict(c) for c in candidates]}
        path.write_text(
            yaml.safe_dump(payload, default_flow_style=False, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
        return path

    def upsert_candidate(self, candidate: Candidate) -> Path:
        items = self.load_candidates()
        by_id = {c.id: c for c in items}
        by_id[candidate.id] = candidate
        return self.save_candidates(list(by_id.values()))

    def next_candidate_id(self, prefix: str = "H") -> str:
        ids = []
        for c in self.load_candidates():
            if c.id.startswith(f"{prefix}-"):
                try:
                    ids.append(int(c.id.split("-", 1)[1]))
                except ValueError:
                    pass
        n = max(ids) + 1 if ids else 1
        return f"{prefix}-{n:03d}"

    # --- state ---

    def load_state(self) -> HuntState:
        path = self.root / STATE_FILE
        if not path.exists():
            return HuntState()
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        return HuntState(
            phase=str(data.get("phase") or "idle"),
            prompt=str(data.get("prompt") or ""),
            host=str(data.get("host") or ""),
            budget_remaining=int(data.get("budget_remaining") or 0),
            budget_total=int(data.get("budget_total") or 0),
            acts_done=int(data.get("acts_done") or 0),
            failures=int(data.get("failures") or 0),
            stopped=bool(data.get("stopped")),
            stop_reason=str(data.get("stop_reason") or ""),
            last_summary=str(data.get("last_summary") or ""),
        )

    def save_state(self, state: HuntState) -> Path:
        path = self.root / STATE_FILE
        path.write_text(
            yaml.safe_dump(asdict(state), default_flow_style=False, allow_unicode=True, sort_keys=False),
            encoding="utf-8",
        )
        return path

    def status_summary(self) -> dict[str, Any]:
        state = self.load_state()
        surface = self.load_surface()
        candidates = self.load_candidates()
        pending = [c for c in candidates if c.status == "pending"]
        validated = [c for c in candidates if c.status == "validated"]
        return {
            "phase": state.phase,
            "host": state.host or surface.get("host") or "",
            "budget_remaining": state.budget_remaining,
            "budget_total": state.budget_total,
            "acts_done": state.acts_done,
            "failures": state.failures,
            "stopped": state.stopped,
            "stop_reason": state.stop_reason,
            "endpoints": len(surface.get("endpoints") or []),
            "candidates_pending": len(pending),
            "candidates_validated": len(validated),
            "last_summary": state.last_summary,
        }
