"""Persistent AI/LLM/RAG/MCP target surface model per hunt target."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import yaml

from .fileutil import atomic_write_text, interprocess_lock

AI_SURFACES_FILE = "ai_surfaces.yaml"


@dataclass
class AiSurface:
    id: str
    chat_url: str = ""
    method: str = "POST"
    prompt_field: str = "message"
    session_field: str = "conversation_id"
    upload_urls: list[str] = field(default_factory=list)
    retrieval_urls: list[str] = field(default_factory=list)
    tool_urls: list[str] = field(default_factory=list)
    mcp_urls: list[str] = field(default_factory=list)
    auth_state: str = ""
    tenant: str = ""
    account: str = ""
    tags: list[str] = field(default_factory=list)
    notes: str = ""
    updated: str = ""

    def as_dict(self) -> dict[str, Any]:
        return asdict(self)


def ai_surfaces_path(target_dir: Path) -> Path:
    return Path(target_dir) / "hunt" / AI_SURFACES_FILE


def _lock(target_dir: Path):
    root = Path(target_dir) / "hunt"
    root.mkdir(parents=True, exist_ok=True)
    return interprocess_lock(root / ".ai_surfaces.lock", timeout=20.0)


def load_ai_surfaces(target_dir: Path) -> dict[str, Any]:
    path = ai_surfaces_path(target_dir)
    if not path.is_file():
        return {"updated": "", "surfaces": []}
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001
        return {"updated": "", "surfaces": []}
    if not isinstance(data, dict):
        return {"updated": "", "surfaces": []}
    surfaces = data.get("surfaces") or []
    if not isinstance(surfaces, list):
        surfaces = []
    return {"updated": str(data.get("updated") or ""), "surfaces": surfaces}


def list_ai_surfaces(target_dir: Path) -> list[AiSurface]:
    out: list[AiSurface] = []
    for item in load_ai_surfaces(target_dir).get("surfaces") or []:
        if not isinstance(item, dict) or not item.get("id"):
            continue
        out.append(
            AiSurface(
                id=str(item["id"]),
                chat_url=str(item.get("chat_url") or ""),
                method=str(item.get("method") or "POST"),
                prompt_field=str(item.get("prompt_field") or "message"),
                session_field=str(item.get("session_field") or "conversation_id"),
                upload_urls=list(item.get("upload_urls") or []),
                retrieval_urls=list(item.get("retrieval_urls") or []),
                tool_urls=list(item.get("tool_urls") or []),
                mcp_urls=list(item.get("mcp_urls") or []),
                auth_state=str(item.get("auth_state") or ""),
                tenant=str(item.get("tenant") or ""),
                account=str(item.get("account") or ""),
                tags=list(item.get("tags") or []),
                notes=str(item.get("notes") or ""),
                updated=str(item.get("updated") or ""),
            )
        )
    return out


def upsert_ai_surface(
    target_dir: Path,
    *,
    surface_id: str = "",
    chat_url: str = "",
    method: str = "POST",
    prompt_field: str = "message",
    session_field: str = "conversation_id",
    upload_urls: list[str] | None = None,
    retrieval_urls: list[str] | None = None,
    tool_urls: list[str] | None = None,
    mcp_urls: list[str] | None = None,
    auth_state: str = "",
    tenant: str = "",
    account: str = "",
    tags: list[str] | None = None,
    notes: str = "",
) -> dict[str, Any]:
    sid = (surface_id or "").strip() or _guess_id(chat_url or (mcp_urls or [""])[0])
    if not sid:
        return {"ok": False, "error": "surface_id or chat_url required"}
    now = datetime.now(timezone.utc).isoformat()
    with _lock(target_dir):
        data = load_ai_surfaces(target_dir)
        surfaces = [s for s in (data.get("surfaces") or []) if isinstance(s, dict)]
        by_id = {str(s.get("id")): s for s in surfaces if s.get("id")}
        prev = by_id.get(sid) or {}
        merged = AiSurface(
            id=sid,
            chat_url=chat_url or str(prev.get("chat_url") or ""),
            method=(method or str(prev.get("method") or "POST")).upper(),
            prompt_field=prompt_field or str(prev.get("prompt_field") or "message"),
            session_field=session_field or str(prev.get("session_field") or "conversation_id"),
            upload_urls=_merge_urls(prev.get("upload_urls"), upload_urls),
            retrieval_urls=_merge_urls(prev.get("retrieval_urls"), retrieval_urls),
            tool_urls=_merge_urls(prev.get("tool_urls"), tool_urls),
            mcp_urls=_merge_urls(prev.get("mcp_urls"), mcp_urls),
            auth_state=auth_state or str(prev.get("auth_state") or ""),
            tenant=tenant or str(prev.get("tenant") or ""),
            account=account or str(prev.get("account") or ""),
            tags=sorted(set(list(prev.get("tags") or []) + list(tags or []))),
            notes=notes or str(prev.get("notes") or ""),
            updated=now,
        )
        by_id[sid] = merged.as_dict()
        payload = {"updated": now, "surfaces": list(by_id.values())}
        path = ai_surfaces_path(target_dir)
        path.parent.mkdir(parents=True, exist_ok=True)
        atomic_write_text(
            path,
            yaml.safe_dump(payload, default_flow_style=False, allow_unicode=True, sort_keys=False),
        )
    return {"ok": True, "surface": merged.as_dict(), "path": str(ai_surfaces_path(target_dir))}


def get_ai_surface(target_dir: Path, surface_id: str = "") -> AiSurface | None:
    surfaces = list_ai_surfaces(target_dir)
    if surface_id:
        for s in surfaces:
            if s.id == surface_id:
                return s
        return None
    return surfaces[0] if surfaces else None


def _guess_id(url: str) -> str:
    from urllib.parse import urlparse

    if not url:
        return ""
    try:
        p = urlparse(url if "://" in url else f"https://{url}")
        host = (p.hostname or "ai").replace(".", "_")
        path = (p.path or "/chat").strip("/").replace("/", "_")[:40] or "chat"
        return f"{host}_{path}"
    except Exception:  # noqa: BLE001
        return "ai_surface"


def _merge_urls(prev: Any, extra: list[str] | None) -> list[str]:
    out: list[str] = []
    for u in list(prev or []) + list(extra or []):
        s = str(u or "").strip()
        if s and s not in out:
            out.append(s)
    return out[:40]
