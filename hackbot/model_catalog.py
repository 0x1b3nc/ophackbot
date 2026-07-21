"""Strict model catalogs per provider — ``/model`` only accepts real ids.

Curated allowlists ship in-repo. When a key/server is available we also merge a
live ``/models`` (or Ollama ``/api/tags``, Anthropic ``/v1/models``) listing so
new account models work without a kit release. Live results are TTL-cached
(memory + optional disk under ``.hackbot/model_cache/``). Unknown ids rejected.
"""

from __future__ import annotations

import json
import os
import re
import time
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .providers import PROVIDERS, _first_env

ROOT = Path(__file__).resolve().parents[1]
_CACHE_DIR = ROOT / ".hackbot" / "model_cache"

# provider -> (monotonic_ts, ids|None, source_note)
_LIVE_MEM: dict[str, tuple[float, list[str] | None, str]] = {}


def _norm(raw: str) -> str:
    text = (raw or "").strip().lower().replace(" ", "-")
    return re.sub(r"[^a-z0-9./:_+-]+", "-", text).strip("-")


def _cache_ttl() -> float:
    try:
        return max(0.0, float(os.environ.get("HACKBOT_MODEL_CACHE_TTL", "300") or "300"))
    except ValueError:
        return 300.0


@dataclass(frozen=True)
class ModelInfo:
    id: str
    aliases: tuple[str, ...] = ()
    note: str = ""


def _m(mid: str, *aliases: str, note: str = "") -> ModelInfo:
    return ModelInfo(id=mid, aliases=tuple(aliases), note=note)


# Curated real model ids (plus common aliases). Live fetch may add more.
_CURATED: dict[str, tuple[ModelInfo, ...]] = {
    "openai": (
        _m("gpt-4o", "4o"),
        _m("gpt-4o-mini", "4o-mini"),
        _m("gpt-4.1", "4.1"),
        _m("gpt-4.1-mini", "4.1-mini"),
        _m("gpt-4.1-nano"),
        _m("o3", "o3"),
        _m("o3-mini"),
        _m("o4-mini", "o4"),
        _m("gpt-5", "gpt5"),
        _m("gpt-5-mini"),
        _m("gpt-5.1"),
        _m("gpt-5.2"),
        _m("gpt-5.4"),
        _m("gpt-5.5", "gpt5.5"),
        _m("gpt-5.5-codex"),
        _m("gpt-5-codex"),
        _m("gpt-5.6-sol", "sol"),
        _m("gpt-5.6-terra", "terra"),
        _m("gpt-5.6-luna", "luna"),
    ),
    "anthropic": (
        _m("claude-sonnet-4-20250514", "sonnet-4", "claude-sonnet-4", "sonnet"),
        _m("claude-opus-4-20250514", "opus-4", "claude-opus-4", "opus"),
        _m("claude-3-7-sonnet-latest", "sonnet-3.7", "claude-3-7-sonnet"),
        _m("claude-3-5-haiku-latest", "haiku", "claude-3-5-haiku"),
        _m("claude-opus-4-8", "opus-4.8", "claude-opus-4.8"),
        _m("claude-sonnet-4-6", "sonnet-4.6", "claude-sonnet-4.6"),
        _m("claude-opus-4-6", "opus-4.6", "claude-opus-4.6"),
        _m("claude-opus-4-7", "opus-4.7"),
        _m("claude-haiku-4-5", "haiku-4.5"),
        _m("claude-sonnet-5", "sonnet-5"),
        _m("claude-fable-5", "fable-5", "fable"),
    ),
    "codex": (
        _m("gpt-5.5", "gpt5.5"),
        _m("gpt-5.5-codex"),
        _m("gpt-5-codex"),
        _m("gpt-5.3-codex"),
        _m("o4-mini", "o4"),
        _m("o3"),
        _m("default", "plan", "auto", note="Codex plan default"),
    ),
    "deepseek": (
        _m("deepseek-chat", "chat", "v3"),
        _m("deepseek-reasoner", "reasoner", "r1"),
    ),
    "glm": (
        _m("glm-4.6", "4.6"),
        _m("glm-4.5", "4.5"),
        _m("glm-4.5-air", "4.5-air"),
        _m("glm-5", "5"),
        _m("glm-5.2", "5.2"),
    ),
    "openrouter": (
        _m("openai/gpt-4o-mini"),
        _m("openai/gpt-4o"),
        _m("anthropic/claude-sonnet-4"),
        _m("anthropic/claude-opus-4"),
        _m("deepseek/deepseek-chat"),
        _m("deepseek/deepseek-r1"),
        _m("z-ai/glm-4.6"),
        _m("google/gemini-2.5-pro"),
        _m("google/gemini-2.5-flash"),
        _m("meta-llama/llama-3.1-70b-instruct"),
        _m("moonshotai/kimi-k2.5"),
    ),
    "ollama": (
        _m("llama3.1", "llama3", "llama"),
        _m("llama3.2"),
        _m("qwen2.5", "qwen"),
        _m("mistral"),
        _m("deepseek-r1", "r1"),
        _m("codellama"),
        _m("phi3"),
        _m("gemma2"),
    ),
    "lmstudio": (),  # live list from local server only
    "custom": (),  # live list from HACKBOT_BASE_URL only
}


def _http_json(url: str, *, headers: dict[str, str] | None = None, timeout: float = 8.0) -> Any:
    req = urllib.request.Request(url, headers=headers or {}, method="GET")
    with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
        return json.loads(resp.read().decode("utf-8", errors="replace"))


def clear_model_cache(provider: str | None = None) -> None:
    """Drop in-memory (+ disk) live model cache. ``None`` clears all providers."""
    if provider is None:
        _LIVE_MEM.clear()
        if _CACHE_DIR.is_dir():
            for path in _CACHE_DIR.glob("*.json"):
                try:
                    path.unlink()
                except OSError:
                    pass
        return
    _LIVE_MEM.pop(provider, None)
    path = _CACHE_DIR / f"{provider}.json"
    if path.is_file():
        try:
            path.unlink()
        except OSError:
            pass


def _read_disk_cache(provider: str) -> list[str] | None:
    path = _CACHE_DIR / f"{provider}.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    ids = data.get("ids") if isinstance(data, dict) else None
    if not isinstance(ids, list):
        return None
    out = [str(x) for x in ids if x]
    return out or None


def _write_disk_cache(provider: str, ids: list[str]) -> None:
    try:
        _CACHE_DIR.mkdir(parents=True, exist_ok=True)
        path = _CACHE_DIR / f"{provider}.json"
        path.write_text(
            json.dumps({"provider": provider, "ids": ids, "ts": time.time()}, indent=2),
            encoding="utf-8",
        )
    except OSError:
        pass


def _fetch_openai_wire_models(provider: str, p: Any) -> list[str] | None:
    base = (os.environ.get("HACKBOT_BASE_URL") or p.base_url or "").rstrip("/")
    if not base:
        return None
    key = _first_env(p.key_envs) or p.dummy_key
    headers = {"Authorization": f"Bearer {key}"}
    if provider == "openrouter":
        headers["HTTP-Referer"] = "https://github.com/hackbot-kit"
        headers["X-Title"] = "hackbot"
    try:
        data = _http_json(f"{base}/models", headers=headers, timeout=10.0)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError, ValueError):
        return None
    items = data.get("data") if isinstance(data, dict) else None
    if not isinstance(items, list):
        return None
    ids = [str(it.get("id")) for it in items if isinstance(it, dict) and it.get("id")]
    return ids or None


def _fetch_anthropic_models() -> list[str] | None:
    key = _first_env(("ANTHROPIC_API_KEY",))
    if not key:
        return None
    headers = {
        "x-api-key": key,
        "anthropic-version": "2023-06-01",
    }
    out: list[str] = []
    after: str | None = None
    for _ in range(20):  # hard cap pages
        url = "https://api.anthropic.com/v1/models?limit=100"
        if after:
            url += f"&after_id={urllib.parse.quote(str(after))}"
        try:
            data = _http_json(url, headers=headers, timeout=10.0)
        except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError, ValueError):
            return out or None
        items = data.get("data") if isinstance(data, dict) else None
        if not isinstance(items, list):
            break
        for it in items:
            if isinstance(it, dict) and it.get("id"):
                mid = str(it["id"])
                out.append(mid)
                # display_name aliases help /model fuzzy matching later via live list only
        if not data.get("has_more"):
            break
        after = data.get("last_id") or (items[-1].get("id") if items else None)
        if not after:
            break
    return out or None


def _fetch_ollama_models(p: Any) -> list[str] | None:
    base = (os.environ.get("HACKBOT_BASE_URL") or p.base_url or "").rstrip("/")
    root = re.sub(r"/v1/?$", "", base) or "http://localhost:11434"
    try:
        data = _http_json(f"{root}/api/tags", timeout=3.0)
    except (urllib.error.URLError, TimeoutError, json.JSONDecodeError, OSError):
        return None
    models = data.get("models") or []
    out: list[str] = []
    for item in models:
        name = item.get("name") if isinstance(item, dict) else None
        if name:
            out.append(str(name))
            if ":" in name:
                out.append(name.split(":", 1)[0])
    return out or None


def _fetch_live_uncached(provider: str) -> list[str] | None:
    p = PROVIDERS.get(provider)
    if p is None:
        return None

    if provider == "cursor":
        try:
            from .cursor_models import fetch_live_catalog

            live = fetch_live_catalog(api_key=_first_env(("CURSOR_API_KEY",)))
            if not live:
                return None
            return [getattr(m, "id", "") for m in live if getattr(m, "id", None)]
        except Exception:
            return None

    if provider == "ollama":
        return _fetch_ollama_models(p)

    if p.wire == "openai":
        return _fetch_openai_wire_models(provider, p)

    if p.wire == "anthropic" or provider == "anthropic":
        return _fetch_anthropic_models()

    return None


def fetch_live_models(provider: str, *, force_refresh: bool = False) -> list[str] | None:
    """Return live model ids for the provider, or None if unavailable.

    Uses in-memory TTL cache; on network miss falls back to disk cache when present.
    """
    now = time.monotonic()
    ttl = _cache_ttl()
    if not force_refresh and provider in _LIVE_MEM:
        ts, ids, _note = _LIVE_MEM[provider]
        if ttl <= 0 or (now - ts) < ttl:
            return ids

    live = _fetch_live_uncached(provider)
    if live:
        _LIVE_MEM[provider] = (now, live, "live")
        _write_disk_cache(provider, live)
        return live

    disk = _read_disk_cache(provider)
    if disk:
        _LIVE_MEM[provider] = (now, disk, "disk-cache")
        return disk

    _LIVE_MEM[provider] = (now, None, "unavailable")
    return None


def live_models_status(provider: str) -> str:
    """Short note for ``/models`` UI about live/cache state."""
    if provider not in _LIVE_MEM:
        return "not fetched yet"
    _ts, ids, note = _LIVE_MEM[provider]
    if ids is None:
        return f"{note} (curated only — is the API/server up?)"
    return f"{note} ({len(ids)} ids)"


def _alias_map(provider: str) -> dict[str, str]:
    """alias_norm -> canonical id (curated)."""
    out: dict[str, str] = {}
    for info in _CURATED.get(provider, ()):
        out[_norm(info.id)] = info.id
        for a in info.aliases:
            out[_norm(a)] = info.id
    return out


def known_models(provider: str, *, include_live: bool = True) -> list[tuple[str, str]]:
    """Return [(id, note), ...] for ``/models``."""
    if provider == "cursor":
        from .cursor_models import list_model_suggestions

        return list_model_suggestions(api_key=_first_env(("CURSOR_API_KEY",)))

    seen: dict[str, str] = {}
    for info in _CURATED.get(provider, ()):
        note = info.note or "curated"
        seen[info.id] = note
    if include_live:
        live = fetch_live_models(provider)
        status = live_models_status(provider)
        if live:
            tag = "live" if "disk" not in status else "cached"
            for mid in live:
                seen.setdefault(mid, tag)
    # Sort: curated first (stable order), then live extras alpha
    curated_ids = [i.id for i in _CURATED.get(provider, ())]
    ordered: list[tuple[str, str]] = []
    for mid in curated_ids:
        if mid in seen:
            ordered.append((mid, seen.pop(mid)))
    for mid in sorted(seen.keys()):
        ordered.append((mid, seen[mid]))
    return ordered


def resolve_model(provider: str, raw: str) -> tuple[str, str]:
    """Resolve ``raw`` to a canonical model id.

    Returns ``(canonical_id, source)`` where source is curated|live|alias.
    Raises ``ValueError`` if unknown.
    """
    if provider == "cursor":
        from .cursor_models import resolve_cursor_model

        resolved = resolve_cursor_model(raw, require_known=True)
        return resolved.entry.id, resolved.source

    if provider == "offline":
        raise ValueError("offline brain has no models — /provider <name> first")

    text = (raw or "").strip()
    key = _norm(text)
    # Codex plan default (empty -m)
    if provider == "codex" and key in {"", "default", "plan", "auto"}:
        return "", "curated"
    if not text:
        raise ValueError("empty model id")

    aliases = _alias_map(provider)

    if key in aliases:
        canon = aliases[key]
        if provider == "codex" and canon in {"default", ""}:
            return "", "curated"
        return canon, "curated"

    # Exact curated id (case variants)
    for info in _CURATED.get(provider, ()):
        if _norm(info.id) == key:
            return info.id, "curated"

    live = fetch_live_models(provider)
    if live:
        live_norm = {_norm(x): x for x in live}
        if key in live_norm:
            return live_norm[key], "live"
        for lid in live:
            if _norm(lid) == key or lid.lower() == text.lower():
                return lid, "live"

    known = known_models(provider, include_live=bool(live))
    sample = ", ".join(mid for mid, _ in known[:12]) or "(none — is the server up?)"
    more = f" (+{len(known) - 12} more)" if len(known) > 12 else ""
    hint = ""
    if provider in {"ollama", "lmstudio", "custom", "openrouter"} and not live:
        hint = " Live list empty — start the server / check HACKBOT_BASE_URL + key, then /models refresh."
    elif provider == "anthropic" and not live:
        hint = " Live Anthropic /v1/models failed — curated list only until the key works; try /models refresh."
    raise ValueError(
        f"unknown model {raw!r} for provider {provider!r}. "
        f"Use /models. Known: {sample}{more}.{hint}"
    )


def assert_model_allowed(provider: str, model: str) -> str:
    """Validate env model before a turn; return canonical id (may be '')."""
    if provider in {"offline", ""}:
        return model
    if provider == "codex" and not (model or "").strip():
        return ""
    canonical, _src = resolve_model(provider, model)
    return canonical
