"""Strict model catalogs per provider — ``/model`` only accepts real ids.

Curated allowlists ship in-repo. When a key/server is available we also merge a
live ``/models`` (or Ollama ``/api/tags``) listing so new account models work
without a kit release. Unknown ids are rejected.
"""

from __future__ import annotations

import json
import os
import re
import urllib.error
import urllib.request
from dataclasses import dataclass
from typing import Any

from .providers import PROVIDERS, _first_env


def _norm(raw: str) -> str:
    text = (raw or "").strip().lower().replace(" ", "-")
    return re.sub(r"[^a-z0-9./:_+-]+", "-", text).strip("-")


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
        _m("claude-sonnet-4-6", "sonnet-4.6"),
        _m("claude-opus-4-7", "opus-4.7"),
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


def fetch_live_models(provider: str) -> list[str] | None:
    """Return live model ids for the provider, or None if unavailable."""
    p = PROVIDERS.get(provider)
    if p is None:
        return None

    if provider == "cursor":
        try:
            from .cursor_models import fetch_live_catalog
            from .providers import _first_env as fe

            live = fetch_live_catalog(api_key=fe(("CURSOR_API_KEY",)))
            if not live:
                return None
            return [getattr(m, "id", "") for m in live if getattr(m, "id", None)]
        except Exception:
            return None

    if provider == "ollama":
        base = (os.environ.get("HACKBOT_BASE_URL") or p.base_url or "").rstrip("/")
        # HACKBOT_BASE_URL may be …/v1 — tags is on root
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
                # also bare tag without :latest
                if ":" in name:
                    out.append(name.split(":", 1)[0])
        return out or None

    if p.wire not in {"openai", "anthropic"}:
        return None

    # OpenAI-compatible GET /models (OpenAI, DeepSeek, GLM, OpenRouter, LM Studio, custom)
    if p.wire == "openai":
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

    # Anthropic has no simple public models list on the Messages API — curated only.
    return None


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
        if live:
            for mid in live:
                seen.setdefault(mid, "live")
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
        # OpenRouter / Ollama often need exact match including org prefix
        for lid in live:
            if _norm(lid) == key or lid.lower() == text.lower():
                return lid, "live"

    known = known_models(provider, include_live=bool(live))
    sample = ", ".join(mid for mid, _ in known[:12]) or "(none — is the server up?)"
    more = f" (+{len(known) - 12} more)" if len(known) > 12 else ""
    raise ValueError(
        f"unknown model {raw!r} for provider {provider!r}. "
        f"Use /models. Known: {sample}{more}"
    )


def assert_model_allowed(provider: str, model: str) -> str:
    """Validate env model before a turn; return canonical id (may be '')."""
    if provider in {"offline", ""}:
        return model
    if provider == "codex" and not (model or "").strip():
        return ""
    canonical, _src = resolve_model(provider, model)
    return canonical
