"""Cursor model catalog, aliases, effort/fast → ModelSelection.

``/model`` used to accept any free-text string. For the Cursor wire we normalize
aliases (incl. Grok 4.5), build real ``ModelSelection`` params, and optionally
cross-check against ``Cursor.models.list()`` when the SDK bridge works.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from typing import Any

from .providers import normalize_effort


@dataclass(frozen=True)
class CatalogEntry:
    id: str
    display_name: str
    aliases: tuple[str, ...] = ()
    effort_param: str | None = "thinking"  # or "effort" when catalog says so
    supports_fast: bool = True
    effort_values: tuple[str, ...] = ("low", "medium", "high")


# First-party pool + common SDK ids (docs: Auto, Composer 2.5, Grok 4.5).
_CURATED: tuple[CatalogEntry, ...] = (
    CatalogEntry(
        id="auto",
        display_name="Auto",
        aliases=("auto",),
        effort_param=None,
        supports_fast=False,
    ),
    CatalogEntry(
        id="composer-2.5",
        display_name="Composer 2.5",
        aliases=("composer-2.5", "composer2.5", "composer", "composer-2"),
        effort_param="thinking",
        supports_fast=True,
    ),
    CatalogEntry(
        id="grok-4.5",
        display_name="Grok 4.5",
        aliases=(
            "grok-4.5",
            "grok4.5",
            "grok",
            "cursor-grok-4.5",
            "cursor-grok-4.5-high",
            "cursor-grok-4.5-high-fast",
            "cursor-grok-4.5-fast",
        ),
        effort_param="thinking",
        supports_fast=True,
    ),
)


@dataclass
class ResolvedCursorModel:
    entry: CatalogEntry
    effort: str | None  # low|medium|high or None
    fast: bool
    source: str  # curated | live
    label: str = ""

    @property
    def id(self) -> str:
        """Alias for entry.id — matches cursor_sdk.ModelSelection shape."""
        return self.entry.id

    def fingerprint(self) -> str:
        return f"{self.entry.id}|{self.effort or '-'}|fast={int(self.fast)}"

    def display(self) -> str:
        parts = [self.entry.id]
        if self.effort:
            parts.append(self.effort)
        if self.entry.supports_fast:
            parts.append("fast" if self.fast else "standard")
        return " · ".join(parts)


_LAST_RESOLVED: str | None = None
_LAST_LIVE_IDS: list[str] | None = None


def last_resolved_label() -> str | None:
    return _LAST_RESOLVED


def set_last_resolved_label(label: str | None) -> None:
    global _LAST_RESOLVED
    _LAST_RESOLVED = label


def parse_effort_fast(raw: str) -> tuple[str | None, bool | None]:
    """Parse ``high``, ``high fast``, ``medium-fast``, ``fast high``, ``high nofast``.

    Returns (effort_level|None, fast|None). ``fast is None`` means leave unchanged.
    """
    text = (raw or "").strip().lower()
    if not text:
        return None, None
    tokens = [t for t in re.split(r"[\s\-+,_/]+", text) if t]
    fast: bool | None = None
    if "nofast" in tokens or "standard" in tokens or "normal" in tokens:
        fast = False
        tokens = [t for t in tokens if t not in {"nofast", "standard", "normal"}]
    if "fast" in tokens:
        fast = True
        tokens = [t for t in tokens if t != "fast"]
    effort = None
    if tokens:
        effort = normalize_effort(tokens[0])
        if effort == "auto":
            effort = "auto"
    return effort, fast


def _norm_alias(name: str) -> str:
    return re.sub(r"[^a-z0-9.]+", "-", (name or "").strip().lower()).strip("-")


def _curated_by_alias(raw: str) -> CatalogEntry | None:
    key = _norm_alias(raw)
    # Strip trailing effort/fast suffixes from Task-style slugs
    for suffix in ("-high-fast", "-medium-fast", "-low-fast", "-high", "-medium", "-low", "-fast"):
        if key.endswith(suffix) and key not in {"composer-2.5", "grok-4.5"}:
            # only strip when it looks like cursor-grok-4.5-high-fast
            base = key[: -len(suffix)]
            if base:
                key = base
                break
    for entry in _CURATED:
        aliases = {_norm_alias(a) for a in entry.aliases} | {_norm_alias(entry.id)}
        if key in aliases:
            return entry
    return None


def fetch_live_catalog(*, api_key: str | None = None) -> list[Any] | None:
    """Best-effort ``Cursor.models.list()``. Returns None if SDK/bridge fails."""
    global _LAST_LIVE_IDS
    try:
        from cursor_sdk import Cursor

        from .cursor_bridge_win import apply_windows_bridge_patch

        apply_windows_bridge_patch()
    except ImportError:
        return None
    try:
        models = Cursor.models.list(api_key=api_key)
    except Exception:
        return None
    if not models:
        return None
    _LAST_LIVE_IDS = [getattr(m, "id", "") for m in models if getattr(m, "id", None)]
    return list(models)


def list_model_suggestions(*, api_key: str | None = None) -> list[tuple[str, str]]:
    """Return [(id, note), ...] for ``/models``."""
    live = fetch_live_catalog(api_key=api_key)
    out: list[tuple[str, str]] = []
    seen: set[str] = set()
    if live:
        for m in live:
            mid = getattr(m, "id", "") or ""
            if not mid or mid in seen:
                continue
            seen.add(mid)
            name = getattr(m, "display_name", "") or mid
            params = getattr(m, "parameters", ()) or ()
            pids = [getattr(p, "id", "") for p in params]
            note = name
            if pids:
                note += f"  params={','.join(pids)}"
            out.append((mid, note))
    for entry in _CURATED:
        if entry.id in seen:
            continue
        note = f"{entry.display_name} (curated)"
        if entry.supports_fast:
            note += "  +fast"
        if entry.effort_param:
            note += f"  +{entry.effort_param}"
        out.append((entry.id, note))
    return out


def _effort_for_cursor(effort: str | None) -> str | None:
    if not effort or effort == "auto":
        return None
    if effort == "minimal":
        return "low"
    if effort == "xhigh":
        return "high"
    if effort in {"low", "medium", "high"}:
        return effort
    return None


def _fast_from_env() -> bool:
    raw = (os.environ.get("HACKBOT_CURSOR_FAST") or "").strip().lower()
    if raw in {"1", "true", "yes", "on"}:
        return True
    if raw in {"0", "false", "no", "off"}:
        return False
    # Explicit default: standard (not silent fast billing)
    return False


def resolve_cursor_model(
    raw_model: str | None,
    *,
    effort: str | None = None,
    fast: bool | None = None,
    api_key: str | None = None,
    require_known: bool = True,
) -> ResolvedCursorModel:
    """Normalize model id + effort/fast for Cursor SDK."""
    raw = (raw_model or os.environ.get("HACKBOT_MODEL") or "composer-2.5").strip()
    # "grok 4.5" / "Grok 4.5" → normalized via alias map
    entry = _curated_by_alias(raw.replace(" ", "-") if " " in raw else raw)
    if entry is None:
        entry = _curated_by_alias(raw)
    source = "curated"
    live = fetch_live_catalog(api_key=api_key)
    if live:
        live_ids = {getattr(m, "id", "") for m in live}
        if entry and entry.id in live_ids:
            source = "live"
        elif not entry:
            # Accept exact live id
            key = raw
            match = next((m for m in live if getattr(m, "id", None) == key), None)
            if match is None:
                # case-insensitive
                match = next(
                    (
                        m
                        for m in live
                        if _norm_alias(getattr(m, "id", "")) == _norm_alias(key)
                    ),
                    None,
                )
            if match is not None:
                mid = getattr(match, "id")
                params = getattr(match, "parameters", ()) or ()
                pids = {getattr(p, "id", "") for p in params}
                effort_param = (
                    "thinking"
                    if "thinking" in pids
                    else ("effort" if "effort" in pids else None)
                )
                entry = CatalogEntry(
                    id=mid,
                    display_name=getattr(match, "display_name", mid) or mid,
                    aliases=(mid,),
                    effort_param=effort_param,
                    supports_fast="fast" in pids,
                )
                source = "live"

    if entry is None:
        if require_known:
            known = ", ".join(e.id for e in _CURATED)
            raise ValueError(
                f"unknown Cursor model {raw!r}. "
                f"Use /models. Known: {known} (plus live catalog when available)."
            )
        entry = CatalogEntry(
            id=raw,
            display_name=raw,
            aliases=(raw,),
            effort_param="thinking",
            supports_fast=True,
        )
        source = "passthrough"

    eff = _effort_for_cursor(effort if effort is not None else os.environ.get("HACKBOT_EFFORT"))
    if fast is None:
        fast = _fast_from_env()
    resolved = ResolvedCursorModel(
        entry=entry,
        effort=eff,
        fast=bool(fast) if entry.supports_fast else False,
        source=source,
    )
    resolved.label = resolved.display()
    return resolved


def build_model_selection(resolved: ResolvedCursorModel) -> Any:
    """Build cursor_sdk.ModelSelection (or ResolvedCursorModel if SDK missing)."""
    try:
        from cursor_sdk import ModelParameterValue, ModelSelection
    except ImportError:
        # Keep effort/fast in the object so format_selection_label / tests work
        # without cursor-sdk installed.
        return resolved

    params: list[Any] = []
    if resolved.effort and resolved.entry.effort_param:
        params.append(
            ModelParameterValue(id=resolved.entry.effort_param, value=resolved.effort)
        )
    if resolved.entry.supports_fast:
        params.append(
            ModelParameterValue(
                id="fast", value="true" if resolved.fast else "false"
            )
        )
    return ModelSelection(id=resolved.entry.id, params=tuple(params))


def format_selection_label(selection: Any) -> str:
    """Human label from ModelSelection / result.model / our ResolvedCursorModel."""
    if isinstance(selection, ResolvedCursorModel):
        return selection.display()
    if selection is None:
        return "?"
    mid = getattr(selection, "id", None) or (
        selection.get("id") if isinstance(selection, dict) else None
    )
    if not mid:
        return str(selection)
    params = getattr(selection, "params", None) or (
        selection.get("params") if isinstance(selection, dict) else ()
    )
    bits = [str(mid)]
    for p in params or ():
        pid = getattr(p, "id", None) or (p.get("id") if isinstance(p, dict) else None)
        pval = getattr(p, "value", None) or (p.get("value") if isinstance(p, dict) else None)
        if pid == "fast":
            bits.append("fast" if str(pval).lower() == "true" else "standard")
        elif pid and pval:
            bits.append(f"{pid}={pval}")
    return " · ".join(bits)
