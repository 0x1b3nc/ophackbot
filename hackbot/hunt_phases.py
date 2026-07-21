"""Hunt phase budgets: recon → authz → inject, with pivot on clean bans."""

from __future__ import annotations

import os
from typing import Any

PHASE_ORDER = ("recon", "authz", "inject")

PHASE_MODULES: dict[str, frozenset[str]] = {
    "recon": frozenset(
        {
            "secrets",
            "discover_paths",
            "analyze_headers",
            "mine_params",
            "crt_subdomains",
            "wayback_urls",
            "analyze_js",
            "map_surface",
            "observe_v2",
        }
    ),
    "authz": frozenset(
        {
            "idor",
            "session_bootstrap",
            "browser_diff",
            "auth-bypass",
            "oauth",
            "jwt_active",
            "mass_assignment",
        }
    ),
    "inject": frozenset(
        {
            "ssrf",
            "sqli",
            "xss",
            "lfi",
            "ssti",
            "xxe",
            "cors",
            "open_redirect",
            "graphql",
            "race",
            "websocket",
            "brute",
            "second_order_xss",
            "oob_poll",
            "rate-limit",
        }
    ),
}

# When a module is banned after clean failures, prefer these pivots next.
PIVOT_MAP: dict[str, tuple[str, ...]] = {
    "xxe": ("ssrf", "lfi", "graphql"),
    "ssrf": ("xss", "open_redirect", "xxe"),
    "sqli": ("ssti", "xss", "idor"),
    "xss": ("second_order_xss", "cors", "sqli"),
    "idor": ("browser_diff", "mass_assignment", "auth-bypass"),
    "lfi": ("ssti", "ssrf", "path"),
    "ssti": ("sqli", "xss"),
    "cors": ("oauth", "open_redirect"),
    "graphql": ("idor", "mass_assignment"),
    "secrets": ("discover_paths", "analyze_js"),
    "discover_paths": ("mine_params", "analyze_headers"),
}


def phase_for_module(module: str) -> str:
    mod = (module or "").strip().lower()
    for phase, mods in PHASE_MODULES.items():
        if mod in mods:
            return phase
    return "inject"


def allocate_phase_budgets(total: int) -> dict[str, int]:
    """Split remaining act budget across recon/authz/inject.

    Override with ``HACKBOT_HUNT_PHASE_BUDGETS=recon:30,authz:35,inject:35``
    (percentages) or ``recon:8,authz:10,inject:10`` (absolute if sum≈total).
    """
    total = max(0, int(total))
    raw = (os.environ.get("HACKBOT_HUNT_PHASE_BUDGETS") or "").strip()
    if raw:
        parts: dict[str, int] = {}
        for chunk in raw.split(","):
            if ":" not in chunk:
                continue
            k, v = chunk.split(":", 1)
            try:
                parts[k.strip().lower()] = int(v.strip())
            except ValueError:
                continue
        if parts:
            values = [parts.get(p, 0) for p in PHASE_ORDER]
            s = sum(values) or 1
            # Percent-style if sum is ~100
            if 80 <= s <= 120 and total > 0:
                out = {p: max(1, int(total * parts.get(p, 0) / 100)) for p in PHASE_ORDER}
            else:
                out = {p: max(0, parts.get(p, 0)) for p in PHASE_ORDER}
            # Normalize to total
            diff = total - sum(out.values())
            out["inject"] = max(0, out.get("inject", 0) + diff)
            return out
    # Default: 30% recon / 35% authz / 35% inject (min 1 when total allows)
    if total <= 0:
        return {p: 0 for p in PHASE_ORDER}
    if total < 3:
        return {"recon": total, "authz": 0, "inject": 0}
    r = max(1, int(total * 0.30))
    a = max(1, int(total * 0.35))
    i = max(0, total - r - a)
    return {"recon": r, "authz": a, "inject": i}


def prefer_phase(queue: list[Any], phase: str) -> list[Any]:
    """Stable-partition: current phase first, then later phases, then earlier."""
    if not queue:
        return queue
    try:
        idx = PHASE_ORDER.index(phase)
    except ValueError:
        idx = 0
    order = list(PHASE_ORDER[idx:]) + list(PHASE_ORDER[:idx])

    def key(h: Any) -> tuple[int, int]:
        mod = getattr(h, "module", None) or (h.get("module") if isinstance(h, dict) else "")
        p = phase_for_module(str(mod))
        try:
            pi = order.index(p)
        except ValueError:
            pi = len(order)
        pri = -int(getattr(h, "priority", 0) or 0)
        return (pi, pri)

    return sorted(queue, key=key)


def advance_phase(current: str) -> str | None:
    try:
        i = PHASE_ORDER.index(current)
    except ValueError:
        return "authz"
    if i + 1 < len(PHASE_ORDER):
        return PHASE_ORDER[i + 1]
    return None


def pivot_modules(banned_module: str) -> tuple[str, ...]:
    return PIVOT_MAP.get((banned_module or "").lower(), ())
