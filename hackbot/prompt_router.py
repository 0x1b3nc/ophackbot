"""Prompt routing: offline confidence + optional LLM interpret (PT-BR / EN).

When the rule brain is unsure and a model provider is configured, ask the model
for a tiny JSON plan, then execute via the same tools/rails (SCOPE, approve, force).
"""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass, field
from typing import Any

from . import ui
from .campaign import (
    MODULES,
    detect_campaign_modules,
    has_attack_intent,
    normalize_text,
    resolve_modules,
    score_module,
)
from .force import is_forced, prompt_wants_force
from .session import get_active

VALID_MODULES = frozenset(m.id for m in MODULES)

ROUTER_SYSTEM = """You are Hackbot's prompt router for authorized bug-bounty work only.
The user writes in Brazilian Portuguese or English (or a mix).
Reply with ONLY one JSON object (no markdown fences), schema:
{
  "language": "pt-BR" or "en",
  "intent": "campaign" | "playbook" | "run_tool" | "scope" | "knowledge" | "chat" | "other",
  "modules": ["recon"|"secrets"|"auth-bypass"|"brute"|"dos"|"idor"|"ssrf", ...],
  "host": "hostname or empty",
  "target_dir": "targets/<name> or empty",
  "endpoint": "full URL or empty",
  "tool": "httpx|katana|nuclei|ffuf|rate_probe|secrets_scan|brute_login or empty",
  "approve": false,
  "force": false,
  "summary_pt": "one short sentence of what you understood",
  "summary_en": "one short sentence of what you understood"
}
Rules:
- Prefer campaign when they want multiple attacks / explore / break / test broadly.
- modules empty → use ["recon","secrets","auth-bypass"] for vague hunt intents.
- Never invent out-of-scope hosts; leave host empty if unclear.
- approve true only if they clearly asked to send real traffic / approve.
- force true only if they assume responsibility / force / eu assumo.
"""


@dataclass
class RouteDecision:
    language: str = "en"
    intent: str = "other"
    modules: list[str] = field(default_factory=list)
    host: str | None = None
    target_dir: str | None = None
    endpoint: str | None = None
    tool: str | None = None
    approve: bool = False
    force: bool = False
    summary_pt: str = ""
    summary_en: str = ""
    source: str = "offline"  # offline | llm | offline+llm
    confidence: float = 0.0
    used_default_pack: bool = False

    def summary_for_ui(self) -> str:
        if self.language.lower().startswith("pt") and self.summary_pt:
            return self.summary_pt
        return self.summary_en or self.summary_pt or "(no summary)"


def auto_route_enabled() -> bool:
    raw = os.environ.get("HACKBOT_AUTO_ROUTE", "1").strip().lower()
    return raw not in {"0", "false", "off", "no"}


def model_usable_for_route() -> bool:
    """True when an HTTP model provider is configured (not offline/codex-only)."""
    if os.environ.get("HACKBOT_LOCAL", "").strip().lower() in {"1", "true", "yes"}:
        return False
    if os.environ.get("HACKBOT_PROVIDER", "").strip().lower() in {"offline", "local"}:
        return False
    try:
        from .providers import resolve_config

        cfg = resolve_config()
    except Exception:
        return False
    if cfg.wire == "codex":
        # Codex is fine for chat but routing JSON is simpler via HTTP wires.
        # Still allow if user forced HACKBOT_ROUTE_CODEX=1 later; default skip.
        return os.environ.get("HACKBOT_ROUTE_CODEX", "").strip() in {"1", "true", "yes"}
    return True


def offline_confidence(prompt: str, *, host: str | None, intents: list[str], classes: list[str]) -> float:
    """0..1 how sure the rule brain is about what to do."""
    norm = normalize_text(prompt)
    score = 0.15
    if host:
        score += 0.25
    mods = detect_campaign_modules(prompt)
    if mods:
        best = max(score_module(norm, m) for m in mods)
        score += min(0.35, 0.08 * best)
    elif has_attack_intent(prompt):
        score += 0.12  # intent clear, classes vague
    if intents and intents != ["list"]:
        score += 0.15
    if classes and classes != ["recon"]:
        score += 0.1
    if "campaign" in intents or "playbook_run" in intents or "run" in intents:
        score += 0.1
    # Penalize very short / ambiguous prompts
    if len(norm.split()) < 4 and not host:
        score -= 0.2
    return max(0.0, min(1.0, score))


def _extract_json(text: str) -> dict[str, Any] | None:
    text = text.strip()
    if text.startswith("```"):
        text = re.sub(r"^```(?:json)?\s*", "", text)
        text = re.sub(r"\s*```$", "", text)
    try:
        obj = json.loads(text)
        return obj if isinstance(obj, dict) else None
    except json.JSONDecodeError:
        m = re.search(r"\{[\s\S]*\}", text)
        if not m:
            return None
        try:
            obj = json.loads(m.group(0))
            return obj if isinstance(obj, dict) else None
        except json.JSONDecodeError:
            return None


def llm_interpret(prompt: str) -> RouteDecision | None:
    """Ask the configured model for a routing JSON. Returns None on failure."""
    from .llm import LLMError, chat

    try:
        resp = chat(
            system=ROUTER_SYSTEM,
            messages=[{"role": "user", "content": prompt}],
            tools=[],
            effort="minimal",
        )
    except LLMError as exc:
        ui.warn(f"route LLM unavailable: {exc}")
        return None
    except Exception as exc:  # noqa: BLE001
        ui.warn(f"route LLM error: {type(exc).__name__}: {exc}")
        return None

    obj = _extract_json(resp.text or "")
    if not obj:
        ui.warn("route LLM returned non-JSON; keeping offline plan")
        return None

    modules = [str(x) for x in (obj.get("modules") or []) if str(x) in VALID_MODULES]
    host = (obj.get("host") or "").strip() or None
    target_dir = (obj.get("target_dir") or "").strip() or None
    endpoint = (obj.get("endpoint") or "").strip() or None
    tool = (obj.get("tool") or "").strip() or None
    lang = str(obj.get("language") or "en")
    intent = str(obj.get("intent") or "other")

    return RouteDecision(
        language=lang,
        intent=intent,
        modules=modules,
        host=host,
        target_dir=target_dir,
        endpoint=endpoint,
        tool=tool,
        approve=bool(obj.get("approve")),
        force=bool(obj.get("force")),
        summary_pt=str(obj.get("summary_pt") or ""),
        summary_en=str(obj.get("summary_en") or ""),
        source="llm",
        confidence=0.85,
        used_default_pack=not modules and intent in {"campaign", "other", "playbook"},
    )


def route_prompt(
    prompt: str,
    *,
    host: str | None = None,
    target_dir: str | None = None,
    intents: list[str] | None = None,
    classes: list[str] | None = None,
    approve: bool = False,
    force: bool = False,
) -> RouteDecision:
    """Combine offline scoring with optional LLM escalation."""
    intents = intents or []
    classes = classes or []
    conf = offline_confidence(prompt, host=host, intents=intents, classes=classes)
    mods, used_default = resolve_modules(prompt)
    mod_ids = [m.id for m in mods]

    decision = RouteDecision(
        language=_guess_lang(prompt),
        intent=_offline_intent(intents, prompt),
        modules=mod_ids,
        host=host,
        target_dir=target_dir,
        endpoint=None,
        approve=approve,
        force=force or is_forced() or prompt_wants_force(prompt),
        summary_pt=_offline_summary_pt(prompt, mod_ids, used_default),
        summary_en=_offline_summary_en(prompt, mod_ids, used_default),
        source="offline",
        confidence=conf,
        used_default_pack=used_default,
    )

    threshold = float(os.environ.get("HACKBOT_ROUTE_THRESHOLD", "0.68") or "0.68")
    if conf >= threshold or not auto_route_enabled():
        return decision

    if not model_usable_for_route():
        ui.info(
            "offline confidence low — set a model with /provider so I can interpret "
            "PT-BR/EN prompts better (HACKBOT_AUTO_ROUTE=1)"
        )
        return decision

    ui.info(f"offline confidence={conf:.2f} < {threshold:.2f} — asking model to interpret prompt")
    llm = llm_interpret(prompt)
    if llm is None:
        return decision

    # Merge: prefer LLM modules/host when present; keep operator approve/force ORs
    active = get_active()
    merged = RouteDecision(
        language=llm.language or decision.language,
        intent=llm.intent or decision.intent,
        modules=llm.modules or decision.modules,
        host=llm.host or decision.host or (active.in_scope_hosts[0] if active and active.in_scope_hosts else None),
        target_dir=llm.target_dir
        or decision.target_dir
        or (f"targets/{active.name}" if active else None),
        endpoint=llm.endpoint or decision.endpoint,
        tool=llm.tool or decision.tool,
        approve=decision.approve or llm.approve,
        force=decision.force or llm.force,
        summary_pt=llm.summary_pt or decision.summary_pt,
        summary_en=llm.summary_en or decision.summary_en,
        source="offline+llm",
        confidence=max(conf, llm.confidence),
        used_default_pack=llm.used_default_pack and not llm.modules,
    )
    if not merged.modules and merged.intent in {"campaign", "playbook", "other"}:
        merged.modules = list(decision.modules) or ["recon", "secrets", "auth-bypass"]
        merged.used_default_pack = True
    return merged


def _guess_lang(text: str) -> str:
    low = text.lower()
    pt_markers = (
        "ção",
        "são",
        "não",
        "voce",
        "você",
        "pra ",
        "pro ",
        "fala",
        "ataque",
        "senha",
        "vazamento",
        "escopo",
        "scope",
        "faça",
        "faca",
        "me entrega",
    )
    # Accent-stripped check too
    norm = normalize_text(text)
    if any(m in low for m in pt_markers) or any(
        normalize_text(m) in norm for m in ("nao", "voce", "ataque", "senha", "vazamento", "faca", "entregue")
    ):
        return "pt-BR"
    return "en"


def _offline_intent(intents: list[str], prompt: str) -> str:
    if "campaign" in intents or has_attack_intent(prompt):
        return "campaign"
    if "playbook_run" in intents:
        return "playbook"
    if "run" in intents:
        return "run_tool"
    if "scope" in intents:
        return "scope"
    if "knowledge" in intents:
        return "knowledge"
    return "other"


def _offline_summary_pt(prompt: str, modules: list[str], used_default: bool) -> str:
    if used_default:
        return "Intenção de hunt detectada; usando pacote padrão (recon/secrets/auth-bypass/…)."
    if modules:
        return f"Campanha offline com módulos: {', '.join(modules)}."
    return "Plano offline a partir de regras/palavras-chave."


def _offline_summary_en(prompt: str, modules: list[str], used_default: bool) -> str:
    if used_default:
        return "Hunt intent detected; using default pack (recon/secrets/auth-bypass/…)."
    if modules:
        return f"Offline campaign modules: {', '.join(modules)}."
    return "Offline plan from rules/keywords."
