"""Load effective Hackbot config (file + env). Example YAML is no longer inert."""

from __future__ import annotations

import os
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Any

import yaml

ROOT = Path(__file__).resolve().parents[1]
DEFAULT_EXAMPLE = ROOT / "configs" / "hackbot.example.yaml"
DEFAULT_USER = ROOT / "configs" / "hackbot.yaml"

_CACHE: "HackbotConfig | None" = None


@dataclass(frozen=True)
class SafetyConfig:
    require_scope_file: bool = True
    block_out_of_scope: bool = True
    require_policy_quote_for_active_testing: bool = True
    destructive_actions_require_approval: bool = True
    redact_secrets: bool = True
    default_max_rps: int = 3
    subprocess_timeout_sec: float = 300.0


@dataclass(frozen=True)
class IntegrationsConfig:
    hexstrike_server: str = "http://127.0.0.1:8888"
    reconftw_path: str = "../reconftw/reconftw.sh"
    burp_exports_dir: str = "./targets"


@dataclass(frozen=True)
class KnowledgeConfig:
    routing: str = "./bounty_knowledge/study_notes/STUDY_MATERIAL_ROUTING.md"
    index: str = "./bounty_knowledge/study_notes/INDEX.md"
    external_dir: str = "./external_knowledge"


@dataclass(frozen=True)
class HackbotConfig:
    workspace: str = "."
    safety: SafetyConfig = field(default_factory=SafetyConfig)
    integrations: IntegrationsConfig = field(default_factory=IntegrationsConfig)
    knowledge: KnowledgeConfig = field(default_factory=KnowledgeConfig)
    source_path: str = ""
    notes: tuple[str, ...] = ()

    def to_public_dict(self) -> dict[str, Any]:
        return {
            "workspace": self.workspace,
            "safety": asdict(self.safety),
            "integrations": asdict(self.integrations),
            "knowledge": asdict(self.knowledge),
            "source_path": self.source_path,
            "notes": list(self.notes),
        }


def reset_config_cache() -> None:
    global _CACHE
    _CACHE = None


def get_config(*, reload: bool = False) -> HackbotConfig:
    global _CACHE
    if _CACHE is not None and not reload:
        return _CACHE
    _CACHE = load_config()
    return _CACHE


def load_config(
    path: Path | None = None,
    *,
    environ: dict[str, str] | None = None,
) -> HackbotConfig:
    """Load YAML config. Precedence: explicit path > hackbot.yaml > example > defaults; env wins."""
    env = environ if environ is not None else os.environ
    notes: list[str] = []
    chosen: Path | None = Path(path) if path else None
    if chosen is None:
        if DEFAULT_USER.exists():
            chosen = DEFAULT_USER
        elif DEFAULT_EXAMPLE.exists():
            chosen = DEFAULT_EXAMPLE
            notes.append(f"using example config {DEFAULT_EXAMPLE.name} (copy to hackbot.yaml to customize)")
    raw: dict[str, Any] = {}
    source = ""
    if chosen and chosen.exists():
        source = str(chosen)
        loaded = yaml.safe_load(chosen.read_text(encoding="utf-8")) or {}
        if not isinstance(loaded, dict):
            raise ValueError(f"config root must be a mapping: {chosen}")
        raw = loaded

    safety_raw = dict(raw.get("safety") or {})
    integ_raw = dict(raw.get("integrations") or {})
    know_raw = dict(raw.get("knowledge") or {})

    # Env overrides (operator-facing knobs we actually honor).
    if env.get("HACKBOT_MAX_RPS"):
        safety_raw["default_max_rps"] = int(float(env["HACKBOT_MAX_RPS"]))
        notes.append("default_max_rps overridden by HACKBOT_MAX_RPS")
    if env.get("HACKBOT_SUBPROCESS_TIMEOUT"):
        safety_raw["subprocess_timeout_sec"] = float(env["HACKBOT_SUBPROCESS_TIMEOUT"])
        notes.append("subprocess_timeout_sec overridden by HACKBOT_SUBPROCESS_TIMEOUT")
    if env.get("HACKBOT_STRICT_REDACT", "").strip().lower() in {"1", "true", "yes", "on"}:
        safety_raw["redact_secrets"] = True
        notes.append("redact_secrets forced by HACKBOT_STRICT_REDACT")

    safety = SafetyConfig(
        require_scope_file=_as_bool(safety_raw.get("require_scope_file"), True),
        block_out_of_scope=_as_bool(safety_raw.get("block_out_of_scope"), True),
        require_policy_quote_for_active_testing=_as_bool(
            safety_raw.get("require_policy_quote_for_active_testing"), True
        ),
        destructive_actions_require_approval=_as_bool(
            safety_raw.get("destructive_actions_require_approval"), True
        ),
        redact_secrets=_as_bool(safety_raw.get("redact_secrets"), True),
        default_max_rps=max(1, int(safety_raw.get("default_max_rps") or 3)),
        subprocess_timeout_sec=max(
            5.0, float(safety_raw.get("subprocess_timeout_sec") or 300.0)
        ),
    )

    # Non-negotiable floors — config cannot silently disable these.
    if not safety.require_scope_file:
        notes.append("require_scope_file=false ignored (SCOPE.md remains mandatory)")
        safety = SafetyConfig(**{**asdict(safety), "require_scope_file": True})
    if not safety.block_out_of_scope:
        notes.append("block_out_of_scope=false ignored (OOS stays hard-blocked)")
        safety = SafetyConfig(**{**asdict(safety), "block_out_of_scope": True})
    if not safety.destructive_actions_require_approval:
        notes.append(
            "destructive_actions_require_approval=false ignored (approve still required)"
        )
        safety = SafetyConfig(
            **{**asdict(safety), "destructive_actions_require_approval": True}
        )

    return HackbotConfig(
        workspace=str(raw.get("workspace") or "."),
        safety=safety,
        integrations=IntegrationsConfig(
            hexstrike_server=str(
                integ_raw.get("hexstrike_server") or "http://127.0.0.1:8888"
            ),
            reconftw_path=str(integ_raw.get("reconftw_path") or "../reconftw/reconftw.sh"),
            burp_exports_dir=str(integ_raw.get("burp_exports_dir") or "./targets"),
        ),
        knowledge=KnowledgeConfig(
            routing=str(
                know_raw.get("routing")
                or "./bounty_knowledge/study_notes/STUDY_MATERIAL_ROUTING.md"
            ),
            index=str(know_raw.get("index") or "./bounty_knowledge/study_notes/INDEX.md"),
            external_dir=str(know_raw.get("external_dir") or "./external_knowledge"),
        ),
        source_path=source,
        notes=tuple(notes),
    )


def _as_bool(value: Any, default: bool) -> bool:
    if value is None:
        return default
    if isinstance(value, bool):
        return value
    return str(value).strip().lower() in {"1", "true", "yes", "on"}
