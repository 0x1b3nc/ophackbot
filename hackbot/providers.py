"""Provider registry: make hackbot model-agnostic.

Whatever model the user brings (OpenAI, Anthropic, Codex/ChatGPT plan, DeepSeek,
GLM/Zhipu, OpenRouter, or a local model) plugs into the same hackbot brain.

A provider declares:
  - wire        : how we talk to it ("openai", "anthropic", or "codex")
  - base_url    : endpoint for openai-wire providers
  - key_envs    : env vars we look at for the API key (first hit wins)
  - default_model
  - effort_style: how it accepts a reasoning-effort hint (or None)
  - models      : a few suggestions (any name the account supports still works)

Reasoning effort is normalized to: minimal | low | medium | high | xhigh.
Each wire maps that to the right knob (or ignores it if unsupported).
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

EFFORT_LEVELS = ("auto", "minimal", "low", "medium", "high", "xhigh")

_EFFORT_ALIASES = {
    "min": "minimal",
    "minimal": "minimal",
    "lo": "low",
    "low": "low",
    "med": "medium",
    "mid": "medium",
    "medium": "medium",
    "normal": "medium",
    "default": "medium",
    "hi": "high",
    "high": "high",
    "x": "xhigh",
    "xh": "xhigh",
    "xhigh": "xhigh",
    "extra": "xhigh",
    "extrahigh": "xhigh",
    "extra-high": "xhigh",
    "max": "xhigh",
    "ultra": "xhigh",
    "auto": "auto",
}


@dataclass(frozen=True)
class Provider:
    name: str
    wire: str  # "openai" | "anthropic" | "codex"
    label: str
    base_url: str = ""
    key_envs: tuple[str, ...] = ()
    default_model: str = ""
    effort_style: str | None = None  # openai | anthropic | openrouter | glm | codex | None
    requires_key: bool = True
    dummy_key: str = "sk-local"
    models: tuple[str, ...] = field(default_factory=tuple)
    note: str = ""


PROVIDERS: dict[str, Provider] = {
    "openai": Provider(
        name="openai",
        wire="openai",
        label="OpenAI",
        base_url="https://api.openai.com/v1",
        key_envs=("OPENAI_API_KEY", "HACKBOT_API_KEY"),
        default_model="gpt-4o",
        effort_style="openai",
        models=("gpt-4o", "gpt-4o-mini", "gpt-4.1", "o4-mini", "o3", "gpt-5.5", "gpt-5.6-sol", "gpt-5.6-terra"),
        note="Paid API. /model only accepts real ids (curated + live /v1/models).",
    ),
    "anthropic": Provider(
        name="anthropic",
        wire="anthropic",
        label="Anthropic (Claude)",
        base_url="https://api.anthropic.com",
        key_envs=("ANTHROPIC_API_KEY",),
        default_model="claude-sonnet-4-20250514",
        effort_style="anthropic",
        models=(
            "claude-opus-4-20250514",
            "claude-sonnet-4-20250514",
            "claude-3-7-sonnet-latest",
            "claude-3-5-haiku-latest",
        ),
        note="Effort → thinking budget. /model: curated + live GET /v1/models (cached).",
    ),
    "codex": Provider(
        name="codex",
        wire="codex",
        label="Codex CLI (your ChatGPT plan)",
        default_model="",  # empty -> codex uses your plan default
        effort_style="codex",
        requires_key=False,
        models=("default", "gpt-5.5", "gpt-5.5-codex", "gpt-5-codex", "o4-mini"),
        note="ChatGPT plan via codex exec. /model default|gpt-5.5|... only.",
    ),
    "cursor": Provider(
        name="cursor",
        wire="cursor",
        label="Cursor SDK (your Cursor plan)",
        key_envs=("CURSOR_API_KEY",),
        default_model="composer-2.5",
        effort_style="cursor",
        models=("composer-2.5", "grok-4.5", "auto"),
        note=(
            "Local Cursor agent via cursor-sdk + hackbot CustomTools (SCOPE/approve). "
            "/model composer-2.5|grok-4.5|auto. /effort low|medium|high[ fast]."
        ),
    ),
    "deepseek": Provider(
        name="deepseek",
        wire="openai",
        label="DeepSeek",
        base_url="https://api.deepseek.com",
        key_envs=("DEEPSEEK_API_KEY", "HACKBOT_API_KEY"),
        default_model="deepseek-chat",
        effort_style=None,
        models=("deepseek-chat", "deepseek-reasoner"),
        note="Only deepseek-chat / deepseek-reasoner (+ live /models if any).",
    ),
    "glm": Provider(
        name="glm",
        wire="openai",
        label="GLM / Zhipu",
        base_url="https://open.bigmodel.cn/api/paas/v4",
        key_envs=("GLM_API_KEY", "ZHIPUAI_API_KEY", "HACKBOT_API_KEY"),
        default_model="glm-4.6",
        effort_style="glm",
        models=("glm-4.6", "glm-4.5", "glm-4.5-air", "glm-5.2"),
        note="Strict /model. Optional HACKBOT_BASE_URL=https://api.z.ai/api/paas/v4",
    ),
    "openrouter": Provider(
        name="openrouter",
        wire="openai",
        label="OpenRouter (many models)",
        base_url="https://openrouter.ai/api/v1",
        key_envs=("OPENROUTER_API_KEY", "HACKBOT_API_KEY"),
        default_model="openai/gpt-4o-mini",
        effort_style="openrouter",
        models=(
            "openai/gpt-4o-mini",
            "anthropic/claude-sonnet-4",
            "deepseek/deepseek-chat",
            "z-ai/glm-4.6",
            "google/gemini-2.5-pro",
            "meta-llama/llama-3.1-70b-instruct",
        ),
        note="Strict /model: curated + live OpenRouter catalog when key is set.",
    ),
    "ollama": Provider(
        name="ollama",
        wire="openai",
        label="Ollama (local, free)",
        base_url="http://localhost:11434/v1",
        key_envs=("HACKBOT_API_KEY",),
        default_model="llama3.1",
        effort_style=None,
        requires_key=False,
        models=("llama3.1", "qwen2.5", "mistral", "deepseek-r1"),
        note="Strict /model: curated + ollama /api/tags when running.",
    ),
    "lmstudio": Provider(
        name="lmstudio",
        wire="openai",
        label="LM Studio (local, free)",
        base_url="http://localhost:1234/v1",
        key_envs=("HACKBOT_API_KEY",),
        default_model="",
        effort_style=None,
        requires_key=False,
        models=(),
        note="Strict /model: only ids from LM Studio GET /v1/models.",
    ),
    "custom": Provider(
        name="custom",
        wire="openai",
        label="Custom OpenAI-compatible",
        base_url="",  # taken from HACKBOT_BASE_URL
        key_envs=("HACKBOT_API_KEY", "OPENAI_API_KEY"),
        default_model="gpt-4o",
        effort_style="openai",
        requires_key=False,
        note="Any OpenAI-compatible gateway. Set HACKBOT_BASE_URL.",
    ),
}


@dataclass(frozen=True)
class Config:
    provider: str
    wire: str
    model: str
    base_url: str
    api_key: str
    effort: str | None
    effort_style: str | None


class ConfigError(RuntimeError):
    pass


def normalize_effort(value: str | None) -> str | None:
    if not value:
        return None
    key = value.strip().lower()
    return _EFFORT_ALIASES.get(key)


def _user_env_windows(name: str) -> str | None:
    """Read a User-level env var (what `setx` writes). Process env is unchanged
    until the shell is restarted — this bridges that Windows footgun."""
    if os.name != "nt":
        return None
    try:
        import winreg
    except ImportError:
        return None
    try:
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, r"Environment") as key:
            val, _ = winreg.QueryValueEx(key, name)
    except OSError:
        return None
    if isinstance(val, str) and val.strip():
        return val.strip()
    return None


def _first_env(names: tuple[str, ...]) -> str | None:
    for name in names:
        val = os.environ.get(name)
        if val and val.strip():
            return val.strip()
        # setx / System Properties → User env (not yet in this process)
        persisted = _user_env_windows(name)
        if persisted:
            os.environ[name] = persisted
            return persisted
    return None


def _infer_provider() -> str | None:
    """Pick a provider from whatever keys/env are present."""
    if os.environ.get("HACKBOT_BASE_URL"):
        return "custom"
    if os.environ.get("ANTHROPIC_API_KEY"):
        return "anthropic"
    if os.environ.get("OPENAI_API_KEY"):
        return "openai"
    if os.environ.get("DEEPSEEK_API_KEY"):
        return "deepseek"
    if os.environ.get("GLM_API_KEY") or os.environ.get("ZHIPUAI_API_KEY"):
        return "glm"
    if os.environ.get("OPENROUTER_API_KEY"):
        return "openrouter"
    return None


def resolve_config() -> Config:
    """Resolve provider/model/effort from env. Raises ConfigError if no model.

    HACKBOT_EFFORT=auto is stored as None here; call sites resolve per prompt
    via intent.resolve_effort_for_prompt.
    """
    raw_effort = os.environ.get("HACKBOT_EFFORT", "auto")
    norm = normalize_effort(raw_effort)
    effort = None if norm in (None, "auto") else norm

    forced = os.environ.get("HACKBOT_PROVIDER", "").strip().lower()
    name = forced or _infer_provider() or ""
    if not name:
        raise ConfigError(
            "No model configured. In the REPL: /providers then /provider <name>.\n"
            "Or set HACKBOT_PROVIDER=openai|anthropic|deepseek|glm|openrouter|ollama|codex|cursor|…\n"
            "Keys: OPENAI_API_KEY / ANTHROPIC_API_KEY / DEEPSEEK_API_KEY / GLM_API_KEY / "
            "OPENROUTER_API_KEY / CURSOR_API_KEY, or HACKBOT_BASE_URL for local/custom.\n"
            "Optional: HACKBOT_MODEL, HACKBOT_EFFORT (auto|minimal|low|medium|high|xhigh)."
        )
    if name not in PROVIDERS:
        raise ConfigError(f"unknown provider '{name}'. Known: {', '.join(PROVIDERS)}")

    p = PROVIDERS[name]
    model = os.environ.get("HACKBOT_MODEL") or p.default_model
    base_url = (os.environ.get("HACKBOT_BASE_URL") or p.base_url).rstrip("/")
    key = _first_env(p.key_envs)
    if p.requires_key and not key:
        hint = p.key_envs[0]
        raise ConfigError(
            f"{p.label} needs {hint} set.\n"
            f"  this session:  $env:{hint} = \"...\"\n"
            f"  persistent:    setx {hint} \"...\"  (then open a NEW terminal)"
        )
    api_key = key or p.dummy_key

    return Config(
        provider=name,
        wire=p.wire,
        model=model,
        base_url=base_url,
        api_key=api_key,
        effort=effort,
        effort_style=p.effort_style,
    )


def list_providers() -> list[Provider]:
    return list(PROVIDERS.values())
