"""Interactive REPL. Type a prompt; the agent thinks and uses tools.

hackbot is model-agnostic: it's the knowledge/safety layer, you bring the model.
Pick a provider, a model, and a reasoning effort, then just talk.

Brains:
  - model  : any HTTP provider (OpenAI, Anthropic, DeepSeek, GLM, OpenRouter, local)
  - codex  : the `codex` CLI, powered by your ChatGPT plan
  - offline: no model, rule-based planner (still runs tools)
"""

from __future__ import annotations

import os

from rich.prompt import Confirm, Prompt

from . import ui
from .agent import run_agent
from .codex_backend import codex_available, run_codex_turn
from .llm import LLMError
from .local_agent import run_local_agent
from .providers import (
    EFFORT_LEVELS,
    PROVIDERS,
    ConfigError,
    normalize_effort,
    resolve_config,
)


def _approve(prompt: str) -> bool:
    ui.permission(prompt)
    return Confirm.ask("[bold yellow]Allow this action?[/]", default=False)


def _describe(cfg) -> str:
    label = PROVIDERS[cfg.provider].label
    text = f"{label} / {cfg.model or '(plan default)'}"
    if cfg.effort:
        text += f" / effort={cfg.effort}"
    return text


def _resolve_mode() -> tuple[str, str]:
    """Return (mode, label). mode is 'model' | 'codex' | 'offline'."""
    if os.environ.get("HACKBOT_LOCAL", "").strip() in {"1", "true", "yes"}:
        return "offline", "offline (forced by HACKBOT_LOCAL)"

    # HACKBOT_BACKEND is a friendly alias for HACKBOT_PROVIDER.
    backend = os.environ.get("HACKBOT_BACKEND", "").strip().lower()
    if backend and not os.environ.get("HACKBOT_PROVIDER"):
        if backend == "offline":
            return "offline", "offline (forced by HACKBOT_BACKEND)"
        os.environ["HACKBOT_PROVIDER"] = backend

    forced = os.environ.get("HACKBOT_PROVIDER", "").strip().lower()
    if forced == "offline":
        return "offline", "offline (manual)"

    try:
        cfg = resolve_config()
    except ConfigError as exc:
        # Explicit provider but misconfigured (e.g. missing key): show why.
        if forced:
            reason = str(exc).splitlines()[0]
            return "offline", f"offline ({reason})"
        # Default: offline. Never auto-pick codex or anything else; the user
        # chooses a model with /provider (or a key). Offline is home base.
        return "offline", "offline (default - pick a model with /provider)"

    if cfg.wire == "codex":
        if codex_available():
            return "codex", _describe(cfg)
        return "offline", "offline (codex not logged in - run `codex login`)"
    return "model", _describe(cfg)


class _Session:
    def __init__(self) -> None:
        self.model_history: list = []
        self.codex_history: list[tuple[str, str]] = []

    def clear(self) -> None:
        self.model_history.clear()
        self.codex_history.clear()


def _run_turn(mode: str, text: str, session: _Session) -> None:
    if mode == "model":
        run_agent(text, history=session.model_history, approve_fn=_approve)
    elif mode == "codex":
        model = os.environ.get("HACKBOT_MODEL") or None
        effort = normalize_effort(os.environ.get("HACKBOT_EFFORT"))
        # File ops are ON by default; each op still asks approval. Turn the whole
        # capability off with /codex-write (codex becomes a read-only advisor).
        allow_file_ops = os.environ.get("HACKBOT_CODEX_FILEOPS", "1").strip() not in {"0", "false", "off", "no"}
        answer = run_codex_turn(
            text,
            history=session.codex_history,
            model=model,
            effort=effort,
            approve_fn=_approve,
            allow_file_ops=allow_file_ops,
        )
        session.codex_history.append(("user", text))
        session.codex_history.append(("hackbot", answer))
    else:
        run_local_agent(text, approve_fn=_approve)


def _cmd_providers() -> None:
    ui.rule("providers")
    for p in PROVIDERS.values():
        has_key = any(os.environ.get(e) for e in p.key_envs) or not p.requires_key
        mark = "ready" if has_key else "needs key"
        ui.kv(p.name, f"{p.label}  [{mark}]")
        if p.note:
            ui.info(f"    {p.note}")
    ui.info("switch with:  /provider <name>")


def _cmd_models(provider_name: str) -> None:
    p = PROVIDERS.get(provider_name)
    ui.kv("provider", provider_name)
    if p and p.models:
        ui.info("model suggestions (any name your account supports works):")
        for name in p.models:
            ui.info(f"  {name}")
    ui.info("set with:  /model <name>")


def _current_label() -> str:
    try:
        return _describe(resolve_config())
    except ConfigError:
        return "(none)"


def start_repl(*, one_shot: str | None = None) -> int:
    ui.splash_agent()
    mode, label = _resolve_mode()

    ui.success(f"ready  {label}")
    if mode == "offline":
        ui.info("offline brain: rule-based. pick a model for real reasoning:")
        ui.info("  /providers   then   /provider <name>   /model <name>   /effort <level>")
    else:
        ui.info("switch anytime:  /provider  /model  /effort  /status  /help")

    session = _Session()

    if one_shot:
        _run_turn(mode, one_shot, session)
        return 0

    ui.info("chat is open. type a task, press Enter. it stays open.  /exit  /help")
    ui.console.print()

    while True:
        try:
            user = Prompt.ask("[bold cyan]hackbot[/]")
        except (EOFError, KeyboardInterrupt):
            ui.console.print()
            ui.info("bye")
            return 0

        text = (user or "").strip()
        if not text:
            continue
        if text in {"/exit", "/quit", "exit", "quit"}:
            ui.info("bye")
            return 0
        if text == "/clear":
            session.clear()
            ui.success("context cleared")
            continue
        if text in {"/mode", "/status"}:
            ui.kv("brain", mode)
            ui.kv("config", label)
            continue

        # ---- providers / brains ------------------------------------------
        if text == "/providers":
            _cmd_providers()
            continue
        if text.startswith("/provider"):
            arg = text[len("/provider"):].strip().lower()
            if not arg:
                ui.kv("provider", label)
                ui.info("list: /providers   set: /provider <name>")
                continue
            if arg not in PROVIDERS and arg not in {"offline", "local"}:
                ui.error(f"unknown provider '{arg}'. try /providers")
                continue
            if arg in {"offline", "local"}:
                os.environ["HACKBOT_PROVIDER"] = "offline"
            else:
                os.environ["HACKBOT_PROVIDER"] = arg
            mode, label = _resolve_mode()
            ui.success(f"provider -> {label}  (brain: {mode})")
            continue
        if text in {"/codex"}:
            os.environ["HACKBOT_PROVIDER"] = "codex"
            mode, label = _resolve_mode()
            if mode == "codex":
                ui.success(f"switched to codex  ({label})")
            else:
                ui.error("codex not ready. run `codex login` (Sign in with ChatGPT) first.")
            continue
        if text in {"/codex-write", "/codexwrite", "/codex-files"}:
            on = os.environ.get("HACKBOT_CODEX_FILEOPS", "1").strip() not in {"0", "false", "off", "no"}
            if on:
                os.environ["HACKBOT_CODEX_FILEOPS"] = "0"
                ui.success("codex file changes: OFF (read-only advisor, proposes only)")
            else:
                os.environ["HACKBOT_CODEX_FILEOPS"] = "1"
                ui.success(
                    "codex file changes: ON - codex proposes edits, hackbot applies "
                    "them (works anywhere) and asks you to approve each one."
                )
            continue
        if text in {"/local", "/offline"}:
            os.environ["HACKBOT_PROVIDER"] = "offline"
            mode, label = _resolve_mode()
            ui.success("switched to offline (rule-based) brain")
            continue

        # ---- model --------------------------------------------------------
        if text == "/models":
            try:
                prov = resolve_config().provider
            except ConfigError:
                prov = os.environ.get("HACKBOT_PROVIDER", "openai")
            _cmd_models(prov)
            continue
        if text.startswith("/model"):
            arg = text[len("/model"):].strip()
            if not arg:
                ui.kv("model", os.environ.get("HACKBOT_MODEL") or "(provider default)")
                ui.info("set with:  /model <name>   (list: /models)")
                continue
            os.environ["HACKBOT_MODEL"] = arg
            mode, label = _resolve_mode()
            ui.success(f"model -> {arg}")
            continue

        # ---- reasoning effort --------------------------------------------
        if text.startswith("/effort"):
            arg = text[len("/effort"):].strip()
            if not arg:
                ui.kv("effort", os.environ.get("HACKBOT_EFFORT") or "(provider default)")
                ui.info("levels: " + " | ".join(EFFORT_LEVELS))
                ui.info("set with:  /effort <level>")
                continue
            level = normalize_effort(arg)
            if not level:
                ui.error(f"unknown effort '{arg}'. levels: {', '.join(EFFORT_LEVELS)}")
                continue
            os.environ["HACKBOT_EFFORT"] = level
            mode, label = _resolve_mode()
            ui.success(f"effort -> {level}")
            continue

        if text.startswith("/stream"):
            arg = text[len("/stream"):].strip().lower()
            if arg in {"on", "1", "true"}:
                os.environ["HACKBOT_STREAM"] = "1"
                ui.success("live streaming ON")
            elif arg in {"off", "0", "false"}:
                os.environ["HACKBOT_STREAM"] = "0"
                ui.success("live streaming OFF")
            else:
                cur = os.environ.get("HACKBOT_STREAM", "1") not in {"0", "false", "off"}
                ui.kv("streaming", "on" if cur else "off")
                ui.info("set with:  /stream on | off")
            continue

        if text == "/help":
            ui.info("just talk. examples:")
            ui.info("  check if example.com is in scope for targets/demo")
            ui.info("  open IDOR notes and draft a hunt plan for example.com/api/orders/1")
            ui.info("provider: /providers  /provider <name>  (/codex /local)")
            ui.info("model:    /models  /model <name>")
            ui.info("effort:   /effort <minimal|low|medium|high|xhigh>")
            ui.info("stream:   /stream on|off   (live reasoning)")
            ui.info("codex:    /codex-write     (toggle codex file changes; on by default, asks per edit)")
            ui.info("session:  /status  /clear  /exit")
            continue

        _run_turn(mode, text, session)
        ui.console.print()
