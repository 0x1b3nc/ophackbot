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
from .force import disable_force, enable_force, is_forced
from .hunt_controller import hunt_status, request_stop, run_hunt
from .identity import save_session
from .local_agent import run_local_agent
from .providers import (
    EFFORT_LEVELS,
    PROVIDERS,
    ConfigError,
    normalize_effort,
    resolve_config,
)
from .session import clear_active, get_active, set_active, status_line
from .tools import execute_tool


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
        disable_force()


def _prompt_label(mode: str) -> str:
    effort = os.environ.get("HACKBOT_EFFORT", "auto") or "auto"
    short = mode if mode != "model" else "model"
    active = get_active()
    if active:
        return f"{short} · {effort} · {active.name}"
    return f"{short} · {effort}"


def _run_turn(mode: str, text: str, session: _Session) -> None:
    try:
        if mode == "model":
            run_agent(text, history=session.model_history, approve_fn=_approve)
        elif mode == "codex":
            model = os.environ.get("HACKBOT_MODEL") or None
            # File ops ON by default; each op still asks approval.
            allow_file_ops = os.environ.get("HACKBOT_CODEX_FILEOPS", "1").strip() not in {
                "0",
                "false",
                "off",
                "no",
            }
            answer = run_codex_turn(
                text,
                history=session.codex_history,
                model=model,
                approve_fn=_approve,
                allow_file_ops=allow_file_ops,
            )
            if answer != "(cancelled)":
                session.codex_history.append(("user", text))
                session.codex_history.append(("hackbot", answer))
                # Cap codex history too
                if len(session.codex_history) > 12:
                    del session.codex_history[: len(session.codex_history) - 12]
        else:
            run_local_agent(text, approve_fn=_approve)
    except KeyboardInterrupt:
        ui.warn("cancelled")


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
            tag = _prompt_label(mode)
            user = Prompt.ask(f"[bold cyan]hackbot[/] [dim]· {tag}[/]")
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
            ui.kv("hunt", status_line())
            ui.kv("force", "ON" if is_forced() else "off")
            active = get_active()
            if active is not None:
                st = hunt_status(active.target_dir)
                if st.get("phase") and st.get("phase") != "idle":
                    ui.kv(
                        "autohunt",
                        f"phase={st.get('phase')} budget={st.get('budget_remaining')}/{st.get('budget_total')} "
                        f"endpoints={st.get('endpoints')}",
                    )
            continue

        if text.startswith("/force"):
            arg = text[len("/force") :].strip().lower()
            if arg in {"", "on", "1", "true", "yes"}:
                enable_force()
            elif arg in {"off", "0", "false", "no"}:
                disable_force()
            else:
                ui.kv("force", "ON" if is_forced() else "off")
                ui.info("set: /force on | off")
            continue

        if text.startswith("/hunt"):
            active = get_active()
            rest = text[len("/hunt") :].strip()
            if rest.lower() in {"", "help", "?"}:
                ui.info("usage: /hunt <prompt> [--approve] [--budget N]")
                ui.info("       /hunt status")
                ui.info("       /hunt stop")
                ui.info("session approve unlocks active traffic for the whole OODA loop")
                continue
            if rest.lower() == "stop":
                request_stop()
                ui.warn("hunt stop requested")
                continue
            if rest.lower() in {"status", "stat"}:
                if active is None:
                    ui.error("no active target — /target <name> first")
                    continue
                st = hunt_status(active.target_dir)
                ui.code_panel(
                    __import__("json").dumps(st, indent=2),
                    title="hunt status",
                    lexer="json",
                )
                continue
            if active is None:
                ui.error("no active target — /target <name> first")
                continue
            approve_session = False
            budget = None
            tokens = rest.split()
            prompt_parts: list[str] = []
            i = 0
            while i < len(tokens):
                tok = tokens[i]
                if tok in {"--approve", "-a", "--yes"}:
                    approve_session = True
                    i += 1
                    continue
                if tok == "--budget" and i + 1 < len(tokens):
                    try:
                        budget = int(tokens[i + 1])
                    except ValueError:
                        ui.error("--budget needs an integer")
                        break
                    i += 2
                    continue
                prompt_parts.append(tok)
                i += 1
            else:
                prompt = " ".join(prompt_parts).strip()
                if not prompt:
                    ui.error("usage: /hunt <prompt> [--approve]")
                    continue
                result = run_hunt(
                    active.target_dir,
                    prompt,
                    approve_session=approve_session,
                    budget=budget,
                    approve_fn=_approve if approve_session else None,
                    force=is_forced(),
                )
                ui.code_panel(
                    __import__("json").dumps(result, indent=2)[:4000],
                    title="hunt result",
                    lexer="json",
                )
            continue

        if text.startswith("/target"):
            arg = text[len("/target") :].strip()
            if not arg or arg in {"clear", "none", "off"}:
                if arg in {"clear", "none", "off"}:
                    clear_active()
                    ui.success("active target cleared")
                else:
                    ui.kv("hunt", status_line())
                    ui.info("set: /target <name>   clear: /target clear")
                continue
            try:
                session = set_active(arg)
            except FileNotFoundError as exc:
                ui.error(str(exc))
                continue
            ui.success(f"active target -> {session.name}")
            ui.info(status_line())
            if session.next_step:
                ui.info(f"next: {session.next_step}")
            continue

        if text in {"/sessions", "/identity"}:
            active = get_active()
            if active is None:
                ui.error("no active target — /target <name> first")
                continue
            out = execute_tool(
                "show_identity",
                {"target_dir": str(active.target_dir)},
            )
            ui.code_panel(out, title="identity", lexer="json")
            continue

        if text.startswith("/session"):
            # /session set A --bearer TOKEN | --cookie VAL
            active = get_active()
            if active is None:
                ui.error("no active target — /target <name> first")
                continue
            rest = text[len("/session") :].strip()
            parts = rest.split()
            if not parts or parts[0] in {"help", "?"}:
                ui.info("usage: /session set A --bearer <token>")
                ui.info("       /session set B --cookie <cookie>")
                ui.info("       /sessions")
                continue
            if parts[0] != "set" or len(parts) < 2:
                ui.error("usage: /session set <name> --bearer|--cookie <value>")
                continue
            name_s = parts[1]
            bearer = ""
            cookie = ""
            if "--bearer" in parts:
                idx = parts.index("--bearer")
                bearer = parts[idx + 1] if idx + 1 < len(parts) else ""
            if "--cookie" in parts:
                idx = parts.index("--cookie")
                cookie = parts[idx + 1] if idx + 1 < len(parts) else ""
            if not bearer and not cookie:
                ui.error("pass --bearer and/or --cookie")
                continue
            if not Confirm.ask(
                f"[bold yellow]Write session {name_s} to secrets/sessions.yaml?[/]",
                default=False,
            ):
                ui.warn("denied")
                continue
            ident = save_session(
                active.target_dir,
                name_s,
                authorization=bearer or None,
                cookie=cookie or None,
            )
            ui.success(f"session {name_s} saved (gitignored)")
            ui.kv("ready", ", ".join(ident.ready_sessions()) or "(none)")
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
            # Force a fresh login-status check when the user asks for codex.
            codex_available(force=True)
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
                ui.kv("effort", os.environ.get("HACKBOT_EFFORT", "auto"))
                ui.info("levels: " + " | ".join(EFFORT_LEVELS))
                ui.info("auto = minimal for chat, medium for hunt tasks")
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

        if text.startswith("/verbose"):
            arg = text[len("/verbose"):].strip().lower()
            if arg in {"on", "1", "true"}:
                os.environ["HACKBOT_VERBOSE"] = "1"
                ui.success("verbose tool panels ON")
            elif arg in {"off", "0", "false"}:
                os.environ["HACKBOT_VERBOSE"] = "0"
                ui.success("verbose tool panels OFF (compact lines)")
            else:
                cur = os.environ.get("HACKBOT_VERBOSE", "").strip().lower() in {"1", "true", "yes", "on"}
                ui.kv("verbose", "on" if cur else "off")
                ui.info("set with:  /verbose on | off")
            continue

        if text == "/help":
            ui.info("just talk — slash commands are optional shortcuts:")
            ui.info("  as credenciais estão no arquivo tokens.yaml em Downloads; explora example.com approve")
            ui.info("  leia a imagem Desktop/scope.png")
            ui.info("  explora vulnerabilidades em example.com (targets/demo)")
            ui.info("provider: /providers  /provider <name>  (/codex /local)")
            ui.info("model:    /models  /model <name>")
            ui.info("effort:   /effort <auto|minimal|low|medium|high|xhigh>")
            ui.info("stream:   /stream on|off   (live reasoning)")
            ui.info("verbose:  /verbose on|off  (full tool panels)")
            ui.info("codex:    /codex-write     (toggle codex file changes; on by default)")
            ui.info("shortcuts:/target  /hunt  /session  /force  /status")
            ui.info("session:  /clear  /exit   (Ctrl+C cancels a running turn)")
            continue

        _run_turn(mode, text, session)
        ui.console.print()
