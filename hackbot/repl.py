"""Interactive REPL. Type a prompt; the agent thinks and uses tools.

hackbot is model-agnostic: it's the knowledge/safety layer, you bring the model.
Pick a provider, a model, and a reasoning effort, then just talk.

Brains:
  - model  : any HTTP provider (OpenAI, Anthropic, DeepSeek, GLM, OpenRouter, local)
  - codex  : the `codex` CLI, powered by your ChatGPT plan
  - cursor : Cursor SDK local agent (CURSOR_API_KEY)
  - offline: no model, rule-based planner (still runs tools)
"""

from __future__ import annotations

import os

from rich.prompt import Confirm, Prompt

from . import ui
from .agent import run_agent
from .codex_backend import codex_available, run_codex_turn
from .cursor_backend import close_cursor_agent, cursor_available, run_cursor_turn
from .cursor_models import last_resolved_label, parse_effort_fast, resolve_cursor_model
from .model_catalog import clear_model_cache, known_models, live_models_status, resolve_model
from .force import disable_force, enable_force, is_forced
from .hunt_controller import hunt_status, request_stop, run_hunt
from .identity import save_session
from .local_agent import run_local_agent
from .operator_gate import operator_prompt_active
from .providers import (
    EFFORT_LEVELS,
    PROVIDERS,
    ConfigError,
    normalize_effort,
    resolve_config,
)
from .session import clear_active, get_active, set_active, status_line
from .step_mode import (
    disable_step_mode,
    enable_step_mode,
    maybe_disable_from_prompt,
    step_mode_enabled,
)
from .tools import execute_tool
from .yolo import boot_yolo_from_env, disable_yolo, enable_yolo, is_yolo, yolo_auto_approve


def _approve(prompt: str) -> bool:
    if is_yolo():
        return yolo_auto_approve(prompt)
    with operator_prompt_active():
        # Fresh line so stream/tool status cannot stick to the Confirm prompt.
        ui.console.print()
        ui.permission(prompt)
        while True:
            raw = Prompt.ask(
                "[bold yellow]Allow this action?[/] [dim]y/n[/]",
                default="n",
            )
            ans = (raw or "").strip().lower()
            if ans in {"y", "yes", "approve", "--approve", "/approve"}:
                return True
            if ans in {"n", "no", "deny", "deny.", ""}:
                return False
            ui.warn("enter y or n (also: approve / deny)")


def _describe(cfg) -> str:
    label = PROVIDERS[cfg.provider].label
    text = f"{label} / {cfg.model or '(plan default)'}"
    if cfg.effort:
        text += f" / effort={cfg.effort}"
    return text


def _resolve_mode() -> tuple[str, str]:
    """Return (mode, label). mode is 'model' | 'codex' | 'cursor' | 'offline'.

    Home base is always offline unless the operator *explicitly* sets
    HACKBOT_PROVIDER / HACKBOT_BACKEND or uses /provider. Keys alone do not
    auto-switch the REPL brain (avoids surprising Codex/OpenAI takeover).
    """
    if os.environ.get("HACKBOT_LOCAL", "").strip() in {"1", "true", "yes"}:
        return "offline", "offline (forced by HACKBOT_LOCAL)"

    provider = os.environ.get("HACKBOT_PROVIDER", "").strip().lower()
    backend = os.environ.get("HACKBOT_BACKEND", "").strip().lower()
    # PROVIDER wins; BACKEND is a legacy alias
    if provider:
        forced, source = provider, "HACKBOT_PROVIDER"
    elif backend:
        forced, source = backend, "HACKBOT_BACKEND"
        # Align for resolve_config / mid-session tool calls (same process only)
        os.environ["HACKBOT_PROVIDER"] = forced
    else:
        forced, source = "", ""

    if not forced or forced == "offline":
        return "offline", "offline (default — /provider to pick a model)"

    try:
        cfg = resolve_config()
    except ConfigError as exc:
        reason = str(exc).splitlines()[0]
        return "offline", f"offline ({reason})"

    if cfg.wire == "codex":
        if codex_available():
            return "codex", _describe(cfg) + f" [{source}]"
        return "offline", "offline (codex not logged in — run `codex login` or /provider offline)"
    if cfg.wire == "cursor":
        if cursor_available():
            return "cursor", _describe(cfg) + f" [{source}]"
        return (
            "offline",
            "offline (cursor needs CURSOR_API_KEY + pip install 'hackbot-kit[cursor]')",
        )
    return "model", _describe(cfg) + f" [{source}]"


class _Session:
    def __init__(self) -> None:
        self.model_history: list = []
        self.codex_history: list[tuple[str, str]] = []
        self.cursor_history: list[tuple[str, str]] = []

    def clear(self) -> None:
        self.model_history.clear()
        self.codex_history.clear()
        self.cursor_history.clear()
        close_cursor_agent()
        disable_force()


def _prompt_label(mode: str) -> str:
    effort = os.environ.get("HACKBOT_EFFORT", "auto") or "auto"
    short = mode if mode != "model" else "model"
    if mode == "cursor":
        model = os.environ.get("HACKBOT_MODEL") or "composer-2.5"
        fast = os.environ.get("HACKBOT_CURSOR_FAST", "").strip().lower() in {
            "1",
            "true",
            "yes",
            "on",
        }
        bits = [short, model, effort]
        if fast:
            bits.append("fast")
        used = last_resolved_label()
        if used:
            bits.append(f"last={used}")
        active = get_active()
        if active:
            bits.append(active.name)
        return " · ".join(bits)
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
        elif mode == "cursor":
            model = os.environ.get("HACKBOT_MODEL") or None
            allow_file_ops = os.environ.get("HACKBOT_CURSOR_FILEOPS", "1").strip() not in {
                "0",
                "false",
                "off",
                "no",
            }
            answer = run_cursor_turn(
                text,
                history=session.cursor_history,
                model=model,
                approve_fn=_approve,
                allow_file_ops=allow_file_ops,
            )
            if answer != "(cancelled)":
                session.cursor_history.append(("user", text))
                session.cursor_history.append(("hackbot", answer))
                if len(session.cursor_history) > 12:
                    del session.cursor_history[: len(session.cursor_history) - 12]
        else:
            run_local_agent(text, approve_fn=_approve)
    except KeyboardInterrupt:
        ui.warn("cancelled")


def _cmd_providers() -> None:
    from .providers import _first_env

    ui.rule("providers")
    for p in PROVIDERS.values():
        has_key = bool(_first_env(p.key_envs)) if p.key_envs else True
        if not p.requires_key:
            has_key = True
        if p.name == "cursor":
            if not has_key:
                mark = "needs key"
            elif cursor_available():
                mark = "ready"
            else:
                mark = "needs cursor-sdk"
        else:
            mark = "ready" if has_key else "needs key"
        ui.kv(p.name, f"{p.label}  [{mark}]")
        if p.note:
            ui.info(f"    {p.note}")
    ui.info("switch with:  /provider <name>")


def _cmd_models(provider_name: str, *, refresh: bool = False) -> None:
    ui.rule(f"models ({provider_name})")
    if refresh:
        clear_model_cache(provider_name)
        ui.info("cache cleared — refetching live catalog…")
        from .model_catalog import fetch_live_models

        fetch_live_models(provider_name, force_refresh=True)
    rows = known_models(provider_name, include_live=True)
    if not rows:
        ui.warn("no known models — start the local server or set the API key, then /models refresh")
    for mid, note in rows:
        ui.kv(mid, note)
    if provider_name not in {"cursor", "offline"}:
        ui.info(f"live status: {live_models_status(provider_name)}")
    ui.info("ONLY these ids are accepted. set:  /model <id>   |   refresh: /models refresh")


def _current_label() -> str:
    try:
        return _describe(resolve_config())
    except ConfigError:
        return "(none)"


def start_repl(*, one_shot: str | None = None) -> int:
    ui.splash_agent()
    mode, label = _resolve_mode()
    boot_yolo_from_env()

    ui.success(f"ready  {label}")
    if mode == "offline":
        ui.info("default brain = offline (hackbot rules + tools). models are opt-in:")
        ui.info("  /providers   →   /provider openai|anthropic|codex|cursor|…   /model   /effort")
    else:
        ui.info("model brain active (from HACKBOT_PROVIDER or /provider). back home: /provider offline")
        ui.info("switch anytime:  /provider  /model  /effort  /status  /help")
    if is_yolo():
        ui.warn(
            "YOLO on - approve skipped; OOS still blocked. "
            "Step mode still pauses after each hunt act unless /step off. "
            "/yolo off to restore prompts."
        )
    if not step_mode_enabled():
        ui.warn("step mode OFF — full hunt until finding / budget / blocker")

    session = _Session()

    if one_shot:
        _run_turn(mode, one_shot, session)
        return 0

    ui.info("chat is open. type a task, press Enter. it stays open.  /exit  /help")
    ui.console.print()

    while True:
        try:
            # Spinner/progress must be fully dead before Prompt.ask or the prompt
            # line doubles and glues onto the next ``- codex effort=…`` banner.
            ui.ensure_prompt_line()
            tag = _prompt_label(mode)
            user = Prompt.ask(f"[bold cyan]hackbot[/] [dim]· {tag}[/]")
        except (EOFError, KeyboardInterrupt):
            ui.console.print()
            ui.info("bye")
            return 0

        text = (user or "").strip()
        if not text:
            continue
        # Fresh line so turn banners never share a row with the echoed input.
        ui.console.print()
        # Stray approve keystrokes after a raced prompt — do not start a new turn.
        if text.lower() in {"y", "n", "yy", "nn", "yes", "no"}:
            ui.warn(
                "no permission prompt is waiting — type a real task "
                "(or answer Allow this action? when it appears)"
            )
            continue
        if text in {"/exit", "/quit", "exit", "quit"}:
            ui.info("bye")
            return 0
        if text == "/clear":
            session.clear()
            ui.success("context cleared")
            continue
        if text in {"/mode", "/status"}:
            from .capabilities import collect_capabilities, print_capabilities

            ui.kv("brain", mode)
            ui.kv("config", label)
            ui.kv("hunt", status_line())
            ui.kv("yolo", "ON" if is_yolo() else "off")
            ui.kv("force", "ON" if is_forced() else "off")
            ui.kv(
                "step",
                "ON (pause each act)" if step_mode_enabled() else "OFF (full hunt)",
            )
            if mode == "cursor":
                ui.kv("model", os.environ.get("HACKBOT_MODEL") or "composer-2.5")
                ui.kv("effort", os.environ.get("HACKBOT_EFFORT", "auto"))
                fast_on = os.environ.get("HACKBOT_CURSOR_FAST", "").strip().lower() in {
                    "1",
                    "true",
                    "yes",
                    "on",
                }
                ui.kv("fast", "on" if fast_on else "off (standard)")
                used = last_resolved_label()
                ui.kv("last used (from SDK)", used or "(no turn yet)")
                try:
                    r = resolve_cursor_model(
                        os.environ.get("HACKBOT_MODEL"),
                        effort=os.environ.get("HACKBOT_EFFORT"),
                        require_known=True,
                    )
                    ui.kv("will request", r.display())
                except ValueError as exc:
                    ui.warn(str(exc))
            active = get_active()
            if active is not None:
                st = hunt_status(active.target_dir)
                if st.get("phase") and st.get("phase") != "idle":
                    ui.kv(
                        "autohunt",
                        f"phase={st.get('phase')} budget={st.get('budget_remaining')}/{st.get('budget_total')} "
                        f"endpoints={st.get('endpoints')}",
                    )
            print_capabilities(collect_capabilities(), compact=True)
            ui.info("full stack: /tools")
            continue

        if text in {"/tools", "/caps", "/capabilities", "/stack"}:
            from .capabilities import collect_capabilities, print_capabilities

            print_capabilities(collect_capabilities(), compact=False)
            continue

        if text in {"/config", "/cfg"}:
            from .config import get_config

            cfg = get_config(reload=True)
            ui.rule("effective config")
            ui.kv("source", cfg.source_path or "(defaults)")
            ui.kv("max_rps", str(cfg.safety.default_max_rps))
            ui.kv("subprocess_timeout_sec", str(cfg.safety.subprocess_timeout_sec))
            ui.kv("require_scope_file", str(cfg.safety.require_scope_file))
            ui.kv("block_out_of_scope", str(cfg.safety.block_out_of_scope))
            ui.kv("redact_secrets", str(cfg.safety.redact_secrets))
            ui.kv("hexstrike", cfg.integrations.hexstrike_server)
            for note in cfg.notes:
                ui.info(note)
            ui.info("edit configs/hackbot.yaml or set HACKBOT_MAX_RPS / HACKBOT_SUBPROCESS_TIMEOUT")
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

        if text.startswith("/yolo"):
            arg = text[len("/yolo") :].strip().lower()
            if arg in {"", "on", "1", "true", "yes"}:
                enable_yolo()
            elif arg in {"off", "0", "false", "no"}:
                disable_yolo()
            else:
                ui.kv("yolo", "ON" if is_yolo() else "off")
                ui.info("set: /yolo on | off")
                ui.info("also: HACKBOT_YOLO=1  and  .hackbot/sudo_pass for lab sudo")
            continue

        if text.startswith("/step"):
            arg = text[len("/step") :].strip().lower()
            if arg in {"", "on", "1", "true", "yes"}:
                enable_step_mode()
            elif arg in {"off", "0", "false", "no", "full", "hunt"}:
                disable_step_mode()
            else:
                ui.kv("step", "ON (pause each act)" if step_mode_enabled() else "OFF (full hunt)")
                ui.info("set: /step on | off")
                ui.info("off = keep hunting until finding / budget / blocker")
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
            approve_session = bool(is_yolo())
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
                target_session = set_active(arg)
            except FileNotFoundError as exc:
                ui.error(str(exc))
                continue
            ui.success(f"active target -> {target_session.name}")
            ui.info(status_line())
            if target_session.next_step:
                ui.info(f"next: {target_session.next_step}")
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
                # Common typo: /provier
                ui.error(f"unknown provider '{arg}'. try /providers")
                ui.info("example:  /provider cursor")
                continue
            prev = mode
            if arg in {"offline", "local"}:
                os.environ["HACKBOT_PROVIDER"] = "offline"
            else:
                os.environ["HACKBOT_PROVIDER"] = arg
            if prev == "cursor" and arg != "cursor":
                close_cursor_agent()
            mode, label = _resolve_mode()
            ui.success(f"provider -> {label}  (brain: {mode})")
            continue
        if text in {"/codex"}:
            if mode == "cursor":
                close_cursor_agent()
            os.environ["HACKBOT_PROVIDER"] = "codex"
            # Force a fresh login-status check when the user asks for codex.
            codex_available(force=True)
            mode, label = _resolve_mode()
            if mode == "codex":
                ui.success(f"switched to codex  ({label})")
            else:
                ui.error("codex not ready. run `codex login` (Sign in with ChatGPT) first.")
            continue
        if text in {"/cursor"}:
            os.environ["HACKBOT_PROVIDER"] = "cursor"
            mode, label = _resolve_mode()
            if mode == "cursor":
                ui.success(f"switched to cursor  ({label})")
            else:
                ui.error(
                    "cursor not ready. set CURSOR_API_KEY and "
                    "pip install 'hackbot-kit[cursor]' (or cursor-sdk)."
                )
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
            if mode == "cursor":
                close_cursor_agent()
            os.environ["HACKBOT_PROVIDER"] = "offline"
            mode, label = _resolve_mode()
            ui.success("switched to offline (rule-based) brain")
            continue

        # ---- model --------------------------------------------------------
        if text == "/models" or text.startswith("/models "):
            refresh = text.strip().lower() in {"/models refresh", "/models --refresh"}
            try:
                prov = resolve_config().provider
            except ConfigError:
                prov = os.environ.get("HACKBOT_PROVIDER", "").strip().lower() or (
                    "cursor" if mode == "cursor" else "openai"
                )
            if mode in {"cursor", "codex", "model"} and prov in {"", "offline"}:
                prov = "cursor" if mode == "cursor" else ("codex" if mode == "codex" else prov)
            _cmd_models(
                prov if prov and prov != "offline" else (os.environ.get("HACKBOT_PROVIDER") or "openai"),
                refresh=refresh,
            )
            if prov == "cursor" or mode == "cursor":
                ui.info("effort+fast:  /effort high fast   |   /fast on|off")
                ui.info("proof: after each turn, look for 'used model …'")
                ui.info(
                    "tools: HACKBOT_CURSOR_TOOLS=1 (default) registers hackbot "
                    "CustomTools; mode defaults to agent"
                )
            continue
        if text.startswith("/model"):
            arg = text[len("/model"):].strip()
            if not arg:
                ui.kv("model", os.environ.get("HACKBOT_MODEL") or "(provider default)")
                ui.info("set with:  /model <id>   (list: /models) — unknown ids are rejected")
                continue
            try:
                prov = resolve_config().provider
            except ConfigError:
                prov = os.environ.get("HACKBOT_PROVIDER", "").strip().lower()
            if not prov or prov == "offline":
                if mode == "cursor":
                    prov = "cursor"
                elif mode == "codex":
                    prov = "codex"
                else:
                    ui.error("pick a provider first: /provider openai|anthropic|cursor|…")
                    continue
            try:
                canonical, source = resolve_model(prov, arg)
            except ValueError as exc:
                ui.error(str(exc))
                ui.info("list valid ids: /models")
                continue
            os.environ["HACKBOT_MODEL"] = canonical
            if prov == "cursor":
                close_cursor_agent()
                try:
                    resolved = resolve_cursor_model(canonical, require_known=True)
                    ui.success(f"model -> {canonical}  [{source}]")
                    ui.info(f"will request: {resolved.display()}")
                except ValueError:
                    ui.success(f"model -> {canonical}  [{source}]")
            else:
                mode, label = _resolve_mode()
                ui.success(f"model -> {canonical or '(plan default)'}  [{source}]")
            mode, label = _resolve_mode()
            continue

        # ---- reasoning effort --------------------------------------------
        if text.startswith("/effort"):
            arg = text[len("/effort"):].strip()
            if not arg:
                ui.kv("effort", os.environ.get("HACKBOT_EFFORT", "auto"))
                ui.kv(
                    "fast",
                    "on"
                    if os.environ.get("HACKBOT_CURSOR_FAST", "").strip().lower()
                    in {"1", "true", "yes", "on"}
                    else "off",
                )
                ui.info("levels: " + " | ".join(EFFORT_LEVELS))
                ui.info("auto = minimal for chat, medium for hunt tasks")
                ui.info("cursor:  /effort high fast   |   /effort medium   |   /effort high nofast")
                ui.info("set with:  /effort <level>[ fast]")
                continue
            level, fast = parse_effort_fast(arg)
            if not level:
                ui.error(
                    f"unknown effort '{arg}'. examples: low | medium | high | high fast"
                )
                continue
            os.environ["HACKBOT_EFFORT"] = level
            if fast is not None:
                os.environ["HACKBOT_CURSOR_FAST"] = "1" if fast else "0"
                close_cursor_agent()
            mode, label = _resolve_mode()
            msg = f"effort -> {level}"
            if fast is True:
                msg += " + fast"
            elif fast is False:
                msg += " + standard (nofast)"
            ui.success(msg)
            continue

        if text.startswith("/fast"):
            arg = text[len("/fast") :].strip().lower()
            if arg in {"on", "1", "true", "yes"}:
                os.environ["HACKBOT_CURSOR_FAST"] = "1"
                close_cursor_agent()
                ui.success("cursor fast: ON")
            elif arg in {"off", "0", "false", "no"}:
                os.environ["HACKBOT_CURSOR_FAST"] = "0"
                close_cursor_agent()
                ui.success("cursor fast: OFF (standard)")
            else:
                cur = os.environ.get("HACKBOT_CURSOR_FAST", "").strip().lower() in {
                    "1",
                    "true",
                    "yes",
                    "on",
                }
                ui.kv("fast", "on" if cur else "off")
                ui.info("set with:  /fast on | off   (Cursor ModelSelection param)")
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
            ui.info("provider: /providers  /provider <name>  (/codex /cursor /local)")
            ui.info("model:    /models  /models refresh  /model <id>  (unknown ids rejected)")
            ui.info("effort:   /effort <auto|low|medium|high>[ fast]   /fast on|off")
            ui.info("stream:   /stream on|off   (live reasoning)")
            ui.info("step:     /step on|off     (off = hunt until finding/budget)")
            ui.info("verbose:  /verbose on|off  (full tool panels)")
            ui.info("codex:    /codex-write     (toggle codex file changes; on by default)")
            ui.info("cursor:   /model grok-4.5 | composer-2.5 | auto")
            ui.info("          /effort high fast   — real ModelSelection params")
            ui.info("          after each turn: 'used model …' proves SDK selection")
            ui.info("          HACKBOT_CURSOR_TOOLS=1  CustomTool loop (SCOPE/approve)")
            ui.info("          HACKBOT_CURSOR_MODE=plan|agent  (default agent if tools on)")
            ui.info(
                "shortcuts:/target  /hunt  /session  /yolo  /step  /force  /status  /tools  /config"
            )
            ui.info("lab:     stack_prepare / burp_ensure / lab_exec  (sudo: .hackbot/sudo_pass)")
            ui.info("stack:    /tools  (httpx/katana/nuclei/ffuf + HexStrike/Burp health)")
            ui.info("session:  /clear  /exit   (Ctrl+C cancels a running turn)")
            continue

        # "não pausa / até achar" → full hunt (step mode off) for this session.
        maybe_disable_from_prompt(text)
        _run_turn(mode, text, session)
        ui.console.print()
