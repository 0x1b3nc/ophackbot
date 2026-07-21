"""Autonomous hunt controller: Observe → Decide → Act → Validate loop."""

from __future__ import annotations

import json
import os
import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Callable
from urllib.parse import urlparse

from . import ui
from .audit import log_decision
from .auth_continuity import result_indicates_unauthorized
from .force import is_forced
from .hunt_memory import Candidate, HuntMemory, HuntState
from .hunt_phases import (
    advance_phase,
    allocate_phase_budgets,
    phase_for_module,
    pivot_modules,
    prefer_phase,
)
from .identity import load_identity
from .policy_guard import ScopePolicy, host_from_target, policy_quote_for
from .surface import normalize_seed, seed_candidates_from_surface
from .validator import promote_campaign_row, validate_and_log

ApproveFn = Callable[[str], bool]

DEFAULT_BUDGET = 28
CIRCUIT_BREAKER = 5

_STOP_REQUESTED = False


@dataclass
class Hypothesis:
    module: str
    url: str
    title: str
    priority: int = 50
    params: dict[str, str] | None = None
    aggression: int = 2
    scope_quote: str = ""
    signal_tags: tuple[str, ...] = ()
    method: str = "GET"

    def dedupe_key(self) -> str:
        param = (self.params or {}).get("param", "")
        return f"{self.module}|{self.method}|{self.url}|{param}"


MODULE_AGGRESSION: dict[str, int] = {
    "secrets": 1,
    "discover_paths": 1,
    "analyze_headers": 1,
    "crt_subdomains": 0,
    "wayback_urls": 0,
    "analyze_js": 1,
    "mine_params": 1,
    "cors": 2,
    "open_redirect": 2,
    "graphql": 2,
    "lfi": 2,
    "ssti": 2,
    "xxe": 2,
    "ssrf": 2,
    "xss": 2,
    "sqli": 2,
    "idor": 2,
    "session_bootstrap": 2,
    "auth-bypass": 2,
    "oauth": 2,
    "jwt_active": 2,
    "browser_diff": 2,
    "websocket": 2,
    "race": 3,
    "brute": 3,
    "rate-limit": 3,
    "oob_poll": 1,
    "mass_assignment": 2,
    "second_order_xss": 2,
}

# Only these modules may auto-promote to FINDINGS (setup/recon never do).
FINDING_MODULES: frozenset[str] = frozenset(
    {
        "secrets",
        "idor",
        "ssrf",
        "sqli",
        "xss",
        "lfi",
        "ssti",
        "xxe",
        "cors",
        "open_redirect",
        "graphql",
        "oauth",
        "jwt_active",
        "browser_diff",
        "race",
        "websocket",
        "brute",
        "mass_assignment",
        "second_order_xss",
    }
)

CHAIN_MODULE_MAP: dict[str, str] = {
    "jwt": "jwt_active",
    "idor": "idor",
    "bola": "idor",
    "ssrf": "ssrf",
    "sqli": "sqli",
    "xss": "xss",
    "auth-bypass": "auth-bypass",
    "auth": "auth-bypass",
    "oauth": "oauth",
    "graphql": "graphql",
    "lfi": "lfi",
    "ssti": "ssti",
    "xxe": "xxe",
}


def keep_pause() -> bool:
    return os.environ.get("HACKBOT_HUNT_KEEP_PAUSE", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def log_aggression(
    target_dir: Path,
    *,
    module: str,
    level: int,
    quote: str,
    host: str = "",
    url: str = "",
) -> None:
    """Audit aggression level + SCOPE quote before an act (OPERATING_RULES)."""
    log_decision(
        "ALLOW",
        f"aggression L{level} module={module} quote={quote[:160]}",
        kind="aggression",
        target=str(target_dir),
        tool=module,
        host=host,
        extra={"aggression": level, "url": (url or "")[:120]},
    )


def unauth_only() -> bool:
    return os.environ.get("HACKBOT_HUNT_UNAUTH", "").strip().lower() in {"1", "true", "yes", "on"}


def stop_on_finding() -> bool:
    return os.environ.get("HACKBOT_HUNT_STOP_ON_FINDING", "").strip().lower() in {
        "1",
        "true",
        "yes",
        "on",
    }


def observe_osint_enabled() -> bool:
    raw = os.environ.get("HACKBOT_OBSERVE_OSINT", "1").strip().lower()
    return raw not in {"0", "false", "no", "off"}


def request_stop() -> None:
    global _STOP_REQUESTED
    _STOP_REQUESTED = True


def stop_requested() -> bool:
    return bool(_STOP_REQUESTED)


def clear_stop() -> None:
    global _STOP_REQUESTED
    _STOP_REQUESTED = False


def _budget_default() -> int:
    raw = os.environ.get("HACKBOT_HUNT_BUDGET", "").strip()
    if raw.isdigit():
        return max(5, min(80, int(raw)))
    return DEFAULT_BUDGET


def extract_host_from_prompt(text: str, *, fallback_hosts: tuple[str, ...] = ()) -> str:
    m = re.search(r"https?://[^\s\"'<>]+", text, re.I)
    if m:
        return host_from_target(m.group(0).rstrip(".,;)"))
    m = re.search(
        r"\b((?:[a-z0-9-]+\.)+[a-z]{2,})(?::\d+)?(?:/[^\s]*)?\b",
        text,
        re.I,
    )
    if m:
        return host_from_target(m.group(1))
    if fallback_hosts:
        return fallback_hosts[0]
    return ""


def extract_seed_from_prompt(text: str, *, fallback: str = "") -> str:
    """Prefer a full URL (with port/path) so local labs keep the listen port."""
    m = re.search(r"https?://[^\s\"'<>]+", text, re.I)
    if m:
        return normalize_seed(m.group(0).rstrip(".,;)"))
    host = extract_host_from_prompt(text)
    if host:
        return normalize_seed(host)
    if fallback:
        return normalize_seed(fallback)
    return ""


def hunt_status(target_dir: Path) -> dict[str, Any]:
    try:
        from .hunt_telemetry import rich_hunt_status

        return rich_hunt_status(target_dir)
    except Exception:  # noqa: BLE001
        return HuntMemory(target_dir).status_summary()


def run_hunt(
    target_dir: Path,
    prompt: str,
    *,
    host: str = "",
    approve_session: bool = False,
    budget: int | None = None,
    approve_fn: ApproveFn | None = None,
    force: bool | None = None,
) -> dict[str, Any]:
    """Run the OODA hunt loop until budget/stop/no work."""
    from .tools import execute_tool  # local import avoids cycle

    clear_stop()
    target_dir = Path(target_dir)
    memory = HuntMemory(target_dir)
    force_flag = is_forced() if force is None else force
    budget_total = budget if budget is not None else _budget_default()

    policy = ScopePolicy.load(target_dir)
    seed = ""
    if host and ("://" in host or host.startswith("localhost") or re.match(r"^\d+\.\d+\.\d+\.\d+", host)):
        seed = normalize_seed(host)
    if not seed:
        seed = extract_seed_from_prompt(prompt, fallback="")
    host = host_from_target(seed) if seed else (
        host or extract_host_from_prompt(
            prompt, fallback_hosts=policy.in_scope if policy.structured else ()
        )
    )
    if not seed and host:
        seed = normalize_seed(host)
    if not host:
        return {
            "ok": False,
            "error": "no host — pass a URL/host in the prompt or set SCOPE in-scope hosts",
        }
    try:
        policy.assert_action_allowed(host, "autonomous hunt loop", force=force_flag)
    except PermissionError as exc:
        return {"ok": False, "error": str(exc), "kind": "scope_denied"}

    if approve_session:
        if approve_fn is None:
            log_decision(
                "DENY",
                "hunt session approve missing approver",
                kind="active_traffic",
                tool="run_hunt",
                host=host,
            )
            return {"ok": False, "error": "no approver for session approve"}
        desc = (
            f"Approve AUTONOMOUS HUNT session?\n"
            f"  host={host}\n  budget={budget_total}\n  force={force_flag}\n"
            f"  unauth_only={unauth_only()}\n"
            f"  plan=observe_v2 → secrets/discover → authz/inject (SCOPE-gated)\n"
            f"  prompt={prompt[:120]}"
        )
        if not approve_fn(desc):
            log_decision(
                "DENY",
                desc,
                kind="active_traffic",
                tool="run_hunt",
                host=host,
            )
            return {"ok": False, "error": "operator denied hunt session", "denied": True}
        log_decision(
            "ALLOW",
            desc,
            kind="active_traffic",
            tool="run_hunt",
            host=host,
            extra={"force_override": force_flag, "budget": budget_total},
        )

    phase_budgets = allocate_phase_budgets(budget_total)
    state = HuntState(
        phase="observe",
        prompt=prompt,
        host=host,
        budget_remaining=budget_total,
        budget_total=budget_total,
        acts_done=0,
        failures=0,
        stopped=False,
        hunt_phase="recon",
        phase_budget_recon=phase_budgets.get("recon", 0),
        phase_budget_authz=phase_budgets.get("authz", 0),
        phase_budget_inject=phase_budgets.get("inject", 0),
    )
    memory.save_state(state)

    auto_approve: ApproveFn = lambda _d: True
    tool_approve = auto_approve if approve_session else approve_fn

    findings_logged: list[str] = []
    acts: list[dict[str, Any]] = []

    ui.rule("hunt start")
    ui.kv("host", host)
    ui.kv("budget", str(budget_total))
    ui.kv(
        "phase_budgets",
        f"recon={state.phase_budget_recon} authz={state.phase_budget_authz} "
        f"inject={state.phase_budget_inject}",
    )
    ui.kv("approve_session", str(approve_session))

    # Default: clear sticky pause so a new hunt session can run
    if not keep_pause():
        try:
            from .hunt_telemetry import clear_pause

            clear_pause(target_dir)
        except Exception:  # noqa: BLE001
            pass

    # --- Observe v2: deepen surface before Decide ---
    state.phase = "observe"
    memory.save_state(state)
    from .observe import observe_v2

    surface_raw = observe_v2(
        target_dir,
        seed,
        approve=approve_session,
        force=force_flag,
        execute_tool=execute_tool if approve_session else None,
    )
    memory.append_attempt(
        {
            "phase": "observe",
            "module": "observe_v2",
            "url": seed,
            "outcome": "ok" if surface_raw.get("ok") else "error",
            "detail": {"tags": surface_raw.get("tags"), "endpoints": surface_raw.get("endpoint_count")},
        }
    )
    if approve_session:
        state.budget_remaining -= 1
        state.acts_done += 1
    acts.append({"module": "observe_v2", "result": surface_raw})

    # Seed baseline candidates from surface + always-on modules
    _seed_queue(memory, host, seed)

    # Always try secrets early (chaining source)
    queue = _decide(memory, host, seed, target_dir=target_dir)

    while state.budget_remaining > 0 and not state.stopped and not _STOP_REQUESTED:
        state.phase = "decide"
        memory.save_state(state)

        if not queue:
            queue = _decide(memory, host, seed, target_dir=target_dir)
        # Prefer current hunt_phase; advance when phase budget empty or no work left
        queue = prefer_phase(queue, state.hunt_phase)
        queue, advanced = _apply_phase_gate(state, queue)
        if advanced:
            ui.info(f"hunt phase → {state.hunt_phase}")
            memory.save_state(state)
        if not queue:
            queue = _decide(memory, host, seed, target_dir=target_dir)
            queue = prefer_phase(queue, state.hunt_phase)
            queue, _ = _apply_phase_gate(state, queue)
        if not queue:
            state.stopped = True
            state.stop_reason = "no more hypotheses"
            break

        hyp = queue.pop(0)
        if _already_attempted(memory, hyp):
            continue

        # Skip authz modules in unauth-only mode
        if unauth_only() and hyp.module in {"idor", "session_bootstrap", "browser_diff", "auth-bypass"}:
            continue

        from .hunt_telemetry import is_paused, record_telemetry

        if is_paused(target_dir):
            state.stopped = True
            state.stop_reason = "paused"
            break

        state.phase = "act"
        memory.save_state(state)
        level = hyp.aggression if hyp.aggression else MODULE_AGGRESSION.get(hyp.module, 2)
        quote = hyp.scope_quote or policy_quote_for(policy, level)
        log_aggression(
            target_dir,
            module=hyp.module,
            level=level,
            quote=quote,
            host=host,
            url=hyp.url,
        )
        # Skill-card gate: open playbook metadata before L2+ acts
        if level >= 2:
            try:
                pb_raw = execute_tool("open_playbook", {"task": hyp.module, "endpoint": hyp.url})
                pb = json.loads(pb_raw) if isinstance(pb_raw, str) else {}
                quote = quote or f"playbook:{pb.get('class') or hyp.module}"
                hyp.scope_quote = quote
            except Exception:  # noqa: BLE001
                pass
        ui.info(f"act [L{level}] [{hyp.module}] {hyp.title}")

        try:
            act_result = _act(
                target_dir,
                hyp,
                host=host,
                approve=approve_session,
                force=force_flag,
                approve_fn=tool_approve,
                execute_tool=execute_tool,
            )
            # Mid-hunt auth continuity: 401 → refresh sessions once → retry act
            if (
                approve_session
                and hyp.module != "session_bootstrap"
                and result_indicates_unauthorized(act_result)
            ):
                from .auth_continuity import origin_from_target, refresh_ready_sessions

                base = origin_from_target(hyp.url or host)
                ui.warn(f"auth continuity: 401 on {hyp.module} — refreshing sessions")
                refresh = refresh_ready_sessions(
                    target_dir,
                    base,
                    approve=True,
                    force=force_flag,
                )
                act_result = dict(act_result)
                act_result["auth_refresh"] = {
                    "ok": bool(refresh.get("ok")),
                    "reason": refresh.get("reason"),
                    "needs_setup": bool(refresh.get("needs_setup")),
                }
                if refresh.get("needs_setup"):
                    act_result["outcome"] = "needs_setup"
                    act_result["summary"] = str(
                        refresh.get("hint") or refresh.get("reason") or "mfa_detected"
                    )
                    act_result["detail"] = {
                        **(act_result.get("detail") if isinstance(act_result.get("detail"), dict) else {}),
                        "auth_refresh": refresh,
                    }
                elif refresh.get("ok"):
                    from .auth_continuity import session_smoke as _session_smoke

                    smoke = _session_smoke(
                        target_dir,
                        base,
                        session="A",
                        approve=True,
                        force=force_flag,
                    )
                    act_result["auth_refresh"]["smoke"] = {
                        "ok": smoke.get("ok"),
                        "skipped": smoke.get("skipped"),
                        "reason": smoke.get("reason"),
                    }
                    if smoke.get("ok") is False and not smoke.get("skipped"):
                        ui.warn("auth continuity: refresh ok but whoami smoke failed")
                        act_result["summary"] = str(
                            smoke.get("hint") or smoke.get("reason") or "smoke_failed"
                        )
                    else:
                        ui.info("auth continuity: sessions refreshed — retrying act once")
                        retry = _act(
                            target_dir,
                            hyp,
                            host=host,
                            approve=approve_session,
                            force=force_flag,
                            approve_fn=tool_approve,
                            execute_tool=execute_tool,
                        )
                        retry = dict(retry)
                        retry["auth_refreshed"] = True
                        retry["auth_refresh"] = act_result["auth_refresh"]
                        act_result = retry
                else:
                    ui.warn(
                        f"auth continuity: refresh failed ({refresh.get('reason') or refresh.get('error')})"
                    )
        except PermissionError as exc:
            memory.append_attempt(
                {
                    "phase": "act",
                    "module": hyp.module,
                    "url": hyp.url,
                    "outcome": "scope_denied",
                    "detail": str(exc),
                }
            )
            state.failures += 1
            acts.append({"module": hyp.module, "error": str(exc)})
            if state.failures >= CIRCUIT_BREAKER:
                state.stopped = True
                state.stop_reason = "circuit breaker (scope/failures)"
                break
            continue
        except Exception as exc:  # noqa: BLE001
            memory.append_attempt(
                {
                    "phase": "act",
                    "module": hyp.module,
                    "url": hyp.url,
                    "outcome": "error",
                    "detail": f"{type(exc).__name__}: {exc}",
                }
            )
            state.failures += 1
            acts.append({"module": hyp.module, "error": f"{type(exc).__name__}: {exc}"})
            if state.failures >= CIRCUIT_BREAKER:
                state.stopped = True
                state.stop_reason = "circuit breaker"
                break
            continue

        state.budget_remaining -= 1
        state.acts_done += 1
        _charge_phase_budget(state, hyp.module)
        acts.append({"module": hyp.module, "result": act_result})

        outcome = str(act_result.get("outcome") or "done")
        memory.append_attempt(
            {
                "phase": "act",
                "module": hyp.module,
                "url": hyp.url,
                "method": hyp.method,
                "params": dict(hyp.params or {}),
                "aggression": level,
                "scope_quote": quote[:200],
                "dedupe_key": hyp.dedupe_key(),
                "outcome": outcome,
                "detail": act_result.get("summary") or "",
                "signal": bool(act_result.get("signal")),
                "signal_tags": list(hyp.signal_tags),
                "hunt_phase": state.hunt_phase,
            }
        )

        # Pivot: ban modules that keep coming back clean
        if outcome == "clean" and hyp.module in FINDING_MODULES and not act_result.get("signal"):
            before = _banned_modules(target_dir)
            _bump_clean_count(target_dir, hyp.module, ban_after=3)
            after = _banned_modules(target_dir)
            newly = after - before
            if newly:
                for banned_mod in newly:
                    ui.warn(f"pivot: ban {banned_mod} after clean streak")
                    for pivot_mod in pivot_modules(banned_mod):
                        for follow in _pivot_hypotheses(memory, host, seed, pivot_mod, boost=15):
                            if not _already_attempted(memory, follow):
                                queue.append(follow)

        # Chaining: inject follow-ups from this result + re-rank
        for follow in _chain_from_result(hyp, act_result, memory, host):
            if not _already_attempted(memory, follow):
                queue.append(follow)
        queue = _rerank(queue, act_result)

        try:
            from .hunt_telemetry import record_telemetry

            record_telemetry(
                target_dir,
                {
                    "module": hyp.module,
                    "url": hyp.url,
                    "signal": bool(act_result.get("signal")),
                    "outcome": act_result.get("outcome"),
                    "aggression": level,
                },
            )
        except Exception:  # noqa: BLE001
            pass

        # Validate if signal — setup/recon modules never auto-FINDINGS
        if act_result.get("signal") and hyp.module in FINDING_MODULES:
            state.phase = "validate"
            memory.save_state(state)
            win_params = _winning_params(hyp, act_result)
            cand = memory.new_candidate(
                module=hyp.module,
                title=hyp.title,
                url=hyp.url,
                detail=str(act_result.get("summary") or ""),
                params=win_params,
                status="pending",
            )
            # Soft browser hints stay likely until ownership swap
            verdict = "likely" if hyp.module in {"browser_diff"} else "confirmed"
            detail_obj = act_result.get("detail") if isinstance(act_result.get("detail"), dict) else {}
            nested = detail_obj.get("detail") if isinstance(detail_obj.get("detail"), dict) else detail_obj
            idor_verdict = str(
                nested.get("verdict") or detail_obj.get("verdict") or ""
            ).lower()
            if hyp.module == "idor" and idor_verdict == "likely":
                verdict = "likely"
            if hyp.module == "idor" and idor_verdict in {"inconclusive", "negative"}:
                # Do not promote non-findings
                memory.save_state(state)
                continue
            vr = validate_and_log(
                target_dir,
                cand,
                observed=str(act_result.get("summary") or act_result.get("detail") or ""),
                impact=f"Autonomous hunt signal for {hyp.module}",
                verdict=verdict,
                rehit=True,
                execute_tool=execute_tool if approve_session else None,
                approve=approve_session,
                force=force_flag,
            )
            if vr.ok and vr.finding_id:
                findings_logged.append(vr.finding_id)
                try:
                    from .hunt_resume import evidence_index_append

                    evidence_index_append(
                        target_dir,
                        {
                            "candidate": cand.id,
                            "finding": vr.finding_id,
                            "module": hyp.module,
                            "url": hyp.url,
                            "evidence": vr.evidence,
                        },
                    )
                except Exception:  # noqa: BLE001
                    pass
                if stop_on_finding():
                    state.stopped = True
                    state.stop_reason = f"stop_on_finding:{vr.finding_id}"
                    break
            # Validate uses same act budget slot — do not double-charge

        if act_result.get("hard_fail"):
            state.failures += 1
            if state.failures >= CIRCUIT_BREAKER:
                state.stopped = True
                state.stop_reason = "circuit breaker (target failures)"
                break

        # Mid-hunt: turn top chain edges into hypotheses when we have signals
        if act_result.get("signal") and state.acts_done % 4 == 0:
            for ch in _hypotheses_from_chains(target_dir, host)[:3]:
                if not _already_attempted(memory, ch):
                    queue.append(ch)
            queue = _rerank(queue, act_result)

        memory.save_state(state)

    if _STOP_REQUESTED:
        state.stopped = True
        state.stop_reason = state.stop_reason or "operator /hunt stop"
    if state.budget_remaining <= 0 and not state.stop_reason:
        state.stop_reason = "budget exhausted"

    state.phase = "done"
    # Always attempt chain suggestions from whatever we learned
    try:
        from .chain_builder import build_chains

        chains = build_chains(target_dir)
        acts.append({"module": "build_chains", "result": {"count": chains.get("count")}})
        for ch in _hypotheses_from_chains(target_dir, host)[:5]:
            # Record as suggested next acts in summary only (budget done)
            acts.append({"module": "chain_hyp", "result": {"module": ch.module, "url": ch.url}})
    except Exception:  # noqa: BLE001
        chains = {}

    try:
        from .learning import ingest_from_hunt

        learned = ingest_from_hunt(target_dir, program=Path(target_dir).name)
        acts.append({"module": "learn_ingest", "result": learned})
    except Exception:  # noqa: BLE001
        learned = {}

    # Auto submit-ready drafts (Bugcrowd/VRT by default)
    if findings_logged and approve_session:
        report_plat = (os.environ.get("HACKBOT_REPORT_PLATFORM") or "bugcrowd").strip().lower()
        for fid in findings_logged[:3]:
            try:
                execute_tool(
                    "write_report_draft",
                    {
                        "target_dir": str(target_dir),
                        "finding_id": fid,
                        "platform": report_plat,
                    },
                    approve_fn=tool_approve,
                )
            except Exception:  # noqa: BLE001
                pass

    try:
        from .hunt_resume import write_hunt_resume

        write_hunt_resume(
            target_dir,
            host=host,
            summary=f"stop={state.stop_reason or 'complete'} tags={surface_raw.get('tags')}",
            acts_done=state.acts_done,
            findings=findings_logged,
            failures=[a.get("error", "") for a in acts if a.get("error")][:5],
        )
    except Exception:  # noqa: BLE001
        pass

    state.last_summary = (
        f"acts={state.acts_done} findings={len(findings_logged)} "
        f"chains={chains.get('count', 0)} learned={learned.get('recorded', 0)} "
        f"reason={state.stop_reason or 'complete'}"
    )
    memory.save_state(state)
    clear_stop()

    summary = {
        "ok": True,
        "host": host,
        "approve_session": approve_session,
        "acts_done": state.acts_done,
        "budget_remaining": state.budget_remaining,
        "findings": findings_logged,
        "chains": chains.get("chains") if isinstance(chains, dict) else [],
        "stop_reason": state.stop_reason,
        "surface": surface_raw,
        "status": memory.status_summary(),
        "acts": acts[-12:],
    }
    ui.rule("hunt done")
    ui.kv("acts", str(state.acts_done))
    ui.kv("findings", ", ".join(findings_logged) or "(none)")
    ui.kv("stop", state.stop_reason or "complete")
    log_decision(
        "ALLOW" if approve_session else "INFO",
        f"hunt finished host={host} acts={state.acts_done} findings={len(findings_logged)}",
        kind="hunt",
        tool="run_hunt",
        host=host,
        extra={"stop_reason": state.stop_reason},
    )
    return summary


def _seed_queue(memory: HuntMemory, host: str, seed: str) -> None:
    """Ensure baseline candidates exist for always-on modules."""
    # secrets / rate always considered via decide; just ensure surface host set
    data = memory.load_surface()
    if not data.get("host"):
        data["host"] = host
        memory.save_surface(data)


def _phase_budget_remaining(state: HuntState, phase: str) -> int:
    if phase == "recon":
        return int(state.phase_budget_recon)
    if phase == "authz":
        return int(state.phase_budget_authz)
    return int(state.phase_budget_inject)


def _set_phase_budget(state: HuntState, phase: str, value: int) -> None:
    value = max(0, int(value))
    if phase == "recon":
        state.phase_budget_recon = value
    elif phase == "authz":
        state.phase_budget_authz = value
    else:
        state.phase_budget_inject = value


def _charge_phase_budget(state: HuntState, module: str) -> None:
    phase = phase_for_module(module)
    # Prefer charging the module's phase; if that bucket is empty, charge current hunt_phase
    if _phase_budget_remaining(state, phase) > 0:
        _set_phase_budget(state, phase, _phase_budget_remaining(state, phase) - 1)
    elif _phase_budget_remaining(state, state.hunt_phase) > 0:
        _set_phase_budget(
            state, state.hunt_phase, _phase_budget_remaining(state, state.hunt_phase) - 1
        )


def _apply_phase_gate(state: HuntState, queue: list[Hypothesis]) -> tuple[list[Hypothesis], bool]:
    """Drop/skip work outside current phase when budget remains; advance when empty."""
    advanced = False
    # Advance while current phase has no budget left
    while _phase_budget_remaining(state, state.hunt_phase) <= 0:
        nxt = advance_phase(state.hunt_phase)
        if nxt is None:
            break
        state.hunt_phase = nxt
        advanced = True

    phase = state.hunt_phase
    in_phase = [h for h in queue if phase_for_module(h.module) == phase]
    if in_phase and _phase_budget_remaining(state, phase) > 0:
        # Keep later-phase items for after advance; drop earlier-phase leftovers
        later = [
            h
            for h in queue
            if phase_for_module(h.module) != phase
            and _phase_index(phase_for_module(h.module)) > _phase_index(phase)
        ]
        return prefer_phase(in_phase + later, phase), advanced

    # No work in this phase — advance once and retry partition
    nxt = advance_phase(phase)
    if nxt is None:
        return prefer_phase(queue, phase), advanced
    state.hunt_phase = nxt
    advanced = True
    return prefer_phase(queue, state.hunt_phase), advanced


def _phase_index(phase: str) -> int:
    from .hunt_phases import PHASE_ORDER

    try:
        return PHASE_ORDER.index(phase)
    except ValueError:
        return 99


def _banned_modules(target_dir: Path) -> set[str]:
    neg = Path(target_dir) / "hunt" / "negative_learning.json"
    if not neg.exists():
        return set()
    try:
        return set(json.loads(neg.read_text(encoding="utf-8")).get("banned_modules") or [])
    except Exception:  # noqa: BLE001
        return set()


def _winning_params(hyp: Hypothesis, act_result: dict[str, Any]) -> dict[str, str]:
    """Capture replayable winning-act fields for validator + learning."""
    params = {k: str(v) for k, v in dict(hyp.params or {}).items()}
    params["_method"] = hyp.method or "GET"
    detail_obj = act_result.get("detail") if isinstance(act_result.get("detail"), dict) else {}
    nested = detail_obj.get("detail") if isinstance(detail_obj.get("detail"), dict) else detail_obj
    if isinstance(nested, dict):
        if nested.get("matrix"):
            params["matrix"] = str(nested["matrix"])
        methods = nested.get("methods")
        if isinstance(methods, list) and methods:
            params["methods"] = ",".join(str(m) for m in methods)
        elif nested.get("method"):
            params["methods"] = str(nested["method"])
        if nested.get("param"):
            params.setdefault("param", str(nested["param"]))
        # Best row payload hints
        rows = nested.get("rows") if isinstance(nested.get("rows"), list) else []
        best = next((r for r in rows if r.get("verdict") in {"confirmed", "likely"}), None)
        if isinstance(best, dict) and best.get("method"):
            params["_winning_method"] = str(best["method"])
    params["_winning_summary"] = str(act_result.get("summary") or "")[:400]
    return params


def _pivot_hypotheses(
    memory: HuntMemory,
    host: str,
    seed: str,
    module: str,
    *,
    boost: int = 10,
) -> list[Hypothesis]:
    """Spawn a small set of pivot acts after a module is banned."""
    origin = seed if "://" in seed else f"https://{host}"
    out: list[Hypothesis] = []
    if module not in MODULE_AGGRESSION and module not in FINDING_MODULES:
        return out
    # Prefer endpoints already on surface
    eps = list(memory.endpoints())[:5]
    urls = [e.url for e in eps] or [origin]
    for url in urls[:2]:
        out.append(
            Hypothesis(
                module=module,
                url=url,
                title=f"Pivot after clean ban → {module}",
                priority=70 + boost,
                aggression=MODULE_AGGRESSION.get(module, 2),
                signal_tags=("pivot",),
            )
        )
    return out


def _decide(
    memory: HuntMemory,
    host: str,
    seed: str,
    *,
    target_dir: Path | None = None,
) -> list[Hypothesis]:
    """Build hypothesis queue — evidence-driven, not blind always-ons."""
    ideas: list[Hypothesis] = []
    try:
        from .learning import suggest_for_host, suggest_payload_hints

        learned = suggest_for_host(host).get("suggestions") or []
        payload_hints = suggest_payload_hints(host)
    except Exception:  # noqa: BLE001
        learned = []
        payload_hints = []
    boost = {s["module"]: int(s.get("score") or 0) for s in learned if isinstance(s, dict)}
    hint_by_mod = {
        str(h.get("module")): h for h in payload_hints if isinstance(h, dict) and h.get("module")
    }

    # Negative learning: skip modules marked dead for this host
    banned: set[str] = set()
    if target_dir:
        neg = Path(target_dir) / "hunt" / "negative_learning.json"
        if neg.exists():
            try:
                banned = set(json.loads(neg.read_text(encoding="utf-8")).get("banned_modules") or [])
            except Exception:  # noqa: BLE001
                banned = set()

    from .observe import load_observe_tags

    tags = load_observe_tags(target_dir) if target_dir else set()
    origin = seed if "://" in seed else f"https://{host}"
    parsed = urlparse(origin)
    origin_base = f"{parsed.scheme}://{parsed.netloc}"

    # Early always: secrets + discover
    ideas.append(
        Hypothesis(
            module="secrets",
            url=seed,
            title="Secrets / credential leak scan",
            priority=95 + boost.get("secrets", 0),
            aggression=MODULE_AGGRESSION["secrets"],
        )
    )
    ideas.append(
        Hypothesis(
            module="discover_paths",
            url=origin_base,
            title="Content discovery / path fuzz",
            priority=88 + boost.get("discover_paths", 0),
            aggression=MODULE_AGGRESSION["discover_paths"],
        )
    )
    ideas.append(
        Hypothesis(
            module="analyze_headers",
            url=seed,
            title="Security headers fingerprint",
            priority=85 + boost.get("analyze_headers", 0),
            aggression=1,
        )
    )

    # Session bootstrap if accounts present and A/B missing
    if target_dir and not unauth_only():
        try:
            from .accounts import has_accounts

            ident = load_identity(target_dir)
            ready = set(ident.ready_sessions())
            if has_accounts(target_dir) and not ({"A", "B"} <= ready or len(ready) >= 2):
                ideas.append(
                    Hypothesis(
                        module="session_bootstrap",
                        url=origin_base,
                        title="Bootstrap A/B sessions from accounts.yaml",
                        priority=99,
                        aggression=2,
                        signal_tags=("login",),
                    )
                )
        except Exception:  # noqa: BLE001
            pass

    for idea in seed_candidates_from_surface(memory):
        mod = str(idea["module"])
        if mod in banned:
            continue
        params = dict(idea.get("params") or {})
        method = "GET"
        if mod == "idor":
            method = params.get("method") or "GET"
            url_l = str(idea["url"]).lower()
            # Full BOLA/BFLA write matrix when A/B likely useful
            if any(
                x in url_l
                for x in ("/api/", "order", "user", "account", "graphql", "admin", "profile")
            ):
                if "graphql" in url_l:
                    params.setdefault("methods", "POST")
                    params.setdefault("matrix", "both")
                    params.setdefault(
                        "body",
                        '{"query":"mutation($id:ID!){update(id:$id){id}}","variables":{"id":"1"}}',
                    )
                else:
                    params.setdefault("methods", "GET,PATCH,PUT,DELETE")
                    params.setdefault("matrix", "both")
            else:
                params.setdefault("methods", "GET,PATCH")
                params.setdefault("matrix", "both")
        # Apply cross-program payload/param hints
        ph = hint_by_mod.get(mod)
        if ph:
            if ph.get("param"):
                params.setdefault("param", str(ph["param"]))
            if ph.get("payload") and mod in {"ssrf", "xss", "sqli", "ssti", "lfi", "xxe"}:
                params.setdefault("payload", str(ph["payload"])[:300])
            if ph.get("body") and mod == "idor":
                params.setdefault("body", str(ph["body"])[:500])
        ideas.append(
            Hypothesis(
                module=mod,
                url=str(idea["url"]),
                title=str(idea["title"]),
                priority=int(idea.get("priority") or 50)
                + boost.get(mod, 0)
                + (8 if ph else 0),
                params=params,
                method=method,
                aggression=MODULE_AGGRESSION.get(mod, 2),
            )
        )

    # Conditional seeds from tags / surface
    eps = list(memory.endpoints())
    has_graphql = any("graphql" in e.url.lower() for e in eps) or "graphql" in tags
    has_login = any("login" in e.url.lower() for e in eps) or "login" in tags
    has_ws = any(e.url.startswith("ws") for e in eps) or "websocket" in tags
    has_xml = "xml" in tags or any(".xml" in e.url.lower() or "soap" in e.url.lower() for e in eps)
    has_oauth = any("oauth" in e.url.lower() or "authorize" in e.url.lower() for e in eps)
    has_jwt = any("jwt" in (e.notes or "").lower() or "token" in e.url.lower() for e in eps)

    if has_login and "auth-bypass" not in banned:
        ideas.append(
            Hypothesis(
                module="auth-bypass",
                url=origin_base + "/login",
                title="Auth-bypass at /login",
                priority=65 + boost.get("auth-bypass", 0),
                aggression=2,
            )
        )
    # Sink-gated seeds: only when Observe wrote matching sink tags (or tags/surface agree)
    from .sink_registry import has_sink

    sink_ok = lambda kind: (  # noqa: E731
        not target_dir
        or has_sink(target_dir, kind)
        or kind in tags
        or (kind == "id" and any(e.has_id_param() for e in eps))
        or (kind == "url_like" and any(e.url_like_params() for e in eps))
        or (kind == "graphql" and has_graphql)
        or (kind == "xml" and has_xml)
        or (kind == "websocket" and has_ws)
    )

    if has_graphql and "graphql" not in banned and sink_ok("graphql"):
        gql = next((e.url for e in eps if "graphql" in e.url.lower()), origin_base + "/graphql")
        ideas.append(
            Hypothesis(
                module="graphql",
                url=gql,
                title="GraphQL introspection",
                priority=72 + boost.get("graphql", 0),
                aggression=2,
                signal_tags=("graphql",),
            )
        )
    if has_ws and "websocket" not in banned and sink_ok("websocket"):
        ws = next((e.url for e in eps if e.url.startswith("ws")), f"wss://{host}/ws")
        ideas.append(
            Hypothesis(
                module="websocket",
                url=ws,
                title="Websocket handshake",
                priority=55,
                aggression=2,
            )
        )
    if has_xml and "xxe" not in banned and sink_ok("xml"):
        xml_url = next((e.url for e in eps if "xml" in e.url.lower() or "soap" in e.url.lower()), seed)
        ideas.append(
            Hypothesis(
                module="xxe",
                url=xml_url,
                title="XXE probe on XML sink",
                priority=60,
                aggression=2,
            )
        )
    if has_oauth and "oauth" not in banned:
        ou = next((e.url for e in eps if "oauth" in e.url.lower() or "authorize" in e.url.lower()), seed)
        ideas.append(
            Hypothesis(
                module="oauth",
                url=ou,
                title="OAuth misconfig probe",
                priority=68,
                aggression=2,
            )
        )
    if has_jwt and "jwt_active" not in banned:
        ideas.append(
            Hypothesis(
                module="jwt_active",
                url=seed,
                title="JWT active probe",
                priority=66,
                aggression=2,
            )
        )

    # Mine params / CORS only when we have HTML-ish endpoints
    if eps:
        ideas.append(
            Hypothesis(
                module="mine_params",
                url=seed,
                title="Hidden parameter mining",
                priority=58 + boost.get("mine_params", 0),
                aggression=1,
            )
        )
        ideas.append(
            Hypothesis(
                module="cors",
                url=seed,
                title="CORS Origin reflection",
                priority=60 + boost.get("cors", 0),
                aggression=2,
            )
        )

    # SSRF/LFI/SSTI/second-order XSS only when surface has matching params/sinks
    for ep in eps:
        for p in ep.url_like_params():
            if not sink_ok("url_like"):
                break
            ideas.append(
                Hypothesis(
                    module="ssrf",
                    url=ep.url,
                    title=f"SSRF via {p}",
                    priority=70,
                    params={"param": p},
                    aggression=2,
                )
            )
        for p in ep.params:
            pl = p.lower()
            if pl in {"file", "path", "template", "page", "doc"}:
                ideas.append(
                    Hypothesis(
                        module="lfi",
                        url=ep.url,
                        title=f"LFI via {p}",
                        priority=54,
                        params={"param": p},
                        aggression=2,
                    )
                )
            if pl in {"q", "query", "search", "name", "template"}:
                ideas.append(
                    Hypothesis(
                        module="ssti",
                        url=ep.url,
                        title=f"SSTI via {p}",
                        priority=53,
                        params={"param": p},
                        aggression=2,
                    )
                )
            if pl in {"comment", "message", "bio", "note", "content", "body"}:
                ideas.append(
                    Hypothesis(
                        module="second_order_xss",
                        url=ep.url,
                        title=f"Second-order XSS via {p}",
                        priority=56,
                        params={"param": p, "trigger_url": ep.url},
                        aggression=2,
                    )
                )

    # Browser A/B when sessions ready
    if target_dir and not unauth_only():
        ident = load_identity(target_dir)
        if {"A", "B"} <= set(ident.ready_sessions()):
            ideas.append(
                Hypothesis(
                    module="browser_diff",
                    url=seed,
                    title="Browser A/B soft IDOR",
                    priority=75,
                    aggression=2,
                )
            )

    # OOB poll only when a canary was previously stored by SSRF/XSS
    if (Path(target_dir) / "hunt" / "last_canary.json").exists() if target_dir else False:
        ideas.append(
            Hypothesis(
                module="oob_poll",
                url=seed,
                title="OOB canary poll (stored)",
                priority=40,
                aggression=1,
            )
        )

    pending = []
    seen: set[str] = set()
    for hyp in ideas:
        if hyp.module == "recon" or hyp.module in banned:
            continue
        key = hyp.dedupe_key()
        if key in seen:
            continue
        seen.add(key)
        if _already_attempted(memory, hyp):
            continue
        pending.append(hyp)

    pending.sort(key=lambda h: -h.priority)
    return pending[:40]


def _rerank(queue: list[Hypothesis], act_result: dict[str, Any]) -> list[Hypothesis]:
    """Boost queue items related to last signal."""
    if not act_result.get("signal"):
        queue.sort(key=lambda h: -h.priority)
        return queue
    summary = str(act_result.get("summary") or "").lower()
    for h in queue:
        if h.module in summary or any(t in summary for t in h.signal_tags):
            h.priority += 5
        if act_result.get("outcome") == "needs_setup" and h.module == "session_bootstrap":
            h.priority += 20
    queue.sort(key=lambda h: -h.priority)
    return queue


def _hypotheses_from_chains(target_dir: Path, host: str) -> list[Hypothesis]:
    out: list[Hypothesis] = []
    skip = {"rce", "csrf", "dos", "phishing"}
    try:
        from .chain_builder import build_chains
        from .findings import parse_latest_finding

        chains = build_chains(target_dir)
        # Prefer latest finding endpoint as URL anchor
        finding_url = ""
        try:
            latest = parse_latest_finding(Path(target_dir))
            if latest:
                finding_url = str(latest.get("endpoint") or latest.get("asset") or "")
        except Exception:  # noqa: BLE001
            finding_url = ""
        for edge in (chains.get("chains") or [])[:8]:
            raw_to = str(edge.get("to") or edge.get("module") or "").lower()
            if not raw_to or raw_to in skip:
                continue
            to_mod = CHAIN_MODULE_MAP.get(raw_to, raw_to if raw_to in MODULE_AGGRESSION else "")
            if not to_mod:
                continue
            url = str(edge.get("url") or edge.get("endpoint") or finding_url or "")
            if not url:
                continue
            out.append(
                Hypothesis(
                    module=to_mod,
                    url=url,
                    title=f"Chain follow-up → {to_mod}",
                    priority=80,
                    aggression=MODULE_AGGRESSION.get(to_mod, 2),
                    signal_tags=("chain",),
                )
            )
    except Exception:  # noqa: BLE001
        return []
    return out


def _already_attempted(memory: HuntMemory, hyp: Hypothesis) -> bool:
    key = hyp.dedupe_key()
    terminal = {"found", "clean", "mapped", "ok", "done", "hit", "validated", "rejected", "skipped"}
    soft = {"needs_setup", "error", "failed", "scope_denied"}
    for row in memory.recent_attempts(120):
        if row.get("phase") != "act":
            continue
        outcome = str(row.get("outcome") or "")
        if outcome in soft:
            continue  # allow retry after fixing sessions/accounts
        row_key = row.get("dedupe_key") or (
            f"{row.get('module')}|{row.get('method') or 'GET'}|{row.get('url')}|"
            f"{(row.get('params') or {}).get('param', '') if isinstance(row.get('params'), dict) else ''}"
        )
        if row_key == key and (outcome in terminal or not outcome):
            return True
        if (
            not row.get("dedupe_key")
            and row.get("module") == hyp.module
            and row.get("url") == hyp.url
            and not (hyp.params or {}).get("param")
            and hyp.method == "GET"
            and outcome not in soft
        ):
            return True
    for c in memory.load_candidates():
        if c.module == hyp.module and c.url == hyp.url and c.status in {"validated", "rejected"}:
            return True
    return False


def _act(
    target_dir: Path,
    hyp: Hypothesis,
    *,
    host: str,
    approve: bool,
    force: bool,
    approve_fn: ApproveFn | None,
    execute_tool: Callable[..., str],
) -> dict[str, Any]:
    """Execute one specialist module; return normalized result with optional signal."""
    target_s = str(target_dir)

    if hyp.module == "session_bootstrap":
        raw = execute_tool(
            "session_bootstrap",
            {
                "target_dir": target_s,
                "base_url": hyp.url or host,
                "approve": approve,
                "force": force,
            },
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        if data.get("needs_setup"):
            reason = str(data.get("reason") or "needs_setup")
            if reason == "sso_detected":
                summary = "SSO/IdP detected — operator must complete login (no bypass)"
            else:
                summary = "MFA/2FA detected — operator must complete login"
            return {
                "outcome": "needs_setup",
                "signal": False,
                "summary": summary,
                "detail": data,
                "sso_urls": list((data.get("detect") or {}).get("sso_urls") or data.get("sso_urls") or []),
            }
        # Real success = sessions ready (chainable, NEVER a FINDINGS signal)
        ident = load_identity(target_dir)
        ready = ident.ready_sessions()
        ok = len(ready) >= 1 and bool(data.get("signal") or data.get("ok"))
        # Smoke fail on all rows → do not chain
        rows = data.get("results") or data.get("detail", {}).get("results") or []
        if isinstance(data.get("detail"), dict) and not rows:
            rows = (data.get("detail") or {}).get("results") or []
        smoke_fail = False
        for row in rows if isinstance(rows, list) else []:
            if not isinstance(row, dict):
                continue
            smoke = row.get("smoke") or {}
            if smoke.get("ok") is False and not smoke.get("skipped"):
                smoke_fail = True
                break
            if row.get("reason") == "smoke_failed":
                smoke_fail = True
                break
        chain_ok = ok and not smoke_fail
        return {
            "outcome": "ok" if chain_ok else ("failed" if smoke_fail or not ok else "ok"),
            "signal": False,
            "chain": chain_ok,
            "smoke_ok": None if not rows else (False if smoke_fail else True),
            "summary": (
                f"bootstrap smoke_failed sessions={ready}"
                if smoke_fail
                else f"bootstrap sessions={ready}"
            ),
            "detail": data,
        }

    if hyp.module == "secrets":
        # Prefer origin URL (scheme+host+port) for tools that take a host/base
        scan_base = hyp.url or host
        raw = execute_tool(
            "secrets_scan",
            {"target_dir": target_s, "host": scan_base, "approve": approve, "force": force},
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        hits = int(data.get("hit_count") or 0)
        return {
            "outcome": "found" if hits else "clean",
            "signal": hits > 0,
            "summary": f"secrets hits={hits} kinds={data.get('kinds')}",
            "detail": data,
            "hard_fail": data.get("ok") is False and data.get("kind") == "internal_error",
        }

    if hyp.module == "idor":
        ident = load_identity(target_dir)
        ready = set(ident.ready_sessions())
        if not ({"A", "B"} <= ready or len(ready) >= 2):
            return {
                "outcome": "needs_setup",
                "signal": False,
                "summary": "IDOR needs A/B sessions (load secrets or set_session)",
            }
        sessions = sorted(ready)
        session_a = (hyp.params or {}).get("session_a") or ("A" if "A" in ready else sessions[0])
        session_b = (hyp.params or {}).get("session_b") or ("B" if "B" in ready else sessions[1])
        if session_a not in ready:
            session_a = "A" if "A" in ready else sessions[0]
        if session_b not in ready or session_b == session_a:
            session_b = next((s for s in sessions if s != session_a), sessions[-1])
        raw = execute_tool(
            "idor_probe",
            {
                "target_dir": target_s,
                "url": hyp.url,
                "session_a": session_a,
                "session_b": session_b,
                "param": (hyp.params or {}).get("param") or "",
                "swap_value": (hyp.params or {}).get("swap_value") or "",
                "methods": (hyp.params or {}).get("methods") or hyp.method or "GET",
                "matrix": (hyp.params or {}).get("matrix") or "bola",
                "body": (hyp.params or {}).get("body") or "",
                "approve": approve,
                "force": force,
            },
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        detail = data.get("detail") if isinstance(data.get("detail"), dict) else data
        verdict = str(data.get("verdict") or detail.get("verdict") or "").lower()
        return {
            "outcome": verdict or ("found" if data.get("signal") else "clean"),
            "signal": bool(data.get("signal")) or verdict in {"confirmed", "likely"},
            "summary": f"idor verdict={verdict or data.get('reason')}",
            "detail": data,
        }

    if hyp.module == "discover_paths":
        raw = execute_tool(
            "discover_paths",
            {
                "target_dir": target_s,
                "base_url": hyp.url or host,
                "approve": approve,
                "force": force,
            },
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        return {
            "outcome": "found" if data.get("signal") else "mapped",
            "signal": bool(data.get("signal")),
            "summary": str(data.get("reason") or "discover_paths"),
            "detail": data,
        }

    if hyp.module == "ssrf":
        raw = execute_tool(
            "ssrf_probe",
            {
                "target_dir": target_s,
                "url": hyp.url,
                "param": (hyp.params or {}).get("param") or "url",
                "approve": approve,
                "force": force,
            },
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        return {
            "outcome": "found" if data.get("signal") else "clean",
            "signal": bool(data.get("signal")),
            "summary": str(data.get("reason") or "ssrf"),
            "detail": data,
        }

    if hyp.module == "race":
        raw = execute_tool(
            "race_probe",
            {
                "target_dir": target_s,
                "url": hyp.url,
                "approve": approve,
                "force": force,
                "session": (hyp.params or {}).get("session") or "",
            },
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        return {
            "outcome": "found" if data.get("signal") else "clean",
            "signal": bool(data.get("signal")),
            "summary": str(data.get("reason") or "race"),
            "detail": data,
        }

    if hyp.module in {"websocket", "ws"}:
        raw = execute_tool(
            "websocket_probe",
            {
                "target_dir": target_s,
                "url": hyp.url,
                "approve": approve,
                "force": force,
            },
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        return {
            "outcome": "found" if data.get("signal") else "clean",
            "signal": bool(data.get("signal")),
            "summary": str(data.get("reason") or "websocket"),
            "detail": data,
        }

    if hyp.module == "auth-bypass":
        before = set(load_identity(target_dir).ready_sessions())
        raw = execute_tool(
            "run_playbook",
            {
                "target_dir": target_s,
                "task": "auth-bypass",
                "host": host,
                "endpoint": hyp.url,
                "approve": approve,
                "force": force,
            },
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        after = set(load_identity(target_dir).ready_sessions())
        # Real signal for chaining only (not FINDINGS — new session ≠ vuln)
        signal = len(after - before) > 0 or (len(after) > len(before))
        return {
            "outcome": "ok" if signal else "done",
            "signal": False,
            "chain": signal,
            "summary": "auth-bypass: new session" if signal else "auth-bypass: no new session",
            "detail": data,
        }

    if hyp.module == "browser_diff":
        raw = execute_tool(
            "browser_diff_sessions",
            {
                "target_dir": target_s,
                "url": hyp.url,
                "session_a": "A",
                "session_b": "B",
                "approve": approve,
                "force": force,
                "promote": False,
            },
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        diff = data.get("diff") if isinstance(data.get("diff"), dict) else {}
        soft = bool(
            data.get("signal")
            or data.get("soft_idor")
            or data.get("idor_soft_hint")
            or diff.get("idor_soft_hint")
        )
        return {
            "outcome": "found" if soft else "clean",
            "signal": soft,
            "summary": str(data.get("reason") or ("soft IDOR hint" if soft else "browser_diff clean")),
            "detail": data,
        }

    if hyp.module == "oauth":
        raw = execute_tool(
            "oauth_probe",
            {"target_dir": target_s, "url": hyp.url, "approve": approve, "force": force},
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        return {
            "outcome": "found" if data.get("signal") else "clean",
            "signal": bool(data.get("signal")),
            "summary": str(data.get("reason") or "oauth"),
            "detail": data,
        }

    if hyp.module == "jwt_active":
        token = (hyp.params or {}).get("token") or ""
        raw = execute_tool(
            "jwt_active_probe",
            {
                "target_dir": target_s,
                "url": hyp.url,
                "token": token,
                "approve": approve,
                "force": force,
            },
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        return {
            "outcome": "found" if data.get("signal") else "clean",
            "signal": bool(data.get("signal")),
            "summary": str(data.get("reason") or "jwt_active"),
            "detail": data,
        }

    if hyp.module == "oob_poll":
        canary_path = Path(target_dir) / "hunt" / "last_canary.json"
        if not canary_path.exists():
            return {
                "outcome": "skipped",
                "signal": False,
                "summary": "no stored canary — run ssrf_probe with OOB first",
            }
        try:
            canary = json.loads(canary_path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            return {"outcome": "error", "signal": False, "summary": "bad last_canary.json"}
        from .oob import wait_and_poll

        poll = wait_and_poll(canary, rounds=3, delay_sec=1.0)
        return {
            "outcome": "hit" if poll.get("signal") else "clean",
            "signal": bool(poll.get("signal")),
            "summary": "oob poll stored canary",
            "detail": {"canary": canary, "poll": poll},
        }

    if hyp.module == "brute":
        raw = execute_tool(
            "brute_login",
            {
                "target_dir": target_s,
                "url": hyp.url,
                "username": "test",
                "approve": approve,
                "force": force,
            },
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        return {
            "outcome": "found" if data.get("success") else "clean",
            "signal": bool(data.get("success")),
            "summary": f"brute tried={data.get('tried')} success={data.get('success')}",
            "detail": data,
        }

    if hyp.module in {"rate-limit", "dos"}:
        raw = execute_tool(
            "run_playbook",
            {
                "target_dir": target_s,
                "task": "rate-limit",
                "host": host,
                "endpoint": hyp.url,
                "approve": approve,
                "force": force,
            },
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        return {
            "outcome": "done",
            "signal": False,  # rate findings are informational; don't auto-FINDINGS
            "summary": "rate-limit probe done",
            "detail": data,
        }

    if hyp.module == "sqli":
        raw = execute_tool(
            "sqli_probe",
            {
                "target_dir": target_s,
                "url": hyp.url,
                "param": (hyp.params or {}).get("param") or "id",
                "approve": approve,
                "force": force,
            },
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        detail = data.get("detail") if isinstance(data.get("detail"), dict) else data
        if isinstance(detail, str):
            try:
                detail = json.loads(detail)
            except json.JSONDecodeError:
                detail = data
        signal = bool(data.get("signal") or (isinstance(detail, dict) and detail.get("signal")))
        reason = data.get("reason") or (detail.get("reason") if isinstance(detail, dict) else "")
        return {
            "outcome": "found" if signal else "clean",
            "signal": signal,
            "summary": f"sqli: {reason}",
            "detail": data,
        }

    if hyp.module == "xss":
        raw = execute_tool(
            "xss_probe",
            {
                "target_dir": target_s,
                "url": hyp.url,
                "param": (hyp.params or {}).get("param") or "q",
                "approve": approve,
                "force": force,
            },
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        detail = data.get("detail") if isinstance(data.get("detail"), dict) else data
        if isinstance(detail, str):
            try:
                detail = json.loads(detail)
            except json.JSONDecodeError:
                detail = data
        signal = bool(data.get("signal") or (isinstance(detail, dict) and detail.get("signal")))
        reason = data.get("reason") or (detail.get("reason") if isinstance(detail, dict) else "")
        return {
            "outcome": "found" if signal else "clean",
            "signal": signal,
            "summary": f"xss: {reason}",
            "detail": data,
        }

    if hyp.module == "analyze_headers":
        raw = execute_tool(
            "analyze_headers",
            {"target_dir": target_s, "url": hyp.url, "approve": approve, "force": force},
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        missing = data.get("missing_security") or []
        return {
            "outcome": "done",
            "signal": False,
            "summary": f"headers missing={len(missing)}",
            "detail": data,
        }

    if hyp.module == "cors":
        raw = execute_tool(
            "cors_probe",
            {"target_dir": target_s, "url": hyp.url, "approve": approve, "force": force},
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        return {
            "outcome": "found" if data.get("signal") else "clean",
            "signal": bool(data.get("signal")),
            "summary": str(data.get("reason") or "cors"),
            "detail": data,
        }

    if hyp.module == "mine_params":
        raw = execute_tool(
            "mine_params",
            {"target_dir": target_s, "url": hyp.url, "approve": approve, "force": force},
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        n = int(data.get("found_count") or 0)
        return {
            "outcome": "found" if n else "clean",
            "signal": False,  # params alone aren't a finding
            "summary": f"interesting params={n}",
            "detail": data,
        }

    if hyp.module == "graphql":
        raw = execute_tool(
            "graphql_probe",
            {"target_dir": target_s, "url": hyp.url, "approve": approve, "force": force},
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        return {
            "outcome": "found" if data.get("signal") else "clean",
            "signal": bool(data.get("signal")),
            "summary": str(data.get("reason") or "graphql"),
            "detail": data,
        }

    if hyp.module == "open_redirect":
        raw = execute_tool(
            "open_redirect_probe",
            {
                "target_dir": target_s,
                "url": hyp.url,
                "param": (hyp.params or {}).get("param") or "next",
                "approve": approve,
                "force": force,
            },
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        return {
            "outcome": "found" if data.get("signal") else "clean",
            "signal": bool(data.get("signal")),
            "summary": str(data.get("reason") or "redirect"),
            "detail": data,
        }

    if hyp.module == "lfi":
        raw = execute_tool(
            "lfi_probe",
            {
                "target_dir": target_s,
                "url": hyp.url,
                "param": (hyp.params or {}).get("param") or "file",
                "approve": approve,
                "force": force,
            },
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        return {
            "outcome": "found" if data.get("signal") else "clean",
            "signal": bool(data.get("signal")),
            "summary": str(data.get("reason") or "lfi"),
            "detail": data,
        }

    if hyp.module == "ssti":
        raw = execute_tool(
            "ssti_probe",
            {
                "target_dir": target_s,
                "url": hyp.url,
                "param": (hyp.params or {}).get("param") or "q",
                "approve": approve,
                "force": force,
            },
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        return {
            "outcome": "found" if data.get("signal") else "clean",
            "signal": bool(data.get("signal")),
            "summary": str(data.get("reason") or "ssti"),
            "detail": data,
        }

    if hyp.module == "xxe":
        raw = execute_tool(
            "xxe_probe",
            {"target_dir": target_s, "url": hyp.url, "approve": approve, "force": force},
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        # Negative learning only after repeated cleans (not one-shot ban)
        if not data.get("signal"):
            try:
                _bump_clean_count(target_dir, "xxe", ban_after=3)
            except Exception:  # noqa: BLE001
                pass
        return {
            "outcome": "found" if data.get("signal") else "clean",
            "signal": bool(data.get("signal")),
            "summary": str(data.get("reason") or "xxe"),
            "detail": data,
        }

    if hyp.module == "analyze_js":
        raw = execute_tool(
            "analyze_js",
            {"target_dir": target_s, "url": hyp.url, "approve": approve, "force": force},
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        return {
            "outcome": "mapped",
            "signal": False,
            "summary": str(data.get("message") or "analyze_js"),
            "detail": data,
        }

    if hyp.module == "openapi_ingest":
        try:
            from .openapi_parse import ingest_openapi_text
            from .scoped_http import scoped_fetch_bytes
            from .surface import origin_of

            resp = scoped_fetch_bytes(
                hyp.url,
                target_dir=target_dir,
                action="openapi ingest",
                force=force,
                timeout=12,
                headers={"User-Agent": "hackbot-openapi"},
                max_bytes=500_000,
            )
            text = resp.body.decode("utf-8", errors="replace")
            r = ingest_openapi_text(target_dir, text, base_url=origin_of(hyp.url), host=host)
            r["final_url"] = resp.url
            r["redirect_hops"] = resp.hops
            return {
                "outcome": "mapped",
                "signal": False,
                "chain": int(r.get("seeded") or 0) > 0,
                "summary": f"openapi seeded={r.get('seeded')}",
                "detail": r,
            }
        except PermissionError as exc:
            return {
                "outcome": "scope_denied",
                "signal": False,
                "summary": f"openapi_ingest scope: {exc}",
            }
        except Exception as exc:  # noqa: BLE001
            return {
                "outcome": "error",
                "signal": False,
                "summary": f"openapi_ingest:{type(exc).__name__}",
            }

    if hyp.module == "second_order_xss":
        raw = execute_tool(
            "second_order_xss",
            {
                "target_dir": target_s,
                "url": hyp.url,
                "trigger_url": (hyp.params or {}).get("trigger_url") or hyp.url,
                "param": (hyp.params or {}).get("param") or "comment",
                "method": (hyp.params or {}).get("method") or "POST",
                "approve": approve,
                "force": force,
            },
            approve_fn=approve_fn,
        )
        data = json.loads(raw)
        return {
            "outcome": "found" if data.get("signal") else "clean",
            "signal": bool(data.get("signal")),
            "summary": str(data.get("reason") or "second_order_xss"),
            "detail": data,
        }

    return {"outcome": "skipped", "signal": False, "summary": f"unknown module {hyp.module}"}


def _chain_from_result(
    hyp: Hypothesis,
    result: dict[str, Any],
    memory: HuntMemory,
    host: str,
) -> list[Hypothesis]:
    """Result-driven follow-ups (secrets → auth, id endpoints → idor, etc.)."""
    follows: list[Hypothesis] = []
    detail = result.get("detail") if isinstance(result.get("detail"), dict) else {}

    if hyp.module == "mine_params":
        params: list[Any] = []
        # Tool wrapper nests runner JSON under detail; runner uses "found"
        blob = detail
        if isinstance(blob.get("detail"), dict):
            blob = blob["detail"]
        params = list(blob.get("found") or blob.get("params") or [])
        for p in params[:6]:
            if isinstance(p, dict):
                pname = str(p.get("param") or p.get("name") or "")
            else:
                pname = str(p)
            if not pname:
                continue
            follows.append(
                Hypothesis(
                    module="sqli",
                    url=hyp.url,
                    title=f"SQLi after mine_params — {pname}",
                    priority=70,
                    params={"param": pname},
                )
            )
            follows.append(
                Hypothesis(
                    module="xss",
                    url=hyp.url,
                    title=f"XSS after mine_params — {pname}",
                    priority=65,
                    params={"param": pname},
                )
            )
            if "url" in pname.lower() or pname.lower() in {"url", "uri", "redirect", "next"}:
                follows.append(
                    Hypothesis(
                        module="ssrf",
                        url=hyp.url,
                        title=f"SSRF after mine_params — {pname}",
                        priority=72,
                        params={"param": pname},
                    )
                )

    if hyp.module == "session_bootstrap" and (result.get("signal") or result.get("chain")):
        # Gate IDOR on smoke: fail → no IDOR; skipped/ok → allow
        if result.get("smoke_ok") is not False:
            for ep in memory.endpoints():
                if ep.has_id_param() or re.search(r"/\d+(?:/|$)", ep.url):
                    follows.append(
                        Hypothesis(
                            module="idor",
                            url=ep.url,
                            title=f"IDOR after bootstrap — {ep.url}",
                            priority=94,
                            params={"methods": "GET,PATCH", "matrix": "both"},
                            method="GET",
                        )
                    )
    if hyp.module == "session_bootstrap":
        sso_urls = list(result.get("sso_urls") or [])
        blob = detail if isinstance(detail, dict) else {}
        if not sso_urls:
            sso_urls = list(
                (blob.get("detect") or {}).get("sso_urls")
                or blob.get("sso_urls")
                or []
            )
        if sso_urls or (
            result.get("outcome") == "needs_setup"
            and "sso" in str(result.get("summary") or "").lower()
        ):
            ou = sso_urls[0] if sso_urls else f"https://{host}/oauth/authorize"
            follows.append(
                Hypothesis(
                    module="oauth",
                    url=ou,
                    title="OAuth probe after SSO login surface",
                    priority=88,
                )
            )

    if hyp.module == "graphql" and result.get("signal"):
        # Queue mutation authz if schema exposed
        follows.append(
            Hypothesis(
                module="idor",
                url=hyp.url,
                title="GraphQL mutation authz follow-up",
                priority=90,
                params={
                    "methods": "POST",
                    "matrix": "bfla",
                    "body": '{"query":"mutation { __typename }"}',
                },
                method="POST",
                signal_tags=("graphql",),
            )
        )
        # Object-ID style queries (BOLA via GraphQL variables)
        follows.append(
            Hypothesis(
                module="idor",
                url=hyp.url,
                title="GraphQL BOLA via id variable",
                priority=89,
                params={
                    "methods": "POST",
                    "matrix": "both",
                    "param": "id",
                    "swap_value": "2",
                    "body": '{"query":"query($id:ID!){node(id:$id){id}}","variables":{"id":"1"}}',
                },
                method="POST",
                signal_tags=("graphql", "id"),
            )
        )

    if hyp.module == "discover_paths":
        for ep in memory.endpoints():
            if ep.source == "discover_paths" and (ep.has_id_param() or re.search(r"/\d+(?:/|$)", ep.url)):
                follows.append(
                    Hypothesis(
                        module="idor",
                        url=ep.url,
                        title=f"IDOR after discovery — {ep.url}",
                        priority=91,
                        params={"methods": "GET,PATCH", "matrix": "both"},
                    )
                )
            if any(x in ep.url.lower() for x in ("openapi", "swagger", "api-docs")):
                follows.append(
                    Hypothesis(
                        module="openapi_ingest",
                        url=ep.url,
                        title=f"Ingest OpenAPI — {ep.url}",
                        priority=86,
                    )
                )
        # Negative learning: no interesting paths
        if not result.get("signal") and not (detail.get("detail") or {}).get("hits"):
            pass

    if hyp.module == "secrets" and result.get("signal"):
        origin = hyp.url if "://" in hyp.url else f"https://{host}"
        parsed = urlparse(origin)
        base = f"{parsed.scheme}://{parsed.netloc}"
        # If scan applied LEAKED session, prefer authenticated follow-ups with it
        applied = ""
        blob = detail
        if isinstance(blob.get("detail"), dict):
            blob = blob["detail"]
        applied = str(blob.get("applied_session") or "")
        follows.append(
            Hypothesis(
                module="session_bootstrap",
                url=base,
                title="Bootstrap after secrets",
                priority=97,
            )
        )
        follows.append(
            Hypothesis(
                module="auth-bypass",
                url=base + "/login",
                title="Auth-bypass after secrets hit",
                priority=88,
            )
        )
        for ep in memory.endpoints():
            if ep.has_id_param() or re.search(r"/\d+(?:/|$)", ep.url):
                params = {"methods": "GET,PATCH", "matrix": "both"}
                if applied:
                    params["session_a"] = applied
                follows.append(
                    Hypothesis(
                        module="idor",
                        url=ep.url,
                        title=f"IDOR after secrets — {ep.url}",
                        priority=92,
                        params=params,
                    )
                )
            # Stored XSS candidate after secret/config pages with form-ish params
            for p in ep.params:
                if p.lower() in {"comment", "message", "bio", "note", "content", "body"}:
                    follows.append(
                        Hypothesis(
                            module="second_order_xss",
                            url=ep.url,
                            title=f"Second-order XSS via {p}",
                            priority=70,
                            params={"param": p, "trigger_url": ep.url},
                        )
                    )
    if hyp.module == "auth-bypass" and (result.get("signal") or result.get("chain")):
        for ep in memory.endpoints():
            if ep.has_id_param():
                follows.append(
                    Hypothesis(
                        module="idor",
                        url=ep.url,
                        title=f"IDOR after auth signal — {ep.url}",
                        priority=93,
                        params={"methods": "GET,PATCH", "matrix": "both"},
                    )
                )

    # 401/403 → bootstrap (structured detection + summary fallback)
    summary = str(result.get("summary") or "").lower()
    auth_wall = result_indicates_unauthorized(result) or "403" in summary
    if auth_wall and hyp.module != "session_bootstrap":
        if result.get("auth_refreshed") and not result_indicates_unauthorized(result):
            pass  # refresh+retry already cleared the wall
        else:
            follows.append(
                Hypothesis(
                    module="session_bootstrap",
                    url=f"https://{host}",
                    title="Bootstrap after auth wall",
                    priority=96,
                )
            )
    if result.get("outcome") == "needs_setup" and hyp.module == "session_bootstrap":
        # Keep MFA/SSO visible; do not invent IDOR follow-ups (oauth probe allowed)
        follows = [f for f in follows if f.module != "idor"]
    return follows


def promote_campaign_findings(target_dir: Path, campaign_result: dict[str, Any]) -> list[str]:
    """After run_campaign, promote FOUND rows through the validator."""
    host = str(campaign_result.get("host") or "")
    ids: list[str] = []
    for row in campaign_result.get("modules") or []:
        vr = promote_campaign_row(target_dir, row, host=host)
        if vr and vr.ok and vr.finding_id:
            ids.append(vr.finding_id)
    return ids


def record_negative_learning(target_dir: Path, module: str) -> None:
    """Remember modules that are dead for this target (no graphql, etc.)."""
    path = Path(target_dir) / "hunt" / "negative_learning.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = {"banned_modules": []}
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            data = {"banned_modules": []}
    banned = set(data.get("banned_modules") or [])
    banned.add(module)
    data["banned_modules"] = sorted(banned)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")


def _bump_clean_count(target_dir: Path, module: str, *, ban_after: int = 3) -> None:
    path = Path(target_dir) / "hunt" / "negative_learning.json"
    path.parent.mkdir(parents=True, exist_ok=True)
    data: dict[str, Any] = {"banned_modules": [], "clean_counts": {}}
    if path.exists():
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception:  # noqa: BLE001
            data = {"banned_modules": [], "clean_counts": {}}
    counts = dict(data.get("clean_counts") or {})
    counts[module] = int(counts.get(module) or 0) + 1
    data["clean_counts"] = counts
    if counts[module] >= ban_after:
        banned = set(data.get("banned_modules") or [])
        banned.add(module)
        data["banned_modules"] = sorted(banned)
    path.write_text(json.dumps(data, indent=2), encoding="utf-8")
