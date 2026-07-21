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
from .force import is_forced
from .hunt_memory import Candidate, HuntMemory, HuntState
from .identity import load_identity
from .policy_guard import ScopePolicy, host_from_target
from .surface import map_surface, normalize_seed, seed_candidates_from_surface
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


def request_stop() -> None:
    global _STOP_REQUESTED
    _STOP_REQUESTED = True


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

    state = HuntState(
        phase="observe",
        prompt=prompt,
        host=host,
        budget_remaining=budget_total,
        budget_total=budget_total,
        acts_done=0,
        failures=0,
        stopped=False,
    )
    memory.save_state(state)

    auto_approve: ApproveFn = lambda _d: True
    tool_approve = auto_approve if approve_session else approve_fn

    findings_logged: list[str] = []
    acts: list[dict[str, Any]] = []

    ui.rule("hunt start")
    ui.kv("host", host)
    ui.kv("budget", str(budget_total))
    ui.kv("approve_session", str(approve_session))

    # --- Observe: map surface first ---
    state.phase = "observe"
    memory.save_state(state)
    surface_raw = map_surface(
        target_dir,
        seed,
        approve=approve_session,
        force=force_flag,
    )
    memory.append_attempt(
        {
            "phase": "observe",
            "module": "recon",
            "url": seed,
            "outcome": "ok" if surface_raw.get("ok") else "error",
            "detail": surface_raw,
        }
    )
    if approve_session:
        state.budget_remaining -= 1
        state.acts_done += 1
    acts.append({"module": "recon", "result": surface_raw})

    # Seed baseline candidates from surface + always-on modules
    _seed_queue(memory, host, seed)

    # Always try secrets early (chaining source)
    queue = _decide(memory, host, seed)

    while state.budget_remaining > 0 and not state.stopped and not _STOP_REQUESTED:
        state.phase = "decide"
        memory.save_state(state)

        if not queue:
            queue = _decide(memory, host, seed)
        if not queue:
            state.stopped = True
            state.stop_reason = "no more hypotheses"
            break

        hyp = queue.pop(0)
        if _already_attempted(memory, hyp):
            continue

        state.phase = "act"
        memory.save_state(state)
        ui.info(f"act [{hyp.module}] {hyp.title}")

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
        acts.append({"module": hyp.module, "result": act_result})

        memory.append_attempt(
            {
                "phase": "act",
                "module": hyp.module,
                "url": hyp.url,
                "outcome": act_result.get("outcome") or "done",
                "detail": act_result.get("summary") or "",
            }
        )

        # Chaining: inject follow-ups from this result
        for follow in _chain_from_result(hyp, act_result, memory, host):
            if not _already_attempted(memory, follow):
                queue.append(follow)
        queue.sort(key=lambda h: -h.priority)

        # Validate if signal
        if act_result.get("signal"):
            state.phase = "validate"
            memory.save_state(state)
            cand = Candidate(
                id=memory.next_candidate_id(),
                module=hyp.module,
                title=hyp.title,
                url=hyp.url,
                detail=str(act_result.get("summary") or ""),
                params=dict(hyp.params or {}),
                status="pending",
            )
            memory.upsert_candidate(cand)
            vr = validate_and_log(
                target_dir,
                cand,
                observed=str(act_result.get("summary") or act_result.get("detail") or ""),
                impact=f"Autonomous hunt signal for {hyp.module}",
            )
            if vr.ok and vr.finding_id:
                findings_logged.append(vr.finding_id)
            state.budget_remaining -= 1
            state.acts_done += 1

        if act_result.get("hard_fail"):
            state.failures += 1
            if state.failures >= CIRCUIT_BREAKER:
                state.stopped = True
                state.stop_reason = "circuit breaker (target failures)"
                break

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
    except Exception:  # noqa: BLE001
        chains = {}

    try:
        from .learning import ingest_from_hunt

        learned = ingest_from_hunt(target_dir, program=Path(target_dir).name)
        acts.append({"module": "learn_ingest", "result": learned})
    except Exception:  # noqa: BLE001
        learned = {}

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


def _decide(memory: HuntMemory, host: str, seed: str) -> list[Hypothesis]:
    ideas: list[Hypothesis] = []

    # Always-on pack (priority order) — boost from cross-program learning
    try:
        from .learning import suggest_for_host

        learned = suggest_for_host(host).get("suggestions") or []
    except Exception:  # noqa: BLE001
        learned = []
    boost = {s["module"]: int(s.get("score") or 0) for s in learned if isinstance(s, dict)}

    origin = seed if "://" in seed else f"https://{host}"
    parsed = urlparse(origin)
    origin_base = f"{parsed.scheme}://{parsed.netloc}"

    ideas.append(
        Hypothesis(
            module="secrets",
            url=seed,
            title="Secrets / credential leak scan",
            priority=95 + boost.get("secrets", 0),
        )
    )
    ideas.append(
        Hypothesis(
            module="discover_paths",
            url=origin_base,
            title="Content discovery / path fuzz",
            priority=88 + boost.get("discover_paths", 0),
        )
    )
    ideas.append(
        Hypothesis(
            module="recon",
            url=seed,
            title="Surface already mapped — skip if done",
            priority=5,
        )
    )

    for idea in seed_candidates_from_surface(memory):
        ideas.append(
            Hypothesis(
                module=str(idea["module"]),
                url=str(idea["url"]),
                title=str(idea["title"]),
                priority=int(idea.get("priority") or 50),
                params=dict(idea.get("params") or {}),
            )
        )

    # Login guesses
    ideas.append(
        Hypothesis(
            module="auth-bypass",
            url=origin_base + "/login",
            title="Auth-bypass at /login",
            priority=65 + boost.get("auth-bypass", 0),
        )
    )
    ideas.append(
        Hypothesis(
            module="rate-limit",
            url=seed,
            title="Bounded rate-limit probe",
            priority=30 + boost.get("rate-limit", 0),
        )
    )
    ideas.append(
        Hypothesis(
            module="analyze_headers",
            url=seed,
            title="Security headers fingerprint",
            priority=85 + boost.get("analyze_headers", 0),
        )
    )
    ideas.append(
        Hypothesis(
            module="cors",
            url=seed,
            title="CORS Origin reflection",
            priority=60 + boost.get("cors", 0),
        )
    )
    ideas.append(
        Hypothesis(
            module="mine_params",
            url=seed,
            title="Hidden parameter mining",
            priority=58 + boost.get("mine_params", 0),
        )
    )
    ideas.append(
        Hypothesis(
            module="graphql",
            url=origin_base + "/graphql",
            title="GraphQL introspection",
            priority=62 + boost.get("graphql", 0),
        )
    )
    ideas.append(
        Hypothesis(
            module="open_redirect",
            url=seed,
            title="Open redirect probe",
            priority=52 + boost.get("open_redirect", 0),
            params={"param": "next"},
        )
    )
    ideas.append(
        Hypothesis(
            module="lfi",
            url=seed,
            title="LFI / path traversal",
            priority=54 + boost.get("lfi", 0),
            params={"param": "file"},
        )
    )
    ideas.append(
        Hypothesis(
            module="ssti",
            url=seed,
            title="SSTI math canary",
            priority=53 + boost.get("ssti", 0),
            params={"param": "q"},
        )
    )
    ideas.append(
        Hypothesis(
            module="ssrf",
            url=seed,
            title="SSRF param probe",
            priority=56 + boost.get("ssrf", 0),
            params={"param": "url"},
        )
    )
    ideas.append(
        Hypothesis(
            module="race",
            url=seed,
            title="Bounded race / parallel burst",
            priority=48 + boost.get("race", 0),
        )
    )

    # Filter already attempted / validated
    pending = []
    for hyp in ideas:
        if hyp.module == "recon":
            continue  # recon done at start
        if _already_attempted(memory, hyp):
            continue
        pending.append(hyp)

    pending.sort(key=lambda h: -h.priority)
    # Cap queue growth
    return pending[:40]


def _already_attempted(memory: HuntMemory, hyp: Hypothesis) -> bool:
    key = f"{hyp.module}|{hyp.url}|{(hyp.params or {}).get('param', '')}"
    for row in memory.recent_attempts(80):
        if row.get("phase") != "act":
            continue
        prev = (
            f"{row.get('module')}|{row.get('url')}|"
            f"{(row.get('params') or {}).get('param', '') if isinstance(row.get('params'), dict) else ''}"
        )
        # attempts don't always store params — match module+url
        if row.get("module") == hyp.module and row.get("url") == hyp.url:
            return True
        if prev == key:
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
        session_a = "A" if "A" in ready else sessions[0]
        session_b = "B" if "B" in ready else sessions[1]
        raw = execute_tool(
            "idor_probe",
            {
                "target_dir": target_s,
                "url": hyp.url,
                "session_a": session_a,
                "session_b": session_b,
                "param": (hyp.params or {}).get("param") or "",
                "swap_value": (hyp.params or {}).get("swap_value") or "",
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
        signal = False
        for step in data.get("steps") or []:
            out = str(step.get("result") or "").lower()
            if "200" in out and ("token" in out or "session" in out or "success" in out):
                signal = True
        return {
            "outcome": "done",
            "signal": signal,
            "summary": "auth-bypass probes done" + (" (interesting)" if signal else ""),
            "detail": data,
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
        return {
            "outcome": "found" if data.get("signal") else "clean",
            "signal": bool(data.get("signal")),
            "summary": str(data.get("reason") or "xxe"),
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
    if hyp.module == "discover_paths":
        # Fresh paths may unlock IDOR/authz targets
        for ep in memory.endpoints():
            if ep.source == "discover_paths" and (ep.has_id_param() or re.search(r"/\d+(?:/|$)", ep.url)):
                follows.append(
                    Hypothesis(
                        module="idor",
                        url=ep.url,
                        title=f"IDOR after discovery — {ep.url}",
                        priority=91,
                    )
                )
    if hyp.module == "secrets" and result.get("signal"):
        origin = hyp.url if "://" in hyp.url else f"https://{host}"
        parsed = urlparse(origin)
        base = f"{parsed.scheme}://{parsed.netloc}"
        follows.append(
            Hypothesis(
                module="auth-bypass",
                url=base + "/login",
                title="Auth-bypass after secrets hit",
                priority=88,
            )
        )
        # Promote IDOR if we have id-like endpoints
        for ep in memory.endpoints():
            if ep.has_id_param() or re.search(r"/\d+(?:/|$)", ep.url):
                follows.append(
                    Hypothesis(
                        module="idor",
                        url=ep.url,
                        title=f"IDOR after secrets — {ep.url}",
                        priority=92,
                    )
                )
    if hyp.module == "auth-bypass" and result.get("signal"):
        for ep in memory.endpoints():
            if ep.has_id_param():
                follows.append(
                    Hypothesis(
                        module="idor",
                        url=ep.url,
                        title=f"IDOR after auth signal — {ep.url}",
                        priority=93,
                    )
                )
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
