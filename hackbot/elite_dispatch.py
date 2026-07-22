"""Tool dispatch helpers for Elite Upgrade tools (keeps tools.py thinner)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Callable

from .boolparse import parse_bool
from .coverage_map import (
    coverage_summary,
    load_coverage,
    mark_coverage,
    mark_coverage_url,
    untested_priorities,
)
from .force import is_forced
from .fp_signatures import confidence_score, match_fp_signatures
from .policy_guard import host_from_target
from .runners import browser as browser_runner
from .runners import elite_probes
from .workflow_harness import (
    list_workflows,
    load_workflow,
    preview_workflow,
    reassert_workflow,
    run_workflow,
)

ApproveFn = Callable[[str], bool]
ROOT = Path(__file__).resolve().parents[1]


def _target(value: str) -> Path:
    target = Path(value)
    if not target.is_absolute():
        target = ROOT / target
    return target


def _force(args: dict[str, Any]) -> bool:
    if "force" not in args or args.get("force") is None:
        return is_forced()
    if args.get("force") is False:
        return is_forced()
    return bool(parse_bool(args.get("force"), default=False) or is_forced())


def _approve_active(
    approve_fn: ApproveFn | None,
    *,
    tool: str,
    url: str,
    force: bool,
    aggression: int,
    require_approval: Callable[..., str | None],
) -> str | None:
    return require_approval(
        approve_fn,
        f"Approve ACTIVE {tool}?\n  url={url}\n  force={force}",
        kind="active_traffic",
        tool=tool,
        host=host_from_target(url),
        force_override=force,
        aggression=aggression,
    )


def _runner_json(result: Any) -> str:
    try:
        payload = json.loads(result.stdout) if result.stdout else {}
    except json.JSONDecodeError:
        payload = {"raw": result.stdout}
    return json.dumps(
        {
            "ok": True,
            "executed": result.executed,
            "message": result.message,
            **(payload if isinstance(payload, dict) else {"detail": payload}),
        }
    )


def dispatch_elite(
    name: str,
    args: dict[str, Any],
    *,
    approve_fn: ApproveFn | None,
    require_approval: Callable[..., str | None],
) -> str | None:
    """Handle elite tools. Return JSON string, or None if name not elite."""

    if name == "workflow_load":
        target = _target(args["target_dir"])
        wid = (args.get("workflow_id") or "").strip()
        if not wid:
            return json.dumps({"ok": True, "workflows": list_workflows(target)})
        wf = load_workflow(target, wid)
        return json.dumps(preview_workflow(wf))

    if name == "workflow_run":
        target = _target(args["target_dir"])
        return json.dumps(
            run_workflow(
                target,
                args["workflow_id"],
                approve=parse_bool(args.get("approve")),
                force=_force(args),
                approve_fn=approve_fn,
            )
        )

    if name == "workflow_assert":
        target = _target(args["target_dir"])
        return json.dumps(reassert_workflow(target, args["workflow_id"]))

    if name == "coverage_map":
        target = _target(args["target_dir"])
        action = str(args.get("action") or "summary").lower()
        if action == "summary":
            return json.dumps(coverage_summary(target))
        if action == "list":
            data = load_coverage(target)
            return json.dumps({"ok": True, "entries": data.get("entries") or {}})
        if action == "priorities":
            return json.dumps({"ok": True, "priorities": untested_priorities(target)})
        if action == "mark":
            status = str(args.get("status") or "dry")
            if args.get("url"):
                return json.dumps(
                    mark_coverage_url(
                        target,
                        cls=str(args.get("class") or "unknown"),
                        url=str(args["url"]),
                        method=str(args.get("method") or "GET"),
                        param=str(args.get("param") or ""),
                        authz=str(args.get("authz") or ""),
                        status=status,
                        note=str(args.get("note") or ""),
                    )
                )
            return json.dumps(
                mark_coverage(
                    target,
                    cls=str(args.get("class") or "unknown"),
                    method=str(args.get("method") or "GET"),
                    path=str(args.get("path") or "/"),
                    param=str(args.get("param") or ""),
                    authz=str(args.get("authz") or ""),
                    status=status,
                    note=str(args.get("note") or ""),
                )
            )
        return json.dumps({"ok": False, "error": f"unknown action {action}"})

    if name == "hunt_cockpit":
        return json.dumps(_hunt_cockpit(_target(args["target_dir"])))

    if name == "finding_score":
        observed = str(args.get("observed") or "")
        url = str(args.get("url") or "")
        module = str(args.get("module") or "")
        verdict = str(args.get("verdict") or "")
        fp = match_fp_signatures(module=module, observed=observed, url=url, verdict=verdict)
        score = confidence_score(
            module=module,
            verdict=verdict,
            fp=fp,
            has_ownership_diff=parse_bool(args.get("has_ownership_diff")),
        )
        return json.dumps(
            {
                "ok": True,
                "confidence": score,
                "fp": fp,
                "promote_ok": score >= 0.75 and not fp.get("is_fp"),
            }
        )

    if name == "dedupe_findings":
        return json.dumps(
            _dedupe_findings(_target(args["target_dir"]), write=parse_bool(args.get("write")))
        )

    if name == "chain_validate":
        return json.dumps(_chain_validate(_target(args["target_dir"]), args, approve_fn))

    # Browser elite
    browser_map = {
        "browser_map_spa": (
            lambda: browser_runner.browser_map_spa(
                _target(args["target_dir"]),
                args["url"],
                approve=parse_bool(args.get("approve")),
                force=_force(args),
                seed_surface=parse_bool(args.get("seed_surface"), default=True),
            ),
            2,
        ),
        "dom_xss_probe": (
            lambda: browser_runner.dom_xss_probe(
                _target(args["target_dir"]),
                args["url"],
                approve=parse_bool(args.get("approve")),
                force=_force(args),
            ),
            2,
        ),
        "postmessage_probe": (
            lambda: browser_runner.postmessage_probe(
                _target(args["target_dir"]),
                args["url"],
                approve=parse_bool(args.get("approve")),
                force=_force(args),
            ),
            2,
        ),
        "prototype_pollution_probe": (
            lambda: browser_runner.prototype_pollution_probe(
                _target(args["target_dir"]),
                args["url"],
                approve=parse_bool(args.get("approve")),
                force=_force(args),
            ),
            2,
        ),
        "browser_har_seed": (
            lambda: browser_runner.browser_har_seed(
                _target(args["target_dir"]),
                args["url"],
                approve=parse_bool(args.get("approve")),
                force=_force(args),
            ),
            2,
        ),
    }
    if name in browser_map:
        fn, agg = browser_map[name]
        approve = parse_bool(args.get("approve"))
        force = _force(args)
        if approve:
            refusal = _approve_active(
                approve_fn,
                tool=name,
                url=args["url"],
                force=force,
                aggression=agg,
                require_approval=require_approval,
            )
            if refusal:
                return refusal
        return _runner_json(fn())

    # HTTP elite probes
    url_tools = {
        "cache_poison_probe": (elite_probes.cache_poison_probe, 2),
        "http_smuggle_probe": (elite_probes.http_smuggle_probe, 3),
        "host_header_probe": (elite_probes.host_header_probe, 2),
        "absolute_url_probe": (elite_probes.absolute_url_probe, 2),
        "graphql_batch_probe": (elite_probes.graphql_batch_probe, 2),
        "saml_probe": (elite_probes.saml_probe, 2),
        "oidc_probe": (elite_probes.oidc_probe, 2),
        "cdn_origin_hint": (elite_probes.cdn_origin_hint, 1),
        "session_fixation_probe": (elite_probes.session_fixation_probe, 2),
    }
    if name in url_tools:
        runner, agg = url_tools[name]
        approve = parse_bool(args.get("approve"))
        force = _force(args)
        url = args["url"]
        if approve:
            refusal = _approve_active(
                approve_fn,
                tool=name,
                url=url,
                force=force,
                aggression=agg,
                require_approval=require_approval,
            )
            if refusal:
                return refusal
        kwargs: dict[str, Any] = {"approve": approve, "force": force}
        if name == "session_fixation_probe":
            kwargs["login_url"] = str(args.get("login_url") or "")
        return _runner_json(runner(_target(args["target_dir"]), url, **kwargs))

    if name == "graphql_authz_probe":
        approve = parse_bool(args.get("approve"))
        force = _force(args)
        if approve:
            refusal = _approve_active(
                approve_fn,
                tool=name,
                url=args["url"],
                force=force,
                aggression=2,
                require_approval=require_approval,
            )
            if refusal:
                return refusal
        return _runner_json(
            elite_probes.graphql_authz_probe(
                _target(args["target_dir"]),
                args["url"],
                args["query"],
                session_a=str(args.get("session_a") or "A"),
                session_b=str(args.get("session_b") or "B"),
                approve=approve,
                force=force,
            )
        )

    if name == "websocket_authz_probe":
        approve = parse_bool(args.get("approve"))
        force = _force(args)
        if approve:
            refusal = _approve_active(
                approve_fn,
                tool=name,
                url=args["url"],
                force=force,
                aggression=2,
                require_approval=require_approval,
            )
            if refusal:
                return refusal
        return _runner_json(
            elite_probes.websocket_authz_probe(
                _target(args["target_dir"]),
                args["url"],
                message=str(args.get("message") or ""),
                session=str(args.get("session") or ""),
                approve=approve,
                force=force,
            )
        )

    if name == "token_binding_check":
        approve = parse_bool(args.get("approve"))
        force = _force(args)
        if approve:
            refusal = _approve_active(
                approve_fn,
                tool=name,
                url=args["url"],
                force=force,
                aggression=2,
                require_approval=require_approval,
            )
            if refusal:
                return refusal
        return _runner_json(
            elite_probes.token_binding_check(
                _target(args["target_dir"]),
                args["url"],
                session=str(args.get("session") or ""),
                approve=approve,
                force=force,
            )
        )

    if name == "takeover_probe":
        approve = parse_bool(args.get("approve"))
        force = _force(args)
        host = args["host"]
        url = host if "://" in host else f"https://{host}"
        if approve:
            refusal = _approve_active(
                approve_fn,
                tool=name,
                url=url,
                force=force,
                aggression=1,
                require_approval=require_approval,
            )
            if refusal:
                return refusal
        return _runner_json(
            elite_probes.takeover_probe(
                _target(args["target_dir"]), host, approve=approve, force=force
            )
        )

    if name == "ssrf_protocol_matrix":
        approve = parse_bool(args.get("approve"))
        force = _force(args)
        if approve:
            refusal = _approve_active(
                approve_fn,
                tool=name,
                url=args["url"],
                force=force,
                aggression=2,
                require_approval=require_approval,
            )
            if refusal:
                return refusal
        return _runner_json(
            elite_probes.ssrf_protocol_matrix(
                _target(args["target_dir"]),
                args["url"],
                args["param"],
                approve=approve,
                force=force,
            )
        )

    if name == "asset_graph_build":
        return json.dumps(elite_probes.asset_graph_build(_target(args["target_dir"])))

    if name == "burp_watch":
        return json.dumps(
            elite_probes.burp_watch(
                _target(args["target_dir"]), limit=int(args.get("limit") or 40)
            )
        )

    if name == "proxy_correlate":
        return json.dumps(
            elite_probes.proxy_correlate(
                _target(args["target_dir"]),
                limit=int(args.get("limit") or 40),
                seed_surface=parse_bool(args.get("seed_surface"), default=True),
            )
        )

    return None


def _hunt_cockpit(target: Path) -> dict[str, Any]:
    from .hunt_controller import hunt_status
    from .hunt_memory import HuntMemory
    from .hunt_telemetry import prehunt_checklist

    mem = HuntMemory(target)
    surface = mem.endpoints()
    cov = coverage_summary(target)
    status = {}
    try:
        status = hunt_status(target)
    except Exception:  # noqa: BLE001
        status = {}
    checklist = {}
    try:
        checklist = prehunt_checklist(target)
    except Exception:  # noqa: BLE001
        checklist = {}
    prios = untested_priorities(target, limit=5)
    next_step = ""
    if prios:
        p = prios[0]
        next_step = (
            f"hypothesis: {p.get('class')} on {p.get('path')} still {p.get('status')} | "
            f"aggression 2 | tool=workflow_run or idor_probe | expected assert+evidence"
        )
    elif status.get("next_step"):
        next_step = str(status.get("next_step"))
    return {
        "ok": True,
        "surface_size": len(surface),
        "coverage_pct": cov.get("coverage_pct"),
        "coverage_counts": cov.get("counts"),
        "hunt_status": status,
        "checklist": checklist,
        "priorities": prios,
        "next_falsifiable_step": next_step,
        "approvals_pending": "operator approve required for ACTIVE tools (default dry-run)",
    }


def _dedupe_findings(target: Path, *, write: bool = False) -> dict[str, Any]:
    path = target / "FINDINGS.md"
    if not path.is_file():
        return {"ok": True, "duplicates": [], "kept": 0, "message": "no FINDINGS.md"}
    text = path.read_text(encoding="utf-8", errors="replace")
    blocks = re.split(r"(?=^## )", text, flags=re.M)
    seen: set[str] = set()
    kept: list[str] = []
    dups: list[str] = []
    for block in blocks:
        if not block.strip():
            continue
        if not block.startswith("## "):
            kept.append(block)
            continue
        title = block.splitlines()[0][3:].strip()
        cls_m = re.search(r"^- Class:\s*(.+)$", block, re.M)
        ep_m = re.search(r"^- Endpoint:\s*(.+)$", block, re.M)
        key = "|".join(
            [
                (cls_m.group(1).strip().lower() if cls_m else ""),
                (ep_m.group(1).strip().lower() if ep_m else ""),
                title.lower(),
            ]
        )
        if key in seen:
            dups.append(title)
            continue
        seen.add(key)
        kept.append(block)
    if write and dups:
        path.write_text("".join(kept), encoding="utf-8")
    return {
        "ok": True,
        "duplicates": dups,
        "kept": len(seen),
        "wrote": bool(write and dups),
        "path": str(path),
    }


def _chain_validate(
    target: Path, args: dict[str, Any], approve_fn: ApproveFn | None
) -> dict[str, Any]:
    from .tools import execute_tool

    label_a = args.get("label_a")
    label_b = args.get("label_b")
    if label_a and label_b:
        raw = execute_tool(
            "assert_diff",
            {
                "target_dir": str(target),
                "label_a": label_a,
                "label_b": label_b,
                "kind": args.get("kind") or "idor",
            },
            approve_fn=approve_fn,
        )
        try:
            diff = json.loads(raw)
        except json.JSONDecodeError:
            diff = {"ok": False, "raw": raw}
        verdict = str(diff.get("verdict") or "")
        evidence = str(diff.get("evidence") or "")
        passed = verdict in {"confirmed", "likely"} and bool(evidence)
        return {
            "ok": passed,
            "passed": passed,
            "verdict": verdict,
            "evidence": evidence,
            "promote_findings": passed,
            "diff": diff,
            "note": "FINDINGS promotion only when assert+evidence present",
        }
    # Fallback: inspect chains.md presence
    chains = target / "hunt" / "chains.md"
    return {
        "ok": chains.is_file(),
        "passed": False,
        "path": str(chains) if chains.is_file() else "",
        "hint": "Pass label_a + label_b to validate A→B asserts",
        "chain_id": args.get("chain_id") or "",
    }
