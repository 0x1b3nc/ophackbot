"""Target-local workflow harness — YAML under hunt/workflows/.

Steps: request | extract | mutate | assert | tool
Dry-run by default; ACTIVE requires approve. SCOPE gates every request URL.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Callable
import yaml

from . import ui
from .coverage_map import mark_coverage_url
from .policy_guard import ScopePolicy, host_from_target

ApproveFn = Callable[[str], bool]

ROOT = Path(__file__).resolve().parents[1]


def workflows_dir(target_dir: Path) -> Path:
    return Path(target_dir) / "hunt" / "workflows"


def state_dir(target_dir: Path) -> Path:
    return workflows_dir(target_dir) / "_state"


def list_workflows(target_dir: Path) -> list[str]:
    d = workflows_dir(target_dir)
    if not d.is_dir():
        return []
    return sorted(p.stem for p in d.glob("*.yaml") if p.is_file())


def load_workflow(target_dir: Path, workflow_id: str) -> dict[str, Any]:
    wid = (workflow_id or "").strip().removesuffix(".yaml")
    if not wid or "/" in wid or "\\" in wid or ".." in wid:
        raise ValueError(f"invalid workflow id: {workflow_id!r}")
    path = workflows_dir(target_dir) / f"{wid}.yaml"
    if not path.is_file():
        raise FileNotFoundError(f"workflow not found: {path}")
    data = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    if not isinstance(data, dict):
        raise ValueError("workflow YAML must be a mapping")
    data.setdefault("id", wid)
    data["_path"] = str(path)
    return data


def _subst(text: str, vars_: dict[str, Any]) -> str:
    out = str(text)
    for key, val in vars_.items():
        out = out.replace("{" + str(key) + "}", str(val))
    return out


def _subst_obj(obj: Any, vars_: dict[str, Any]) -> Any:
    if isinstance(obj, str):
        return _subst(obj, vars_)
    if isinstance(obj, list):
        return [_subst_obj(x, vars_) for x in obj]
    if isinstance(obj, dict):
        return {k: _subst_obj(v, vars_) for k, v in obj.items()}
    return obj


def _jsonpath_get(data: Any, path: str) -> Any:
    """Tiny jsonpath subset: $.a.b[0].c"""
    if not path or not path.startswith("$"):
        return None
    cur = data
    token = path[1:]
    # split on . but keep [n]
    parts = re.findall(r"\.([A-Za-z0-9_]+)|\[(\d+)\]", token)
    if path == "$":
        return data
    for name, idx in parts:
        if name:
            if not isinstance(cur, dict):
                return None
            cur = cur.get(name)
        else:
            if not isinstance(cur, (list, tuple)):
                return None
            try:
                cur = cur[int(idx)]
            except (IndexError, ValueError):
                return None
    return cur


def _extract_from_body(
    body: str,
    *,
    jsonpath: str = "",
    regex: str = "",
    group: int = 1,
) -> Any:
    if jsonpath:
        try:
            data = json.loads(body) if body.strip() else None
        except json.JSONDecodeError:
            data = None
        if data is not None:
            return _jsonpath_get(data, jsonpath)
    if regex:
        m = re.search(regex, body or "", re.I | re.S)
        if not m:
            return None
        try:
            return m.group(group)
        except IndexError:
            return m.group(0)
    return None


def preview_workflow(wf: dict[str, Any]) -> dict[str, Any]:
    steps = wf.get("steps") or []
    return {
        "ok": True,
        "id": wf.get("id"),
        "class": wf.get("class"),
        "aggression_max": wf.get("aggression_max", 2),
        "accounts": wf.get("accounts") or [],
        "vars": wf.get("vars") or {},
        "stop_on": wf.get("stop_on") or [],
        "cleanup_steps": len(wf.get("cleanup") or []),
        "steps": [
            {
                "id": s.get("id") or f"step_{i}",
                "kind": s.get("kind") or "request",
                "account": s.get("account"),
                "title": s.get("title") or s.get("id"),
            }
            for i, s in enumerate(steps)
            if isinstance(s, dict)
        ],
        "path": wf.get("_path"),
    }


def _save_state(target_dir: Path, workflow_id: str, state: dict[str, Any]) -> Path:
    d = state_dir(target_dir)
    d.mkdir(parents=True, exist_ok=True)
    path = d / f"{workflow_id}.json"
    path.write_text(json.dumps(state, indent=2, ensure_ascii=False), encoding="utf-8")
    return path


def load_state(target_dir: Path, workflow_id: str) -> dict[str, Any] | None:
    path = state_dir(target_dir) / f"{workflow_id}.json"
    if not path.is_file():
        return None
    try:
        return json.loads(path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        return None


def run_workflow(
    target_dir: Path,
    workflow_id: str,
    *,
    approve: bool = False,
    force: bool = False,
    approve_fn: ApproveFn | None = None,
    execute_tool: Callable[..., str] | None = None,
    max_steps: int = 40,
) -> dict[str, Any]:
    """Execute or dry-run a workflow. SCOPE + approve rails preserved."""
    from .tools import _RESPONSE_CACHE, _cache_key, _require_approval, execute_tool as _exec

    exec_fn = execute_tool or _exec
    target = Path(target_dir)
    if not target.is_absolute():
        target = ROOT / target
    wf = load_workflow(target, workflow_id)
    wid = str(wf.get("id") or workflow_id)
    preview = preview_workflow(wf)
    vars_: dict[str, Any] = dict(wf.get("vars") or {})
    vars_.setdefault("target_dir", str(target))
    agg_max = int(wf.get("aggression_max") or 2)
    cls = str(wf.get("class") or "workflow")

    if not approve:
        ui.dry_run_banner()
        plan_steps = []
        for i, step in enumerate(wf.get("steps") or []):
            if not isinstance(step, dict):
                continue
            kind = step.get("kind") or "request"
            req = _subst_obj(step.get("request") or {}, vars_)
            plan_steps.append(
                {
                    "id": step.get("id") or f"step_{i}",
                    "kind": kind,
                    "account": step.get("account"),
                    "request": req if kind == "request" else None,
                    "assert": step.get("assert"),
                    "dry_run": True,
                }
            )
            url = (req or {}).get("url") if isinstance(req, dict) else None
            if url:
                mark_coverage_url(
                    target,
                    cls=cls,
                    url=str(url),
                    method=str((req or {}).get("method") or "GET"),
                    authz=str(step.get("account") or ""),
                    status="dry",
                    note=f"workflow:{wid}",
                )
        state = {
            "workflow_id": wid,
            "status": "dry-run",
            "vars": vars_,
            "steps": plan_steps,
            "updated": datetime.now(timezone.utc).isoformat(),
        }
        sp = _save_state(target, wid, state)
        return {
            "ok": True,
            "executed": False,
            "message": "dry-run",
            "preview": preview,
            "plan": plan_steps,
            "state_path": str(sp),
            "aggression_max": agg_max,
        }

    # ACTIVE path — one operator approve for the whole workflow
    host_hint = ""
    for step in wf.get("steps") or []:
        if isinstance(step, dict) and (step.get("request") or {}).get("url"):
            host_hint = host_from_target(
                _subst(str(step["request"]["url"]), vars_)
            )
            break
    refusal = _require_approval(
        approve_fn,
        f"Approve ACTIVE workflow?\n  id={wid}\n  class={cls}\n  "
        f"steps={len(wf.get('steps') or [])}\n  host={host_hint or '?'}\n  "
        f"aggression_max={agg_max}\n  force={force}",
        kind="active_traffic",
        tool="workflow_run",
        host=host_hint,
        force_override=force,
        aggression=agg_max,
    )
    if refusal:
        try:
            return json.loads(refusal)
        except Exception:  # noqa: BLE001
            return {"ok": False, "error": refusal, "kind": "denied"}

    def _auto_allow(_desc: str) -> bool:
        return True

    policy = ScopePolicy.load(target)
    results: list[dict[str, Any]] = []
    last_label = ""
    stopped = False
    stop_reason = ""

    steps = list(wf.get("steps") or [])[:max_steps]
    for i, step in enumerate(steps):
        if not isinstance(step, dict):
            continue
        sid = str(step.get("id") or f"step_{i}")
        kind = str(step.get("kind") or "request").lower()
        account = step.get("account")
        step_res: dict[str, Any] = {"id": sid, "kind": kind, "ok": True}

        try:
            if kind == "mutate":
                mut = step.get("mutate") or step.get("set") or {}
                if isinstance(mut, dict):
                    for k, v in mut.items():
                        vars_[str(k)] = _subst_obj(v, vars_)
                step_res["vars"] = {k: vars_[k] for k in list(mut) if isinstance(mut, dict)}
            elif kind == "extract":
                label = str(step.get("label") or last_label)
                cached = _RESPONSE_CACHE.get(_cache_key(target, label)) or {}
                body = str(cached.get("body") or cached.get("text") or "")
                for ex in step.get("extract") or []:
                    if not isinstance(ex, dict):
                        continue
                    name = str(ex.get("name") or "")
                    if not name:
                        continue
                    val = _extract_from_body(
                        body,
                        jsonpath=str(ex.get("jsonpath") or ""),
                        regex=str(ex.get("regex") or ""),
                        group=int(ex.get("group") or 1),
                    )
                    vars_[name] = val
                    step_res.setdefault("extracted", {})[name] = val
            elif kind == "request":
                req = _subst_obj(dict(step.get("request") or {}), vars_)
                url = str(req.get("url") or "")
                if not url:
                    raise ValueError(f"step {sid}: request.url required")
                # Hard SCOPE gate before traffic
                policy.assert_action_allowed(
                    url,
                    action=f"workflow {wid} {sid}",
                    force=force,
                    tool="http_request",
                )
                label = str(req.get("label") or sid)
                last_label = label
                call_args = {
                    "target_dir": str(target),
                    "url": url,
                    "method": str(req.get("method") or "GET"),
                    "session": str(account or req.get("session") or ""),
                    "body": req.get("body") or "",
                    "content_type": req.get("content_type") or "",
                    "label": label,
                    "approve": True,
                    "force": force,
                }
                if not call_args["session"]:
                    call_args.pop("session")
                if not call_args["body"]:
                    call_args.pop("body")
                if not call_args["content_type"]:
                    call_args.pop("content_type")
                raw = exec_fn("http_request", call_args, approve_fn=_auto_allow)
                try:
                    payload = json.loads(raw)
                except Exception:  # noqa: BLE001
                    payload = {"ok": False, "raw": raw[:500]}
                step_res["http"] = {
                    k: payload.get(k)
                    for k in ("ok", "status", "error", "kind", "dry_run", "label")
                    if k in payload
                }
                # inline extract after request
                for ex in step.get("extract") or []:
                    if not isinstance(ex, dict):
                        continue
                    name = str(ex.get("name") or "")
                    if not name:
                        continue
                    cached = _RESPONSE_CACHE.get(_cache_key(target, label)) or {}
                    body = str(
                        cached.get("body")
                        or cached.get("text")
                        or payload.get("body")
                        or ""
                    )
                    val = _extract_from_body(
                        body,
                        jsonpath=str(ex.get("jsonpath") or ""),
                        regex=str(ex.get("regex") or ""),
                        group=int(ex.get("group") or 1),
                    )
                    vars_[name] = val
                    step_res.setdefault("extracted", {})[name] = val
                # inline asserts
                ok_assert, assert_detail = _run_asserts(
                    target,
                    step.get("assert") or [],
                    vars_=vars_,
                    last_label=label,
                    exec_fn=exec_fn,
                    approve_fn=_auto_allow,
                )
                step_res["assert"] = assert_detail
                if not ok_assert:
                    step_res["ok"] = False
                    stopped = True
                    stop_reason = "assert_fail"
                mark_coverage_url(
                    target,
                    cls=cls,
                    url=url,
                    method=str(req.get("method") or "GET"),
                    authz=str(account or ""),
                    status="pos" if ok_assert and payload.get("ok") else "active",
                    note=f"workflow:{wid}:{sid}",
                )
            elif kind == "assert":
                ok_assert, assert_detail = _run_asserts(
                    target,
                    step.get("assert") or [],
                    vars_=vars_,
                    last_label=last_label,
                    exec_fn=exec_fn,
                    approve_fn=_auto_allow,
                )
                step_res["assert"] = assert_detail
                if not ok_assert:
                    step_res["ok"] = False
                    stopped = True
                    stop_reason = "assert_fail"
            elif kind == "tool":
                tool_name = str(step.get("tool") or (step.get("tool_call") or {}).get("tool") or "")
                call_args = _subst_obj(
                    dict(
                        step.get("args")
                        or (step.get("tool_call") or {}).get("args")
                        or {}
                    ),
                    vars_,
                )
                call_args.setdefault("target_dir", str(target))
                call_args["approve"] = True
                call_args["force"] = force
                raw = exec_fn(tool_name, call_args, approve_fn=_auto_allow)
                try:
                    step_res["tool_result"] = json.loads(raw)
                except Exception:  # noqa: BLE001
                    step_res["tool_result"] = {"raw": raw[:800]}
            else:
                step_res["ok"] = False
                step_res["error"] = f"unknown kind: {kind}"
                stopped = True
                stop_reason = "bad_step"
        except PermissionError as exc:
            step_res["ok"] = False
            step_res["error"] = str(exc)
            step_res["kind"] = "scope_denied"
            stopped = True
            stop_reason = "out_of_scope"
        except Exception as exc:  # noqa: BLE001
            step_res["ok"] = False
            step_res["error"] = f"{type(exc).__name__}: {exc}"
            stopped = True
            stop_reason = "error"

        results.append(step_res)
        if stopped:
            break

    # cleanup on stop if approved run
    cleanup_results: list[dict[str, Any]] = []
    if stopped or True:
        for c in wf.get("cleanup") or []:
            if not isinstance(c, dict):
                continue
            tool_name = str(c.get("tool") or "http_request")
            call_args = _subst_obj(dict(c.get("args") or {}), vars_)
            call_args.setdefault("target_dir", str(target))
            call_args["approve"] = True
            call_args["force"] = force
            try:
                raw = exec_fn(tool_name, call_args, approve_fn=_auto_allow)
                cleanup_results.append({"tool": tool_name, "ok": True, "raw": raw[:300]})
            except Exception as exc:  # noqa: BLE001
                cleanup_results.append(
                    {"tool": tool_name, "ok": False, "error": str(exc)[:200]}
                )

    state = {
        "workflow_id": wid,
        "status": "stopped" if stopped else "done",
        "stop_reason": stop_reason,
        "vars": vars_,
        "results": results,
        "cleanup": cleanup_results,
        "updated": datetime.now(timezone.utc).isoformat(),
    }
    sp = _save_state(target, wid, state)
    return {
        "ok": not stopped or stop_reason == "assert_fail",
        "executed": True,
        "stopped": stopped,
        "stop_reason": stop_reason,
        "results": results,
        "vars": vars_,
        "cleanup": cleanup_results,
        "state_path": str(sp),
        "preview": preview,
    }


def _run_asserts(
    target: Path,
    asserts: list[Any],
    *,
    vars_: dict[str, Any],
    last_label: str,
    exec_fn: Callable[..., str],
    approve_fn: ApproveFn,
) -> tuple[bool, list[dict[str, Any]]]:
    from .tools import _RESPONSE_CACHE, _cache_key

    details: list[dict[str, Any]] = []
    all_ok = True
    for a in asserts:
        if not isinstance(a, dict):
            continue
        atype = str(a.get("type") or "status").lower()
        detail: dict[str, Any] = {"type": atype}
        ok = True
        if atype == "diff_labels":
            raw = exec_fn(
                "assert_diff",
                {
                    "target_dir": str(target),
                    "label_a": _subst(str(a.get("label_a") or ""), vars_),
                    "label_b": _subst(str(a.get("label_b") or ""), vars_),
                    "kind": str(a.get("kind") or "idor"),
                    "object_hint": str(a.get("object_hint") or ""),
                },
                approve_fn=approve_fn,
            )
            try:
                payload = json.loads(raw)
            except Exception:  # noqa: BLE001
                payload = {"ok": False}
            verdict = str(payload.get("verdict") or "")
            expect = str(a.get("expect_verdict") or "")
            if expect:
                ok = verdict == expect
            else:
                # default: assert ran; caller decides — treat confirmed/likely as signal
                ok = payload.get("ok") is True
            detail["verdict"] = verdict
            detail["payload_ok"] = payload.get("ok")
        else:
            label = _subst(str(a.get("label") or last_label), vars_)
            cached = _RESPONSE_CACHE.get(_cache_key(target, label)) or {}
            status = cached.get("status") or cached.get("status_code")
            body = str(cached.get("body") or cached.get("text") or "")
            if atype == "status":
                want = a.get("equals")
                ok = status is not None and int(status) == int(want)
                detail["status"] = status
                detail["equals"] = want
            elif atype == "regex":
                pat = _subst(str(a.get("pattern") or a.get("regex") or ""), vars_)
                ok = bool(re.search(pat, body, re.I | re.S)) if pat else False
                detail["pattern"] = pat
            elif atype == "jsonpath":
                path = str(a.get("jsonpath") or "")
                try:
                    data = json.loads(body) if body.strip() else None
                except json.JSONDecodeError:
                    data = None
                got = _jsonpath_get(data, path) if data is not None else None
                if "equals" in a:
                    ok = got == a.get("equals")
                else:
                    ok = got is not None
                detail["got"] = got
            elif atype == "var_equals":
                name = str(a.get("name") or "")
                ok = vars_.get(name) == a.get("equals")
                detail["got"] = vars_.get(name)
            else:
                ok = False
                detail["error"] = f"unknown assert type: {atype}"
        detail["ok"] = ok
        if not ok:
            all_ok = False
        details.append(detail)
    return all_ok, details


def reassert_workflow(
    target_dir: Path,
    workflow_id: str,
    *,
    execute_tool: Callable[..., str] | None = None,
) -> dict[str, Any]:
    """Re-run assert steps against saved state / response cache (no traffic)."""
    from .tools import execute_tool as _exec

    exec_fn = execute_tool or _exec
    target = Path(target_dir)
    if not target.is_absolute():
        target = ROOT / target
    wf = load_workflow(target, workflow_id)
    wid = str(wf.get("id") or workflow_id)
    state = load_state(target, wid) or {}
    vars_ = dict(state.get("vars") or wf.get("vars") or {})
    results: list[dict[str, Any]] = []
    all_ok = True
    last_label = ""
    for i, step in enumerate(wf.get("steps") or []):
        if not isinstance(step, dict):
            continue
        kind = str(step.get("kind") or "")
        asserts = step.get("assert") or []
        if kind not in {"assert", "request"} or not asserts:
            continue
        if kind == "request":
            last_label = str((step.get("request") or {}).get("label") or step.get("id") or "")
        ok, detail = _run_asserts(
            target,
            asserts,
            vars_=vars_,
            last_label=last_label,
            exec_fn=exec_fn,
            approve_fn=lambda _d: True,
        )
        results.append({"id": step.get("id") or f"step_{i}", "ok": ok, "assert": detail})
        if not ok:
            all_ok = False
    return {"ok": all_ok, "workflow_id": wid, "results": results, "vars": vars_}
