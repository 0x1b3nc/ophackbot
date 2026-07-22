"""AI/LLM/RAG/MCP security probes — dry-run default, canary payloads, SCOPE-gated."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ..ai_payloads import (
    AiPayload,
    classify_ai_output,
    payloads_for,
    redact_ai_evidence,
)
from ..coverage_map import mark_coverage_url
from . import http_request as http_mod
from .base import RunnerResult, require_in_scope
from .elite_probes import _dry, _gate, _save


def _build_body(prompt_field: str, prompt: str, session_field: str, session: str) -> str:
    payload: dict[str, Any] = {prompt_field or "message": prompt}
    if session_field and session:
        payload[session_field] = session
    # Common chat shapes
    if prompt_field in {"messages", "input"}:
        payload = {
            prompt_field: [{"role": "user", "content": prompt}],
        }
        if session_field and session:
            payload[session_field] = session
    return json.dumps(payload)


def _run_family(
    *,
    tool: str,
    family: str,
    target_dir: Path,
    url: str,
    approve: bool,
    force: bool,
    canary: str,
    session: str,
    prompt_field: str,
    session_field: str,
    method: str,
    max_payloads: int,
    cls: str,
) -> RunnerResult:
    packs = payloads_for(family, limit=max_payloads)
    if canary:
        packs = [
            AiPayload(
                p.family,
                p.text.replace(p.canary, canary),
                canary,
                p.notes,
            )
            for p in packs
        ]
    plan = {
        "url": url,
        "family": family,
        "payload_count": len(packs),
        "canary": canary or (packs[0].canary if packs else ""),
        "session": session,
        "approve": approve,
    }
    early = _gate(
        target_dir,
        url,
        action=f"ai {family} probe",
        approve=approve,
        force=force,
        tool=tool,
        plan=plan,
    )
    if early:
        return early
    results: list[dict[str, Any]] = []
    for p in packs:
        body = p.text if p.family == "mcp" else _build_body(prompt_field, p.text, session_field, session)
        ctype = "application/json"
        result = http_mod.http_request(
            target_dir,
            url,
            method=method.upper() if p.family != "mcp" else "POST",
            session=session or None,
            body=body,
            content_type=ctype,
            approve=True,
            force=force,
            label=f"ai_{family[:12]}",
            extra_headers={"X-Hackbot-Canary": "hb-ai-canary"},
        )
        try:
            payload = json.loads(result.stdout) if result.stdout else {}
        except json.JSONDecodeError:
            payload = {}
        preview = redact_ai_evidence(str(payload.get("body_preview") or ""))
        scored = classify_ai_output(preview, canary=p.canary)
        results.append(
            {
                "canary": p.canary,
                "status": payload.get("status"),
                "outcome": scored["outcome"],
                "severity": scored["severity"],
                "preview": preview[:300],
            }
        )
    best = next(
        (r for r in results if r["outcome"] not in {"blocked", "inconclusive"}),
        results[0] if results else {"outcome": "inconclusive", "severity": "Info"},
    )
    out = {
        "ok": True,
        "tool": tool,
        "family": family,
        "results": results,
        "outcome": best.get("outcome"),
        "severity": best.get("severity"),
    }
    path = _save(target_dir, tool, out)
    if path:
        out["evidence"] = path
    status = "pos" if best.get("outcome") in {
        "canary_returned",
        "cross_tenant_signal",
        "tool_executed",
        "system_boundary_signal",
    } else "neg"
    mark_coverage_url(target_dir, cls=cls, url=url, method=method, status=status, note=tool)
    return RunnerResult([tool, url], True, 0, json.dumps(out), "", "executed")


def llm_prompt_probe(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
    canary: str = "",
    session: str = "",
    prompt_field: str = "message",
    session_field: str = "conversation_id",
    method: str = "POST",
    max_payloads: int = 3,
) -> RunnerResult:
    return _run_family(
        tool="llm_prompt_probe",
        family="prompt-injection",
        target_dir=target_dir,
        url=url,
        approve=approve,
        force=force,
        canary=canary,
        session=session,
        prompt_field=prompt_field,
        session_field=session_field,
        method=method,
        max_payloads=max_payloads,
        cls="prompt-injection",
    )


def llm_indirect_prompt_probe(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
    canary: str = "",
    session: str = "",
    prompt_field: str = "message",
    session_field: str = "conversation_id",
    method: str = "POST",
    max_payloads: int = 2,
) -> RunnerResult:
    return _run_family(
        tool="llm_indirect_prompt_probe",
        family="indirect-prompt",
        target_dir=target_dir,
        url=url,
        approve=approve,
        force=force,
        canary=canary,
        session=session,
        prompt_field=prompt_field,
        session_field=session_field,
        method=method,
        max_payloads=max_payloads,
        cls="prompt-injection",
    )


def llm_rag_probe(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
    canary: str = "",
    session: str = "",
    prompt_field: str = "message",
    session_field: str = "conversation_id",
    method: str = "POST",
    max_payloads: int = 2,
) -> RunnerResult:
    return _run_family(
        tool="llm_rag_probe",
        family="rag",
        target_dir=target_dir,
        url=url,
        approve=approve,
        force=force,
        canary=canary,
        session=session,
        prompt_field=prompt_field,
        session_field=session_field,
        method=method,
        max_payloads=max_payloads,
        cls="rag",
    )


def llm_tool_abuse_probe(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
    canary: str = "",
    session: str = "",
    prompt_field: str = "message",
    session_field: str = "conversation_id",
    method: str = "POST",
    max_payloads: int = 2,
) -> RunnerResult:
    return _run_family(
        tool="llm_tool_abuse_probe",
        family="tool-abuse",
        target_dir=target_dir,
        url=url,
        approve=approve,
        force=force,
        canary=canary,
        session=session,
        prompt_field=prompt_field,
        session_field=session_field,
        method=method,
        max_payloads=max_payloads,
        cls="agentic",
    )


def llm_tenant_isolation_probe(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
    canary: str = "",
    session: str = "",
    prompt_field: str = "message",
    session_field: str = "conversation_id",
    method: str = "POST",
    max_payloads: int = 1,
) -> RunnerResult:
    return _run_family(
        tool="llm_tenant_isolation_probe",
        family="tenant-isolation",
        target_dir=target_dir,
        url=url,
        approve=approve,
        force=force,
        canary=canary,
        session=session,
        prompt_field=prompt_field,
        session_field=session_field,
        method=method,
        max_payloads=max_payloads,
        cls="llm",
    )


def mcp_agent_probe(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
    canary: str = "hb-canary",
    session: str = "",
    max_payloads: int = 2,
) -> RunnerResult:
    return _run_family(
        tool="mcp_agent_probe",
        family="mcp",
        target_dir=target_dir,
        url=url,
        approve=approve,
        force=force,
        canary=canary,
        session=session,
        prompt_field="message",
        session_field="",
        method="POST",
        max_payloads=max_payloads,
        cls="mcp",
    )


def ai_eval_run(
    target_dir: Path,
    url: str,
    *,
    families: str = "prompt-injection,rag,tool-abuse",
    approve: bool = False,
    force: bool = False,
    canary: str = "",
    session: str = "",
    prompt_field: str = "message",
    session_field: str = "conversation_id",
    method: str = "POST",
    max_payloads: int = 1,
) -> RunnerResult:
    require_in_scope(target_dir, url, action="ai eval run", force=force, tool="ai_eval_run")
    fams = [f.strip() for f in (families or "").split(",") if f.strip()][:6]
    plan = {"url": url, "families": fams, "approve": approve}
    if not approve:
        mark_coverage_url(target_dir, cls="llm", url=url, status="dry", note="ai_eval_run")
        return _dry(["ai_eval_run", url], plan)
    bundle: list[dict[str, Any]] = []
    runners = {
        "prompt-injection": llm_prompt_probe,
        "indirect-prompt": llm_indirect_prompt_probe,
        "rag": llm_rag_probe,
        "tool-abuse": llm_tool_abuse_probe,
        "tenant-isolation": llm_tenant_isolation_probe,
        "mcp": mcp_agent_probe,
        "system-boundary": llm_prompt_probe,
    }
    for fam in fams:
        fn = runners.get(fam)
        if not fn:
            continue
        kwargs: dict[str, Any] = {
            "approve": True,
            "force": force,
            "canary": canary,
            "session": session,
            "max_payloads": max_payloads,
        }
        if fam != "mcp":
            kwargs.update(
                prompt_field=prompt_field,
                session_field=session_field,
                method=method,
            )
        result = fn(target_dir, url, **kwargs)
        try:
            payload = json.loads(result.stdout) if result.stdout else {}
        except json.JSONDecodeError:
            payload = {"raw": result.stdout}
        bundle.append({"family": fam, "outcome": payload.get("outcome"), "detail": payload})
    out = {"ok": True, "evaluations": bundle}
    _save(target_dir, "ai_eval_run", out)
    return RunnerResult(["ai_eval_run", url], True, 0, json.dumps(out), "", "executed")
