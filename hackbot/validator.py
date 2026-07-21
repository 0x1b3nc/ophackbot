"""Validate hunt candidates before they become FINDINGS."""

from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from . import ui
from .evidence import EvidenceStore
from .findings import Finding, append_finding, next_finding_id, update_resume_next_step
from .hunt_memory import Candidate, HuntMemory
from .redaction import StrictRedactError


@dataclass(frozen=True)
class ValidationResult:
    ok: bool
    status: str  # validated | rejected | needs_setup | skipped
    finding_id: str = ""
    evidence: str = ""
    detail: str = ""


def _findings_text(target_dir: Path) -> str:
    path = Path(target_dir) / "FINDINGS.md"
    if not path.exists():
        return ""
    return path.read_text(encoding="utf-8", errors="replace")


def validate_and_log(
    target_dir: Path,
    candidate: Candidate,
    *,
    observed: str,
    impact: str = "",
    write_finding: bool = True,
    write_resume: bool = True,
    verdict: str = "confirmed",
    rehit: bool = False,
    execute_tool: Any = None,
    approve: bool = False,
    force: bool = False,
) -> ValidationResult:
    """Prove a candidate and optionally append FINDINGS.md.

    Rules:
    - Requires non-empty evidence path or observed proof text
    - Rejects empty / speculative claims
    - Optional independent re-hit + negative control before FINDINGS
    - Dedup by sink fingerprint (module+url)
    - verdict defaults to confirmed; use 'likely' for soft signals
    """
    memory = HuntMemory(target_dir)
    proof = (observed or candidate.detail or "").strip()
    if not proof and not candidate.evidence:
        candidate.status = "rejected"
        candidate.detail = "no reproducible proof"
        memory.upsert_candidate(candidate)
        return ValidationResult(False, "rejected", detail="no reproducible proof")

    # Dedup: same module+url already in FINDINGS
    existing = _findings_text(target_dir).lower()
    sink_fp = f"{candidate.module}|{candidate.url}".lower()
    if candidate.url and candidate.url.lower() in existing and candidate.module.lower() in existing:
        candidate.status = "rejected"
        candidate.detail = "duplicate_sink"
        memory.upsert_candidate(candidate)
        return ValidationResult(False, "rejected", detail="duplicate_sink")

    rehit_info: dict[str, Any] = {}
    if rehit and execute_tool and candidate.url and approve:
        try:
            rehit_info = _replay_winning_act(
                execute_tool,
                target_dir,
                candidate,
                force=force,
            )
            # Blind classes: correlate stored OOB / Interactsh canary
            if candidate.module in {"ssrf", "xxe", "xss"}:
                oob = _correlate_oob(execute_tool, target_dir)
                if oob is not None:
                    rehit_info["oob"] = oob
                    if oob.get("signal") or oob.get("hit") or oob.get("interactions"):
                        proof = proof + "\n\noob_correlated=true"
            proof = proof + "\n\nrehit=" + json.dumps(rehit_info, default=str)[:2000]
        except Exception as exc:  # noqa: BLE001
            rehit_info["error"] = f"{type(exc).__name__}: {exc}"

    from .fp_signatures import confidence_score, match_fp_signatures

    fp = match_fp_signatures(
        module=candidate.module,
        observed=proof,
        url=candidate.url,
        verdict=verdict,
    )
    ownership = "distinct body" in proof.lower() or "owner" in proof.lower() or "json_leak" in proof.lower()
    score = confidence_score(
        module=candidate.module,
        verdict=verdict,
        rehit=rehit_info or None,
        fp=fp,
        has_ownership_diff=ownership,
    )
    # Evidence gate: confirmed only at high confidence
    final_verdict = verdict
    if fp.get("is_fp") and score < 0.75:
        candidate.status = "rejected"
        candidate.detail = f"fp_signature:{fp.get('reason')} score={score}"
        memory.upsert_candidate(candidate)
        try:
            from .hunt_telemetry import record_telemetry

            record_telemetry(
                target_dir,
                {"module": candidate.module, "signal": False, "outcome": "fp_rejected", "confidence": score},
            )
        except Exception:  # noqa: BLE001
            pass
        return ValidationResult(False, "rejected", detail=candidate.detail)
    if score < 0.75:
        final_verdict = "likely"
    if score < 0.45:
        candidate.status = "rejected"
        candidate.detail = f"low_confidence:{score}"
        memory.upsert_candidate(candidate)
        return ValidationResult(False, "rejected", detail=candidate.detail)
    if score >= 0.75 and final_verdict == "likely" and candidate.module == "idor":
        # Keep likely unless ownership proof present
        pass
    elif score >= 0.75 and verdict == "confirmed":
        final_verdict = "confirmed"
    verdict = final_verdict

    # Persist evidence artifact
    evidence_path = candidate.evidence
    try:
        blob = json.dumps(
            {
                "candidate_id": candidate.id,
                "module": candidate.module,
                "url": candidate.url,
                "title": candidate.title,
                "observed": proof[:8000],
                "params": candidate.params,
                "verdict": verdict,
                "sink_fingerprint": sink_fp,
                "rehit": rehit_info,
                "confidence": score,
                "fp": fp,
            },
            indent=2,
        )
        path = EvidenceStore(target_dir).save(f"validate_{candidate.id}.json", blob)
        evidence_path = str(path)
    except StrictRedactError as exc:
        candidate.status = "rejected"
        candidate.detail = f"evidence redaction failed: {exc}"
        memory.upsert_candidate(candidate)
        return ValidationResult(False, "rejected", detail=str(exc))

    candidate.evidence = evidence_path
    candidate.detail = proof[:500]
    candidate.status = "validated"
    memory.upsert_candidate(candidate)

    finding_id = ""
    if write_finding:
        from .severity import severity_for_class

        sev = severity_for_class(candidate.module)
        fid = next_finding_id(_findings_text(target_dir))
        finding = Finding(
            finding_id=fid,
            title=candidate.title or f"{candidate.module} on {candidate.url}",
            class_name=candidate.module or "unknown",
            endpoint=candidate.url,
            verdict=verdict if verdict in {"confirmed", "likely", "draft"} else "likely",
            asset=candidate.url,
            preconditions="Authorized hunt; SCOPE + session approve",
            observed=proof[:1000],
            impact=impact
            or (
                f"Potential {candidate.module} issue — operator triage required. "
                f"Severity hint: {sev.line()}"
            ),
            evidence=evidence_path,
            next_step="Triage severity and draft platform report",
            status="draft",
        )
        append_finding(target_dir, finding)
        finding_id = fid
        ui.success(f"FINDINGS: {fid} ({candidate.module}, verdict={finding.verdict})")
        if write_resume:
            update_resume_next_step(
                target_dir,
                f"Triage {fid} and decide report vs further chaining",
            )

    memory.append_attempt(
        {
            "phase": "validate",
            "module": candidate.module,
            "url": candidate.url,
            "outcome": "validated",
            "finding_id": finding_id,
            "evidence": evidence_path,
            "verdict": verdict,
            "confidence": score,
        }
    )
    try:
        from .hunt_telemetry import record_telemetry

        record_telemetry(
            target_dir,
            {
                "module": candidate.module,
                "signal": True,
                "outcome": "validated",
                "confidence": score,
                "verdict": verdict,
                "finding_id": finding_id,
            },
        )
    except Exception:  # noqa: BLE001
        pass
    return ValidationResult(
        True,
        "validated",
        finding_id=finding_id,
        evidence=evidence_path,
        detail=proof[:300],
    )


def _parse_tool_json(raw: Any) -> dict[str, Any]:
    if isinstance(raw, dict):
        return raw
    if isinstance(raw, str):
        try:
            data = json.loads(raw)
            return data if isinstance(data, dict) else {"raw": raw[:500]}
        except json.JSONDecodeError:
            return {"raw": raw[:500]}
    return {}


def _replay_winning_act(
    execute_tool: Any,
    target_dir: Path,
    candidate: Candidate,
    *,
    force: bool,
) -> dict[str, Any]:
    """Replay the winning act (class-aware) + anonymous negative control."""
    params = dict(candidate.params or {})
    info: dict[str, Any] = {"module": candidate.module, "url": candidate.url}

    # Negative control: unauthenticated GET
    neg = execute_tool(
        "http_request",
        {
            "target_dir": str(target_dir),
            "url": candidate.url,
            "approve": True,
            "force": force,
            "label": "validate_neg",
        },
    )
    info["negative"] = _parse_tool_json(neg)

    mod = (candidate.module or "").lower()
    if mod == "idor":
        raw = execute_tool(
            "idor_probe",
            {
                "target_dir": str(target_dir),
                "url": candidate.url,
                "param": params.get("param") or "",
                "swap_value": params.get("swap_value") or "",
                "methods": params.get("methods")
                or params.get("_winning_method")
                or "GET,PATCH",
                "matrix": params.get("matrix") or "both",
                "body": params.get("body") or "",
                "approve": True,
                "force": force,
            },
        )
        info["winning_replay"] = _parse_tool_json(raw)
        return info

    probe_map = {
        "ssrf": "ssrf_probe",
        "sqli": "sqli_probe",
        "xss": "xss_probe",
        "lfi": "lfi_probe",
        "ssti": "ssti_probe",
        "xxe": "xxe_probe",
        "cors": "cors_probe",
        "open_redirect": "open_redirect_probe",
        "graphql": "graphql_probe",
        "race": "race_probe",
        "mass_assignment": "mass_assignment_probe",
    }
    tool = probe_map.get(mod)
    if tool:
        args: dict[str, Any] = {
            "target_dir": str(target_dir),
            "url": candidate.url,
            "approve": True,
            "force": force,
        }
        if params.get("param"):
            args["param"] = params["param"]
        if params.get("payload"):
            args["payload"] = params["payload"]
        try:
            raw = execute_tool(tool, args)
            info["winning_replay"] = _parse_tool_json(raw)
            return info
        except Exception as exc:  # noqa: BLE001
            info["winning_replay_error"] = f"{type(exc).__name__}: {exc}"

    # Fallback: authenticated GET as session A
    pos = execute_tool(
        "http_request",
        {
            "target_dir": str(target_dir),
            "url": candidate.url,
            "session": "A",
            "method": params.get("_winning_method") or params.get("_method") or "GET",
            "approve": True,
            "force": force,
            "label": "validate_rehit",
        },
    )
    info["rehit"] = _parse_tool_json(pos)
    return info


def _correlate_oob(execute_tool: Any, target_dir: Path) -> dict[str, Any] | None:
    canary_path = Path(target_dir) / "hunt" / "last_canary.json"
    if not canary_path.exists():
        return None
    try:
        canary = json.loads(canary_path.read_text(encoding="utf-8"))
    except Exception:  # noqa: BLE001
        canary = {}
    if not isinstance(canary, dict):
        canary = {}
    try:
        raw = execute_tool("interactsh_poll", {"wait": False, "canary": canary})
        data = _parse_tool_json(raw)
        data["canary_present"] = True
        return data
    except Exception:
        try:
            raw = execute_tool("oob_poll", {"canary": canary})
            data = _parse_tool_json(raw)
            data["canary_present"] = True
            return data
        except Exception as exc:  # noqa: BLE001
            return {"error": f"{type(exc).__name__}: {exc}", "canary_present": True}


def promote_browser_diff(
    target_dir: Path,
    *,
    url: str,
    diff: dict[str, Any],
    snap_a: dict[str, Any],
    snap_b: dict[str, Any],
    session_a: str = "A",
    session_b: str = "B",
    write_finding: bool = True,
) -> ValidationResult | None:
    """Auto-promote A/B browser soft IDOR hint → candidate + validator (verdict=likely)."""
    if not (diff or {}).get("idor_soft_hint"):
        return None

    memory = HuntMemory(target_dir)
    # Dedup: skip if same url+module already validated recently
    for c in memory.load_candidates():
        if (
            c.module == "idor"
            and c.url == url
            and c.status == "validated"
            and "browser_diff" in (c.detail or "")
        ):
            return ValidationResult(
                True,
                "skipped",
                finding_id="",
                detail="already validated browser_diff candidate for this URL",
            )

    observed = (
        f"browser_diff soft IDOR hint: sessions {session_a}/{session_b} both got "
        f"2xx with similar bodies on {url}. "
        f"A status={snap_a.get('status')} hash={snap_a.get('body_hash')} len={snap_a.get('body_len')}; "
        f"B status={snap_b.get('status')} hash={snap_b.get('body_hash')} len={snap_b.get('body_len')}. "
        f"status_equal={diff.get('status_equal')} body_hash_equal={diff.get('body_hash_equal')}. "
        "Not a full IDOR proof — operator should confirm ownership swap / assert_diff."
    )
    candidate = memory.new_candidate(
        module="idor",
        title=f"Possible IDOR/BOLA via A/B browser diff on {url}",
        url=url,
        detail=observed[:500],
        params={"session_a": session_a, "session_b": session_b, "source": "browser_diff"},
        status="pending",
        prefix="BR",
    )
    from .severity import severity_for_class

    sev = severity_for_class("idor")
    return validate_and_log(
        target_dir,
        candidate,
        observed=observed,
        impact=(
            "Possible broken object-level authorization: two accounts received similar "
            f"authorized responses for the same URL. Severity hint: {sev.line()}. "
            "Confirm with object ownership swap before final severity."
        ),
        write_finding=write_finding,
        verdict="likely",
    )


def promote_campaign_row(
    target_dir: Path,
    row: dict[str, Any],
    *,
    host: str,
) -> ValidationResult | None:
    """Turn a campaign FOUND row into a validated FINDING (or skip)."""
    if (row.get("status") or "").upper() != "FOUND":
        return None
    memory = HuntMemory(target_dir)
    candidate = memory.new_candidate(
        module=str(row.get("id") or "campaign"),
        title=str(row.get("label") or row.get("id") or "campaign hit"),
        url=host,
        detail=str(row.get("summary") or ""),
        status="pending",
        prefix="CAMP",
    )
    return validate_and_log(
        target_dir,
        candidate,
        observed=str(row.get("summary") or "campaign FOUND"),
        impact=f"Campaign module {row.get('id')} reported FOUND",
    )
