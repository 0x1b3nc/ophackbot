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
            # Independent re-hit as anonymous (negative control) then with label
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
            rehit_info["negative"] = json.loads(neg) if isinstance(neg, str) else neg
            pos = execute_tool(
                "http_request",
                {
                    "target_dir": str(target_dir),
                    "url": candidate.url,
                    "session": "A",
                    "approve": True,
                    "force": force,
                    "label": "validate_rehit",
                },
            )
            rehit_info["rehit"] = json.loads(pos) if isinstance(pos, str) else pos
            proof = proof + "\n\nrehit=" + json.dumps(rehit_info)[:1500]
        except Exception as exc:  # noqa: BLE001
            rehit_info["error"] = f"{type(exc).__name__}: {exc}"

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
        }
    )
    return ValidationResult(
        True,
        "validated",
        finding_id=finding_id,
        evidence=evidence_path,
        detail=proof[:300],
    )


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
    candidate = Candidate(
        id=memory.next_candidate_id("BR"),
        module="idor",
        title=f"Possible IDOR/BOLA via A/B browser diff on {url}",
        url=url,
        detail=observed[:500],
        params={"session_a": session_a, "session_b": session_b, "source": "browser_diff"},
        status="pending",
    )
    memory.upsert_candidate(candidate)
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
    cid = memory.next_candidate_id("CAMP")
    candidate = Candidate(
        id=cid,
        module=str(row.get("id") or "campaign"),
        title=str(row.get("label") or row.get("id") or "campaign hit"),
        url=host,
        detail=str(row.get("summary") or ""),
        status="pending",
    )
    memory.upsert_candidate(candidate)
    return validate_and_log(
        target_dir,
        candidate,
        observed=str(row.get("summary") or "campaign FOUND"),
        impact=f"Campaign module {row.get('id')} reported FOUND",
    )
