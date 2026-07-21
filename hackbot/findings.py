"""Structured FINDINGS.md / RESUME.md updates for the hunt loop."""

from __future__ import annotations

import json
import re
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class Finding:
    finding_id: str
    title: str
    class_name: str
    endpoint: str
    verdict: str
    asset: str
    preconditions: str
    observed: str
    impact: str
    evidence: str
    next_step: str
    status: str = "draft"

    def markdown_block(self) -> str:
        from .severity import severity_for_class

        sev = severity_for_class(self.class_name)
        return "\n".join(
            [
                f"## {self.finding_id} {self.title}",
                "",
                f"- Status: {self.status}",
                f"- Class: {self.class_name}",
                f"- Verdict: {self.verdict}",
                f"- Severity hint: {sev.line()}",
                f"- CVSS hint: {sev.vector or 'TBD'}",
                f"- Asset: {self.asset}",
                f"- Endpoint: {self.endpoint}",
                f"- Preconditions: {self.preconditions}",
                "- Expected: Secure denial (403/404) for cross-account access",
                f"- Observed: {self.observed}",
                f"- Impact: {self.impact}",
                f"- Evidence: {self.evidence}",
                f"- Next step: {self.next_step}",
                "",
            ]
        )


def next_finding_id(findings_text: str) -> str:
    ids = [int(m) for m in re.findall(r"##\s*C-(\d+)", findings_text, re.I)]
    n = max(ids) + 1 if ids else 1
    return f"C-{n:03d}"


def append_finding(target_dir: Path, finding: Finding) -> Path:
    path = Path(target_dir) / "FINDINGS.md"
    if path.exists():
        text = path.read_text(encoding="utf-8", errors="replace")
    else:
        text = "# Findings\n\n"
    if "No confirmed findings yet." in text and finding.verdict in {"confirmed", "likely"}:
        text = text.replace("No confirmed findings yet.\n\n", "")
    block = finding.markdown_block()
    if not text.endswith("\n"):
        text += "\n"
    text += block
    path.write_text(text, encoding="utf-8")
    return path


def parse_finding_by_id(target_dir: Path, finding_id: str = "latest") -> dict[str, Any] | None:
    """Return one FINDINGS block by id, or the latest C-### entry."""
    path = Path(target_dir) / "FINDINGS.md"
    if not path.exists():
        return None
    text = path.read_text(encoding="utf-8", errors="replace")
    blocks = re.split(r"(?=^##\s*C-\d+)", text, flags=re.M)
    latest = None
    wanted = (finding_id or "latest").strip().lower()
    for block in blocks:
        m = re.match(r"##\s*(C-\d+)\s+(.*)", block.strip())
        if not m:
            continue
        fields = {"finding_id": m.group(1), "title": m.group(2).strip()}
        for line in block.splitlines():
            if line.startswith("- ") and ":" in line:
                key, _, val = line[2:].partition(":")
                fields[key.strip().lower().replace(" ", "_")] = val.strip()
        latest = fields
        if wanted not in {"latest", "last", "*", ""} and fields["finding_id"].lower() == wanted:
            return fields
    return latest


def parse_latest_finding(target_dir: Path) -> dict[str, Any] | None:
    return parse_finding_by_id(target_dir, "latest")


def update_resume_next_step(
    target_dir: Path,
    next_step: str,
    *,
    accounts_note: str = "",
) -> Path:
    path = Path(target_dir) / "RESUME.md"
    if path.exists():
        text = path.read_text(encoding="utf-8", errors="replace")
    else:
        text = "# Resume\n\n## Last State\n\n- No work started.\n\n## Accounts\n\n- None.\n\n## Safe Next Step\n\n- TBD\n"

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    text = _replace_section_bullets(
        text,
        "safe next step",
        [next_step],
    )
    if accounts_note:
        text = _replace_section_bullets(text, "accounts", [accounts_note])
    text = _replace_section_bullets(
        text,
        "last state",
        [f"Updated {stamp}", next_step],
    )
    path.write_text(text, encoding="utf-8")
    return path


def _replace_section_bullets(text: str, heading_substr: str, bullets: list[str]) -> str:
    lines = text.splitlines()
    out: list[str] = []
    i = 0
    replaced = False
    while i < len(lines):
        line = lines[i]
        stripped = line.strip().lower()
        if stripped.startswith("##") and heading_substr in stripped.lstrip("#").strip():
            out.append(line)
            i += 1
            # skip existing bullets / blank until next heading
            while i < len(lines) and not lines[i].strip().startswith("##"):
                i += 1
            out.append("")
            for b in bullets:
                out.append(f"- {b}")
            out.append("")
            replaced = True
            continue
        out.append(line)
        i += 1
    if not replaced:
        out.append("")
        out.append(f"## {heading_substr.title()}")
        out.append("")
        for b in bullets:
            out.append(f"- {b}")
        out.append("")
    return "\n".join(out).rstrip() + "\n"


def report_fields_from_finding(finding: dict[str, Any]) -> dict[str, str]:
    """Map FINDINGS fields into write_report_draft args (submit-ready PoC)."""
    from .severity import severity_for_class, vrt_for_class

    endpoint = finding.get("endpoint") or finding.get("asset") or "TBD"
    verdict = finding.get("verdict") or "draft"
    title = finding.get("title") or finding.get("finding_id") or "Finding"
    fid = finding.get("finding_id") or ""
    class_name = finding.get("class") or finding.get("class_name") or "TBD"
    observed = finding.get("observed") or ""
    sev = severity_for_class(class_name)
    vrt = vrt_for_class(class_name)
    evidence_path = finding.get("evidence") or ""
    win = _load_evidence_blob(evidence_path)
    params = win.get("params") if isinstance(win.get("params"), dict) else {}
    methods = str(params.get("methods") or params.get("_winning_method") or "GET")
    matrix = str(params.get("matrix") or "bola")
    param = str(params.get("param") or "")
    rehit = win.get("rehit") if isinstance(win.get("rehit"), dict) else {}
    winning = rehit.get("winning_replay") if isinstance(rehit.get("winning_replay"), dict) else {}
    neg = rehit.get("negative") if isinstance(rehit.get("negative"), dict) else {}

    steps = _minimal_poc_steps(
        class_name=class_name,
        endpoint=endpoint,
        methods=methods,
        matrix=matrix,
        param=param,
        verdict=verdict,
        fid=fid,
        winning=winning,
        negative=neg,
        observed=observed,
    )
    impact = finding.get("impact") or (
        f"Potential {class_name} on {endpoint}. Confirm data sensitivity and "
        "write/mutation impact before final severity."
    )
    if sev.score != "TBD" and "Severity hint" not in impact:
        impact = f"{impact}\n\nSeverity hint: {sev.line()} — {sev.rationale}"
    impact = f"{impact}\n\nVRT hint: {vrt}"
    evidence_block = evidence_path or "See evidence/safe/ and FINDINGS.md"
    if winning.get("verdict") or winning.get("signal") is not None:
        evidence_block += (
            f"\n\nWinning replay: verdict={winning.get('verdict')} "
            f"signal={winning.get('signal')} methods={winning.get('methods')}"
        )
    if neg:
        evidence_block += (
            f"\nNegative control (unauth): status={neg.get('status') or neg.get('ok')}"
        )
    return {
        "title": f"{fid} {title}".strip() if fid else title,
        "target": endpoint,
        "preconditions": finding.get("preconditions")
        or "Authorized program; in-scope host; two test accounts A/B when authz",
        "steps": steps,
        "impact": impact,
        "evidence": evidence_block,
        "vuln_type": class_name,
        "vrt": vrt,
        "observed": observed,
        "severity_hint": sev.line(),
        "cvss_vector": sev.vector,
        "severity": sev.severity,
        "cvss_score": sev.score,
    }


def _load_evidence_blob(path: str) -> dict[str, Any]:
    if not path:
        return {}
    try:
        p = Path(path)
        if not p.is_file():
            return {}
        data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        return data if isinstance(data, dict) else {}
    except Exception:  # noqa: BLE001
        return {}


def _minimal_poc_steps(
    *,
    class_name: str,
    endpoint: str,
    methods: str,
    matrix: str,
    param: str,
    verdict: str,
    fid: str,
    winning: dict[str, Any],
    negative: dict[str, Any],
    observed: str,
) -> str:
    cls = (class_name or "").lower()
    lines: list[str] = [
        f"## Minimal PoC ({cls or 'issue'})",
        f"1. Target: `{endpoint}`",
        f"2. Method(s): `{methods}`  matrix=`{matrix}`"
        + (f"  param=`{param}`" if param else ""),
    ]
    if cls in {"idor", "bola", "bac", "bfla", "authz", "browser_diff"}:
        lines.extend(
            [
                "3. Authenticate as account **A**; capture a request to an object A owns.",
                "4. Replay the **exact** request as account **B** (BOLA). "
                "Also try privileged method/path as B (BFLA) and ID swap when applicable.",
                "5. Confirm B receives A's object / succeeds on write (negative: unauth denied).",
            ]
        )
    elif cls in {"ssrf", "xxe", "xss"}:
        lines.extend(
            [
                "3. Inject the OOB/Interactsh (or marked) payload into the sink parameter.",
                "4. Trigger the request; poll Collaborator/Interactsh for DNS/HTTP hit.",
                "5. Negative control: same request without the payload shows no OOB hit.",
            ]
        )
    else:
        lines.extend(
            [
                "3. Send the proving request (see evidence JSON winning_replay).",
                "4. Compare against negative control (unauthenticated / benign input).",
                "5. Capture response diff that demonstrates impact.",
            ]
        )
    lines.append(f"6. Finding id `{fid}` verdict=`{verdict}` — attach redacted evidence.")
    if winning.get("reason"):
        lines.append(f"\nWinning act reason: {winning.get('reason')}")
    if negative:
        lines.append(
            f"Negative control note: status/ok={negative.get('status', negative.get('ok'))}"
        )
    if observed:
        lines.append(f"\nObserved notes:\n{observed[:1200]}")
    return "\n".join(lines)
