"""Structured FINDINGS.md / RESUME.md updates for the hunt loop."""

from __future__ import annotations

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
    """Map FINDINGS fields into write_report_draft args."""
    from .severity import severity_for_class

    endpoint = finding.get("endpoint") or finding.get("asset") or "TBD"
    verdict = finding.get("verdict") or "draft"
    title = finding.get("title") or finding.get("finding_id") or "Finding"
    fid = finding.get("finding_id") or ""
    class_name = finding.get("class") or finding.get("class_name") or "TBD"
    observed = finding.get("observed") or ""
    sev = severity_for_class(class_name)
    steps = (
        f"1. Authenticate as account A and fetch owned object at {endpoint}\n"
        f"2. Replay the same request as account B (ID swap only)\n"
        f"3. Compare responses (verdict={verdict})\n"
        f"4. See FINDINGS.md {fid} and evidence/safe/"
    )
    if observed:
        steps += f"\n\nObserved notes from FINDINGS:\n{observed}"
    impact = finding.get("impact") or (
        "Cross-account access to another user's object (BOLA/IDOR). "
        "Confirm data sensitivity and write paths before final severity."
    )
    if sev.score != "TBD" and "Severity hint" not in impact:
        impact = f"{impact}\n\nSeverity hint: {sev.line()} — {sev.rationale}"
    return {
        "title": f"{fid} {title}".strip() if fid else title,
        "target": endpoint,
        "preconditions": finding.get("preconditions") or "Two in-scope test accounts A and B",
        "steps": steps,
        "impact": impact,
        "evidence": finding.get("evidence") or "See evidence/safe/ and FINDINGS.md",
        "vuln_type": class_name,
        "observed": observed,
        "severity_hint": sev.line(),
        "cvss_vector": sev.vector,
        "severity": sev.severity,
        "cvss_score": sev.score,
    }
