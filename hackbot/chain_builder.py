"""Multi-finding exploit chain builder (A→B escalation suggestions)."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .findings import parse_latest_finding, update_resume_next_step
from .hunt_memory import HuntMemory


@dataclass(frozen=True)
class ChainEdge:
    from_class: str
    to_class: str
    reason: str
    priority: int = 50


# Capability table distilled from common bounty escalation paths
_EDGES: tuple[ChainEdge, ...] = (
    ChainEdge("secrets", "auth-bypass", "Leaked token/key → try auth bypass / session upgrade", 90),
    ChainEdge("secrets", "idor", "Creds → authenticated IDOR with A/B", 88),
    ChainEdge("jwt", "idor", "Forged/weak JWT → cross-account object access", 92),
    ChainEdge("jwt", "auth-bypass", "alg=none / claim flip → privileged session", 95),
    ChainEdge("oauth", "idor", "OAuth account takeover / token → victim objects", 90),
    ChainEdge("ssrf", "secrets", "SSRF → cloud metadata / internal secrets", 93),
    ChainEdge("ssrf", "lfi", "file:// SSRF sibling of LFI", 70),
    ChainEdge("xss", "oauth", "XSS → steal OAuth code/token from redirect", 85),
    ChainEdge("xss", "csrf", "XSS amplifies CSRF / session riding", 60),
    ChainEdge("sqli", "secrets", "SQLi → dump credentials/tokens", 94),
    ChainEdge("sqli", "auth-bypass", "SQLi login bypass", 90),
    ChainEdge("lfi", "secrets", "LFI → read env/config secrets", 91),
    ChainEdge("ssti", "rce", "SSTI often escalates to RCE (manual confirm)", 80),
    ChainEdge("xxe", "ssrf", "XXE → SSRF via external entity", 86),
    ChainEdge("xxe", "lfi", "XXE file:// read", 87),
    ChainEdge("cors", "xss", "CORS misconfig + XSS = data theft", 75),
    ChainEdge("open_redirect", "oauth", "Open redirect → OAuth token theft", 92),
    ChainEdge("graphql", "idor", "GraphQL IDOR / mutation authz", 84),
    ChainEdge("brute", "idor", "Valid login → authz hunting", 70),
    ChainEdge("auth-bypass", "idor", "Bypass → privileged IDOR", 93),
)


def _normalize_class(name: str) -> str:
    n = (name or "").lower().strip()
    aliases = {
        "credential-leak": "secrets",
        "tokens": "secrets",
        "jwt_active": "jwt",
        "analyze_jwt": "jwt",
        "open-redirect": "open_redirect",
        "openredirect": "open_redirect",
        "bola": "idor",
        "bac": "idor",
        "authz": "idor",
        "injection": "sqli",
    }
    return aliases.get(n, n)


def _findings_classes(target_dir: Path) -> list[dict[str, str]]:
    path = Path(target_dir) / "FINDINGS.md"
    if not path.exists():
        return []
    text = path.read_text(encoding="utf-8", errors="replace")
    out: list[dict[str, str]] = []
    for block in re.split(r"(?=^##\s*C-\d+)", text, flags=re.M):
        m = re.match(r"##\s*(C-\d+)\s+(.*)", block.strip())
        if not m:
            continue
        fields = {"finding_id": m.group(1), "title": m.group(2).strip(), "class": ""}
        for line in block.splitlines():
            if line.startswith("- ") and ":" in line:
                key, _, val = line[2:].partition(":")
                key = key.strip().lower()
                if key == "class":
                    fields["class"] = val.strip()
                if key == "endpoint":
                    fields["endpoint"] = val.strip()
        if fields["class"] or fields["finding_id"]:
            out.append(fields)
    return out


def build_chains(target_dir: Path) -> dict[str, Any]:
    """Propose A→B chains from FINDINGS + hunt candidates/attempts."""
    findings = _findings_classes(target_dir)
    memory = HuntMemory(target_dir)
    classes: set[str] = set()
    for f in findings:
        classes.add(_normalize_class(f.get("class") or ""))
    for c in memory.load_candidates():
        if c.status == "validated":
            classes.add(_normalize_class(c.module))
    for row in memory.recent_attempts(100):
        if row.get("outcome") in {"found", "validated"} or row.get("signal"):
            classes.add(_normalize_class(str(row.get("module") or "")))

    classes.discard("")
    chains: list[dict[str, Any]] = []
    for edge in _EDGES:
        if edge.from_class in classes:
            # Prefer edges whose target isn't already confirmed
            already = edge.to_class in classes
            chains.append(
                {
                    "from": edge.from_class,
                    "to": edge.to_class,
                    "reason": edge.reason,
                    "priority": edge.priority - (20 if already else 0),
                    "already_have_to": already,
                    "next_action": _next_action(edge.to_class),
                }
            )

    chains.sort(key=lambda c: -int(c["priority"]))
    # Dedupe by from→to
    seen: set[str] = set()
    uniq: list[dict[str, Any]] = []
    for c in chains:
        key = f"{c['from']}->{c['to']}"
        if key in seen:
            continue
        seen.add(key)
        uniq.append(c)

    md_lines = [
        "# Exploit chains",
        "",
        f"Observed classes: {', '.join(sorted(classes)) or '(none yet)'}",
        "",
        "| From | To | Why | Next |",
        "| --- | --- | --- | --- |",
    ]
    for c in uniq[:15]:
        md_lines.append(
            f"| {c['from']} | {c['to']} | {c['reason']} | `{c['next_action']}` |"
        )
    md_lines.append("")
    md = "\n".join(md_lines)

    # Persist + nudge resume
    hunt = Path(target_dir) / "hunt"
    hunt.mkdir(parents=True, exist_ok=True)
    (hunt / "chains.md").write_text(md, encoding="utf-8")
    if uniq:
        top = uniq[0]
        update_resume_next_step(
            target_dir,
            f"Chain: {top['from']} → {top['to']} — {top['next_action']}",
        )

    return {
        "ok": True,
        "classes": sorted(classes),
        "chains": uniq[:15],
        "count": len(uniq),
        "path": str(hunt / "chains.md"),
        "report_md": md,
        "latest_finding": parse_latest_finding(target_dir),
    }


def _next_action(to_class: str) -> str:
    mapping = {
        "idor": "run idor playbook with A/B on object URL",
        "auth-bypass": "run auth-bypass / jwt_active_probe",
        "secrets": "secrets_scan + check env/config paths",
        "ssrf": "ssrf playbook on URL-like params",
        "lfi": "lfi_probe on file/path params",
        "xss": "xss_probe on reflected params",
        "oauth": "oauth_probe on authorize URL",
        "jwt": "jwt_active_probe with captured token",
        "graphql": "graphql_probe introspection + authz",
        "rce": "manual SSTI→RCE confirm (out of auto scope)",
        "csrf": "manual CSRF PoC with session cookie",
        "sqli": "sqli_probe on id/search params",
        "xxe": "xxe_probe on XML endpoints",
        "cors": "cors_probe",
        "open_redirect": "open_redirect_probe",
        "brute": "brute_login capped",
    }
    return mapping.get(to_class, f"hunt/test for {to_class}")
