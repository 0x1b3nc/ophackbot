"""Route bounty tasks to mandatory local study notes."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
NOTES = ROOT / "bounty_knowledge" / "study_notes"
INDEX = NOTES / "INDEX.md"
ROUTING = NOTES / "STUDY_MATERIAL_ROUTING.md"
OPERATING_RULES = ROOT / "docs" / "OPERATING_RULES.md"

# Trigger keywords -> relative note paths under study_notes/
CLASS_ROUTES: dict[str, tuple[str, ...]] = {
    "idor": ("web-vulns/idor-bac.md",),
    "bola": ("web-vulns/idor-bac.md",),
    "bac": ("web-vulns/idor-bac.md",),
    "bfla": ("web-vulns/idor-bac.md",),
    "authz": ("web-vulns/idor-bac.md",),
    "access-control": ("web-vulns/idor-bac.md",),
    "graphql": ("api-security/graphql-smuggling-cache.md", "web-vulns/idor-bac.md"),
    "oauth": ("web-vulns/auth-session.md",),
    "oidc": ("web-vulns/auth-session.md",),
    "jwt": ("web-vulns/auth-session.md",),
    "session": ("web-vulns/auth-session.md",),
    "ssrf": ("web-vulns/ssrf.md",),
    "sqli": ("web-vulns/injection.md",),
    "nosqli": ("web-vulns/injection.md",),
    "injection": ("web-vulns/injection.md",),
    "ssti": ("web-vulns/injection.md",),
    "xxe": ("web-vulns/injection.md",),
    "race": ("web-vulns/race-conditions.md",),
    "xss": ("web-vulns/client-side.md",),
    "prototype-pollution": ("web-vulns/client-side.md",),
    "postmessage": ("web-vulns/client-side.md",),
    "smuggling": ("api-security/smuggling-cache.md",),
    "cache": ("api-security/smuggling-cache.md",),
    "api": ("api-security/owasp-api-top10.md",),
    "mobile": ("api-security/mobile-maui-banking-api.md",),
    "apk": ("api-security/mobile-maui-banking-api.md",),
    "takeover": ("recon/subdomain-takeover.md",),
    "recon": ("recon/content-discovery.md",),
    "discovery": ("recon/content-discovery.md",),
    "llm": ("ai-security/promptfoo-lm-security-db.md",),
    "mcp": (
        "ai-security/promptfoo-lm-security-db.md",
        "red-team/bishopfox-advisories-ai-mcp.md",
    ),
    "prompt-injection": ("ai-security/promptfoo-lm-security-db.md",),
}


@dataclass(frozen=True)
class KnowledgeBundle:
    class_name: str
    notes: tuple[Path, ...]
    missing: tuple[Path, ...]
    always: tuple[Path, ...]


def classify(task: str) -> list[str]:
    """Return matching bug-class keys for a free-text task description."""
    text = task.lower()
    hits = [key for key in CLASS_ROUTES if key in text]
    return hits or ["recon"]


def notes_for_classes(classes: list[str]) -> list[Path]:
    seen: list[Path] = []
    for cls in classes:
        for rel in CLASS_ROUTES.get(cls, ()):
            path = NOTES / rel
            if path not in seen:
                seen.append(path)
    return seen


def required_bundle(task: str) -> KnowledgeBundle:
    classes = classify(task)
    class_name = ",".join(classes)
    notes = notes_for_classes(classes)
    always = (OPERATING_RULES, INDEX, ROUTING)
    missing = tuple(p for p in (*always, *notes) if not p.exists())
    return KnowledgeBundle(
        class_name=class_name,
        notes=tuple(notes),
        missing=missing,
        always=always,
    )


def open_notes(task: str, max_chars: int = 4000) -> str:
    """Load mandatory notes for a task. Missing files are listed, not invented."""
    bundle = required_bundle(task)
    chunks: list[str] = []
    chunks.append(f"class={bundle.class_name}")
    for path in (*bundle.always, *bundle.notes):
        chunks.append(f"\n--- {path} ---")
        if path.exists():
            text = path.read_text(encoding="utf-8", errors="replace")
            chunks.append(text[:max_chars])
            if len(text) > max_chars:
                chunks.append(f"... truncated ({len(text)} bytes total)")
        else:
            chunks.append("missing (inference: note not present locally)")
    if bundle.missing:
        chunks.append(
            "\ninference: some required notes are missing on disk: "
            + ", ".join(str(p) for p in bundle.missing)
        )
    return "\n".join(chunks)


def list_routes() -> str:
    lines = ["trigger -> notes"]
    for key, rels in sorted(CLASS_ROUTES.items()):
        lines.append(f"{key}: {', '.join(rels)}")
    return "\n".join(lines)
