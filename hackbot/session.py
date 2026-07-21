"""Active target session: SCOPE / RESUME / FINDINGS loaded for the agent."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
TARGETS = ROOT / "targets"

_MAX_FILE_CHARS = 3500


@dataclass
class TargetSession:
    target_dir: Path
    name: str
    scope_excerpt: str = ""
    resume_excerpt: str = ""
    findings_excerpt: str = ""
    in_scope_hosts: tuple[str, ...] = ()
    next_step: str = ""
    loaded_files: list[str] = field(default_factory=list)

    def context_block(self) -> str:
        hosts = ", ".join(self.in_scope_hosts) or "(see SCOPE)"
        parts = [
            f"Active target: {self.name} ({self.target_dir})",
            f"In-scope hosts (structured or inferred): {hosts}",
        ]
        if self.next_step:
            parts.append(f"Safe next step from RESUME.md: {self.next_step}")
        if self.resume_excerpt:
            parts.append("--- RESUME.md ---\n" + self.resume_excerpt)
        if self.findings_excerpt:
            parts.append("--- FINDINGS.md ---\n" + self.findings_excerpt)
        if self.scope_excerpt:
            parts.append("--- SCOPE.md (excerpt) ---\n" + self.scope_excerpt)
        return "\n\n".join(parts)


def resolve_target_dir(value: str) -> Path:
    p = Path(value)
    if not p.is_absolute():
        if (ROOT / value).exists():
            p = ROOT / value
        elif (TARGETS / value).exists():
            p = TARGETS / value
        else:
            p = ROOT / value
    return p.resolve()


def _read_excerpt(path: Path, limit: int = _MAX_FILE_CHARS) -> str:
    if not path.exists():
        return ""
    with path.open("r", encoding="utf-8", errors="replace") as handle:
        text = handle.read(limit + 1)
    if len(text) > limit:
        return text[:limit] + "\n...(truncated)"
    return text


def _next_step_from_resume(text: str) -> str:
    capture = False
    lines: list[str] = []
    for line in text.splitlines():
        stripped = line.strip()
        if stripped.lower().startswith("##") and "next" in stripped.lower():
            capture = True
            continue
        if capture and stripped.startswith("##"):
            break
        if capture and stripped.startswith("-"):
            lines.append(stripped.lstrip("- ").strip())
    return lines[0] if lines else ""


def load_session(target: str) -> TargetSession:
    """Load target workspace files into a session object."""
    root = resolve_target_dir(target)
    if not root.exists():
        raise FileNotFoundError(f"target not found: {target}")
    scope_path = root / "SCOPE.md"
    resume_path = root / "RESUME.md"
    findings_path = root / "FINDINGS.md"

    from .policy_guard import ScopePolicy

    hosts: tuple[str, ...] = ()
    scope_excerpt = _read_excerpt(scope_path, 2500)
    if scope_path.exists():
        try:
            policy = ScopePolicy.load(root)
            if policy.structured and policy.in_scope:
                hosts = policy.in_scope
        except Exception:
            pass

    resume = _read_excerpt(resume_path)
    findings = _read_excerpt(findings_path, 2500)
    loaded = [str(p) for p in (scope_path, resume_path, findings_path) if p.exists()]

    return TargetSession(
        target_dir=root,
        name=root.name,
        scope_excerpt=scope_excerpt,
        resume_excerpt=resume,
        findings_excerpt=findings,
        in_scope_hosts=hosts,
        next_step=_next_step_from_resume(resume),
        loaded_files=loaded,
    )


# Process-wide active session (REPL sets this).
_ACTIVE: TargetSession | None = None


def get_active() -> TargetSession | None:
    return _ACTIVE


def set_active(target: str) -> TargetSession:
    global _ACTIVE
    _ACTIVE = load_session(target)
    return _ACTIVE


def clear_active() -> None:
    global _ACTIVE
    _ACTIVE = None


def status_line() -> str:
    s = _ACTIVE
    if s is None:
        return "no active target  (/target <name>)"
    nxt = s.next_step or "(none in RESUME.md)"
    hosts = ",".join(s.in_scope_hosts[:3]) if s.in_scope_hosts else "?"
    return f"target={s.name}  hosts={hosts}  next={nxt[:60]}"
