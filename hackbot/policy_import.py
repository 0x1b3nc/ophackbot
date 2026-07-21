"""Import rough program policy text into SCOPE.md YAML front-matter."""

from __future__ import annotations

import re
from pathlib import Path

import yaml

from .session import resolve_target_dir

_HOST_RE = re.compile(
    r"(?:\*\.)?(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,}",
    re.IGNORECASE,
)

# Longer / more specific aliases first so "out of scope" wins over "in scope".
_SECTION_MATCHERS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("out_of_scope", ("out of scope", "out-of-scope", "excluded", "not in scope")),
    ("prohibited", ("explicitly prohibited", "prohibited", "forbidden", "do not", "out of bounds")),
    ("allowed", ("explicitly allowed", "allowed", "permitted", "you may")),
    ("in_scope", ("in scope", "in-scope", "targets", "assets", "scope")),
)


def _section_bodies(text: str) -> dict[str, str]:
    """Map canonical keys -> body text under matching markdown/plain headings."""
    lines = text.splitlines()
    bodies: dict[str, list[str]] = {k: [] for k, _ in _SECTION_MATCHERS}
    active: str | None = None
    for line in lines:
        stripped = line.strip()
        heading = ""
        if stripped.startswith("#"):
            heading = stripped.lstrip("#").strip().lower()
        elif re.match(r"^[A-Z][A-Za-z0-9 /&-]{2,40}:?\s*$", stripped):
            heading = stripped.rstrip(":").strip().lower()
        if heading:
            active = None
            for key, aliases in _SECTION_MATCHERS:
                if any(a in heading for a in aliases):
                    active = key
                    break
            continue
        if active:
            bodies[active].append(line)
    return {k: "\n".join(v) for k, v in bodies.items()}


def _hosts_from(body: str) -> list[str]:
    found: list[str] = []
    for match in _HOST_RE.finditer(body):
        host = match.group(0).lower().rstrip(".")
        if host not in found:
            found.append(host)
    # Also bullet lines that are bare hosts
    for line in body.splitlines():
        token = line.strip().lstrip("-*` ").rstrip("`")
        if _HOST_RE.fullmatch(token):
            h = token.lower().rstrip(".")
            if h not in found:
                found.append(h)
    return found


def _bullets_from(body: str) -> list[str]:
    items: list[str] = []
    for line in body.splitlines():
        stripped = line.strip()
        if stripped.startswith(("-", "*", "•")):
            item = stripped.lstrip("-*• ").strip()
            if item and item not in items:
                items.append(item[:200])
    return items


def parse_policy_text(text: str) -> dict[str, list[str]]:
    """Extract structured scope fields from free-form policy markdown/text."""
    bodies = _section_bodies(text)
    in_scope = _hosts_from(bodies.get("in_scope", ""))
    out_of_scope = _hosts_from(bodies.get("out_of_scope", ""))
    # Fallback: all hosts in doc minus out_of_scope if no in_scope section
    if not in_scope:
        all_hosts = _hosts_from(text)
        in_scope = [h for h in all_hosts if h not in out_of_scope]
    allowed = _bullets_from(bodies.get("allowed", "")) or ["Passive recon"]
    prohibited = _bullets_from(bodies.get("prohibited", "")) or [
        "DoS",
        "Brute force",
        "Credential stuffing",
    ]
    return {
        "in_scope": in_scope,
        "out_of_scope": out_of_scope,
        "allowed": allowed,
        "prohibited": prohibited,
    }


def render_scope_md(meta: dict[str, list[str]], *, notes: str = "") -> str:
    # Quote wildcard hosts for YAML safety
    def dump_list(items: list[str]) -> list[str]:
        return items

    payload = {
        "in_scope": dump_list(meta.get("in_scope") or []),
        "out_of_scope": dump_list(meta.get("out_of_scope") or []),
        "allowed": dump_list(meta.get("allowed") or []),
        "prohibited": dump_list(meta.get("prohibited") or []),
    }
    fm = yaml.safe_dump(payload, default_flow_style=False, sort_keys=False).strip()
    body = notes.strip() or (
        "# Scope\n\nImported from program policy text. YAML above is the source of truth.\n"
    )
    return f"---\n{fm}\n---\n\n{body}\n"


def import_policy_to_target(
    target: str,
    policy_text: str,
    *,
    write: bool = False,
) -> tuple[dict[str, list[str]], str, Path]:
    """Parse policy and optionally write SCOPE.md under the target."""
    meta = parse_policy_text(policy_text)
    root = resolve_target_dir(target)
    root.mkdir(parents=True, exist_ok=True)
    existing_notes = ""
    scope_path = root / "SCOPE.md"
    if scope_path.exists():
        raw = scope_path.read_text(encoding="utf-8", errors="replace")
        if raw.lstrip().startswith("---"):
            # Keep markdown body after front-matter
            parts = raw.split("---", 2)
            if len(parts) >= 3:
                existing_notes = parts[2].strip()
        else:
            existing_notes = raw.strip()
    rendered = render_scope_md(meta, notes=existing_notes)
    if write:
        scope_path.write_text(rendered, encoding="utf-8")
    return meta, rendered, scope_path
