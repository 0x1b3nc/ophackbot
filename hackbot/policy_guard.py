"""Parse target SCOPE.md and gate active actions by host and aggression."""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.parse import urlparse

import yaml

ACTIVE_KEYWORDS = (
    "nuclei",
    "ffuf",
    "feroxbuster",
    "gobuster",
    "sqlmap",
    "hydra",
    "masscan",
    "naabu",
    "rustscan",
    "brute",
    "race",
    "dos",
    "stress",
    "active scanning",
    "automated scanning",
    "automation",
)

LEVEL3_KEYWORDS = (
    "dos",
    "denial of service",
    "brute force",
    "bruteforce",
    "password spray",
    "credential stuffing",
    "stress",
    "rate-limit testing",
    "rate limit testing",
)


@dataclass(frozen=True)
class ScopePolicy:
    root: Path
    scope_text: str
    in_scope: tuple[str, ...] = field(default_factory=tuple)
    out_of_scope: tuple[str, ...] = field(default_factory=tuple)
    allowed: tuple[str, ...] = field(default_factory=tuple)
    prohibited: tuple[str, ...] = field(default_factory=tuple)
    structured: bool = False

    @classmethod
    def load(cls, target_dir: Path) -> "ScopePolicy":
        scope_path = target_dir / "SCOPE.md"
        if not scope_path.exists():
            raise FileNotFoundError(f"missing required scope file: {scope_path}")
        raw = scope_path.read_text(encoding="utf-8", errors="replace")
        meta, body = _split_front_matter(raw)
        if meta is None:
            return cls(target_dir, raw)
        return cls(
            target_dir,
            body if body.strip() else raw,
            in_scope=_as_str_tuple(meta.get("in_scope")),
            out_of_scope=_as_str_tuple(meta.get("out_of_scope")),
            allowed=_as_str_tuple(meta.get("allowed")),
            prohibited=_as_str_tuple(meta.get("prohibited")),
            structured=True,
        )

    def contains_host(self, host: str) -> bool:
        host = host.lower().strip().rstrip(".")
        if not host:
            return False
        if self.structured and self.in_scope:
            return _host_in_entries(host, self.in_scope)
        text = self.scope_text.lower()
        if _host_mentioned(text, host):
            return True
        parts = host.split(".")
        # Only explicit *.parent wildcards count (never bare ".com").
        for index in range(len(parts) - 1):
            parent = ".".join(parts[index + 1 :])
            if _wildcard_mentioned(text, parent):
                return True
        return False

    def is_explicitly_out_of_scope(self, host: str) -> bool:
        """Host listed under out_of_scope (YAML) or an Out of Scope section."""
        host = host.lower().strip().rstrip(".")
        if not host:
            return False
        if self.structured and self.out_of_scope:
            return _host_in_entries(host, self.out_of_scope)
        sections = _sections_named(self.scope_text.lower(), ("out of scope",))
        if not sections:
            return False
        section = "\n".join(sections)
        if _host_mentioned(section, host):
            return True
        parts = host.split(".")
        for index in range(len(parts) - 1):
            parent = ".".join(parts[index + 1 :])
            if _wildcard_mentioned(section, parent):
                return True
        return False

    def mentions_active_testing(self) -> bool:
        if self.structured and self.allowed:
            blob = " ".join(self.allowed).lower()
            if any(word in blob for word in ACTIVE_KEYWORDS):
                return True
        text = self.scope_text.lower()
        return any(word in text for word in ACTIVE_KEYWORDS)

    def allows_level3(self) -> bool:
        """True only if a level-3 keyword appears under Allowed / allowed list."""
        if self.structured and self.allowed:
            blob = " ".join(self.allowed).lower()
            if any(word in blob for word in LEVEL3_KEYWORDS):
                return True
            # Structured and allowed is present but no level-3 wording: stop here
            # so Markdown prose does not accidentally authorize level 3.
            return False
        text = self.scope_text.lower()
        allowed_sections = _sections_named(text, ("explicitly allowed", "allowed", "permitted"))
        for section in allowed_sections:
            if any(word in section for word in LEVEL3_KEYWORDS):
                return True
        return False

    def classify_aggression(self, action: str) -> int:
        action_l = action.lower()
        if any(
            word in action_l
            for word in (
                "dos",
                "stress",
                "brute",
                "password spray",
                "credential stuffing",
            )
        ):
            return 3
        if any(
            word in action_l
            for word in (
                "ffuf",
                "nuclei",
                "fuzz",
                "race",
                "idor",
                "mutation",
                "write",
            )
        ):
            return 2
        if any(
            word in action_l
            for word in (
                "httpx",
                "katana",
                "subfinder",
                "crawl",
                "fingerprint",
            )
        ):
            return 1
        return 0

    def assert_host_allowed(self, host: str) -> None:
        if self.is_explicitly_out_of_scope(host):
            raise PermissionError(f"host out of scope: {host}")
        if not self.contains_host(host):
            raise PermissionError(
                f"host not confirmed in SCOPE.md: {host}. "
                "Refuse active traffic until scope text includes it."
            )


def host_from_target(value: str) -> str:
    parsed = urlparse(value if "://" in value else f"https://{value}")
    return (parsed.hostname or "").lower().rstrip(".")


def policy_quote_for(policy: ScopePolicy, aggression: int) -> str:
    """Return a short quote from SCOPE.md that best supports the action level."""
    if policy.structured:
        if aggression >= 3 and policy.allowed:
            for item in policy.allowed:
                if any(k in item.lower() for k in LEVEL3_KEYWORDS):
                    return item[:240]
        if policy.allowed:
            return policy.allowed[0][:240]
        if policy.in_scope:
            return f"in_scope: {policy.in_scope[0]}"
    lines = [ln.strip() for ln in policy.scope_text.splitlines() if ln.strip()]
    if aggression >= 3:
        keys = LEVEL3_KEYWORDS
    elif aggression >= 1:
        keys = ("in scope", "allowed", "automation", "scanning", "passive recon", "httpx")
    else:
        keys = ("passive", "osint", "in scope", "allowed")
    for line in lines:
        if line.startswith("#") or line.startswith("---"):
            continue
        lower = line.lower()
        if any(k in lower for k in keys):
            return line[:240]
    for line in lines:
        if not line.startswith("#") and not line.startswith("---"):
            return line[:240]
    return "(empty SCOPE.md - inference: no authorizing text found)"


def _as_str_tuple(value: Any) -> tuple[str, ...]:
    if value is None:
        return ()
    if isinstance(value, str):
        return (value,)
    if isinstance(value, (list, tuple)):
        return tuple(str(v) for v in value if v is not None and str(v).strip())
    return ()


def _split_front_matter(raw: str) -> tuple[dict[str, Any] | None, str]:
    """Parse leading YAML front-matter. Returns (meta or None, body)."""
    text = raw.lstrip("\ufeff")
    if not text.startswith("---"):
        return None, raw
    lines = text.splitlines()
    if not lines or lines[0].strip() != "---":
        return None, raw
    end = None
    for i in range(1, len(lines)):
        if lines[i].strip() == "---":
            end = i
            break
    if end is None:
        return None, raw
    block = "\n".join(lines[1:end])
    body = "\n".join(lines[end + 1 :])
    try:
        meta = yaml.safe_load(block)
    except yaml.YAMLError:
        return None, raw
    if not isinstance(meta, dict):
        return None, raw
    return meta, body


def _normalize_entry(entry: str) -> str:
    return entry.lower().strip().strip("`").rstrip(".")


def _host_in_entries(host: str, entries: tuple[str, ...]) -> bool:
    host = host.lower().strip().rstrip(".")
    for raw in entries:
        entry = _normalize_entry(raw)
        if not entry:
            continue
        if entry.startswith("*."):
            parent = entry[2:]
            if not parent or "." not in parent:
                continue
            if host.endswith("." + parent) and host != parent:
                return True
            continue
        if host == entry:
            return True
    return False


def _host_mentioned(text: str, host: str) -> bool:
    """True if host appears as its own token, not inside a longer hostname."""
    host = host.lower().strip(".")
    if not host:
        return False
    # Dot counts as a host character so example.com != admin.example.com
    # and api.demo.test != *.api.demo.test.
    pattern = re.compile(
        rf"(?<![a-z0-9.*-]){re.escape(host)}(?![a-z0-9.-])",
        re.IGNORECASE,
    )
    return pattern.search(text) is not None


def _wildcard_mentioned(text: str, parent: str) -> bool:
    """True if SCOPE lists *.parent as a wildcard entry."""
    parent = parent.lower().strip(".")
    if not parent or "." not in parent:
        # Refuse bare TLDs like *.com
        return False
    pattern = re.compile(
        rf"(?<![a-z0-9.*-])\*\.{re.escape(parent)}(?![a-z0-9.-])",
        re.IGNORECASE,
    )
    return pattern.search(text) is not None


def _sections_named(text: str, headings: tuple[str, ...]) -> list[str]:
    """Return body text under markdown headings that match any of headings."""
    lines = text.splitlines()
    sections: list[str] = []
    capture: list[str] = []
    active = False
    for line in lines:
        stripped = line.strip()
        if stripped.startswith("#"):
            title = stripped.lstrip("#").strip().lower()
            if active and capture:
                sections.append("\n".join(capture))
            capture = []
            active = any(h in title for h in headings)
            continue
        if active:
            capture.append(line)
    if active and capture:
        sections.append("\n".join(capture))
    return sections
