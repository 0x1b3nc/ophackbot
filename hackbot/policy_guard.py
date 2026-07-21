"""Parse target SCOPE.md and gate active actions by host/URL and aggression."""

from __future__ import annotations

import ipaddress
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
    "active testing",
    "mutating",
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
    "race condition",
    "race testing",
    "concurrency testing",
)

# Tool-id aggression (primary). Text hints remain as fallback.
TOOL_AGGRESSION: dict[str, int] = {
    "rate_probe": 3,
    "brute_login": 3,
    "race_probe": 3,
    "method_override_probe": 3,
    "mass_assignment_probe": 2,
    "graphql_probe": 2,
    "idor_probe": 2,
    "sqli_probe": 2,
    "xss_probe": 2,
    "ssrf_probe": 2,
    "lfi_probe": 2,
    "ssti_probe": 2,
    "xxe_probe": 2,
    "cors_probe": 2,
    "open_redirect_probe": 2,
    "param_mine": 2,
    "content_discovery": 2,
    "nuclei": 2,
    "ffuf": 2,
    "browser_evaluate": 2,
    "browser_eval": 2,
    "websocket_probe": 2,
    "session_bootstrap": 2,
    "detect_login": 1,
    "session_smoke": 1,
    "oauth_probe": 2,
    "jwt_active": 2,
    "http_request": 2,
    "extract_page": 1,
    "httpx": 1,
    "katana": 1,
    "subfinder": 1,
    "analyze_js": 1,
    "analyze_headers": 1,
    "secrets_scan": 1,
    "crt_subdomains": 0,
    "wayback_urls": 0,
}

# Prohibited phrase → needles matched against action/tool text.
PROHIBITED_ALIASES: dict[str, tuple[str, ...]] = {
    "automated scanning": (
        "nuclei",
        "ffuf",
        "fuzz",
        "ferox",
        "gobuster",
        "automated scanning",
        "content discovery",
        "parameter mining",
    ),
    "mutating requests": (
        "mutat",
        "mass assignment",
        "method override",
        "write",
        "delete",
        "graphql",
        "browser eval",
        "browser evaluate",
    ),
    "brute force": ("brute", "password spray", "credential stuffing", "hydra"),
    "bruteforce": ("brute", "password spray", "credential stuffing"),
    # Keep rate-limit separate: programs often ban DoS but allow bounded rate probes.
    "dos": ("dos", "denial of service", "ddos", "flood"),
    "denial of service": ("dos", "denial of service", "ddos", "flood"),
    "credential stuffing": ("credential stuffing", "password spray", "brute"),
}


@dataclass(frozen=True)
class ScopeRule:
    """One SCOPE entry. Host-only rules leave scheme/port/path unconstrained."""

    raw: str
    host: str = ""
    scheme: str | None = None
    port: int | None = None
    path_prefix: str | None = None
    network: str | None = None  # CIDR / single IP as ip_network string


@dataclass(frozen=True)
class ScopePolicy:
    root: Path
    scope_text: str
    in_scope: tuple[str, ...] = field(default_factory=tuple)
    out_of_scope: tuple[str, ...] = field(default_factory=tuple)
    allowed: tuple[str, ...] = field(default_factory=tuple)
    prohibited: tuple[str, ...] = field(default_factory=tuple)
    structured: bool = False
    in_rules: tuple[ScopeRule, ...] = field(default_factory=tuple)
    out_rules: tuple[ScopeRule, ...] = field(default_factory=tuple)

    @classmethod
    def load(cls, target_dir: Path) -> "ScopePolicy":
        scope_path = target_dir / "SCOPE.md"
        if not scope_path.exists():
            raise FileNotFoundError(f"missing required scope file: {scope_path}")
        raw = scope_path.read_text(encoding="utf-8", errors="replace")
        meta, body = _split_front_matter(raw)
        if meta is None:
            return cls(target_dir, raw)
        in_scope = _as_str_tuple(meta.get("in_scope"))
        out_of_scope = _as_str_tuple(meta.get("out_of_scope"))
        return cls(
            target_dir,
            body if body.strip() else raw,
            in_scope=in_scope,
            out_of_scope=out_of_scope,
            allowed=_as_str_tuple(meta.get("allowed")),
            prohibited=_as_str_tuple(meta.get("prohibited")),
            structured=True,
            in_rules=tuple(parse_scope_rule(x) for x in in_scope),
            out_rules=tuple(parse_scope_rule(x) for x in out_of_scope),
        )

    def contains_host(self, host: str) -> bool:
        host = host.lower().strip().rstrip(".")
        if not host:
            return False
        if self.structured and self.in_rules:
            return any(_host_matches_rule(host, rule) for rule in self.in_rules)
        text = self.scope_text.lower()
        if _host_mentioned(text, host):
            return True
        parts = host.split(".")
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
        if self.structured and self.out_rules:
            return any(_host_matches_rule(host, rule) for rule in self.out_rules)
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

    def target_out_of_scope(self, host_or_url: str) -> bool:
        """True if host or full URL matches an explicit OOS rule."""
        host = host_from_target(host_or_url)
        if host and self.is_explicitly_out_of_scope(host):
            return True
        if self.structured and self.out_rules and _looks_like_url(host_or_url):
            return any(_url_matches_rule(host_or_url, rule) for rule in self.out_rules)
        return False

    def target_in_scope(self, host_or_url: str) -> bool:
        """True if host or URL is covered by an in-scope rule (constraints honored)."""
        if _looks_like_url(host_or_url) and self.structured and self.in_rules:
            return any(_url_matches_rule(host_or_url, rule) for rule in self.in_rules)
        return self.contains_host(host_from_target(host_or_url))

    def mentions_active_testing(self) -> bool:
        if self.structured and self.allowed:
            blob = " ".join(self.allowed).lower()
            if any(word in blob for word in ACTIVE_KEYWORDS):
                return True
            return False
        text = self.scope_text.lower()
        return any(word in text for word in ACTIVE_KEYWORDS)

    def allows_level3(self) -> bool:
        """True only if a level-3 keyword appears under Allowed / allowed list."""
        if self.structured and self.allowed:
            blob = " ".join(self.allowed).lower()
            if any(word in blob for word in LEVEL3_KEYWORDS):
                return True
            return False
        text = self.scope_text.lower()
        allowed_sections = _sections_named(text, ("explicitly allowed", "allowed", "permitted"))
        for section in allowed_sections:
            if any(word in section for word in LEVEL3_KEYWORDS):
                return True
        return False

    def prohibited_items(self) -> tuple[str, ...]:
        if self.structured and self.prohibited:
            return self.prohibited
        items: list[str] = []
        for section in _sections_named(
            self.scope_text.lower(),
            ("explicitly prohibited", "prohibited"),
        ):
            items.extend(_bullet_items(section))
        return tuple(items)

    def matching_prohibited(self, action: str, *, tool: str | None = None) -> str | None:
        """Return the prohibited policy item that matches action/tool, if any."""
        hay = f"{action} {(tool or '').replace('_', ' ')}".lower()
        for item in self.prohibited_items():
            if _prohibited_matches(item, hay):
                return item
        return None

    def classify_aggression(self, action: str, *, tool: str | None = None) -> int:
        level = 0
        if tool:
            key = tool.lower().strip()
            if key in TOOL_AGGRESSION:
                level = max(level, TOOL_AGGRESSION[key])
            # also try without _probe suffix variants
            alt = key.replace("-", "_")
            if alt in TOOL_AGGRESSION:
                level = max(level, TOOL_AGGRESSION[alt])
        level = max(level, _classify_aggression_text(action))
        return level

    def assert_host_allowed(self, host: str) -> None:
        if self.is_explicitly_out_of_scope(host):
            raise PermissionError(f"host out of scope: {host}")
        if not self.contains_host(host):
            raise PermissionError(
                f"host not confirmed in SCOPE.md: {host}. "
                "Refuse active traffic until scope text includes it."
            )

    def assert_action_allowed(
        self,
        host_or_url: str,
        action: str,
        *,
        force: bool = False,
        tool: str | None = None,
    ) -> dict[str, object]:
        """Gate target + aggression + prohibited. OOS never bypassable.

        Soft gates (NOT_CONFIRMED, L3 wording, prohibited, L2 without active
        allow on structured SCOPE) yield to operator ``force``.
        """
        host = host_from_target(host_or_url)
        if self.target_out_of_scope(host_or_url):
            raise PermissionError(
                f"host out of scope: {host or host_or_url} "
                "(OUT_OF_SCOPE cannot be overridden with /force)"
            )

        in_scope = self.target_in_scope(host_or_url)
        status = "IN_SCOPE" if in_scope else "NOT_CONFIRMED"
        level = self.classify_aggression(action, tool=tool)
        warnings: list[str] = []
        force_override = False

        if not in_scope:
            if force:
                force_override = True
                warnings.append(
                    "target NOT_CONFIRMED in SCOPE.md — forced by operator"
                )
            else:
                raise PermissionError(
                    f"target not confirmed in SCOPE.md: {host_or_url}. "
                    "Add it to SCOPE or use /force (operator responsibility)."
                )

        prohibited_hit = self.matching_prohibited(action, tool=tool)
        if prohibited_hit:
            if force:
                force_override = True
                warnings.append(
                    f"action matches prohibited '{prohibited_hit}' — forced by operator"
                )
            else:
                raise PermissionError(
                    f"action prohibited by SCOPE.md: {prohibited_hit}. "
                    "Remove from prohibited, or use /force (operator responsibility)."
                )

        if level >= 3 and not self.allows_level3():
            if force:
                force_override = True
                warnings.append(
                    "level 3 not explicitly allowed in SCOPE.md — forced by operator"
                )
            else:
                raise PermissionError(
                    "level 3 (rate-limit/stress/brute) not explicitly allowed in SCOPE.md. "
                    "Add wording under Allowed, or use /force."
                )

        if level >= 2 and not self.mentions_active_testing():
            if force:
                force_override = True
                warnings.append(
                    "active/moderate testing not mentioned in SCOPE — forced by operator"
                )
            elif self.structured:
                # Structured SCOPE with no active allow: hard deny (policy fidelity).
                raise PermissionError(
                    "active/moderate action not allowed by structured SCOPE.md "
                    f"(aggression={level}). Add active/automated wording under allowed, "
                    "or use /force."
                )
            else:
                warnings.append(
                    "active/moderate action: confirm policy text before running "
                    "(or /force to override)"
                )

        return {
            "host": host,
            "target": host_or_url,
            "status": status,
            "aggression": level,
            "force_override": force_override,
            "warnings": warnings,
            "policy_quote": policy_quote_for(self, level),
            "tool": tool or "",
            "prohibited_match": prohibited_hit or "",
        }


def parse_scope_rule(entry: str) -> ScopeRule:
    """Parse a YAML/Markdown scope entry into a host (+ optional URL constraints)."""
    raw = str(entry).strip()
    norm = raw.strip("`").strip()
    if not norm:
        return ScopeRule(raw=raw, host="")

    # CIDR or bare IP (before host/path parsing so 10.0.0.0/8 is not path "/8")
    cidr_rule = _try_parse_network_rule(raw, norm)
    if cidr_rule is not None:
        return cidr_rule

    # Bare wildcard host: *.parent.tld
    if (
        norm.startswith("*.")
        and "://" not in norm
        and "/" not in norm
        and norm.count(":") == 0
    ):
        return ScopeRule(raw=raw, host=norm.lower().rstrip("."))

    if "://" in norm:
        parsed = urlparse(norm)
        host = (parsed.hostname or "").lower().rstrip(".")
        path_prefix = _path_prefix_from_parsed(parsed.path)
        port = parsed.port
        scheme = (parsed.scheme or "").lower() or None
        return ScopeRule(
            raw=raw,
            host=host,
            scheme=scheme,
            port=port,
            path_prefix=path_prefix,
        )

    # host[:port][/path]
    path_prefix = None
    hostport = norm
    if "/" in norm:
        hostport, _, rest = norm.partition("/")
        path_prefix = _path_prefix_from_parsed("/" + rest)
    host, port = _split_host_port(hostport)
    return ScopeRule(raw=raw, host=host, port=port, path_prefix=path_prefix)


def _try_parse_network_rule(raw: str, norm: str) -> ScopeRule | None:
    if "://" in norm:
        return None
    candidate = norm
    # Strip optional path from mistaken "10.0.0.1/24/extra" — only pure CIDR/IP.
    if "/" in norm:
        left, _, right = norm.partition("/")
        left = left.strip()
        # host/path like example.com/v1 — not a network
        try:
            ipaddress.ip_address(left.strip("[]"))
        except ValueError:
            return None
        # right must be prefix length only
        prefix = right.split("/", 1)[0].strip()
        if not prefix.isdigit():
            return None
        candidate = f"{left}/{prefix}"
    try:
        net = ipaddress.ip_network(candidate.strip("[]"), strict=False)
    except ValueError:
        try:
            addr = ipaddress.ip_address(candidate.strip("[]"))
            net = ipaddress.ip_network(f"{addr}/{addr.max_prefixlen}", strict=False)
        except ValueError:
            return None
    return ScopeRule(raw=raw, host="", network=str(net))


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


def _classify_aggression_text(action: str) -> int:
    action_l = action.lower()
    if any(
        word in action_l
        for word in (
            "dos",
            "stress",
            "brute",
            "password spray",
            "credential stuffing",
            "rate-limit",
            "rate limit",
            "rate_probe",
            "rate-probe",
            "race condition",
            "race_probe",
            "method override",
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
            "mass assignment",
            "write",
            "sqli",
            "xss",
            "injection",
            "ssrf",
            "graphql",
            "browser eval",
            "browser evaluate",
            "playwright",
            "parameter pollution",
            "websocket",
            "lfi",
            "ssti",
            "xxe",
            "cors",
            "open redirect",
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


def _looks_like_url(value: str) -> bool:
    v = value.strip()
    return "://" in v or v.startswith("//")


def _path_prefix_from_parsed(path: str) -> str | None:
    path = (path or "").strip()
    if not path or path == "/":
        return None
    if path.endswith("/*"):
        path = path[:-2]
    elif path.endswith("*"):
        path = path[:-1]
    if not path.startswith("/"):
        path = "/" + path
    path = path.rstrip("/")
    if not path or path == "/":
        return None
    return path


def _split_host_port(hostport: str) -> tuple[str, int | None]:
    hostport = hostport.strip().lower().rstrip(".")
    if not hostport:
        return "", None
    # IPv6 in brackets
    if hostport.startswith("["):
        end = hostport.find("]")
        if end > 0:
            host = hostport[1:end]
            rest = hostport[end + 1 :]
            if rest.startswith(":") and rest[1:].isdigit():
                return host, int(rest[1:])
            return host, None
    if hostport.count(":") == 1:
        host, _, port_s = hostport.partition(":")
        if port_s.isdigit():
            return host.rstrip("."), int(port_s)
    return hostport, None


def _host_matches_rule(host: str, rule: ScopeRule) -> bool:
    host = host.lower().strip().rstrip(".")
    if not host:
        return False
    if rule.network:
        try:
            addr = ipaddress.ip_address(host.strip("[]"))
            return addr in ipaddress.ip_network(rule.network, strict=False)
        except ValueError:
            return False
    entry = rule.host.lower().strip().rstrip(".")
    if not entry:
        return False
    if entry.startswith("*."):
        parent = entry[2:]
        if not parent or "." not in parent:
            return False
        return host.endswith("." + parent) and host != parent
    return host == entry


def _url_matches_rule(url: str, rule: ScopeRule) -> bool:
    if not rule.host and not rule.network:
        return False
    parsed = urlparse(url if "://" in url else f"https://{url}")
    host = (parsed.hostname or "").lower().rstrip(".")
    if not _host_matches_rule(host, rule):
        return False
    if rule.scheme:
        if (parsed.scheme or "").lower() != rule.scheme.lower():
            return False
    if rule.port is not None:
        eff = parsed.port
        if eff is None:
            if parsed.scheme == "https":
                eff = 443
            elif parsed.scheme == "http":
                eff = 80
        if eff != rule.port:
            return False
    if rule.path_prefix:
        path = parsed.path or "/"
        prefix = rule.path_prefix
        if not (path == prefix or path.startswith(prefix + "/")):
            return False
    return True


def _prohibited_matches(item: str, hay: str) -> bool:
    item_l = item.lower().strip()
    if not item_l:
        return False
    if item_l in hay:
        return True
    for key, needles in PROHIBITED_ALIASES.items():
        if key in item_l or item_l in key:
            if any(n in hay for n in needles):
                return True
    tokens = [t for t in re.split(r"\W+", item_l) if len(t) >= 4]
    if len(tokens) >= 2 and all(t in hay for t in tokens):
        return True
    if len(tokens) == 1 and tokens[0] in hay:
        return True
    return False


def _bullet_items(section: str) -> list[str]:
    items: list[str] = []
    for line in section.splitlines():
        stripped = line.strip().lstrip("-*").strip().strip("`")
        if stripped:
            items.append(stripped)
    return items


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


def _host_mentioned(text: str, host: str) -> bool:
    """True if host appears as its own token, not inside a longer hostname."""
    host = host.lower().strip(".")
    if not host:
        return False
    pattern = re.compile(
        rf"(?<![a-z0-9.*-]){re.escape(host)}(?![a-z0-9.-])",
        re.IGNORECASE,
    )
    return pattern.search(text) is not None


def _wildcard_mentioned(text: str, parent: str) -> bool:
    """True if SCOPE lists *.parent as a wildcard entry."""
    parent = parent.lower().strip(".")
    if not parent or "." not in parent:
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
