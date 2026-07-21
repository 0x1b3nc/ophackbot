"""Import A/B sessions from operator-provided credential files (NL-friendly)."""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any

import yaml

# bearer / cookie patterns (values never logged by callers — use masked summaries)
_BEARER_RE = re.compile(
    r"(?i)(?:bearer|authorization|token|access[_-]?token|jwt)\s*[:=]?\s*(?:Bearer\s+)?([A-Za-z0-9_\-\.=+/]{8,})"
)
_COOKIE_RE = re.compile(
    r"(?i)(?:cookie|cookies|session[_-]?cookie)\s*[:=]\s*([^\n\"']{8,})"
)
_AUTH_HEADER_RE = re.compile(
    r"(?i)authorization\s*[:=]\s*(Bearer\s+[^\s\"']+|Token\s+[^\s\"']+|[^\s\"']{12,})"
)
_SESSION_LINE_RE = re.compile(
    r"(?i)(?:session|conta|account|user)\s*([AB])\s+(?:bearer|authorization|token)\s+(\S+)"
)
_SESSION_COOKIE_LINE_RE = re.compile(
    r"(?i)(?:session|conta|account|user)\s*([AB])\s+cookie\s+(\S+)"
)


def parse_sessions_text(text: str) -> dict[str, dict[str, str]]:
    """Extract session A/B (and named) creds from yaml/json/env/prose.

    Returns {name: {authorization?, cookie?, ...headers}}.
    """
    text = text.strip()
    if not text:
        return {}

    # Try structured first
    structured = _from_structured(text)
    if structured:
        return structured

    return _from_prose(text)


def _from_structured(text: str) -> dict[str, dict[str, str]]:
    data: Any = None
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        try:
            data = yaml.safe_load(text)
        except Exception:
            data = None
    if not isinstance(data, dict):
        return {}

    out: dict[str, dict[str, str]] = {}

    # hackbot sessions.yaml shape: {sessions: {A: {...}}, headers: {...}}
    sessions = data.get("sessions") if isinstance(data.get("sessions"), dict) else None
    if sessions:
        for name, body in sessions.items():
            parsed = _normalize_session_body(body)
            if parsed:
                out[str(name)] = parsed
        return out

    # Flat {A: {bearer: ...}, B: {...}} or {account_a: "..."}
    for key, body in data.items():
        if key in {"headers", "program_headers", "in_scope", "out_of_scope"}:
            continue
        if isinstance(body, (dict, str)):
            parsed = _normalize_session_body(body)
            if parsed:
                name = _canon_name(str(key))
                out[name] = parsed

    # {tokens: [{name: A, bearer: ...}]}
    for list_key in ("tokens", "accounts", "users", "identities"):
        items = data.get(list_key)
        if not isinstance(items, list):
            continue
        for item in items:
            if not isinstance(item, dict):
                continue
            name = _canon_name(str(item.get("name") or item.get("account") or item.get("id") or ""))
            if not name:
                name = "A" if "A" not in out else ("B" if "B" not in out else f"S{len(out)+1}")
            parsed = _normalize_session_body(item)
            if parsed:
                out[name] = parsed

    return out


def _normalize_session_body(body: Any) -> dict[str, str]:
    if isinstance(body, str):
        s = body.strip()
        if not s:
            return {}
        if s.lower().startswith("bearer "):
            return {"authorization": s}
        if "=" in s and ("session" in s.lower() or "token" in s.lower() or len(s) > 20):
            # cookie-ish
            return {"cookie": s}
        return {"authorization": f"Bearer {s}" if not s.lower().startswith("bearer") else s}

    if not isinstance(body, dict):
        return {}

    out: dict[str, str] = {}
    auth = (
        body.get("authorization")
        or body.get("Authorization")
        or body.get("bearer")
        or body.get("token")
        or body.get("access_token")
        or body.get("jwt")
    )
    if auth:
        auth_s = str(auth).strip()
        if auth_s and not auth_s.lower().startswith("bearer ") and not auth_s.lower().startswith(
            "token "
        ):
            # JWT-looking or opaque token
            if auth_s.count(".") == 2 or len(auth_s) > 20:
                auth_s = f"Bearer {auth_s}"
        out["authorization"] = auth_s

    cookie = body.get("cookie") or body.get("Cookie") or body.get("cookies")
    if cookie:
        out["cookie"] = str(cookie).strip()

    headers = body.get("headers")
    if isinstance(headers, dict):
        for k, v in headers.items():
            if str(k).lower() == "authorization" and "authorization" not in out:
                out["authorization"] = str(v)
            elif str(k).lower() == "cookie" and "cookie" not in out:
                out["cookie"] = str(v)

    return out if out.get("authorization") or out.get("cookie") else {}


def _canon_name(name: str) -> str:
    n = name.strip()
    if not n:
        return ""
    low = n.lower().replace(" ", "_")
    if low in {"a", "account_a", "user_a", "attacker", "low"}:
        return "A"
    if low in {"b", "account_b", "user_b", "victim", "high"}:
        return "B"
    if len(n) <= 2:
        return n.upper()
    return n


def _from_prose(text: str) -> dict[str, dict[str, str]]:
    out: dict[str, dict[str, str]] = {}

    for m in _SESSION_LINE_RE.finditer(text):
        name = _canon_name(m.group(1))
        out[name] = {"authorization": _as_bearer(m.group(2))}
    for m in _SESSION_COOKIE_LINE_RE.finditer(text):
        name = _canon_name(m.group(1))
        out.setdefault(name, {})["cookie"] = m.group(2).strip().rstrip(",;")

    if out:
        return out

    # Split by session markers
    blocks = re.split(r"(?i)(?:^|\n)\s*(?:session\s+)?([AB]|account\s*[AB]|user\s*[AB])\b", text)
    if len(blocks) >= 3:
        i = 1
        while i + 1 < len(blocks):
            name = _canon_name(blocks[i])
            body = blocks[i + 1]
            parsed = _extract_creds_from_chunk(body)
            if parsed:
                out[name or ("A" if "A" not in out else "B")] = parsed
            i += 2

    if not out:
        bearers = _BEARER_RE.findall(text)
        cookies = _COOKIE_RE.findall(text)
        auths = _AUTH_HEADER_RE.findall(text)
        tokens = auths or bearers
        if len(tokens) >= 2:
            out["A"] = {"authorization": _as_bearer(tokens[0])}
            out["B"] = {"authorization": _as_bearer(tokens[1])}
        elif len(tokens) == 1:
            out["A"] = {"authorization": _as_bearer(tokens[0])}
        if cookies and "A" in out and "cookie" not in out["A"]:
            out["A"]["cookie"] = cookies[0].strip()
        elif cookies and "A" not in out:
            out["A"] = {"cookie": cookies[0].strip()}
        if len(cookies) >= 2:
            out.setdefault("B", {})["cookie"] = cookies[1].strip()

    return out


def _extract_creds_from_chunk(chunk: str) -> dict[str, str]:
    out: dict[str, str] = {}
    m = _AUTH_HEADER_RE.search(chunk) or _BEARER_RE.search(chunk)
    if m:
        out["authorization"] = _as_bearer(m.group(1))
    m = _COOKIE_RE.search(chunk)
    if m:
        out["cookie"] = m.group(1).strip().rstrip(",;")
    return out


def _as_bearer(raw: str) -> str:
    s = raw.strip().strip("\"'")
    if s.lower().startswith("bearer ") or s.lower().startswith("token "):
        return s
    return f"Bearer {s}"


def load_sessions_from_path(path: Path) -> dict[str, dict[str, str]]:
    text = path.read_text(encoding="utf-8", errors="replace")
    return parse_sessions_text(text)


def extract_path_mentions(text: str) -> list[str]:
    """Pull likely file paths from a natural-language prompt (PT-BR/EN)."""
    found: list[str] = []
    patterns = (
        r'(?i)(?:arquivo|file|ficheiro)\s+[\"\']?([^\s\"\']+\.(?:ya?ml|json|env|txt|md|csv|log|conf|ini|png|jpe?g|webp|gif))[\"\']?'
        r'\s+(?:na|no|em|in|at)\s+(?:pasta|folder|dir(?:ectory)?)\s+[\"\']?([^\s\"\']+)[\"\']?',
        r'(?i)(?:na|no|em|in)\s+(?:pasta|folder|dir(?:ectory)?)\s+[\"\']?([^\s\"\']+)[\"\']?'
        r'\s+(?:o\s+)?(?:arquivo|file)\s+[\"\']?([^\s\"\']+)[\"\']?',
        r'(?i)(?:arquivo|file|ficheiro|path)\s+[\"\']?([^\s\"\']+\.(?:ya?ml|json|env|txt|md|csv|log|conf|ini|png|jpe?g|webp|gif|har|js))[\"\']?',
        r'(?i)(?:~|/|\\|[A-Za-z]:\\)[^\s\"\']+\.(?:ya?ml|json|env|txt|md|png|jpe?g|webp|gif|har|js)',
        r'(?i)(?:targets|secrets|Downloads|Desktop|Documentos|Documents)/[^\s\"\']+',
    )
    for pat in patterns:
        for m in re.finditer(pat, text):
            if m.lastindex and m.lastindex >= 2 and m.group(2):
                g1, g2 = m.group(1), m.group(2)
                # Decide which is folder vs file
                if re.search(r"\.(ya?ml|json|env|txt|md|png|jpe?g|webp|gif)$", g1, re.I):
                    found.append(f"{g2.rstrip('/\\')}/{g1}")
                else:
                    found.append(f"{g1.rstrip('/\\')}/{g2}")
            else:
                found.append(m.group(1) if m.lastindex else m.group(0))
    # Dedup preserve order
    out: list[str] = []
    seen: set[str] = set()
    for p in found:
        p = p.strip().strip("\"'.,;")
        key = p.lower()
        if p and key not in seen:
            seen.add(key)
            out.append(p)
    return out
