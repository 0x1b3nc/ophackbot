"""Per-target identity: program headers + A/B sessions (secrets/, never logged raw)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from .policy_guard import _sections_named, _split_front_matter

SESSIONS_FILE = "sessions.yaml"
EXAMPLE_NAME = "sessions.example.yaml"


@dataclass
class SessionCreds:
    name: str
    authorization: str = ""
    cookie: str = ""
    headers: dict[str, str] = field(default_factory=dict)

    def has_auth(self) -> bool:
        return bool(self.authorization or self.cookie or self.headers)

    def as_headers(self) -> dict[str, str]:
        out = dict(self.headers)
        if self.authorization:
            out.setdefault("Authorization", self.authorization)
        if self.cookie:
            out.setdefault("Cookie", self.cookie)
        return out

    def masked(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "authorization": _mask_secret(self.authorization),
            "cookie": _mask_cookie(self.cookie),
            "headers": {k: _mask_secret(v) for k, v in self.headers.items()},
            "ready": self.has_auth(),
        }


@dataclass
class Identity:
    target_dir: Path
    program_headers: dict[str, str] = field(default_factory=dict)
    sessions: dict[str, SessionCreds] = field(default_factory=dict)
    sessions_path: Path | None = None

    def session_names(self) -> list[str]:
        return sorted(self.sessions.keys())

    def ready_sessions(self) -> list[str]:
        return sorted(n for n, s in self.sessions.items() if s.has_auth())

    def get_session(self, name: str) -> SessionCreds | None:
        key = name.strip().upper() if len(name.strip()) <= 2 else name.strip()
        # Prefer exact, then case-insensitive, then single-letter upper
        if name in self.sessions:
            return self.sessions[name]
        for k, v in self.sessions.items():
            if k.lower() == name.lower():
                return v
        if key in self.sessions:
            return self.sessions[key]
        return None

    def merge_headers(self, session_name: str | None = None) -> dict[str, str]:
        out = dict(self.program_headers)
        if session_name:
            sess = self.get_session(session_name)
            if sess:
                out.update(sess.as_headers())
        return out

    def masked_summary(self) -> dict[str, Any]:
        return {
            "target": str(self.target_dir),
            "sessions_file": str(self.sessions_path) if self.sessions_path else None,
            "program_headers": {k: _mask_secret(v) for k, v in self.program_headers.items()},
            "program_header_count": len(self.program_headers),
            "sessions": {n: s.masked() for n, s in self.sessions.items()},
            "ready": self.ready_sessions(),
        }


def sessions_path_for(target_dir: Path) -> Path:
    return target_dir / "secrets" / SESSIONS_FILE


def load_identity(target_dir: Path) -> Identity:
    target_dir = Path(target_dir)
    program_headers = _headers_from_scope(target_dir)
    path = sessions_path_for(target_dir)
    sessions: dict[str, SessionCreds] = {}
    file_headers: dict[str, str] = {}

    if path.exists():
        raw = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or {}
        if not isinstance(raw, dict):
            raw = {}
        fh = raw.get("headers") or {}
        if isinstance(fh, dict):
            file_headers = {str(k): str(v) for k, v in fh.items() if v is not None}
        sess_block = raw.get("sessions") or {}
        if isinstance(sess_block, dict):
            for name, body in sess_block.items():
                if not isinstance(body, dict):
                    continue
                extra = body.get("headers") or {}
                extra_h = (
                    {str(k): str(v) for k, v in extra.items() if v is not None}
                    if isinstance(extra, dict)
                    else {}
                )
                sessions[str(name)] = SessionCreds(
                    name=str(name),
                    authorization=str(body.get("authorization") or body.get("bearer") or ""),
                    cookie=str(body.get("cookie") or ""),
                    headers=extra_h,
                )

    # Session-file headers overlay SCOPE headers (more specific for the hunt).
    merged_headers = {**program_headers, **file_headers}
    return Identity(
        target_dir=target_dir,
        program_headers=merged_headers,
        sessions=sessions,
        sessions_path=path if path.exists() else path,
    )


def save_session(
    target_dir: Path,
    name: str,
    *,
    authorization: str | None = None,
    cookie: str | None = None,
    headers: dict[str, str] | None = None,
    clear: bool = False,
) -> Identity:
    """Create/update one session in secrets/sessions.yaml. Values stay on disk only."""
    target_dir = Path(target_dir)
    secrets = target_dir / "secrets"
    secrets.mkdir(parents=True, exist_ok=True)
    path = sessions_path_for(target_dir)

    data: dict[str, Any] = {"headers": {}, "sessions": {}}
    if path.exists():
        loaded = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or {}
        if isinstance(loaded, dict):
            data["headers"] = loaded.get("headers") or {}
            data["sessions"] = loaded.get("sessions") or {}
            if not isinstance(data["headers"], dict):
                data["headers"] = {}
            if not isinstance(data["sessions"], dict):
                data["sessions"] = {}

    key = name.strip()
    if clear:
        data["sessions"].pop(key, None)
    else:
        entry = dict(data["sessions"].get(key) or {})
        if authorization is not None:
            if authorization.lower().startswith("bearer ") or not authorization:
                entry["authorization"] = authorization
            else:
                entry["authorization"] = f"Bearer {authorization}"
        if cookie is not None:
            entry["cookie"] = cookie
        if headers is not None:
            prev = entry.get("headers") if isinstance(entry.get("headers"), dict) else {}
            merged = {**prev, **headers}
            entry["headers"] = merged
        data["sessions"][key] = entry

    path.write_text(
        yaml.safe_dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    return load_identity(target_dir)


def save_program_headers(target_dir: Path, headers: dict[str, str]) -> Identity:
    """Merge program-level headers into sessions.yaml (not SCOPE.md)."""
    target_dir = Path(target_dir)
    secrets = target_dir / "secrets"
    secrets.mkdir(parents=True, exist_ok=True)
    path = sessions_path_for(target_dir)
    data: dict[str, Any] = {"headers": {}, "sessions": {}}
    if path.exists():
        loaded = yaml.safe_load(path.read_text(encoding="utf-8", errors="replace")) or {}
        if isinstance(loaded, dict):
            data["headers"] = dict(loaded.get("headers") or {})
            data["sessions"] = dict(loaded.get("sessions") or {})
    data["headers"].update(headers)
    path.write_text(
        yaml.safe_dump(data, default_flow_style=False, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    return load_identity(target_dir)


def ensure_example(target_dir: Path) -> Path:
    """Write sessions.example.yaml if missing (safe to commit)."""
    secrets = Path(target_dir) / "secrets"
    secrets.mkdir(parents=True, exist_ok=True)
    example = secrets / EXAMPLE_NAME
    if not example.exists():
        example.write_text(_EXAMPLE_YAML, encoding="utf-8")
    return example


def _headers_from_scope(target_dir: Path) -> dict[str, str]:
    scope_path = target_dir / "SCOPE.md"
    if not scope_path.exists():
        return {}
    raw = scope_path.read_text(encoding="utf-8", errors="replace")
    meta, body = _split_front_matter(raw)
    headers: dict[str, str] = {}
    if isinstance(meta, dict) and meta.get("headers"):
        h = meta["headers"]
        if isinstance(h, dict):
            headers.update({str(k): str(v) for k, v in h.items() if v is not None})
    # Markdown "Required Headers" bullets: `- Name: value` or `- \`Name\`: value`
    text = body if meta is not None else raw
    for section in _sections_named(text, ("required headers", "required headers / identity", "identity")):
        for line in section.splitlines():
            stripped = line.strip()
            if not stripped.startswith("-"):
                continue
            item = stripped.lstrip("- ").strip()
            if ":" not in item or item.lower().startswith("none"):
                continue
            key, _, val = item.partition(":")
            key = key.strip().strip("`")
            val = val.strip().strip("`")
            if key and val and val.lower() != "none documented yet.":
                headers[key] = val
    return headers


def _mask_secret(value: str) -> str:
    if not value:
        return "(empty)"
    if value.lower().startswith("bearer "):
        token = value[7:].strip()
        if len(token) <= 8:
            return "Bearer ***"
        return f"Bearer {token[:4]}…{token[-4:]}"
    if len(value) <= 8:
        return "***"
    return f"{value[:3]}…{value[-3:]} ({len(value)} chars)"


def _mask_cookie(value: str) -> str:
    if not value:
        return "(empty)"
    parts = [p.strip() for p in value.split(";") if p.strip()]
    return f"({len(parts)} cookie keys)" if parts else "(empty)"


_EXAMPLE_YAML = """# Copy to sessions.yaml and fill in. sessions.yaml is gitignored.
# Never commit live tokens.

headers:
  # X-Bug-Bounty: researcher@example.com

sessions:
  A:
    authorization: "Bearer <token-account-A>"
    # cookie: "session=<cookie-A>"
    # headers:
    #   X-CSRF-Token: "..."
  B:
    authorization: "Bearer <token-account-B>"
"""


# Re-export ScopePolicy load helper usage without circular imports in callers
__all__ = [
    "Identity",
    "SessionCreds",
    "ensure_example",
    "load_identity",
    "save_program_headers",
    "save_session",
    "sessions_path_for",
]
