"""Load per-target test accounts for session bootstrap (gitignored secrets/)."""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

ACCOUNTS_FILE = "accounts.yaml"
EXAMPLE_NAME = "accounts.example.yaml"


@dataclass
class Account:
    name: str
    username: str = ""
    password: str = ""
    role: str = "user"
    extra: dict[str, str] = field(default_factory=dict)

    def ready(self) -> bool:
        return bool(self.username and self.password)

    def masked(self) -> dict[str, Any]:
        return {
            "name": self.name,
            "username": self.username,
            "password": "***" if self.password else "",
            "role": self.role,
            "ready": self.ready(),
        }


@dataclass
class LoginConfig:
    path: str = "/login"
    method: str = "POST"
    user_field: str = "username"
    pass_field: str = "password"
    csrf_field: str = "csrf_token"


@dataclass
class AccountsFile:
    target_dir: Path
    accounts: dict[str, Account] = field(default_factory=dict)
    login: LoginConfig = field(default_factory=LoginConfig)

    def ready_names(self) -> list[str]:
        return sorted(n for n, a in self.accounts.items() if a.ready())

    def get(self, name: str) -> Account | None:
        if name in self.accounts:
            return self.accounts[name]
        for k, v in self.accounts.items():
            if k.lower() == name.lower():
                return v
        return None

    def masked_summary(self) -> dict[str, Any]:
        return {
            "path": str(self.target_dir / "secrets" / ACCOUNTS_FILE),
            "ready": self.ready_names(),
            "login_path": self.login.path,
            "accounts": {k: v.masked() for k, v in self.accounts.items()},
        }


def accounts_path(target_dir: Path) -> Path:
    return Path(target_dir) / "secrets" / ACCOUNTS_FILE


def has_accounts(target_dir: Path) -> bool:
    path = accounts_path(target_dir)
    if not path.exists():
        return False
    data = load_accounts(target_dir)
    return len(data.ready_names()) >= 1


def load_accounts(target_dir: Path) -> AccountsFile:
    path = accounts_path(target_dir)
    out = AccountsFile(target_dir=Path(target_dir))
    if not path.exists():
        return out
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception:  # noqa: BLE001
        return out
    if not isinstance(raw, dict):
        return out
    login_raw = raw.get("login") or {}
    if isinstance(login_raw, dict):
        out.login = LoginConfig(
            path=str(login_raw.get("path") or "/login"),
            method=str(login_raw.get("method") or "POST").upper(),
            user_field=str(login_raw.get("user_field") or "username"),
            pass_field=str(login_raw.get("pass_field") or "password"),
            csrf_field=str(login_raw.get("csrf_field") or "csrf_token"),
        )
    accounts = raw.get("accounts") or {}
    if isinstance(accounts, dict):
        for name, meta in accounts.items():
            if not isinstance(meta, dict):
                continue
            extra = {
                str(k): str(v)
                for k, v in meta.items()
                if k not in {"username", "password", "role", "email", "user"}
            }
            out.accounts[str(name)] = Account(
                name=str(name),
                username=str(meta.get("username") or meta.get("email") or meta.get("user") or ""),
                password=str(meta.get("password") or ""),
                role=str(meta.get("role") or "user"),
                extra=extra,
            )
    return out


def ensure_accounts_example(target_dir: Path) -> Path:
    """Copy example next to secrets if missing (never overwrite live accounts)."""
    secrets = Path(target_dir) / "secrets"
    secrets.mkdir(parents=True, exist_ok=True)
    dest = secrets / EXAMPLE_NAME
    if dest.exists():
        return dest
    sample = (
        "# Copy to accounts.yaml and fill in. accounts.yaml is gitignored.\n"
        "accounts:\n"
        "  A:\n"
        "    username: user_a@example.com\n"
        "    password: ChangeMe-A\n"
        "    role: user\n"
        "  B:\n"
        "    username: user_b@example.com\n"
        "    password: ChangeMe-B\n"
        "    role: user\n"
        "login:\n"
        "  path: /login\n"
    )
    dest.write_text(sample, encoding="utf-8")
    return dest


def save_account(
    target_dir: Path,
    name: str,
    *,
    username: str | None = None,
    password: str | None = None,
    role: str | None = None,
) -> AccountsFile:
    """Merge one account into secrets/accounts.yaml (preserve login: and other accounts)."""
    path = accounts_path(target_dir)
    path.parent.mkdir(parents=True, exist_ok=True)
    raw: dict[str, Any] = {}
    if path.exists():
        try:
            loaded = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
            if isinstance(loaded, dict):
                raw = loaded
        except Exception:  # noqa: BLE001
            raw = {}
    accounts = raw.get("accounts")
    if not isinstance(accounts, dict):
        accounts = {}
    key = str(name).strip() or "A"
    # Prefer existing casing (A/B)
    for existing in list(accounts.keys()):
        if str(existing).lower() == key.lower():
            key = str(existing)
            break
    entry = dict(accounts.get(key) or {}) if isinstance(accounts.get(key), dict) else {}
    if username is not None:
        entry["username"] = str(username)
        entry.pop("email", None)
        entry.pop("user", None)
    if password is not None:
        entry["password"] = str(password)
    if role is not None:
        entry["role"] = str(role)
    elif "role" not in entry:
        entry["role"] = "user"
    accounts[key] = entry
    raw["accounts"] = accounts
    if "login" not in raw or not isinstance(raw.get("login"), dict):
        raw["login"] = {
            "path": "/login",
            "method": "POST",
            "user_field": "username",
            "pass_field": "password",
            "csrf_field": "csrf_token",
        }
    path.write_text(
        yaml.safe_dump(raw, default_flow_style=False, allow_unicode=True, sort_keys=False),
        encoding="utf-8",
    )
    return load_accounts(target_dir)
