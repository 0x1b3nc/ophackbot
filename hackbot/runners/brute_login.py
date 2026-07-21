"""Capped login bruteforce / password spray for authorized tests.

Hard caps: max 20 attempts, tiny default wordlist. Needs level-3 SCOPE or /force.
"""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .. import ui
from ..identity import load_identity
from ..redaction import redact_text
from .base import RunnerResult, require_in_scope

MAX_ATTEMPTS = 20
DEFAULT_PASSWORDS = (
    "password",
    "Password1!",
    "123456",
    "admin",
    "welcome",
    "letmein",
    "qwerty",
    "test",
    "Test123!",
    "changeme",
)


def brute_login(
    target_dir: Path,
    login_url: str,
    *,
    username: str = "test",
    passwords: list[str] | None = None,
    user_field: str = "username",
    pass_field: str = "password",
    approve: bool = False,
    force: bool = False,
    timeout: float = 10.0,
) -> RunnerResult:
    require_in_scope(
        target_dir,
        login_url,
        action="brute force password spray",
        force=force,
    )
    url = login_url if "://" in login_url else f"https://{login_url}"
    wordlist = list(passwords or DEFAULT_PASSWORDS)[:MAX_ATTEMPTS]
    # Optional: secrets/wordlist-test.txt
    wl_path = Path(target_dir) / "secrets" / "wordlist-test.txt"
    if wl_path.exists() and not passwords:
        lines = [
            ln.strip()
            for ln in wl_path.read_text(encoding="utf-8", errors="replace").splitlines()
            if ln.strip() and not ln.strip().startswith("#")
        ]
        if lines:
            wordlist = lines[:MAX_ATTEMPTS]

    identity = load_identity(target_dir)
    base_headers = identity.merge_headers(None)
    base_headers.setdefault("Content-Type", "application/x-www-form-urlencoded")
    base_headers.setdefault("User-Agent", "hackbot-brute-login")

    plan = {
        "url": url,
        "username": username,
        "attempts": len(wordlist),
        "cap": MAX_ATTEMPTS,
        "fields": {user_field: username, pass_field: "***"},
    }
    ui.code_panel(json.dumps(plan, indent=2), title="brute_login", lexer="json")
    cmd = ["brute_login", url, username, str(len(wordlist))]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    attempts: list[dict[str, Any]] = []
    success: dict[str, Any] | None = None
    for pwd in wordlist:
        body = urllib.parse.urlencode({user_field: username, pass_field: pwd}).encode()
        req = urllib.request.Request(url, data=body, method="POST", headers=base_headers)
        status = 0
        length = 0
        err = ""
        try:
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = int(getattr(resp, "status", None) or resp.getcode())
                raw = resp.read(8000)
                length = len(raw)
                text = raw.decode("utf-8", errors="replace").lower()
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            try:
                raw = exc.read(4000)
                length = len(raw)
                text = raw.decode("utf-8", errors="replace").lower()
            except Exception:  # noqa: BLE001
                text = ""
        except Exception as exc:  # noqa: BLE001
            err = f"{type(exc).__name__}: {exc}"
            text = ""

        # Heuristic success: 2xx/3xx and body lacks obvious failure markers
        fail_marks = ("invalid", "incorrect", "failed", "unauthorized", "wrong password")
        ok_marks = ("dashboard", "logout", "welcome", "success", "token")
        looks_fail = any(m in text for m in fail_marks)
        looks_ok = any(m in text for m in ok_marks)
        hit = status in {200, 201, 204, 302, 303} and looks_ok and not looks_fail
        row = {
            "password_redacted": redact_text(pwd),
            "status": status,
            "length": length,
            "error": err,
            "hit": hit,
        }
        attempts.append(row)
        if hit:
            success = row
            break

    summary = {
        "tried": len(attempts),
        "success": bool(success),
        "success_row": success,
        "attempts": attempts,
    }
    ui.kv("success", "YES" if success else "no")
    ui.kv("tried", str(len(attempts)))
    return RunnerResult(cmd, True, 0, json.dumps(summary), "", "executed")
