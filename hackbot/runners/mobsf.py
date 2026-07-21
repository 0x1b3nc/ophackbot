"""MobSF REST client — upload/scan against local or remote MobSF."""

from __future__ import annotations

import json
import os
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .. import ui
from ..redaction import redact_text
from .base import RunnerResult


def _base() -> str:
    return (os.environ.get("HACKBOT_MOBSF_URL") or "http://127.0.0.1:8000").rstrip("/")


def _api_key() -> str:
    return (os.environ.get("HACKBOT_MOBSF_API_KEY") or os.environ.get("MOBSF_API_KEY") or "").strip()


def mobsf_health(*, base_url: str = "", timeout: float = 5.0) -> dict[str, Any]:
    base = (base_url or _base()).rstrip("/")
    tried: list[Any] = []
    for path in ("/api/v1/health", "/"):
        full = base + path
        try:
            req = urllib.request.Request(
                full,
                headers={"Authorization": _api_key(), "User-Agent": "hackbot-mobsf"},
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(2000).decode("utf-8", errors="replace")
                return {
                    "ok": True,
                    "up": True,
                    "base": base,
                    "path": path,
                    "preview": redact_text(body[:200]),
                    "api_key_set": bool(_api_key()),
                }
        except Exception as exc:  # noqa: BLE001
            tried.append({"url": full, "error": type(exc).__name__})
    return {
        "ok": True,
        "up": False,
        "base": base,
        "tried": tried,
        "api_key_set": bool(_api_key()),
        "hint": "Start MobSF and set HACKBOT_MOBSF_URL / HACKBOT_MOBSF_API_KEY.",
    }


def mobsf_upload(
    target_dir: Path,
    apk_path: Path,
    *,
    approve: bool = False,
    base_url: str = "",
    timeout: float = 60.0,
) -> RunnerResult:
    del target_dir
    base = (base_url or _base()).rstrip("/")
    key = _api_key()
    plan = {"apk": str(apk_path), "base": base, "approve": approve, "api_key_set": bool(key)}
    ui.code_panel(json.dumps(plan, indent=2), title="mobsf_upload", lexer="json")
    cmd = ["mobsf_upload", str(apk_path)]
    if not apk_path.exists():
        return RunnerResult(cmd, False, None, json.dumps({"ok": False, "error": "missing apk"}), "", "error")
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")
    if not key:
        return RunnerResult(
            cmd,
            False,
            None,
            json.dumps({"ok": False, "error": "missing_api_key", "hint": "Set HACKBOT_MOBSF_API_KEY"}),
            "",
            "error",
        )

    boundary = "----hackbotmobsf"
    filename = apk_path.name
    raw = apk_path.read_bytes()
    body = (
        f"--{boundary}\r\n"
        f'Content-Disposition: form-data; name="file"; filename="{filename}"\r\n'
        "Content-Type: application/octet-stream\r\n\r\n"
    ).encode() + raw + f"\r\n--{boundary}--\r\n".encode()

    req = urllib.request.Request(
        base + "/api/v1/upload",
        data=body,
        method="POST",
        headers={
            "Authorization": key,
            "Content-Type": f"multipart/form-data; boundary={boundary}",
            "User-Agent": "hackbot-mobsf",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read(8000).decode("utf-8", errors="replace")
        data = json.loads(text) if text.strip().startswith("{") else {"raw": text[:500]}
        return RunnerResult(
            cmd,
            True,
            0,
            json.dumps({"ok": True, "upload": data}),
            "",
            "executed",
        )
    except urllib.error.HTTPError as exc:
        detail = exc.read(2000).decode("utf-8", errors="replace") if exc.fp else ""
        return RunnerResult(
            cmd,
            False,
            int(exc.code),
            json.dumps({"ok": False, "error": f"HTTP {exc.code}", "detail": redact_text(detail[:300])}),
            "",
            "error",
        )
    except Exception as exc:  # noqa: BLE001
        return RunnerResult(
            cmd,
            False,
            None,
            json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}),
            "",
            "error",
        )


def mobsf_scan(
    *,
    hash_id: str,
    scan_type: str = "apk",
    approve: bool = False,
    base_url: str = "",
    timeout: float = 120.0,
) -> RunnerResult:
    base = (base_url or _base()).rstrip("/")
    key = _api_key()
    plan = {"hash": hash_id, "scan_type": scan_type, "approve": approve}
    cmd = ["mobsf_scan", hash_id]
    ui.code_panel(json.dumps(plan, indent=2), title="mobsf_scan", lexer="json")
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")
    if not key:
        return RunnerResult(cmd, False, None, json.dumps({"ok": False, "error": "missing_api_key"}), "", "error")
    body = urllib.parse.urlencode({"hash": hash_id, "scan_type": scan_type}).encode()
    req = urllib.request.Request(
        base + "/api/v1/scan",
        data=body,
        method="POST",
        headers={
            "Authorization": key,
            "Content-Type": "application/x-www-form-urlencoded",
        },
    )
    try:
        with urllib.request.urlopen(req, timeout=timeout) as resp:
            text = resp.read(20_000).decode("utf-8", errors="replace")
        data = json.loads(text) if text.strip().startswith("{") else {"raw": text[:800]}
        return RunnerResult(cmd, True, 0, json.dumps({"ok": True, "scan": data}), "", "executed")
    except Exception as exc:  # noqa: BLE001
        return RunnerResult(
            cmd,
            False,
            None,
            json.dumps({"ok": False, "error": f"{type(exc).__name__}: {exc}"}),
            "",
            "error",
        )
