"""First-class scoped curl — same rails as http_request (SCOPE + approve + sessions)."""

from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from .. import ui
from ..identity import load_identity
from ..policy_guard import host_from_target
from ..redaction import redact_text
from .base import RunnerResult, require_in_scope


def curl_request(
    target_dir: Path,
    url: str,
    *,
    method: str = "GET",
    session: str = "",
    body: str = "",
    content_type: str = "",
    extra_headers: dict[str, str] | None = None,
    approve: bool = False,
    force: bool = False,
    timeout: float = 20.0,
    label: str = "",
) -> RunnerResult:
    """Run curl against an in-scope URL with session headers. Dry-run default."""
    require_in_scope(
        target_dir,
        url,
        action="curl_request",
        force=force,
        tool="curl_request",
    )
    full_url = url if "://" in url else f"https://{url}"
    method = (method or "GET").upper()
    identity = load_identity(target_dir)
    headers = identity.merge_headers(session or None)
    if extra_headers:
        headers.update(extra_headers)
    if body:
        if content_type:
            headers.setdefault("Content-Type", content_type)
        elif not any(k.lower() == "content-type" for k in headers):
            headers.setdefault("Content-Type", "application/json")

    masked = {
        k: ("***" if k.lower() in {"authorization", "cookie", "x-api-key"} else v)
        for k, v in headers.items()
    }
    plan = {
        "method": method,
        "url": full_url,
        "session": session or "(none)",
        "headers": masked,
        "body_len": len(body or ""),
        "label": label or "",
        "transport": "curl",
        "approve": approve,
    }
    ui.code_panel(json.dumps(plan, indent=2), title="curl_request", lexer="json")
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(
            ["curl", "-X", method, full_url],
            False,
            None,
            json.dumps({"dry_run": True, **plan}),
            "",
            "dry-run",
        )

    curl_bin = shutil.which("curl")
    if not curl_bin:
        from . import http_request as http_mod

        return http_mod.http_request(
            target_dir,
            full_url,
            method=method,
            session=session or None,
            body=body or None,
            content_type=content_type or None,
            extra_headers=extra_headers,
            approve=True,
            force=force,
            timeout=timeout,
            label=label or "curl_fallback",
        )

    with tempfile.TemporaryDirectory(prefix="hb_curl_") as tmp:
        body_path = Path(tmp) / "body.bin"
        hdr_path = Path(tmp) / "hdrs.txt"
        argv = [
            curl_bin,
            "-sS",
            "-L",
            "--max-redirs",
            "5",
            "--max-time",
            str(float(timeout)),
            "-X",
            method,
            "-D",
            str(hdr_path),
            "-o",
            str(body_path),
            "-w",
            "%{http_code}\n%{url_effective}\n",
        ]
        for k, v in headers.items():
            argv.extend(["-H", f"{k}: {v}"])
        if body:
            data_file = Path(tmp) / "req.body"
            data_file.write_text(body, encoding="utf-8")
            argv.extend(["--data-binary", f"@{data_file}"])
        argv.append(full_url)

        try:
            proc = subprocess.run(
                argv,
                capture_output=True,
                text=True,
                timeout=float(timeout) + 5,
                check=False,
            )
        except subprocess.TimeoutExpired:
            return RunnerResult(
                ["curl", "-X", method, full_url],
                True,
                124,
                json.dumps({"ok": False, "error": "timeout", "url": full_url}),
                "",
                "timeout",
            )

        meta_lines = (proc.stdout or "").strip().splitlines()
        status = 0
        final_url = full_url
        if meta_lines:
            try:
                status = int(meta_lines[0].strip())
            except ValueError:
                status = 0
            if len(meta_lines) > 1:
                final_url = meta_lines[1].strip() or full_url

        if final_url and urlparse_host(final_url) != urlparse_host(full_url):
            try:
                require_in_scope(
                    target_dir,
                    final_url,
                    action="curl_request redirect",
                    force=force,
                    tool="curl_request",
                )
            except PermissionError as exc:
                return RunnerResult(
                    ["curl", "-X", method, full_url],
                    True,
                    1,
                    json.dumps({"ok": False, "error": str(exc), "final_url": final_url}),
                    "",
                    "oos_redirect",
                )

        raw_body = body_path.read_bytes()[:200_000] if body_path.exists() else b""
        resp_body = raw_body.decode("utf-8", errors="replace")
        resp_headers: dict[str, str] = {}
        if hdr_path.exists():
            text = hdr_path.read_text(encoding="utf-8", errors="replace")
            blocks = text.replace("\r\n", "\n").split("\n\n")
            last = ""
            for block in reversed(blocks):
                if block.strip():
                    last = block
                    break
            for line in last.splitlines():
                if ":" in line and not line.lower().startswith("http/"):
                    hk, _, hv = line.partition(":")
                    resp_headers[hk.strip()] = hv.strip()

        out: dict[str, Any] = {
            "ok": proc.returncode == 0,
            "method": method,
            "url": full_url,
            "final_url": final_url,
            "session": session or None,
            "label": label or (session or "anon"),
            "status": status,
            "length": len(resp_body),
            "headers": {
                k: ("***" if k.lower() in {"set-cookie", "authorization"} else v)
                for k, v in list(resp_headers.items())[:40]
            },
            "body_preview": redact_text(resp_body[:2000]),
            "body": resp_body[:50_000],
            "transport": "curl",
            "stderr": redact_text((proc.stderr or "")[:500]),
            "returncode": proc.returncode,
            "host": host_from_target(full_url),
        }
        ui.action_line("curl", f"{method} {full_url} → {status}", ok=bool(status))
        return RunnerResult(
            ["curl", "-X", method, full_url, f"session={session or '-'}"],
            True,
            proc.returncode,
            json.dumps(out),
            "",
            "executed",
        )


def urlparse_host(url: str) -> str:
    return (host_from_target(url) or "").lower()
