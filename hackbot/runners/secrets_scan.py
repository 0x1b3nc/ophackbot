"""Scan in-scope URLs for exposed tokens / credential-like secrets."""

from __future__ import annotations

import json
import re
import urllib.error
import urllib.request
from pathlib import Path
from typing import Any

from .. import ui
from ..redaction import redact_text
from .base import RunnerResult, require_in_scope

# Paths commonly leaking config/secrets in apps (relative to origin)
DEFAULT_PATHS = (
    "/",
    "/.env",
    "/.env.local",
    "/config.js",
    "/env.js",
    "/api/config",
    "/api/v1/config",
    "/actuator/env",
    "/.git/config",
    "/robots.txt",
)

# Capture groups kept short; values redacted in output
PATTERNS: tuple[tuple[str, re.Pattern[str]], ...] = (
    ("aws_key", re.compile(r"AKIA[0-9A-Z]{16}")),
    ("jwt", re.compile(r"eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}")),
    ("github_pat", re.compile(r"ghp_[A-Za-z0-9]{20,}")),
    ("slack_token", re.compile(r"xox[baprs]-[A-Za-z0-9-]{10,}")),
    ("generic_api_key", re.compile(r"(?i)(?:api[_-]?key|apikey|secret[_-]?key)\s*[:=]\s*['\"]?([A-Za-z0-9_\-]{16,})")),
    ("bearer_literal", re.compile(r"(?i)bearer\s+([A-Za-z0-9\-._~+/]+=*)")),
    ("password_assign", re.compile(r"(?i)(?:password|passwd|pwd)\s*[:=]\s*['\"]([^'\"]{4,})['\"]")),
    ("private_key", re.compile(r"-----BEGIN (?:RSA |EC )?PRIVATE KEY-----")),
)


def secrets_scan(
    target_dir: Path,
    base: str,
    *,
    paths: list[str] | None = None,
    approve: bool = False,
    force: bool = False,
    timeout: float = 12.0,
    apply_session: bool = True,
) -> RunnerResult:
    require_in_scope(target_dir, base, action="secrets scan recon", force=force)
    origin = base if "://" in base else f"https://{base}"
    origin = origin.rstrip("/")
    # If base has a path beyond host, still scan origin root + that URL
    from urllib.parse import urlparse

    parsed = urlparse(origin if "://" in origin else f"https://{origin}")
    root = f"{parsed.scheme}://{parsed.netloc}"
    scan_paths = list(paths or DEFAULT_PATHS)
    if parsed.path and parsed.path not in {"", "/"}:
        scan_paths.insert(0, parsed.path)

    plan = {"base": root, "paths": scan_paths[:20], "approve": approve, "apply_session": apply_session}
    ui.code_panel(json.dumps(plan, indent=2), title="secrets_scan", lexer="json")
    cmd = ["secrets_scan", root, f"paths={len(scan_paths)}"]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    findings: list[dict[str, Any]] = []
    fetched = 0
    applied_session = ""
    for rel in scan_paths[:20]:
        url = rel if rel.startswith("http") else root + (rel if rel.startswith("/") else "/" + rel)
        try:
            req = urllib.request.Request(url, method="GET", headers={"User-Agent": "hackbot-secrets-scan"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                status = int(getattr(resp, "status", None) or resp.getcode())
                body = resp.read(250_000).decode("utf-8", errors="replace")
        except urllib.error.HTTPError as exc:
            status = int(exc.code)
            try:
                body = exc.read(100_000).decode("utf-8", errors="replace")
            except Exception:  # noqa: BLE001
                body = ""
        except Exception as exc:  # noqa: BLE001
            findings.append({"url": url, "error": f"{type(exc).__name__}: {exc}"})
            continue
        fetched += 1
        for kind, pat in PATTERNS:
            for match in pat.finditer(body):
                snippet = match.group(0)[:80]
                findings.append(
                    {
                        "url": url,
                        "status": status,
                        "kind": kind,
                        "match_redacted": redact_text(snippet),
                    }
                )
                # Apply usable auth material into session LEAKED (never log raw)
                if kind in {"jwt", "bearer_literal"} and apply_session:
                    try:
                        from ..identity import save_session

                        raw_tok = match.group(0)
                        if kind == "bearer_literal" and match.lastindex:
                            raw_tok = match.group(1)
                        save_session(target_dir, "LEAKED", authorization=raw_tok)
                        applied_session = "LEAKED"
                    except Exception:  # noqa: BLE001
                        pass
                break  # one hit per kind per URL is enough signal

    unique_kinds = sorted({f["kind"] for f in findings if "kind" in f})
    summary = {
        "fetched": fetched,
        "hit_count": len([f for f in findings if "kind" in f]),
        "kinds": unique_kinds,
        "findings": findings[:40],
        "applied_session": applied_session or None,
    }
    ui.kv("hits", str(summary["hit_count"]))
    ui.kv("kinds", ", ".join(unique_kinds) or "(none)")
    stdout = json.dumps(summary)
    return RunnerResult(cmd, True, 0, stdout, "", "executed")
