"""Capped hidden-parameter miner (Arjun-style lite)."""

from __future__ import annotations

import json
import urllib.error
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .. import ui
from .base import RunnerResult, require_in_scope

DEFAULT_WORDS = (
    "id",
    "user",
    "user_id",
    "account",
    "uid",
    "token",
    "debug",
    "test",
    "admin",
    "redirect",
    "next",
    "url",
    "callback",
    "return",
    "file",
    "path",
    "page",
    "q",
    "query",
    "search",
    "filter",
    "sort",
    "order",
    "limit",
    "offset",
    "format",
    "json",
    "api_key",
    "key",
    "secret",
    "role",
    "email",
    "ref",
    "src",
    "dest",
    "target",
    "lang",
    "locale",
    "version",
    "v",
)


def mine_params(
    target_dir: Path,
    url: str,
    *,
    wordlist: list[str] | None = None,
    approve: bool = False,
    force: bool = False,
    timeout: float = 10.0,
    max_words: int = 40,
) -> RunnerResult:
    require_in_scope(target_dir, url, action="parameter mining fuzz", force=force)
    words = list(wordlist or DEFAULT_WORDS)[:max_words]
    plan = {"url": url, "words": len(words), "approve": approve}
    ui.code_panel(json.dumps(plan, indent=2), title="mine_params", lexer="json")
    cmd = ["mine_params", url, f"words={len(words)}"]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
    base_qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)

    def _fetch(qs: dict[str, list[str]]) -> tuple[int, int]:
        query = urllib.parse.urlencode({k: v[0] if v else "" for k, v in qs.items()})
        probe = urllib.parse.urlunparse(
            (parsed.scheme, parsed.netloc, parsed.path, "", query, "")
        )
        try:
            req = urllib.request.Request(probe, headers={"User-Agent": "hackbot-param-miner"})
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                body = resp.read(80_000)
                return int(getattr(resp, "status", None) or resp.getcode()), len(body)
        except urllib.error.HTTPError as exc:
            body = exc.read(40_000) if exc.fp else b""
            return int(exc.code), len(body)
        except Exception:
            return 0, 0

    base_status, base_len = _fetch(base_qs)
    found: list[dict[str, Any]] = []
    for word in words:
        if word in base_qs:
            continue
        qs = dict(base_qs)
        qs[word] = ["hackbot1"]
        st, ln = _fetch(qs)
        if st == 0:
            continue
        # Interesting if status differs or body length swings
        if st != base_status or abs(ln - base_len) > max(80, int(base_len * 0.08)):
            found.append(
                {
                    "param": word,
                    "status": st,
                    "length": ln,
                    "base_status": base_status,
                    "base_length": base_len,
                }
            )

    payload = {
        "ok": True,
        "url": url,
        "baseline": {"status": base_status, "length": base_len},
        "found": found,
        "found_count": len(found),
    }
    ui.success(f"params: {len(found)} interesting")
    return RunnerResult(cmd, True, 0, json.dumps(payload), "", "executed")
