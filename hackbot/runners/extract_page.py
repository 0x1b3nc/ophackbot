"""Extract readable page content (title, text, links) under SCOPE gates."""

from __future__ import annotations

import json
import re
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from .. import ui
from ..redaction import redact_text
from .base import RunnerResult, require_in_scope

_TEXT_CAP = 8000
_LINK_CAP = 40


class _PageExtractor(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.title_parts: list[str] = []
        self.text_parts: list[str] = []
        self.links: list[str] = []
        self._in_title = False
        self._skip = 0

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        low = tag.lower()
        if low in {"script", "style", "noscript"}:
            self._skip += 1
            return
        if low == "title":
            self._in_title = True
        if low == "a":
            href = ""
            for k, v in attrs:
                if k.lower() == "href" and v:
                    href = v.strip()
                    break
            if href and not href.startswith(("#", "javascript:", "mailto:")):
                self.links.append(href)

    def handle_endtag(self, tag: str) -> None:
        low = tag.lower()
        if low in {"script", "style", "noscript"} and self._skip:
            self._skip -= 1
            return
        if low == "title":
            self._in_title = False

    def handle_data(self, data: str) -> None:
        if self._skip:
            return
        chunk = re.sub(r"\s+", " ", data).strip()
        if not chunk:
            return
        if self._in_title:
            self.title_parts.append(chunk)
        else:
            self.text_parts.append(chunk)


def _parse_html(html: str, base_url: str) -> dict[str, Any]:
    parser = _PageExtractor()
    try:
        parser.feed(html)
        parser.close()
    except Exception:  # noqa: BLE001
        pass
    title = " ".join(parser.title_parts).strip()
    text = " ".join(parser.text_parts).strip()
    text = re.sub(r"\s{2,}", " ", text)
    abs_links: list[str] = []
    seen: set[str] = set()
    for href in parser.links:
        full = urljoin(base_url, href)
        if full in seen:
            continue
        seen.add(full)
        abs_links.append(full)
        if len(abs_links) >= _LINK_CAP:
            break
    return {
        "title": title[:300],
        "text": text[:_TEXT_CAP],
        "text_truncated": len(text) > _TEXT_CAP,
        "links": abs_links,
        "link_count": len(abs_links),
    }


def extract_page(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
    timeout: float = 15.0,
    session: str = "",
) -> RunnerResult:
    """GET page and return title / cleaned text / links (scoped)."""
    full = url if "://" in url else f"https://{url}"
    require_in_scope(target_dir, full, action="extract page content", force=force)
    plan = {"url": full, "approve": approve, "session": session or None}
    ui.code_panel(json.dumps(plan, indent=2), title="extract_page", lexer="json")
    cmd = ["extract_page", full]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    from ..scoped_http import scoped_fetch_bytes
    from ..identity import load_identity

    headers = {"User-Agent": "hackbot-extract-page"}
    if session:
        headers.update(load_identity(target_dir).merge_headers(session))
    try:
        resp = scoped_fetch_bytes(
            full,
            target_dir=target_dir,
            action="extract page content",
            force=force,
            timeout=timeout,
            headers=headers,
            max_bytes=400_000,
            gate_initial=False,
        )
    except Exception as exc:  # noqa: BLE001
        return RunnerResult(
            cmd,
            True,
            1,
            json.dumps({"ok": False, "error": type(exc).__name__, "detail": str(exc)[:200]}),
            "",
            "error",
        )

    html = resp.body.decode("utf-8", errors="replace")
    parsed = _parse_html(html, full)
    thin = len(parsed["text"].strip()) < 40
    payload: dict[str, Any] = {
        "ok": True,
        "url": full,
        "status": resp.status,
        "final_url": getattr(resp, "url", None) or full,
        "title": redact_text(parsed["title"]),
        "text": redact_text(parsed["text"]),
        "text_truncated": parsed["text_truncated"],
        "links": [redact_text(u) for u in parsed["links"]],
        "link_count": parsed["link_count"],
        "thin_content": thin,
    }
    if thin:
        payload["hint"] = (
            "Little text extracted (SPA/JS-heavy?). Try browser_navigate + browser_eval "
            "for DOM text."
        )
    ui.success(f"extract_page: {payload.get('title') or urlparse(full).netloc} ({resp.status})")
    return RunnerResult(cmd, True, 0, json.dumps(payload), "", "executed")
