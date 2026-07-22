"""Extract readable page content (title, text, links) under SCOPE gates.

Persists full HTML + extracted text under ``evidence/safe/`` so the agent can
``read_file`` beyond the JSON preview. Flags SPA / auth-gated pages clearly.
"""

from __future__ import annotations

import json
import re
from datetime import datetime, timezone
from html.parser import HTMLParser
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlparse

from .. import ui
from ..redaction import redact_text
from .base import RunnerResult, require_in_scope

_TEXT_PREVIEW = 12_000
_TEXT_FILE_CAP = 200_000
_HTML_FILE_CAP = 800_000
_LINK_CAP = 80
_EMBED_CAP = 60_000

_SPA_MARKERS = (
    "id=\"root\"",
    "id='root'",
    "id=\"app\"",
    "id='app'",
    "__NEXT_DATA__",
    "ng-version",
    "data-reactroot",
    "webpackJsonp",
    "window.__INITIAL_STATE__",
)
_JSON_BLOB_RE = re.compile(
    r"<script[^>]+id=[\"']__NEXT_DATA__[\"'][^>]*>(\{.*?\})</script>"
    r"|window\.__INITIAL_STATE__\s*=\s*(\{.*?\});",
    re.I | re.S,
)


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
        "text": text,
        "links": abs_links,
        "link_count": len(abs_links),
    }


def _detect_spa(html: str, text: str) -> dict[str, Any]:
    low = html.lower()
    markers = [m for m in _SPA_MARKERS if m.lower() in low]
    script_count = low.count("<script")
    thin = len(text.strip()) < 80
    marketing_heavy = any(
        w in text.lower()
        for w in ("sign in", "log in", "get started", "pricing", "careers", "cookie")
    ) and thin is False and len(text) < 2500
    likely = bool(markers) or (script_count >= 8 and thin) or (script_count >= 12 and marketing_heavy)
    return {
        "likely_spa": likely,
        "spa_markers": markers[:8],
        "script_tags": script_count,
        "thin_content": thin,
        "marketing_shell": bool(marketing_heavy and markers),
    }


def _extract_embedded_json(html: str) -> str:
    chunks: list[str] = []
    for m in _JSON_BLOB_RE.finditer(html):
        blob = next((g for g in m.groups() if g), "")
        if blob:
            chunks.append(blob[: _EMBED_CAP // 2])
    # JSON-LD
    for m in re.finditer(
        r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
        html,
        re.I | re.S,
    ):
        chunks.append(m.group(1)[:8000])
    joined = "\n---\n".join(chunks)
    return joined[:_EMBED_CAP]


def _save_artifact(target_dir: Path, name: str, content: str) -> str:
    try:
        from ..evidence import EvidenceStore

        return str(EvidenceStore(target_dir).save(name, content))
    except Exception:  # noqa: BLE001
        # Fallback under hunt/
        out = Path(target_dir) / "hunt" / "extract"
        out.mkdir(parents=True, exist_ok=True)
        path = out / name
        path.write_text(content, encoding="utf-8", errors="replace")
        return str(path)


def extract_page(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
    timeout: float = 15.0,
    session: str = "",
    save: bool = True,
) -> RunnerResult:
    """GET page and return title / cleaned text / links (scoped). Saves artifacts by default."""
    full = url if "://" in url else f"https://{url}"
    require_in_scope(target_dir, full, action="extract page content", force=force)
    plan = {
        "url": full,
        "approve": approve,
        "session": session or None,
        "save": save,
        "note": "HTML GET only — no JS. SPA/auth program pages need browser_* + session.",
    }
    ui.code_panel(json.dumps(plan, indent=2), title="extract_page", lexer="json")
    cmd = ["extract_page", full]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    from ..identity import load_identity
    from ..scoped_http import scoped_fetch_bytes

    headers = {"User-Agent": "hackbot-extract-page"}
    identity = load_identity(target_dir)
    if session:
        headers.update(identity.merge_headers(session))
    try:
        resp = scoped_fetch_bytes(
            full,
            target_dir=target_dir,
            action="extract page content",
            force=force,
            timeout=timeout,
            headers=headers,
            max_bytes=_HTML_FILE_CAP,
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
    full_text = parsed["text"]
    spa = _detect_spa(html, full_text)
    embedded = _extract_embedded_json(html)
    host = urlparse(full).hostname or "page"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_host = re.sub(r"[^a-zA-Z0-9._-]+", "_", host)[:60]

    saved_html = ""
    saved_text = ""
    saved_embed = ""
    if save:
        saved_html = _save_artifact(
            target_dir, f"extract_{safe_host}_{stamp}.html", html[:_HTML_FILE_CAP]
        )
        saved_text = _save_artifact(
            target_dir,
            f"extract_{safe_host}_{stamp}.txt",
            redact_text(full_text[:_TEXT_FILE_CAP]),
        )
        if embedded:
            saved_embed = _save_artifact(
                target_dir,
                f"extract_{safe_host}_{stamp}.embed.json.txt",
                redact_text(embedded),
            )

    needs_browser = spa["likely_spa"] or spa["thin_content"] or spa.get("marketing_shell")
    needs_session = (not session) and any(
        w in full_text.lower()
        for w in ("sign in", "log in", "login", "authenticate", "sso")
    )

    payload: dict[str, Any] = {
        "ok": True,
        "url": full,
        "status": resp.status,
        "final_url": getattr(resp, "url", None) or full,
        "title": redact_text(parsed["title"]),
        "text": redact_text(full_text[:_TEXT_PREVIEW]),
        "text_len": len(full_text),
        "text_truncated": len(full_text) > _TEXT_PREVIEW,
        "links": [redact_text(u) for u in parsed["links"]],
        "link_count": parsed["link_count"],
        "session_used": session or None,
        "sessions_ready": identity.ready_sessions(),
        "saved_html": saved_html,
        "saved_text": saved_text,
        "saved_embed": saved_embed or None,
        **spa,
        "needs_browser": bool(needs_browser),
        "needs_session": bool(needs_session),
        "embedded_json_chars": len(embedded),
    }
    hints: list[str] = []
    if needs_browser:
        hints.append(
            "Page looks SPA/JS-rendered. Use browser_with_session or browser_navigate + "
            "browser_eval / browser_network — extract_page cannot run JavaScript."
        )
    if needs_session:
        hints.append(
            "Login wall likely. Load secrets/sessions.yaml then retry with session=A "
            "(or browser_capture_session / browser_with_session)."
        )
    if saved_text:
        hints.append(f"Full extracted text saved — read_file path={saved_text}")
    if saved_html:
        hints.append(f"Raw HTML saved — read_file path={saved_html}")
    if hints:
        payload["hint"] = " | ".join(hints)
        payload["next_tools"] = (
            ["browser_with_session", "browser_network", "browser_eval"]
            if needs_browser
            else ["read_file"]
        )

    ui.success(
        f"extract_page: {payload.get('title') or host} ({resp.status}) "
        f"text={len(full_text)} spa={spa['likely_spa']}"
    )
    return RunnerResult(cmd, True, 0, json.dumps(payload), "", "executed")
