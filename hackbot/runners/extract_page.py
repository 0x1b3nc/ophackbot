"""Extract page content under SCOPE — public pages welcome, no login required.

Strategy:
1. GET HTML (optional session only if caller passes one).
2. Prefer embedded program JSON (``__NEXT_DATA__``, initial state, JSON-LD).
3. If SPA / thin shell, optionally headless-render **without** auth (``render=true``).
4. Always persist HTML + text artifacts for ``read_file``.
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

_TEXT_PREVIEW = 16_000
_TEXT_FILE_CAP = 250_000
_HTML_FILE_CAP = 1_200_000
_LINK_CAP = 80
_EMBED_CAP = 200_000

_SPA_MARKERS = (
    'id="root"',
    "id='root'",
    'id="app"',
    "id='app'",
    "__NEXT_DATA__",
    "ng-version",
    "data-reactroot",
    "webpackJsonp",
    "window.__INITIAL_STATE__",
)

_PROGRAM_KEYS = re.compile(
    r"(inscope|in_scope|outOfScope|out_scope|outofscope|asset|domain|wildcard|"
    r"bounty|severity|program|scope|reward|target|endpoint|url)",
    re.I,
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
    likely = bool(markers) or (script_count >= 8 and thin)
    return {
        "likely_spa": likely,
        "spa_markers": markers[:8],
        "script_tags": script_count,
        "thin_content": thin,
    }


def _extract_script_json(html: str) -> list[tuple[str, str]]:
    """Return list of (source, json_text) from known public SPA embeds."""
    out: list[tuple[str, str]] = []
    for m in re.finditer(
        r'<script[^>]*id=["\']__NEXT_DATA__["\'][^>]*>(.*?)</script>',
        html,
        re.I | re.S,
    ):
        blob = (m.group(1) or "").strip()
        if blob.startswith("{"):
            out.append(("__NEXT_DATA__", blob[:_EMBED_CAP]))
    for m in re.finditer(
        r"window\.__INITIAL_STATE__\s*=\s*(\{.*?\})\s*;",
        html,
        re.I | re.S,
    ):
        blob = (m.group(1) or "").strip()
        if blob:
            out.append(("__INITIAL_STATE__", blob[:_EMBED_CAP]))
    for m in re.finditer(
        r'<script[^>]+type=["\']application/ld\+json["\'][^>]*>(.*?)</script>',
        html,
        re.I | re.S,
    ):
        blob = (m.group(1) or "").strip()
        if blob:
            out.append(("json_ld", blob[:20_000]))
    return out


def _walk_program_bits(obj: Any, *, path: str = "", out: list[str], limit: int = 80) -> None:
    if len(out) >= limit:
        return
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = str(k)
            p = f"{path}.{key}" if path else key
            if _PROGRAM_KEYS.search(key):
                try:
                    if isinstance(v, (str, int, float, bool)) or v is None:
                        out.append(f"{p}={v}")
                    elif isinstance(v, list) and v and all(isinstance(x, (str, int, float)) for x in v[:20]):
                        out.append(f"{p}={v[:30]!r}")
                    else:
                        out.append(f"{p}=<{type(v).__name__} len={len(v) if hasattr(v, '__len__') else '?'}>")
                except Exception:  # noqa: BLE001
                    out.append(f"{p}=?")
            if isinstance(v, (dict, list)):
                _walk_program_bits(v, path=p, out=out, limit=limit)
    elif isinstance(obj, list):
        for i, item in enumerate(obj[:40]):
            _walk_program_bits(item, path=f"{path}[{i}]", out=out, limit=limit)


def _program_summary_from_embeds(embeds: list[tuple[str, str]]) -> dict[str, Any]:
    bits: list[str] = []
    parsed_any = False
    for source, raw in embeds:
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            continue
        parsed_any = True
        local: list[str] = []
        _walk_program_bits(data, out=local)
        if local:
            bits.append(f"[{source}]")
            bits.extend(local[:50])
    text = "\n".join(bits)
    return {
        "has_program_json": parsed_any and bool(bits),
        "program_summary": text[:_TEXT_FILE_CAP],
        "program_keys_found": len([b for b in bits if not b.startswith("[")]),
    }


def _save_artifact(target_dir: Path, name: str, content: str) -> str:
    try:
        from ..evidence import EvidenceStore

        return str(EvidenceStore(target_dir).save(name, content))
    except Exception:  # noqa: BLE001
        out = Path(target_dir) / "hunt" / "extract"
        out.mkdir(parents=True, exist_ok=True)
        path = out / name
        path.write_text(content, encoding="utf-8", errors="replace")
        return str(path)


def _render_public(
    target_dir: Path,
    url: str,
    *,
    force: bool,
    timeout: float,
) -> tuple[str, str, str, int]:
    """Headless Chromium, no cookies/session — public pages only."""
    from playwright.sync_api import sync_playwright

    from .browser import _guarded_page

    require_in_scope(target_dir, url, action="extract_page render", force=force, tool="extract_page")
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=True)
        try:
            _ctx, page, blocked = _guarded_page(
                browser,
                target_dir,
                action="extract_page render",
                force=force,
            )
            page.goto(url, wait_until="networkidle", timeout=int(timeout * 1000))
            if blocked:
                raise PermissionError(f"scope_blocked:{blocked[:5]}")
            title = page.title() or ""
            html = page.content()
            text = page.inner_text("body") if page.query_selector("body") else ""
            # Also pull __NEXT_DATA__ from live DOM if present
            try:
                next_data = page.evaluate(
                    "() => (document.getElementById('__NEXT_DATA__') || {}).textContent || ''"
                )
            except Exception:  # noqa: BLE001
                next_data = ""
            if isinstance(next_data, str) and next_data.strip().startswith("{"):
                if f'id="__NEXT_DATA__"' not in html and "id='__NEXT_DATA__'" not in html:
                    html = (
                        html.replace("</head>", "", 1)
                        + f'<script id="__NEXT_DATA__" type="application/json">{next_data}</script></head>'
                        if "</head>" in html
                        else html + f'<script id="__NEXT_DATA__">{next_data}</script>'
                    )
            status = 200
            return title, html, text, status
        finally:
            browser.close()


def extract_page(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
    timeout: float = 25.0,
    session: str = "",
    save: bool = True,
    render: bool | None = None,
) -> RunnerResult:
    """Extract public page content. Login is optional — never required by default."""
    full = url if "://" in url else f"https://{url}"
    require_in_scope(target_dir, full, action="extract page content", force=force)
    plan = {
        "url": full,
        "approve": approve,
        "session": session or None,
        "save": save,
        "render": render,
        "note": "Public extract OK without login. render=auto uses headless Chromium when SPA.",
    }
    ui.code_panel(json.dumps(plan, indent=2), title="extract_page", lexer="json")
    cmd = ["extract_page", full]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    from ..identity import load_identity
    from ..scoped_http import scoped_fetch_bytes

    headers = {
        "User-Agent": (
            "Mozilla/5.0 (compatible; hackbot-extract-page/1; +https://github.com/0x1b3nc/ophackbot)"
        ),
        "Accept": "text/html,application/xhtml+xml,application/json;q=0.9,*/*;q=0.8",
    }
    identity = load_identity(target_dir)
    if session:
        headers.update(identity.merge_headers(session))

    used_render = False
    title = ""
    html = ""
    visible_text = ""
    status = 0
    final_url = full
    fetch_error = ""

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
        status = int(resp.status)
        final_url = getattr(resp, "url", None) or full
        html = resp.body.decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        fetch_error = f"{type(exc).__name__}: {exc}"[:200]

    parsed = _parse_html(html, full) if html else {"title": "", "text": "", "links": [], "link_count": 0}
    title = parsed["title"] or title
    visible_text = parsed["text"]
    spa = _detect_spa(html, visible_text) if html else {
        "likely_spa": True,
        "spa_markers": [],
        "script_tags": 0,
        "thin_content": True,
    }
    embeds = _extract_script_json(html) if html else []
    prog = _program_summary_from_embeds(embeds)

    # Auto-render public SPA when HTML shell lacks program JSON (NO login)
    do_render = render
    if do_render is None:
        do_render = bool(spa["likely_spa"] and not prog["has_program_json"]) or bool(
            fetch_error and not html
        )

    if do_render:
        try:
            title, html, visible_text, status = _render_public(
                target_dir, full, force=force, timeout=timeout
            )
            used_render = True
            parsed = _parse_html(html, full)
            if not visible_text:
                visible_text = parsed["text"]
            if not title:
                title = parsed["title"]
            spa = _detect_spa(html, visible_text)
            embeds = _extract_script_json(html)
            prog = _program_summary_from_embeds(embeds)
            final_url = full
            fetch_error = ""
        except Exception as exc:  # noqa: BLE001
            fetch_error = (fetch_error + f" | render:{type(exc).__name__}:{exc}")[:300]

    if not html and fetch_error:
        return RunnerResult(
            cmd,
            True,
            1,
            json.dumps({"ok": False, "error": "fetch_failed", "detail": fetch_error, "url": full}),
            "",
            "error",
        )

    # Prefer program JSON summary over marketing DOM text when present
    primary_text = prog["program_summary"] if prog["has_program_json"] else visible_text
    if prog["has_program_json"] and visible_text:
        primary_text = (
            prog["program_summary"]
            + "\n\n--- visible_text ---\n"
            + visible_text[:40_000]
        )

    host = urlparse(full).hostname or "page"
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_host = re.sub(r"[^a-zA-Z0-9._-]+", "_", host)[:60]

    saved_html = saved_text = saved_json = ""
    if save:
        saved_html = _save_artifact(
            target_dir, f"extract_{safe_host}_{stamp}.html", html[:_HTML_FILE_CAP]
        )
        saved_text = _save_artifact(
            target_dir,
            f"extract_{safe_host}_{stamp}.txt",
            redact_text(primary_text[:_TEXT_FILE_CAP]),
        )
        if embeds:
            blob = "\n\n".join(f"// {src}\n{raw}" for src, raw in embeds)[:_EMBED_CAP]
            saved_json = _save_artifact(
                target_dir,
                f"extract_{safe_host}_{stamp}.next.json.txt",
                redact_text(blob),
            )

    auth_wall = status in {401, 403} or (
        status in {301, 302, 303, 307, 308}
        and any(x in (final_url or "").lower() for x in ("/login", "/signin", "/auth"))
    )

    payload: dict[str, Any] = {
        "ok": True,
        "url": full,
        "status": status,
        "final_url": final_url,
        "title": redact_text(title),
        "text": redact_text(primary_text[:_TEXT_PREVIEW]),
        "text_len": len(primary_text),
        "text_truncated": len(primary_text) > _TEXT_PREVIEW,
        "visible_text_len": len(visible_text),
        "links": [redact_text(u) for u in parsed.get("links") or []],
        "link_count": parsed.get("link_count") or 0,
        "session_used": session or None,
        "login_required": False,  # public extract — do not push auth by default
        "auth_wall_detected": bool(auth_wall),
        "used_render": used_render,
        "has_program_json": prog["has_program_json"],
        "program_keys_found": prog["program_keys_found"],
        "saved_html": saved_html,
        "saved_text": saved_text,
        "saved_json": saved_json or None,
        **spa,
        "needs_browser": bool(spa["likely_spa"] and not prog["has_program_json"] and not used_render),
        "embedded_json_chars": sum(len(r) for _, r in embeds),
    }
    if fetch_error:
        payload["warning"] = fetch_error

    hints: list[str] = []
    if prog["has_program_json"]:
        hints.append(
            "Program/scope JSON found in page embed (__NEXT_DATA__/state) — "
            f"read_file path={saved_json or saved_text}"
        )
    elif used_render:
        hints.append("Rendered with headless Chromium (no login). Read saved_text for full body.")
    elif spa["likely_spa"]:
        hints.append(
            "SPA shell without program JSON on first GET. Re-run extract_page with render=true "
            "(still no login) or read saved_html."
        )
    if auth_wall:
        hints.append("HTTP auth wall detected (401/403/login redirect) — session optional, only if needed.")
    if saved_text:
        hints.append(f"Full text: read_file path={saved_text}")
    payload["hint"] = " | ".join(hints) if hints else "Public extract complete."
    payload["next_tools"] = ["read_file"]
    if payload["needs_browser"]:
        payload["next_tools"] = ["extract_page", "read_file"]  # retry with render, not login

    ui.success(
        f"extract_page: {payload.get('title') or host} ({status}) "
        f"program_json={prog['has_program_json']} render={used_render}"
    )
    return RunnerResult(cmd, True, 0, json.dumps(payload), "", "executed")
