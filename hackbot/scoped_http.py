"""HTTP transport that re-validates SCOPE on every redirect hop.

Operator ``force`` still unlocks soft gates (NOT_CONFIRMED / L3 wording).
Explicit OUT_OF_SCOPE remains hard-blocked on every hop — silent redirect
bypass is a bug; intentional force is the operator's responsibility.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from urllib.error import HTTPError
from urllib.parse import urljoin, urlparse
from urllib.request import (
    HTTPRedirectHandler,
    Request,
    build_opener,
)

def _gate(target_dir: Path, host_or_url: str, *, action: str, force: bool) -> None:
    # Local import avoids import cycles with runners.*
    from .runners.base import require_in_scope

    require_in_scope(target_dir, host_or_url, action=action, force=force)


@dataclass
class ScopedResponse:
    """Minimal response surface used by runners (status, headers, body, url, hops)."""

    status: int
    headers: Any
    body: bytes
    url: str
    hops: list[dict[str, Any]] = field(default_factory=list)

    def get_all(self, name: str) -> list[str]:
        get_all = getattr(self.headers, "get_all", None)
        if callable(get_all):
            return list(get_all(name) or [])
        val = self.headers.get(name) if self.headers else None
        return [val] if val else []


class ScopedRedirectHandler(HTTPRedirectHandler):
    def __init__(
        self,
        target_dir: Path,
        *,
        action: str = "",
        force: bool = False,
        hops: list[dict[str, Any]] | None = None,
        max_hops: int = 10,
    ) -> None:
        super().__init__()
        self.target_dir = Path(target_dir)
        self.action = action
        self.force = force
        self.hops = hops if hops is not None else []
        self.max_hops = max_hops

    def redirect_request(self, req, fp, code, msg, headers, newurl):  # noqa: ANN001
        absolute = urljoin(req.full_url, newurl)
        if len(self.hops) >= self.max_hops:
            raise PermissionError(
                f"redirect hop limit ({self.max_hops}) exceeded at {absolute}"
            )
        # Re-gate every hop (OOS hard-block; soft gates honor force)
        _gate(
            self.target_dir,
            absolute,
            action=self.action or "http redirect hop",
            force=self.force,
        )
        self.hops.append(
            {
                "from": req.full_url,
                "to": absolute,
                "code": int(code),
                "host": (urlparse(absolute).hostname or "").lower(),
            }
        )
        return super().redirect_request(req, fp, code, msg, headers, absolute)


def scoped_urlopen(
    req: Request,
    *,
    target_dir: Path,
    action: str = "",
    force: bool = False,
    timeout: float = 20.0,
    max_redirects: int = 10,
    gate_initial: bool = True,
) -> ScopedResponse:
    """Open ``req`` after SCOPE checks on the initial URL and every redirect.

    Raises ``PermissionError`` when a hop is OUT_OF_SCOPE or NOT_CONFIRMED
    without ``force``. Propagates ``HTTPError`` for non-redirect HTTP errors
    (callers often read the error body).
    """
    hops: list[dict[str, Any]] = []
    url = req.full_url
    if gate_initial:
        _gate(target_dir, url, action=action, force=force)

    handler = ScopedRedirectHandler(
        target_dir,
        action=action,
        force=force,
        hops=hops,
        max_hops=max_redirects,
    )
    opener = build_opener(handler)
    try:
        with opener.open(req, timeout=timeout) as resp:
            status = int(getattr(resp, "status", None) or resp.getcode())
            raw = resp.read()
            final = getattr(resp, "geturl", lambda: url)()
            return ScopedResponse(
                status=status,
                headers=resp.headers,
                body=raw,
                url=str(final or url),
                hops=list(hops),
            )
    except HTTPError as exc:
        # Redirects that fail policy raise PermissionError from the handler.
        # Other HTTP errors are returned as a ScopedResponse so runners can
        # inspect bodies (matching prior urlopen/HTTPError behavior).
        if 300 <= int(exc.code) < 400:
            raise
        raw = b""
        try:
            raw = exc.read()
        except Exception:  # noqa: BLE001
            raw = b""
        return ScopedResponse(
            status=int(exc.code),
            headers=exc.headers,
            body=raw,
            url=url,
            hops=list(hops),
        )


def scoped_fetch_bytes(
    url: str,
    *,
    target_dir: Path,
    action: str = "",
    force: bool = False,
    timeout: float = 20.0,
    headers: dict[str, str] | None = None,
    method: str = "GET",
    data: bytes | None = None,
    max_bytes: int | None = None,
    gate_initial: bool = True,
) -> ScopedResponse:
    """Convenience GET/POST with scoped redirects."""
    full = url if "://" in url else f"https://{url}"
    req = Request(full, data=data, method=method.upper(), headers=headers or {})
    resp = scoped_urlopen(
        req,
        target_dir=target_dir,
        action=action,
        force=force,
        timeout=timeout,
        gate_initial=gate_initial,
    )
    if max_bytes is not None and len(resp.body) > max_bytes:
        resp = ScopedResponse(
            status=resp.status,
            headers=resp.headers,
            body=resp.body[:max_bytes],
            url=resp.url,
            hops=resp.hops,
        )
    return resp


def attach_playwright_scope_guard(
    target: Any,
    target_dir: Path,
    *,
    action: str,
    force: bool = False,
    blocked: list[dict[str, str]] | None = None,
) -> list[dict[str, str]]:
    """Abort Playwright requests whose URL fails SCOPE (redirects/subresources)."""
    hits = blocked if blocked is not None else []

    def _handler(route: Any) -> None:  # noqa: ANN401
        req_url = str(getattr(route.request, "url", "") or "")
        if not req_url or req_url.startswith(("data:", "blob:", "about:", "chrome:")):
            route.continue_()
            return
        try:
            _gate(target_dir, req_url, action=action or "browser request", force=force)
        except PermissionError as exc:
            hits.append({"url": req_url, "error": str(exc)})
            route.abort("blockedbyclient")
            return
        route.continue_()

    target.route("**/*", _handler)
    return hits
