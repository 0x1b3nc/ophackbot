"""CORS / open-redirect / security-headers probes + passive recon APIs."""

from __future__ import annotations

import json
import urllib.parse
import urllib.request
from pathlib import Path
from typing import Any

from .. import ui
from ..redaction import redact_text
from ..scoped_http import scoped_fetch_bytes, scoped_fetch_no_redirect
from .base import RunnerResult, require_in_scope


def cors_probe(
    target_dir: Path,
    url: str,
    *,
    origin: str = "https://evil.example",
    approve: bool = False,
    force: bool = False,
    timeout: float = 12.0,
) -> RunnerResult:
    require_in_scope(
        target_dir, url, action="cors reflection probe", force=force, tool="cors_probe"
    )
    plan = {"url": url, "origin": origin, "approve": approve}
    ui.code_panel(json.dumps(plan, indent=2), title="cors_probe", lexer="json")
    cmd = ["cors_probe", url]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    try:
        resp = scoped_fetch_bytes(
            url,
            target_dir=target_dir,
            action="cors reflection probe",
            force=force,
            timeout=timeout,
            headers={"User-Agent": "hackbot-cors-probe", "Origin": origin},
            gate_initial=False,
        )
        status = resp.status
        headers = {k.lower(): v for k, v in resp.headers.items()}
    except Exception as exc:  # noqa: BLE001
        return RunnerResult(cmd, True, 1, "", str(exc), f"error:{type(exc).__name__}")

    acao = headers.get("access-control-allow-origin", "")
    acac = headers.get("access-control-allow-credentials", "")
    reflected = acao == origin or acao == "*"
    creds = acac.lower() == "true"
    signal = reflected and (creds or acao == origin)
    payload = {
        "ok": True,
        "url": url,
        "status": status,
        "acao": acao,
        "acac": acac,
        "reflected": reflected,
        "credentials": creds,
        "signal": signal,
        "redirect_hops": resp.hops,
        "reason": (
            "Origin reflected with credentials"
            if signal and creds
            else ("Origin reflected" if reflected else "no CORS reflection")
        ),
    }
    return RunnerResult(cmd, True, 0, json.dumps(payload), "", "executed")


def open_redirect_probe(
    target_dir: Path,
    url: str,
    *,
    param: str = "next",
    approve: bool = False,
    force: bool = False,
    timeout: float = 12.0,
) -> RunnerResult:
    require_in_scope(
        target_dir, url, action="open redirect probe", force=force, tool="open_redirect_probe"
    )
    evil = "https://evil.example/hackbot"
    parsed = urllib.parse.urlparse(url if "://" in url else f"https://{url}")
    qs = urllib.parse.parse_qs(parsed.query, keep_blank_values=True)
    qs[param] = [evil]
    probe = urllib.parse.urlunparse(
        (
            parsed.scheme,
            parsed.netloc,
            parsed.path,
            "",
            urllib.parse.urlencode({k: v[0] for k, v in qs.items()}),
            "",
        )
    )
    plan = {"url": probe, "param": param, "approve": approve}
    ui.code_panel(json.dumps(plan, indent=2), title="open_redirect_probe", lexer="json")
    cmd = ["open_redirect_probe", probe]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    try:
        resp = scoped_fetch_no_redirect(
            probe,
            target_dir=target_dir,
            action="open redirect probe",
            force=force,
            timeout=timeout,
            headers={"User-Agent": "hackbot-redirect-probe"},
            max_bytes=20_000,
            gate_initial=False,
        )
        status = resp.status
        headers = {k.lower(): v for k, v in resp.headers.items()}
        body = resp.body.decode("utf-8", errors="replace")
    except Exception as exc:  # noqa: BLE001
        return RunnerResult(cmd, True, 1, "", str(exc), f"error:{type(exc).__name__}")

    location = headers.get("location", "")
    if not location and resp.hops:
        location = str(resp.hops[-1].get("to") or "")
    signal = "evil.example" in location or "evil.example" in body
    payload = {
        "ok": True,
        "url": probe,
        "status": status,
        "location": redact_text(location)[:300],
        "signal": signal,
        "redirect_hops": resp.hops,
        "reason": "redirect/body points to evil.example" if signal else "no open redirect signal",
    }
    return RunnerResult(cmd, True, 0, json.dumps(payload), "", "executed")


def analyze_headers(
    target_dir: Path,
    url: str,
    *,
    approve: bool = False,
    force: bool = False,
    timeout: float = 12.0,
) -> RunnerResult:
    require_in_scope(
        target_dir,
        url,
        action="security headers fingerprint",
        force=force,
        tool="analyze_headers",
    )
    plan = {"url": url, "approve": approve}
    ui.code_panel(json.dumps(plan, indent=2), title="analyze_headers", lexer="json")
    cmd = ["analyze_headers", url]
    if not approve:
        ui.dry_run_banner()
        return RunnerResult(cmd, False, None, json.dumps({"dry_run": True, **plan}), "", "dry-run")

    try:
        resp = scoped_fetch_bytes(
            url,
            target_dir=target_dir,
            action="security headers fingerprint",
            force=force,
            timeout=timeout,
            headers={"User-Agent": "hackbot-headers"},
            gate_initial=False,
        )
        status = resp.status
        headers = {k.lower(): v for k, v in resp.headers.items()}
    except Exception as exc:  # noqa: BLE001
        return RunnerResult(cmd, True, 1, "", str(exc), f"error:{type(exc).__name__}")

    interesting = (
        "content-security-policy",
        "strict-transport-security",
        "x-frame-options",
        "x-content-type-options",
        "referrer-policy",
        "permissions-policy",
        "access-control-allow-origin",
        "server",
        "x-powered-by",
        "set-cookie",
    )
    present = {k: headers[k] for k in interesting if k in headers}
    missing = [k for k in interesting[:6] if k not in headers]
    payload = {
        "ok": True,
        "url": url,
        "status": status,
        "headers": {k: redact_text(v)[:200] for k, v in present.items()},
        "missing_security": missing,
        "tech_hints": [f"{k}:{present[k][:60]}" for k in ("server", "x-powered-by") if k in present],
        "redirect_hops": resp.hops,
    }
    return RunnerResult(cmd, True, 0, json.dumps(payload), "", "executed")


def crt_subdomains(domain: str, *, timeout: float = 25.0) -> dict[str, Any]:
    """Passive subdomain enum via crt.sh (no approve — passive OSINT)."""
    domain = domain.strip().lower().lstrip("*.")
    q = urllib.parse.quote(f"%.{domain}")
    url = f"https://crt.sh/?q={q}&output=json"
    try:
        req = urllib.request.Request(url, headers={"User-Agent": "hackbot-crt"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw = resp.read(2_000_000).decode("utf-8", errors="replace")
        rows = json.loads(raw) if raw.strip() else []
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "domain": domain}

    names: set[str] = set()
    for row in rows if isinstance(rows, list) else []:
        nv = str(row.get("name_value") or "")
        for part in nv.split("\n"):
            part = part.strip().lower().lstrip("*.")
            if part.endswith(domain) or part == domain:
                names.add(part)
    return {
        "ok": True,
        "domain": domain,
        "count": len(names),
        "subdomains": sorted(names)[:500],
        "source": "crt.sh",
    }


def wayback_urls(
    domain: str,
    *,
    limit: int = 100,
    timeout: float = 30.0,
    save_dir: Path | None = None,
) -> dict[str, Any]:
    """Passive URL discovery via Wayback CDX API. Optionally persist under recon/."""
    domain = domain.strip().lower()
    api = (
        "https://web.archive.org/cdx/search/cdx"
        f"?url={urllib.parse.quote(domain)}/*&output=json&fl=original&collapse=urlkey&limit={int(limit)}"
    )
    try:
        req = urllib.request.Request(api, headers={"User-Agent": "hackbot-wayback"})
        with urllib.request.urlopen(req, timeout=timeout) as resp:  # noqa: S310
            raw = resp.read(2_000_000).decode("utf-8", errors="replace")
        rows = json.loads(raw) if raw.strip() else []
    except Exception as exc:  # noqa: BLE001
        return {"ok": False, "error": f"{type(exc).__name__}: {exc}", "domain": domain}

    urls: list[str] = []
    for row in rows[1:] if isinstance(rows, list) and rows else []:
        if isinstance(row, list) and row:
            urls.append(str(row[0]))
        elif isinstance(row, str):
            urls.append(row)
    urls = urls[:limit]
    saved = ""
    if save_dir is not None and urls:
        try:
            recon = Path(save_dir) / "recon"
            recon.mkdir(parents=True, exist_ok=True)
            safe = domain.replace("/", "_").replace("\\", "_")
            out = recon / f"wayback_{safe}.txt"
            out.write_text("\n".join(urls) + "\n", encoding="utf-8")
            saved = str(out)
        except OSError as exc:
            saved = f"(save failed: {exc})"
    return {
        "ok": True,
        "domain": domain,
        "count": len(urls),
        "urls": urls,
        "source": "wayback-cdx",
        "saved": saved,
    }
